import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { visible, useTextMode } from "./helpers";

/**
 * Review items 3 and 4: one definition of "secret", one definition of
 * "cleaned up".
 *
 * The app had two clearing functions with overlapping-but-different lists, one
 * predicate that decided whether anything was worth locking, and three success
 * paths that each cleaned up a different amount. Every gap found so far has
 * been the same shape — a secret that one list knew about and another did not:
 *
 * - recovery shares survived `resetState` while being cleared by a wipe
 * - a selected file and key file survived both, and armed no lock at all
 * - the non-UTF-8 decrypt path returned before the plaintext buffer was zeroed
 *
 * These cover the observable half. Buffer zeroing is not observable from a
 * test, so the binary case is pinned by the credential clearing that sits
 * beside it in the same function: if the password is cleared, control reached
 * `finishOperation`, and the zeroing is the line above it.
 */

const SHARE_TEXT = [
  "KMSHARE1:05DZ-4EG3-07VX-TDNP-J21H-K81F-5P11-ZPRS-H0PG-NGC1-PJAP-9ZZY-W78Z-GT37-NF2B-RXE1-JYF0",
  "KMSHARE1:05DZ-4EG3-095E-01FR-2W41-DTRC-G4Z5-YVCK-MRX3-8TVN-5FGC-63MX-3H4B-7PMX-FVDK-Z4V5-0KTG",
].join("\n");

const wipeNow = (p: import("@playwright/test").Page) =>
  p.getByRole("button", { name: /Wipe now/i });

test.describe("one predicate for what counts as a secret", () => {
  test("a chosen file arms the lock, even with every field empty", async ({ page }) => {
    await page.goto("/");

    // Nothing typed anywhere. Before this fix the predicate looked only at
    // password, text secret and output, so a loaded document was "nothing
    // worth locking" — no countdown, and no button to press when someone
    // walked over.
    await expect(
      wipeNow(page),
      "precondition: an empty form should offer nothing to wipe"
    ).toHaveCount(0);

    await page.setInputFiles('input[type="file"]', {
      name: "passport-scan.bin",
      mimeType: "application/octet-stream",
      buffer: Buffer.from("pretend this is a scan of something you care about"),
    });

    await expect(
      visible(wipeNow(page)),
      "a loaded file did not count as a secret on screen"
    ).toBeVisible();
  });

  test("a key file arms the lock on its own", async ({ page }) => {
    await page.goto("/");
    const advanced = visible(page.getByRole("button", { name: /^Advanced/ }));
    if ((await advanced.getAttribute("aria-expanded")) !== "true") await advanced.click();
    await visible(page.getByLabel(/key file/i)).click();

    await page.setInputFiles('input[type="file"]:below(:text("Key file"))', {
      name: "second-factor.key",
      mimeType: "application/octet-stream",
      buffer: Buffer.from("half the key material"),
    });

    await expect(
      visible(wipeNow(page)),
      "a selected key file is half the key material and did not arm the lock"
    ).toBeVisible();
  });
});

test.describe("one clearing function", () => {
  test("changing mode does not leave shares behind", async ({ page }) => {
    await page.goto("/");
    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);
    await visible(page.getByRole("button", { name: /^Use recovery shares$/i })).click();
    await visible(page.getByPlaceholder(/KMSHARE1:/)).fill(SHARE_TEXT);

    // Mode change runs resetState, which cleared the password and the file and
    // not the shares — so k credentials that open the container survived the
    // one action a user would reasonably expect to clear the form.
    await visible(page.getByRole("tab", { name: "Encrypt" })).click();
    await visible(page.getByRole("tab", { name: "Decrypt" })).click();

    await expect(
      wipeNow(page),
      "shares survived a mode change: the lock is still armed on state the user thinks is gone"
    ).toHaveCount(0);

    // And the toggle came back off, so the textarea is not merely hidden.
    await expect(
      page.getByPlaceholder(/KMSHARE1:/),
      "the share textarea is still mounted, so its contents are still in state"
    ).toHaveCount(0);
  });
});

test.describe("one completion path", () => {
  test("a non-text decrypt still clears the password", async ({ page }) => {
    // The container decrypts to bytes that are not valid UTF-8, so the app
    // downloads decrypted.bin instead of rendering it. That branch used to
    // `return` before the shared cleanup, skipping the buffer erase and both
    // credential clears — on the one path whose entire job is handling raw
    // plaintext carefully.
    const fx = JSON.parse(
      readFileSync(resolve(__dirname, "fixtures/binary-plaintext.json"), "utf8")
    ) as { armor: string; password: string };

    await page.goto("/");
    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);
    await visible(page.getByPlaceholder("Enter text to decrypt")).fill(fx.armor);
    const pw = visible(page.getByPlaceholder("Enter decryption password"));
    await pw.fill(fx.password);

    const download = page.waitForEvent("download", { timeout: 90_000 }).catch(() => null);
    await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();

    await expect(visible(page.getByText(/not valid UTF-8/i))).toBeVisible({ timeout: 90_000 });
    expect(await download, "the bytes were not handed over").not.toBeNull();

    // The observable end of the shared cleanup. `finishOperation` erases the
    // plaintext buffer immediately before clearing this, so an empty field
    // here is evidence that control reached the erase too.
    await expect(
      pw,
      "the password survived a successful decrypt — this path skipped the shared cleanup"
    ).toHaveValue("");
  });
});
