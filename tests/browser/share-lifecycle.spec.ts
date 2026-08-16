import { test, expect, type Page } from "@playwright/test";
import { visible, useTextMode, STRONG_PASSWORD } from "./helpers";

/**
 * KM-R03: recovery shares are password-equivalent, and were outside the
 * lifecycle that treats passwords as secrets.
 *
 * §4.6 is explicit that k shares open a container *without* the password. The
 * auto-lock predicate and the panic-wipe button both keyed off password, text
 * secret and output text only — so in the flow that matters most, an heir
 * recovering a file, all three can be empty while the textarea holds enough
 * shares to open everything. The countdown never started and the Wipe now
 * button was not rendered.
 *
 * That is the wrong way round. Share-based recovery is the flow where the
 * person at the keyboard is least likely to be at their own desk.
 */

/** Enough share-shaped text to make the state non-empty. */
const SHARE_TEXT = [
  "KMSHARE1:05DZ-4EG3-07VX-TDNP-J21H-K81F-5P11-ZPRS-H0PG-NGC1-PJAP-9ZZY-W78Z-GT37-NF2B-RXE1-JYF0",
  "KMSHARE1:05DZ-4EG3-095E-01FR-2W41-DTRC-G4Z5-YVCK-MRX3-8TVN-5FGC-63MX-3H4B-7PMX-FVDK-Z4V5-0KTG",
].join("\n");

async function pasteShares(page: Page) {
  await page.goto("/");
  await visible(page.getByRole("tab", { name: "Decrypt" })).click();
  await useTextMode(page);
  await visible(page.getByRole("button", { name: /^Use recovery shares$/i })).click();
  await visible(page.getByPlaceholder(/KMSHARE1:/)).fill(SHARE_TEXT);
}

test.describe("recovery shares are treated as secrets", () => {
  test("pasted shares alone arm the lock and show Wipe now", async ({ page }) => {
    await pasteShares(page);

    // No password, no text secret, no output — exactly the state the old
    // predicate called "nothing worth locking".
    await expect(
      visible(page.getByPlaceholder("Enter decryption password")),
      "this test only means something with the password field empty"
    ).toHaveValue("");

    await expect(
      visible(page.getByRole("button", { name: /^Wipe now$/i })),
      "shares on screen did not count as secrets on screen"
    ).toBeVisible({ timeout: 30_000 });
  });

  test("Wipe now clears the pasted shares", async ({ page }) => {
    await pasteShares(page);
    await visible(page.getByRole("button", { name: /^Wipe now$/i })).click();

    // Absent or empty both count: the wipe may unmount the textarea along with
    // the mode. What must not survive is the text.
    await expect
      .poll(
        async () => {
          const box = page.getByPlaceholder(/KMSHARE1:/);
          return (await box.count()) === 0 ? "" : await box.first().inputValue();
        },
        { message: "the panic wipe left recovery shares in the DOM", timeout: 30_000 }
      )
      .toBe("");
  });

  test("turning the mode off does not leave the shares behind it", async ({ page }) => {
    await pasteShares(page);
    // Back to a password. The textarea disappears; the question is whether its
    // contents did.
    await visible(page.getByRole("button", { name: /^Use a password instead$/i })).click();
    await visible(page.getByRole("button", { name: /^Use recovery shares$/i })).click();

    await expect(
      visible(page.getByPlaceholder(/KMSHARE1:/)),
      "the shares came back when the mode was re-enabled"
    ).toHaveValue("");
  });
});
