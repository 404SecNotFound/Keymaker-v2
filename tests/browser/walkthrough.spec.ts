import { test, expect } from "@playwright/test";
import { visible, useTextMode } from "./helpers";

/**
 * docs/WALKTHROUGH.md — Part 1 and Part 2, in a real browser.
 *
 * `reference/recovery_test.py` executes the walkthrough's *shell* half by
 * extracting the commands from the page and running them. This is the other
 * half: the UI the page tells someone to click through, and the specific
 * claims it makes about what they will see.
 *
 * A walkthrough is a sequence of instructions, so its failure mode is not
 * "looks dated" but "tells you to click something that is not there". The
 * screenshots come from `scripts/capture-screenshots.mjs`, which drives this
 * same path — so the prose, the pictures and the app move together or the
 * build goes red.
 *
 * Every assertion below quotes something the document asserts. If a claim here
 * looks arbitrary, it is because the page makes it in so many words.
 */

const SECRET =
  "Emergency kit — the password manager master password is in the sealed\n" +
  "envelope in the safe. Recovery codes: 4471-0092, 8823-5510, 6104-7735.";
const PASSWORD = "Ridge-Blender-Oakwood-Marina-72!";

test.describe("the walkthrough's encrypt path", () => {
  test("step 1 — the secret field blurs itself", async ({ page }) => {
    await page.goto("/");
    await useTextMode(page);

    const field = visible(page.getByPlaceholder("Enter text to encrypt"));
    await field.fill(SECRET);

    // "The field blurs itself. That is not decoration — it is for the case
    // where you are doing this on a train."
    await expect(field).toHaveClass(/blur/);
    await visible(page.getByRole("button", { name: /^Show secret text$/ })).click();
    await expect(field).not.toHaveClass(/blur/);
  });

  test("step 2 — the Advanced panel offers what the page says it offers", async ({ page }) => {
    await page.goto("/");
    await useTextMode(page);
    await visible(page.getByPlaceholder("Enter text to encrypt")).fill(SECRET);

    await visible(page.getByRole("button", { name: /^Advanced/ })).click();

    // "Key derivation — Argon2id. It is the default and it is the right
    // default." The page rests an argument on Argon2id already being selected;
    // if the default moved, the walkthrough would be telling people to change
    // something that is already changed.
    const argon = visible(page.getByRole("button").filter({ hasText: "Argon2id" }));
    await expect(argon).toContainText(/recommended/i);
    await expect(argon).toContainText(/default/i);

    // "Calibrate for this device measures your machine…"
    await expect(visible(page.getByRole("button", { name: /Calibrate for this device/i }))).toBeVisible();

    await visible(page.getByRole("button").filter({ hasText: "AES → ChaCha (chained)" })).click();

    // "The Effective configuration line at the bottom is the whole decision in
    // one string… it is what `inspect` will print back at you years from now."
    // recovery_test.py checks the other end of that sentence against the real
    // `inspect` output.
    // The parent, not the label: "Effective configuration:" is its own span and
    // the value sits beside it, so matching the text alone finds the caption
    // and none of the answer.
    const effective = visible(page.getByText(/^Effective configuration:/)).locator("xpath=..");
    await expect(effective).toContainText("Argon2id");
    await expect(effective).toContainText("AES+ChaCha");
  });

  test("step 3 — the app states a policy floor and refuses to score the password", async ({ page }) => {
    await page.goto("/");
    await useTextMode(page);
    await visible(page.getByPlaceholder("Enter text to encrypt")).fill(SECRET);
    await visible(page.getByPlaceholder("Enter a strong password")).fill(PASSWORD);

    // The page quotes this line and builds a paragraph on it. KM-02 is the
    // reason it reads the way it does, so a regression to a strength score
    // would make the walkthrough's argument false as well as the UI wrong.
    const policy = page.getByText(/floor, not a strength rating/i).first();
    await expect(policy).toBeVisible();
    await expect(policy).toContainText(/cannot tell how you chose/i);

    // "use Random or Passphrase — those it generated, so it knows the entropy."
    await expect(visible(page.getByRole("button", { name: /^Random$/ }))).toBeVisible();
    await expect(visible(page.getByRole("button", { name: /^Passphrase$/ }))).toBeVisible();
  });

  test("step 4 and part 2 — encrypt, then prove it opens without revealing it", async ({ page }) => {
    await page.goto("/");
    await useTextMode(page);
    await visible(page.getByPlaceholder("Enter text to encrypt")).fill(SECRET);
    await visible(page.getByPlaceholder("Enter a strong password")).fill(PASSWORD);

    await visible(page.getByRole("button", { name: /^Advanced/ })).click();
    await visible(page.getByRole("button").filter({ hasText: "Argon2id" })).click();
    await visible(page.getByRole("button").filter({ hasText: "AES → ChaCha (chained)" })).click();
    await visible(page.getByRole("button", { name: /^Advanced/ })).click();

    await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();
    await page.waitForFunction(
      () => {
        const el = document.querySelector("#output-text") as HTMLTextAreaElement | null;
        return !!el && el.value.startsWith("keym2:");
      },
      null,
      { timeout: 90_000 }
    );

    // "What comes back starts with keym2:".
    const container = await page.evaluate(
      () => (document.querySelector("#output-text") as HTMLTextAreaElement).value
    );
    expect(container.startsWith("keym2:")).toBe(true);

    // ---- Part 2: verify-only ----
    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);
    await visible(page.getByPlaceholder("Enter text to decrypt")).fill(container);
    await visible(page.getByPlaceholder("Enter decryption password")).fill(PASSWORD);
    await visible(page.getByLabel(/Verify only/i)).click();
    await visible(page.getByRole("button", { name: /^Verify Text$/i })).click();

    const verdict = visible(page.getByRole("status").filter({ hasText: /backup opens/i }));
    await expect(verdict).toBeVisible({ timeout: 90_000 });

    // "Read the size. The panel nudges you about this for a reason" — and the
    // page quotes the nudge verbatim, so it has to still be there.
    await expect(verdict).toContainText(/\d+\s*bytes/i);
    await expect(verdict).toContainText(/right password on the wrong backup still verifies/i);

    // "decrypts, authenticates, and throws the plaintext away without
    // rendering it". The claim the whole section rests on.
    const body = await page.evaluate(() => document.body.innerText);
    expect(body, "verify-only rendered the secret the page promises to withhold").not.toContain(
      "4471-0092"
    );
  });

  test("the walkthrough is reachable from the documents that should point at it", async () => {
    // Not a browser assertion, but it belongs with the others: a walkthrough
    // nothing links to is a file in a repository, not documentation.
    const { readFileSync } = await import("node:fs");
    const { join } = await import("node:path");
    for (const doc of ["README.md", "docs/RECOVERY.md"]) {
      const text = readFileSync(join(process.cwd(), doc), "utf8");
      expect(text, `${doc} does not link to the walkthrough`).toContain("WALKTHROUGH.md");
    }
  });
});
