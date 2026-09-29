import { test, expect, type Page } from "@playwright/test";
import { visible, useTextMode, selectCrypto, encryptText, STRONG_PASSWORD } from "./helpers";

/**
 * A verify result belongs to what it checked (roadmap Section 06, part d).
 *
 * "The backup opens with this password" used to stay on screen until a wipe
 * or the next run, beside whatever was loaded or typed afterwards. Here each
 * change is made after a successful verify and the green result must give way
 * to a notice naming it, with no format line of the old backup falling
 * through. Putting the checked input back brings the result back, because it
 * is true again, which is also what shows the notice is not a blanket reset.
 */

const SECRET = "verify-evidence synthetic secret, not a real one";
const ok = (page: Page) => page.getByTestId("verify-result");
const stale = (page: Page) => page.getByTestId("verify-stale");
const box = (page: Page) => visible(page.getByPlaceholder("Enter text to decrypt"));
const passwordField = (page: Page) => visible(page.getByPlaceholder("Enter decryption password"));

/** Seal two different backups, then verify the first one on the Decrypt tab. */
async function verifyFirstOfTwo(page: Page): Promise<[string, string]> {
  await page.goto("/");
  await useTextMode(page);
  await selectCrypto(page, "pbkdf2", "aes");
  const first = await encryptText(page, SECRET, STRONG_PASSWORD);
  // A second seal, waited on until the output is a new container rather than
  // the first one still on screen.
  await visible(page.getByPlaceholder("Enter text to encrypt")).fill(`${SECRET} (second)`);
  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
  await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();
  const output = visible(page.locator("#output-text"));
  await expect(output).not.toHaveValue(first, { timeout: 60_000 });
  await expect(output).toHaveValue(/^keym2:/, { timeout: 60_000 });
  const second = await output.inputValue();

  await visible(page.getByRole("tab", { name: "Decrypt" })).click();
  await useTextMode(page);
  await box(page).fill(first);
  await passwordField(page).fill(STRONG_PASSWORD);
  const toggle = visible(page.getByLabel(/Verify only/i));
  if (!(await toggle.isChecked())) await toggle.click();
  await visible(page.getByRole("button", { name: /^Verify Text$/i })).click();
  await expect(visible(ok(page))).toContainText("The backup opens with this password", { timeout: 60_000 });
  await expect(stale(page)).toHaveCount(0);
  return [first, second];
}

test("another backup in the box takes the result down, and the original brings it back", async ({ page }) => {
  const [first, second] = await verifyFirstOfTwo(page);

  await box(page).fill(second);
  await expect(visible(stale(page))).toContainText("Changed since: backup");
  await expect(ok(page)).toHaveCount(0);
  // The old backup's format line is not shown in its place.
  await expect(page.getByText(/^Format: KEYM/)).toHaveCount(0);

  await box(page).fill(first);
  await expect(visible(ok(page))).toContainText("The backup opens with this password");
  await expect(stale(page)).toHaveCount(0);
});

test("a password typed after the check is not what was checked", async ({ page }) => {
  await verifyFirstOfTwo(page);
  // A successful check clears the field, so this is a new attempt.
  await expect(passwordField(page)).toHaveValue("");

  await passwordField(page).fill("a different password entirely, 2026");
  await expect(visible(stale(page))).toContainText("Changed since: credentials");
  await expect(ok(page)).toHaveCount(0);

  await passwordField(page).fill("");
  await expect(visible(ok(page))).toBeVisible();
});

test("switching to recovery shares is a different way in", async ({ page }) => {
  await verifyFirstOfTwo(page);
  await visible(page.getByRole("button", { name: /^Use recovery shares$/ })).click();
  await expect(visible(stale(page))).toContainText("unlock method");
  await expect(ok(page)).toHaveCount(0);
});
