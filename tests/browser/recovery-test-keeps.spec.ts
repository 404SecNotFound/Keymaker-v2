import { test, expect, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { visible, useTextMode, selectCrypto, encryptText, STRONG_PASSWORD } from "./helpers";

/**
 * Testing a backup must not destroy it (roadmap Section 06, part e).
 *
 * The Recovery tab's tests switch to the Decrypt tab, and a tab switch used
 * to reset the form, taking the receipt, the steps and, in Text mode, the
 * page's only copy of the container with it. Here the backup survives the
 * round trip, and a verify of this exact backup is recorded as evidence: a
 * recovery test, and a saved-copy check when the bytes came from a file.
 *
 * The negative case is in the same file: a verify that opens a *different*
 * backup is still a green verify on the Decrypt tab, and must count for
 * nothing here. That is what shows the match is on the bytes.
 */

const SECRET = "recovery-test synthetic secret, not a real one";
const step = (page: Page, id: string) => page.getByTestId("workflow-steps").locator(`li[data-step="${id}"]`);
const tab = (page: Page, name: string) => visible(page.getByRole("tab", { name, exact: true }));

async function seal(page: Page): Promise<string> {
  await page.goto("/");
  await useTextMode(page);
  await selectCrypto(page, "pbkdf2", "aes");
  return encryptText(page, SECRET, STRONG_PASSWORD);
}

async function verifyOnDecrypt(page: Page) {
  await visible(page.getByPlaceholder("Enter decryption password")).fill(STRONG_PASSWORD);
  const toggle = visible(page.getByLabel(/Verify only/i));
  if (!(await toggle.isChecked())) await toggle.click();
  await expect(toggle).toBeChecked();
  await visible(page.getByRole("button", { name: /^Verify (Text|File)$/i })).click();
  await expect(visible(page.getByTestId("verify-result"))).toContainText("The backup opens with this password", {
    timeout: 60_000,
  });
}

test("testing from the Recovery tab keeps the backup, and counts as a recovery test", async ({ page }) => {
  const armored = await seal(page);

  await tab(page, "Recovery").click();
  await visible(page.getByRole("button", { name: /Verify with password/ })).click();
  await expect(visible(page.getByPlaceholder("Enter text to decrypt"))).toHaveValue(armored);
  await verifyOnDecrypt(page);

  // The Recovery tab still describes the backup, now tested.
  await tab(page, "Recovery").click();
  await expect(page.getByText(/No newly created backup/)).toHaveCount(0);
  await expect(visible(page.getByTestId("recovery-test"))).toContainText(/Verified with the password at \d{1,2}[:.]\d{2}/);

  // And the Encrypt tab has it back as it was: receipt, container, steps.
  await tab(page, "Encrypt").click();
  await expect(visible(page.getByTestId("seal-receipt"))).toBeVisible();
  await expect(page.getByTestId("receipt-stale"), "a tab switch read as a change to the form").toHaveCount(0);
  await expect(visible(page.locator("#output-text"))).toHaveValue(armored);
  await expect(step(page, "create")).toHaveAttribute("data-state", "done");
  await expect(step(page, "recovery")).toHaveAttribute("data-state", "done");
  // The page pasted its own copy, so nothing says a saved copy was checked.
  await expect(step(page, "saved-copy")).not.toHaveAttribute("data-state", "done");
});

test("verifying the downloaded file checks the saved copy", async ({ page }) => {
  await seal(page);
  const download = page.waitForEvent("download");
  await visible(page.getByRole("button", { name: /Download \.keym/ })).click();
  const saved = readFileSync((await (await download).path())!);

  await tab(page, "Decrypt").click();
  await page.locator("#decrypt-file").setInputFiles({ name: "backup.keym", mimeType: "application/octet-stream", buffer: saved });
  await verifyOnDecrypt(page);

  await tab(page, "Encrypt").click();
  await expect(step(page, "saved-copy")).toHaveAttribute("data-state", "done");
  await expect(page.getByTestId("workflow-step-detail")).not.toContainText("Check saved copy.");
  await expect(step(page, "recovery")).toHaveAttribute("data-state", "done");
  await tab(page, "Recovery").click();
  await expect(visible(page.getByTestId("recovery-saved-copy"))).toContainText("matched this backup byte for byte");
});

test("a verify of a different backup counts for nothing", async ({ page }) => {
  const earlier = await seal(page);
  // A second backup replaces the first; the first is now someone else's.
  await visible(page.getByPlaceholder("Enter text to encrypt")).fill(`${SECRET} (second)`);
  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
  await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();
  await expect(visible(page.locator("#output-text"))).not.toHaveValue(earlier, { timeout: 60_000 });
  await expect(visible(page.getByTestId("seal-receipt"))).toBeVisible();

  await tab(page, "Decrypt").click();
  await useTextMode(page);
  await visible(page.getByPlaceholder("Enter text to decrypt")).fill(earlier);
  await verifyOnDecrypt(page);

  await tab(page, "Encrypt").click();
  await expect(visible(page.getByTestId("seal-receipt"))).toBeVisible();
  await expect(step(page, "recovery")).not.toHaveAttribute("data-state", "done");
  await tab(page, "Recovery").click();
  await expect(visible(page.getByTestId("recovery-test"))).toHaveText("Not tested yet in this session");
});

test("a wipe still takes the backup", async ({ page }) => {
  await seal(page);
  await tab(page, "Decrypt").click();
  await tab(page, "Encrypt").click();
  await expect(visible(page.getByTestId("seal-receipt"))).toBeVisible();
  await visible(page.getByRole("button", { name: /Wipe now/ })).click();
  await expect(page.getByTestId("seal-receipt")).toHaveCount(0);
  await tab(page, "Recovery").click();
  await expect(visible(page.getByText(/No newly created backup/))).toBeVisible();
});
