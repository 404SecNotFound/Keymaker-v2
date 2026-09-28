import { test, expect, type Page } from "@playwright/test";
import { visible, useTextMode, selectCrypto, STRONG_PASSWORD } from "./helpers";

/**
 * What the page says about the backup on screen, and when it stops saying it
 * (roadmap Section 06).
 *
 * The receipt, the Recovery tab and the rule shown before creation are claims
 * about a specific backup. These tests hold each claim to the backup it
 * describes:
 *
 *  - before creation, the exact AND/OR rule is on screen and follows the form;
 *  - starting a new job takes the old receipt down at once, and a Stop or a
 *    failure does not bring it back;
 *  - once the form moves on, the receipt says what changed rather than
 *    reading as a description of the form;
 *  - a download or print is recorded as started, not as saved.
 */

const SECRET = "workflow-evidence synthetic secret, not a real one";

async function openAdvanced(page: Page) {
  const advanced = visible(page.getByRole("button", { name: /^Advanced/ }));
  if ((await advanced.getAttribute("aria-expanded")) !== "true") await advanced.click();
  await expect(advanced).toHaveAttribute("aria-expanded", "true");
}

async function enableShares(page: Page, k: number, n: number) {
  await openAdvanced(page);
  const sharesSwitch = visible(page.getByRole("switch", { name: "Recovery shares" }));
  await expect(async () => {
    if ((await sharesSwitch.getAttribute("aria-checked")) !== "true") await sharesSwitch.click();
    await expect(sharesSwitch).toHaveAttribute("aria-checked", "true", { timeout: 1_000 });
  }).toPass({ timeout: 20_000 });
  await visible(page.getByLabel("Shares to print")).fill(String(n));
  await visible(page.getByLabel("Needed to open")).fill(String(k));
}

/** Seal SECRET in Text mode with PBKDF2 (the KDF is not under test). */
async function seal(page: Page) {
  await page.goto("/");
  await useTextMode(page);
  await selectCrypto(page, "pbkdf2", "aes");
  await visible(page.getByPlaceholder("Enter text to encrypt")).fill(SECRET);
  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
  await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();
  await expect(visible(page.getByTestId("seal-receipt"))).toBeVisible({ timeout: 60_000 });
}

const rule = (page: Page) => visible(page.getByTestId("access-rule"));

test("the exact access rule is shown before creation and follows the form", async ({ page }) => {
  await page.goto("/");
  await useTextMode(page);
  await expect(rule(page)).toHaveText("Opens with: Passphrase");

  await enableShares(page, 2, 3);
  await expect(rule(page)).toHaveText("Opens with: Passphrase or 2-of-3 recovery shares");

  const needsPassword = visible(page.locator("#shares-need-password"));
  await needsPassword.click();
  await expect(needsPassword).toHaveAttribute("aria-checked", "true");
  await expect(rule(page)).toHaveText("Opens with: Passphrase and 2-of-3 recovery shares, both needed");

  // And the receipt, afterwards, uses the same words for the same backup.
  await visible(page.getByPlaceholder("Enter text to encrypt")).fill(SECRET);
  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
  await selectCrypto(page, "pbkdf2", "aes");
  await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();
  await expect(visible(page.getByTestId("receipt-ways"))).toHaveText(
    "Passphrase and 2-of-3 recovery shares, both needed",
    { timeout: 60_000 }
  );
});

test("a new job takes the old receipt down at once, and a Stop does not bring it back", async ({ page }) => {
  await seal(page);

  // A second job, slow enough to be caught in flight.
  await openAdvanced(page);
  await visible(page.getByRole("button").filter({ hasText: "Argon2id" })).click();
  await visible(page.getByLabel("Argon2id memory")).fill("256");
  await visible(page.getByLabel("Argon2id time cost")).fill("10");
  await visible(page.getByPlaceholder("Enter text to encrypt")).fill(`${SECRET} (second)`);
  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
  await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();
  await expect(page.locator(".animate-spin").first(), "the second job never started").toBeVisible({ timeout: 20_000 });

  await expect(page.getByTestId("seal-receipt"), "the old receipt stayed up while a new job ran").toHaveCount(0);

  await visible(page.getByTestId("cancel-operation")).click();
  await expect(page.locator(".animate-spin")).toHaveCount(0, { timeout: 15_000 });
  await page.waitForTimeout(2_000);
  await expect(page.getByTestId("seal-receipt"), "a stopped job brought a receipt back").toHaveCount(0);

  await visible(page.getByRole("tab", { name: "Recovery", exact: true })).click();
  await expect(page.getByText(/No newly created backup/)).toBeVisible();
});

test("once the form moves on, the receipt says what changed", async ({ page }) => {
  await seal(page);
  const stale = page.getByTestId("receipt-stale");
  await expect(stale, "a freshly sealed receipt was marked stale").toHaveCount(0);

  // A setting.
  await selectCrypto(page, "pbkdf2", "chacha");
  await expect(visible(stale)).toContainText("Changed since this backup was made: cipher");
  // Put it back, and the receipt describes the form again.
  await selectCrypto(page, "pbkdf2", "aes");
  await expect(stale).toHaveCount(0);

  // The access rule.
  await enableShares(page, 2, 3);
  await expect(visible(stale)).toContainText("access rule");

  // New content.
  await visible(page.getByPlaceholder("Enter text to encrypt")).fill("something else");
  await expect(visible(stale)).toContainText("content");

  // The Recovery tab says the same.
  await visible(page.getByRole("tab", { name: "Recovery", exact: true })).click();
  await expect(visible(page.getByTestId("recovery-stale"))).toContainText("access rule");
});

test("a download is recorded as started, not as saved", async ({ page }) => {
  await seal(page);
  await visible(page.getByRole("tab", { name: "Recovery", exact: true })).click();
  const saved = visible(page.getByTestId("recovery-saved-copy"));
  await expect(saved).toContainText("Not saved yet");

  await visible(page.getByRole("tab", { name: "Encrypt", exact: true })).click();
  const download = page.waitForEvent("download");
  await visible(page.getByRole("button", { name: /Download \.keym/ })).click();
  await download;

  await visible(page.getByRole("tab", { name: "Recovery", exact: true })).click();
  await expect(saved).toContainText(/Download started at \d{1,2}[:.]\d{2}/);
  await expect(saved).toContainText("does not tell this page whether the file was kept");
  await expect(saved).not.toContainText("Not saved yet");
});
