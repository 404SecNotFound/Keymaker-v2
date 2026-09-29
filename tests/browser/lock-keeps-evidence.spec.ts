import { test, expect, type Page } from "@playwright/test";
import { visible, useTextMode, selectCrypto, STRONG_PASSWORD } from "./helpers";

/**
 * The auto-lock and the evidence about a backup (roadmap Section 06, part f).
 *
 * The lock spares issued shares, because they exist once and someone may be
 * copying them onto paper. It used to clear everything else about the backup
 * they open: the receipt, the steps and a passed rehearsal. The dialog then
 * showed strips for a backup the rest of the page no longer described.
 *
 * With shares on screen the lock now keeps that evidence and still clears the
 * secrets. Without shares it still clears the backup, which the second test
 * pins so the change cannot quietly widen.
 */

const SECRET = "lock-evidence synthetic secret, not a real one";
const dialog = (page: Page) => page.getByRole("dialog");
const step = (page: Page, id: string) => page.getByTestId("workflow-steps").locator(`li[data-step="${id}"]`);

async function sealText(page: Page, withShares: boolean) {
  await page.clock.install();
  await page.goto("/");
  await useTextMode(page);
  await selectCrypto(page, "pbkdf2", "aes");
  if (withShares) {
    const advanced = visible(page.getByRole("button", { name: /^Advanced/ }));
    if ((await advanced.getAttribute("aria-expanded")) !== "true") await advanced.click();
    const sharesSwitch = visible(page.getByRole("switch", { name: "Recovery shares" }));
    await expect(async () => {
      if ((await sharesSwitch.getAttribute("aria-checked")) !== "true") await sharesSwitch.click();
      await expect(sharesSwitch).toHaveAttribute("aria-checked", "true", { timeout: 1_000 });
    }).toPass({ timeout: 20_000 });
    await visible(page.getByLabel("Shares to print")).fill("3");
    await visible(page.getByLabel("Needed to open")).fill("2");
  }
  await visible(page.getByPlaceholder("Enter text to encrypt")).fill(SECRET);
  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
  await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();
}

test("with shares on screen, the lock keeps the receipt, the steps and a passed rehearsal", async ({ page }) => {
  await sealText(page, true);
  await expect(dialog(page).getByText(/Save these 3 shares now/)).toBeVisible({ timeout: 90_000 });
  const shares = (await dialog(page).getByText(/^KMSHARE2:/).allTextContents()).map((s) => s.trim());
  await dialog(page).getByRole("button", { name: /Rehearse now/ }).click();
  await dialog(page).getByLabel("Strips to rehearse with").fill(`${shares[0]}\n${shares[2]}`);
  await dialog(page).getByRole("button", { name: /^Open with these strips$/ }).click();
  await expect(dialog(page).getByTestId("rehearsal-result")).toContainText(/Opened in/, { timeout: 60_000 });

  // Nothing touched for longer than the lock allows. The warning shows first,
  // then goes without a click: that is the lock firing. (Its toast is on a
  // timer of its own, which the fake clock runs past, so it is not the proof.)
  await page.clock.runFor("04:40");
  await expect(page.getByRole("button", { name: /Keep open/i }).first()).toBeAttached();
  await page.clock.runFor("00:50");
  await expect(page.getByRole("button", { name: /Keep open/i })).toHaveCount(0);
  // The shares were spared, as before.
  await expect(dialog(page).getByText(/^KMSHARE2:/)).toHaveCount(3);

  await page.getByRole("button", { name: "I have saved these shares" }).click();
  await expect(visible(page.getByTestId("seal-receipt")), "the lock cleared the receipt the shares belong to").toBeVisible();
  await expect(step(page, "create")).toHaveAttribute("data-state", "done");
  await expect(step(page, "recovery"), "the lock cleared the rehearsal the owner just passed").toHaveAttribute(
    "data-state",
    "done"
  );
  await visible(page.getByRole("tab", { name: "Recovery", exact: true })).click();
  await expect(page.getByText(/No newly created backup/)).toHaveCount(0);
  await expect(visible(page.getByTestId("recovery-test"))).toContainText("Rehearsed on");
});

test("without shares on screen, the lock still clears the backup", async ({ page }) => {
  await sealText(page, false);
  await expect(visible(page.getByTestId("seal-receipt"))).toBeVisible({ timeout: 60_000 });

  await page.clock.runFor("04:40");
  await expect(page.getByRole("button", { name: /Keep open/i }).first()).toBeAttached();
  await page.clock.runFor("00:50");
  await expect(page.getByRole("button", { name: /Keep open/i })).toHaveCount(0);
  await expect(page.getByTestId("seal-receipt")).toHaveCount(0);
  await expect(visible(page.locator('[data-testid="workflow-steps"] li[data-step="create"]'))).not.toHaveAttribute(
    "data-state",
    "done"
  );
  await visible(page.getByRole("tab", { name: "Recovery", exact: true })).click();
  await expect(visible(page.getByText(/No newly created backup/))).toBeVisible();
});
