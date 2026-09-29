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
 * secrets.
 *
 * Decided afterwards: without shares the lock also keeps an unsaved Text-mode
 * backup, which is the page's only copy of the container. The container is
 * ciphertext. The rest of the file pins the edges of that decision: decrypted
 * output is never kept, the timer does not re-arm for the container alone,
 * and a File-mode backup, already downloaded, is still cleared.
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

/** Nothing touched for longer than the lock allows: the warning, then the lock. */
async function idleUntilLocked(page: Page) {
  await page.clock.runFor("04:40");
  await expect(page.getByRole("button", { name: /Keep open/i }).first()).toBeAttached();
  await page.clock.runFor("00:50");
  await expect(page.getByRole("button", { name: /Keep open/i })).toHaveCount(0);
}

const output = (page: Page) => visible(page.locator("#output-text"));

/**
 * Nothing warns within the next 4:40. Read once, after a real second for
 * React to draw anything the fake clock just triggered. Not `toHaveCount(0)`:
 * it retries, the page's clock keeps running, and a warning that is there
 * goes away when its lock fires, so the retry passes.
 */
async function expectNoLockWarning(page: Page, message: string) {
  await page.clock.runFor("04:40");
  await page.waitForTimeout(1_000);
  expect(await page.getByRole("button", { name: /Keep open/i }).count(), message).toBe(0);
}

/**
 * Sealing clears the plaintext and the password, so afterwards only the
 * container is on screen and there is nothing for the lock to clear. A
 * password typed for the next backup is a secret again, and arms it.
 */
async function typeNextPassword(page: Page) {
  await visible(page.getByPlaceholder("Enter a strong password")).fill("a password for the next backup");
}

/** Is `text` in any text box on the page, visible or not? */
const onPage = (page: Page, text: string) =>
  page.evaluate((t) => [...document.querySelectorAll("textarea, input")].some((el) => (el as HTMLInputElement).value.includes(t)), text);

test("without shares, the lock keeps an unsaved Text backup and clears the secrets", async ({ page }) => {
  await sealText(page, false);
  await expect(visible(page.getByTestId("seal-receipt"))).toBeVisible({ timeout: 60_000 });
  await expect(output(page)).toHaveValue(/^keym2:/);
  const armored = await output(page).inputValue();

  // Only the container is on screen: nothing to lock, so no warning comes.
  // 4:40 is inside the warning window; a lock that had fired by 5:30 would
  // already have taken its warning away.
  await expectNoLockWarning(page, "the lock's timer counts the container it keeps");
  await page.clock.runFor("01:00");
  await expect(output(page)).toHaveValue(armored);

  await typeNextPassword(page);
  await idleUntilLocked(page);
  // The secret went.
  await expect(visible(page.getByPlaceholder("Enter a strong password"))).toHaveValue("");
  // The backup stayed: the container, the receipt and the steps.
  await expect(output(page), "the lock cleared the only copy of an unsaved backup").toHaveValue(armored);
  await expect(visible(page.getByTestId("seal-receipt"))).toBeVisible();
  await expect(step(page, "create")).toHaveAttribute("data-state", "done");
  await visible(page.getByRole("tab", { name: "Recovery", exact: true })).click();
  await expect(page.getByText(/No newly created backup/)).toHaveCount(0);

  // With only the container left there is nothing to lock, so the timer
  // stays off instead of firing again every five minutes.
  await expectNoLockWarning(page, "the timer re-armed for a container the lock keeps");
  // A wipe is still offered, and still takes the backup.
  await visible(page.getByRole("tab", { name: "Encrypt", exact: true })).click();
  await visible(page.getByRole("button", { name: /Wipe now/ })).click();
  await expect(page.getByTestId("seal-receipt")).toHaveCount(0);
});

test("the lock never keeps decrypted output", async ({ page }) => {
  await sealText(page, false);
  await expect(output(page)).toHaveValue(/^keym2:/, { timeout: 60_000 });
  const armored = await output(page).inputValue();

  await visible(page.getByRole("tab", { name: "Decrypt", exact: true })).click();
  await useTextMode(page);
  await visible(page.getByPlaceholder("Enter text to decrypt")).fill(armored);
  await visible(page.getByPlaceholder("Enter decryption password")).fill(STRONG_PASSWORD);
  await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();
  await expect(output(page)).toHaveValue(SECRET, { timeout: 60_000 });

  await idleUntilLocked(page);
  expect(await onPage(page, SECRET), "the lock kept decrypted plaintext on screen").toBe(false);
  // Back on the Encrypt tab, the backup is still there.
  await visible(page.getByRole("tab", { name: "Encrypt", exact: true })).click();
  await expect(output(page)).toHaveValue(armored);
  await expect(visible(page.getByTestId("seal-receipt"))).toBeVisible();
});

test("a File-mode backup, already downloaded, is still cleared by the lock", async ({ page }) => {
  await page.clock.install();
  await page.goto("/");
  await selectCrypto(page, "pbkdf2", "aes");
  await visible(page.getByRole("button", { name: "File", exact: true })).click();
  await page.setInputFiles('input[type="file"]', {
    name: "notes.txt",
    mimeType: "text/plain",
    buffer: Buffer.from(SECRET),
  });
  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
  const download = page.waitForEvent("download", { timeout: 90_000 });
  await visible(page.getByRole("button", { name: /^Encrypt File$/i })).click();
  await download;
  await expect(visible(page.getByTestId("seal-receipt"))).toBeVisible({ timeout: 60_000 });

  await typeNextPassword(page);
  await idleUntilLocked(page);
  await expect(page.getByTestId("seal-receipt")).toHaveCount(0);
  await visible(page.getByRole("tab", { name: "Recovery", exact: true })).click();
  await expect(visible(page.getByText(/No newly created backup/))).toBeVisible();
});
