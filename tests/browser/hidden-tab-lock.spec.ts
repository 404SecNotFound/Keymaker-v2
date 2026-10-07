import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";
import { visible } from "./helpers";

/**
 * Two places a secret outlived the app's own hygiene.
 *
 * The dice validator's roll log is a wallet's entropy in the clear, in a
 * panel that is force-mounted, so Wipe now, the idle lock and a tab change
 * all left it in a hidden textarea until the page closed. And the idle lock
 * is driven by an interval that a hidden tab throttles and a cached tab
 * freezes, so a password left in a background tab outlived five minutes by
 * as long as the tab stayed hidden.
 *
 * `visibilitychange` is driven by hand: Playwright has no first-class way to
 * hide a page, and the handlers read `document.visibilityState`, so the
 * property is overridden before the event is dispatched.
 */

const ROLLS = "4 6 2 3 1 5 6 6 2 1 3 4 5 2 6 1 3 3 4 5";

async function setVisibility(page: Page, state: "hidden" | "visible") {
  await page.evaluate((value) => {
    Object.defineProperty(document, "visibilityState", { value, configurable: true });
    document.dispatchEvent(new Event("visibilitychange"));
  }, state);
}

const PASSWORD = "correct horse battery staple over the treetops";

/**
 * Type the password and wait until the app has taken it.
 *
 * `fill` waits for the field, not for React to own it. On WebKit under CI the
 * fill can land on the server-rendered input before hydration, and hydration
 * then puts the controlled value back to empty: the field reads "" and the app
 * never saw a secret, so there is nothing to lock or wipe and every assertion
 * below fails for a reason that has nothing to do with the lock. The
 * `aria-describedby` link to the password feedback is rendered by React only
 * when its own state holds a password, so it is the proof the fill registered.
 * Retried for the same reason inheritance.spec.ts retries its first click.
 */
async function typePassword(page: Page) {
  const password = visible(page.getByPlaceholder("Enter a strong password"));
  await expect(async () => {
    await password.fill(PASSWORD);
    await expect(password).toHaveAttribute("aria-describedby", "password-feedback", { timeout: 2_000 });
  }).toPass({ timeout: 30_000 });
  return password;
}

async function openRollLog(page: Page) {
  await page.goto("/");
  await visible(page.getByRole("tab", { name: "Tools" })).click();
  await visible(page.getByRole("button", { name: /Check a roll log/ })).click();
  const log = page.locator("#roll-log");
  await log.fill(ROLLS);
  await expect(log).toHaveValue(ROLLS);
  return log;
}

test("the dice roll log is cleared when the app wipes", async ({ page }) => {
  // Wipe now is offered only while the main form holds a secret, so the
  // password goes in first. Encrypt to Tools is the one tab change that does
  // not reset the form, so the password survives it and the wipe below is
  // the only thing that can clear the log.
  await page.goto("/");
  await typePassword(page);
  await visible(page.getByRole("tab", { name: "Tools" })).click();
  await visible(page.getByRole("button", { name: /Check a roll log/ })).click();
  const log = page.locator("#roll-log");
  await log.fill(ROLLS);
  await expect(log).toHaveValue(ROLLS);

  await page.keyboard.press("ControlOrMeta+k");
  await expect(page.getByRole("dialog", { name: "Command menu" })).toBeVisible();
  await page.getByRole("combobox", { name: "Filter commands" }).fill("wipe");
  await page.getByRole("option", { name: /Wipe now/ }).click();

  await expect(log).toHaveValue("");
});

test("the dice roll log is cleared when the tab is hidden", async ({ page }) => {
  const log = await openRollLog(page);
  await setVisibility(page, "hidden");
  await expect(log).toHaveValue("");
});

test("a password left in a hidden tab is locked on return once the idle period has passed", async ({ page }) => {
  await page.clock.install();
  await page.goto("/");
  const password = await typePassword(page);

  // Hidden for longer than the lock allows, with no timer allowed to run,
  // which is exactly what a frozen tab looks like. The clock is paused first:
  // `setSystemTime` alone moves the wall clock, but a running clock then fires
  // the one-second interval, which sees the elapsed time and locks by itself,
  // so the test passed with the return-from-hidden lock removed.
  await setVisibility(page, "hidden");
  const now = await page.evaluate(() => Date.now());
  await page.clock.pauseAt(now + 1_000);
  await page.clock.setSystemTime(now + 6 * 60_000);
  await expect(password).toHaveValue(/./);

  await setVisibility(page, "visible");
  await expect(password).toHaveValue("");
});

test("a short absence does not lock", async ({ page }) => {
  await page.clock.install();
  await page.goto("/");
  const password = await typePassword(page);

  await setVisibility(page, "hidden");
  const now = await page.evaluate(() => Date.now());
  await page.clock.pauseAt(now + 1_000);
  await page.clock.setSystemTime(now + 60_000);
  await setVisibility(page, "visible");
  await expect(password).toHaveValue(/./);
});
