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
  await visible(page.getByPlaceholder("Enter a strong password")).fill("correct horse battery staple over the treetops");
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
  const password = visible(page.getByPlaceholder("Enter a strong password"));
  await password.fill("correct horse battery staple over the treetops");

  // Hidden for longer than the lock allows, with no timer allowed to run:
  // `setSystemTime` moves the wall clock without firing the interval, which
  // is exactly what a frozen tab looks like.
  await setVisibility(page, "hidden");
  const now = await page.evaluate(() => Date.now());
  await page.clock.setSystemTime(now + 6 * 60_000);
  await expect(password).toHaveValue(/./);

  await setVisibility(page, "visible");
  await expect(password).toHaveValue("");
});

test("a short absence does not lock", async ({ page }) => {
  await page.clock.install();
  await page.goto("/");
  const password = visible(page.getByPlaceholder("Enter a strong password"));
  await password.fill("correct horse battery staple over the treetops");

  await setVisibility(page, "hidden");
  const now = await page.evaluate(() => Date.now());
  await page.clock.setSystemTime(now + 60_000);
  await setVisibility(page, "visible");
  await expect(password).toHaveValue(/./);
});
