import { test, expect, type Page } from "@playwright/test";
import { visible, STRONG_PASSWORD } from "./helpers";

/**
 * Roadmap 4.5, the inheritance plan.
 *
 * The plan adds no capability: it is guidance that turns on recovery shares and
 * points at controls already on the encrypt form. So these tests assert *page
 * state* the plan is supposed to produce: the switch that came on, the numbers
 * the warning names, the shares the encrypt actually issued, never merely that
 * a panel appeared. A plan that rendered its prose and wired nothing would pass
 * any test that stopped at "it is visible".
 *
 * Each test carries its own negative control:
 *   - the plan is absent until it is opened (the panel is not furniture);
 *   - the warning names the live k of n, so a hardcoded string fails once the
 *     count changes;
 *   - a tab switch ends it, so a flag that never cleared fails;
 *   - encrypting issues the shares, so a plan that did not turn them on fails.
 */

const plan = (page: Page) => page.getByTestId("inheritance-plan");
const sharesSwitch = (page: Page) =>
  visible(page.getByRole("switch", { name: "Recovery shares" }));

test.beforeEach(async ({ page }) => {
  await page.goto("/");
});

test("the plan is not on the page until it is opened, and opening it turns shares on", async ({ page }) => {
  // Negative control for everything below: nothing inheritance-shaped is on a
  // clean page. A panel that rendered unconditionally would fail here.
  await expect(plan(page)).toBeHidden();

  await page.getByTestId("inheritance-open").click();

  await expect(plan(page)).toBeVisible();
  // The point of the plan: it configured the form. Recovery shares are on, and
  // Advanced, where their controls live, is open.
  await expect(sharesSwitch(page)).toBeChecked();
  await expect(
    visible(page.getByRole("button", { name: /^Advanced/ }))
  ).toHaveAttribute("aria-expanded", "true");
});

test("the warning names the live k of n, not a fixed string", async ({ page }) => {
  await page.getByTestId("inheritance-open").click();

  const warning = page.getByTestId("inheritance-warning");
  await expect(warning).toContainText("any 2 of the 3 shares");
  await expect(warning).toContainText("as sensitive as the password itself");

  // Change the count on the form the plan pointed at. If the warning's number
  // were a literal, it would still read "3": the control that catches a plan
  // describing a share set the user is no longer making.
  await visible(page.locator("#shamir-count")).fill("4");
  await expect(warning).toContainText("any 2 of the 4 shares");
});

test("the command bar reaches the plan (reach, not a second capability)", async ({ page }) => {
  await page.keyboard.press("Control+k");
  await expect(page.getByRole("dialog", { name: "Command menu" })).toBeVisible();
  await page.getByRole("combobox", { name: "Filter commands" }).fill("inherit");
  await page.keyboard.press("Enter");

  await expect(plan(page)).toBeVisible();
  await expect(sharesSwitch(page)).toBeChecked();
});

test("a tab switch ends the plan", async ({ page }) => {
  await page.getByTestId("inheritance-open").click();
  await expect(plan(page)).toBeVisible();

  await visible(page.getByRole("tab", { name: "Decrypt" })).click();
  await visible(page.getByRole("tab", { name: "Encrypt" })).click();

  // The plan belonged to a deliberate encrypt-and-hand-on session; a tab click
  // ends it the same way it resets the form. A flag that outlived the reset
  // would leave the panel up here.
  await expect(plan(page)).toBeHidden();
});

test("dismissing hides the guidance but keeps the shares configured", async ({ page }) => {
  await page.getByTestId("inheritance-open").click();
  await expect(sharesSwitch(page)).toBeChecked();

  await page.getByRole("button", { name: "Hide the inheritance plan" }).click();

  await expect(plan(page)).toBeHidden();
  // Dismiss hides the instructions; it does not undo a choice the user has made.
  // The shares the plan turned on stay on.
  await expect(sharesSwitch(page)).toBeChecked();
});

test("following the plan, encrypting issues the heir's shares", async ({ page }) => {
  await page.getByTestId("inheritance-open").click();
  await expect(sharesSwitch(page)).toBeChecked();

  await visible(page.getByRole("button", { name: "Text", exact: true })).click();
  await visible(page.getByPlaceholder("Enter text to encrypt")).fill(
    "the vault code is 4417 and the will is with Naz"
  );
  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
  await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();

  // The composition proof: the plan turned on a 2-of-3 set, so a real encrypt
  // produces the issued-shares dialog with three shares. A plan that only
  // rendered guidance would land on an ordinary container and no dialog.
  const dialog = page.getByRole("dialog", { name: /Save these 3 shares now/ });
  await expect(dialog).toBeVisible({ timeout: 90_000 });
  await expect(dialog.getByText(/^KMSHARE1:/).first()).toBeVisible();
  await expect(dialog.getByText(/^KMSHARE1:/)).toHaveCount(3);
});
