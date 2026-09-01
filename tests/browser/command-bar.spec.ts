import { test, expect, type Page } from "@playwright/test";
import { visible } from "./helpers";

/**
 * The command bar (⌘K / Ctrl+K).
 *
 * Two properties matter enough to pin. First, the bar adds reach, not
 * capability: every command calls a handler a button already calls, so these
 * tests assert *page state* after a command runs — the tab that switched, the
 * password that appeared, the field that emptied — never merely that a dialog
 * flashed. A palette whose commands silently did nothing would pass any test
 * that stopped at "it opened".
 *
 * Second, the list is contextual. "Wipe now" exists only while there is
 * something to wipe, and the test proves both halves: absent on a clean page,
 * present once a secret exists, and *effective* when run. The absent half is
 * the negative control for the present half — a palette that listed
 * everything unconditionally would fail it.
 */

const openBar = async (page: Page) => {
  await page.keyboard.press("Control+k");
  await expect(page.getByRole("dialog", { name: "Command menu" })).toBeVisible();
};

const commandInput = (page: Page) => page.getByRole("combobox", { name: "Filter commands" });

test.beforeEach(async ({ page }) => {
  await page.goto("/");
});

test("Ctrl+K opens the command menu, Escape closes it, Ctrl+K again reopens", async ({ page }) => {
  const dialog = page.getByRole("dialog", { name: "Command menu" });
  await expect(dialog).toBeHidden();

  await openBar(page);
  await expect(commandInput(page)).toBeFocused();

  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();

  // The same chord toggles — a second press must not be eaten by the first
  // dialog's teardown.
  await openBar(page);
});

test("the header hint opens it with a click", async ({ page }) => {
  await page.getByTestId("command-bar-hint").click();
  await expect(page.getByRole("dialog", { name: "Command menu" })).toBeVisible();
});

test("typing filters and Enter runs the first match — switching to Decrypt", async ({ page }) => {
  await expect(page.getByRole("tab", { name: "Encrypt" })).toHaveAttribute("aria-selected", "true");

  await openBar(page);
  await commandInput(page).fill("decry");
  await page.keyboard.press("Enter");

  await expect(page.getByRole("dialog", { name: "Command menu" })).toBeHidden();
  await expect(page.getByRole("tab", { name: "Decrypt" })).toHaveAttribute("aria-selected", "true");
});

test("the arrow keys move the selection — the second Go-to entry is Tools", async ({ page }) => {
  await openBar(page);
  // On the encrypt tab the list opens on [Decrypt, Tools, …]; one step down
  // and Enter must land on Tools, or the active row and the run row have
  // come apart — the exact failure aria-activedescendant wiring can hide.
  await page.keyboard.press("ArrowDown");
  await page.keyboard.press("Enter");

  await expect(page.getByRole("tab", { name: "Tools" })).toHaveAttribute("aria-selected", "true");
});

test("a command reaches the real handler — the passphrase generator fills the field", async ({ page }) => {
  await openBar(page);
  await commandInput(page).fill("passphrase");
  await page.keyboard.press("Enter");

  // Seven words from the EFF list, space-separated. Asserting the shape of
  // the value, not just non-emptiness: a handler that ran but wrote the
  // wrong thing should not pass.
  const password = visible(page.getByPlaceholder("Enter a strong password"));
  await expect(password).toHaveValue(/^[a-z]+( [a-z]+){6}$/);
});

test("Wipe now is offered only while something needs wiping, and it wipes", async ({ page }) => {
  // Clean page: no secrets, so no wipe command — however it is searched for.
  await openBar(page);
  await commandInput(page).fill("wipe");
  await expect(page.getByRole("option", { name: /Wipe now/ })).toBeHidden();
  await expect(page.getByText("No command matches")).toBeVisible();
  await page.keyboard.press("Escape");

  // A typed password is a secret on screen; now the command must exist.
  const password = visible(page.getByPlaceholder("Enter a strong password"));
  await password.fill("correct horse battery staple over the treetops");

  await openBar(page);
  await commandInput(page).fill("wipe");
  await page.getByRole("option", { name: /Wipe now/ }).click();

  await expect(password).toHaveValue("");
});

test("an unmatched query says so, and Enter on nothing does nothing", async ({ page }) => {
  await openBar(page);
  await commandInput(page).fill("zzzz-no-such-command");
  await expect(page.getByText(/No command matches/)).toBeVisible();

  await page.keyboard.press("Enter");
  // Still open: an empty list must make Enter inert, not run some stale
  // selection from before the filter emptied it.
  await expect(page.getByRole("dialog", { name: "Command menu" })).toBeVisible();

  // The tab is checked after closing, not through the open dialog: Radix
  // marks everything outside a modal aria-hidden, so while the palette is up
  // the tab has no accessible role to find — the same fact LockWarning's
  // comment records from the other direction.
  await page.keyboard.press("Escape");
  await expect(page.getByRole("tab", { name: "Encrypt" })).toHaveAttribute("aria-selected", "true");
});
