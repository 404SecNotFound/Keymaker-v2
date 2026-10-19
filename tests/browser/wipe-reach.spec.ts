import { test, expect, type Page } from "@playwright/test";
import { visible, useTextMode, STRONG_PASSWORD } from "./helpers";

/**
 * Two holders of a secret that "Wipe now" did not reach.
 *
 * The clipboard: a copy arms a 60-second overwrite, and a wipe inside that
 * minute cleared every holder on the page and left the clipboard as it was,
 * while the toast said the secrets were cleared. The camera scanner: an open
 * dialog holds every strip it has read, and the wipe did not close it.
 *
 * The controls bite: with the clipboard overwrite removed from
 * `clearSensitiveState`, the copy outlives the wipe for the rest of its
 * minute; with `setCameraOpen(false)` removed, the scanner stays open.
 */

async function wipeNow(page: Page) {
  await page.keyboard.press("ControlOrMeta+k");
  await expect(page.getByRole("dialog", { name: "Command menu" })).toBeVisible();
  await page.getByRole("combobox", { name: "Filter commands" }).fill("wipe");
  await page.getByRole("option", { name: /Wipe now/ }).click();
}

test.describe("what the wipe reaches", () => {
  test("a clipboard copy still inside its minute is overwritten by the wipe", async ({ page, context, browserName }) => {
    test.skip(browserName !== "chromium", "clipboard-read/write are not permission names Firefox or WebKit accept");
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
    await page.goto("/");
    await useTextMode(page);

    const password = visible(page.getByPlaceholder("Enter a strong password"));
    await password.fill(STRONG_PASSWORD);
    await expect(password).toHaveAttribute("aria-describedby", "password-feedback");
    await visible(page.getByRole("button", { name: /^Copy$/ })).click();
    // The toast and its live-region announcement both carry the title.
    await expect(page.getByText("Copied to clipboard").first()).toBeVisible();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(STRONG_PASSWORD);

    await wipeNow(page);
    await expect(password).toHaveValue("");
    // Well inside the 60 seconds the copy would otherwise have had.
    await expect
      .poll(() => page.evaluate(() => navigator.clipboard.readText()), { timeout: 10_000 })
      .toBe("");
  });

  test("an open camera scanner is closed by the wipe", async ({ page }) => {
    await page.goto("/");
    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);
    // Wipe now is offered only while the form holds a secret.
    await visible(page.getByPlaceholder("Enter decryption password")).fill("a password to be wiped");
    await visible(page.getByRole("button", { name: /^Use recovery shares$/ })).click();
    await visible(page.getByRole("button", { name: "Scan strips with the camera" })).click();
    const dialog = page.getByTestId("camera-scan");
    await expect(dialog).toBeVisible();

    await wipeNow(page);
    await expect(dialog).toBeHidden();
  });
});
