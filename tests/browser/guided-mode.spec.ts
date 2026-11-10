import { test, expect } from "@playwright/test";
import { visible, useTextMode } from "./helpers";

/**
 * Guided mode: the Encrypt form, one step at a time.
 *
 * It is the same form with parts hidden, so what needs holding is that the
 * right part is on screen, that it is off unless asked for, and that Next
 * does not let someone past a step that is not done. The password step has
 * the rule with teeth: a generated password sits in a masked field and is
 * cleared once the backup is sealed, so a person who never pressed Show would
 * seal a backup behind a password they never saw.
 */
test.describe("guided mode", () => {
  test("is off by default and shows the whole form", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByTestId("guide-heading")).toHaveCount(0);
    await expect(visible(page.getByPlaceholder("Enter a strong password"))).toBeVisible();
    await expect(visible(page.getByRole("button", { name: /^Encrypt (File|Text)$/ }))).toBeVisible();
  });

  test("shows one step at a time and holds Next until the step is done", async ({ page }) => {
    await page.goto("/");
    await visible(page.getByTestId("guide-toggle")).click();
    await expect(page.getByTestId("guide-heading")).toContainText("Choose what to protect");

    // Only the content step is on screen: the password field and the Encrypt
    // button exist but are not shown.
    await expect(page.getByPlaceholder("Enter a strong password").locator("visible=true")).toHaveCount(0);
    await expect(page.getByRole("button", { name: /^Encrypt (File|Text)$/ }).locator("visible=true")).toHaveCount(0);

    const next = visible(page.getByRole("button", { name: /^Next$/ }));
    await expect(next, "Next was available with nothing to protect").toBeDisabled();

    await useTextMode(page);
    await visible(page.getByPlaceholder("Enter text to encrypt")).fill("a private note");
    await expect(next).toBeEnabled();
    await next.click();

    await expect(page.getByTestId("guide-heading")).toContainText("Set the password");
    await expect(page.getByPlaceholder("Enter text to encrypt").locator("visible=true")).toHaveCount(0);
    await expect(visible(page.getByPlaceholder("Enter a strong password"))).toBeVisible();
  });

  test("a generated password must be shown before Next", async ({ page }) => {
    await page.goto("/");
    await visible(page.getByTestId("guide-toggle")).click();
    await useTextMode(page);
    await visible(page.getByPlaceholder("Enter text to encrypt")).fill("a private note");
    await visible(page.getByRole("button", { name: /^Next$/ })).click();

    await visible(page.getByRole("button", { name: /Passphrase/ })).click();
    const next = visible(page.getByRole("button", { name: /^Next$/ }));
    await expect(
      next,
      "Next was available with a generated password nobody has seen"
    ).toBeDisabled();
    await expect(page.getByTestId("guide-blocked")).toContainText("Press Show");

    await visible(page.locator('button:has-text("Show")')).click();
    await expect(next).toBeEnabled();
    await next.click();
    await expect(page.getByTestId("guide-heading")).toContainText("Check it, then encrypt");
    await expect(visible(page.getByRole("button", { name: /^Encrypt Text$/ }))).toBeVisible();
  });
});
