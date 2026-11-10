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
  // The rest of the suite runs as a visitor who switched the guide off. These
  // run as a new one, with nothing stored.
  test.use({ storageState: { cookies: [], origins: [] } });

  test("is on for a new visitor, and switching it off is remembered", async ({ page }) => {
    await page.goto("/");
    const toggle = visible(page.getByTestId("guide-toggle"));
    await expect(toggle).toHaveAttribute("aria-checked", "true");
    await expect(page.getByTestId("guide-heading")).toContainText("Choose what to protect");

    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-checked", "false");
    await expect(page.getByTestId("guide-heading")).toHaveCount(0);
    // The whole form is back.
    await expect(visible(page.getByPlaceholder("Enter a strong password"))).toBeVisible();
    await expect(visible(page.getByRole("button", { name: /^Encrypt (File|Text)$/ }))).toBeVisible();

    await page.reload();
    await expect(
      visible(page.getByTestId("guide-toggle")),
      "the guide came back on after it was switched off"
    ).toHaveAttribute("aria-checked", "false");
    await expect(page.getByTestId("guide-heading")).toHaveCount(0);
    expect(
      await page.evaluate(() => Object.keys(window.localStorage)),
      "the app stores one thing, whether the guide is on"
    ).toEqual(["keymaker.guided"]);
  });

  test("the other pages explain themselves while the guide is on", async ({ page }) => {
    await page.goto("/");
    for (const [tab, title] of [["Recovery", "How Recovery works"], ["Audio", "How Audio works"], ["Tools", "How Tools works"]] as const) {
      await visible(page.getByRole("tab", { name: tab })).click();
      await expect(page.getByTestId("guide-intro")).toContainText(title);
    }
    await visible(page.getByTestId("guide-toggle")).click();
    await expect(page.getByTestId("guide-intro")).toHaveCount(0);
  });

  test("Decrypt is guided too, and waits for a backup", async ({ page }) => {
    await page.goto("/");
    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await expect(page.getByTestId("guide-heading")).toContainText("Load the backup");
    const next = visible(page.getByRole("button", { name: /^Next$/ }));
    await expect(next, "Next was available with no backup loaded").toBeDisabled();
    await useTextMode(page);
    await visible(page.getByPlaceholder("Enter text to decrypt")).fill("keym2:AAAA");
    await next.click();
    await expect(page.getByTestId("guide-heading")).toContainText("Say how it opens");
    await visible(page.getByRole("button", { name: /^Next$/ })).click();
    await expect(visible(page.getByRole("button", { name: /^Decrypt Text$/ }))).toBeVisible();
  });

  test("shows one step at a time and holds Next until the step is done", async ({ page }) => {
    await page.goto("/");
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
    await expect(page.getByTestId("guide-heading")).toBeVisible();
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
