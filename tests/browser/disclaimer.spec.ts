import { test, expect } from "@playwright/test";
import { visible } from "./helpers";

/**
 * The standing disclaimer is chrome: it has to be on every view, at every
 * width, without scrolling, and its link has to land on the chapter that
 * says what the app cannot protect against. A disclaimer that is only on
 * one page, or only on desktop, is one most people never read.
 */

const WORDS = /Reviewed by its author, not independently audited/;

for (const width of [320, 1440]) {
  test(`the disclaimer is above the fold on every view at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/");
    for (const view of ["Workspace", "Encrypt", "Decrypt", "Recovery", "Audio", "Tools", "Docs"]) {
      await visible(page.getByRole("tab", { name: view, exact: true })).click();
      const note = page.getByRole("note");
      await expect(note).toContainText(WORDS);
      const box = await note.boundingBox();
      expect(box, `${view} at ${width}`).not.toBeNull();
      expect(box!.y + box!.height, `${view} at ${width} is above the fold`).toBeLessThan(900);
    }
  });
}

test("its link opens the chapter on what the app does not protect against", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("note").getByRole("button", { name: /does not protect against/ }).click();
  await expect(page.getByRole("tab", { name: "Docs", exact: true })).toHaveAttribute("aria-selected", "true");
  const chapter = page.locator("#docs-limits");
  await expect(chapter).toBeVisible();
  await expect(chapter).toContainText(/A compromised device/);
});
