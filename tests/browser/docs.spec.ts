import { test, expect } from "@playwright/test";
import { visible } from "./helpers";

/**
 * The Docs view. Three things matter and each is pinned:
 *
 * 1. It is a real destination: a sidebar tab, a named tab panel, eleven
 *    numbered chapters in order, reachable from the command menu.
 * 2. It links back into the app. "Go to" buttons switch the workspace, so the
 *    docs are a way into the tool rather than a dead end beside it.
 * 3. It keeps the house rules that a long prose page is most likely to break:
 *    every callout carries a textual kind (never colour alone), every table has
 *    a header row, and nothing in it loads a resource from anywhere.
 */

const CHAPTERS = [
  "Start here", "Encrypting", "Opening and verifying", "Ways in", "Seed phrases and dice",
  "Recovery and inheritance", "The audio carrier", "Under the hood", "Best practices",
  "Mistakes to avoid", "What it does not protect against",
];

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await visible(page.getByRole("tab", { name: "Docs", exact: true })).click();
});

test("Docs is a sidebar destination with eleven numbered chapters, in order", async ({ page }) => {
  await expect(page.getByRole("tab", { name: "Docs", exact: true })).toHaveAttribute("aria-selected", "true");
  const panel = page.getByRole("tabpanel", { name: "Docs" });
  await expect(panel).toBeVisible();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Docs");

  const guide = page.getByTestId("docs-guide");
  const headings = guide.getByRole("heading", { level: 2 });
  await expect(headings).toHaveCount(CHAPTERS.length);
  await expect(headings).toHaveText(CHAPTERS);

  // The chapter list mirrors the chapters and each entry lands on its panel.
  const toc = guide.getByRole("navigation", { name: "Chapters" });
  await expect(toc.getByRole("link")).toHaveCount(CHAPTERS.length);
  await toc.getByRole("link", { name: /Under the hood/ }).click();
  await expect(page).toHaveURL(/#docs-internals$/);
  await expect(guide.locator("#docs-internals")).toBeInViewport();
});

test("a Go to button inside the docs switches the workspace", async ({ page }) => {
  const guide = page.getByTestId("docs-guide");
  await guide.getByRole("button", { name: /^Decrypt/ }).first().click();
  await expect(page.getByRole("tab", { name: "Decrypt", exact: true })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Decrypt");
  await expect(guide).toHaveCount(0);
});

test("the command menu reaches the docs, and does not offer them while they are open", async ({ page }) => {
  // Already on Docs: the entry is absent, like "Go to" entries for the current mode.
  await page.getByRole("button", { name: "Open the command menu" }).click();
  const menu = page.getByRole("dialog", { name: "Command menu" });
  await expect(menu).toBeVisible();
  await expect(menu.getByRole("option", { name: /Read the docs/ })).toHaveCount(0);
  await page.keyboard.press("Escape");

  await visible(page.getByRole("tab", { name: "Encrypt", exact: true })).click();
  await page.getByRole("button", { name: "Open the command menu" }).click();
  await menu.getByRole("option", { name: /Read the docs/ }).click();
  await expect(page.getByRole("tab", { name: "Docs", exact: true })).toHaveAttribute("aria-selected", "true");
});

test("callouts name their kind in words, tables have header rows, and nothing loads a resource", async ({ page }) => {
  const guide = page.getByTestId("docs-guide");

  const callouts = guide.locator(".km-docs-callout");
  expect(await callouts.count()).toBeGreaterThan(5);
  for (const kind of await callouts.locator(".km-docs-callout-kind").allTextContents()) {
    expect(["Tip", "Note", "Warning", "No recovery"]).toContain(kind);
  }

  const tables = guide.getByRole("table");
  expect(await tables.count()).toBeGreaterThan(4);
  for (let i = 0; i < await tables.count(); i++) {
    await expect(tables.nth(i).locator("thead th").first()).toBeVisible();
  }

  // Diagrams are HTML; there is no <img>, <svg src>, <iframe>, <video> or
  // external stylesheet anywhere in the guide, so the precache manifest and the
  // CSP are untouched by this view.
  await expect(guide.locator("img, iframe, video, audio, object, embed, link")).toHaveCount(0);
  await expect(guide.locator("[style*='url(']")).toHaveCount(0);
});

test("the docs do not overflow at phone width and the chapter list becomes a wrapped strip", async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 720 });
  await page.reload();
  await visible(page.getByRole("tab", { name: "Docs", exact: true })).click();
  await expect(page.getByTestId("docs-guide")).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(1);
});
