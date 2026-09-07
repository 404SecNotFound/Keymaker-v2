/** Capture the current application shell, without mock data or DOM restyling. */
import { chromium, expect } from "@playwright/test";
import { mkdir } from "node:fs/promises";
import { resolve, join } from "node:path";

const output = resolve(process.env.KEYMAKER_PREVIEW_DIR || "work/workspace-preview");
const base = process.env.KEYMAKER_SHOT_URL || "http://127.0.0.1:4325";
await mkdir(output, { recursive: true });
const browser = await chromium.launch({
  executablePath: !process.env.CI ? process.env.KEYMAKER_BROWSER_PATH : undefined,
});
try {
  const context = await browser.newContext({
    viewport: { width: 1440, height: 1040 },
    deviceScaleFactor: 1,
    colorScheme: "dark",
    reducedMotion: "reduce",
  });
  const page = await context.newPage();
  await page.goto(base, { waitUntil: "networkidle" });
  await page.evaluate(() => document.fonts.ready);
  const capture = async (name) => {
    await page.evaluate(async () => {
      await document.fonts.ready;
      await Promise.all(document.getAnimations()
        .filter(animation => animation.effect?.getTiming().iterations !== Infinity)
        .map(animation => animation.finished.catch(() => {})));
      await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
    });
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    await page.screenshot({ path: join(output, name), fullPage: true, animations: "disabled" });
  };
  for (const view of ["Encrypt", "Workspace", "Decrypt", "Recovery"]) {
    await page.getByRole("tab", { name: view, exact: true }).click();
    await expect(page.getByRole("tab", { name: view, exact: true })).toHaveAttribute("aria-selected", "true");
    await expect(page.getByRole("tabpanel", { name: view, exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { level: 1 })).toHaveText(view === "Workspace" ? "Secure workspace" : view);
    await capture(`keymaker-graphite-${view.toLowerCase()}.png`);
    console.log(`Captured ${view}`);
  }
  await page.getByRole("tab", { name: "Encrypt", exact: true }).click();
  await expect(page.getByRole("tabpanel", { name: "Encrypt", exact: true })).toBeVisible();
  // A disposable, generated password demonstrates real feedback, never a real secret.
  await page.getByRole("button", { name: "Random", exact: true }).click();
  await expect(page.locator("#password-feedback")).toContainText("Generated");
  await expect(page.getByText("Password generated", { exact: true })).not.toBeVisible({ timeout: 10_000 });
  await capture("keymaker-graphite-mint-feedback.png");
  // A public demo file exercises the actual selected-file and enabled-action states.
  await page.locator("#encrypt-file").setInputFiles({
    name: "workspace-notes.txt",
    mimeType: "text/plain",
    buffer: Buffer.from("Public demonstration content for the workspace preview.\n"),
  });
  await expect(page.getByRole("button", { name: "Encrypt File", exact: true })).toBeEnabled();
  await capture("keymaker-graphite-ready.png");
  await page.getByRole("button", { name: /^Advanced/ }).click();
  await capture("keymaker-graphite-advanced.png");
  await page.getByRole("button", { name: /^Advanced/ }).click();
  await page.getByRole("button", { name: "Remove file", exact: true }).click();
  await page.locator("#password").fill("");
  console.log("Captured mint feedback, selected file, and advanced controls");
  await page.setViewportSize({ width: 393, height: 1000 });
  await capture("keymaker-graphite-mobile.png");
  console.log("Captured mobile");
} finally {
  await browser.close();
}
