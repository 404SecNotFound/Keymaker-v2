import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";
import { visible, useTextMode, selectCrypto, capturePrintedSymbols, composePhoto, STRONG_PASSWORD } from "./helpers";

/**
 * "Check a printout", on the Recovery page.
 *
 * The photos here are the real print sheet's symbols, rasterised the way a
 * printer would draw them (capturePrintedSymbols), so the check is exercised
 * on exactly what someone would photograph. What must hold: a strip and a
 * container symbol from this backup are said to belong to it; the same paper
 * checked after a *different* backup is sealed is said not to; and a photo
 * with no code is named, not silently dropped. Nothing is decrypted, and no
 * password is typed on the Recovery page at any point.
 */

async function sealWithShares(page: Page, secret: string) {
  await useTextMode(page);
  await selectCrypto(page, "pbkdf2", "aes");
  const advanced = visible(page.getByRole("button", { name: /^Advanced/ }));
  if ((await advanced.getAttribute("aria-expanded")) !== "true") await advanced.click();
  await expect(advanced).toHaveAttribute("aria-expanded", "true");
  const sharesSwitch = visible(page.getByRole("switch", { name: "Recovery shares" }));
  await expect(async () => {
    if ((await sharesSwitch.getAttribute("aria-checked")) !== "true") await sharesSwitch.click();
    await expect(sharesSwitch).toHaveAttribute("aria-checked", "true", { timeout: 1_000 });
  }).toPass({ timeout: 20_000 });

  await visible(page.getByPlaceholder("Enter text to encrypt")).fill(secret);
  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
  await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();
  await expect(page.getByText(/Save these 3 shares now/)).toBeVisible({ timeout: 90_000 });
}

const png = (name: string, buffer: Buffer) => ({ name, mimeType: "image/png", buffer });

/** A white square, drawn by the page itself: an image with no code in it. */
async function blankPng(page: Page): Promise<Buffer> {
  const url = await page.evaluate(() => {
    const c = document.createElement("canvas");
    c.width = 200;
    c.height = 200;
    const ctx = c.getContext("2d")!;
    ctx.fillStyle = "#ffffff";
    ctx.fillRect(0, 0, 200, 200);
    return c.toDataURL("image/png");
  });
  return Buffer.from(url.split(",")[1] as string, "base64");
}

async function findings(page: Page) {
  const items = page.getByTestId("printout-results").locator("li");
  return items.evaluateAll((els) =>
    els.map((el) => ({ text: el.textContent ?? "", problem: el.getAttribute("data-problem") === "true" }))
  );
}

test("a printout is checked against the backup it came from, and not against another", async ({ page }) => {
  await page.goto("/");
  await sealWithShares(page, "first backup, the one on paper");
  const printed = await capturePrintedSymbols(
    page,
    page.getByRole("dialog").getByRole("button", { name: /Print paper vault/i })
  );
  expect(printed.strips.length).toBe(3);
  expect(printed.parts.length).toBeGreaterThan(0);
  await page.getByRole("button", { name: "I have saved these shares" }).click();

  await visible(page.getByRole("tab", { name: "Recovery" })).click();
  const check = page.getByTestId("printout-check");
  await expect(check).toContainText("belongs to the backup created in this session");
  await page.locator("#printout-check-input").setInputFiles([
    png("strip-2.png", printed.strips[1] as Buffer),
    png("symbol-1.png", printed.parts[0] as Buffer),
    png("blank.png", await blankPng(page)),
  ]);
  await expect(page.getByTestId("printout-results").locator("li")).toHaveCount(3, { timeout: 30_000 });
  const first = await findings(page);
  expect(first[0]?.text).toMatch(/strip-2\.png Recovery strip 2, set [0-9A-Z]{4}-[0-9A-Z]{4}, any 2 open it: reads correctly and belongs to this backup/);
  expect(first[0]?.problem).toBe(false);
  expect(first[1]?.text).toMatch(/symbol-1\.png Container symbol 1 of \d+: reads correctly and belongs to this backup/);
  expect(first[1]?.problem).toBe(false);
  expect(first[2]?.text).toMatch(/blank\.png No QR code was found/);
  expect(first[2]?.problem).toBe(true);

  // The whole strips page in one photo: one line per strip, each named by the
  // photo it came from and its place in it.
  await page.locator("#printout-check-input").setInputFiles([
    png("strips-page.png", await composePhoto(page, printed.strips)),
  ]);
  await expect(page.getByTestId("printout-results").locator("li")).toHaveCount(3, { timeout: 30_000 });
  const page3 = await findings(page);
  expect(page3.map((f) => f.text.match(/Recovery strip (\d)/)?.[1]).sort()).toEqual(["1", "2", "3"]);
  for (const [i, f] of page3.entries()) {
    expect(f.text).toContain(`strips-page.png (${i + 1} of 3)`);
    expect(f.text).toMatch(/belongs to this backup/);
  }

  // A second backup sealed in the same session. The first sheet's paper is
  // now from a different backup, and the old "belongs" lines must be gone
  // rather than left describing a backup that is no longer on the page.
  await visible(page.getByRole("tab", { name: "Encrypt" })).click();
  await sealWithShares(page, "second backup, never printed");
  await page.getByRole("button", { name: "I have saved these shares" }).click();
  await visible(page.getByRole("tab", { name: "Recovery" })).click();
  await expect(page.getByTestId("printout-results")).toHaveCount(0);

  await page.locator("#printout-check-input").setInputFiles([
    png("strip-2.png", printed.strips[1] as Buffer),
    png("symbol-1.png", printed.parts[0] as Buffer),
  ]);
  await expect(page.getByTestId("printout-results").locator("li")).toHaveCount(2, { timeout: 30_000 });
  const second = await findings(page);
  for (const f of second) {
    expect(f.text).toMatch(/from a different backup/);
    expect(f.problem).toBe(true);
  }
});
