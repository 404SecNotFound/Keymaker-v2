import { test, expect, type Page } from "@playwright/test";
import { visible, useTextMode, selectCrypto, capturePrintedSymbols, STRONG_PASSWORD } from "./helpers";

/**
 * The visible step order (roadmap Section 06, part b).
 *
 * Six steps: content, access rule, review, create, check saved copy, prepare
 * recovery. They are status, not a wizard, so what is under test is that each
 * state follows the page's own evidence and never runs ahead of it:
 *
 *  - the steps move with the form, the job and the exports;
 *  - a download or a print is "Started", never "Done";
 *  - the saved copy is "Done" only when every printed container symbol has
 *    been photographed back and matched to this backup, and one symbol of
 *    several is not enough;
 *  - recovery is "Done" only after a rehearsal from the shares opened it.
 */

const SECRET = "workflow-steps synthetic secret, not a real one";

const step = (page: Page, id: string) =>
  page.getByTestId("workflow-steps").locator(`li[data-step="${id}"]`);

async function expectStep(page: Page, id: string, state: string, word: string) {
  const li = step(page, id);
  await expect(li, `step ${id}`).toHaveAttribute("data-state", state);
  // A word as well as a colour.
  await expect(li.locator(".km-step-state")).toHaveText(word);
}

async function enableShares(page: Page) {
  const advanced = visible(page.getByRole("button", { name: /^Advanced/ }));
  if ((await advanced.getAttribute("aria-expanded")) !== "true") await advanced.click();
  await expect(advanced).toHaveAttribute("aria-expanded", "true");
  const sharesSwitch = visible(page.getByRole("switch", { name: "Recovery shares" }));
  await expect(async () => {
    if ((await sharesSwitch.getAttribute("aria-checked")) !== "true") await sharesSwitch.click();
    await expect(sharesSwitch).toHaveAttribute("aria-checked", "true", { timeout: 1_000 });
  }).toPass({ timeout: 20_000 });
}

/** Seal in Text mode with PBKDF2 and 2-of-3 shares; the one-time dialog is left open. */
async function sealWithShares(page: Page, secret: string) {
  await page.goto("/");
  await useTextMode(page);
  await selectCrypto(page, "pbkdf2", "aes");
  await enableShares(page);
  await visible(page.getByPlaceholder("Enter text to encrypt")).fill(secret);
  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
  await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();
  await expect(page.getByText(/Save these 3 shares now/)).toBeVisible({ timeout: 90_000 });
}

const png = (name: string, buffer: Buffer) => ({ name, mimeType: "image/png", buffer });

test("the steps follow the form, the job and the exports, and a download is only started", async ({ page }) => {
  await page.goto("/");
  await useTextMode(page);
  await selectCrypto(page, "pbkdf2", "aes");

  await expectStep(page, "content", "current", "Next");
  await expect(step(page, "content")).toHaveAttribute("aria-current", "step");
  await expectStep(page, "create", "todo", "To do");

  await visible(page.getByPlaceholder("Enter text to encrypt")).fill(SECRET);
  await expectStep(page, "content", "done", "Done");
  await expectStep(page, "access", "current", "Next");

  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
  await expectStep(page, "access", "done", "Done");
  await expectStep(page, "review", "current", "Next");

  await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();
  await expect(visible(page.getByTestId("seal-receipt"))).toBeVisible({ timeout: 60_000 });
  await expectStep(page, "create", "done", "Done");
  await expectStep(page, "saved-copy", "current", "Next");
  await expect(page.getByTestId("workflow-step-detail")).toContainText("Saved copy.");

  const download = page.waitForEvent("download");
  await visible(page.getByRole("button", { name: /Download \.keym/ })).click();
  await download;
  await expectStep(page, "saved-copy", "started", "Started");
  await expectStep(page, "recovery", "current", "Next");

  // The form moves on: creation says so, and nothing further is offered as next.
  await selectCrypto(page, "pbkdf2", "chacha");
  await expectStep(page, "create", "changed", "Changed");
  await expect(page.getByTestId("workflow-step-detail")).toContainText("cipher");
  await expect(page.getByTestId("workflow-steps").locator('li[data-state="current"]')).toHaveCount(0);
});

test("the saved copy is done only when every printed symbol matches this backup", async ({ page }) => {
  // Long enough that the container needs more than one printed symbol, so a
  // check of one of them is a partial check.
  await sealWithShares(page, `${SECRET} `.repeat(120));
  const printed = await capturePrintedSymbols(
    page,
    page.getByRole("dialog").getByRole("button", { name: /Print paper vault/i })
  );
  expect(printed.parts.length, "the container fits one symbol, so no partial check is possible").toBeGreaterThan(1);
  await page.getByRole("button", { name: "I have saved these shares" }).click();
  await expectStep(page, "saved-copy", "started", "Started");

  await visible(page.getByRole("tab", { name: "Recovery", exact: true })).click();
  const input = page.locator("#printout-check-input");
  const results = page.getByTestId("printout-results").locator("li");

  // Strips are not the saved copy, and one symbol of several is not all of it.
  await input.setInputFiles([
    png("strip-1.png", printed.strips[0] as Buffer),
    png("symbol-1.png", printed.parts[0] as Buffer),
  ]);
  await expect(results.filter({ hasText: "symbol-1.png" })).toContainText("belongs to this backup", { timeout: 30_000 });
  await visible(page.getByRole("tab", { name: "Encrypt", exact: true })).click();
  await expectStep(page, "saved-copy", "started", "Started");
  await expect(page.getByTestId("workflow-step-detail")).toContainText(`1 of ${printed.parts.length} printed symbols matched`);

  // The rest, in a second check: checks of the same backup add up.
  await visible(page.getByRole("tab", { name: "Recovery", exact: true })).click();
  await input.setInputFiles(printed.parts.slice(1).map((b, i) => png(`symbol-${i + 2}.png`, b)));
  await expect(results.filter({ hasText: `symbol-${printed.parts.length}.png` })).toContainText(
    "belongs to this backup",
    { timeout: 30_000 }
  );
  await visible(page.getByRole("tab", { name: "Encrypt", exact: true })).click();
  await expectStep(page, "saved-copy", "done", "Done");
  // Not rehearsed, so recovery is still to do.
  await expectStep(page, "recovery", "current", "Next");
});

test("recovery is done only after a rehearsal from the shares opens the backup", async ({ page }) => {
  await sealWithShares(page, SECRET);
  const dialog = page.getByRole("dialog");
  const shares = (await dialog.getByText(/^KMSHARE2:/).allTextContents()).map((s) => s.trim());
  expect(shares).toHaveLength(3);
  await dialog.getByRole("button", { name: /Rehearse now/ }).click();
  await dialog.getByLabel("Strips to rehearse with").fill(`${shares[0]}\n${shares[2]}`);
  await dialog.getByRole("button", { name: /^Open with these strips$/ }).click();
  await expect(dialog.getByTestId("rehearsal-result")).toContainText(/Opened in/, { timeout: 60_000 });
  await page.getByRole("button", { name: "I have saved these shares" }).click();

  await expectStep(page, "recovery", "done", "Done");
  // Printing the sheet was never asked for, so the saved copy is still next.
  await expectStep(page, "saved-copy", "current", "Next");
});

test("the step grid's rows line up at the width the screenshots use", async ({ page }) => {
  // Usability finding S3: a label that wrapped pushed its state word below its
  // neighbours', and the one-line label beside it sat off the row's top.
  await page.setViewportSize({ width: 1180, height: 1140 });
  await page.goto("/");
  const tops = async (selector: string) =>
    page.getByTestId("workflow-steps").locator(selector).evaluateAll((els) =>
      els.map((el) => Math.round(el.getBoundingClientRect().top))
    );
  const labels = await tops(".km-step-label");
  const states = await tops(".km-step-state");
  expect(labels).toHaveLength(6);
  for (const [name, ys] of [["labels", labels], ["states", states]] as const) {
    expect(new Set(ys.slice(0, 3)).size, `row 1 ${name} are not level: ${ys.slice(0, 3)}`).toBe(1);
    expect(new Set(ys.slice(3, 6)).size, `row 2 ${name} are not level: ${ys.slice(3, 6)}`).toBe(1);
  }
});
