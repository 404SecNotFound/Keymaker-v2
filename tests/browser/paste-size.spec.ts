import { test, expect, type Page } from "@playwright/test";
import { visible, useTextMode } from "./helpers";

/**
 * U4 — an oversized paste must not reach the field.
 *
 * The report filed this as "oversized paste crashes the tab (OOM) at ~140 MB".
 * Measuring it found something smaller and more ordinary, and the numbers are
 * what these tests are calibrated against. Worst main-thread block, production
 * build, headless Chromium:
 *
 *   |   pasted | as one line | wrapped at 76 cols |
 *   |   64 KiB |      833 ms |                  — |
 *   |  256 KiB |    3 245 ms |                  — |
 *   |    1 MiB |   12 434 ms |             407 ms |
 *
 * Three things that shaped the fix:
 *
 *   1. The `onChange` handler returns in 3-7 ms at every size. The block is
 *      *after* it, in the browser laying out the field — so a check inside
 *      `processData` could never have helped, and neither could a faster
 *      handler.
 *   2. Encrypt and decrypt block identically, so it is not the BIP-39 check.
 *   3. It is line *length*, not total size: 30x between the same megabyte as
 *      one line and as wrapped lines.
 *
 * (3) is why this is not only about adversarial pastes. Keymaker's own armored
 * output is a single unbroken line, so a user copying a backup out and pasting
 * it back into Decrypt reaches this on the ordinary recovery path.
 *
 * The tests below use single-line input deliberately — wrapped text of the same
 * size does not reproduce it, and a test that cannot reproduce the bug is not a
 * regression test for it.
 */

const KIB = 1024;

/** Paste without shipping megabytes over CDP, driving React the way a real
 *  paste does: the native value setter plus an input event. */
async function paste(page: Page, chars: number): Promise<void> {
  await page.evaluate((n) => {
    const el = document.querySelector("#text-secret") as HTMLTextAreaElement;
    const setter = Object.getOwnPropertyDescriptor(
      window.HTMLTextAreaElement.prototype,
      "value"
    )!.set!;
    setter.call(el, "A".repeat(n));
    el.dispatchEvent(new Event("input", { bubbles: true }));
  }, chars);
}

/** Worst frame gap while `body` runs — what a user actually feels. */
async function worstBlockDuring(page: Page, body: () => Promise<void>, settleMs = 4000): Promise<number> {
  await page.evaluate(() => {
    (window as unknown as { __gaps: number[] }).__gaps = [];
    let last = performance.now();
    const w = window as unknown as { __stop?: boolean; __gaps: number[] };
    w.__stop = false;
    (function sample() {
      const now = performance.now();
      w.__gaps.push(now - last);
      last = now;
      if (!w.__stop) requestAnimationFrame(sample);
    })();
  });
  await body();
  await page.waitForTimeout(settleMs);
  return page.evaluate(() => {
    const w = window as unknown as { __stop?: boolean; __gaps: number[] };
    w.__stop = true;
    return Math.round(Math.max(...w.__gaps));
  });
}

test.describe("oversized paste", () => {
  test("a 1 MiB single-line paste is refused instead of freezing the tab", async ({ page }) => {
    await page.goto("/");
    await useTextMode(page);

    const field = visible(page.getByPlaceholder("Enter text to encrypt"));

    const worst = await worstBlockDuring(page, () => paste(page, 1024 * KIB));

    // Before the gate this measured ~12 400 ms. The threshold is deliberately
    // far below that and far above a normal frame, so it fails loudly on a
    // regression without flaking on a slow runner.
    expect(worst, "the main thread was blocked by the paste").toBeLessThan(2000);

    // Refused, not truncated. Silently keeping a prefix of someone's secret and
    // encrypting that is worse than refusing: it succeeds and loses data.
    await expect(field).toHaveValue("");
    await expect(page.getByText(/Text mode is for secrets up to/i)).toBeVisible();
    await expect(page.getByText(/switch to File mode/i)).toBeVisible();
  });

  test("an oversized paste does not destroy what was already typed", async ({ page }) => {
    await page.goto("/");
    await useTextMode(page);

    const field = visible(page.getByPlaceholder("Enter text to encrypt"));
    await field.fill("abandon ability able about above absent absorb abstract");

    await paste(page, 1024 * KIB);

    await expect(
      field,
      "an oversized paste replaced the secret the user had already entered"
    ).toHaveValue("abandon ability able about above absent absorb abstract");
    await expect(page.getByText(/still here/i)).toBeVisible();
  });

  test("the decrypt field accepts armor for the largest text it can produce", async ({ page }) => {
    await page.goto("/");
    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);

    const field = visible(page.getByPlaceholder("Enter text to decrypt"));

    // The caps are asymmetric on purpose: armor expands by 4/3, so a symmetric
    // pair would let the app produce text it then refuses to take back. 44 KiB
    // is above the 32 KiB plaintext cap and below the 64 KiB armor cap — the
    // band that trap would have occupied.
    await paste(page, 44 * KIB);
    await expect(
      field,
      "armor for a legal text-mode secret was refused — the caps trap the user"
    ).toHaveValue("A".repeat(44 * KIB));
    await expect(page.getByText(/Encrypted text is accepted up to/i)).toHaveCount(0);
  });

  test("the decrypt field still refuses text beyond its own cap", async ({ page }) => {
    await page.goto("/");
    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);

    const worst = await worstBlockDuring(page, () => paste(page, 1024 * KIB));
    expect(worst, "the main thread was blocked by the paste").toBeLessThan(2000);

    await expect(visible(page.getByPlaceholder("Enter text to decrypt"))).toHaveValue("");
    await expect(page.getByText(/Encrypted text is accepted up to/i)).toBeVisible();
    await expect(page.getByText(/decrypt the .keym file itself in File mode/i)).toBeVisible();
  });

  test("ordinary text is unaffected", async ({ page }) => {
    await page.goto("/");
    await useTextMode(page);

    const field = visible(page.getByPlaceholder("Enter text to encrypt"));
    const secret = "correct horse battery staple — a perfectly ordinary note 🔑";
    await field.fill(secret);

    await expect(field).toHaveValue(secret);
    await expect(page.getByText(/Text mode is for secrets up to/i)).toHaveCount(0);
  });

  test("the cap counts UTF-8 bytes, not UTF-16 units", async ({ page }) => {
    await page.goto("/");
    await useTextMode(page);

    const field = visible(page.getByPlaceholder("Enter text to encrypt"));

    // 12 000 emoji: 12 000 code points, 24 000 UTF-16 units, 48 000 UTF-8
    // bytes. Under the cap by string length, over it by the measure the crypto
    // core actually applies. Measuring the wrong one lets a secret through that
    // encryptData would then reject on submit.
    await page.evaluate(() => {
      const el = document.querySelector("#text-secret") as HTMLTextAreaElement;
      const setter = Object.getOwnPropertyDescriptor(
        window.HTMLTextAreaElement.prototype,
        "value"
      )!.set!;
      setter.call(el, "🔑".repeat(12_000));
      el.dispatchEvent(new Event("input", { bubbles: true }));
    });

    await expect(field, "a byte-oversized secret was accepted by string length").toHaveValue("");
    await expect(page.getByText(/Text mode is for secrets up to/i)).toBeVisible();
  });
});
