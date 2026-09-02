import { test, expect, type Page } from "@playwright/test";
import { visible, useTextMode, selectCrypto, encryptText, STRONG_PASSWORD } from "./helpers";

/**
 * The seal as a ceremony (10× plan, Bet 6): the byte map sweeps while the
 * container is written, and a receipt replaces the success toast.
 *
 * The receipt's authority is the container inspector — not the plan pane,
 * which shares the receipt's label functions and could agree with it by
 * construction, but the *parsed* pane, whose rows are read from the bytes the
 * worker wrote. The receipt must say the same KDF and cipher those bytes say.
 * A receipt that named the wrong protection would disagree with its own
 * container, and this file is where that shows.
 *
 * The negative control is the label sabotage recorded in STATUS.md: with the
 * receipt's KDF row hardcoded, the authority assertion fails by name.
 */

const SECRET = "Deed box 12, Coutts Strand; the key is with Margaret.";
const receipt = (page: Page) => page.getByTestId("seal-receipt");

/** Enrol a k-of-n share set. The same helper container-inspector.spec.ts carries. */
async function enableShares(page: Page, k: number, n: number) {
  const advanced = visible(page.getByRole("button", { name: /^Advanced/ }));
  if ((await advanced.getAttribute("aria-expanded")) !== "true") await advanced.click();
  await expect(advanced).toHaveAttribute("aria-expanded", "true");
  const sharesSwitch = visible(page.getByRole("switch", { name: "Recovery shares" }));
  await expect(async () => {
    if ((await sharesSwitch.getAttribute("aria-checked")) !== "true") await sharesSwitch.click();
    await expect(sharesSwitch).toHaveAttribute("aria-checked", "true", { timeout: 1_000 });
  }).toPass({ timeout: 20_000 });
  await visible(page.getByLabel("Shares to print")).fill(String(n));
  await visible(page.getByLabel("Needed to open")).fill(String(k));
}

test("after sealing, the receipt names the output, the KDF and the cipher as the bytes do", async ({ page }) => {
  await page.goto("/");
  await useTextMode(page);
  await selectCrypto(page, "pbkdf2", "aes");
  await encryptText(page, SECRET, STRONG_PASSWORD);

  await expect(receipt(page)).toBeVisible();
  await expect(receipt(page)).toContainText("Sealed.");
  await expect(receipt(page)).toHaveAttribute("role", "status");

  // The authority: the inspector's slot row is parsed from the container the
  // worker wrote. The receipt's KDF must be that row's detail, verbatim.
  const parsedKdf = (
    await page.getByTestId("inspector-slot-row").first().locator("span").last().textContent()
  )!.trim();
  expect(parsedKdf, "the parsed pane has no KDF detail to hold the receipt to").toMatch(/PBKDF2/);
  await expect(receipt(page).getByTestId("receipt-kdf")).toHaveText(parsedKdf);
  const cipher = (await receipt(page).getByTestId("receipt-cipher").textContent())!.trim();
  await expect(page.getByTestId("container-inspector")).toContainText(`Payload sealed with ${cipher}`);

  await expect(receipt(page).getByTestId("receipt-written")).toContainText("text → keym2:");
  await expect(receipt(page).getByTestId("receipt-ways")).toContainText("Passphrase");
  await expect(receipt(page).getByTestId("receipt-left")).toHaveText("nothing");

  // The toast is gone: the receipt is the announcement, where the owner is looking.
  await expect(page.locator('[role="region"][aria-label*="otification"]')).not.toContainText("Success!");
});

test("its buttons download the container, print the paper vault, and rehearse from paper", async ({ page }) => {
  await page.goto("/");
  await useTextMode(page);
  await selectCrypto(page, "pbkdf2", "aes");
  await enableShares(page, 2, 3);
  await encryptText(page, SECRET, STRONG_PASSWORD);
  // The one-time shares dialog sits over the receipt; an owner who has copied
  // the strips closes it.
  await expect(page.getByText(/Save these 3 shares now/)).toBeVisible({ timeout: 30_000 });
  await page.keyboard.press("Escape");
  await expect(page.getByText(/Save these/)).toHaveCount(0);

  await expect(receipt(page)).toBeVisible();
  await expect(receipt(page).getByTestId("receipt-ways")).toContainText("2-of-3 recovery shares");

  // Download: a real file, named the way the app names containers.
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    receipt(page).getByRole("button", { name: /^Download \.keym$/ }).click(),
  ]);
  expect(download.suggestedFilename()).toMatch(/^keymaker-[0-9a-f]{8}\.keym$/);

  // Print: the sheet is in the document at the instant of printing. The stub
  // throws so the sheet stays mounted — paper-vault.spec.ts explains.
  await page.evaluate(() => {
    const w = window as unknown as { __sheets: number | null; print: () => void };
    w.__sheets = null;
    w.print = () => {
      w.__sheets = document.querySelectorAll(".paper-vault").length;
      throw new Error("print stubbed");
    };
  });
  await receipt(page).getByRole("button", { name: /^Print paper vault$/ }).click();
  await page.waitForFunction(() => (window as unknown as { __sheets: unknown }).__sheets !== null);
  expect(await page.evaluate(() => (window as unknown as { __sheets: number }).__sheets)).toBe(1);

  // Rehearse from paper: the heir's own route, set up — Decrypt, the
  // container in the box, verify-only on, the strip box open.
  const armored = await page.evaluate(
    () => (document.querySelector("#output-text") as HTMLTextAreaElement).value
  );
  await receipt(page).getByRole("button", { name: /^Rehearse recovery$/ }).click();
  await expect(page.getByRole("tab", { name: "Decrypt" })).toHaveAttribute("aria-selected", "true");
  await expect(visible(page.getByPlaceholder("Enter text to decrypt"))).toHaveValue(armored);
  await expect(visible(page.getByRole("switch", { name: /Verify only/ }))).toHaveAttribute("aria-checked", "true");
  await expect(visible(page.getByPlaceholder(/KMSHARE1:/))).toBeVisible();
});

test("the byte map sweeps while sealing, and with reduced motion it simply appears — the receipt either way", async ({
  browser,
}) => {
  for (const reduced of [false, true]) {
    const context = await browser.newContext({ reducedMotion: reduced ? "reduce" : "no-preference" });
    const page = await context.newPage();
    try {
      await page.goto("/");
      await useTextMode(page);
      // A slow seal, so the sweep is on screen long enough to be read: the
      // same lever async-guard.spec.ts uses.
      await selectCrypto(page, "argon2id", "aes");
      await visible(page.getByRole("slider", { name: "Argon2id time cost" })).fill("6");
      await visible(page.getByRole("slider", { name: "Argon2id memory" })).fill("128");
      await visible(page.getByPlaceholder("Enter text to encrypt")).fill(SECRET);
      await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
      await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();

      const map = page.getByTestId("inspector-byte-map");
      await expect(map).toHaveAttribute("data-sealing", "true", { timeout: 20_000 });
      const stamp = map.locator('[data-kind="stamp"]');
      await expect(stamp).toHaveCSS("animation-name", /seal-reveal/);
      const duration = await stamp.evaluate((el) => getComputedStyle(el).animationDuration);
      const seconds = (() => {
        const m = /^([\d.e-]+)(ms|s)/.exec(duration.trim());
        if (!m) throw new Error(`unreadable animation-duration: ${duration}`);
        return m[2] === "ms" ? Number(m[1]) / 1000 : Number(m[1]);
      })();
      if (reduced) {
        // The global flattens every animation to a frame: the map is lit at once.
        expect(seconds, `reduced motion still animates: ${duration}`).toBeLessThan(0.001);
      } else {
        // The stamp's share of a 500ms sweep, floored at 80ms.
        expect(seconds, `no sweep: ${duration}`).toBeGreaterThanOrEqual(0.08);
        expect(seconds).toBeLessThanOrEqual(0.5);
      }

      await expect(receipt(page)).toBeVisible({ timeout: 120_000 });
      // The finished container draws its own map, from the bytes, with no sweep.
      await expect(map).not.toHaveAttribute("data-sealing", "true");
    } finally {
      await context.close();
    }
  }
});

test("a wipe is acknowledged in place, not in a toast, and the acknowledgment yields to the next input", async ({
  page,
}) => {
  await page.goto("/");
  await useTextMode(page);
  await visible(page.getByPlaceholder("Enter a strong password")).fill("something worth wiping 1234!");
  await visible(page.getByRole("button", { name: /Wipe now/i })).click();

  const ack = page.getByTestId("wipe-ack");
  await expect(ack).toBeVisible();
  await expect(ack).toContainText("Wiped");
  await expect(ack).toContainText("settings are unchanged");
  await expect(page.locator('[role="region"][aria-label*="otification"]')).not.toContainText("Wiped");
  await expect(visible(page.getByPlaceholder("Enter a strong password"))).toHaveValue("");

  await visible(page.getByPlaceholder("Enter a strong password")).fill("x");
  await expect(ack).toHaveCount(0);
});
