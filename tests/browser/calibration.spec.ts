import { test, expect, type Page } from "@playwright/test";
import { visible } from "./helpers";

/**
 * Argon2id auto-calibration, in a real browser (roadmap 2.5).
 *
 * `kdf-calibration-test.mts` already proves the solver against synthetic
 * devices, including ones no hardware could impersonate. What it cannot prove
 * is that the measurement reaches it: that the Worker op exists, that
 * hash-wasm loads inside the worker, that the warm-up actually separates wasm
 * instantiation from the samples, and that the answer lands on the slider.
 *
 * So these tests assert the *outcome on the page*, not that a message was
 * posted. A calibration that ran perfectly and left the UI unchanged is a
 * failure, and only this file can see it.
 *
 * Nothing here asserts a specific memory size. CI runners vary by an order of
 * magnitude and a threshold tuned to one would be a flake on another — the
 * properties worth holding are that the number is inside the format's bounds,
 * that the page says which constraint bound it, and that a second run agrees
 * with the first.
 */

const MEMORY_FLOOR_MIB = 8;
const FORMAT_MAX_MIB = 256;

async function openArgon2Settings(page: Page) {
  const advanced = visible(page.getByRole("button", { name: /^Advanced/ }));
  if ((await advanced.getAttribute("aria-expanded")) !== "true") await advanced.click();
  await visible(page.getByRole("button").filter({ hasText: "Argon2id" })).click();
}

async function memoryMiB(page: Page): Promise<number> {
  return Number(await visible(page.getByLabel("Argon2id memory")).inputValue());
}

/** The button is disabled while measuring, so its return to enabled is the signal. */
async function calibrate(page: Page) {
  const button = visible(page.getByRole("button", { name: /Calibrate for this device/ }));
  await button.click();
  await expect(
    page.getByRole("button", { name: /Calibrate for this device/ })
  ).toBeEnabled({ timeout: 120_000 });
}

test.describe("Argon2id calibration", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await openArgon2Settings(page);
  });

  test("measures the device and moves the memory slider into range", async ({ page }) => {
    const before = await memoryMiB(page);
    await calibrate(page);

    const after = await memoryMiB(page);
    expect(after).toBeGreaterThanOrEqual(MEMORY_FLOOR_MIB);
    expect(after).toBeLessThanOrEqual(FORMAT_MAX_MIB);
    // Whole MiB, because that is what the solver rounds to and what the slider
    // is stepped in.
    expect(Number.isInteger(after)).toBe(true);

    // The status line has to say something. An empty one after a completed
    // calibration means the result never reached the user, which is the same
    // as not having calibrated.
    const status = page.locator('[role="status"]').filter({ hasText: /\S/ });
    await expect(status.first()).toBeVisible();

    // `before` is only used to prove the page was in a known state first; the
    // value may legitimately be unchanged if the default already fits.
    expect(before).toBeGreaterThan(0);
  });

  test("reports the estimate as measured rather than typical", async ({ page }) => {
    // Before calibrating, the page hedges — it is quoting a laptop it has never
    // seen. That hedge must disappear once it has measured the real device, or
    // the wording is lying in one direction or the other.
    await expect(page.getByText(/on a typical laptop/)).toBeVisible();
    await calibrate(page);
    await expect(page.getByText(/measured on this device/)).toBeVisible();
    await expect(page.getByText(/on a typical laptop/)).toHaveCount(0);
  });

  test("the estimate tracks the sliders after calibrating", async ({ page }) => {
    await calibrate(page);

    const readEstimate = async (): Promise<number> => {
      const text = await visible(page.getByText(/Derivation time: ≈/)).textContent();
      return Number(/≈([\d.]+)s/.exec(text ?? "")?.[1] ?? NaN);
    };

    const atCalibrated = await readEstimate();
    expect(atCalibrated).toBeGreaterThan(0);

    // Doubling time cost must roughly double the predicted time. This is what
    // separates a live model from a number printed once and left there — the
    // pre-calibration heuristic would also move, so the check is that it moves
    // *proportionally*.
    const t = Number(await visible(page.getByLabel("Argon2id time cost")).inputValue());
    await visible(page.getByLabel("Argon2id time cost")).fill(String(t * 2));
    const doubled = await readEstimate();
    expect(doubled).toBeGreaterThan(atCalibrated * 1.5);
    expect(doubled).toBeLessThan(atCalibrated * 2.5);
  });

  test("calibrating twice agrees with itself", async ({ page }) => {
    // Not a determinism claim — it is a timing measurement. But two runs on the
    // same machine landing on wildly different parameters would mean the
    // warm-up is not doing its job and wasm instantiation is still leaking into
    // the samples, which is the failure mode most likely to ship unnoticed.
    await calibrate(page);
    const first = await memoryMiB(page);
    await calibrate(page);
    const second = await memoryMiB(page);

    const ratio = Math.max(first, second) / Math.min(first, second);
    expect(ratio).toBeLessThan(2.5);
  });
});
