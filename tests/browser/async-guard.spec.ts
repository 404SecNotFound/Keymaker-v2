import { test, expect, type Page } from "@playwright/test";
import { visible, useTextMode, STRONG_PASSWORD } from "./helpers";

/**
 * A crypto operation that is still running must never write into a UI that has
 * moved on.
 *
 * Argon2id takes one to three seconds on ordinary hardware, and nothing stops
 * the user switching tab or input type during it. Before the sequence guard,
 * the finished operation carried on regardless: it wrote its output, fired a
 * "Success!" toast onto whichever panel was now visible, and — the damaging
 * part — ran the unconditional `setPassword('')` in its `finally`, wiping a
 * password the user had typed in the meantime.
 *
 * These are UI-level races. The crypto core behaves perfectly in both cases, so
 * no Node test can see them; only a real browser driving real React state can,
 * which is why they shipped.
 *
 * ## Why PBKDF2, and why throttled
 *
 * The race is only reachable on the PBKDF2 path, and finding that out was the
 * point of writing these.
 *
 * Argon2id runs through hash-wasm **on the main thread**. Measured here, an
 * interrupting click issued 200 ms into a 22-second derivation did not resolve
 * until 22.5 s — the page is frozen, so the user's tab switch is queued rather
 * than processed, and by the time it runs the operation has already completed
 * legitimately. The race cannot be triggered there because the UI cannot be
 * touched at all.
 *
 * PBKDF2 goes through WebCrypto, which derives off the main thread. The tab
 * stays responsive, the user really can switch mid-derivation, and the stale
 * completion path really does run against a UI that moved on. Measured on the
 * unguarded build: spinner at 185 ms, interrupt landed at 359 ms, password
 * field empty by 937 ms.
 *
 * CPU throttling widens that window so the tests are not timing-sensitive on
 * faster or slower machines.
 *
 * (Argon2id freezing the tab is not acceptable either — it is the motivation
 * for moving crypto into a Worker. When that lands, this same race becomes
 * reachable on *both* paths, and these tests should be extended rather than
 * relaxed.)
 */

/** Widens the window; the race is already open at 1x, this just removes flake. */
const CPU_THROTTLE = 4;

/** PBKDF2 at 1M iterations finishes around 1-2 s at 4x. This is a wide margin. */
const STALE_OP_SETTLE_MS = 10_000;

/** Select the KDF whose derivation does not freeze the page. */
async function useInterruptibleKdf(page: Page) {
  const advanced = visible(page.getByRole("button", { name: /^Advanced/ }));
  if ((await advanced.getAttribute("aria-expanded")) !== "true") await advanced.click();
  await visible(page.getByRole("button").filter({ hasText: "PBKDF2" })).click();
}

async function throttleCpu(page: Page, rate: number) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("Emulation.setCPUThrottlingRate", { rate });
  return async () => {
    try {
      await cdp.send("Emulation.setCPUThrottlingRate", { rate: 1 });
      await cdp.detach();
    } catch {
      // Page already gone; nothing to restore.
    }
  };
}

/**
 * Begin the operation without awaiting the click.
 *
 * Playwright's actionability checks cost hundreds of milliseconds under
 * throttling, and awaiting them burned most of the window before the assertion
 * could look — the spinner had already come and gone.
 */
function startOperation(page: Page, label: RegExp): Promise<void> {
  return visible(page.getByRole("button", { name: label }))
    .click()
    .catch(() => {
      // Interrupting can re-render the button mid-click. Not a failure.
    });
}

/** Fail loudly if the operation is not genuinely running. */
async function confirmInFlight(page: Page) {
  await expect(
    page.locator(".animate-spin").first(),
    "the operation was not in flight — this test proves nothing unless it is"
  ).toBeVisible({ timeout: 20_000 });
}

test.describe("an operation that loses the UI falls silent", () => {
  test("switching input type mid-derivation does not wipe a newly typed password", async ({
    page,
    browserName,
  }) => {
    test.skip(browserName !== "chromium", "opening the race needs CDP CPU throttling");
    const unthrottle = await throttleCpu(page, CPU_THROTTLE);
    try {
      await page.goto("/");
      await useTextMode(page);
      await useInterruptibleKdf(page);

      await visible(page.getByPlaceholder("Enter text to encrypt")).fill("secret being encrypted");
      await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
      const inFlight = startOperation(page, /^Encrypt Text$/i);
      await confirmInFlight(page);

      // A real click: dispatchEvent skips Radix's pointer handling, and a
      // control that never actually switched would make this test pass or fail
      // for reasons unrelated to the guard.
      await visible(page.getByRole("button", { name: "File", exact: true })).click();
      const NEW_PASSWORD = "a-completely-different-password-9271!X";
      const passwordField = visible(page.getByPlaceholder("Enter a strong password"));
      await passwordField.fill(NEW_PASSWORD);

      // Hold the invariant continuously rather than sampling once after a fixed
      // sleep: the abandoned operation finishes at an unpredictable point
      // inside this window, and a single late check could miss a wipe.
      const deadline = Date.now() + STALE_OP_SETTLE_MS;
      while (Date.now() < deadline) {
        expect(
          await passwordField.inputValue(),
          "the abandoned operation cleared a password field it no longer owns"
        ).toBe(NEW_PASSWORD);
        await page.waitForTimeout(250);
      }

      await inFlight;
    } finally {
      await unthrottle();
    }
  });

  test("switching tabs mid-derivation does not announce success on the new tab", async ({
    page,
    browserName,
  }) => {
    test.skip(browserName !== "chromium", "opening the race needs CDP CPU throttling");
    const unthrottle = await throttleCpu(page, CPU_THROTTLE);
    try {
      await page.goto("/");
      await useTextMode(page);
      await useInterruptibleKdf(page);

      await visible(page.getByPlaceholder("Enter text to encrypt")).fill("secret being encrypted");
      await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
      const inFlight = startOperation(page, /^Encrypt Text$/i);
      await confirmInFlight(page);

      await visible(page.getByRole("tab", { name: "Decrypt" })).click();

      const deadline = Date.now() + STALE_OP_SETTLE_MS;
      while (Date.now() < deadline) {
        const shown = await page.evaluate(() => document.body.innerText);
        expect(
          shown,
          "an abandoned operation announced Success! on a tab that never ran it"
        ).not.toMatch(/Success!/);
        await page.waitForTimeout(250);
      }

      // The Decrypt panel is usable, not stuck mid-operation. resetState
      // returns the input type to File, so match either button name.
      await expect(
        visible(page.getByRole("button", { name: /^Decrypt (File|Text)$/i })),
        "the Decrypt panel should be interactive, not stuck loading"
      ).toBeVisible();

      await inFlight;
    } finally {
      await unthrottle();
    }
  });
});

/**
 * The dice tool must not invent a die.
 *
 * Clearing the field yields Number("") === 0, which used to be silently
 * replaced with 6 — so the tool displayed an entropy figure for a six-sided die
 * the user had never specified. An inflated entropy number is the one output
 * this tool must never produce.
 */
test("the dice tool refuses to compute entropy for a die that was not specified", async ({
  page,
}) => {
  await page.goto("/");
  await visible(page.getByRole("tab", { name: "Tools" })).click();

  const sides = visible(page.getByLabel("Dice sides"));
  await expect(sides).toBeVisible();

  await sides.fill("");
  await expect(
    page.getByText(/Enter the number of sides on your die/i),
    "clearing the die size must say so instead of assuming a d6"
  ).toBeVisible();
  await expect(sides).toHaveAttribute("aria-invalid", "true");

  // Bits per roll must not be log2(6) = 2.58 for a die that does not exist.
  const body = (await page.locator("body").textContent()) ?? "";
  expect(body, "entropy was computed for an unspecified die").not.toContain("2.58");

  // A real die brings the numbers back.
  await sides.fill("6");
  await expect(sides).toHaveAttribute("aria-invalid", "false");
  await expect(page.getByText(/Enter the number of sides on your die/i)).toHaveCount(0);
});
