import { test, expect, type Page } from "@playwright/test";
import { visible, useTextMode, STRONG_PASSWORD } from "./helpers";

/**
 * A crypto operation that is interrupted must fall silent.
 *
 * Argon2id takes one to three seconds on ordinary hardware, and nothing stops
 * the user switching tab or input type during it. Before this was handled, the
 * abandoned operation carried on regardless: it wrote its output, fired a
 * "Success!" toast onto whichever panel was now visible, and — the damaging
 * part — ran the unconditional `setPassword('')` in its `finally`, wiping a
 * password the user had typed in the meantime.
 *
 * These are UI-level races. The crypto core behaves perfectly in both cases, so
 * no Node test can see them; only a real browser driving real React state can,
 * which is why they shipped.
 *
 * ## What is actually being tested, now that there are two defences
 *
 * Every interruption does two things — see `resetState`, `wipeSensitiveState`
 * and `handleInputTypeChange`, where the two lines always appear together. It
 * bumps `opSeqRef`, so the completion path disowns itself, and it calls
 * `cancelAllCryptoWork()`, which *terminates the worker*.
 *
 * The termination happens first, and it changes what these tests can see. A
 * terminated derivation never reaches the success path at all, so no
 * interaction available to a user can produce the stale "Success!" these tests
 * were originally named after. What it produces instead is a rejection —
 * `Error("Cancelled.")` from `failAllPending` — and the sequence guard on the
 * *catch* path is what stops that surfacing as "Processing Error" on a panel
 * the user has just moved to.
 *
 * That is the leak these tests hold shut. Removing `if (!isStale())` from the
 * catch block is the control that proves it: an interrupted operation then
 * announces "Processing Error — Processing failed. Please try again." on a tab
 * that never ran it, and both tests below fail. Removing the same guard from
 * the success path changes nothing observable, because the cancel gets there
 * first — so a test written against *that* path would pass either way, which
 * is what these did until it was measured.
 *
 * The invariant asserted below is therefore the user-visible one — **interrupt
 * an operation and the UI you moved to says nothing about it, success or
 * failure** — rather than a claim about which mechanism delivered it. Both are
 * load-bearing: the guard alone would leave a cancelled operation shouting, and
 * the cancel alone would still lose the sub-millisecond race where the worker
 * posts its result before `terminate()` lands.
 *
 * ## Opening the race
 *
 * Both tests need the same precondition: the operation must still be running
 * when the interaction lands. That window is
 *
 *     (how long the operation takes) − (how long the interaction takes to land)
 *
 * and the only honest way to hold it open is to make the first term large. It
 * is a user-facing setting — Argon2id's cost — so these tests turn it up rather
 * than emulating anything.
 *
 * An earlier version instead selected PBKDF2 and applied 4x CDP CPU throttling,
 * on the reasoning that Argon2id ran through hash-wasm on the main thread and
 * froze the tab, so only the WebCrypto path was interruptible. Both halves of
 * that stopped being true when crypto moved into a Worker: every derivation now
 * runs off the main thread, so both KDFs are interruptible and neither freezes
 * the page.
 *
 * The throttling had by then inverted. `Emulation.setCPUThrottlingRate` slows
 * the renderer's *main thread*; the derivation is on the worker's. Measured
 * here: 1048 ms unthrottled against 1288 ms at 4x — the operation was barely
 * touched, while the interaction that has to land inside it was slowed
 * fourfold. It was narrowing the race it claimed to widen, until on a loaded CI
 * runner the interaction began landing *after* the operation had already
 * finished. Nothing was stale on those runs, the announcement was legitimate,
 * and the assertion read it as a leak. Three red runs on an unrelated pull
 * request were all this.
 *
 * So: no throttling, a deliberately expensive KDF, and the precondition
 * asserted rather than assumed. If the window ever closes again, these fail
 * with "the race never opened" instead of blaming the guard.
 */

/**
 * Argon2id at ten passes over 128 MiB, against defaults of three over 64.
 *
 * Measured on this suite's build: 1058 ms at the default cost, 3063 ms here,
 * against an interaction that lands in ~350 ms. The fixed ~800 ms of worker
 * spawn and WASM load is why the default is not enough on its own — it leaves
 * only ~250 ms of actual derivation to interrupt, and a contended runner eats
 * that. Raising the cost buys margin in the only term that is not overhead.
 *
 * 256 MiB would buy more still (6116 ms), at two of these resident per runner
 * and twice the wall clock. This is the point where the margin is ~9x and the
 * pair of tests still finishes in well under half a minute.
 */
const SLOW_KDF = { timeCost: 10, memoryMiB: 128 };

/**
 * How long to keep watching after the interaction lands, as a multiple of one
 * measured operation, plus a fixed floor.
 *
 * Silence has to be held past the point where the abandoned operation *would*
 * have finished, or it says nothing: a run that stops watching early cannot
 * tell a terminated worker from one that is still going and about to speak.
 * That moment is not observable from outside — the panel that owned it is
 * unmounted and a correctly handled operation is silent by definition — so the
 * window is sized from a measured run instead, and the half extra covers the
 * second run being slower than the one that was measured.
 */
const WATCH_MULTIPLE = 1.5;
const WATCH_FLOOR_MS = 3_000;

/**
 * Everything the app has announced, as a screen reader would receive it.
 *
 * Toasts are the app's only announcement channel, and they live outside the tab
 * panels — which is exactly why an abandoned operation could shout onto a panel
 * that never ran it. Reading the live region rather than the whole document
 * keeps this from being tripped by page prose containing the same words.
 *
 * Returns "" when nothing has been announced, including if the region is not
 * found at all. That failure-open shape is why `measureOperation` exists in the
 * form it does: it proves this function can see a real announcement, so the
 * silence assertions cannot pass merely because the selector went stale.
 */
function announcements(page: Page): Promise<string> {
  return page.evaluate(() => {
    const region = document.querySelector<HTMLElement>(
      '[role="region"][aria-label*="otification"]'
    );
    return (region?.innerText ?? "").trim();
  });
}

/** A fresh page, in Text mode, at the slow KDF, with the form filled. */
async function prepareEncrypt(page: Page) {
  await page.goto("/");
  await useTextMode(page);

  const advanced = visible(page.getByRole("button", { name: /^Advanced/ }));
  if ((await advanced.getAttribute("aria-expanded")) !== "true") await advanced.click();
  await visible(page.getByRole("button").filter({ hasText: "Argon2id" })).click();
  await visible(page.getByRole("slider", { name: "Argon2id time cost" })).fill(
    String(SLOW_KDF.timeCost)
  );
  await visible(page.getByRole("slider", { name: "Argon2id memory" })).fill(
    String(SLOW_KDF.memoryMiB)
  );

  // The window these tests need is bought entirely by those two sliders, and a
  // control that silently ignored a programmatic change would leave the whole
  // file racing at the default cost while still reading as though it were not.
  // The app already prints what it will actually use; this reads it back.
  await expect(
    visible(page.getByText(`Argon2id(${SLOW_KDF.memoryMiB} MiB, t=${SLOW_KDF.timeCost},`)),
    "the cost sliders did not take — the derivation would run at the default cost and the " +
      "window below would be far narrower than this file claims"
  ).toBeVisible();

  await visible(page.getByPlaceholder("Enter text to encrypt")).fill("secret being encrypted");
  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
}

/**
 * Time one uninterrupted operation on this machine, and prove the instrument
 * works while doing it.
 *
 * Measured rather than assumed: a contended CI runner is several times slower
 * than a laptop, and both windows below are multiples of this number. A
 * constant would be either too tight there or wastefully long here.
 */
async function measureOperation(page: Page): Promise<number> {
  await prepareEncrypt(page);
  const started = Date.now();
  await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();
  await expect
    .poll(() => announcements(page), {
      message:
        "an uninterrupted run announced nothing. Either encryption is broken, or " +
        "`announcements` is no longer looking where the toasts are — in which case every " +
        "silence assertion in this file passes without checking anything",
      timeout: 60_000,
    })
    .toMatch(/Success!/);
  return Date.now() - started;
}

/**
 * Begin the operation without awaiting the click.
 *
 * Interrupting re-renders — and in the tab case unmounts — the button we are
 * clicking, so the click's own actionability checks can reject long after the
 * operation is underway. That rejection is not a failure of anything.
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

/**
 * The precondition, checked at the moment the interaction lands.
 *
 * A success already announced means the operation completed while it still
 * owned the UI. That announcement is correct, the interaction was never an
 * interruption, and everything after this point would be reading a legitimate
 * toast as a leak.
 *
 * Only a *success* is disqualifying here. Anything else already on screen is a
 * leak rather than a closed window, and the watch loops report it as one.
 */
async function confirmRaceOpened(page: Page, landedMs: number, operationMs: number) {
  expect(
    await announcements(page),
    `the race never opened: the interaction landed ${landedMs} ms in, but the operation had ` +
      `already succeeded (an uninterrupted one takes ${operationMs} ms here). Nothing was ` +
      `interrupted, so nothing was tested — widen the window by raising SLOW_KDF rather than ` +
      `relaxing what follows.`
  ).not.toMatch(/Success!/);
}

test.describe("an operation that loses the UI falls silent", () => {
  test("switching input type mid-derivation does not wipe a newly typed password", async ({
    page,
    browserName,
  }) => {
    // Not a technical limit — nothing here needs CDP any more. The timings that
    // make the race reliably observable have only been established on Chromium,
    // and this is the wrong test to widen on an unmeasured guess.
    test.skip(browserName !== "chromium", "window timings measured on Chromium only");

    const operationMs = await measureOperation(page);
    // A fresh page: the measured run left an announcement standing and cleared
    // the password field it had just used.
    await prepareEncrypt(page);

    const started = Date.now();
    const inFlight = startOperation(page, /^Encrypt Text$/i);
    await confirmInFlight(page);

    // A real click: dispatchEvent skips Radix's pointer handling, and a
    // control that never actually switched would make this test pass or fail
    // for reasons unrelated to the interruption.
    await visible(page.getByRole("button", { name: "File", exact: true })).click();
    const NEW_PASSWORD = "a-completely-different-password-9271!X";
    const passwordField = visible(page.getByPlaceholder("Enter a strong password"));
    await passwordField.fill(NEW_PASSWORD);
    await confirmRaceOpened(page, Date.now() - started, operationMs);

    // Hold both invariants continuously rather than sampling once after a fixed
    // sleep: the abandoned operation would have finished at an unpredictable
    // point inside this window, and a single late check could miss a wipe.
    const watchUntil = Date.now() + operationMs * WATCH_MULTIPLE + WATCH_FLOOR_MS;
    while (Date.now() < watchUntil) {
      expect(
        await passwordField.inputValue(),
        "the abandoned operation cleared a password field it no longer owns"
      ).toBe(NEW_PASSWORD);
      expect(
        await announcements(page),
        "an abandoned operation announced its outcome after the input type had moved on"
      ).toBe("");
      await page.waitForTimeout(250);
    }

    await inFlight;
  });

  test("switching tabs mid-derivation leaves the new tab silent", async ({
    page,
    browserName,
  }) => {
    test.skip(browserName !== "chromium", "window timings measured on Chromium only");

    const operationMs = await measureOperation(page);
    // A fresh page above all else here: the measured run's own announcement is
    // indistinguishable from the leak this test looks for.
    await prepareEncrypt(page);

    const started = Date.now();
    const inFlight = startOperation(page, /^Encrypt Text$/i);
    await confirmInFlight(page);

    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await confirmRaceOpened(page, Date.now() - started, operationMs);

    const watchUntil = Date.now() + operationMs * WATCH_MULTIPLE + WATCH_FLOOR_MS;
    while (Date.now() < watchUntil) {
      expect(
        await announcements(page),
        "an abandoned operation announced its outcome on a tab that never ran it"
      ).toBe("");
      await page.waitForTimeout(250);
    }

    // The Decrypt panel is usable, not stuck mid-operation. resetState
    // returns the input type to File, so match either button name.
    await expect(
      visible(page.getByRole("button", { name: /^Decrypt (File|Text)$/i })),
      "the Decrypt panel should be interactive, not stuck loading"
    ).toBeVisible();

    await inFlight;
  });
});

// The dice-tool tests that used to live here have moved to dice.spec.ts, which
// is where the rest of the entropy-inflation cases now are.
