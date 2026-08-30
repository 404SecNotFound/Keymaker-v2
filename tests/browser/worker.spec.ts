import { test, expect, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { visible, useTextMode, encryptText, STRONG_PASSWORD } from "./helpers";
import { WORST_CASE_PROBE_MS } from "../../src/lib/worker-probe-policy";

/**
 * Crypto runs off the main thread.
 *
 * The number that motivates this whole change: with Argon2id on the main
 * thread at 256 MiB / t=10, an interaction issued 200 ms into the derivation
 * did not complete for **22.3 seconds**. hash-wasm is synchronous and
 * CPU-bound, so the tab was simply dead — nothing painted, nothing responded,
 * and the user could not even cancel. The same settings on a phone are worse.
 *
 * These tests hold the fix in place. They assert responsiveness directly
 * rather than asserting that a Worker object exists, because "a worker was
 * constructed" is not the property anyone cares about — "the tab still works"
 * is.
 */

/** Max out the Argon2id sliders: the configuration that froze the tab. */
async function maxOutArgon2id(page: Page) {
  const advanced = visible(page.getByRole("button", { name: /^Advanced/ }));
  if ((await advanced.getAttribute("aria-expanded")) !== "true") await advanced.click();
  await visible(page.getByRole("button").filter({ hasText: "Argon2id" })).click();
  await visible(page.getByLabel("Argon2id memory")).fill("256");
  await visible(page.getByLabel("Argon2id time cost")).fill("10");
}

/**
 * Start the operation without awaiting it, with a bounded click.
 *
 * Two hazards, both hit in CI:
 *
 *  - Awaiting the click serialises the test behind actionability checks and
 *    closes the very window we want to act inside.
 *  - Not bounding it is worse. Once the operation is interrupted the button's
 *    label changes ("Encrypt Text" becomes "Encrypt File"), so a click still
 *    retrying actionability is now waiting on a locator that will never match
 *    again. On WebKit that hung until the 120 s test timeout.
 *
 * So: fire it, bound it, and swallow the failure — a click that loses its
 * target because the test deliberately moved the target is not a defect.
 */
function startOperation(page: Page, label: RegExp): Promise<void> {
  return visible(page.getByRole("button", { name: label }))
    .click({ timeout: 15_000 })
    .catch(() => {});
}

/** Fail loudly if the derivation is not actually running yet. */
async function confirmInFlight(page: Page) {
  await expect(
    page.locator(".animate-spin").first(),
    "the derivation never started — this test proves nothing unless it is in flight"
  ).toBeVisible({ timeout: 20_000 });
}

test("the crypto worker is what actually runs the derivation", async ({ page }) => {
  const workers: string[] = [];
  page.on("worker", (w) => workers.push(w.url()));

  await page.goto("/");
  // Warm-up spawns it on mount; give the probe a moment to answer.
  await page.waitForTimeout(2_000);

  expect(
    workers.filter((u) => u.endsWith("/crypto-worker.js")),
    "the page should have started the dedicated crypto worker"
  ).not.toHaveLength(0);
});

test("the tab stays responsive through a maximum-cost Argon2id derivation", async ({ page }) => {
  await page.goto("/");
  await useTextMode(page);
  await maxOutArgon2id(page);
  await page.waitForTimeout(1_500); // let the readiness probe settle

  await visible(page.getByPlaceholder("Enter text to encrypt")).fill("secret");
  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);

  // Start it without awaiting — we are measuring what happens *during*.
  const running = startOperation(page, /^Encrypt Text$/i);

  // Poll the page for a timestamp and record the largest gap between
  // consecutive successful replies.
  //
  // Sampling continuously rather than checking once after a fixed sleep is the
  // point. An earlier version waited 500 ms and then measured, which passed
  // against the *blocking* build too: the derivation had not necessarily
  // started yet, so it measured an idle thread and proved nothing. A gap is
  // only observable if you are still looking when it opens.
  const SAMPLE_FOR_MS = 8_000;
  const deadline = Date.now() + SAMPLE_FOR_MS;
  let previous = Date.now();
  let worstGapMs = 0;

  while (Date.now() < deadline) {
    await page.evaluate(() => Date.now());
    const now = Date.now();
    worstGapMs = Math.max(worstGapMs, now - previous);
    previous = now;
    await page.waitForTimeout(100);
  }

  // Measured: ~30 ms with the worker, and multiple seconds without it (22.3 s
  // at these settings when the derivation ran on the main thread). 2 s is a
  // ceiling loose enough to never flake and tight enough to catch a freeze.
  expect(
    worstGapMs,
    `the main thread stalled for ${worstGapMs} ms during the derivation — it is not running off-thread`
  ).toBeLessThan(2_000);

  await running;
});

test("a derivation can be cancelled, and the tab recovers", async ({ page }) => {
  await page.goto("/");
  await useTextMode(page);
  await maxOutArgon2id(page);
  await page.waitForTimeout(1_500);

  await visible(page.getByPlaceholder("Enter text to encrypt")).fill("secret");
  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
  const running = startOperation(page, /^Encrypt Text$/i);
  // Confirm it is genuinely running first. A fixed sleep was not enough on a
  // slow runner: the click could still be pending, so the test would "cancel"
  // an operation that had never started and assert nothing of value.
  await confirmInFlight(page);

  // Switching input type disowns the operation, which now terminates the
  // worker rather than merely ignoring its result. Before the worker there was
  // no way to stop a synchronous WASM derivation at all: an abandoned run went
  // to completion, burning CPU for an answer nobody would receive.
  await visible(page.getByRole("button", { name: "File", exact: true })).click();

  // The app is immediately usable again — not waiting out a derivation that no
  // longer has a destination.
  await expect(visible(page.getByRole("button", { name: /^Encrypt File$/i }))).toBeVisible({
    timeout: 5_000,
  });
  await expect(page.locator(".animate-spin")).toHaveCount(0);

  await running;
});

/**
 * If the worker cannot load, encryption still works.
 *
 * Losing the worker must degrade responsiveness, never capability. This also
 * covers the ordering hazard that shaped the client's design: buffers are
 * *transferred* to the worker and detached on this side, so a worker that
 * turns out to be broken after being handed the only copy of someone's
 * plaintext would lose it. The client therefore proves the worker answers a
 * probe before trusting it with real data — this test blocks the script so
 * that probe fails, and the round-trip must still complete in-thread.
 */
test("encryption still works when the worker script cannot load", async ({ page }) => {
  await page.route("**/crypto-worker.js", (route) => route.abort());

  await page.goto("/");
  await useTextMode(page);
  await page.waitForTimeout(2_000); // let the probe fail

  const container = await encryptText(page, "fallback path still encrypts", STRONG_PASSWORD);
  expect(container.startsWith("keym2:")).toBe(true);
});

/**
 * The way out of a long derivation, and the notice that says one is coming.
 *
 * Until now the only way to halt a running KDF was to switch input type, which
 * terminates the worker as a side effect of disowning the operation. That
 * works and is undiscoverable. A container can honestly ask for minutes —
 * measured at 315 s for eight PBKDF2 slots at the §6 ceiling — so there has to
 * be a button, and it has to actually stop the work rather than merely hide
 * the spinner.
 */
test("a running derivation can be stopped, and the inputs survive", async ({ page }) => {
  // Watch the worker itself. Without this the test passes against a "cancel"
  // that only calls setIsLoading(false): the spinner goes, the button comes
  // back, and the derivation grinds on in a worker nobody is listening to —
  // which is the pre-worker behaviour this button exists to end.
  const closed: string[] = [];
  page.on("worker", (w) => w.on("close", () => closed.push(w.url())));

  await page.goto("/");
  await useTextMode(page);
  await maxOutArgon2id(page);
  await page.waitForTimeout(1_500);

  await visible(page.getByPlaceholder("Enter text to encrypt")).fill("secret");
  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
  const running = startOperation(page, /^Encrypt Text$/i);
  await confirmInFlight(page);

  const stop = visible(page.getByTestId("cancel-operation"));
  await expect(stop, "no way to stop a derivation that can take minutes").toBeVisible();

  // Baseline taken here, not at zero. The app spawns a warm-up worker on mount
  // and that one closes on its own, so "at least one worker has ever closed"
  // is already true before the click — an assertion on the total passed
  // against a cancel with cancelAllCryptoWork() deleted. What has to be shown
  // is a close caused *by this click*.
  const closedBefore = closed.length;
  await stop.click();

  // Stopped, not merely hidden: the spinner is gone and the primary button is
  // usable again rather than waiting out a derivation nobody will receive.
  await expect(page.locator(".animate-spin")).toHaveCount(0, { timeout: 10_000 });
  await expect(visible(page.getByRole("button", { name: /^Encrypt Text$/i }))).toBeEnabled();

  // The derivation is actually dead, not merely disowned.
  await expect
    .poll(() => closed.length, {
      message: "no worker closed when Stop was pressed — the derivation is still running",
      timeout: 10_000,
    })
    .toBeGreaterThan(closedBefore);

  // And the point of a dedicated cancel rather than reusing the auto-lock's
  // wipe: someone who stops a slow unlock wants to not-wait, not to start
  // over. clearSensitiveState would have emptied both of these.
  await expect(
    visible(page.getByPlaceholder("Enter text to encrypt")),
    "stopping threw away the text the user had entered"
  ).toHaveValue("secret");
  await expect(
    visible(page.getByPlaceholder("Enter a strong password")),
    "stopping threw away the password the user had typed"
  ).toHaveValue(STRONG_PASSWORD);

  await running;
});

/**
 * Stop is honest about what it did.
 *
 * With a worker, the click terminates it and the derivation genuinely ends —
 * the test above. With no worker there is nothing to terminate: the derivation
 * runs in this realm, WebCrypto finishes it whatever the page does, and all
 * Stop can achieve is discarding the result. Both are worth doing and only one
 * is a cancellation. Saying "the unlock was cancelled" in the second case is
 * the KM-02 shape — a claim the software has not earned — and it lands on
 * precisely the browsers least able to afford the wait it is denying.
 *
 * ## Three dead ends, recorded so nobody re-walks them
 *
 *  - **Argon2id with no worker never renders the button.** hash-wasm derives
 *    synchronously, so on the main thread it blocks the event loop and React
 *    never paints Stop. A real property, and a friendlier one than this case:
 *    a frozen tab cannot mislead anybody.
 *  - **Encrypting cannot be made slow enough.** The UI writes PBKDF2 at a fixed
 *    1,000,000 iterations, about a second of WebCrypto.
 *  - **Building the container in-page and reloading does not remove the
 *    worker.** `page.route(…, abort)` only sees the network; once the service
 *    worker has precached crypto-worker.js it serves it from cache on the
 *    reload and the page has a perfectly good worker. The route has to be in
 *    place before the first navigation, which means the container cannot come
 *    from this page — hence the fixture.
 */
test("Stop does not claim to have cancelled work it could not stop", async ({ page }) => {
  const fixture = JSON.parse(
    readFileSync(join(process.cwd(), "tests/browser/fixtures/expensive-pbkdf2.json"), "utf8")
  ) as { password: string; armor: string };

  // Before the first goto, so no service worker is ever registered to serve a
  // cached copy of the script we are trying to take away.
  await page.route("**/crypto-worker.js", (route) => route.abort());

  await page.goto("/");
  await useTextMode(page);
  await page.waitForTimeout(2_000); // let the readiness probe fail

  await visible(page.getByRole("tab", { name: "Decrypt" })).click();
  await useTextMode(page);
  await visible(page.getByPlaceholder("Enter text to decrypt")).fill(fixture.armor);
  await visible(page.getByPlaceholder("Enter decryption password")).fill(fixture.password);
  const running = startOperation(page, /^Decrypt Text$/i);
  await confirmInFlight(page);

  await visible(page.getByTestId("cancel-operation")).click();

  // The wording has to distinguish the two cases, and has to say what actually
  // becomes of the work rather than going quiet about it.
  await expect(
    page.getByText(/run to completion/i).first(),
    "Stop reported a cancellation on a page with no worker to cancel"
  ).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText(/^The unlock was cancelled/)).toHaveCount(0);

  // Still a usable outcome: the inputs survive, as they do with a worker.
  await expect(
    visible(page.getByPlaceholder("Enter decryption password")),
    "stopping threw away the password the user had typed"
  ).toHaveValue(fixture.password);

  await running;
});

/**
 * The tab is about to freeze, and the page says so first.
 *
 * With no Worker, Argon2id derives in hash-wasm on the main thread: the event
 * loop is blocked for the whole run, so the spinner does not animate and Stop
 * never renders. The work completes and the container is identical — the tab is
 * simply gone for the duration, which §6 permits to be minutes.
 *
 * The alternative fix was quietly lowering the cost when no worker is
 * available. That is the trade this project does not make: the KDF and its
 * parameters are the user's choice, and writing a weaker backup than the one
 * they asked for to spare them a wait is worse than the wait.
 *
 * Aborting the script *before the first navigation* is what reliably produces a
 * no-worker page — the same setup as "encryption still works when the worker
 * script cannot load" above. Delaying it does not, which is a separate story
 * recorded in crypto-client.ts.
 */
test("a derivation that will freeze the tab says so before it starts", async ({ page }) => {
  await page.route("**/crypto-worker.js", (route) => route.abort());

  await page.goto("/");
  await useTextMode(page);
  await maxOutArgon2id(page);
  // Settle the form, nothing more. This does NOT wait for the readiness probe
  // to fail: on an engine that takes the timeout path that needs
  // WORST_CASE_PROBE_MS, and reading this line as "the probe has failed by now"
  // is what produced the assertion deadline below being set to exactly the
  // worst case.
  await page.waitForTimeout(2_000);

  await visible(page.getByPlaceholder("Enter text to encrypt")).fill("secret");
  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
  const running = startOperation(page, /^Encrypt Text$/i);

  // Derived, not chosen. This assertion cannot resolve until the readiness
  // probe gives up, and that takes WORST_CASE_PROBE_MS when the worker script
  // neither loads nor errors. The deadline used to be a hard-coded 20 s, which
  // is exactly WORST_CASE_PROBE_MS: the test was racing the thing it was
  // waiting for, and whichever side of the boundary a run landed on decided it.
  // Chromium and WebKit never reach the timeout path — an aborted worker script
  // fires an error event and they resolve in milliseconds — so only Firefox
  // flaked, which reads like an engine bug and is not one.
  //
  // Hard-coding a bigger number would fix today's flake and re-arm the trap the
  // next time either constant moves, so the deadline comes from the constants.
  await expect(
    page.getByText(/stop responding until it finishes/i).first(),
    "no warning before a derivation that blocks the event loop — the tab freezes " +
      "with no spinner and no Stop button, and nothing said it would"
  ).toBeVisible({ timeout: WORST_CASE_PROBE_MS + 15_000 });

  await running;
});

test("a worker-backed derivation does not warn about a freeze", async ({ page }) => {
  // The control on the test above. Same settings, worker available: the warning
  // must not appear, or it is decoration rather than information.
  await page.goto("/");
  await useTextMode(page);
  await maxOutArgon2id(page);
  await page.waitForTimeout(2_000);

  await visible(page.getByPlaceholder("Enter text to encrypt")).fill("secret");
  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
  const running = startOperation(page, /^Encrypt Text$/i);
  await confirmInFlight(page);

  await expect(
    page.getByText(/stop responding until it finishes/i),
    "warned about a frozen tab while running off-thread, where nothing freezes"
  ).toHaveCount(0);

  await running;
});

test("the Stop button is absent when nothing is running", async ({ page }) => {
  // The control on the test above: if Stop were always rendered, finding it
  // mid-derivation would prove nothing about the busy state.
  await page.goto("/");
  await useTextMode(page);
  await expect(page.getByTestId("cancel-operation")).toHaveCount(0);
});
