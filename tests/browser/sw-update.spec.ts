import { test, expect, type Page } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

/**
 * Service-worker update semantics.
 *
 * The worker used to call skipWaiting() on install and clients.claim() on
 * activate, so a deployment replaced the running version underneath any open
 * tab and evicted the old cache on the way out. This app's crypto libraries are
 * lazily imported, so a tab part-way through an Argon2id derivation could go
 * looking for a content-hashed chunk that the new cache does not contain —
 * offline, which is the supported way to use the tool, that import simply
 * fails, mid-encryption.
 *
 * The property under test is therefore not "the user is told about updates".
 * It is that **nothing about the running version changes until the user says
 * so**: the old cache is intact for as long as the new worker waits, and the
 * swap happens on the click and not before.
 *
 * Simulating a deployment means changing the bytes the origin serves for
 * sw.js. Playwright's request interception does not reach the browser's
 * service-worker script fetch (verified: the route handler is never called and
 * the browser re-reads the real file), so this test runs its own static server
 * over a private copy of out/ on its own port. That also isolates it from the
 * shared suite: a different port is a different origin, so no other test's
 * registration or cache is touched.
 */

const BUILD_DIR = resolve(process.cwd(), "out");
const PORT = 4322;
const ORIGIN = `http://127.0.0.1:${PORT}`;
const NEW_CACHE = "keymaker-test-next-version";

const CACHE_VERSION_RE = /const CACHE_VERSION = '([^']*)';/;

/** Serve a private, writable copy of the production export. */
async function startOwnOrigin(): Promise<{ dir: string; server: ChildProcess }> {
  const dir = mkdtempSync(join(tmpdir(), "keymaker-sw-"));
  cpSync(BUILD_DIR, dir, { recursive: true });

  const server = spawn("node", [resolve(process.cwd(), "scripts/static-server.mjs"), dir, String(PORT)], {
    stdio: "ignore",
  });

  const deadline = Date.now() + 30_000;
  for (;;) {
    try {
      const res = await fetch(`${ORIGIN}/sw.js`);
      if (res.ok) break;
    } catch {
      // not listening yet
    }
    if (Date.now() > deadline) throw new Error(`static server did not come up on ${PORT}`);
    await new Promise((r) => setTimeout(r, 200));
  }
  return { dir, server };
}

/** Rewrite the served worker so the browser sees a new release. */
function deployNextVersion(dir: string): string {
  const path = join(dir, "sw.js");
  const original = readFileSync(path, "utf8");
  const match = original.match(CACHE_VERSION_RE);
  if (!match) throw new Error("no CACHE_VERSION in sw.js — has the worker changed shape?");

  const next = original.replace(match[0], `const CACHE_VERSION = '${NEW_CACHE}';`);
  expect(next, "the simulated update must differ from the deployed worker").not.toBe(original);
  writeFileSync(path, next);
  return match[1]!;
}

/**
 * Read something out of the page, yielding null if the page is mid-navigation.
 *
 * Accepting the update reloads the tab, which destroys the execution context
 * under any evaluate in flight. Returning null instead of throwing lets
 * expect.poll ride through that window and settle on the post-reload state.
 */
async function probe<T>(page: Page, fn: () => Promise<T> | T): Promise<T | null> {
  try {
    return await page.evaluate(fn);
  } catch {
    return null;
  }
}

const cacheNames = (page: Page) => probe(page, () => caches.keys());

/**
 * Registration state, read in one round trip.
 *
 * Deliberately not `page.waitForFunction(() => ...getRegistration().then(...))`:
 * that predicate returns a pending Promise, which waitForFunction treats as
 * truthy, so the wait passes immediately having asserted nothing. `expect.poll`
 * awaits the evaluate properly.
 */
const swState = (page: Page) =>
  probe(page, async () => {
    const reg = await navigator.serviceWorker.getRegistration();
    return {
      waiting: reg?.waiting?.state ?? null,
      active: reg?.active?.state ?? null,
      controlled: navigator.serviceWorker.controller !== null,
    };
  });

test.describe("service worker updates wait for the user", () => {
  test("a waiting update leaves the running version untouched until accepted", async ({
    browser,
    browserName,
  }) => {
    test.skip(browserName === "webkit", "service workers are not testable in WebKit here");

    const { dir, server } = await startOwnOrigin();
    const context = await browser.newContext();
    const page = await context.newPage();

    try {
      await page.goto(`${ORIGIN}/`);
      await expect.poll(() => swState(page)).toMatchObject({ controlled: true, active: "activated" });

      const oldCache = readFileSync(join(dir, "sw.js"), "utf8").match(CACHE_VERSION_RE)![1]!;
      await expect.poll(() => cacheNames(page)).toEqual([oldCache]);

      // Nothing pending, so nothing should be asking the user to reload.
      await expect(page.locator("#sw-update-banner")).toHaveCount(0);

      // A release lands while the tab is open.
      deployNextVersion(dir);
      await page.evaluate(async () => {
        const reg = await navigator.serviceWorker.getRegistration();
        await reg?.update();
      });

      // The new worker installs, then stops.
      await expect
        .poll(() => swState(page), { message: "the replacement installs and waits" })
        .toMatchObject({ waiting: "installed", active: "activated", controlled: true });

      // The assertion this file exists for. The replacement is installed and
      // ready, and the running version has lost nothing: its cache is still
      // there, so a lazily imported chunk resolves exactly as it did a moment
      // ago. Both caches coexist precisely because the old one was not evicted.
      await expect
        .poll(() => cacheNames(page), {
          message: "the running version's cache survives a pending update",
        })
        .toEqual(expect.arrayContaining([oldCache, NEW_CACHE]));

      // The offer is made, and it is a real button rather than a click handler
      // on a div — the update path has to be reachable from the keyboard.
      const banner = page.locator("#sw-update-banner");
      await expect(banner).toBeVisible();
      expect(await banner.evaluate((el) => el.tagName)).toBe("BUTTON");

      // Accepting is what promotes the worker; the page then reloads onto it.
      await banner.click();
      await expect
        .poll(() => swState(page), { message: "the accepted update takes over" })
        .toMatchObject({ waiting: null, active: "activated", controlled: true });

      // Only now is the superseded version's cache evicted.
      await expect.poll(() => cacheNames(page)).toEqual([NEW_CACHE]);
      await expect(page.getByRole("tab", { name: "Encrypt" })).toBeVisible();
    } finally {
      await context.close();
      server.kill();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("the deployed worker does not call skipWaiting on install", async () => {
    // The behavioural test above needs a second origin and a real update cycle.
    // This one is cheap, needs no browser, and catches the specific regression —
    // a stray skipWaiting() in the install path — in the artifact that ships.
    const source = readFileSync(join(BUILD_DIR, "sw.js"), "utf8");
    // Comments are stripped first: the install handler's comment explains at
    // length why it does not call skipWaiting, and would match on the word.
    const code = source
      .split("\n")
      .filter((line) => !line.trim().startsWith("//"))
      .join("\n");

    const installBody = code.slice(
      code.indexOf("addEventListener('install'"),
      code.indexOf("addEventListener('message'")
    );
    expect(installBody, "install handler must not promote the new worker").not.toContain("skipWaiting");

    // It must still be reachable on request, or an accepted update never lands.
    expect(code.slice(code.indexOf("addEventListener('message'"))).toContain("skipWaiting");
    expect(source).toContain("SKIP_WAITING");
  });

  test("the deployed worker promotes only for a page it serves", async () => {
    // `message` is same-origin, and on GitHub Pages the origin is shared with
    // every other project site the same account publishes. That is not a
    // theoretical neighbour: it is the same fact that made cache eviction a
    // cross-app problem in KM-R06. Any of those pages can reach this
    // registration through `navigator.serviceWorker.getRegistration()` and
    // post to `registration.waiting`, and an unguarded handler would promote
    // — swapping the running version out from under a tab that is part-way
    // through encrypting a seed phrase, which is the exact outcome the install
    // handler declines to cause on its own.
    //
    // Asserted against the built artifact for the reason the test above gives:
    // the behavioural version needs a second scope and a real update cycle,
    // and the regression worth catching is a guard deleted from the file that
    // ships.
    const source = readFileSync(join(BUILD_DIR, "sw.js"), "utf8");
    const code = source
      .split("\n")
      .filter((line) => !line.trim().startsWith("//"))
      .join("\n");

    const messageBody = code.slice(code.indexOf("addEventListener('message'"));

    // The sender's own URL, checked against this registration's scope. Both
    // halves matter: `event.source` is what the browser sets to the sending
    // client and cannot be forged from script, and `registration.scope` is
    // what distinguishes our page from a neighbour on the same origin.
    expect(
      messageBody,
      "the message handler does not look at which client sent it"
    ).toContain("event.source");
    expect(
      messageBody,
      "the message handler does not check the sender against the worker's scope"
    ).toContain("registration.scope");

    // And the guard has to run before the promotion, not after it.
    expect(
      messageBody.indexOf("registration.scope"),
      "the scope check comes after skipWaiting, so it guards nothing"
    ).toBeLessThan(messageBody.indexOf("self.skipWaiting()"));
  });
});
