import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

/**
 * KM-R06: the worker must evict only its own caches.
 *
 * CacheStorage is per **origin**, and every GitHub Pages project site under
 * `404secnotfound.github.io` shares one. The activation handler used to delete
 * every cache whose name was not the current version — which, read literally,
 * is every cache belonging to every other app the same user has ever opened on
 * that host. Keymaker updating would take their offline copies with it.
 *
 * The bug is invisible from inside Keymaker: its own caches are evicted
 * correctly, offline still works, and every existing test passes. Only a
 * foreign cache shows it, so this test seeds one.
 *
 * It runs against the ordinary suite origin rather than sw-update.spec.ts's
 * private copy, because nothing here needs a simulated release — only an
 * activation ordered after the seeds, which unregistering and reloading
 * provides without a second worker version.
 */

const SW_SOURCE = resolve(process.cwd(), "out/sw.js");
const FOREIGN = "some-other-app-v3";
const STALE_KEYMAKER = "keymaker-an-older-release";

test.describe("service-worker cache ownership", () => {
  test("the prefix and the version cannot drift apart", () => {
    // The ownership test is `startsWith(CACHE_PREFIX)`, so a CACHE_VERSION that
    // stopped matching the prefix would make the worker unable to evict its own
    // old caches — every release would leak one, forever, and nothing else
    // would notice. They are two literals in one file precisely because the
    // build rewrites one of them; this is what keeps them in step.
    const source = readFileSync(SW_SOURCE, "utf8");
    const prefix = source.match(/const CACHE_PREFIX = '([^']*)';/)?.[1];
    const version = source.match(/const CACHE_VERSION = '([^']*)';/)?.[1];

    expect(prefix, "CACHE_PREFIX is missing — has the worker changed shape?").toBeTruthy();
    expect(version, "CACHE_VERSION is missing — has the worker changed shape?").toBeTruthy();
    expect(version!.startsWith(prefix!), `${version} does not start with ${prefix}`).toBe(true);
  });

  test("activation leaves a neighbouring app's cache alone", async ({ page, browserName }) => {
    test.skip(browserName === "webkit", "service workers are unavailable in this WebKit build");

    await page.goto("/");

    // Seed both: one that belongs to someone else, one that is plainly ours and
    // out of date. The second is the control on the first — if activation
    // spared everything, this test would pass while proving nothing.
    await page.evaluate(
      async ([foreign, stale]) => {
        const other = await caches.open(foreign!);
        await other.put("/borrowed", new Response("not keymaker's"));
        const old = await caches.open(stale!);
        await old.put("/stale", new Response("keymaker's, and out of date"));
      },
      [FOREIGN, STALE_KEYMAKER]
    );

    // Both seeds must exist *before* the activation under test, and the
    // previous version of this test did not guarantee that.
    //
    // It seeded after `goto`, then reloaded, on the reasoning that a reload
    // puts the worker through `activate` again. It does not: `activate` fires
    // once per worker *version*, and the version registered by the first load
    // has already had it — quite possibly before the seeds existed. The test
    // passed because activation happens late enough in practice for the seeds
    // to land first, which is a race that happened to be winnable, not an
    // ordering.
    //
    // Unregistering forces the next load to install and activate a fresh
    // worker. That activation cannot precede the seeds, because the worker it
    // belongs to does not exist yet.
    expect(
      await page.evaluate(() => caches.keys()),
      "the seeds are missing before the activation under test — this would pass vacuously"
    ).toEqual(expect.arrayContaining([FOREIGN, STALE_KEYMAKER]));

    await page.evaluate(async () => {
      const registrations = await navigator.serviceWorker.getRegistrations();
      await Promise.all(registrations.map((r) => r.unregister()));
    });

    await page.reload();
    await page.evaluate(() => navigator.serviceWorker.ready);

    await expect
      .poll(() => page.evaluate(() => caches.keys()), { timeout: 30_000 })
      .not.toContain(STALE_KEYMAKER);

    expect(
      await page.evaluate(() => caches.keys()),
      "activation deleted a cache belonging to another app on this origin"
    ).toContain(FOREIGN);

    // And the borrowed entry is intact, not merely the empty cache object.
    expect(
      await page.evaluate(async ([foreign]) => {
        const c = await caches.open(foreign!);
        return (await c.match("/borrowed"))?.text() ?? null;
      }, [FOREIGN]),
      "the foreign cache survived but its contents did not"
    ).toBe("not keymaker's");
  });
});
