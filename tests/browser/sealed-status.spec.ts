import { test, expect, type Page } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { appPath, BASE_PATH, encryptText, selectCrypto, useTextMode, STRONG_PASSWORD } from "./helpers";

/**
 * The sealed status — trust you can test, not read (10× plan, Bet 5).
 *
 * Three claims the inspector's footer now opens into, each a structural fact
 * the page establishes on the spot, and each checked here against an
 * authority outside the component:
 *
 *  - the policy line it quotes is compared to the CSP meta tag of the served
 *    page, character for character — read, not typed;
 *  - the offline notice is driven by the browser's own network state, and the
 *    claim beside it ("still works") is exercised, not trusted: a seal runs
 *    with the network off;
 *  - the in-place check's manifest digest is compared to sha256 of the
 *    SHA256SUMS the build wrote to out/, and its file count to what the
 *    build precaches.
 *
 * The negative control is built in, as the plan asked: a verifier that
 * cannot fail verifies nothing, so the last test alters the cached manifest
 * — the exact bytes the page reads — and expects the mismatch, by file name.
 */

const OUT = resolve(__dirname, "../../out");

/** The service worker has installed and the manifest is in its cache. */
async function waitForPrecache(page: Page) {
  await page.waitForFunction(() => navigator.serviceWorker?.controller !== null, null, {
    timeout: 30_000,
  });
  await page.waitForFunction(
    async (base) => {
      for (const key of await caches.keys()) {
        if (!key.startsWith("keymaker-")) continue;
        const cache = await caches.open(key);
        if (await cache.match(`${base}/SHA256SUMS`)) return true;
      }
      return false;
    },
    BASE_PATH,
    { timeout: 30_000 }
  );
}

const toggle = (page: Page) => page.getByTestId("sealed-toggle");
const panel = (page: Page) => page.getByTestId("sealed-panel");
const result = (page: Page) => page.getByTestId("verify-result");

test("the status opens and quotes the served page's own connect-src, read rather than typed", async ({ page }) => {
  await page.goto("/");

  // The same precondition platform.spec.ts holds, restated so a page that
  // lost its policy fails here on the cause rather than on a missing quote.
  const csp = await page.evaluate(
    () =>
      document
        .querySelector('meta[http-equiv="Content-Security-Policy"]')
        ?.getAttribute("content") ?? ""
  );
  expect(csp).toContain("connect-src 'none'");

  await expect(toggle(page)).toContainText("sealed");
  await expect(toggle(page)).toHaveAttribute("aria-expanded", "false");
  await expect(panel(page)).toHaveCount(0);

  await toggle(page).click();
  await expect(toggle(page)).toHaveAttribute("aria-expanded", "true");
  await expect(panel(page)).toBeVisible();
  await expect(panel(page)).toContainText("Forbidden to talk to any server");

  // Character for character against the meta tag: the directive shown is
  // the one the browser is enforcing, not a string the component believes.
  const inMeta = csp
    .split(";")
    .map((d) => d.trim())
    .find((d) => d.startsWith("connect-src"));
  await expect(panel(page).getByTestId("sealed-directive")).toHaveText(inMeta!);

  await toggle(page).click();
  await expect(panel(page)).toHaveCount(0);
});

test("offline, the footer says so — and a seal still works, because nothing here needs a server", async ({
  browser,
  browserName,
}) => {
  test.skip(browserName === "webkit", "service worker offline mode is not testable in WebKit here");
  const context = await browser.newContext();
  const page = await context.newPage();
  try {
    await page.goto("/");
    await expect(page.getByTestId("offline-notice")).toHaveCount(0);
    await useTextMode(page);
    await selectCrypto(page, "pbkdf2", "aes");
    // The lazy crypto chunks have to be in the cache before the network goes.
    await waitForPrecache(page);

    await context.setOffline(true);
    await expect(page.getByTestId("offline-notice")).toBeVisible();
    await expect(page.getByTestId("offline-notice")).toContainText("still works");
    await toggle(page).click();
    await expect(panel(page).getByTestId("offline-row")).toContainText("You are offline");

    // The claim, exercised: encrypt with the network off.
    const armored = await encryptText(page, "sealed while offline", STRONG_PASSWORD);
    expect(armored.startsWith("keym2:")).toBe(true);

    await context.setOffline(false);
    await expect(page.getByTestId("offline-notice")).toHaveCount(0);
    await expect(panel(page).getByTestId("offline-row")).toContainText("Try it");
  } finally {
    await context.setOffline(false);
    await context.close();
  }
});

test("the in-place check hashes the cached build against the manifest it shipped with", async ({
  browser,
  browserName,
}) => {
  test.skip(browserName === "webkit", "service worker offline mode is not testable in WebKit here");
  const context = await browser.newContext();
  const page = await context.newPage();
  try {
    await page.goto("/");
    await waitForPrecache(page);
    await toggle(page).click();
    await panel(page).getByRole("button", { name: /^Check now$/ }).click();

    await expect(result(page)).toHaveAttribute("data-outcome", "ok", { timeout: 60_000 });
    await expect(result(page)).toHaveAttribute("role", "status");
    await expect(result(page)).toContainText(/\d+ of \d+ cached files match the manifest/);

    // The authority is the artifact on disk: the digest the page prints must
    // be sha256 of the SHA256SUMS the build wrote, and the number of files it
    // found in the cache must cover at least every chunk the build precaches
    // plus the app shell.
    const manifest = readFileSync(resolve(OUT, "SHA256SUMS"));
    const digest = createHash("sha256").update(manifest).digest("hex");
    await expect(result(page)).toContainText(digest);
    const text = (await result(page).textContent()) ?? "";
    const checked = Number(/(\d+) of \d+ cached files/.exec(text)?.[1]);
    const chunks = manifest
      .toString("utf8")
      .split("\n")
      .filter((l) => /  _next\/static\/.*\.(js|css)$/.test(l)).length;
    expect(chunks, "the manifest lists no chunks — is out/ a build?").toBeGreaterThan(0);
    expect(checked, "fewer files checked than the build precaches").toBeGreaterThanOrEqual(chunks + 1);
  } finally {
    await context.close();
  }
});

test("negative control: an altered manifest in the cache is reported as a mismatch, by file", async ({
  browser,
  browserName,
}) => {
  test.skip(browserName === "webkit", "service worker offline mode is not testable in WebKit here");
  const context = await browser.newContext();
  const page = await context.newPage();
  try {
    await page.goto("/");
    await waitForPrecache(page);

    // Rewrite one chunk's digest in the cached manifest — the exact bytes the
    // page reads — and remember which file it was.
    const victim = await page.evaluate(async (base) => {
      for (const key of await caches.keys()) {
        if (!key.startsWith("keymaker-")) continue;
        const cache = await caches.open(key);
        const held = await cache.match(`${base}/SHA256SUMS`);
        if (!held) continue;
        const text = await held.text();
        const line = text.split("\n").find((l) => /  _next\/static\/chunks\/.*\.js$/.test(l));
        if (!line) return null;
        const path = line.slice(66);
        const altered = text.replace(line, `${"0".repeat(64)}  ${path}`);
        await cache.put(
          `${base}/SHA256SUMS`,
          new Response(altered, { headers: { "content-type": "text/plain" } })
        );
        return path;
      }
      return null;
    }, BASE_PATH);
    expect(victim, "no cached chunk line to alter").not.toBeNull();

    await toggle(page).click();
    await panel(page).getByRole("button", { name: /^Check now$/ }).click();
    await expect(result(page)).toHaveAttribute("data-outcome", "mismatch", { timeout: 60_000 });
    await expect(result(page)).toHaveAttribute("role", "alert");
    await expect(result(page)).toContainText(victim!);
    await expect(result(page)).toContainText("Do not trust this copy");
  } finally {
    await context.close();
  }
});

/**
 * A pending update must not trip the check.
 *
 * The service worker does not call skipWaiting(), so after a deploy the new
 * worker installs and waits while the old one keeps serving. Navigations are
 * network-first, and the worker used to write the fetched page back into its
 * own cache, so the next reload through the *old* worker stored the *new*
 * build's HTML beside the *old* SHA256SUMS. The check then hashed a page the
 * manifest never described, and every routine release produced the red "Do
 * not trust this copy" alert until the user accepted the update: a false
 * alarm from the one control that is supposed to be worth believing.
 *
 * Simulating that deploy means changing the bytes the origin serves, for both
 * sw.js and the page, after the browser has precached them. As in
 * sw-update.spec.ts, request interception does not reach the worker's script
 * fetch, so this runs its own static server over a private copy of out/ on a
 * port of its own, not 4322, which sw-update.spec.ts owns, so the two never
 * share an origin, a registration or a cache.
 */
const OWN_PORT = 4323;
const OWN_ORIGIN = `http://127.0.0.1:${OWN_PORT}`;
const CACHE_VERSION_RE = /const CACHE_VERSION = '([^']*)';/;

async function startOwnOrigin(): Promise<{ dir: string; server: ChildProcess }> {
  const dir = mkdtempSync(join(tmpdir(), "keymaker-sealed-"));
  cpSync(OUT, dir, { recursive: true });
  const server = spawn(
    "node",
    [resolve(process.cwd(), "scripts/static-server.mjs"), dir, String(OWN_PORT), BASE_PATH],
    { stdio: "ignore" }
  );
  const deadline = Date.now() + 30_000;
  for (;;) {
    try {
      const res = await fetch(`${OWN_ORIGIN}${appPath("/sw.js")}`);
      if (res.ok) break;
    } catch {
      // not listening yet
    }
    if (Date.now() > deadline) throw new Error(`static server did not come up on ${OWN_PORT}`);
    await new Promise((r) => setTimeout(r, 200));
  }
  return { dir, server };
}

/**
 * A release lands: the worker's cache name changes, and so do the bytes of
 * the page itself. Both matter, a new worker with an identical index.html
 * would put the same bytes back and hide the defect.
 */
function deployNextVersion(dir: string) {
  const swPath = join(dir, "sw.js");
  const sw = readFileSync(swPath, "utf8");
  const match = sw.match(CACHE_VERSION_RE);
  if (!match) throw new Error("no CACHE_VERSION in sw.js — has the worker changed shape?");
  const nextSw = sw.replace(match[0], "const CACHE_VERSION = 'keymaker-sealed-next-version';");
  expect(nextSw, "the simulated update must differ from the deployed worker").not.toBe(sw);
  writeFileSync(swPath, nextSw);

  const pagePath = join(dir, "index.html");
  const page = readFileSync(pagePath, "utf8");
  writeFileSync(pagePath, `${page}<!-- next release -->`);
}

const swState = (page: Page) =>
  page
    .evaluate(async () => {
      const reg = await navigator.serviceWorker.getRegistration();
      return {
        waiting: reg?.waiting?.state ?? null,
        active: reg?.active?.state ?? null,
        controlled: navigator.serviceWorker.controller !== null,
      };
    })
    .catch(() => null);

test("a waiting update does not make the running build fail its own check", async ({
  browser,
  browserName,
}) => {
  test.skip(browserName === "webkit", "service workers are not testable in WebKit here");
  const { dir, server } = await startOwnOrigin();
  const context = await browser.newContext();
  const page = await context.newPage();
  try {
    await page.goto(`${OWN_ORIGIN}${appPath("/")}`);
    await waitForPrecache(page);
    await expect.poll(() => swState(page)).toMatchObject({ controlled: true, active: "activated" });

    // A release lands while the tab is open; the browser picks it up and the
    // new worker installs, then waits, by design.
    deployNextVersion(dir);
    await page.evaluate(async () => {
      const reg = await navigator.serviceWorker.getRegistration();
      await reg?.update();
    });
    await expect
      .poll(() => swState(page), { message: "the replacement installs and waits" })
      .toMatchObject({ waiting: "installed", active: "activated", controlled: true });

    // A second tab is a navigation through the still-active old worker. It is
    // served the new build's HTML from the network, and that page is exactly
    // what must not end up in the old worker's cache.
    //
    // A second tab rather than a reload, because the two are not the same
    // navigation on every engine. Firefox treats a reloading tab as no longer
    // a client of the registration, promotes the waiting worker, and lands the
    // reload on the new one, so the scenario never happens and the poll below
    // sees `waiting: null`. With the first tab still open the registration
    // keeps a live client and the new worker keeps waiting, everywhere.
    const second = await context.newPage();
    await second.goto(`${OWN_ORIGIN}${appPath("/")}`);
    await expect
      .poll(() => swState(second), { message: "the second tab is served by the old worker" })
      .toMatchObject({ controlled: true, waiting: "installed" });

    await toggle(second).click();
    await panel(second).getByRole("button", { name: /^Check now$/ }).click();
    await expect(result(second)).toHaveAttribute("data-outcome", "ok", { timeout: 60_000 });
    await expect(result(second)).not.toContainText("index.html");
  } finally {
    await context.close();
    server.kill();
    rmSync(dir, { recursive: true, force: true });
  }
});
