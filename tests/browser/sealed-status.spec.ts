import { test, expect, type Page } from "@playwright/test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { BASE_PATH, encryptText, selectCrypto, useTextMode, STRONG_PASSWORD } from "./helpers";

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
