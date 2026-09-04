import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { test, expect } from "@playwright/test";
import {
  appPath,
  encryptText,
  selectCrypto,
  useTextMode,
  STRONG_PASSWORD,
  type Cipher,
  type Kdf,
} from "./helpers";

/**
 * Platform guarantees that only exist in a browser running the production
 * bundle: the CSP, WebAssembly availability under that CSP, zero egress, the
 * service worker, and offline operation.
 *
 * None of this is observable from Node. Every regression these catch would
 * otherwise ship green.
 */

test("the production page ships a strict CSP", async ({ page }) => {
  await page.goto("/");
  const csp = await page.evaluate(
    () =>
      document
        .querySelector('meta[http-equiv="Content-Security-Policy"]')
        ?.getAttribute("content") ?? ""
  );

  expect(csp, "CSP meta tag must be present in the production build").not.toBe("");
  expect(csp).toContain("default-src 'none'");
  // The *page* must not be able to open a connection at all. Worth being exact
  // about the scope of this one: the policy is delivered as a <meta> tag, and a
  // <meta> policy does not reach Web Workers, so it does not constrain the
  // crypto worker. Measured against the production export, same-origin target:
  // page fetch BLOCKED, worker fetch ALLOWED 200. See the "gap" section in
  // docs/HOW-IT-WORKS.md — this assertion covers the document, and the worker's
  // behaviour rests on the code plus the reproducible build.
  expect(csp).toContain("connect-src 'none'");
  // Which makes this load-bearing rather than incidental: injected script must
  // not be able to start a worker of its own to escape the directive above. A
  // blob: worker is the obvious route, and 'self' is what refuses it. Untested
  // until the worker gap was measured, at which point it stopped being a
  // hardening nicety and became the thing bounding the blast radius.
  expect(csp).toContain("worker-src 'self'");
  expect(csp).toContain("object-src 'none'");
  expect(csp).toContain("base-uri 'none'");
  const scriptSrc = csp.split(";").find((d) => d.trim().startsWith("script-src")) ?? "";

  // script-src is tightened at build time from 'unsafe-inline' to per-file
  // hashes, and this checks the *whole* directive rather than the one token
  // that used to go wrong.
  //
  // Asserting `not.toContain("'unsafe-inline'")` is a deny-list of length one.
  // It answers "did we make the specific mistake we made before?", and that
  // is not the same question as "is this policy tight". `script-src 'self'
  // 'wasm-unsafe-eval' 'sha256-…' *` satisfies every assertion this block used
  // to make — no 'unsafe-inline', a hash present, wasm-unsafe-eval present —
  // while permitting script from anywhere on the web. A bare scheme, a host,
  // 'unsafe-eval', or 'strict-dynamic' all slip through the same gap, the last
  // of which reduces the hashes to decoration by delegating trust to whatever
  // they go on to load.
  const allowed = new Set(["'self'", "'wasm-unsafe-eval'"]);
  const isHash = (src: string) => /^'sha(256|384|512)-[A-Za-z0-9+/]+={0,2}'$/.test(src);
  const sources = scriptSrc.trim().split(/\s+/).slice(1);
  expect(
    sources.filter((src) => !allowed.has(src) && !isHash(src)),
    "script-src carries a source that is neither allow-listed nor a hash"
  ).toEqual([]);

  // And the two that must be present, rather than merely permitted: without a
  // hash nothing inline runs, and Argon2id cannot instantiate without wasm.
  expect(sources.some(isHash), "no inline-script hash in script-src").toBe(true);
  expect(scriptSrc).toContain("'wasm-unsafe-eval'");

  // style-src keeps 'unsafe-inline' deliberately: React and Tailwind set
  // style="" attributes, which hashes cannot cover without 'unsafe-hashes'
  // and a per-attribute hash for every one — fragile, for no gain here.
  const styleSrc = csp.split(";").find((d) => d.trim().startsWith("style-src")) ?? "";
  expect(styleSrc).toContain("'unsafe-inline'");
});

test("WebAssembly can actually compile under that CSP", async ({ page }) => {
  await page.goto("/");
  const result = await page.evaluate(async () => {
    try {
      // Smallest valid module: the 8-byte header.
      await WebAssembly.instantiate(new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]));
      return "ok";
    } catch (e) {
      return `blocked: ${(e as Error).message}`;
    }
  });
  // This exact assertion is the regression test for the shipped Argon2id bug.
  expect(result).toBe("ok");
});

test("Argon2id is the default and the UI does not offer a dead option", async ({ page }) => {
  await page.goto("/");
  await useTextMode(page);
  await page.getByRole("button", { name: /^Advanced/ }).locator("visible=true").first().click();
  await page.waitForTimeout(1500); // let the capability probe settle

  const state = await page.evaluate(() => {
    const buttons = Array.from(document.querySelectorAll("button"));
    const argon = buttons.find((b) => b.textContent?.includes("Argon2id"));
    return {
      argonText: argon?.textContent ?? "",
      argonDisabled: argon?.hasAttribute("disabled") ?? false,
      // The selected option says so in a machine-readable way — aria-pressed
      // — rather than via whatever border class the current design paints.
      // The class sniff broke the day the palette changed, which is exactly
      // the kind of coupling a selection test should not have.
      argonSelected: argon?.getAttribute("aria-pressed") === "true",
    };
  });

  // Where WASM works — every browser in this matrix — Argon2id must be the
  // default rather than a recommendation the user has to go and find.
  expect(state.argonDisabled).toBe(false);
  expect(state.argonSelected).toBe(true);
  expect(state.argonText).toContain("default");
});

test("no off-origin request is ever made", async ({ page }) => {
  const offOrigin: string[] = [];
  page.on("request", (r) => {
    if (!r.url().startsWith("http://127.0.0.1:4321") && !r.url().startsWith("data:")) {
      offOrigin.push(`${r.method()} ${r.url()}`);
    }
  });

  await page.goto("/");
  await useTextMode(page);
  await selectCrypto(page, "argon2id", "chained");
  await encryptText(page, "a secret that must not leave the device", STRONG_PASSWORD);

  expect(offOrigin, "the page must not talk to anything").toEqual([]);
});

/**
 * Offline coverage for every KDF x cipher combination, each on *first use*.
 *
 * The important word is first. An earlier version of this test loaded the
 * page, went offline, and ran Argon2id + AES — which proved only that the one
 * path it had already exercised still worked. Crypto dependencies are lazily
 * imported and the service worker runtime-caches a chunk when it is requested,
 * so a combination the user had never selected could have had its chunk
 * missing precisely when the network was gone.
 *
 * Each case therefore gets a fresh browser context, loads the page exactly
 * once, goes offline, and only then selects its algorithms. Exercising a
 * cipher online first would populate the cache and invalidate the test.
 */
const OFFLINE_MATRIX: Array<[Kdf, Cipher]> = [
  ["pbkdf2", "aes"],
  ["pbkdf2", "chacha"],
  ["pbkdf2", "chained"],
  ["argon2id", "aes"],
  ["argon2id", "chacha"],
  ["argon2id", "chained"],
];

for (const [kdf, cipher] of OFFLINE_MATRIX) {
  test(`offline first use: ${kdf} + ${cipher}`, async ({ browser, browserName }) => {
    // Service workers are not available in WebKit under Playwright's default
    // configuration, so offline support cannot be exercised there.
    test.skip(browserName === "webkit", "service worker offline mode is not testable in WebKit here");

    // A fresh context guarantees an empty HTTP cache and no service worker,
    // so nothing from a previous case can satisfy this one.
    const context = await browser.newContext();
    const page = await context.newPage();
    const failedRequests: string[] = [];
    page.on("requestfailed", (r) => failedRequests.push(r.url().split("/").pop() ?? r.url()));

    try {
      await page.goto("/");
      await page.waitForFunction(() => navigator.serviceWorker?.controller !== null, null, {
        timeout: 30_000,
      });
      // Give the warm-up a moment to pull the lazy crypto chunks into cache.
      await page.waitForTimeout(2_000);

      await context.setOffline(true);
      await page.reload();
      await expect(page.getByRole("tab", { name: "Encrypt" })).toBeVisible();

      // First time this combination has been touched, and there is no network.
      await useTextMode(page);
      await selectCrypto(page, kdf, cipher);
      const container = await encryptText(page, `offline ${kdf} ${cipher}`, STRONG_PASSWORD);
      expect(container.startsWith("keym2:")).toBe(true);

      expect(
        failedRequests,
        `a request failed while offline — a dependency was not cached: ${failedRequests.join(", ")}`
      ).toEqual([]);
    } finally {
      await context.setOffline(false);
      await context.close();
    }
  });
}

/**
 * Every shipped chunk must be in the *service worker* cache after a first
 * visit — not merely reachable.
 *
 * The offline matrix above cannot see this. It passed at 3 of 17 chunks
 * cached, because Playwright's offline emulation still lets Chromium's HTTP
 * disk cache answer, and that cache had everything from the load a moment
 * earlier. So the suite reported full offline support while the service worker
 * was holding almost none of the app.
 *
 * The difference matters on the timescale users actually experience. The HTTP
 * cache is evictable and heuristic; the Cache Storage entry is not. Load the
 * page today, come back next week on a plane, and only what the worker kept is
 * still there. Testing against a warm HTTP cache measures the wrong one.
 *
 * This counts what the worker itself holds, which is the thing the offline
 * claim in the README is actually about.
 */
test("the service worker caches every shipped chunk on a first visit", async ({
  browser,
  browserName,
}) => {
  test.skip(browserName === "webkit", "service worker offline mode is not testable in WebKit here");

  const outDir = join(process.cwd(), "out");
  const walk = (dir: string): string[] =>
    readdirSync(dir).flatMap((name) => {
      const p = join(dir, name);
      return statSync(p).isDirectory() ? walk(p) : [p];
    });
  const shipped = walk(join(outDir, "_next", "static"))
    .filter((f) => /\.(js|css)$/.test(f))
    // Prefixed, because the cached entries are URL pathnames and the
    // deployment mounts everything under the base path.
    .map((f) => appPath(f.slice(outDir.length)));

  expect(shipped.length, "expected the export to have emitted chunks").toBeGreaterThan(0);

  const context = await browser.newContext();
  const page = await context.newPage();
  try {
    await page.goto("/");
    await page.waitForFunction(() => navigator.serviceWorker?.controller !== null, null, {
      timeout: 30_000,
    });
    // The install precaches; give it room to finish writing before counting.
    await page.waitForTimeout(4_000);

    const cached = new Set(
      await page.evaluate(async () => {
        const paths: string[] = [];
        for (const key of await caches.keys()) {
          const cache = await caches.open(key);
          for (const req of await cache.keys()) paths.push(new URL(req.url).pathname);
        }
        return paths;
      })
    );

    const missing = shipped.filter((f) => !cached.has(f));
    expect(
      missing,
      `${missing.length}/${shipped.length} shipped chunks are absent from the service worker ` +
        `cache. Offline support for these depends on the browser's HTTP cache, which it may ` +
        `evict at any time: ${missing.join(", ")}`
    ).toEqual([]);
  } finally {
    await context.close();
  }
});

/**
 * The page must not scroll sideways on a phone.
 *
 * This shipped, and it is the reason a bug report about the dice tool arrived
 * as "look at the padding": the header put a wordmark and three tabs on one
 * row needing 412px, and the Encrypt panel's four action buttons needed 470px
 * in a row they could not shrink out of. Below those widths the whole document
 * shifted left, so every panel underneath — including the dice results grid —
 * looked like its columns were overlapping. Nothing was wrong with the grid.
 *
 * 320px is the narrowest phone still in use, 375px an iPhone SE or mini, 393px
 * a Pixel, 430px the largest iPhone. 375 and 393 straddle the width at which
 * the header wordmark reappears, which is the tightest margin in the layout —
 * and text metrics are not identical across engines, so this running in all
 * three is the point. All three tabs are checked because each mounts a
 * different panel and any of them can be the thing that overflows.
 */
for (const width of [320, 360, 375, 393, 430]) {
  test(`no horizontal overflow at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/");

    for (const tab of ["Encrypt", "Decrypt", "Audio", "Tools"] as const) {
      await page.getByRole("tab", { name: tab }).locator("visible=true").first().click();

      const overflow = await page.evaluate(() => {
        const doc = document.documentElement;
        // Report the widest offender too — "it overflows" is not actionable on
        // its own, and the culprit is rarely the element you are looking at.
        let worst = { sel: "", right: doc.clientWidth };
        for (const el of Array.from(doc.querySelectorAll("*"))) {
          const box = el.getBoundingClientRect();
          if (box.width === 0 || box.right <= worst.right) continue;
          // className on an SVG element is an SVGAnimatedString, which
          // stringifies to "[object SVGAnimatedString]" and names nothing.
          const raw = (el as HTMLElement | SVGElement).className;
          const cls = (typeof raw === "string" ? raw : (raw?.baseVal ?? "")).slice(0, 60);
          worst = { sel: `${el.tagName.toLowerCase()}.${cls}`, right: box.right };
        }
        return { px: doc.scrollWidth - doc.clientWidth, worst };
      });

      expect(
        overflow.px,
        `${tab} tab scrolls sideways by ${overflow.px}px at ${width}px — widest element: ${overflow.worst.sel}`
      ).toBeLessThanOrEqual(1);
    }
  });
}
