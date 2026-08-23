import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test, expect, type Page } from "@playwright/test";
import {
  encryptText,
  selectCrypto,
  useTextMode,
  STRONG_PASSWORD,
  BASE_PATH,
} from "./helpers";

/**
 * The app, loaded from the subdirectory it is actually deployed to.
 *
 * Everything else in this project tests `out/` served at the origin root.
 * deploy.yml does not publish that: it builds with `KEYMAKER_BASE_PATH`, and a
 * GitHub Pages project site serves the result from `/<repo>/`. Every asset URL,
 * the hand-written `<link>` tags in layout.tsx, the `new Worker()` path in
 * crypto-client.ts and the service worker's registration and precache list all
 * change. None of it was ever loaded in a browser.
 *
 * What makes that worth a separate job rather than a code review is the shape
 * of the failure. A missing asset under this layout does not produce an error
 * page. The HTML is correct and renders; the chunk that would have reported the
 * problem is the chunk that did not arrive. PR #68 measured exactly this on the
 * release archive opened from `file://`: all ten asset requests failed, no
 * JavaScript ran, and the static shell still painted a heading, a password
 * field and an Encrypt button — "complete enough to look like a styling glitch
 * rather than a dead app. Someone could type a real password into it." The
 * worker path is worse still, because
 * `src/lib/crypto-client.ts` catches a failed worker load and silently falls
 * back to running the derivation in-thread. Nothing is thrown. Nothing is
 * logged. Argon2id at 256 MiB simply freezes the tab instead.
 *
 * So these assertions are about where requests *go*, not only whether the page
 * works. A host lenient enough to serve the root layout too would satisfy "the
 * page works" while the deployment 404s.
 */

const OUT = join(process.cwd(), "out");

/**
 * Origin and base path of the export under test.
 *
 * The origin comes from the config's baseURL; the base path comes from
 * KEYMAKER_BASE_PATH, which is what both the build and the static server were
 * given. Reading it from the environment rather than from a dedicated config
 * is what lets the *whole* browser suite run against this layout instead of
 * only the file you are reading — see playwright.config.ts.
 */
function deployment(baseURL: string | undefined): { origin: string; basePath: string } {
  if (!baseURL) throw new Error("base-path suite requires a baseURL; see playwright.config.ts");
  return { origin: new URL(baseURL).origin, basePath: BASE_PATH };
}

/**
 * Refuse to run against the wrong build.
 *
 * `output: 'export'` always writes to `out/`, so whichever build ran last is
 * what the server is holding. Running this suite against a root build would
 * 404 everything and report a dozen failures that all mean "you built the other
 * layout" — and, worse, a future change that served the root build here would
 * turn the whole file green while testing nothing.
 *
 * A hard failure with the command to fix it, never a skip. A skipped gate is
 * how the CSP/Argon2id bug shipped.
 */
// A root run has no base path to check, so these skip — visibly, in the
// report. The hard failure below is reserved for the case that actually hides
// a bug: a base-path run against a root build, which would 404 everything and
// could be "fixed" by serving the root layout, turning the file green while
// testing nothing.
test.skip(
  () => BASE_PATH === "",
  "no KEYMAKER_BASE_PATH: this run serves the root layout, so there is no base path to verify"
);

test.beforeAll(() => {
  const indexHtml = (() => {
    try {
      return readFileSync(join(OUT, "index.html"), "utf8");
    } catch {
      throw new Error(
        `base-path suite: no export found at ${OUT}. Build with KEYMAKER_BASE_PATH set first.`
      );
    }
  })();

  const { deployBasePath } = require(join(process.cwd(), "scripts", "deploy-base-path.cjs")) as {
    deployBasePath: () => string;
  };
  const basePath = deployBasePath();

  expect(
    indexHtml.includes(`"${basePath}/_next/`),
    `base-path suite: the export in out/ does not reference ${basePath}/_next/, so it was ` +
      `built without KEYMAKER_BASE_PATH. This suite would then be testing the root layout ` +
      `under a base-path server. Rebuild with KEYMAKER_BASE_PATH set.`
  ).toBe(true);
});

/**
 * A full encrypt, driven the way a user would.
 *
 * PBKDF2 rather than the Argon2id default: what is under test is URL
 * resolution, and the KDF's cost buys nothing here. The Argon2id path already
 * has a three-engine matrix against the root layout, and the code that loads it
 * is the same code either way.
 */
async function runEncryption(page: Page): Promise<string> {
  await useTextMode(page);
  await selectCrypto(page, "pbkdf2", "chained");
  return encryptText(page, "a secret encrypted from a subdirectory", STRONG_PASSWORD);
}

test("no request escapes the base path, and every one of them resolves", async ({
  page,
  baseURL,
}) => {
  const { origin, basePath } = deployment(baseURL);

  const requested: string[] = [];
  const escaped: string[] = [];
  const failed: string[] = [];
  const notOk: string[] = [];

  page.on("request", (r) => {
    const url = r.url();
    // data: and blob: never leave the document; there is no path to get wrong.
    if (!url.startsWith("http")) return;
    requested.push(url);
    if (!url.startsWith(`${origin}${basePath}/`)) escaped.push(`${r.method()} ${url}`);
  });
  page.on("requestfailed", (r) => failed.push(`${r.url()} — ${r.failure()?.errorText ?? "failed"}`));
  page.on("response", (r) => {
    if (r.status() >= 400) notOk.push(`${r.status()} ${r.url()}`);
  });

  await page.goto(`${basePath}/`);

  // Every tab, because each mounts a different panel and lazily pulls its own
  // chunks — a prefix that is right on the Encrypt panel and wrong on Tools is
  // a bug this would otherwise walk straight past.
  for (const tab of ["Decrypt", "Tools", "Encrypt"] as const) {
    await page.getByRole("tab", { name: tab }).locator("visible=true").first().click();
  }

  const container = await runEncryption(page);

  // Stated first: this is the assertion the whole file exists for. A request to
  // `${origin}/_next/...` is the deployment 404ing, whatever this server did
  // with it.
  expect(
    escaped,
    `these requests were made outside ${basePath}/ and would 404 on the deployment`
  ).toEqual([]);
  expect(failed, "a request failed outright").toEqual([]);
  expect(notOk, "a request was answered with an error status").toEqual([]);

  // Three assertions on empty arrays are all satisfied by a page that requested
  // nothing, so say what "nothing went wrong" was measured over. The export
  // ships nineteen chunks; ten is a floor, not an expectation.
  expect(
    requested.length,
    "the page made almost no requests — these three empty arrays mean nothing"
  ).toBeGreaterThan(10);

  // And the page did the job, rather than merely loading. Renders-but-cannot-
  // encrypt is the exact symptom this layout produced last time.
  expect(container.startsWith("keym2:")).toBe(true);
});

/**
 * Every URL the document *declares*, whether or not the browser goes and gets
 * it.
 *
 * The test above can only see requests that were actually made, and a headless
 * browser does not fetch a favicon, an apple-touch-icon or a web app manifest.
 * Those four `<link>` tags in layout.tsx are hand-written — Next rewrites its
 * own asset URLs and nothing else — so they are among the *most* likely things
 * to lose the prefix and among the least likely to be requested by a test.
 *
 * Measured: stripping `${BASE}` from all four and rebuilding leaves the
 * request-level test green. This one goes red. That is the whole reason it
 * exists as a separate check rather than a stricter version of the other.
 *
 * `page.request` rather than `fetch()` inside the page, because `connect-src
 * 'none'` is a property this project maintains on purpose and the page cannot
 * open a connection of its own — which is also why nothing here can be checked
 * from inside the document.
 */
test("every URL the document declares is under the base path and resolves", async ({
  page,
  baseURL,
}) => {
  const { origin, basePath } = deployment(baseURL);

  await page.goto(`${basePath}/`);

  const declared = await page.evaluate(() => {
    const attrs: Array<[string, string]> = [
      ["link[href]", "href"],
      ["script[src]", "src"],
      ["img[src]", "src"],
      ["source[src]", "src"],
      ["a[href]", "href"],
    ];
    const seen = new Set<string>();
    for (const [selector, attr] of attrs) {
      for (const el of Array.from(document.querySelectorAll(selector))) {
        const raw = el.getAttribute(attr);
        if (!raw) continue;
        // Resolved against document.baseURI, which is what the browser does.
        // A relative URL is correct by construction; the interesting case is a
        // root-absolute one, which silently ignores the subdirectory.
        const url = new URL(raw, document.baseURI);
        if (url.origin !== location.origin) continue;
        seen.add(url.href);
      }
    }
    return [...seen];
  });

  // A page that declared nothing would pass every assertion below. It has a
  // stylesheet and a script at minimum.
  expect(declared.length, "the document declared no same-origin URLs at all").toBeGreaterThan(2);

  expect(
    declared.filter((u) => !u.startsWith(`${origin}${basePath}/`)),
    `these URLs are declared outside ${basePath}/ and would 404 on the deployment, ` +
      `whether or not this browser fetched them`
  ).toEqual([]);

  // Declared under the right prefix is not the same as present. Fetch each one
  // from outside the page, where the CSP does not apply.
  const broken: string[] = [];
  for (const url of declared) {
    const response = await page.request.get(url);
    if (!response.ok()) broken.push(`${response.status()} ${url}`);
  }
  expect(broken, "a URL the document declares is not served").toEqual([]);
});

/**
 * The crypto worker, specifically.
 *
 * It gets its own test because it is the one asset whose absence is invisible.
 * `spawn()` in src/lib/crypto-client.ts installs an `error` listener that marks
 * the worker unavailable and routes everything in-thread, so a 404 on
 * `crypto-worker.js` costs the user a frozen tab during derivation and produces
 * no failure anywhere — including in the test above, which would still see a
 * `keym2:` container come out.
 */
test("the crypto worker is loaded from under the base path", async ({ page, baseURL }) => {
  const { origin, basePath } = deployment(baseURL);
  const workers: string[] = [];
  page.on("worker", (w) => workers.push(w.url()));

  await page.goto(`${basePath}/`);
  await runEncryption(page);

  expect(
    workers,
    "no worker was created — the derivation ran in-thread, which is what a 404 on " +
      "crypto-worker.js looks like from the outside"
  ).not.toEqual([]);
  // Resolved against the origin before comparing, because the engines disagree
  // on the form and not on the fact. Chromium and WebKit report the worker's
  // script as an absolute URL; firefox reports it as a path
  // ("/Keymaker-v2/crypto-worker.js"). Asserting the absolute string passed on
  // two engines and failed on the third while all three were loading exactly
  // the right file — a test failing on spelling rather than on the property.
  const resolved = workers.map((u) => new URL(u, origin).href);
  expect(
    resolved,
    `the worker was created but not from under ${basePath} — a 404 there falls back ` +
      "to in-thread derivation without reporting anything"
  ).toContain(`${origin}${basePath}/crypto-worker.js`);
});

/**
 * The service worker, which carries the offline claim.
 *
 * Its registration path is hand-written in layout.tsx (Next does not rewrite a
 * string passed to `register()`), and its scope is the directory it is served
 * from. Register it at the origin root from a page under `/Keymaker-v2/` and
 * the browser rejects it outright; register it correctly and every entry in the
 * precache list still has to carry the prefix or install fails and offline
 * support is gone with no visible symptom.
 */
test("the service worker registers under the base path and controls the page", async ({
  page,
  baseURL,
}) => {
  const { origin, basePath } = deployment(baseURL);

  await page.goto(`${basePath}/`);
  // Wrapped, because the bare timeout this raises names nothing. A registration
  // outside the page's own scope — `register('/sw.js')` from a page under
  // /Keymaker-v2/ — is rejected by the browser, and layout.tsx catches that
  // rejection and does nothing with it, so the only symptom is a controller
  // that never arrives.
  await page
    .waitForFunction(() => navigator.serviceWorker?.controller !== null, null, { timeout: 30_000 })
    .catch(() => {
      throw new Error(
        "no service worker ever took control of this page. Either registration was refused " +
          "— the path passed to register() is hand-written in layout.tsx and must carry the " +
          "base path, or its scope excludes the page — or install failed."
      );
    });

  const registration = await page.evaluate(async () => {
    const reg = await navigator.serviceWorker.ready;
    return { scope: reg.scope, script: navigator.serviceWorker.controller?.scriptURL ?? "" };
  });

  expect(registration.script).toBe(`${origin}${basePath}/sw.js`);
  expect(registration.scope).toBe(`${origin}${basePath}/`);

  // Install precaches the app shell and every emitted chunk. If any entry in
  // that list kept a root path, `cache.addAll()` rejects and the whole install
  // fails — so a populated cache under this scope is the assertion that the
  // list was prefixed, not merely that registration succeeded.
  await page.waitForTimeout(4_000);
  const cached = await page.evaluate(async () => {
    const paths: string[] = [];
    for (const key of await caches.keys()) {
      const cache = await caches.open(key);
      for (const req of await cache.keys()) paths.push(new URL(req.url).pathname);
    }
    return paths;
  });

  expect(cached.length, "the service worker cached nothing — its install failed").toBeGreaterThan(0);
  expect(
    cached.filter((p) => !p.startsWith(`${basePath}/`)),
    "the precache list carries entries outside the base path"
  ).toEqual([]);
});

/**
 * The CSP survives the rebuild.
 *
 * scripts/apply-csp-hashes.mjs computes a hash per inline script, and the
 * base-path build's inline scripts are not the root build's — the service
 * worker registration embeds the prefix, so the hashes are recomputed over
 * different bytes. A mismatch blocks the script that installs the worker, and
 * Next's hydration payload with it. platform.spec.ts asserts the policy's
 * *shape* against the root build; this asserts that under this build the
 * browser found nothing to refuse.
 *
 * Nothing is driven here on purpose. Blocked inline script breaks hydration, so
 * a test that tried to encrypt first would fail on a click timing out and never
 * reach the assertion that names the cause — which is what this test is for.
 */
test("the base-path build's inline scripts satisfy its own CSP", async ({ page }) => {
  await page.addInitScript(() => {
    const w = window as unknown as { __cspViolations?: string[] };
    w.__cspViolations = [];
    document.addEventListener("securitypolicyviolation", (e) => {
      w.__cspViolations?.push(`${e.violatedDirective} blocked ${e.blockedURI || "inline"}`);
    });
  });

  await page.goto(`${BASE_PATH}/`);
  await page.waitForLoadState("load");
  // The service worker registration runs on `load`; give it and anything else
  // deferred a moment to be refused before counting.
  await page.waitForTimeout(2_000);

  const violations = await page.evaluate(
    () => (window as unknown as { __cspViolations?: string[] }).__cspViolations ?? []
  );

  expect(violations, "the build's own CSP blocked something the build emitted").toEqual([]);
});
