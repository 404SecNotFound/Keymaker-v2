import { defineConfig, devices, chromium, firefox, webkit } from "@playwright/test";
import { existsSync } from "node:fs";

/**
 * Browser tests run against the **production static export**, not the dev
 * server. That distinction is the entire point of this suite.
 *
 * The CSP meta tag is only emitted for production builds, and the Node test
 * suite runs under no CSP at all. So the two places Keymaker was previously
 * tested were both blind to a policy that blocked WebAssembly and left
 * Argon2id silently dead in the only artifact users actually download.
 *
 * `npm run build` must have run first; `webServer` then serves `out/` exactly
 * as a static host would.
 */
/**
 * When set, the suite runs against a build served under a base path — the
 * layout that actually ships.
 *
 * `deploy.yml` builds production with `KEYMAKER_BASE_PATH: /Keymaker-v2`, so
 * every asset in the shipped HTML is referenced absolutely as
 * `/Keymaker-v2/_next/...`. Served from the origin root, as this suite did
 * until now, those URLs are never exercised: the tests passed against a layout
 * no user receives. PR #68 found the cost of that blind spot — release assets
 * 404 from a `file://` URL, producing a page that renders convincingly and
 * cannot encrypt anything.
 *
 * Build with the same variable and the run covers the real thing:
 *
 *   KEYMAKER_BASE_PATH=/Keymaker-v2 npm run build
 *   KEYMAKER_BASE_PATH=/Keymaker-v2 npm run test:browser
 */
const BASE_PATH = (process.env.KEYMAKER_BASE_PATH ?? "").replace(/\/$/, "");

/**
 * Only the engines whose binaries are actually present — locally.
 *
 * `npx playwright install` needs a CDN, and an environment without one has
 * Chromium and nothing else. The suite then reported ~320 failures that were
 * all `Executable doesn't exist`: three hundred red lines that look exactly
 * like a regression and say nothing about the code. Dropping the projects that
 * cannot run turns that into one honest line.
 *
 * **Never in CI.** There the browsers are installed by a step that can itself
 * break, and a config that quietly skips an engine when its binary is missing
 * would turn that broken step into a green run covering one engine instead of
 * three — the failure this whole suite exists to prevent, hidden by the thing
 * meant to make it readable. In CI every project stays, and a missing binary
 * fails as loudly as it should.
 *
 * If nothing survives, that is not a reason to run zero tests and exit 0. A
 * suite that passes by having no work to do is the worst outcome of the three,
 * so it throws instead.
 */
const ENGINES = [
  { name: "chromium", launcher: chromium, use: devices["Desktop Chrome"] },
  { name: "firefox", launcher: firefox, use: devices["Desktop Firefox"] },
  { name: "webkit", launcher: webkit, use: devices["Desktop Safari"] },
] as const;

const installed = (launcher: { executablePath(): string }): boolean => {
  try {
    return existsSync(launcher.executablePath());
  } catch {
    return false;
  }
};

const PROJECTS = process.env.CI
  ? ENGINES.map((e) => ({ name: e.name, use: { ...e.use } }))
  : (() => {
      const present = ENGINES.filter((e) => installed(e.launcher));
      const absent = ENGINES.filter((e) => !installed(e.launcher)).map((e) => e.name);
      if (present.length === 0) {
        throw new Error(
          "No Playwright browser binaries are installed, so this suite would " +
            "report success without running anything.\n" +
            "Install at least one with `npx playwright install chromium`."
        );
      }
      if (absent.length > 0) {
        console.warn(
          `\nplaywright: skipping ${absent.join(" and ")} — not installed here. ` +
            `Running ${present.map((e) => e.name).join(", ")} only; CI covers all three.\n`
        );
      }
      return present.map((e) => ({ name: e.name, use: { ...e.use } }));
    })();

export default defineConfig({
  testDir: "./tests/browser",
  // Crypto is CPU-bound; too many parallel workers just contend for cores and
  // make the Argon2id cases look like hangs.
  workers: process.env.CI ? 2 : 4,
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: 0,
  // `html` is what writes playwright-report/, which the browser workflow
  // uploads when the job fails. Without it that upload had nothing to find, so
  // every red run discarded its own traces and screenshots — the two artifacts
  // that make a CI-only failure diagnosable instead of guessable from a log.
  //
  // The report is self-contained: attachments are copied into it, so the
  // uploaded directory alone is enough for `npx playwright show-report`.
  reporter: process.env.CI
    ? [["github"], ["list"], ["html", { open: "never" }]]
    : [["list"]],
  // Argon2id at 64 MiB is deliberately slow, and a CI runner is slower still.
  timeout: 120_000,
  expect: { timeout: 30_000 },

  use: {
    baseURL: "http://127.0.0.1:4321",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },

  projects: PROJECTS,

  webServer: {
    // A checked-in server from Node's standard library, not `npx --yes serve`.
    // The previous command resolved and executed an unpinned third-party
    // package at test time, inside the very pipeline that verifies the build's
    // security properties. Nothing shipped to users, but a regression suite
    // that fetches unpinned code at runtime is not reproducible.
    command: `node scripts/static-server.mjs out 4321 ${BASE_PATH}`.trimEnd(),
    url: "http://127.0.0.1:4321",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
