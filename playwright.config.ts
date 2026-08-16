import { defineConfig, devices } from "@playwright/test";

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

  projects: [
    {
      name: "chromium",
      use: {
        ...devices["Desktop Chrome"],
        // The runner has no GPU, and the headless shell kept trying anyway.
        //
        // Playwright 1.62's bundled chrome-headless-shell segfaults during
        // startup on the CI runner — SIGSEGV in the gpu-process, immediately
        // after `drmGetDevices2() has not found any devices`. It never reaches
        // a test: the error surfaces from `browser.newContext`, and the test it
        // gets blamed on is only whichever one was next in a deterministic
        // queue (`fullyParallel: false`), which is why it looked like one
        // specific spec had broken. 1.56's shell survived the same path.
        //
        // Asking for a GPU that is not there was never buying anything here.
        // Argon2id is WebAssembly and the QR canvases already rasterise in
        // software — that is what `--enable-unsafe-swiftshader` in Playwright's
        // own default flags is for.
        launchOptions: { args: ["--disable-gpu"] },
      },
    },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
  ],

  webServer: {
    // A checked-in server from Node's standard library, not `npx --yes serve`.
    // The previous command resolved and executed an unpinned third-party
    // package at test time, inside the very pipeline that verifies the build's
    // security properties. Nothing shipped to users, but a regression suite
    // that fetches unpinned code at runtime is not reproducible.
    command: "node scripts/static-server.mjs out 4321",
    url: "http://127.0.0.1:4321",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
