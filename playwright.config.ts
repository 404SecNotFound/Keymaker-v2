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
  reporter: process.env.CI ? [["github"], ["list"]] : [["list"]],
  // Argon2id at 64 MiB is deliberately slow, and a CI runner is slower still.
  timeout: 120_000,
  expect: { timeout: 30_000 },

  use: {
    baseURL: "http://127.0.0.1:4321",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },

  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
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
