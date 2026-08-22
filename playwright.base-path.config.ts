import { defineConfig, devices } from "@playwright/test";

/**
 * The deployed layout — the one the browser suite never loaded.
 *
 * `playwright.config.ts` serves `out/` at the origin root. deploy.yml builds
 * with `KEYMAKER_BASE_PATH`, so what github.io actually serves lives under
 * `/<repo>/` and every asset URL in the export differs from the one under test.
 * Between those two facts sat an untested layout, and it is the layout users
 * get.
 *
 * That gap is not theoretical. The same class of bug shipped once already: the
 * release archive referenced its assets absolutely, so opening `index.html`
 * from `file://` 404'd all ten and produced a page that rendered convincingly
 * and could not encrypt. It renders because the HTML is fine; it cannot encrypt
 * because the code that would have said so is in a chunk that never arrived.
 *
 * A separate config rather than another project in the default run, for a
 * mechanical reason: `output: 'export'` always writes to `out/`, so the root
 * build and the base-path build overwrite each other. Two layouts that cannot
 * exist at once cannot be served at once.
 */

// Same value deploy.yml publishes with, read from the workflow rather than
// repeated here — see scripts/deploy-base-path.cjs for why a copied literal
// makes this gate quietly stop being about the artifact.
const { deployBasePath } = require("./scripts/deploy-base-path.cjs") as {
  deployBasePath: () => string;
};

const BASE_PATH = deployBasePath();
// Not 4321. The two configs must be able to run back to back without the
// second one finding the first one's server still holding the port and
// serving the other layout — which would look like a pass.
const PORT = 4322;

export default defineConfig({
  testDir: "./tests/base-path",
  // Its own directory, so `npm run test:browser` picks none of this up. The
  // default suite would run these against the root server and fail.
  workers: 1,
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: process.env.CI
    ? [["github"], ["list"], ["html", { open: "never" }]]
    : [["list"]],
  timeout: 120_000,
  expect: { timeout: 30_000 },

  use: {
    // Trailing slash matters: `goto("./")` resolves against it to the app, and
    // a relative asset resolves the way it does on the deployment.
    baseURL: `http://127.0.0.1:${PORT}${BASE_PATH}/`,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },

  // Chromium only, and deliberately. What this gate tests is how the *export*
  // resolves URLs, which is a property of the emitted bytes rather than of an
  // engine — the three-engine matrix in playwright.config.ts is what covers
  // engine differences, against the root layout, and running it twice would
  // triple the cost of this job to re-answer a question it already answered.
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],

  webServer: {
    // The third argument is the base path: the server refuses anything outside
    // it, exactly as a project site does, so a request that forgot the prefix
    // 404s here instead of being quietly satisfied.
    command: `node scripts/static-server.mjs out ${PORT} ${BASE_PATH}`,
    url: `http://127.0.0.1:${PORT}${BASE_PATH}/`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
