#!/usr/bin/env node
/**
 * Build the production export the way the deploy workflow builds it.
 *
 * `npm run build` produces the root layout: every asset at `/_next/...`, the
 * service worker at `/sw.js`. That is what a custom domain or an unpacked
 * release archive serves, and it is what the browser suite has always tested.
 *
 * It is not what github.io serves. A Pages *project* site lives under
 * `/<repo>/`, so deploy.yml sets `KEYMAKER_BASE_PATH` and every one of those
 * URLs moves. This runs the same build with the same variable, taking the value
 * from the workflow rather than repeating it — see scripts/deploy-base-path.cjs.
 *
 * The output goes to `out/`, the same place `npm run build` puts it, because
 * `output: 'export'` has no configurable destination. The two builds therefore
 * overwrite each other, which is why the base-path gate is a separate config
 * and a separate CI job rather than another project in the default run: the two
 * layouts cannot exist at once, so they cannot be served at once.
 */
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const require = createRequire(import.meta.url);
const { deployBasePath } = require('./deploy-base-path.cjs');

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const basePath = deployBasePath();

console.log(`build-base-path: building with KEYMAKER_BASE_PATH=${basePath} (from deploy.yml)`);

execFileSync('npm', ['run', 'build'], {
  cwd: ROOT,
  stdio: 'inherit',
  env: {
    ...process.env,
    KEYMAKER_BASE_PATH: basePath,
    // The build should not phone home here any more than it does in CI.
    NEXT_TELEMETRY_DISABLED: '1',
  },
});
