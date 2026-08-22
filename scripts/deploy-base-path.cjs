/**
 * Read the deployment's base path out of .github/workflows/deploy.yml.
 *
 * A GitHub Pages *project* site is served from `/<repo>/`, not the domain root,
 * so the deploy workflow builds with `KEYMAKER_BASE_PATH` set. That single line
 * changes every asset URL in the export, the hand-written `<link>` tags, the
 * service worker's registration path and its precache list.
 *
 * Nothing else read it. The browser suite served `out/` at the root, so the
 * layout that actually ships was the one layout never loaded in a browser —
 * and the failure mode is not a blank page but a page that renders convincingly
 * and cannot encrypt, because a `new Worker()` whose script 404s degrades to an
 * in-thread fallback rather than an error (src/lib/crypto-client.ts).
 *
 * So the base-path gate takes its value from here rather than repeating the
 * literal. A repeated literal is a gate that keeps testing `/Keymaker-v2` after
 * the deployment has moved somewhere else: still green, no longer about the
 * artifact. Reading the workflow means the two cannot disagree — change the
 * deploy and the gate follows it, or fails saying it no longer knows what ships.
 *
 * ## Why CommonJS
 *
 * playwright.config.ts and the CI workflow consume it, the way
 * next.config.js consumes scripts/verifying-doc.cjs. One implementation, two
 * module systems — see that file for the same reasoning at more length.
 */
const { readFileSync } = require('node:fs');
const { join } = require('node:path');

const ROOT = join(__dirname, '..');
const DEPLOY = join(ROOT, '.github', 'workflows', 'deploy.yml');

/**
 * The base path the deploy workflow builds with, without a trailing slash.
 *
 * Requiring *exactly* one assignment is deliberate, for the reason
 * verifying-doc.cjs requires exactly one command block: two would mean the
 * workflow grew a second build step, and picking one arbitrarily would be this
 * code guessing which of them is the one that gets published.
 *
 * An absent assignment throws rather than returning `''`. Silently falling back
 * to a root build would turn this gate into a duplicate of the suite it was
 * added to complement — passing, testing the wrong layout, saying nothing.
 */
function deployBasePath() {
  const workflow = readFileSync(DEPLOY, 'utf8');
  const found = [...workflow.matchAll(/^\s*KEYMAKER_BASE_PATH:\s*(\S+)\s*$/gm)].map((m) =>
    m[1].replace(/^['"]|['"]$/g, '')
  );

  if (found.length !== 1) {
    throw new Error(
      `deploy-base-path: expected exactly one KEYMAKER_BASE_PATH assignment in ` +
        `.github/workflows/deploy.yml, found ${found.length}. The base-path gate ` +
        `takes the layout under test from the workflow that publishes it; it cannot ` +
        `run without knowing which value ships.`
    );
  }

  const base = found[0].replace(/\/$/, '');
  if (!base.startsWith('/')) {
    throw new Error(
      `deploy-base-path: KEYMAKER_BASE_PATH is "${found[0]}", which is not an ` +
        `absolute path. next.config.js passes it to Next as \`basePath\`, which ` +
        `requires a leading slash.`
    );
  }
  return base;
}

module.exports = { deployBasePath };
