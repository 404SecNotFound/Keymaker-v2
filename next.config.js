/** @type {import('next').NextConfig} */

// Subdirectory the app will be served from, without a trailing slash.
//
// Root deployments (a custom domain, a local `serve out/`, Vercel) leave this
// empty. A GitHub Pages *project* site serves at /<repo>/, so the deploy
// workflow sets KEYMAKER_BASE_PATH=/Keymaker-v2 — without it every asset
// request goes to the domain root and the page loads as a blank shell.
const basePath = (process.env.KEYMAKER_BASE_PATH || '').replace(/\/$/, '');

/**
 * Deterministic build id.
 *
 * Next generates a random one per build, and it appears both in the emitted
 * path `_next/static/<buildId>/` and inside the HTML. That single value was the
 * *only* thing making two builds of the same commit differ — every JS and CSS
 * chunk already hashed identically. Left alone it makes the output
 * unreproducible, which would reduce a signed manifest to "CI built this"
 * rather than "rebuild it and check for yourself".
 *
 * The commit SHA is the right value: whoever verifies a deployment knows which
 * commit it claims to be (the manifest records it), and can rebuild exactly
 * that. KEYMAKER_BUILD_ID overrides it for environments without git — a source
 * tarball, say — so verification is still possible there by passing the commit
 * explicitly.
 *
 * The fallback is a constant rather than a timestamp or a random string,
 * because an unreproducible build should be a deliberate choice, not something
 * that happens quietly when git is missing.
 */
function resolveBuildId() {
  if (process.env.KEYMAKER_BUILD_ID) return process.env.KEYMAKER_BUILD_ID;
  if (process.env.GITHUB_SHA) return process.env.GITHUB_SHA;
  try {
    return require('node:child_process')
      .execFileSync('git', ['rev-parse', 'HEAD'], { stdio: ['ignore', 'pipe', 'ignore'] })
      .toString()
      .trim();
  } catch {
    return 'keymaker-local-build';
  }
}

/**
 * The application version, read from package.json at build time.
 *
 * Roadmap 6.1. The footer used to carry its own literal, so two version strings
 * existed and were free to drift — and the one that drifts is the one a user
 * quotes in a bug report, because the footer is the one they can see.
 *
 * This is the *application* version. It is deliberately not the container
 * format version, which is "KEYM v2" and moves only on a format change. The
 * footer states both, separately, because someone whose file will not open
 * needs to know which of the two numbers they are looking at.
 */
const appVersion = require('./package.json').version;

/**
 * The verify page's contents, resolved at build time.
 *
 * Roadmap 6.3. The page tells a visitor which commit the running build claims
 * to be and hands them the commands to check that claim. Both come from
 * somewhere authoritative rather than being typed into a component:
 *
 * - the commit is the same value `generateBuildId` pins the build to, so the
 *   page cannot name a different commit than the one in the asset paths;
 * - the commands are extracted from `docs/VERIFYING.md`, the single place they
 *   are written by hand, for the reason the 6.2 gate gives — a verification
 *   command that does not work is worse than none.
 *
 * Note what is deliberately *not* here: the manifest digest. `SHA256SUMS`
 * covers this page, so baking its digest into the page changes the page and
 * therefore the digest — there is no fixed point. Fetching it at runtime would
 * need `connect-src 'self'`, and `connect-src 'none'` is a property KM-07 was
 * raised to obtain and `platform.spec.ts` exists to keep. A digest served by
 * the same host as the bundle it describes would prove nothing anyway; the
 * commands are the deliverable.
 */
const { deploymentCommands } = require('./scripts/verifying-doc.cjs');
const verifyCommands = deploymentCommands();

const nextConfig = {
  output: 'export',
  generateBuildId: async () => resolveBuildId(),
  ...(basePath ? { basePath, assetPrefix: basePath } : {}),
  // Exposed to client code so the hand-written <link> tags and the service
  // worker registration in layout.tsx can prefix themselves. Next rewrites
  // its own asset URLs, but not ones we author by hand.
  env: {
    KEYMAKER_BASE_PATH: basePath,
    KEYMAKER_APP_VERSION: appVersion,
    KEYMAKER_COMMIT: resolveBuildId(),
    KEYMAKER_VERIFY_COSIGN: verifyCommands.cosign,
    KEYMAKER_VERIFY_SHA256SUM: verifyCommands.sums,
  },
};

// The bundle analyzer is a Webpack-only plugin.
// Since Turbopack is the default in Next.js 15+, we conditionally
// apply the plugin only when we're explicitly running a Webpack build
// for analysis.
if (process.env.ANALYZE === 'true') {
  const withBundleAnalyzer = require('@next/bundle-analyzer')({
    enabled: true,
  });
  module.exports = withBundleAnalyzer(nextConfig);
} else {
  module.exports = nextConfig;
}
