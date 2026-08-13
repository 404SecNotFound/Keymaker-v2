/** @type {import('next').NextConfig} */

// Subdirectory the app will be served from, without a trailing slash.
//
// Root deployments (a custom domain, a local `serve out/`, Vercel) leave this
// empty. A GitHub Pages *project* site serves at /<repo>/, so the deploy
// workflow sets KEYMAKER_BASE_PATH=/Keymaker-v2 — without it every asset
// request goes to the domain root and the page loads as a blank shell.
const basePath = (process.env.KEYMAKER_BASE_PATH || '').replace(/\/$/, '');

const nextConfig = {
  output: 'export',
  ...(basePath ? { basePath, assetPrefix: basePath } : {}),
  // Exposed to client code so the hand-written <link> tags and the service
  // worker registration in layout.tsx can prefix themselves. Next rewrites
  // its own asset URLs, but not ones we author by hand.
  env: { KEYMAKER_BASE_PATH: basePath },
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
