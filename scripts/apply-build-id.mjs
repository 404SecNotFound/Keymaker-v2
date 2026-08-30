#!/usr/bin/env node
/**
 * Stamp the service worker's cache name with a content-derived build id.
 *
 * public/sw.js ships with `keymaker-__BUILD_ID__`. This replaces the
 * placeholder in the *built* copy under out/ with a short hash of everything
 * the build emitted, so a release that changes any shipped byte gets a new
 * cache name and a release that changes nothing does not.
 *
 * Why not a hand-maintained version constant: the previous one read
 * 'keymaker-v1.0.0' across several shipped changes to the service worker
 * itself, including a caching-scope change. A constant is only correct while
 * someone remembers to bump it, and nothing failed when they didn't.
 *
 * Why it matters beyond staleness: the activate handler distinguishes a real
 * upgrade from a first install by looking for a cache under a different name.
 * If the name never changes, that check can never fire, and clients are never
 * told a new version is active.
 *
 * Fails closed — if the placeholder is missing, the build stops rather than
 * silently shipping an unversioned worker.
 */
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const OUT_DIR = new URL('../out', import.meta.url).pathname;
const SW = join(OUT_DIR, 'sw.js');
const PLACEHOLDER = '__BUILD_ID__';
const ASSETS_PLACEHOLDER = '__PRECACHE_ASSETS__';
const BASE = (process.env.KEYMAKER_BASE_PATH || '').replace(/\/$/, '');

function walk(dir) {
  const found = [];
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) found.push(...walk(p));
    else found.push(p);
  }
  return found;
}

let sw;
try {
  sw = readFileSync(SW, 'utf8');
} catch {
  console.error('build-id: ERROR — out/sw.js not found. Did the export run?');
  process.exit(1);
}

if (!sw.includes(PLACEHOLDER)) {
  console.error(
    `build-id: ERROR — ${PLACEHOLDER} not present in out/sw.js. The service ` +
      'worker would ship with a cache name that never changes, which also ' +
      'disables its upgrade detection. Refusing to continue.'
  );
  process.exit(1);
}

if (!sw.includes(ASSETS_PLACEHOLDER)) {
  console.error(
    `build-id: ERROR — ${ASSETS_PLACEHOLDER} not present in out/sw.js. Without ` +
      'a precache manifest the worker can only cache chunks it happens to ' +
      'intercept, so a dependency fetched before it takes control is missing ' +
      'offline. Refusing to ship an unreliable offline guarantee.'
  );
  process.exit(1);
}

// Every JS/CSS chunk the export emitted, as request paths. Content-hashed and
// therefore immutable, which is what makes precaching them safe.
//
// The two Latin Inter files ride along for the same reason the chunks do:
// they are content-hashed, and without them the first offline visit renders
// in the fallback stack — the app works, but looks different offline, which
// is exactly the kind of quiet inconsistency the precache exists to prevent.
// Only Latin: the other subsets are fetched on demand for text that uses
// them, and precaching every script would quadruple the font bytes for
// glyphs the UI never draws.
const staticDir = join(OUT_DIR, '_next', 'static');
const precache = walk(staticDir)
  .filter((f) => /\.(js|css)$/.test(f) || /inter-latin(-ext)?-wght-normal[^/]*\.woff2$/.test(f))
  .map((f) => `${BASE}${f.slice(OUT_DIR.length)}`)
  .sort();

if (precache.length === 0) {
  console.error('build-id: ERROR — no static chunks found to precache. Did the export run?');
  process.exit(1);
}

const precacheBytes = walk(staticDir)
  .filter((f) => /\.(js|css)$/.test(f) || /inter-latin(-ext)?-wght-normal[^/]*\.woff2$/.test(f))
  .reduce((n, f) => n + readFileSync(f).length, 0);

// Hash every emitted file except the worker itself, whose content is about to
// depend on the hash. Paths are included so a pure rename still counts.
const hash = createHash('sha256');
for (const file of walk(OUT_DIR)) {
  if (file === SW) continue;
  hash.update(file.slice(OUT_DIR.length));
  hash.update(readFileSync(file));
}
const buildId = hash.digest('hex').slice(0, 12);

const stamped = sw
  .replaceAll(PLACEHOLDER, buildId)
  .replace(ASSETS_PLACEHOLDER, JSON.stringify(precache, null, 2));

writeFileSync(SW, stamped, 'utf8');
console.log(`build-id: service worker cache is keymaker-${buildId}`);
console.log(
  `build-id: precaching ${precache.length} chunk(s), ${(precacheBytes / 1024).toFixed(0)} KB`
);
