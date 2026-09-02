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
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
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
// The two Latin font files ride along for the same reason the chunks do: they
// are content-hashed, and without them the first offline visit renders in the
// fallback stack — the app works, but looks different offline, which is
// exactly the kind of quiet inconsistency the precache exists to prevent.
// Only Latin: the other subsets are fetched on demand for text that uses them,
// and precaching every script would quadruple the font bytes for glyphs the UI
// never draws.
//
// The patterns name the families, so they go stale silently when the UI moves
// — which has now happened twice: once when the identity left Inter, and again
// when the text face left Satoshi for Plus Jakarta Sans. Both times the only
// symptom was an offline first visit in the fallback face. The assertions
// below turn that back into a build failure.
//
// One entry per family, each asserted separately. A single combined count is
// the version of this check that cannot fail for the reason it exists: with
// two families and one total, the mono face alone keeps the number above zero
// while the text face — the one that sets the whole page — is quietly absent.
const FONT_PRECACHE = [
  { family: 'Plus Jakarta Sans (text and display)', re: /plus-jakarta-sans-latin(-ext)?-wght-normal[^/]*\.woff2$/ },
  { family: 'JetBrains Mono (data surfaces)', re: /jetbrains-mono-latin(-ext)?-wght-normal[^/]*\.woff2$/ },
];
const isPrecachedFont = (f) => FONT_PRECACHE.some(({ re }) => re.test(f));
const wanted = (f) => /\.(js|css)$/.test(f) || isPrecachedFont(f);

const staticDir = join(OUT_DIR, '_next', 'static');
const staticFiles = walk(staticDir).filter(wanted);

const missing = FONT_PRECACHE.filter(({ re }) => !staticFiles.some((f) => re.test(f)));
if (missing.length) {
  for (const { family } of missing) {
    console.error(
      `build-id: ERROR — no font files matched the precache pattern for ${family}. ` +
        'It was renamed or replaced and FONT_PRECACHE was not updated, so the first ' +
        'offline visit would render it in the fallback stack.'
    );
  }
  process.exit(1);
}
const fontCount = staticFiles.filter(isPrecachedFont).length;

const precache = staticFiles.map((f) => `${BASE}${f.slice(OUT_DIR.length)}`).sort();

if (precache.length === 0) {
  console.error('build-id: ERROR — no static chunks found to precache. Did the export run?');
  process.exit(1);
}

const precacheBytes = staticFiles.reduce((n, f) => n + readFileSync(f).length, 0);

// Every hand-written entry in the worker's own precache list must exist in the
// export. That list is maintained by hand — the chunks are injected below, but
// the app shell, the recovery kit, the icons and the hero plate are typed out —
// so renaming one of those files anywhere else in the tree leaves a path here
// pointing at nothing.
//
// The consequence is out of all proportion to the typo. `cache.addAll()` is
// atomic: one 404 rejects the whole call, so install fails, no worker ever takes
// control, and everything that depends on one fails at once — offline first use,
// precache coverage, cache isolation, update semantics, the base-path suite.
// That is exactly what a renamed hero plate did: 29 red tests across all three
// engines, not one of whose names mentions the asset, while the build and the
// palette audit both stayed green.
//
// Checked against the export rather than the repo, because the export is what
// the worker will actually fetch.
const listed = [...sw.matchAll(/`\$\{BASE\}(\/[^`]*)`/g)].map((m) => m[1]);
if (listed.length === 0) {
  console.error(
    'build-id: ERROR — found no `${BASE}/…` entries in the service worker. The ' +
      'precache list changed shape, so this check is no longer reading it and would ' +
      'pass whatever the list said. Update the pattern rather than deleting the check.'
  );
  process.exit(1);
}
// SHA256SUMS is the one entry that cannot exist yet: build-manifest.mjs
// writes it *after* this script, because it has to cover the stamped worker.
// It is always written — a build that skipped it would fail install, loudly,
// on every service-worker test — so the exemption is narrow and named.
const PRODUCED_LATER = new Set(['/SHA256SUMS']);
const unresolved = listed.filter((p) => !PRODUCED_LATER.has(p) && !existsSync(join(OUT_DIR, p)));
if (unresolved.length) {
  for (const p of unresolved) {
    console.error(
      `build-id: ERROR — the service worker precaches ${p}, which the export does not ` +
        'contain. cache.addAll() is atomic, so this one 404 fails install and every ' +
        'service-worker test with it. Fix the path in public/sw.js.'
    );
  }
  process.exit(1);
}

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
