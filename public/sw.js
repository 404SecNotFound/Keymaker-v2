// Keymaker Service Worker — hand-rolled, zero dependencies
//
// Cache version. The literal below is a placeholder: the build replaces it
// with a hash of the emitted bundle (see scripts/apply-build-id.mjs), because
// a manually bumped constant is only correct if someone remembers, and it had
// already gone stale across several shipped changes to this very file.
//
// It matters beyond cache freshness: the activate handler decides whether a
// genuine upgrade occurred by looking for a cache under a *different* name. A
// version string that never changes makes that check unable to fire.
/**
 * Every cache this worker owns starts with this. Ownership has to be a *prefix*
 * test rather than "not the current name", because CacheStorage is per-origin
 * and GitHub Pages puts every project site on one origin: deleting everything
 * that is not the current Keymaker cache deletes the offline caches of every
 * other app the same user has visited under 404secnotfound.github.io.
 */
const CACHE_PREFIX = 'keymaker-';
// Spelled out rather than built from CACHE_PREFIX, so this stays a single
// quoted literal on one line: sw-update.spec.ts rewrites it by regex to
// simulate a release, and a concatenation would not match. The cost is two
// places holding the same prefix, which sw-cache-isolation.spec.ts checks
// cannot drift — if they ever did, the worker would stop recognising its own
// old caches and leak one per release, silently.
const CACHE_VERSION = 'keymaker-__BUILD_ID__';

// Where this worker is served from, without a trailing slash. On a root
// deployment that is "", on a GitHub Pages project site "/Keymaker-v2".
//
// Derived from self.location rather than baked in at build time, because the
// worker's own URL is the one thing that is always correct: the scope of a
// service worker is the directory it is served from, so this cannot disagree
// with reality the way a hardcoded prefix could.
const BASE = new URL('./', self.location).pathname.replace(/\/$/, '');

// App shell files to precache on install: the HTML entry point, the icons and
// the manifest. The build output is handled separately, below.
const APP_SHELL = [
  `${BASE}/`,
  // The crypto worker. It lives at the origin root rather than under
  // _next/static (see scripts/build-crypto-worker.mjs), so the generated
  // precache manifest below does not cover it and it has to be named here.
  // Missing it would mean the app loads offline and then cannot encrypt.
  `${BASE}/crypto-worker.js`,
  // The recovery kit — the printed procedure and the standalone Python
  // decryptors, copied in by scripts/build-recovery-kit.mjs. Precached
  // deliberately: the moment someone needs these is the moment the website is
  // unreachable, so a recovery document that requires the site to be up is not
  // a recovery document.
  //
  // Both decryptors, not only the current one. The app writes v2 now, but every
  // container written before Phase 3 is v1 and stays readable forever — caching
  // only keym2.py would strand precisely the oldest backups.
  `${BASE}/recovery/RECOVERY.md`,
  `${BASE}/recovery/keym.py`,
  `${BASE}/recovery/keym2.py`,
  `${BASE}/logo.svg`,
  // The hero background plate. Named here rather than left to runtime caching
  // for the same reason as everything else in this list: isCacheableAsset()
  // below is an allowlist, so an asset that is precached but not listed is
  // still fetched from the network by the fetch handler — which offline means
  // a failed request on the first screen the user sees.
  `${BASE}/hero-cipher-field.webp`,
  `${BASE}/favicon.ico`,
  `${BASE}/manifest.json`,
  `${BASE}/apple-touch-icon.png`,
  `${BASE}/icon-192x192.png`,
  `${BASE}/icon-512x512.png`,
  // The build's own manifest. Precached so the page can read it back from
  // this cache: the page's policy is connect-src 'none', so a fetch from it
  // is refused, and the Cache API is the one place it may look. The sealed
  // status hashes what this cache holds against it — see
  // src/components/sealed-status.tsx. Written by scripts/build-manifest.mjs
  // *after* this worker is stamped, so apply-build-id.mjs exempts it from
  // the exists-in-the-export check every other entry here passes.
  `${BASE}/SHA256SUMS`,
];

// Every JS and CSS chunk the export emitted. The build replaces this
// placeholder with the real list — see scripts/apply-build-id.mjs.
//
// These are precached rather than left to the fetch handler to pick up as the
// page requests them. Runtime caching cannot carry the offline guarantee: a
// chunk fetched *before* this worker controls the page is never seen by the
// fetch handler, so it never enters the cache. Measured on a first visit with
// runtime caching alone, 3 of 17 shipped chunks reached the cache — and the
// offline tests still passed, because Chromium's HTTP cache answered the rest.
// That is a cache the browser may evict whenever it likes, not a guarantee.
// The user who loads the page, closes the tab, and comes back next week on a
// plane gets a blank screen.
//
// The chunks are content-hashed and therefore immutable, which is what makes
// precaching all of them safe rather than a staleness risk.
const PRECACHE_ASSETS = __PRECACHE_ASSETS__;

// ---- Install: precache the app shell and the whole build ----
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_VERSION).then((cache) => {
      // Shell first, so a partial install still renders something; then the
      // chunks, which include the lazily imported crypto dependencies
      // (hash-wasm for Argon2id, @noble/ciphers for ChaCha, the EFF wordlist)
      // that a user may not touch until after the network is gone.
      return cache.addAll(APP_SHELL).then(() => cache.addAll(PRECACHE_ASSETS));
    })
  );

  // Deliberately NOT skipWaiting().
  //
  // A new worker that activates immediately replaces the running version under
  // whatever the page is in the middle of. For this app that middle can be an
  // Argon2id derivation: the crypto libraries are lazily imported, so a chunk
  // may still be fetched after the swap — and the activate handler below has by
  // then evicted the old cache, whose content-hashed URLs the new build does
  // not contain. Online that is a slow re-fetch of the wrong version's chunk;
  // offline, which is the supported way to use this tool, it is a failed import
  // part-way through encrypting a seed phrase.
  //
  // So the new worker waits. The page notices it waiting and offers a reload,
  // and the swap happens when the user says so — see the SKIP_WAITING handler
  // below and the registration script in src/app/layout.tsx. On a first install
  // there is no active worker to wait behind, so this costs a first-time
  // visitor nothing: install proceeds straight to activate.
});

// ---- Update handoff ----
// Sent by the page when the user accepts the update. This is the only thing
// that promotes a waiting worker, which is what keeps the version stable for
// the lifetime of a page that never accepts.
self.addEventListener('message', (event) => {
  if (!event.data || event.data.type !== 'SKIP_WAITING') return;

  // Only from a page this worker actually serves.
  //
  // `message` is same-origin, and on GitHub Pages the origin is shared with
  // every other project site the same account publishes — the same fact that
  // made cache eviction a cross-app problem (KM-R06, see the activate handler
  // above). Without this check any of those pages could post SKIP_WAITING and
  // promote Keymaker's waiting worker, which is precisely the thing the
  // install handler declines to do on its own: swapping the running version
  // out from under a tab part-way through encrypting a seed phrase.
  //
  // event.source is the Client that sent it. Requiring its URL to sit under
  // this registration's scope refuses a neighbour without refusing our own
  // page, and there is no ambiguity about which is which.
  const source = event.source;
  if (!source || typeof source.url !== 'string') return;
  if (!source.url.startsWith(self.registration.scope)) return;

  self.skipWaiting();
});

// ---- Activate: clean up old caches ----
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      // Ours, and not the current one. An exact-inequality test would have
      // treated a neighbouring app's cache as stale — it is not this version,
      // so it looked evictable — and taken it out on every activation.
      const stale = keys.filter((key) => key.startsWith(CACHE_PREFIX) && key !== CACHE_VERSION);

      // Evicting here is safe now in a way it was not before: activation can
      // only be reached on a first install (nothing to evict) or because the
      // user accepted the update, in which case the page reloads onto this
      // version the moment control changes.
      return Promise.all(stale.map((key) => caches.delete(key)))
        // Take control of open tabs. On a first install this is what makes the
        // app work offline without a reload; on an accepted update the page is
        // reloading anyway.
        .then(() => self.clients.claim());
    })
  );
});

// ---- Fetch strategies ----
// Navigations (the app shell) are network-first: users always get the
// newest deployed bundle when online, and the cache only serves as an
// offline fallback. Without this, cache-first on '/' could pin returning
// users to a stale bundle — including one with since-fixed security bugs —
// whenever a release forgets to bump CACHE_VERSION.
// Hashed static assets (/_next/static/*) are immutable by construction,
// so cache-first remains correct and fast for them.
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Only handle same-origin requests — never cache or intercept cross-origin
  // (this also means any accidental external requests just pass through)
  if (url.origin !== self.location.origin) return;

  // Only handle GET requests
  if (event.request.method !== 'GET') return;

  const cacheResponse = (request, response) => {
    // Don't cache error responses or opaque responses
    if (!response || response.status !== 200 || response.type !== 'basic') {
      return response;
    }
    // Clone the response — one copy goes to cache, one to the browser
    const toCache = response.clone();
    caches.open(CACHE_VERSION).then((cache) => {
      cache.put(request, toCache);
    });
    return response;
  };

  const isNavigation =
    event.request.mode === 'navigate' ||
    url.pathname === `${BASE}/` ||
    url.pathname === `${BASE}/index.html`;

  if (isNavigation) {
    // Network-first with cache fallback (offline support). Only '/' is
    // precached; any other navigation path (e.g. '/index.html') falls back
    // to the precached app shell when there is no exact cache match.
    //
    // The network response is served as-is and deliberately *not* written
    // back to the cache. The precached shell already is the offline copy, so
    // storing it again would buy nothing, and it would cost the integrity
    // check: after a deploy the new worker installs and waits while this one
    // keeps serving, and a navigation through it fetches the *new* build's
    // HTML. Putting that beside the *old* SHA256SUMS makes the cache disagree
    // with its own manifest, and the sealed status (see
    // src/components/sealed-status.tsx) then reports a mismatch on index.html
    // for every routine release until the update is accepted. The cache must
    // stay exactly what the manifest describes: the bytes install() wrote.
    event.respondWith(
      fetch(event.request).catch(() =>
        caches.match(event.request).then((cached) => cached || caches.match(`${BASE}/`))
      )
    );
    return;
  }

  // Cache-first, but only for asset categories we have deliberately decided
  // belong in the offline bundle.
  //
  // The previous rule was "cache-first for everything else", which was correct
  // for the app as it stands but is a standing invitation: any same-origin
  // resource added later would start being persisted to disk without anyone
  // choosing that. For a tool whose users may be handling seed phrases, what
  // lands in durable storage should be an allowlist, not a default.
  //
  // Anything not matched here falls through to the network untouched.
  if (isCacheableAsset(url.pathname)) {
    event.respondWith(
      caches.match(event.request).then((cached) => {
        if (cached) return cached;
        return fetch(event.request).then((response) =>
          cacheResponse(event.request, response)
        );
      })
    );
  }
});

/**
 * Static assets eligible for offline caching.
 *
 * /_next/static/* is content-hashed and therefore immutable, so cache-first is
 * both safe and correct. The rest is the fixed set of icons and metadata the
 * installed PWA needs to launch offline. Deliberately excluded: anything
 * dynamic, anything user-supplied, and anything not enumerated here.
 */
function isCacheableAsset(pathname) {
  if (pathname.startsWith(`${BASE}/_next/static/`)) return true;
  return APP_SHELL.includes(pathname);
}
