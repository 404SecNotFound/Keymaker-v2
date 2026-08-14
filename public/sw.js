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
  // decryptor, copied in by scripts/build-recovery-kit.mjs. Precached
  // deliberately: the moment someone needs these is the moment the website is
  // unreachable, so a recovery document that requires the site to be up is not
  // a recovery document.
  `${BASE}/recovery/RECOVERY.md`,
  `${BASE}/recovery/keym.py`,
  `${BASE}/logo.svg`,
  `${BASE}/favicon.ico`,
  `${BASE}/manifest.json`,
  `${BASE}/apple-touch-icon.png`,
  `${BASE}/icon-192x192.png`,
  `${BASE}/icon-512x512.png`,
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
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

// ---- Activate: clean up old caches ----
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      const stale = keys.filter((key) => key !== CACHE_VERSION);

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
    event.respondWith(
      fetch(event.request)
        .then((response) => cacheResponse(event.request, response))
        .catch(() =>
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
