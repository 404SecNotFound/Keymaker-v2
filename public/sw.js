// Keymaker Service Worker — hand-rolled, zero dependencies
// Cache version: bump this on every release to invalidate stale caches
const CACHE_VERSION = 'keymaker-v1.0.0';

// App shell files to precache on install.
// For a static Next.js export the HTML entry point and key assets are enough;
// the rest (JS chunks, CSS) are picked up at runtime via the fetch handler.
const APP_SHELL = [
  '/',
  '/logo.svg',
  '/favicon.ico',
  '/manifest.json',
  '/apple-touch-icon.png',
  '/icon-192x192.png',
  '/icon-512x512.png',
];

// ---- Install: precache the app shell ----
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_VERSION).then((cache) => {
      return cache.addAll(APP_SHELL);
    })
  );
  // Activate immediately instead of waiting for existing tabs to close
  self.skipWaiting();
});

// ---- Activate: clean up old caches ----
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      const stale = keys.filter((key) => key !== CACHE_VERSION);

      // `activate` also fires on the very first install, when there is no
      // previous version to have replaced. Only a run that finds and evicts
      // a cache from an older CACHE_VERSION is a genuine update — otherwise
      // a first-time visitor is told a new version is available before they
      // have ever loaded one.
      const isUpgrade = stale.length > 0;

      return Promise.all(stale.map((key) => caches.delete(key)))
        // Take control of all open tabs immediately
        .then(() => self.clients.claim())
        .then(() => {
          if (!isUpgrade) return;
          // Notify all open tabs that a new version is active
          return self.clients.matchAll({ type: 'window' }).then((clients) => {
            clients.forEach((client) => {
              client.postMessage({ type: 'SW_UPDATED' });
            });
          });
        });
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
    url.pathname === '/' ||
    url.pathname === '/index.html';

  if (isNavigation) {
    // Network-first with cache fallback (offline support). Only '/' is
    // precached; any other navigation path (e.g. '/index.html') falls back
    // to the precached app shell when there is no exact cache match.
    event.respondWith(
      fetch(event.request)
        .then((response) => cacheResponse(event.request, response))
        .catch(() =>
          caches.match(event.request).then((cached) => cached || caches.match('/'))
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
  if (pathname.startsWith('/_next/static/')) return true;
  return APP_SHELL.includes(pathname);
}
