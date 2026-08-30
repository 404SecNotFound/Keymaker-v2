import type {Metadata} from 'next';
import './globals.css';
import { Toaster } from "@/components/ui/toaster"

// Subdirectory the app is served from — "" at a domain root, "/Keymaker-v2"
// on a GitHub Pages project site. Next prefixes its own asset URLs from
// next.config.js, but not <link> tags we write by hand or a path passed to
// serviceWorker.register(), so those are prefixed here.
const BASE = process.env.KEYMAKER_BASE_PATH || '';

// Absolute origin, needed only for social-card metadata: Open Graph requires
// fully-qualified URLs, and a crawler has no page context to resolve a
// relative one against. Overridable so a fork or a custom domain does not
// advertise someone else's host.
const SITE_URL =
  process.env.KEYMAKER_SITE_URL || `https://404secnotfound.github.io${BASE || '/Keymaker-v2'}`;

const DESCRIPTION =
  'Encrypt files, notes and seed phrases entirely in your browser. Argon2id or ' +
  'PBKDF2, AES-256-GCM, ChaCha20-Poly1305 or both chained, in a self-describing ' +
  'authenticated container. No server, no account, no upload — and it keeps working offline.';

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: {
    default: 'Keymaker — client-side encryption that never leaves your browser',
    template: '%s · Keymaker',
  },
  description: DESCRIPTION,
  applicationName: 'Keymaker',
  category: 'security',
  keywords: [
    'client-side encryption',
    'browser encryption',
    'Argon2id',
    'AES-256-GCM',
    'ChaCha20-Poly1305',
    'authenticated encryption',
    'AEAD',
    'PBKDF2',
    'BIP-39',
    'SeedQR',
    'seed phrase backup',
    'offline encryption',
    'zero knowledge',
    'file encryption',
    'PWA',
    'open source',
  ],
  authors: [{ name: '404SecNotFound', url: 'https://github.com/404SecNotFound' }],
  creator: '404SecNotFound',
  // The app has no backend and stores nothing, so there is nothing to index
  // beyond the landing page — but it should be findable.
  robots: { index: true, follow: true },
  openGraph: {
    type: 'website',
    url: SITE_URL,
    siteName: 'Keymaker',
    title: 'Keymaker — encrypt everything, trust nothing',
    description: DESCRIPTION,
    images: [
      {
        url: '/og-card.png',
        width: 1200,
        height: 630,
        alt: 'Keymaker — client-side encryption with Argon2id, AES-256-GCM and ChaCha20-Poly1305.',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Keymaker — encrypt everything, trust nothing',
    description:
      'Client-side encryption for files, notes and seed phrases. Argon2id and chained AEAD ciphers. Nothing ever leaves your browser.',
    images: ['/og-card.png'],
  },
  // Icons and the manifest stay as hand-written <link> tags in <head> below:
  // they already carry the basePath prefix, and declaring them here too would
  // emit a duplicate set.
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <head>
        {/*
          'wasm-unsafe-eval' is load-bearing for Argon2id: hash-wasm compiles a
          WebAssembly module, and browsers refuse to instantiate WASM unless
          script-src allows it. Without this token the Argon2id path dies
          silently in the production build while PBKDF2 keeps working.

          Note this meta tag is only emitted for production, so `npm run dev`
          has no CSP at all — which is precisely how the omission escaped
          notice. The Node test suite has no CSP either.

          The token permits WASM compilation *only*. It does not enable eval()
          for JavaScript the way 'unsafe-eval' would.
        */}
        {process.env.NODE_ENV === 'production' && (
          <meta
            httpEquiv="Content-Security-Policy"
            content="default-src 'none'; script-src 'self' 'wasm-unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'none'; worker-src 'self'; manifest-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'"
          />
        )}
        <link rel="icon" type="image/svg+xml" href={`${BASE}/logo.svg`} />
        <link rel="icon" type="image/x-icon" href={`${BASE}/favicon.ico`} />
        <link rel="manifest" href={`${BASE}/manifest.json`} />
        <link rel="apple-touch-icon" sizes="1024x1024" href={`${BASE}/apple-touch-icon.png`} />
        <meta name="theme-color" content="#08090a" />
        <meta name="mobile-web-app-capable" content="yes" />
        <meta name="apple-mobile-web-app-capable" content="yes" />
        <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent" />
      </head>
      <body className="font-body antialiased">
        {children}
        <Toaster />
        <script
          dangerouslySetInnerHTML={{
            __html: `
              // The new worker waits rather than taking over (see public/sw.js).
              // This side of the handoff spots it waiting, offers the swap, and
              // performs it only when the user accepts — so a version change can
              // never land in the middle of an encryption.
              if ('serviceWorker' in navigator) {
                var reloading = false;

                function offerUpdate(registration) {
                  if (document.getElementById('sw-update-banner')) return;

                  var banner = document.createElement('button');
                  banner.id = 'sw-update-banner';
                  banner.type = 'button';
                  banner.setAttribute('role', 'alert');
                  banner.style.cssText = 'position:fixed;bottom:1rem;left:50%;transform:translateX(-50%);z-index:9999;background:#F5F3F1;color:#14120F;padding:0.75rem 1.25rem;border:1px solid rgba(255,255,255,0.18);border-radius:9999px;font:inherit;font-size:0.875rem;font-weight:500;cursor:pointer;';
                  banner.textContent = 'A new version of Keymaker is ready — tap to reload';
                  banner.onclick = function() {
                    // Nothing swaps until this click. Promoting the waiting
                    // worker triggers controllerchange, which reloads the page
                    // onto the new version.
                    banner.disabled = true;
                    banner.textContent = 'Updating…';
                    reloading = true;
                    if (registration.waiting) {
                      registration.waiting.postMessage({ type: 'SKIP_WAITING' });
                    } else {
                      window.location.reload();
                    }
                  };
                  document.body.appendChild(banner);
                }

                // Guarded by the flag the banner sets, because controllerchange
                // also fires on a first install when the new worker claims a
                // page that had no controller — reloading there would bounce a
                // first-time visitor for no reason.
                navigator.serviceWorker.addEventListener('controllerchange', function() {
                  if (!reloading) return;
                  reloading = false;
                  window.location.reload();
                });

                window.addEventListener('load', function() {
                  navigator.serviceWorker.register('${BASE}/sw.js').then(function(registration) {
                    // Already waiting when this page loaded — an update landed
                    // during a previous visit that was never accepted.
                    if (registration.waiting) offerUpdate(registration);

                    registration.addEventListener('updatefound', function() {
                      var installing = registration.installing;
                      if (!installing) return;
                      installing.addEventListener('statechange', function() {
                        // 'installed' with a controller present means this is a
                        // replacement waiting its turn, not the first install.
                        if (installing.state === 'installed' && navigator.serviceWorker.controller) {
                          offerUpdate(registration);
                        }
                      });
                    });
                  }).catch(function() {
                    // Registration failing costs offline support, nothing else.
                    // The app runs entirely in the page.
                  });
                });
              }
            `,
          }}
        />
      </body>
    </html>
  );
}
