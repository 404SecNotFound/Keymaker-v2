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
            content="default-src 'none'; script-src 'self' 'wasm-unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'none'; worker-src 'self'; manifest-src 'self'; object-src 'none'; base-uri 'self'; form-action 'none'"
          />
        )}
        <link rel="icon" type="image/svg+xml" href={`${BASE}/logo.svg`} />
        <link rel="icon" type="image/x-icon" href={`${BASE}/favicon.ico`} />
        <link rel="manifest" href={`${BASE}/manifest.json`} />
        <link rel="apple-touch-icon" sizes="1024x1024" href={`${BASE}/apple-touch-icon.png`} />
        <meta name="theme-color" content="#c07f2e" />
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
              if ('serviceWorker' in navigator) {
                window.addEventListener('load', function() {
                  navigator.serviceWorker.register('${BASE}/sw.js');
                });

                // Listen for the service worker's update notification
                navigator.serviceWorker.addEventListener('message', function(event) {
                  if (event.data && event.data.type === 'SW_UPDATED') {
                    // Show a non-intrusive update banner
                    var banner = document.createElement('div');
                    banner.setAttribute('role', 'alert');
                    banner.style.cssText = 'position:fixed;bottom:1rem;left:50%;transform:translateX(-50%);z-index:9999;background:#c07f2e;color:#000;padding:0.75rem 1.25rem;border-radius:0.5rem;font-size:0.875rem;font-weight:600;cursor:pointer;box-shadow:0 4px 12px rgba(0,0,0,0.3);';
                    banner.textContent = 'A new version of Keymaker is available — tap to reload';
                    banner.onclick = function() { window.location.reload(); };
                    document.body.appendChild(banner);
                  }
                });
              }
            `,
          }}
        />
      </body>
    </html>
  );
}
