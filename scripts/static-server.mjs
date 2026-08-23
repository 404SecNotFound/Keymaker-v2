#!/usr/bin/env node
/**
 * Minimal static file server for the browser test suite.
 *
 * Replaces `npx --yes serve`, which resolved and executed an unpinned package
 * at test time. That put an arbitrary version of a third-party server — and
 * its dependency tree — inside the pipeline whose job is verifying the
 * security properties of the build. It never shipped to users, but a
 * regression suite that fetches unpinned code at runtime cannot claim to be
 * reproducible.
 *
 * Node's standard library is enough here: serve files from a directory, guess
 * a content type, refuse to escape the root. No dependencies, nothing to pin.
 *
 *   node scripts/static-server.mjs <dir> <port> [basePath]
 */
import { createServer } from 'node:http';
import { createReadStream, statSync } from 'node:fs';
import { join, normalize, extname, resolve, sep } from 'node:path';

const [, , dirArg = 'out', portArg = '4321', basePathArg = ''] = process.argv;
const ROOT = resolve(dirArg);
const PORT = Number(portArg);
const BASE = basePathArg.replace(/\/$/, '');

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
  '.wasm': 'application/wasm',
  '.webmanifest': 'application/manifest+json',
};

const server = createServer((req, res) => {
  let pathname;
  try {
    pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  } catch {
    res.writeHead(400).end('Bad request');
    return;
  }

  if (BASE) {
    if (pathname === BASE) {
      res.writeHead(301, { Location: `${BASE}/` }).end();
      return;
    }
    // The root redirects into the base path so the browser suite's 91
    // `goto("/")` calls reach the app without being rewritten.
    //
    // This is a harness convenience and not a production behaviour: GitHub
    // Pages serves nothing at the origin root and would return its own 404.
    // It is safe because it is not the thing under test. What the base-path
    // run exists to check is that the *assets* resolve — the built HTML
    // references them absolutely, as `/Keymaker-v2/_next/...`, and only a
    // server that mounts the app there can prove those URLs are right. The
    // entry redirect changes where the document is fetched from; it does not
    // touch a single asset URL inside it.
    if (pathname === '/') {
      res.writeHead(302, { Location: `${BASE}/` }).end();
      return;
    }
    if (!pathname.startsWith(`${BASE}/`)) {
      res.writeHead(404).end('Not found');
      return;
    }
    pathname = pathname.slice(BASE.length);
  }

  // Resolve inside ROOT, then verify — normalize alone does not stop `..`
  // from climbing out once symlinks and encodings are involved.
  let filePath = join(ROOT, normalize(pathname));
  if (filePath !== ROOT && !filePath.startsWith(ROOT + sep)) {
    res.writeHead(403).end('Forbidden');
    return;
  }

  try {
    if (statSync(filePath).isDirectory()) filePath = join(filePath, 'index.html');
  } catch {
    res.writeHead(404).end('Not found');
    return;
  }

  let size;
  try {
    size = statSync(filePath).size;
  } catch {
    res.writeHead(404).end('Not found');
    return;
  }

  res.writeHead(200, {
    'Content-Type': TYPES[extname(filePath).toLowerCase()] ?? 'application/octet-stream',
    'Content-Length': size,
    // The suite asserts on the page's own CSP meta tag; no caching so each
    // test run sees the current build rather than a previous one.
    'Cache-Control': 'no-store',
  });
  createReadStream(filePath).pipe(res);
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`static-server: ${ROOT} on http://127.0.0.1:${PORT}${BASE}/`);
});
