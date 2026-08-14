#!/usr/bin/env node
/**
 * Bundle the crypto worker into public/crypto-worker.js.
 *
 * ## Why this is a build step and not `new Worker(new URL(...))`
 *
 * That is the idiomatic form and it was tried first. Neither Turbopack path
 * works for this project:
 *
 *  - As a **module** worker, Turbopack emits its own bootstrap shim and the
 *    worker dies at runtime with "Missing worker bootstrap config" — the shim
 *    expects a chunk-loading environment the static export does not provide.
 *  - As a **classic** worker, Turbopack stops treating it as code at all and
 *    copies the raw TypeScript to `out/_next/static/media/crypto-worker.*.ts`.
 *    The build then fails typechecking its own emitted asset, and had it not,
 *    the browser would have been served TypeScript to execute.
 *
 * So the worker is bundled here, explicitly, and served from the origin root
 * like `sw.js` — which has the same shape of problem and the same solution.
 * A static export benefits from fewer moving parts, not more.
 *
 * The bundle is self-contained: hash-wasm and @noble/ciphers are inlined rather
 * than left as dynamic imports. Inside a worker a dynamic import would have to
 * resolve a chunk URL relative to the worker's own location, which is exactly
 * the fragile path this script exists to avoid. It also means the worker cannot
 * be missing a dependency when it runs offline — there is nothing to fetch.
 */
import { build } from 'esbuild';
import { readFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const ENTRY = join(HERE, '..', 'src', 'lib', 'crypto-worker.ts');
const OUT = join(HERE, '..', 'public', 'crypto-worker.js');

const result = await build({
  entryPoints: [ENTRY],
  outfile: OUT,
  bundle: true,
  // Classic worker: no import statements at runtime, nothing to resolve.
  format: 'iife',
  platform: 'browser',
  target: ['es2022'],
  minify: true,
  // A worker has no `window`; some bundled dependencies feature-detect on it.
  define: { 'process.env.NODE_ENV': '"production"' },
  legalComments: 'none',
  logLevel: 'warning',
  metafile: true,
});

const bytes = statSync(OUT).size;
const source = readFileSync(OUT, 'utf8');

// Fail closed on the two ways this can silently produce a broken worker.
if (!source.includes('addEventListener')) {
  console.error('crypto-worker: ERROR — bundle has no message listener. Refusing to ship.');
  process.exit(1);
}
if (/\bimport\s*\(/.test(source) || /\bfrom\s*["']/.test(source)) {
  console.error(
    'crypto-worker: ERROR — bundle still contains import syntax, so it is not ' +
      'self-contained. A classic worker cannot resolve these at runtime.'
  );
  process.exit(1);
}

console.log(`crypto-worker: bundled ${(bytes / 1024).toFixed(0)} KB to public/crypto-worker.js`);
if (result.warnings.length) {
  for (const w of result.warnings) console.warn(`crypto-worker: warning — ${w.text}`);
}
