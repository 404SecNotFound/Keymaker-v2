#!/usr/bin/env node
/**
 * The Argon2id module is pinned by content, not only by version.
 *
 * hash-wasm ships Argon2 as a base64 WebAssembly blob, and both bundles embed
 * it: the crypto worker (public/crypto-worker.js) and the page bundle that
 * runs the no-worker fallback. The only pin on those bytes was the lockfile,
 * and a lockfile bump arrives inside a grouped Dependabot PR beside UI bumps,
 * where two changed `integrity` lines are the easiest thing in the diff to
 * scroll past. The KDF is the one dependency whose bytes must not move
 * unnoticed, so this fails the build unless the blob in node_modules hashes
 * to the value below AND the same blob is what the built bundles carry.
 *
 * Bumping hash-wasm on purpose: run `node scripts/check-argon2-blob.mjs
 * --print` on the new version, read the diff of the wasm you are about to
 * ship, and update ARGON2_WASM_SHA256 in the same commit. That is the review
 * this gate exists to force.
 *
 *     node scripts/check-argon2-blob.mjs            # after `next build`
 *     node scripts/check-argon2-blob.mjs --print    # show the current hash
 */
import { createHash } from 'node:crypto';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');

/** sha256 of the base64 text of hash-wasm 4.12.0's Argon2 module. */
const ARGON2_WASM_SHA256 = '97761c69e09ace28ef2f38ca4715d79543430e0459400430d54044579e31a2db';

const dist = readFileSync(join(ROOT, 'node_modules', 'hash-wasm', 'dist', 'index.esm.js'), 'utf8');
// `var name$k = "argon2"; var data$k = "AGFzbQ…"` — the suffix is whatever the
// bundler chose, so it is captured and matched rather than assumed.
const m = /var name\$(\w+) = "argon2";\s*var data\$\1 = "(AGFzbQ[A-Za-z0-9+/=]+)"/.exec(dist);
if (!m) {
  console.error(
    'argon2-blob: ERROR — could not find the Argon2 wasm blob in hash-wasm/dist/index.esm.js. ' +
      'The package layout changed; read the new one before trusting it.'
  );
  process.exit(1);
}
const blob = m[2];
const actual = createHash('sha256').update(blob).digest('hex');

if (process.argv.includes('--print')) {
  console.log(`argon2-blob: ${actual} (${blob.length} base64 chars)`);
  process.exit(0);
}

if (actual !== ARGON2_WASM_SHA256) {
  console.error(
    `argon2-blob: ERROR — the Argon2 wasm in node_modules hashes to ${actual}, ` +
      `expected ${ARGON2_WASM_SHA256}. hash-wasm changed underneath the pin. ` +
      'Review the new module, then update ARGON2_WASM_SHA256 deliberately.'
  );
  process.exit(1);
}

// What ships is what was pinned: the worker, and exactly one page chunk.
const worker = readFileSync(join(ROOT, 'public', 'crypto-worker.js'), 'utf8');
if (!worker.includes(blob)) {
  console.error('argon2-blob: ERROR — public/crypto-worker.js does not carry the pinned Argon2 module.');
  process.exit(1);
}

const chunksDir = join(ROOT, 'out', '_next', 'static', 'chunks');
if (existsSync(chunksDir)) {
  const carrying = readdirSync(chunksDir)
    .filter((f) => f.endsWith('.js'))
    .filter((f) => readFileSync(join(chunksDir, f), 'utf8').includes(blob));
  if (carrying.length !== 1) {
    console.error(
      `argon2-blob: ERROR — expected exactly one page chunk to carry the Argon2 module, found ${carrying.length}` +
        (carrying.length ? `: ${carrying.join(', ')}` : '') +
        '. The fallback KDF is either missing or duplicated.'
    );
    process.exit(1);
  }
  console.log(`argon2-blob: pinned module present in crypto-worker.js and ${carrying[0]}`);
} else {
  console.log('argon2-blob: pinned module present in crypto-worker.js (no out/ to check)');
}
