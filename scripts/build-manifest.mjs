#!/usr/bin/env node
/**
 * Emit out/SHA256SUMS — a digest of every file in the deployed artifact.
 *
 * ## What this is for
 *
 * The README concedes that "whoever serves the bundle is the trust anchor".
 * That is honest and it is also the largest unaddressed risk in the project: a
 * zero-server tool is only as trustworthy as the copy the browser actually
 * received. Reading the source on GitHub tells you nothing about the JavaScript
 * that GitHub Pages served you this morning.
 *
 * This file, signed, closes that gap. It lets anyone answer two separate
 * questions:
 *
 *  1. **Is the deployed site the artifact CI produced?** Fetch the files, hash
 *     them, compare to this manifest, and verify the manifest's signature came
 *     from this repository's deploy workflow. That is provenance.
 *  2. **Does that artifact correspond to the published source?** Check out the
 *     commit, rebuild, and diff the manifests. That is reproducibility, and it
 *     only became possible once `generateBuildId` was pinned — see
 *     next.config.js for why Next's random build id made every build differ.
 *
 * Provenance without reproducibility would only prove "GitHub built this",
 * which does not tell a user whether the source they read is the code they ran.
 *
 * ## Format
 *
 * Standard `sha256sum` output — two spaces, path relative to out/ — so it can
 * be checked with the coreutils tool that is already on every machine:
 *
 *     cd out && sha256sum -c SHA256SUMS
 *
 * No timestamps, no host details, nothing environment-dependent: the manifest
 * is a pure function of the tree, or it could not be compared across rebuilds.
 * The signing certificate carries the time and the builder identity, which is
 * where that information belongs.
 */
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

const OUT_DIR = new URL('../out', import.meta.url).pathname;
const MANIFEST = join(OUT_DIR, 'SHA256SUMS');

/** Names that must never appear in the manifest. */
const SELF = new Set(['SHA256SUMS', 'SHA256SUMS.sigstore', 'SHA256SUMS.sigstore.json']);

/**
 * Deploy-control files: consumed by the host, never served by it.
 *
 * `.nojekyll` tells GitHub Pages to publish `_next/` as-is instead of handing
 * the tree to Jekyll, which drops underscore-prefixed directories. Pages reads
 * the file and then answers 404 for it, so a manifest that listed it could
 * never verify against the live site, every reader following VERIFYING.md
 * got `.nojekyll: FAILED open or read` on an honest deployment. It is part of
 * the upload, not part of the artifact a browser can receive, and the manifest
 * is a promise about the latter.
 */
const DEPLOY_CONTROL = new Set(['.nojekyll']);

function walk(dir) {
  const found = [];
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) found.push(...walk(p));
    else found.push(p);
  }
  return found;
}

let files;
try {
  files = walk(OUT_DIR);
} catch {
  console.error('manifest: ERROR — out/ not found. Did the export run?');
  process.exit(1);
}

const entries = files
  // Posix separators, so a manifest built on Windows compares equal to one
  // built on Linux. A path separator difference would look like tampering.
  .map((f) => ({ abs: f, rel: relative(OUT_DIR, f).split(sep).join('/') }))
  .filter((e) => !SELF.has(e.rel) && !DEPLOY_CONTROL.has(e.rel))
  .sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0));

if (entries.length === 0) {
  console.error('manifest: ERROR — out/ contained no files. Refusing to sign nothing.');
  process.exit(1);
}

// The index.html carries the CSP and loads everything else; a manifest that
// omitted it would verify while saying nothing about the page actually served.
if (!entries.some((e) => e.rel === 'index.html')) {
  console.error('manifest: ERROR — index.html is missing from out/. Refusing to continue.');
  process.exit(1);
}

const lines = entries.map((e) => {
  const digest = createHash('sha256').update(readFileSync(e.abs)).digest('hex');
  return `${digest}  ${e.rel}`;
});

const body = lines.join('\n') + '\n';
writeFileSync(MANIFEST, body, 'utf8');

const manifestDigest = createHash('sha256').update(body).digest('hex');
const totalBytes = entries.reduce((n, e) => n + statSync(e.abs).size, 0);

console.log(`manifest: ${entries.length} files, ${(totalBytes / 1024).toFixed(0)} KB`);
console.log(`manifest: sha256(SHA256SUMS) = ${manifestDigest}`);
