#!/usr/bin/env node
/**
 * Sign out/SHA256SUMS with Sigstore, keyless.
 *
 * ## What the signature is for
 *
 * README.md concedes that "whoever serves the bundle is the trust anchor" —
 * reading the source on GitHub says nothing about the JavaScript that Pages
 * actually served you. The manifest lists what was deployed; this signature is
 * what makes the manifest itself worth believing.
 *
 * Keyless means there is no private key to store, rotate, or leak. The workflow
 * proves its identity with the OIDC token GitHub mints for it, Fulcio issues a
 * short-lived certificate bound to that identity, and the whole thing is logged
 * in Rekor. A verifier does not check "was this signed by a key we published" —
 * which only moves the trust problem — but "was this signed by *this workflow*,
 * in *this repository*". That is the property a user actually wants.
 *
 * ## Why a script and not the cosign action
 *
 * Every action in this repository is pinned to a commit SHA. Adding an
 * unpinned one to introduce *supply-chain verification* would be a poor trade.
 * The `sigstore` package is pinned in package-lock.json with an integrity
 * hash, which is the same mechanism the rest of the toolchain already relies
 * on, and it produces an interoperable bundle — `cosign verify-blob --bundle`
 * reads it fine.
 *
 * ## Why this runs in its own job
 *
 * deploy.yml keeps the build job on `contents: read` precisely so that the job
 * running untrusted transitive install scripts via `npm ci` can never mint an
 * OIDC identity. Signing needs `id-token: write`, so it must not happen there.
 * The signing job installs with `--ignore-scripts` for the same reason: it
 * holds the token, so nothing it installs gets to run code.
 */
import { sign } from 'sigstore';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const OUT = join(dirname(fileURLToPath(import.meta.url)), '..', 'out');
const MANIFEST = join(OUT, 'SHA256SUMS');
const BUNDLE = join(OUT, 'SHA256SUMS.sigstore');

let payload;
try {
  payload = readFileSync(MANIFEST);
} catch {
  console.error('sign: ERROR — out/SHA256SUMS not found. Run the build first.');
  process.exit(1);
}

if (payload.length === 0) {
  console.error('sign: ERROR — the manifest is empty. Refusing to sign nothing.');
  process.exit(1);
}

// Ambient credentials only. There is deliberately no fallback to an interactive
// browser flow or a local key: a signature produced from a developer laptop
// would assert an identity that says nothing about how the artifact was built,
// which is the whole point of signing it.
if (!process.env.ACTIONS_ID_TOKEN_REQUEST_URL) {
  console.error(
    'sign: ERROR — no GitHub Actions OIDC token available.\n' +
      'This step signs with the workflow identity and is meant to run in CI with\n' +
      "`permissions: id-token: write`. It has no local-key mode on purpose: a\n" +
      'signature from someone’s laptop would prove nothing about the build.'
  );
  process.exit(1);
}

const bundle = await sign(payload);
writeFileSync(BUNDLE, JSON.stringify(bundle), 'utf8');

console.log(`sign: signed ${payload.length} bytes of manifest`);
console.log(`sign: wrote ${BUNDLE.replace(/.*\/out\//, 'out/')}`);
