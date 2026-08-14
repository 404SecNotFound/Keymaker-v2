#!/usr/bin/env node
/**
 * Verify a deployed Keymaker build against its signed manifest.
 *
 * Answers two independent questions, and it is worth being precise about which
 * is which, because they fail for different reasons and mean different things:
 *
 *  1. **Do the files match the manifest?** Every file in out/ is hashed and
 *     compared. A mismatch means the artifact was altered after it was built.
 *  2. **Was the manifest signed by this repository's deploy workflow?** The
 *     Sigstore bundle is verified against the manifest bytes, and the signing
 *     certificate's identity is checked. A mismatch means someone else signed
 *     it — which is exactly the case a signature exists to catch.
 *
 * Check (1) alone proves internal consistency and nothing more: anyone
 * tampering with the site would simply regenerate the manifest. Check (2) alone
 * proves a manifest was signed but says nothing about the files beside it. Both
 * together are the claim.
 *
 * Neither is a substitute for reproducibility. That the deployed artifact came
 * from *this workflow* does not establish it came from the *published source* —
 * for that, rebuild the commit and compare manifests. `npm run
 * verify:reproducible` is the guard that keeps rebuilding possible.
 *
 * Usage:
 *   node scripts/verify-manifest.mjs            # verify ./out
 *   node scripts/verify-manifest.mjs <dir>      # verify a downloaded copy
 */
import { verify } from 'sigstore';
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative, sep } from 'node:path';

const DIR =
  process.argv[2] || join(dirname(fileURLToPath(import.meta.url)), '..', 'out');
const MANIFEST = join(DIR, 'SHA256SUMS');
const BUNDLE = join(DIR, 'SHA256SUMS.sigstore');

/**
 * Who is allowed to have signed this.
 *
 * The certificate identity is the whole point of keyless signing: it is not
 * "some key we published", which only relocates the trust problem, but "the
 * deploy workflow of this repository, running on GitHub". Overridable so a fork
 * can verify its own deployments rather than being told a legitimate build is
 * forged.
 */
const EXPECTED_ISSUER = process.env.KEYMAKER_CERT_ISSUER || 'https://token.actions.githubusercontent.com';
const EXPECTED_IDENTITY =
  process.env.KEYMAKER_CERT_IDENTITY ||
  'https://github.com/404SecNotFound/Keymaker-v2/.github/workflows/deploy.yml@refs/heads/main';

const SELF = new Set(['SHA256SUMS', 'SHA256SUMS.sigstore']);

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

function fail(message) {
  console.error(`verify: FAILED — ${message}`);
  process.exit(1);
}

let manifestBytes;
try {
  manifestBytes = readFileSync(MANIFEST);
} catch {
  fail(`no SHA256SUMS in ${DIR}`);
}

// ---- 1. Files match the manifest ----

const expected = new Map();
for (const line of manifestBytes.toString('utf8').split('\n')) {
  if (!line.trim()) continue;
  const m = /^([a-f0-9]{64})\s\s(.+)$/.exec(line);
  if (!m) fail(`unparseable manifest line: ${line.slice(0, 80)}`);
  expected.set(m[2], m[1]);
}

const present = new Map();
for (const abs of walk(DIR)) {
  const rel = relative(DIR, abs).split(sep).join('/');
  if (SELF.has(rel)) continue;
  present.set(rel, createHash('sha256').update(readFileSync(abs)).digest('hex'));
}

const missing = [...expected.keys()].filter((f) => !present.has(f));
const unexpected = [...present.keys()].filter((f) => !expected.has(f));
const altered = [...expected.keys()].filter(
  (f) => present.has(f) && present.get(f) !== expected.get(f)
);

for (const f of missing) console.error(`  missing:   ${f}`);
// An extra file is not cosmetic: it is a file nobody signed for, served from
// the same origin, under the same CSP, by a tool whose entire claim is that
// nothing unexpected runs.
for (const f of unexpected) console.error(`  unsigned:  ${f}`);
for (const f of altered) console.error(`  altered:   ${f}`);

if (missing.length || unexpected.length || altered.length) {
  fail(
    `${missing.length} missing, ${unexpected.length} unsigned, ${altered.length} altered ` +
      `out of ${expected.size} files`
  );
}
console.log(`verify: ${expected.size} files match the manifest`);

// ---- 2. The manifest was signed by the expected identity ----

let bundle;
try {
  bundle = JSON.parse(readFileSync(BUNDLE, 'utf8'));
} catch {
  fail(
    `no SHA256SUMS.sigstore in ${DIR}. The files are internally consistent, ` +
      'but nothing establishes who produced them.'
  );
}

try {
  await verify(bundle, manifestBytes, {
    certificateIssuer: EXPECTED_ISSUER,
    certificateIdentityURI: EXPECTED_IDENTITY,
  });
} catch (error) {
  fail(
    `signature check failed: ${error instanceof Error ? error.message : String(error)}\n` +
      `  expected issuer:   ${EXPECTED_ISSUER}\n` +
      `  expected identity: ${EXPECTED_IDENTITY}`
  );
}

console.log(`verify: signature valid — signed by ${EXPECTED_IDENTITY}`);
console.log('verify: OK');
