#!/usr/bin/env node
/**
 * The gate on roadmap 6.2:
 *
 *   "the release workflow attaches SHA256SUMS and its signature, and the
 *    `cosign verify-blob` line in the notes is copied from docs/VERIFYING.md
 *    rather than retyped. A verification command that does not work is worse
 *    than none."
 *
 * Both halves get a check here, because both are the kind of thing that is true
 * on the day it is written and quietly false a month later.
 *
 * The copied-ness check is the interesting one. "Copied" cannot be asserted by
 * looking at the notes alone — a retyped command looks identical to a copied one
 * until the document changes underneath it. So the test extracts the command
 * from docs/VERIFYING.md itself, masks the single value that legitimately
 * differs, and demands the rest match byte for byte. Edit the document's flags
 * and this fails; edit only the generator and this fails too.
 *
 * Runs with no dependencies installed and no network, like the wordlist check,
 * so it can sit in the cheap CI job.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { composeNotes, readSources } from './release-notes.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

let failures = 0;
function check(name, ok, detail) {
  if (ok) {
    console.log(`  ok   ${name}`);
  } else {
    failures++;
    console.log(`  FAIL ${name}${detail ? `\n         ${detail}` : ''}`);
  }
}

/** Assert that composing with these inputs throws, and that it says why. */
function refuses(name, opts, expectedFragment) {
  let message = null;
  try {
    composeNotes(opts);
  } catch (error) {
    message = error instanceof Error ? error.message : String(error);
  }
  if (message === null) {
    check(name, false, 'composed successfully; it should have refused');
  } else {
    check(name, message.includes(expectedFragment), `threw, but message lacked ${JSON.stringify(expectedFragment)}:\n         ${message}`);
  }
}

console.log('Release notes generator\n');

const { doc, version } = readSources();
const TAG = `v${version}`;
const IDENTITY = `https://github.com/404SecNotFound/Keymaker-v2/.github/workflows/release.yml@refs/tags/${TAG}`;

const notes = composeNotes({ doc, version, tag: TAG, workflowRef: IDENTITY, changelog: 'Something changed.' });

// ---- 1. The cosign command is copied, not retyped ----

/** The single fenced bash block in a markdown string that contains `needle`. */
function bashBlock(markdown, needle) {
  const blocks = [...markdown.matchAll(/```bash\n([\s\S]*?)```/g)].map((m) => m[1].trimEnd());
  const found = blocks.filter((b) => b.includes(needle));
  return found.length === 1 ? found[0] : null;
}

const docCosign = bashBlock(doc, 'cosign verify-blob');
const notesCosign = bashBlock(notes, 'cosign verify-blob');

check('docs/VERIFYING.md has exactly one cosign block', docCosign !== null);
check('the notes have exactly one cosign block', notesCosign !== null);

// The identity is the one value that must differ: the document verifies the
// deployment, the notes verify a tag. Mask it on both sides and everything
// else — every flag, every line break, every continuation backslash — has to
// be identical, because all of it came from the same place.
const maskIdentity = (s) => s.replace(/--certificate-identity '[^']*'/, "--certificate-identity '<IDENTITY>'");
check(
  'the notes’ cosign command is the document’s, modulo the identity',
  docCosign !== null && notesCosign !== null && maskIdentity(docCosign) === maskIdentity(notesCosign),
  docCosign === null || notesCosign === null
    ? undefined
    : `document:\n${maskIdentity(docCosign)}\n\n         notes:\n${maskIdentity(notesCosign)}`
);

// Named individually as well as covered by the equality above, because these
// are the flags whose absence is silent. `cosign verify-blob` without
// --certificate-identity prints "Verified OK" for a signature from anybody.
for (const flag of ['--bundle', '--certificate-oidc-issuer', '--certificate-identity']) {
  check(`the notes keep ${flag}`, (notesCosign || '').includes(flag));
}

// ---- 2. The identity is the release's, not the deployment's ----

check(
  'the notes name this workflow and tag',
  (notesCosign || '').includes(`--certificate-identity '${IDENTITY}'`),
  notesCosign || ''
);
check(
  'the deployment identity does not survive into the command',
  !(notesCosign || '').includes('deploy.yml@refs/heads/main'),
  'a release verified against deploy.yml@refs/heads/main fails for every user'
);

// ---- 3. The manifest check transfers, the site-mirroring steps do not ----

const notesSums = bashBlock(notes, 'sha256sum -c SHA256SUMS');
check('the notes carry the sha256sum check', notesSums !== null);
check(
  'the sha256sum line is the document’s, verbatim',
  (bashBlock(doc, 'sha256sum -c SHA256SUMS') || '')
    .split('\n')
    .filter((l) => l.startsWith('sha256sum '))
    .every((l) => (notesSums || '').includes(l))
);
// wget-ing the live site is the deployment procedure. Printed beside a tarball
// it would send a reader off to download something else entirely and then
// check it against this manifest, which fails for a reason that looks like
// tampering.
check('no site-mirroring steps leak into the notes', !/^(wget|cd site)/m.test(notesSums || ''), notesSums || '');

// ---- 4. The notes and the workflow agree on what is attached ----

const workflow = readFileSync(join(ROOT, '.github', 'workflows', 'release.yml'), 'utf8');
for (const asset of ['SHA256SUMS', 'SHA256SUMS.sigstore']) {
  check(`release.yml attaches ${asset}`, workflow.includes(`assets/out/${asset}`), 'the gate names this file specifically');
}
check(
  'release.yml attaches the tarball the notes tell users to unpack',
  workflow.includes('keymaker-${{ github.ref_name }}.tar.gz'),
  'the notes unpack keymaker-<tag>.tar.gz'
);
check(
  'the notes name every asset the workflow attaches',
  ['SHA256SUMS', 'SHA256SUMS.sigstore', `keymaker-${TAG}.tar.gz`].every((a) => notes.includes(a))
);
// The signature is verified against the identity the notes publish, in the job
// that produced it — so a wrong identity fails the release rather than every
// reader of it.
check(
  'release.yml verifies with the same identity it publishes',
  workflow.includes('KEYMAKER_CERT_IDENTITY: ${{ github.server_url }}/${{ github.workflow_ref }}') &&
    workflow.includes("'${{ github.server_url }}/${{ github.workflow_ref }}'"),
  'the verify step and the notes step must be given the same value'
);

// ---- 5. Content the roadmap asks for ----

check('the notes state the container format', notes.includes('KEYM v2'));
check('the notes point at the independent implementation', notes.includes('reference/keym2.py'));
check('an annotated tag’s message becomes "What changed"', notes.includes('## What changed\n\nSomething changed.'));
check(
  'a tag with no message omits the section rather than emptying it',
  !composeNotes({ doc, version, tag: TAG, workflowRef: IDENTITY, changelog: '  \n  ' }).includes('## What changed')
);
// The artifact is built for /Keymaker-v2/. Someone who unpacks it expecting a
// portable build gets a blank page and no explanation.
check('the notes disclose the base path', notes.includes('/Keymaker-v2/'));

// A release body is not rendered inside the repository tree, so `[x](docs/x.md)`
// 404s there even though it works everywhere else in this repo. Same failure
// class as a broken verify command, cheaper to make.
const relativeLinks = [...notes.matchAll(/\[[^\]]+\]\((?!https?:)([^)]+)\)/g)].map((m) => m[1]);
check('every link is absolute', relativeLinks.length === 0, relativeLinks.join(', '));
check(
  'links are pinned at the tag, not at a moving branch',
  [...notes.matchAll(/\]\((https:\/\/github\.com\/[^)]+)\)/g)].every((m) => m[1].includes(`/blob/${TAG}/`))
);
refuses(
  'refuses a workflow ref it cannot derive a repository URL from',
  { doc, version, tag: TAG, workflowRef: 'release.yml@refs/tags/v2.0.0' },
  'could not derive the repository URL'
);

// ---- 6. It refuses rather than emitting something plausible and wrong ----
//
// These are the checks that make the ones above worth anything. Every failure
// mode below produces notes that *look* fine — a missing section, a command
// with the wrong identity, a version that disagrees with the build — and each
// one is only discoverable by a reader at the moment they are relying on it.

refuses(
  'refuses when the cosign block is gone from the document',
  { doc: doc.replace(/```bash\n[^`]*cosign verify-blob[\s\S]*?```/, ''), version, tag: TAG, workflowRef: IDENTITY },
  'found 0'
);

const docWithTwo = doc.replace(
  /(```bash\n[^`]*cosign verify-blob[\s\S]*?```)/,
  '$1\n\n$1'
);
refuses(
  'refuses when the document grows a second copy',
  { doc: docWithTwo, version, tag: TAG, workflowRef: IDENTITY },
  'found 2'
);

refuses(
  'refuses when the identity flag changes shape and substitution silently no-ops',
  {
    doc: doc.replace(/--certificate-identity '([^']*)'/, '--certificate-identity=$1'),
    version,
    tag: TAG,
    workflowRef: IDENTITY,
  },
  'could not substitute'
);

refuses(
  'refuses a tag that disagrees with package.json',
  { doc, version, tag: 'v9.9.9', workflowRef: IDENTITY },
  'does not match package.json'
);

refuses(
  'refuses when the sha256sum block is gone',
  { doc: doc.replace(/```bash\n[^`]*sha256sum -c SHA256SUMS[\s\S]*?```/, ''), version, tag: TAG, workflowRef: IDENTITY },
  'sha256sum -c SHA256SUMS'
);

console.log();
if (failures > 0) {
  console.error(`${failures} check(s) failed.`);
  console.error('If docs/VERIFYING.md moved its verification commands, move scripts/release-notes.mjs');
  console.error('with it — do not paste a second copy of the command into the generator.');
  process.exit(1);
}
console.log('All checks passed — release notes are generated from docs/VERIFYING.md.');
