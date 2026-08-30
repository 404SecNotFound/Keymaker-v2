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
import { composeNotes, readSources, writtenFormatVersion } from './release-notes.mjs';

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

const { doc, version, formatVersion } = readSources();
const TAG = `v${version}`;
const IDENTITY = `https://github.com/404SecNotFound/Keymaker-v2/.github/workflows/release.yml@refs/tags/${TAG}`;

const notes = composeNotes({ doc, version, formatVersion, tag: TAG, workflowRef: IDENTITY, changelog: 'Something changed.' });

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
//
// Read as values rather than as one textual shape. Every identity in this
// workflow now reaches its step through `env:`, so the previous form of this
// check — which looked for the expression inline, in quotes, inside a `run:`
// body — was asserting the very thing the shell-injection fix removed, and
// went red on a workflow that had got safer. What matters is not where the
// expression sits but that every site is handed the same one.
const CANONICAL_IDENTITY = '${{ github.server_url }}/${{ github.workflow_ref }}';
const identities = [...workflow.matchAll(/^\s*[A-Z_]*IDENTITY:\s*(\S.*?)\s*$/gm)].map((m) => m[1]);
const distinctIdentities = [...new Set(identities)];
check(
  'release.yml verifies with the same identity it publishes',
  identities.length >= 2 && distinctIdentities.length === 1 && distinctIdentities[0] === CANONICAL_IDENTITY,
  `the verify steps and the notes step must be given the same value; found ${identities.length} site(s): ${
    distinctIdentities.map((i) => JSON.stringify(i)).join(', ') || 'none'
  }`
);

// The other half of the same rule, and the half with teeth. A tag name is
// attacker-influenced text — git permits quotes, semicolons and $( ) in a ref
// — and `${{ }}` is substituted into a script *before* bash parses it. So an
// interpolation anywhere inside a `run:` body hands the tag author a shell in
// a job that holds a token. Values arrive through `env:` instead, which GitHub
// passes to the process rather than through the parser.
//
// Nothing guarded that, and it is precisely the kind of thing reintroduced by
// copying the shape of a neighbouring step.
const interpolatedRunLines = [];
{
  const lines = workflow.split('\n');
  let runIndent = null;
  for (const [i, line] of lines.entries()) {
    if (runIndent !== null) {
      const indent = line.search(/\S/);
      if (indent === -1) continue; // blank lines stay inside the block
      if (indent <= runIndent) runIndent = null; // a dedent ends it
      else if (line.includes('${{')) interpolatedRunLines.push(`line ${i + 1}: ${line.trim()}`);
    }
    if (runIndent === null) {
      const start = line.match(/^(\s*)run:\s*(.*)$/);
      if (start) {
        if (/^[|>]/.test(start[2])) runIndent = start[1].length;
        else if (start[2].includes('${{')) interpolatedRunLines.push(`line ${i + 1}: ${line.trim()}`);
      }
    }
  }
}
check(
  'no tag-controlled value is interpolated into a shell',
  interpolatedRunLines.length === 0,
  interpolatedRunLines.join('\n         ')
);

// ---- 5. Content the roadmap asks for ----

check(
  'the notes state the container format this build actually writes',
  notes.includes(`writing **KEYM v${formatVersion}** containers`),
  `the implementation writes v${formatVersion}; the notes do not say so`
);
check('the notes point at the independent implementation', notes.includes('reference/keym2.py'));
check('an annotated tag’s message becomes "What changed"', notes.includes('## What changed\n\nSomething changed.'));
check(
  'a tag with no message omits the section rather than emptying it',
  !composeNotes({ doc, version, formatVersion, tag: TAG, workflowRef: IDENTITY, changelog: '  \n  ' }).includes('## What changed')
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
  { doc, version, formatVersion, tag: TAG, workflowRef: 'release.yml@refs/tags/v2.0.0' },
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
  { doc: doc.replace(/```bash\n[^`]*cosign verify-blob[\s\S]*?```/, ''), version, formatVersion, tag: TAG, workflowRef: IDENTITY },
  'found 0'
);

const docWithTwo = doc.replace(
  /(```bash\n[^`]*cosign verify-blob[\s\S]*?```)/,
  '$1\n\n$1'
);
refuses(
  'refuses when the document grows a second copy',
  { doc: docWithTwo, version, formatVersion, tag: TAG, workflowRef: IDENTITY },
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
  { doc, version, formatVersion, tag: 'v9.9.9', workflowRef: IDENTITY },
  'does not match package.json'
);

refuses(
  'refuses when the sha256sum block is gone',
  { doc: doc.replace(/```bash\n[^`]*sha256sum -c SHA256SUMS[\s\S]*?```/, ''), version, formatVersion, tag: TAG, workflowRef: IDENTITY },
  'sha256sum -c SHA256SUMS'
);

// ---- 4. The container version is read, not restated ----
//
// This is the check the notes did not have. "KEYM v2" was prose in three
// places; when the writer moved to v3 nothing made them follow, and v2.1.0
// published notes that opened with "writing KEYM v2 containers" and linked
// FORMAT-V2-DESIGN.md while the tag message below said v3. The reader most
// likely to read that section is one holding a file that will not open, and it
// pointed them at the wrong specification.

check(
  'and link that version\'s specification, not another one',
  notes.includes(`docs/FORMAT-V${formatVersion}-DESIGN.md`) &&
    !/FORMAT-V(?!${formatVersion}\b)\d+-DESIGN/.test(notes.replace(new RegExp(`FORMAT-V${formatVersion}-DESIGN`, 'g'), '')),
  'the notes link a format document other than the one this build writes'
);

// The number comes from src/lib/keym-v2.ts. If that declaration moves, the
// extractor must refuse rather than fall back to a number that used to be true.
refuses(
  'refuses to compose without a format version rather than defaulting',
  { doc, version, tag: TAG, workflowRef: IDENTITY },
  'needs formatVersion'
);

check(
  'reads the written version out of the implementation',
  writtenFormatVersion('export const KEYM2_VERSION = KEYM2_VERSION_V7;') === 7,
  'the extractor did not read the declared version'
);

let extractorRefused = false;
try {
  writtenFormatVersion('const KEYM2_VERSION = "not a version";');
} catch {
  extractorRefused = true;
}
check(
  'refuses when the declaration it reads is gone',
  extractorRefused,
  'it returned a version from a source that does not declare one'
);

console.log();
if (failures > 0) {
  console.error(`${failures} check(s) failed.`);
  console.error('If docs/VERIFYING.md moved its verification commands, move scripts/release-notes.mjs');
  console.error('with it — do not paste a second copy of the command into the generator.');
  process.exit(1);
}
console.log('All checks passed — release notes are generated from docs/VERIFYING.md.');
