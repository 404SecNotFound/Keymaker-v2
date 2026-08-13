#!/usr/bin/env node
/**
 * Regenerate src/lib/eff-wordlist.ts from upstream sources.
 *
 * This is a maintenance tool, not a build step and not a test. It needs the
 * network; nothing else in the project does. `npm run verify:wordlist` is the
 * offline check that runs in CI, and it re-derives the same checksum this
 * script records, so a hand-edited wordlist fails there without needing this.
 *
 * WHY THIS SCRIPT EXISTS AT ALL
 *
 * A passphrase generator's entropy claim is arithmetic over the size of the
 * list it samples from. If the list silently contains a duplicate, the claim
 * is an overstatement — the two colliding entries are one outcome, not two.
 * That is the same failure class as KM-02/KM-03: a number the user relies on
 * that is larger than the truth. So the list is not transcribed, typed, or
 * recalled. It is fetched, cross-checked against independent redistributions,
 * and pinned by hash.
 *
 * SOURCES
 *
 * The canonical file is EFF's, at
 * https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt — see
 * https://www.eff.org/dice for the accompanying write-up. That host is not
 * reachable from every build environment, so this script pulls the same list
 * from three independent redistributions on two package registries and
 * requires all three to agree on the full ordered 7,776-word sequence before
 * emitting anything. Agreement across independently maintained republications
 * is what stands in for fetching from eff.org directly: a corrupted or
 * tampered copy would have to have been introduced identically in all three.
 *
 * Two of the three ship the upstream file byte-for-byte, so the recorded
 * SHA-256 is the hash of the real artifact, not of anything this project
 * invented.
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const OUT = new URL('../src/lib/eff-wordlist.ts', import.meta.url).pathname;

// Pinned by exact version and, where the registry publishes one, by the
// integrity hash of the archive itself. An unpinned fetch would make this
// script's output depend on whatever was current the day it last ran.
const SOURCES = [
  {
    id: 'npm:eff-diceware-passphrase@3.0.0',
    url: 'https://registry.npmjs.org/eff-diceware-passphrase/-/eff-diceware-passphrase-3.0.0.tgz',
    archiveSha256: 'e3b1965ff4cd9c86bea15794857fbf4e2e0be32e2c52bb0c32bfa2df401ac2f4',
    kind: 'tgz',
    member: 'package/eff_large_wordlist.txt',
  },
  {
    id: 'pypi:diceware@1.0.1',
    url: 'https://files.pythonhosted.org/packages/3b/82/a89797a4bb6f80eb85716ecd1dcbaf0073a3eb39f7ccae98ef72692d2434/diceware-1.0.1-py3-none-any.whl',
    kind: 'zip',
    member: 'diceware/wordlists/wordlist_en_eff.txt',
  },
  {
    id: 'pypi:xkcdpass@1.30.0',
    url: 'https://files.pythonhosted.org/packages/6b/be/ea93adc1b4597b62c236d61dc6cf0e26ca8a729cb5afae4dc5acc5b33fa8/xkcdpass-1.30.0-py3-none-any.whl',
    kind: 'zip',
    member: 'xkcdpass/static/eff-long',
  },
];

const work = mkdtempSync(join(tmpdir(), 'keym-wordlist-'));

function fetchToFile(url, dest) {
  execFileSync('curl', ['-sSL', '--fail', '--max-time', '120', '-o', dest, url], {
    stdio: ['ignore', 'ignore', 'inherit'],
  });
}

function extract(archive, kind, member, dest) {
  if (kind === 'tgz') {
    execFileSync('tar', ['xzf', archive, '-C', dest, member]);
    return readFileSync(join(dest, member));
  }
  // Wheels are plain zip archives. `unzip -p` streams one member to stdout.
  return execFileSync('unzip', ['-p', archive, member], { maxBuffer: 1 << 24 });
}

/**
 * Reduce a redistribution to the bare ordered word sequence.
 *
 * The three sources differ in packaging, not content: some keep EFF's
 * "<dice>\t<word>" columns, others ship words alone. Taking the last
 * whitespace-separated field normalises both without assuming which is which.
 */
function toWords(buf) {
  return buf
    .toString('utf8')
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .map((line) => line.split(/\s+/).pop());
}

console.log('Fetching sources...\n');

const fetched = [];
for (const src of SOURCES) {
  const archive = join(work, src.id.replace(/[^a-z0-9]+/gi, '_'));
  fetchToFile(src.url, archive);

  const archiveHash = createHash('sha256').update(readFileSync(archive)).digest('hex');
  if (src.archiveSha256 && archiveHash !== src.archiveSha256) {
    throw new Error(
      `${src.id}: archive SHA-256 mismatch\n  expected ${src.archiveSha256}\n  got      ${archiveHash}`
    );
  }

  const raw = extract(archive, src.kind, src.member, work);
  const words = toWords(raw);
  fetched.push({ ...src, words, rawSha256: createHash('sha256').update(raw).digest('hex') });

  console.log(`  ${src.id}`);
  console.log(`    archive sha256 ${archiveHash}`);
  console.log(`    member         ${src.member}`);
  console.log(`    member sha256  ${createHash('sha256').update(raw).digest('hex')}`);
  console.log(`    words          ${words.length}\n`);
}

// --- Cross-source agreement -------------------------------------------------
// Order matters as much as membership: the dice index is positional, so two
// lists holding the same words in a different order are different lists.
const [reference, ...others] = fetched;
for (const other of others) {
  if (other.words.length !== reference.words.length) {
    throw new Error(
      `length disagreement: ${reference.id} has ${reference.words.length}, ` +
        `${other.id} has ${other.words.length}`
    );
  }
  const differing = reference.words.findIndex((w, i) => w !== other.words[i]);
  if (differing !== -1) {
    throw new Error(
      `content disagreement at index ${differing}: ` +
        `${reference.id} has "${reference.words[differing]}", ` +
        `${other.id} has "${other.words[differing]}"`
    );
  }
}
console.log(`All ${fetched.length} sources agree on the full ordered sequence.\n`);

const words = reference.words;

// --- Structural checks ------------------------------------------------------
// These are the properties the entropy claim actually rests on. Duplicates are
// the one that matters most: 7,776 entries with one collision is 7,775
// outcomes, and every bit-count downstream would be overstated.
const problems = [];
if (words.length !== 7776) problems.push(`expected 7776 words, got ${words.length}`);
if (new Set(words).size !== words.length) {
  const seen = new Set();
  const dupes = words.filter((w) => (seen.has(w) ? true : (seen.add(w), false)));
  problems.push(`duplicate entries: ${[...new Set(dupes)].join(', ')}`);
}
// [a-z] plus the hyphen, which four genuine entries use (drop-down, felt-tip,
// t-shirt, yo-yo). Asserted rather than assumed: an entry carrying whitespace
// would silently split a passphrase into more "words" than were drawn.
const badChars = words.filter((w) => !/^[a-z-]+$/.test(w));
if (badChars.length) problems.push(`unexpected characters: ${badChars.join(', ')}`);
if (problems.length) throw new Error('Wordlist failed validation:\n  ' + problems.join('\n  '));

// --- Canonical form and checksum -------------------------------------------
// The canonical form is EFF's own file layout: five-digit dice index, a tab,
// the word, newline-terminated. Reconstructing it here means the recorded
// checksum is the hash of the upstream artifact, so the verification step can
// prove the shipped array is that artifact — complete, in order, unaltered —
// with a single comparison.
const canonical = words
  .map((w, i) => {
    const dice = i
      .toString(6)
      .padStart(5, '0')
      .split('')
      .map((d) => String(Number(d) + 1))
      .join('');
    return `${dice}\t${w}\n`;
  })
  .join('');
const canonicalSha256 = createHash('sha256').update(canonical, 'utf8').digest('hex');

const byteIdentical = fetched.filter((f) => f.rawSha256 === canonicalSha256).map((f) => f.id);
console.log(`Canonical SHA-256: ${canonicalSha256}`);
console.log(`Byte-identical upstream copies: ${byteIdentical.join(', ') || 'none'}\n`);

// --- Emit -------------------------------------------------------------------
// Words go out as one space-delimited string split at load rather than 7,776
// quoted array elements: about a third of the source size, and it parses as a
// single string literal instead of a large array expression.
const WRAP = 88;
const lines = [];
let line = '';
for (const w of words) {
  if (line && line.length + 1 + w.length > WRAP) {
    lines.push(line);
    line = w;
  } else {
    line = line ? `${line} ${w}` : w;
  }
}
if (line) lines.push(line);

const ts = `// GENERATED FILE — do not edit by hand.
//
// Regenerate with:  node scripts/generate-wordlist.mjs   (requires network)
// Verify with:      npm run verify:wordlist              (offline, runs in CI)
//
// The EFF Long Wordlist (2016), 7,776 entries in dice order, used by the
// passphrase generator. Upstream:
//   https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
//   https://www.eff.org/dice
//
// Not transcribed. Fetched from ${fetched.length} independent redistributions and
// required to agree on the full ordered sequence before this file was written:
${fetched.map((f) => `//   ${f.id}\n//     ${f.member}\n//     sha256 ${f.rawSha256}`).join('\n')}
//
// ${byteIdentical.length} of those ship EFF's file byte-for-byte, so the checksum below is the
// hash of the upstream artifact itself:
//
//   sha256(canonical) = ${canonicalSha256}
//
// "Canonical" is EFF's own layout — "<5-digit dice index>\\t<word>\\n" for all
// 6^5 indices in order. verify-wordlist.mjs rebuilds exactly those bytes from
// the array below and compares, which checks content, order and completeness
// in one assertion.

/**
 * SHA-256 of the canonical upstream file, reconstructible from EFF_LARGE_WORDLIST.
 * Checked offline by scripts/verify-wordlist.mjs.
 */
export const EFF_LARGE_WORDLIST_SHA256 =
  '${canonicalSha256}';

/**
 * The EFF Long Wordlist in dice order: index 0 is roll 11111, index 7775 is
 * 66666. Order is load-bearing — the dice index is positional.
 *
 * Stored whitespace-delimited and split once at module load. Every entry
 * matches /^[a-z-]+$/ and none contains whitespace, so the split is exact and
 * a generated passphrase always has as many words as draws were made.
 *
 * The literal is wrapped for readability, so the separator is /\\s+/ rather
 * than a single space — splitting on ' ' would fuse the pair straddling each
 * line break into one entry and silently shorten the list.
 */
export const EFF_LARGE_WORDLIST: readonly string[] = \`
${lines.join('\n')}
\`
  .trim()
  .split(/\\s+/);

/**
 * 7,776 = 6^5. Exported so the entropy arithmetic reads from the list itself
 * rather than from a constant that could drift away from it.
 */
export const EFF_LARGE_WORDLIST_SIZE = EFF_LARGE_WORDLIST.length;
`;

writeFileSync(OUT, ts);
rmSync(work, { recursive: true, force: true });

console.log(`Wrote ${OUT}`);
console.log(`  ${words.length} words, ${(ts.length / 1024).toFixed(1)} KiB of source`);
