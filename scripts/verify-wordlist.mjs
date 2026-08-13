#!/usr/bin/env node
/**
 * Offline verification of the bundled EFF Long Wordlist.
 *
 * Runs in CI with no network and no dependencies installed. Its job is to make
 * a hand-edit of src/lib/eff-wordlist.ts fail loudly, because that file is the
 * denominator of the passphrase generator's entropy claim: drop an entry and
 * every bit-count the UI prints is wrong, duplicate one and it is overstated.
 * That is the KM-02/KM-03 failure class — a number the user trusts that is
 * larger than the truth — so it gets a test rather than a comment.
 *
 * The central check reconstructs EFF's own file layout from the shipped array
 * and compares its SHA-256 to the recorded one. That single comparison covers
 * content, order and completeness at once: any substitution, reordering,
 * insertion or deletion changes the digest.
 *
 * scripts/generate-wordlist.mjs is the counterpart that fetches and cross-checks
 * upstream sources. It needs the network and is run by hand; this does not.
 */
import { createHash } from 'node:crypto';

const {
  EFF_LARGE_WORDLIST: WORDS,
  EFF_LARGE_WORDLIST_SIZE: SIZE,
  EFF_LARGE_WORDLIST_SHA256: RECORDED,
} = await import('../src/lib/eff-wordlist.ts');

let failures = 0;
function check(name, ok, detail) {
  if (ok) {
    console.log(`  ok   ${name}`);
  } else {
    failures++;
    console.log(`  FAIL ${name}${detail ? `\n         ${detail}` : ''}`);
  }
}

console.log('EFF Long Wordlist verification\n');

// 6^5 — one entry per outcome of five dice. A short list is not merely smaller,
// it breaks the dice mapping the list is built around.
check('7,776 entries', WORDS.length === 7776, `got ${WORDS.length}`);
check('exported size matches array', SIZE === WORDS.length, `${SIZE} vs ${WORDS.length}`);

// The one that the entropy claim rests on most directly. A collision means two
// dice rolls that produce the same word, so the real outcome space is smaller
// than log2(7776) per word says it is.
const unique = new Set(WORDS);
const duplicates = [...new Set(WORDS.filter((w, i) => WORDS.indexOf(w) !== i))];
check('no duplicates', unique.size === WORDS.length, duplicates.length ? `repeated: ${duplicates.join(', ')}` : '');

// Whitespace inside an entry would split one drawn word into two on display,
// so a phrase would appear to carry more words — and more entropy — than was
// actually drawn. The hyphen is legitimate: drop-down, felt-tip, t-shirt, yo-yo.
const malformed = WORDS.filter((w) => !/^[a-z-]+$/.test(w));
check('entries match /^[a-z-]+$/', malformed.length === 0, malformed.slice(0, 10).join(', '));

const lengths = WORDS.map((w) => w.length);
check(
  'entry lengths within 3..9',
  Math.min(...lengths) >= 3 && Math.max(...lengths) <= 9,
  `observed ${Math.min(...lengths)}..${Math.max(...lengths)}`
);

// Reconstruct EFF's file: "<dice>\t<word>\n" for all 6^5 indices in order.
const canonical = WORDS.map((w, i) => {
  const dice = i
    .toString(6)
    .padStart(5, '0')
    .split('')
    .map((d) => String(Number(d) + 1))
    .join('');
  return `${dice}\t${w}\n`;
}).join('');
const digest = createHash('sha256').update(canonical, 'utf8').digest('hex');

check('canonical SHA-256 matches upstream', digest === RECORDED, `recorded ${RECORDED}\n         computed ${digest}`);

// Guards the reconstruction itself rather than the data: if the dice-index
// arithmetic above were wrong, the digest check would fail for a reason that
// has nothing to do with the wordlist, and this says which.
check('dice index spans 11111..66666', canonical.startsWith('11111\t') && canonical.endsWith('66666\tzoom\n'));

console.log();
if (failures > 0) {
  console.error(`${failures} check(s) failed.`);
  console.error('If the wordlist was changed deliberately, rerun scripts/generate-wordlist.mjs');
  console.error('so the recorded checksum is derived from upstream rather than edited to match.');
  process.exit(1);
}
console.log(`All checks passed — ${WORDS.length} words, sha256 ${digest}`);
