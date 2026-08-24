/**
 * The Shamir core under a hostile caller — `docs/FORMAT-V2-DESIGN.md` §4.6.
 *
 * Run with:  npm run test:shamir
 *
 * ## Why this is separate from the parity gate
 *
 * `reference/crosstest2.py` compares the emitted bytes of the two
 * implementations, which establishes that they *agree*. It cannot establish
 * that either is right, and on the index guard they agreed while both were
 * wrong: 256 and 0 are the same point in GF(2^8), 257 and 1 are the same point,
 * and both implementations compared the caller's number rather than the field
 * element. Each produced a clean 32-byte value from an index it had refused to
 * validate — the same clean wrong value, byte for byte, so parity was green.
 *
 * A suite that only asks "do the two match?" is structurally unable to see
 * that. This one asks "what does one of them do with input a person would not
 * hand it?" and the answers are pinned below.
 *
 * ## What is asserted, and what is only measured
 *
 * Three of the four sections assert. The fourth counts, because the property it
 * covers is probabilistic and asserting a rate would be asserting the absence
 * of an event this harness is too small to observe. That follows the paper-part
 * fuzzer, which counts undetectable substitutions rather than pretending to
 * have excluded them.
 *
 * ## What this deliberately does not claim
 *
 * The share record is **unauthenticated by design** and section 2 exists to
 * make that explicit rather than to complain about it. `share_checksum` is four
 * bytes of an unkeyed SHA-256 over a body containing no secret, so anyone can
 * evaluate it and therefore anyone can mint a well-formed share. §4.6 claims
 * only that it catches transcription damage. It does — section 3 measures how
 * well — and what stops a *forged* share is the slot AEAD, which is asserted
 * here so that nobody later mistakes the checksum or the set id for a security
 * control they are not.
 */
import {
  gfMul,
  shamirSplit,
  shamirCombine,
  combineShares,
  decodeShare,
  encodeShare,
  shareSetId,
  SHARE_LEN,
  SHARE_VALUE_LEN,
} from "../src/lib/keym-v2-shamir.ts";
import { createHash, randomBytes } from "node:crypto";

let passed = 0;
let failures = 0;
function check(ok: boolean, message: string): void {
  if (ok) {
    passed++;
  } else {
    failures++;
    console.error(`  FAIL  ${message}`);
  }
}

/** Fixed, so a failure is reproducible from the log alone. */
const SECRET = new Uint8Array(32);
for (let i = 0; i < 32; i++) SECRET[i] = (i * 7) & 0xff;
const COEFFS = new Uint8Array(32);
for (let i = 0; i < 32; i++) COEFFS[i] = (i * 13 + 5) & 0xff;

/** `shamirCombine` reports every refusal as the generic §6 failure. */
function refuses(fn: () => unknown): boolean {
  try {
    fn();
    return false;
  } catch {
    return true;
  }
}

async function main(): Promise<void> {
  const parts = shamirSplit(SECRET, 2, 3, COEFFS);
  const roundTrip = shamirCombine(parts.slice(0, 2));
  check(
    Buffer.from(roundTrip).equals(Buffer.from(SECRET)),
    "the honest 2-of-3 round trip still reconstructs the secret"
  );

  // ---- 1. Crafted indices ----
  // The guards and the arithmetic have to be checking the same domain. gfMul
  // masks to 0xff; a guard reading the caller's number is looking at a
  // different value from the one that will be multiplied.
  console.log("\nCrafted indices — the guard and the field must agree:");
  const other = parts[1]!.value;
  const first = parts[0]!.value;
  const crafted: [string, number, number, Uint8Array][] = [
    ["0 — the classic, already guarded", 0, 2, other],
    ["256 — masks to 0, past an `x === 0` test", 256, 2, other],
    ["512 — masks to 0 as well", 512, 2, other],
    ["-1 — masks to 255, a legal index it is not", -1, 2, other],
    ["257 beside 1 — distinct numbers, one point", 257, 1, first],
    ["1.5 — truncates to 1, and 1 ^ 1.5 is 0", 1.5, 1, first],
    ["NaN — every comparison against it is false", NaN, 2, other],
    ["Infinity", Infinity, 2, other],
  ];
  for (const [label, index, otherIndex, otherValue] of crafted) {
    check(
      refuses(() => shamirCombine([{ index, value: first }, { index: otherIndex, value: otherValue }])),
      `index ${label}: reconstructed instead of refusing`
    );
  }
  // The duplicate rule still has to hold for the ordinary case it was written
  // for, and the legal endpoints must still be accepted.
  check(
    refuses(() => shamirCombine([{ index: 1, value: first }, { index: 1, value: other }])),
    "a literally duplicated index is still refused"
  );
  // 255 is the top of the field-legal range and must survive the new bound.
  // `shamirSplit` caps n at 16 (a print-kit limit, §4.6), so the point is
  // evaluated straight off the polynomial: for k=2, f_j(x) = s_j ^ (a_j . x).
  const at255 = new Uint8Array(SHARE_VALUE_LEN);
  for (let j = 0; j < SHARE_VALUE_LEN; j++) {
    at255[j] = (SECRET[j] as number) ^ gfMul(COEFFS[j] as number, 255);
  }
  // Guarded, for the reason CLAUDE.md gives: a bound that crept down to 254
  // makes this *throw*, and an escaping throw aborts the run and reads as a
  // control that did not bite. It has to be recorded as a failed check instead.
  let wide: Uint8Array | null = null;
  try {
    wide = shamirCombine([
      { index: 255, value: at255 },
      { index: 1, value: parts[0]!.value },
    ]);
  } catch (error) {
    wide = null;
    console.error(`  (index 255 was refused: ${(error as Error).message})`);
  }
  check(
    wide !== null && Buffer.from(wide).equals(Buffer.from(SECRET)),
    "index 255 is field-legal and must still reconstruct, not be caught by the new bound"
  );

  // ---- 2. The share record is unauthenticated ----
  console.log("\nThe share record carries no authenticity, and must not appear to:");
  const forged = await encodeShare({
    setId: new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
    threshold: 2,
    index: 7,
    value: new Uint8Array(32).fill(0x41),
  });
  const decoded = await decodeShare(forged);
  check(
    decoded.index === 7 && decoded.threshold === 2,
    "a share minted from arbitrary fields decodes — the checksum is unkeyed and this is by design"
  );
  // Which is exactly why the set-id check cannot be load-bearing: an attacker
  // writes the target's set id into the share for the same cost.
  const victimSalt = new Uint8Array(32).fill(0x33);
  const victimSetId = await shareSetId(victimSalt);
  const impersonating = await Promise.all(
    [1, 2].map((index) =>
      encodeShare({ setId: victimSetId, threshold: 2, index, value: new Uint8Array(32).fill(index) })
    )
  );
  let combined: Uint8Array | null = null;
  try {
    combined = await combineShares(impersonating, victimSetId);
  } catch {
    combined = null;
  }
  check(
    combined !== null && combined.length === SHARE_VALUE_LEN,
    "shares carrying a copied set id pass every set-level rule — the id is a diagnostic, not a gate"
  );
  check(
    combined !== null && !Buffer.from(combined).equals(Buffer.from(SECRET)),
    "and reconstruct something that is not the real share secret, leaving the slot AEAD to refuse it"
  );

  // ---- 3. What share_set_id is actually worth against accident ----
  // Four bytes, so honest sets collide on a birthday schedule. Searched rather
  // than asserted from theory: the number is the point.
  console.log("\nshare_set_id is four bytes — the accidental-collision cost, measured:");
  const ctx = Buffer.from("keymaker.v2.share-set");
  const seen = new Map<string, Buffer>();
  let tries = 0;
  let collision: [Buffer, Buffer] | null = null;
  while (collision === null && tries < 4_000_000) {
    const salt = randomBytes(32);
    const id = createHash("sha256").update(Buffer.concat([ctx, salt])).digest().subarray(0, 4).toString("hex");
    const prev = seen.get(id);
    if (prev !== undefined && !prev.equals(salt)) collision = [prev, salt];
    else seen.set(id, salt);
    tries++;
  }
  check(collision !== null, "expected a 4-byte birthday collision well inside the search bound");
  if (collision !== null) {
    const a = await shareSetId(new Uint8Array(collision[0]));
    const b = await shareSetId(new Uint8Array(collision[1]));
    check(
      Buffer.from(a).equals(Buffer.from(b)),
      "the two salts really do derive the same share_set_id"
    );
    console.log(
      `  two distinct slot salts share a set id after ${tries} draws ` +
        `(${Buffer.from(a).toString("hex")}) — as expected for 32 bits`
    );
  }

  // ---- 4. What the checksum does claim: transcription damage ----
  // Counted, not asserted at a rate. A 4-byte checksum lets roughly one damaged
  // share in 2^32 through, which this harness cannot observe and will not
  // pretend to have excluded.
  console.log("\nTranscription damage — the one property §4.6 claims for the checksum:");
  const real = await encodeShare({
    setId: new Uint8Array([1, 2, 3, 4]),
    threshold: 2,
    index: 1,
    value: new Uint8Array(randomBytes(32)),
  });
  const ALPHA = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  const bodyStart = "KMSHARE1:".length;
  const accepts = async (text: string): Promise<boolean> => {
    try {
      await decodeShare(text);
      return true;
    } catch {
      return false;
    }
  };

  let subs = 0;
  let subsEscaped = 0;
  for (let pos = bodyStart; pos < real.length; pos++) {
    if (real[pos] === "-") continue;
    for (const c of ALPHA) {
      if (c === real[pos]) continue;
      subs++;
      if (await accepts(real.slice(0, pos) + c + real.slice(pos + 1))) subsEscaped++;
    }
  }

  // Hyphens are ignored by the decoder, so transpositions are measured on the
  // ungrouped body — otherwise the grouping hides the swaps that straddle it,
  // which are the ones a person copying in blocks of four actually makes.
  const flat = real.slice(bodyStart).replace(/-/g, "");
  let trans = 0;
  let transEscaped = 0;
  for (let pos = 0; pos + 1 < flat.length; pos++) {
    if (flat[pos] === flat[pos + 1]) continue;
    trans++;
    const swapped = flat.slice(0, pos) + flat[pos + 1] + flat[pos] + flat.slice(pos + 2);
    if (await accepts("KMSHARE1:" + swapped)) transEscaped++;
  }

  // A dropped or doubled character changes the length, so it is refused by the
  // base32 length rule before the checksum is consulted at all.
  let lengthErrors = 0;
  let lengthEscaped = 0;
  for (let pos = 0; pos < flat.length; pos++) {
    lengthErrors += 2;
    if (await accepts("KMSHARE1:" + flat.slice(0, pos) + flat.slice(pos + 1))) lengthEscaped++;
    if (await accepts("KMSHARE1:" + flat.slice(0, pos) + flat[pos] + flat.slice(pos))) lengthEscaped++;
  }

  console.log(`  single-character substitutions: ${subsEscaped}/${subs} undetected`);
  console.log(`  adjacent transpositions:        ${transEscaped}/${trans} undetected`);
  console.log(`  dropped / doubled characters:   ${lengthEscaped}/${lengthErrors} undetected`);
  console.log(
    `  ${SHARE_LEN}-byte record, 4-byte checksum: expected escape rate 2^-32, ` +
      `so 0 observed here is the expected result and not evidence of more.`
  );
  check(subsEscaped === 0, `a single-character typo went undetected (${subsEscaped} of ${subs})`);
  check(transEscaped === 0, `an adjacent transposition went undetected (${transEscaped} of ${trans})`);
  check(
    lengthEscaped === 0,
    `a dropped or doubled character went undetected (${lengthEscaped} of ${lengthErrors})`
  );

  console.log(`\n${passed} assertions passed, ${failures} failed`);
  if (failures > 0) {
    console.error("Shamir adversarial suite FAILED.");
    process.exit(1);
  }
  console.log("Shamir adversarial suite passed.");
}

await main();
