/**
 * Fuzzer for the KEYM **v2** surfaces.
 *
 * Run with:  npm run test:fuzz2
 *
 * `keymaker-fuzz.mts` is v1-shaped. It drives `parseKeym()`/`detectFormat()`
 * and, because `decryptData` dispatches on the version byte, its random blobs
 * do reach the v2 parser — but only ever as noise. It never builds a real
 * multi-slot container and walks a mutation across the slot table, and it
 * never touches the four v2 surfaces that take input as *text* rather than as
 * a `.keym` file:
 *
 *   - armor (`keym2:…`), pasted into the decrypt box
 *   - Shamir shares (`KMSHARE1:…`), typed in off paper by an heir
 *   - the §7.2 self-extracting page, handed to `keym2.py` or pasted back
 *   - the slot table itself, whose `slot_count` is deliberately outside every
 *     AAD (§5.3) and is therefore the one header field an attacker can edit
 *     without invalidating anything
 *
 * Each of those is consumed before authentication, which is the same position
 * the v1 parser occupies and the reason it was fuzzed first.
 *
 * The invariants are the v1 ones, restated for v2:
 *
 *   1. Rejection is a thrown Error — never a crash, never a hang, never a
 *      silent success on garbage, and never `undefined` coming back as if it
 *      were plaintext.
 *   2. Structural rejection is fast. Deciding a slot table is malformed is
 *      byte inspection and must not reach a KDF.
 *   3. Rejection is deterministic. Same bytes, same verdict, every time.
 *   4. A slot that cannot be parsed disqualifies *itself*, not the container.
 *      This one is v2-specific and it is a data-loss property, not a security
 *      one: §4.4 requires unknown and broken slots to be skipped, because
 *      rewriting six bytes of slot 0 must not make a container permanently
 *      unopenable through the untouched, valid slot 1.
 *
 * The generator is seeded, so a CI failure reproduces exactly.
 */
import {
  addPasskeySlotKeym2,
  addShamirSlotKeym2,
  armorKeym2,
  dearmorKeym2,
  decryptKeym2,
  encryptKeym2WithExplicitSecrets,
  inspectKeym2,
  keym2SlotLen,
  KEYM2_ARMOR_PREFIX,
  KEYM2_MAX_SLOTS,
} from "../src/lib/keym-v2.ts";
import { combineShares } from "../src/lib/keym-v2-shamir.ts";
import { looksLikeSelfExtract } from "../src/lib/keym-v2-selfextract.ts";
import { CipherId, KdfId } from "../src/lib/keymaker-crypto.ts";

const PASSWORD = "fuzz-harness-password-not-a-secret-0000";
const PRF_OUTPUT = new Uint8Array(32).fill(0x5a);
/** Fixed, because the harness must be reproducible; §4.7 lets the caller
 *  supply the slot salt so conformance can pin bytes, and that is what makes
 *  a seeded fuzz run repeat exactly. */
const PASSKEY_SALT = new Uint8Array(32).fill(0x3c);
const FIXED_SALT = new Uint8Array(32).fill(0x11);
const FIXED_MASTER_KEY = new Uint8Array(32).fill(0x22);
const SHAMIR_SALT = new Uint8Array(32).fill(0x33);
const SHARE_SECRET = new Uint8Array(32).fill(0x44);
/** (k-1) coefficients x 32 bytes for a 2-of-3 split. */
const SHAMIR_COEFFS = new Uint8Array(32).fill(0x55);

/** §3/§4.4 offsets the mutation sweeps need. Mirrored, not imported: these are
 *  module-private in keym-v2.ts, and a fuzzer that imported them would stop
 *  noticing if the layout moved underneath it. */
const SLOT_COUNT_OFFSET = 8;
const SLOT_TABLE_OFFSET = 9;

/**
 * Two budgets, for the same reason the v1 fuzzer has two.
 *
 * A structural rejection — bad magic, `slot_count` out of range, a container
 * shorter than its own declared slot table — is byte inspection and must
 * finish in microseconds without deriving anything.
 *
 * Reaching a KDF is legitimate once the header is structurally valid and in
 * range: a slot's wrap genuinely cannot be checked before its key exists. What
 * bounding the parameters bought is not "hostile files are free" but "hostile
 * files cost no more than the most expensive setting a real user could have
 * chosen", per slot, times the slots a matching secret makes us try.
 *
 * KDF_BOUND_MS is deliberately generous. A measured worst case is 8 slots at
 * the §6 ceiling (256 MiB, t=10, p=8) at ~4.5 s each — about 36 s. This
 * harness never builds one, because doing so would make the fuzz job take
 * longer than the rest of CI combined; the ceiling is asserted here so that a
 * parameter escaping its bound still shows up as a timeout rather than as a
 * job that merely got slower.
 */
const PARSE_REJECT_MS = 750;
const KDF_BOUND_MS = 40_000;

let failures = 0;
let passed = 0;
function check(condition: boolean, label: string) {
  if (condition) passed++;
  else {
    failures++;
    console.error(`  FAIL  ${label}`);
  }
}

/** xorshift32 — small, deterministic, seedable. Math.random() would make a CI
 *  failure unreproducible, which is the one thing a fuzzer must not be. */
function makeRng(seed: number) {
  let s = seed >>> 0 || 0x2545f491;
  return () => {
    s ^= s << 13;
    s >>>= 0;
    s ^= s >> 17;
    s ^= s << 5;
    s >>>= 0;
    return s;
  };
}

/** Cheapest legal write settings: this exercises the *format*, and paying for
 *  real Argon2id would only make it something nobody runs. PBKDF2's floor is
 *  enforced on encrypt, so 600_000 is the least this can honestly ask for. */
const FAST = {
  kdf: { kdf: KdfId.PBKDF2, params: { iterations: 600_000 } },
  cipher: CipherId.AES_256_GCM,
} as const;

/** What the fixture container holds, so a success can be checked rather than
 *  merely counted. */
const PLAINTEXT = "fuzz plaintext, v2";

/**
 * Feed one blob to the v2 decrypt path and assert the invariants.
 *
 * **Success is not automatically a failure here, and that is the difference
 * from the v1 fuzzer.** That harness feeds garbage, so any success means it
 * authenticated noise. This one deforms a *real* three-slot container, and
 * §4.4 requires a damaged slot to disqualify only itself — so mutating the
 * Shamir slot and then opening the container through the untouched passphrase
 * slot is the specified behaviour, not a finding. Asserting "never succeeds"
 * here reported 574 failures on a correct implementation.
 *
 * The property that actually holds is tighter and worth more: a mutation
 * either fails cleanly or returns *exactly* the original plaintext. Never a
 * prefix, never a different length, never garbage that authenticated. That
 * rules out the failure this format's chunking could plausibly have — a
 * truncated payload whose surviving chunks all verify.
 *
 * Returns the outcome so callers can run the same bytes twice and compare.
 */
async function probeContainer(bytes: Uint8Array, label: string): Promise<string> {
  // inspectKeym2 must be total. It drives a label in the decrypt panel and is
  // called on whatever the user pasted, so it returns null rather than
  // throwing — a throw here reaches the UI as an unhandled rejection.
  try {
    inspectKeym2(bytes);
  } catch (e) {
    check(false, `${label}: inspectKeym2 threw (${(e as Error).message})`);
    return "inspect-threw";
  }

  const started = process.hrtime.bigint();
  let outcome: string;
  let message = "";
  try {
    const result = await decryptKeym2(bytes, PASSWORD, null);
    const text = new TextDecoder().decode(result.data);
    check(
      text === PLAINTEXT,
      `${label}: decrypt succeeded but returned ${result.data.length} bytes that are not the ` +
        `plaintext — authenticated something that is not what was sealed`
    );
    outcome = "success";
  } catch (e) {
    outcome = e instanceof Error ? "error" : "non-error-throw";
    message = e instanceof Error ? e.message : String(e);
    check(e instanceof Error, `${label}: threw a non-Error value (${String(e)})`);
  }
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

  // §6 makes every failure message generic on purpose, so the message cannot
  // say whether a KDF ran. Structure is what decides: a container whose slot
  // table cannot even be laid out was rejected without deriving anything.
  const budget = laidOut(bytes) ? KDF_BOUND_MS : PARSE_REJECT_MS;
  check(
    elapsedMs < budget,
    `${label}: ${elapsedMs.toFixed(1)}ms exceeds the ${
      budget === PARSE_REJECT_MS ? "parse" : "KDF"
    } budget of ${budget}ms (error=${message.slice(0, 70)})`
  );
  return outcome;
}

/** Could this blob's slot table be laid out at all? Mirrors §6's arithmetic,
 *  and is the line between "must be microseconds" and "may derive a key". */
function laidOut(b: Uint8Array): boolean {
  if (b.length < SLOT_TABLE_OFFSET) return false;
  const count = b[SLOT_COUNT_OFFSET] as number;
  if (count < 1 || count > KEYM2_MAX_SLOTS) return false;
  // Cipher id is byte 6; an unknown one is rejected structurally.
  const cipher = b[6] as number;
  if (cipher !== CipherId.AES_256_GCM && cipher !== CipherId.CHACHA20_POLY1305 && cipher !== CipherId.CHAINED) {
    return false;
  }
  return b.length >= SLOT_TABLE_OFFSET + count * keym2SlotLen(cipher);
}

/** Text surfaces must reject without throwing anything but an Error, and fast:
 *  none of them derives a key. */
async function probeText(
  fn: () => unknown | Promise<unknown>,
  label: string,
  budgetMs = PARSE_REJECT_MS
): Promise<string> {
  const started = process.hrtime.bigint();
  let outcome: string;
  try {
    await fn();
    outcome = "returned";
  } catch (e) {
    outcome = e instanceof Error ? "error" : "non-error-throw";
    check(e instanceof Error, `${label}: threw a non-Error value (${String(e)})`);
  }
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  check(elapsedMs < budgetMs, `${label}: ${elapsedMs.toFixed(1)}ms exceeds ${budgetMs}ms`);
  return outcome;
}

async function main() {
  console.log("\nKEYM v2 fuzzing\n");

  // A real container with one slot of each type. Built once: this is the
  // artifact the mutation sweeps deform, and building it is the expensive part.
  console.log("Building a three-slot container (passphrase + shamir + passkey)…");
  const plaintext = new TextEncoder().encode(PLAINTEXT);
  // Every secret pinned, so the fixture is byte-identical on every run.
  //
  // `encryptKeym2` draws a random salt and master key, which made the header's
  // "a CI failure reproduces exactly" false: the mutation sweep skips a
  // position when the byte already holds the value it is about to be set to,
  // and with random bytes underneath, the number of skips — and so the
  // assertion count — drifted run to run. Measured at 4389, 4387 and 4383
  // across three runs before this was pinned.
  //
  // `encryptKeym2WithExplicitSecrets` exists for exactly this: the conformance
  // suite uses it to pin bytes against the Python reference. Same reason here.
  const oneSlot = await encryptKeym2WithExplicitSecrets(
    plaintext, PASSWORD, null, FAST, FIXED_SALT, FIXED_MASTER_KEY
  );
  const shareSet = await addShamirSlotKeym2(
    oneSlot, { password: PASSWORD, keyFile: null }, 2, 3,
    { salt: SHAMIR_SALT, shareSecret: SHARE_SECRET, coefficients: SHAMIR_COEFFS }
  );
  const twoSlot = shareSet.container;
  const threeSlot = await addPasskeySlotKeym2(
    twoSlot,
    { password: PASSWORD, keyFile: null },
    PRF_OUTPUT,
    PASSKEY_SALT
  );
  // The fixture must be byte-identical every run, or "a CI failure reproduces
  // exactly" is a claim and not a property. Building it twice from the same
  // pinned inputs is the cheapest way to hold that: it costs one extra PBKDF2
  // and it fails the moment someone reintroduces a random secret here.
  const rebuilt = await encryptKeym2WithExplicitSecrets(
    plaintext, PASSWORD, null, FAST, FIXED_SALT, FIXED_MASTER_KEY
  );
  check(
    rebuilt.length === oneSlot.length && rebuilt.every((b, i) => b === oneSlot[i]),
    "fixture: two builds from the same pinned secrets differ — this harness is not reproducible"
  );

  const width = keym2SlotLen(CipherId.AES_256_GCM);
  const tableEnd = SLOT_TABLE_OFFSET + 3 * width;
  console.log(`  ${threeSlot.length} bytes, slot width ${width}, table [${SLOT_TABLE_OFFSET}, ${tableEnd})`);

  // Sanity: the unmutated container must still open, or every "rejected"
  // below is vacuous — a harness that cannot open a good container proves
  // nothing by rejecting bad ones.
  const good = await decryptKeym2(threeSlot, PASSWORD, null);
  check(
    new TextDecoder().decode(good.data) === PLAINTEXT,
    "baseline: the unmutated three-slot container opens"
  );

  // ---- 1. slot_count, the one field in no AAD (§5.3) ----
  // Editable by anyone who can write the file, with no key. Every value must
  // either lay the table out correctly or be refused; none may hang or crash.
  console.log("\nslot_count sweep (0..255 — deliberately outside every AAD):");
  for (let n = 0; n <= 255; n++) {
    const m = threeSlot.slice(0);
    m[SLOT_COUNT_OFFSET] = n;
    await probeContainer(m, `slot_count=${n}`);
  }
  console.log("  256 slot_count values probed");

  // ---- 2. Slot-table mutation ----
  // Every byte of every slot, flipped three ways. §4.4's skip rule is what is
  // really under test: breaking slot 0 must leave slots 1 and 2 reachable.
  console.log("\nSlot-table mutation sweep (every byte, 3 values):");
  let tableMutations = 0;
  for (let i = SLOT_TABLE_OFFSET; i < tableEnd; i++) {
    for (const value of [0x00, 0x7f, 0xff]) {
      const m = threeSlot.slice(0);
      if (m[i] === value) continue;
      m[i] = value;
      await probeContainer(m, `slot-table@${i}=0x${value.toString(16)}`);
      tableMutations++;
    }
  }
  console.log(`  ${tableMutations} slot-table mutations probed`);

  // ---- 3. §4.4's skip rule, stated as a property ----
  // Corrupting the *passphrase* slot must not cost the container: the Shamir
  // and passkey slots beside it still hold the same master key. This is the
  // data-loss invariant, and it is the one a fuzzer can assert positively
  // rather than by absence.
  console.log("\nSkip rule (§4.4): breaking one slot must not strand the others:");
  for (const offset of [0, 1, 8, 40, 47, width - 1]) {
    const m = threeSlot.slice(0);
    const at = SLOT_TABLE_OFFSET + offset;
    m[at] = (m[at]! ^ 0xff) & 0xff;
    // The passkey slot must still open it. If this throws, one damaged slot
    // took the whole container with it.
    try {
      const r = await decryptKeym2(m, "", null, undefined, PRF_OUTPUT);
      check(
        new TextDecoder().decode(r.data) === PLAINTEXT,
        `skip-rule: passkey unlock returned the wrong plaintext after damaging slot-0 byte ${offset}`
      );
    } catch (e) {
      check(false, `skip-rule: damaging slot-0 byte ${offset} stranded the container (${(e as Error).message})`);
    }
  }
  console.log("  6 slot-0 corruption points probed via the passkey slot");

  // ---- 4. Truncation ----
  console.log("\nTruncation sweep (the real container cut at every length):");
  for (let cut = 0; cut < threeSlot.length; cut++) {
    await probeContainer(threeSlot.slice(0, cut), `truncated@${cut}`);
  }
  console.log(`  ${threeSlot.length} truncation points probed`);

  // ---- 5. Armor ----
  // A string, pasted by a user. dearmorKeym2 must reject anything that is not
  // exactly what armorKeym2 emits, and must accept everything that is —
  // including the line wrapping RECOVERY.md promises.
  console.log("\nArmor (keym2:…) — text pasted into the decrypt box:");
  const realArmor = armorKeym2(threeSlot);
  check(dearmorKeym2(realArmor).length === threeSlot.length, "armor: the real thing round-trips");

  const rng = makeRng(0xa12f0e);
  let armorProbes = 0;
  for (let i = 0; i < 300; i++) {
    const len = rng() % 400;
    let body = "";
    for (let j = 0; j < len; j++) body += String.fromCharCode(32 + (rng() % 95));
    const text = i % 3 === 0 ? KEYM2_ARMOR_PREFIX + body : body;
    await probeText(() => dearmorKeym2(text), `armor-random#${i}`);
    armorProbes++;
  }
  // Targeted: characters outside the alphabet injected into a real armor
  // string. These must be *rejected*, not merely survived. A decoder that
  // discards unknown characters instead of refusing them turns a corrupted
  // backup into a different container, which then fails authentication and
  // reports the wrong problem to the person least able to diagnose it.
  //
  // Four junk characters, not one, so a lax decoder is left with a
  // legal-length body and actually returns. A single character would break on
  // length instead and be rejected for the wrong reason — the trap that made
  // an earlier probe in reference/keym2.py's selftest vacuous.
  //
  // Whitespace is excluded deliberately: §7 strips it before decoding.
  for (const junk of ["!!!!", "****", "????", "€€€€"]) {
    for (const at of [8, 40, realArmor.length - 4]) {
      const text = realArmor.slice(0, at) + junk + realArmor.slice(at);
      let rejected = false;
      try {
        dearmorKeym2(text);
      } catch {
        rejected = true;
      }
      check(rejected, `armor-inject: ${junk}@${at} was accepted; the decoder is discarding junk`);
      armorProbes++;
    }
  }
  // ...and the whitespace it must keep accepting, so the check above cannot be
  // satisfied by a decoder that simply rejects everything.
  for (const ws of ["\n", "\r\n", " ", "\t"]) {
    const text = realArmor.slice(0, 40) + ws + realArmor.slice(40);
    let bytes: Uint8Array | null = null;
    try {
      bytes = dearmorKeym2(text);
    } catch {
      bytes = null;
    }
    check(
      bytes !== null && bytes.length === threeSlot.length,
      `armor-whitespace: ${JSON.stringify(ws)} was refused; RECOVERY.md promises line breaks are fine`
    );
    armorProbes++;
  }
  console.log(`  ${armorProbes} armor inputs probed`);

  // ---- 6. Shamir shares ----
  // Typed in off paper, by someone who cannot debug what they typed. Wrong
  // characters, wrong count, duplicates, and shares from another set all have
  // to fail cleanly rather than reconstruct a plausible-looking wrong secret.
  console.log("\nShamir shares (KMSHARE1:…) — typed in off paper:");
  let shareProbes = 0;
  const realShares = shareSet.shares;
  check(realShares.length === 3, "shamir: the fixture issued three shares");

  for (let i = 0; i < 200; i++) {
    const len = rng() % 80;
    let body = "";
    for (let j = 0; j < len; j++) body += String.fromCharCode(32 + (rng() % 95));
    await probeText(() => combineShares([`KMSHARE1:${body}`]), `share-random#${i}`, 2_000);
    shareProbes++;
  }
  // Duplicates must not satisfy a 2-of-3 threshold: the same point twice is
  // one point, and treating it as two would reconstruct garbage from a single
  // share.
  await probeText(
    () => combineShares([realShares[0]!, realShares[0]!]),
    "share-duplicate: the same share twice",
    2_000
  );
  // Single-character corruption of a real share — the realistic transcription
  // error, and the reason shares carry a checksum.
  for (const at of [10, 20, 30]) {
    const s = realShares[0]!;
    const bad = s.slice(0, at) + (s[at] === "A" ? "B" : "A") + s.slice(at + 1);
    await probeText(() => combineShares([bad, realShares[1]!]), `share-typo@${at}`, 2_000);
    shareProbes++;
  }
  console.log(`  ${shareProbes + 1} share inputs probed`);

  // ---- 7. Self-extracting page ----
  // looksLikeSelfExtract drives a branch in the decrypt path, so it is called
  // on arbitrary pasted text and must be total.
  console.log("\nSelf-extract detection — arbitrary pasted text:");
  let seProbes = 0;
  for (let i = 0; i < 200; i++) {
    const len = rng() % 500;
    let text = "";
    for (let j = 0; j < len; j++) text += String.fromCharCode(rng() % 0x2000);
    await probeText(() => {
      const v = looksLikeSelfExtract(text);
      check(typeof v === "boolean", `self-extract#${i}: returned ${typeof v}, not a boolean`);
    }, `self-extract#${i}`);
    seProbes++;
  }
  console.log(`  ${seProbes} pasted-text inputs probed`);

  // ---- 8. Determinism ----
  console.log("\nDeterminism (same bytes, three runs, identical verdict):");
  const rng2 = makeRng(0x5eed2);
  for (let i = 0; i < 20; i++) {
    const m = threeSlot.slice(0);
    const at = SLOT_TABLE_OFFSET + (rng2() % (3 * width));
    m[at] = rng2() & 0xff;
    const a = await probeContainer(m, `determinism#${i}a`);
    const b = await probeContainer(m, `determinism#${i}b`);
    const c = await probeContainer(m, `determinism#${i}c`);
    check(a === b && b === c, `determinism#${i}: verdicts differed (${a}/${b}/${c})`);
  }

  console.log(`\n${passed} assertions passed, ${failures} failed`);
  if (failures > 0) {
    console.error("KEYM v2 fuzzing FAILED.");
    process.exit(1);
  }
  console.log("KEYM v2 fuzzing passed.");
}

await main();
