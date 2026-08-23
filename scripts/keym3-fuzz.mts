/**
 * Fuzzer for the KEYM **v3** slot table.
 *
 * Run with:  npm run test:fuzz3
 *
 * `keym2-fuzz.mts` is pinned to v2 and stays that way: v2 containers remain
 * readable forever, so the surface that parses them has to keep being fuzzed.
 * But v3 is what the app writes now, and v3 moved every offset the v2 harness
 * knows — `slot_count` from 8 to 24, the table from 9 to 57, with a 16-byte
 * `container_id` and a 32-byte `slot_table_mac` in between. A harness aimed at
 * v2's offsets probes v3's *header* and calls it a slot table.
 *
 * ## What is new here, and why a fuzzer is the right shape for it
 *
 * v3's whole claim is one sentence: **if the slot table changed, the reader
 * says so.** That is a statement about every byte of a region, which is
 * exactly the kind of claim a hand-written test samples and a sweep settles.
 * `keymaker-regression.mts` checks four representative tampers — a strip, a
 * reorder, a flipped byte, a stripped slot 0. This checks all of them:
 *
 *   1. **Every byte the MAC covers, mutated.** If the container still opens,
 *      `slotTableAuthentic` MUST be `false`. A MAC that skipped a field would
 *      show up here as a mutation that opens and still reports `true`, and
 *      nowhere else.
 *   2. **Every byte of the MAC itself, mutated.** These must *all* still open
 *      — the MAC is in no AAD — and must *all* report `false`. §5.2 is
 *      report-don't-refuse, and a reader that started refusing would turn
 *      detectable tampering into a lost backup. That is the failure this
 *      project most wants not to ship, so it is asserted positively rather
 *      than inferred from an absence.
 *   3. **The write side.** v3 §5.3 step 2: a table that does not verify must
 *      not be re-sealed, because re-sealing mints a valid MAC over the
 *      attacker's table and destroys the evidence. Sampled rather than swept —
 *      enrolment costs an unwrap — but sampled across each mutation class.
 *
 * The v1 and v2 invariants still apply and are still checked: rejection is a
 * thrown Error, structural rejection is fast, the verdict is deterministic,
 * and a broken slot disqualifies itself rather than the container (§4.4).
 *
 * ## What this harness does *not* pin
 *
 * `slot_count`'s presence in the MAC input is not independently established
 * here, and cannot be. §5.1 hashes `core_header ‖ slot_count ‖ records`, but
 * `payload_offset` is derived from `slot_count` too — so every mutation of it
 * either fails to lay the container out at all, or moves a record as well and
 * would be caught by the record bytes alone. Only one of 256 values opens, and
 * that one is the original. A construction that dropped `slot_count` from the
 * hash would pass everything below.
 *
 * That coverage lives where it can: `reference/keym2.py`'s §8 test vector pins
 * the MAC and its intermediate `K_table` byte for byte, and `crosstest2.py`
 * pins the two implementations against each other. Said here rather than left
 * implied, because a sweep that looks exhaustive is the worst place for an
 * unstated hole.
 *
 * The generator is seeded, so a CI failure reproduces exactly.
 */
import {
  addPasskeySlotKeym2,
  addShamirSlotKeym2,
  decryptKeym2,
  encryptKeym2WithExplicitSecrets,
  inspectKeym2,
  isKeym2Binary,
  keym2SlotLen,
  KEYM2_MAX_SLOTS,
  KEYM2_VERSION_V3,
} from "../src/lib/keym-v2.ts";
import { CipherId, KdfId } from "../src/lib/keymaker-crypto.ts";

const PASSWORD = "fuzz-harness-password-not-a-secret-0000";
const PRF_OUTPUT = new Uint8Array(32).fill(0x5a);
const PASSKEY_SALT = new Uint8Array(32).fill(0x3c);
const FIXED_SALT = new Uint8Array(32).fill(0x11);
const FIXED_MASTER_KEY = new Uint8Array(32).fill(0x22);
const FIXED_CONTAINER_ID = new Uint8Array(16).fill(0x66);
const SHAMIR_SALT = new Uint8Array(32).fill(0x33);
const SHARE_SECRET = new Uint8Array(32).fill(0x44);
const SHAMIR_COEFFS = new Uint8Array(32).fill(0x55);

/**
 * v3 §3 offsets. Mirrored, not imported, for the reason the v2 harness gives
 * and then demonstrated: these are module-private, and a fuzzer that imported
 * them would follow the layout wherever it moved instead of noticing that it
 * had. When the default writer flipped to v3, the v2 harness failed loudly on
 * its own mirrored constants before a single probe ran. That is the mechanism
 * working, and it only works if the numbers are written here.
 */
const CORE_HEADER_LEN = 24;
const CONTAINER_ID_OFFSET = 8;
const CONTAINER_ID_LEN = 16;
const SLOT_COUNT_OFFSET = 24;
const SLOT_TABLE_MAC_OFFSET = 25;
const SLOT_TABLE_MAC_LEN = 32;
const SLOT_TABLE_OFFSET = 57;

const PARSE_REJECT_MS = 750;
const KDF_BOUND_MS = 40_000;

let failures = 0;
let passed = 0;
function check(condition: boolean, label: string) {
  if (condition) {
    passed++;
    return;
  }
  failures++;
  console.log(`  FAIL ${label}`);
}

/** xorshift32. Seeded so a CI failure reproduces exactly. */
function makeRng(seed: number) {
  let s = seed >>> 0 || 1;
  return () => {
    s ^= s << 13;
    s >>>= 0;
    s ^= s >>> 17;
    s ^= s << 5;
    s >>>= 0;
    return s;
  };
}

const FAST = {
  kdf: { kdf: KdfId.PBKDF2, params: { iterations: 600_000 } },
  cipher: CipherId.AES_256_GCM,
} as const;

const PLAINTEXT = "fuzz plaintext, v3";

type Outcome = {
  kind: "success" | "error" | "non-error-throw" | "inspect-threw";
  /** §5.2's third value. `null` for a v2 container, and for anything that did
   *  not open — nothing is claimed about a table nobody could check. */
  authentic: boolean | null;
};

/** Could this blob's slot table be laid out at all? v3's arithmetic, which is
 *  the line between "must be microseconds" and "may derive a key". */
function laidOut(b: Uint8Array): boolean {
  if (b.length < SLOT_TABLE_OFFSET) return false;
  if (b[4] !== KEYM2_VERSION_V3) return false;
  const count = b[SLOT_COUNT_OFFSET] as number;
  if (count < 1 || count > KEYM2_MAX_SLOTS) return false;
  const cipher = b[6] as number;
  if (
    cipher !== CipherId.AES_256_GCM &&
    cipher !== CipherId.CHACHA20_POLY1305 &&
    cipher !== CipherId.CHAINED
  ) {
    return false;
  }
  return b.length >= SLOT_TABLE_OFFSET + count * keym2SlotLen(cipher);
}

/**
 * Feed one blob to the v3 decrypt path and assert the invariants.
 *
 * As in the v2 harness, a success is not itself a finding: §4.4 requires a
 * damaged slot to disqualify only itself, so opening a deformed container
 * through an untouched slot is specified behaviour. What must hold is tighter
 * — a mutation either fails cleanly or returns *exactly* the sealed plaintext.
 *
 * The v3 addition is the third return value. Whether the table authenticated
 * is not checked here, because whether it *should* have depends on which
 * bytes the caller moved; the sweeps assert it, each against its own
 * expectation.
 */
async function probe(bytes: Uint8Array, label: string): Promise<Outcome> {
  // Total by contract: this drives a label in the decrypt panel and is called
  // on whatever was pasted, so it returns null rather than throwing.
  try {
    inspectKeym2(bytes);
  } catch (e) {
    check(false, `${label}: inspectKeym2 threw (${(e as Error).message})`);
    return { kind: "inspect-threw", authentic: null };
  }
  // Same contract, and the sniffer v3 was briefly invisible to: it compared
  // byte 4 against a single version.
  try {
    isKeym2Binary(bytes);
  } catch (e) {
    check(false, `${label}: isKeym2Binary threw (${(e as Error).message})`);
    return { kind: "inspect-threw", authentic: null };
  }

  const started = process.hrtime.bigint();
  let out: Outcome;
  let message = "";
  try {
    const result = await decryptKeym2(bytes, PASSWORD, null);
    const text = new TextDecoder().decode(result.data);
    check(
      text === PLAINTEXT,
      `${label}: decrypt succeeded but returned ${result.data.length} bytes that are not the ` +
        `plaintext — authenticated something that is not what was sealed`
    );
    out = { kind: "success", authentic: result.slotTableAuthentic };
  } catch (e) {
    message = e instanceof Error ? e.message : String(e);
    check(e instanceof Error, `${label}: threw a non-Error value (${String(e)})`);
    out = { kind: e instanceof Error ? "error" : "non-error-throw", authentic: null };
  }
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

  const budget = laidOut(bytes) ? KDF_BOUND_MS : PARSE_REJECT_MS;
  check(
    elapsedMs < budget,
    `${label}: ${elapsedMs.toFixed(1)}ms exceeds the ${
      budget === PARSE_REJECT_MS ? "parse" : "KDF"
    } budget of ${budget}ms (error=${message.slice(0, 70)})`
  );
  return out;
}

/**
 * v3 §5.3 step 2, as a property rather than as four examples.
 *
 * Enrolling on a table that does not verify must be refused. The attack it
 * closes is the strip finished by the victim: the owner is the one person who
 * can still open a container whose heir slot was removed, so the owner is the
 * one whose next enrolment re-seals the attacker's table with the real key.
 */
async function enrolmentIsRefused(bytes: Uint8Array, label: string): Promise<void> {
  for (const [what, run] of [
    ["passkey", () => addPasskeySlotKeym2(bytes, { password: PASSWORD, keyFile: null },
      PRF_OUTPUT, PASSKEY_SALT)],
    ["shares", () => addShamirSlotKeym2(bytes, { password: PASSWORD, keyFile: null }, 2, 3)],
  ] as const) {
    let refused = false;
    try {
      await run();
    } catch {
      refused = true;
    }
    check(refused, `${label}: enrolling a ${what} on a table that does not verify was allowed (§5.3)`);
  }
}

async function main() {
  console.log("\nKEYM v3 fuzzing\n");

  console.log("Building a three-slot v3 container (passphrase + shamir + passkey)…");
  const plaintext = new TextEncoder().encode(PLAINTEXT);
  // Every secret pinned, including `container_id` — which is new in v3 and is
  // drawn from the CSPRNG by default, so leaving it unpinned would make the
  // fixture differ every run and the assertion count drift with it. That is
  // the same trap the v2 harness hit with the salt and the master key.
  const oneSlot = await encryptKeym2WithExplicitSecrets(
    plaintext, PASSWORD, null, FAST, FIXED_SALT, FIXED_MASTER_KEY,
    KEYM2_VERSION_V3, FIXED_CONTAINER_ID
  );
  const shareSet = await addShamirSlotKeym2(
    oneSlot, { password: PASSWORD, keyFile: null }, 2, 3,
    { salt: SHAMIR_SALT, shareSecret: SHARE_SECRET, coefficients: SHAMIR_COEFFS }
  );
  const threeSlot = await addPasskeySlotKeym2(
    shareSet.container, { password: PASSWORD, keyFile: null }, PRF_OUTPUT, PASSKEY_SALT
  );

  const rebuilt = await encryptKeym2WithExplicitSecrets(
    plaintext, PASSWORD, null, FAST, FIXED_SALT, FIXED_MASTER_KEY,
    KEYM2_VERSION_V3, FIXED_CONTAINER_ID
  );
  check(
    rebuilt.length === oneSlot.length && rebuilt.every((b, i) => b === oneSlot[i]),
    "fixture: two builds from the same pinned secrets differ — this harness is not reproducible"
  );

  const width = keym2SlotLen(CipherId.AES_256_GCM);
  const tableEnd = SLOT_TABLE_OFFSET + 3 * width;
  console.log(
    `  ${threeSlot.length} bytes, slot width ${width}, ` +
      `mac [${SLOT_TABLE_MAC_OFFSET}, ${SLOT_TABLE_MAC_OFFSET + SLOT_TABLE_MAC_LEN}), ` +
      `table [${SLOT_TABLE_OFFSET}, ${tableEnd})`
  );

  // The layout the mirrored constants claim, checked against the container the
  // library actually produced. Every sweep below indexes by these numbers, so
  // if they are wrong the sweeps probe the wrong bytes and pass while testing
  // nothing.
  check(threeSlot[4] === KEYM2_VERSION_V3, "layout: the fixture declares version 3");
  check(threeSlot[SLOT_COUNT_OFFSET] === 3, "layout: slot_count is at offset 24 and reads 3");
  check(
    threeSlot.length === SLOT_TABLE_OFFSET + 3 * width + (oneSlot.length - SLOT_TABLE_OFFSET - width),
    "layout: payload starts at 57 + slot_count × slot_len"
  );
  check(
    FIXED_CONTAINER_ID.length === CONTAINER_ID_LEN &&
      FIXED_CONTAINER_ID.every((b, i) => threeSlot[CONTAINER_ID_OFFSET + i] === b),
    "layout: container_id is 16 bytes at offset 8, and survived two enrolments"
  );

  // Baseline. Every "rejected" below is vacuous without it, and so is every
  // "reported": a harness whose fixture already fails its own MAC would find
  // tampering everywhere.
  const good = await probe(threeSlot, "baseline");
  check(good.kind === "success", "baseline: the unmutated v3 container opens");
  check(
    good.authentic === true,
    "baseline: the unmutated v3 container reports an authentic table"
  );

  // ---- 1. slot_table_mac: report, do not refuse (§5.2) ----
  //
  // The MAC is in no AAD — it cannot be, since enrolment rewrites it without
  // touching the payload — so every one of these still opens. Both halves are
  // asserted: the plaintext comes back, *and* the table is reported. A reader
  // that refused here would satisfy neither, and refusing is the tempting
  // mistake: it feels safer and it costs someone their backup.
  console.log("\nslot_table_mac sweep (every byte, 3 values — §5.2 report-don't-refuse):");
  let macMutations = 0;
  for (let i = SLOT_TABLE_MAC_OFFSET; i < SLOT_TABLE_MAC_OFFSET + SLOT_TABLE_MAC_LEN; i++) {
    for (const value of [0x00, 0x7f, 0xff]) {
      const m = threeSlot.slice(0);
      if (m[i] === value) continue;
      m[i] = value;
      const r = await probe(m, `mac@${i}=0x${value.toString(16)}`);
      check(
        r.kind === "success",
        `mac@${i}=0x${value.toString(16)}: a wrong MAC refused the plaintext — §5.2 says report, ` +
          `not refuse; refusing converts detectable tampering into a lost backup`
      );
      check(
        r.authentic === false,
        `mac@${i}=0x${value.toString(16)}: opened and reported authentic=${r.authentic}, ` +
          `but the stored MAC was changed`
      );
      macMutations++;
    }
  }
  console.log(`  ${macMutations} MAC mutations probed, all expected to open and all to report`);

  // ---- 2. slot_count, still the field in no payload AAD ----
  //
  // v3 moved it to 24 and brought it under the MAC. So the pre-v3 behaviour
  // holds — every value lays the table out or is refused, none hangs — and one
  // thing is added: any value that still opens must report a changed table,
  // because the count is the first thing the MAC covers after the header.
  console.log("\nslot_count sweep (0..255 at offset 24 — now covered by the MAC):");
  let countOpened = 0;
  for (let n = 0; n <= 255; n++) {
    const m = threeSlot.slice(0);
    m[SLOT_COUNT_OFFSET] = n;
    const r = await probe(m, `slot_count=${n}`);
    if (r.kind !== "success") continue;
    countOpened++;
    if (n === 3) {
      check(r.authentic === true, "slot_count=3: unchanged, so the table must still authenticate");
    } else {
      check(
        r.authentic === false,
        `slot_count=${n}: opened and reported authentic=${r.authentic} — the count the MAC ` +
          `covers was changed`
      );
    }
  }
  console.log(`  256 slot_count values probed, ${countOpened} of them opened`);

  // ---- 3. Every byte of the slot table ----
  //
  // The sweep the whole revision exists for. Mutating a slot the password does
  // not use leaves the container openable through slot 0, and every one of
  // those opens MUST report. A MAC that covered only the prefixes, or only the
  // first record, or hashed the records as a set, would pass the four examples
  // in keymaker-regression.mts and fail somewhere in here.
  console.log("\nSlot-table mutation sweep (every byte, 3 values — every open must report):");
  let tableMutations = 0;
  let tableOpened = 0;
  for (let i = SLOT_TABLE_OFFSET; i < tableEnd; i++) {
    for (const value of [0x00, 0x7f, 0xff]) {
      const m = threeSlot.slice(0);
      if (m[i] === value) continue;
      m[i] = value;
      const r = await probe(m, `table@${i}=0x${value.toString(16)}`);
      tableMutations++;
      if (r.kind !== "success") continue;
      tableOpened++;
      check(
        r.authentic === false,
        `table@${i}=0x${value.toString(16)}: opened and reported authentic=${r.authentic}, ` +
          `so byte ${i - SLOT_TABLE_OFFSET} of the table is outside the MAC`
      );
    }
  }
  console.log(
    `  ${tableMutations} slot-table mutations probed, ${tableOpened} opened — all reported`
  );

  // ---- 4. Slot removal, at every position ----
  //
  // §1.1's attack, run three ways rather than once. Each must still return the
  // plaintext to whoever holds a surviving slot, and each must report.
  console.log("\nSlot removal (§1.1 — the attack v3 exists to detect):");
  for (let victim = 0; victim < 3; victim++) {
    const at = SLOT_TABLE_OFFSET + victim * width;
    const m = new Uint8Array(threeSlot.length - width);
    m.set(threeSlot.subarray(0, at), 0);
    m.set(threeSlot.subarray(at + width), at);
    m[SLOT_COUNT_OFFSET] = 2;
    // Slot 0 is the passphrase slot; with it gone the passkey is the way in.
    const r =
      victim === 0
        ? await (async () => {
            try {
              const d = await decryptKeym2(m, "", null, undefined, PRF_OUTPUT);
              return { kind: "success" as const, authentic: d.slotTableAuthentic };
            } catch {
              return { kind: "error" as const, authentic: null };
            }
          })()
        : await probe(m, `strip-slot-${victim}`);
    check(r.kind === "success", `strip-slot-${victim}: a surviving slot no longer opens it (§5.2)`);
    check(
      r.authentic === false,
      `strip-slot-${victim}: opened and reported authentic=${r.authentic} — a removed slot is ` +
        `the thing this format was revised to notice`
    );
  }
  console.log("  3 removal positions probed");

  // ---- 5. Reordering ----
  //
  // Inert as an attack: the unlock walk tries every slot. Which is exactly why
  // it is worth sweeping — the MAC has to notice a change that changes nothing,
  // and a construction that hashed the records as a set rather than a sequence
  // would sail past everything above.
  console.log("\nSlot reordering (inert as an attack, which is why it is checked):");
  for (const [a, b] of [[0, 1], [0, 2], [1, 2]] as const) {
    const m = threeSlot.slice(0);
    const A = threeSlot.subarray(SLOT_TABLE_OFFSET + a * width, SLOT_TABLE_OFFSET + (a + 1) * width);
    const B = threeSlot.subarray(SLOT_TABLE_OFFSET + b * width, SLOT_TABLE_OFFSET + (b + 1) * width);
    m.set(B, SLOT_TABLE_OFFSET + a * width);
    m.set(A, SLOT_TABLE_OFFSET + b * width);
    const r = await probe(m, `swap-${a}-${b}`);
    check(r.kind === "success", `swap-${a}-${b}: reordering must not cost the container`);
    check(
      r.authentic === false,
      `swap-${a}-${b}: opened and reported authentic=${r.authentic} — the MAC is order-blind, ` +
        `so it is hashing the records as a set`
    );
  }
  console.log("  3 reorderings probed");

  // ---- 6. The core header, including container_id ----
  //
  // Everything here is in the payload AAD as well as the MAC, so these are
  // expected to fail closed rather than to open and report. They are swept for
  // the v1 invariants: clean rejection, no hang, and a structural refusal that
  // never reaches a KDF.
  console.log("\nCore-header sweep (24 bytes, 3 values — expected to fail closed):");
  let headerMutations = 0;
  let headerOpened = 0;
  for (let i = 0; i < CORE_HEADER_LEN; i++) {
    for (const value of [0x00, 0x7f, 0xff]) {
      const m = threeSlot.slice(0);
      if (m[i] === value) continue;
      m[i] = value;
      const r = await probe(m, `header@${i}=0x${value.toString(16)}`);
      headerMutations++;
      if (r.kind !== "success") continue;
      headerOpened++;
      // If one does open, the MAC still has to have noticed: the core header
      // is its first input.
      check(
        r.authentic === false,
        `header@${i}=0x${value.toString(16)}: opened and reported authentic=${r.authentic}`
      );
    }
  }
  console.log(
    `  ${headerMutations} core-header mutations probed, ${headerOpened} opened` +
      `${headerOpened ? " — all reported" : " (all failed closed, as expected)"}`
  );

  // ---- 7. Truncation ----
  console.log("\nTruncation sweep (the real container cut at every length):");
  for (let cut = 0; cut < threeSlot.length; cut++) {
    await probe(threeSlot.slice(0, cut), `truncated@${cut}`);
  }
  console.log(`  ${threeSlot.length} truncation points probed`);

  // ---- 8. Random bytes at v3's offsets ----
  //
  // Structurally plausible garbage: real magic, real version, random
  // everything else. These reach further into the parser than pure noise does,
  // which is the point.
  console.log("\nStructured random containers (real magic and version, random body):");
  const rng = makeRng(0x3ce7a1);
  for (let i = 0; i < 400; i++) {
    const len = SLOT_TABLE_OFFSET + (rng() % 400);
    const m = new Uint8Array(len);
    for (let j = 0; j < len; j++) m[j] = rng() & 0xff;
    m[0] = 0x4b; m[1] = 0x45; m[2] = 0x59; m[3] = 0x4d; // "KEYM"
    m[4] = KEYM2_VERSION_V3;
    await probe(m, `structured-random#${i}`);
  }
  console.log("  400 structured random containers probed");

  // ---- 9. The write side (§5.3 step 2) ----
  //
  // Sampled, not swept: each enrolment unwraps the master key, which is a
  // PBKDF2 run. One representative from each mutation class is enough to catch
  // a guard that was removed, and a sweep here would cost minutes to learn the
  // same thing.
  console.log("\nEnrolment on a table that does not verify (§5.3 step 2):");
  const stripped = new Uint8Array(threeSlot.length - width);
  stripped.set(threeSlot.subarray(0, SLOT_TABLE_OFFSET + 2 * width), 0);
  stripped.set(threeSlot.subarray(SLOT_TABLE_OFFSET + 3 * width), SLOT_TABLE_OFFSET + 2 * width);
  stripped[SLOT_COUNT_OFFSET] = 2;

  const macFlipped = threeSlot.slice(0);
  macFlipped[SLOT_TABLE_MAC_OFFSET] = (macFlipped[SLOT_TABLE_MAC_OFFSET]! ^ 0xff) & 0xff;

  const swapped = threeSlot.slice(0);
  swapped.set(
    threeSlot.subarray(SLOT_TABLE_OFFSET + width, SLOT_TABLE_OFFSET + 2 * width),
    SLOT_TABLE_OFFSET
  );
  swapped.set(
    threeSlot.subarray(SLOT_TABLE_OFFSET, SLOT_TABLE_OFFSET + width),
    SLOT_TABLE_OFFSET + width
  );

  for (const [label, bytes] of [
    ["stripped", stripped],
    ["mac-flipped", macFlipped],
    ["reordered", swapped],
  ] as const) {
    // Precondition, or the refusal below could be for any reason at all.
    const r = await probe(bytes, `write-side/${label}`);
    check(
      r.kind === "success" && r.authentic === false,
      `write-side/${label}: the fixture is not the case it claims to be ` +
        `(kind=${r.kind}, authentic=${r.authentic})`
    );
    await enrolmentIsRefused(bytes, `write-side/${label}`);
  }
  // ...and the other side of it, so the checks above cannot be satisfied by an
  // implementation that simply refuses every enrolment.
  let enrolled = false;
  try {
    const grown = await addPasskeySlotKeym2(
      shareSet.container, { password: PASSWORD, keyFile: null }, PRF_OUTPUT, PASSKEY_SALT
    );
    const r = await probe(grown, "write-side/intact");
    enrolled = r.kind === "success" && r.authentic === true;
  } catch {
    enrolled = false;
  }
  check(enrolled, "write-side/intact: an untouched table must still accept an enrolment");
  console.log("  3 tampered tables and 1 intact one probed");

  // ---- 10. Determinism ----
  //
  // Same bytes, same verdict. A parser that reached a nondeterministic
  // decision — an uninitialised read, a time-dependent branch — would make
  // every result above unreproducible and every CI failure unfixable.
  console.log("\nDeterminism (same bytes twice, same verdict):");
  for (const at of [SLOT_COUNT_OFFSET, SLOT_TABLE_MAC_OFFSET + 7, SLOT_TABLE_OFFSET + 3, tableEnd - 1]) {
    const m = threeSlot.slice(0);
    m[at] = (m[at]! ^ 0xff) & 0xff;
    const first = await probe(m, `determinism@${at}#1`);
    const second = await probe(m, `determinism@${at}#2`);
    check(
      first.kind === second.kind && first.authentic === second.authentic,
      `determinism@${at}: ${first.kind}/${first.authentic} then ${second.kind}/${second.authentic}`
    );
  }
  console.log("  4 byte positions probed twice each");

  console.log(`\n${passed} assertions passed, ${failures} failed`);
  if (failures) {
    console.log("KEYM v3 FUZZING FAILED — do not ship.");
    process.exit(1);
  }
  console.log("KEYM v3 fuzzing passed.");
}

await main();
