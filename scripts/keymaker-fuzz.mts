/**
 * Fuzzer for the KEYM container parser.
 *
 * Run with:  npm run test:fuzz
 *
 * parseKeym() and detectFormat() consume fully attacker-controlled binary: a
 * `.keym` file or a pasted base64 blob arrives before anything about it has
 * been authenticated. The AEAD tag can only be checked after a key has been
 * derived using parameters the input itself supplied, so every byte ahead of
 * that point is hostile until proven otherwise.
 *
 * The properties asserted here are the ones that matter for that position in
 * the pipeline:
 *
 *   1. Rejection is by thrown Error — never a crash, never a hang, and never a
 *      silent success on garbage.
 *   2. Rejection is fast. A malformed header must not cause an expensive key
 *      derivation, so every case is timed. This is what caught KM-01: hostile
 *      cost parameters were being executed before authentication could reject
 *      them.
 *   3. Rejection is deterministic. The same bytes always produce the same
 *      verdict — no dependence on allocation order or timing.
 *   4. No plaintext is ever returned for input that fails authentication.
 *
 * The generator is seeded and fully deterministic, so a CI failure reproduces
 * exactly. Math.random() is deliberately not used.
 */
import { decryptData, detectFormat, encryptData, CipherId, KdfId } from "../src/lib/keymaker-crypto.ts";

const PASSWORD = "fuzz-harness-password-not-a-secret-0000";

/**
 * Two different timing bars, because there are two different rejections.
 *
 * A *parse-level* rejection — bad magic, unknown id, out-of-range cost
 * parameter, truncated header — is pure byte inspection and must complete in
 * microseconds. It must never reach a KDF. That is the KM-01 invariant, and
 * PARSE_REJECT_MS enforces it.
 *
 * An *authentication* failure is different: the header was structurally valid
 * and in range, so a key genuinely had to be derived before the tag could be
 * checked. That work is real and is supposed to cost something.
 *
 * Which means the honest statement of what bounding the parameters bought is
 * not "hostile files are free" but "hostile files cost no more than the most
 * expensive setting a real user could have chosen". KDF_BOUND_MS asserts that
 * ceiling exists. Anything slower means a parameter escaped its bound.
 */
const PARSE_REJECT_MS = 750;
const KDF_BOUND_MS = 30_000;

let failures = 0;
let passed = 0;
function check(condition: boolean, label: string) {
  if (condition) {
    passed++;
  } else {
    failures++;
    console.error(`  FAIL  ${label}`);
  }
}

/** xorshift32 — small, deterministic, and seedable. */
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

const KEYM = [0x4b, 0x45, 0x59, 0x4d];

/**
 * Feed one blob to the parser and assert the invariants. Returns the outcome
 * so callers can check determinism by running the same bytes twice.
 */
async function probe(bytes: Uint8Array, label: string): Promise<string> {
  const buf = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;

  // detectFormat must be total: it classifies bytes and must never throw.
  let detected = "";
  try {
    detected = detectFormat(bytes);
  } catch (e) {
    check(false, `${label}: detectFormat threw (${(e as Error).message})`);
    return "detect-threw";
  }

  const started = process.hrtime.bigint();
  let outcome: string;
  let message = "";
  try {
    const result = await decryptData(buf, PASSWORD, null);
    // Succeeding on fuzz input would mean we authenticated random bytes.
    check(false, `${label}: decrypt SUCCEEDED on fuzz input (${result.data.byteLength} bytes)`);
    outcome = "success";
  } catch (e) {
    outcome = e instanceof Error ? "error" : "non-error-throw";
    message = e instanceof Error ? e.message : String(e);
    check(e instanceof Error, `${label}: threw a non-Error value`);
  }
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

  // Errors raised by inspecting bytes, before any key derivation.
  const isParseRejection =
    /Invalid KEYM|out of range|too short|unknown KDF|unknown cipher|newer KEYM|too large|must be an integer/i.test(
      message
    );
  const budget = isParseRejection ? PARSE_REJECT_MS : KDF_BOUND_MS;
  check(
    elapsedMs < budget,
    `${label}: ${elapsedMs.toFixed(1)}ms exceeds the ${
      isParseRejection ? "parse" : "KDF"
    } budget of ${budget}ms (detected=${detected}, error=${message.slice(0, 70)})`
  );
  return outcome;
}

async function main() {
  console.log("\nKEYM parser fuzzing\n");

  // ---- 1. Structured hostile headers ----
  // Every combination of version, kdf id and cipher id, including the invalid
  // ones, with maximal cost parameters. This is the shape of an attack: a
  // syntactically plausible header carrying absurd instructions.
  console.log("Structured headers (version x kdf x cipher x extreme params):");
  let structured = 0;
  for (const version of [0, 1, 2, 0xff]) {
    for (const kdfId of [0, 1, 2, 0xff]) {
      for (const cipherId of [0, 1, 2, 3, 0xff]) {
        for (const extreme of [0x00, 0xff]) {
          const body = new Uint8Array(160).fill(extreme);
          body.set(KEYM, 0);
          body[4] = version;
          body[5] = kdfId;
          body[6] = cipherId;
          await probe(body, `v${version}/kdf${kdfId}/cipher${cipherId}/fill${extreme}`);
          structured++;
        }
      }
    }
  }
  console.log(`  ${structured} structured headers probed`);

  // ---- 2. Truncation at every byte ----
  // A real container cut short at each possible length. Off-by-one reads and
  // unchecked slices surface here.
  console.log("\nTruncation sweep (a real container cut at every length):");
  const real = new Uint8Array(
    await encryptData(new TextEncoder().encode("fuzz plaintext").buffer as ArrayBuffer, PASSWORD, null, {
      kdf: { kdf: KdfId.PBKDF2, params: { iterations: 600_000 } },
      cipher: CipherId.CHAINED,
    })
  );
  // Strictly shorter than the real thing — the untruncated container is valid
  // and is supposed to decrypt.
  for (let cut = 0; cut < real.length; cut++) {
    await probe(real.slice(0, cut), `truncated@${cut}`);
  }
  console.log(`  ${real.length} truncation points probed (full length ${real.length})`);

  // ---- 3. Single-byte mutation of every header position ----
  console.log("\nHeader mutation sweep (each byte flipped to 0x00, 0x7f, 0xff):");
  let mutations = 0;
  for (let i = 0; i < Math.min(real.length, 96); i++) {
    for (const value of [0x00, 0x7f, 0xff]) {
      const m = real.slice(0);
      if (m[i] === value) continue;
      m[i] = value;
      await probe(m, `mutate@${i}=0x${value.toString(16)}`);
      mutations++;
    }
  }
  console.log(`  ${mutations} single-byte mutations probed`);

  // ---- 4. Pseudo-random blobs ----
  console.log("\nRandom blobs (seeded, deterministic):");
  const rng = makeRng(0xc0ffee);
  let random = 0;
  for (let i = 0; i < 400; i++) {
    const len = rng() % 300;
    const b = new Uint8Array(len);
    for (let j = 0; j < len; j++) b[j] = rng() & 0xff;
    // Half the time, force the magic so the KEYM path is exercised rather
    // than being dismissed instantly as a legacy blob.
    if (i % 2 === 0 && len >= 8) b.set(KEYM, 0);
    await probe(b, `random#${i}(len=${len})`);
    random++;
  }
  console.log(`  ${random} random blobs probed`);

  // ---- 5. Determinism ----
  // The same bytes must yield the same verdict every time.
  console.log("\nDeterminism (same bytes, three runs, identical verdict):");
  const rng2 = makeRng(0x5eed);
  for (let i = 0; i < 25; i++) {
    const len = 8 + (rng2() % 200);
    const b = new Uint8Array(len);
    for (let j = 0; j < len; j++) b[j] = rng2() & 0xff;
    b.set(KEYM, 0);
    const a1 = await probe(b, `determinism#${i}a`);
    const a2 = await probe(b, `determinism#${i}b`);
    const a3 = await probe(b, `determinism#${i}c`);
    check(a1 === a2 && a2 === a3, `determinism#${i}: verdicts differed (${a1}/${a2}/${a3})`);
  }

  console.log(`\n${passed} assertions passed, ${failures} failed`);
  if (failures > 0) {
    console.error("Parser fuzzing FAILED.");
    process.exit(1);
  }
  console.log("Parser fuzzing passed.");
}

await main();
