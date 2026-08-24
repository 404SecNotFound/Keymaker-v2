/**
 * Version dispatch: does `decryptData()` route v2 to v2 and leave v1 alone?
 *
 * `reference/crosstest2.py` deliberately drives `decryptKeym2` directly, so a
 * failure there points at the format code rather than at the routing. This
 * file tests the other half — the public entry point — because that is where a
 * regression would actually reach a user, and because "v1 must remain readable
 * exactly as it is today" (FORMAT-V2-DESIGN §preamble) is a claim about
 * `decryptData`, not about the v2 module.
 *
 * The frozen fixtures in scripts/fixtures/keymaker/ are the strongest form of
 * that claim and are already checked by `npm run test:keymaker`. What is new
 * here is that adding a second version to the dispatch cannot quietly send a
 * v1 container down the v2 path, or a truncated one down the legacy path.
 */
import { webcrypto } from "node:crypto";
import {
  CipherId,
  KdfId,
  decryptData,
  detectFormat,
  MAX_CONTAINER_SIZE,
  oversizeRecoveryHelp,
  encryptData,
  type KdfParams,
} from "../src/lib/keymaker-crypto.ts";
import {
  KEYM2_ARMOR_PREFIX,
  KEYM2_CORE_HEADER_LEN,
  armorKeym2,
  dearmorKeym2,
  encryptKeym2,
  KEYM2_VERSION_V2,
  KEYM2_HEADER_PEEK_BYTES,
  KEYM2_MAX_SLOTS,
  KEYM2_VERSION_V3,
  keym2SlotCountOffset,
  keym2SlotTableOffset,
  isKeym2Binary,
  keym2SlotLen,
  keym2UnlockCost,
  describeUnlockCost,
  UNLOCK_COST_NOTICE_THRESHOLD,
} from "../src/lib/keym-v2.ts";

if (!globalThis.crypto) {
  (globalThis as { crypto?: Crypto }).crypto = webcrypto as unknown as Crypto;
}

let passed = 0;
const failures: string[] = [];

function check(ok: boolean, label: string, detail = ""): void {
  if (ok) {
    passed++;
    console.log(`  ok   ${label}`);
  } else {
    failures.push(label);
    console.log(`  FAIL ${label}${detail ? `   ${detail}` : ""}`);
  }
}

async function expectReject(label: string, fn: () => Promise<unknown>): Promise<void> {
  try {
    await fn();
    check(false, label, "no error raised");
  } catch {
    check(true, label);
  }
}

const PASSWORD = "correct horse battery staple — dispatch ✅";
const FAST: KdfParams = { kdf: KdfId.PBKDF2, params: { iterations: 600_000 } };
const enc = new TextEncoder();
const dec = new TextDecoder();

function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer;
}

console.log("\nKEYM version dispatch\n");

// --- detectFormat separates the versions on byte 4 ---------------------------
const v1 = new Uint8Array(await encryptData(toArrayBuffer(enc.encode("v1 payload")), PASSWORD, null, {
  kdf: FAST,
  cipher: CipherId.AES_256_GCM,
}));
const v2 = await encryptKeym2(
  enc.encode("v2 payload"),
  PASSWORD,
  null,
  { kdf: FAST, cipher: CipherId.AES_256_GCM },
  KEYM2_VERSION_V2
);

const v3 = await encryptKeym2(
  enc.encode("v3 payload"),
  PASSWORD,
  null,
  { kdf: FAST, cipher: CipherId.AES_256_GCM },
  KEYM2_VERSION_V3
);

check(detectFormat(v1) === "keym-v1", "a v1 container is detected as v1");
check(detectFormat(v2) === "keym-v2", "a v2 container is detected as v2");
// v3 §6, and the reason this classifier had to learn a third name. While it
// answered "keym-v1" for byte 3, `decryptData` sent a container the v2 parser
// understood perfectly to the v1 path, which rejected it as "a newer KEYM
// version" — a reader refusing a format it had already implemented.
check(detectFormat(v3) === "keym-v3", "a v3 container is detected as v3");
check(!isKeym2Binary(v1), "isKeym2Binary rejects v1");
check(isKeym2Binary(v2), "isKeym2Binary accepts v2");

// An unknown version must not fall through to the headerless legacy path,
// where it would cost a million PBKDF2 iterations before failing.
const v9 = Uint8Array.from(v2);
v9[4] = 9;
check(detectFormat(v9) === "keym-v1", "an unknown version stays in the KEYM family");

// --- decryptData routes each version to the right implementation ------------
const openedV1 = await decryptData(toArrayBuffer(v1), PASSWORD, null);
check(dec.decode(openedV1.data) === "v1 payload", "decryptData still opens v1");
check(openedV1.format === "keym-v1", "decryptData reports v1");

const openedV2 = await decryptData(toArrayBuffer(v2), PASSWORD, null);
check(dec.decode(openedV2.data) === "v2 payload", "decryptData opens v2 through the dispatch");
check(openedV2.format === "keym-v2", "decryptData reports v2");

const openedV3 = await decryptData(toArrayBuffer(v3), PASSWORD, null);
check(dec.decode(openedV3.data) === "v3 payload", "decryptData opens v3 through the dispatch");
check(openedV3.format === "keym-v3", "decryptData reports v3");

// v3 §5.2 travels with the plaintext or it is not a report. Two containers that
// have never been touched, and the verdict distinguishes "sealed and intact"
// from "carries no seal at all" rather than collapsing both to a passing
// boolean — a `null` read as falsy would accuse every v1 and v2 backup of
// tampering, and a `null` read as truthy would clear a stripped v3 one.
check(openedV3.slotTableAuthentic === true, "decryptData reports a v3 slot table as authentic");
check(openedV2.slotTableAuthentic === null, "decryptData claims nothing about a v2 slot table");
check(openedV1.slotTableAuthentic === null, "decryptData claims nothing about a v1 slot table");

// --- the key-file flag survives the dispatch --------------------------------
const keyFile = new Uint8Array(64).fill(7);
const v2k = await encryptKeym2(enc.encode("with a key file"), PASSWORD, keyFile, {
  kdf: FAST,
  cipher: CipherId.CHAINED,
});
const openedV2k = await decryptData(toArrayBuffer(v2k), PASSWORD, toArrayBuffer(keyFile));
check(dec.decode(openedV2k.data) === "with a key file", "v2 + key file round-trips via decryptData");
check(openedV2k.keyFileUsed, "the key-file flag survives the dispatch");

// --- failures stay generic through the dispatch -----------------------------
await expectReject("wrong password on v2 is refused", () =>
  decryptData(toArrayBuffer(v2), "not the password", null)
);
await expectReject("a truncated v2 container is refused", () =>
  decryptData(toArrayBuffer(v2.subarray(0, v2.length - 1)), PASSWORD, null)
);
// Core header plus the slot-count byte and nothing else. Since the slot
// amendment the header is no longer a fixed 48 bytes, so this is written from
// the constant rather than from a number that used to be right.
await expectReject("a header-only v2 container is refused", () =>
  decryptData(toArrayBuffer(v2.subarray(0, KEYM2_CORE_HEADER_LEN + 1)), PASSWORD, null)
);
await expectReject("a v2 container with no payload is refused", () =>
  decryptData(toArrayBuffer(v2.subarray(0, KEYM2_CORE_HEADER_LEN + 1 + 96)), PASSWORD, null)
);

{
  // The two error paths must be indistinguishable — §6 and v1's rule alike.
  const messages = new Set<string>();
  for (const bad of [
    { blob: v2, pw: "wrong" },
    { blob: (() => { const m = Uint8Array.from(v2); m[m.length - 1] ^= 1; return m; })(), pw: PASSWORD },
  ]) {
    try {
      await decryptData(toArrayBuffer(bad.blob), bad.pw, null);
    } catch (e) {
      messages.add((e as Error).message);
    }
  }
  check(messages.size === 1, "wrong password and corruption are indistinguishable",
    `saw ${messages.size} distinct messages: ${[...messages].join(" | ")}`);
}

// --- armor (§7) --------------------------------------------------------------
const armored = armorKeym2(v2);
check(armored.startsWith(KEYM2_ARMOR_PREFIX), "armor carries the keym2: prefix");
check(!armored.includes("="), "armor is unpadded base64url");
check(armored.charCodeAt(0) === 0x6b, "armor's first byte is lowercase k, not the magic's K");
check(
  Buffer.from(dearmorKeym2(armored)).equals(Buffer.from(v2)),
  "armor round-trips byte-for-byte"
);
await expectReject("uppercase KEYM2: is refused", async () => dearmorKeym2("KEYM2:AAAA"));

// --- encryptKeym2 must draw a fresh master key every time --------------------
//
// This is the one entry point the UI actually calls, and until now nothing
// tested the quality of the key it generates — only that containers
// round-trip. The byte-equality conformance suite cannot help: it drives
// `encryptKeym2WithExplicitSecrets`, because pinning bytes against the Python
// reference means supplying the salt and master key rather than generating
// them.
//
// That gap has teeth. Zero the master key inside `encryptKeym2` and every
// container is wrapped and sealed under a key of all zeros. Nothing appears to
// break: the slot wraps the same zeros the payload keys derive from, so the
// container decrypts perfectly and every round-trip test passes while the
// master key is a constant the whole world knows.
//
// The test is an XOR relation, not a byte comparison, and the first attempt
// here got that wrong. Comparing two containers byte-for-byte looks sufficient
// — payload nonces are deterministic counters (§5.2), so a constant key means
// a constant keystream — but the payload AAD covers the core header, which
// carries a *random* salt. Same key, same nonce, same plaintext, different AAD
// still produces a different GCM tag. The bytes differ, the comparison passes,
// and the keystream is reused anyway. That test was green against a master key
// hard-coded to zero.
//
// AES-GCM is counter mode, so key and nonce reuse means the same keystream:
// c1 ^ c2 == p1 ^ p2, exactly, over the ciphertext body. That identity holds
// however the tag or the header differ, and it is the actual harm — two
// plaintexts under one keystream — rather than a proxy for it.
const KEYSTREAM_PROBE_LEN = 32;
const GCM_TAG_LEN = 16;
const probeA = new Uint8Array(KEYSTREAM_PROBE_LEN).fill(0x41);
const probeB = new Uint8Array(KEYSTREAM_PROBE_LEN).fill(0x5a);

const encProbe = (pt: Uint8Array) =>
  encryptKeym2(pt, PASSWORD, null, { kdf: FAST, cipher: CipherId.AES_256_GCM });
const cA = await encProbe(probeA);
const cB = await encProbe(probeB);

/** The ciphertext body of the single payload chunk: everything before its tag. */
const body = (c: Uint8Array) =>
  c.subarray(c.length - GCM_TAG_LEN - KEYSTREAM_PROBE_LEN, c.length - GCM_TAG_LEN);

const bodyA = body(cA);
const bodyB = body(cB);
let keystreamReused = bodyA.length === bodyB.length;
for (let i = 0; i < bodyA.length && keystreamReused; i++) {
  if ((bodyA[i]! ^ bodyB[i]!) !== (probeA[i]! ^ probeB[i]!)) keystreamReused = false;
}

check(
  !keystreamReused,
  "two containers share a payload keystream (c1^c2 == p1^p2): encryptKeym2 is not drawing a fresh master key"
);

// The control on the control. If the slice missed the ciphertext body the XOR
// above would compare tag or header bytes, never match, and pass for the wrong
// reason — so confirm the window really is the body by checking it is not the
// plaintext itself and that both containers are the size this assumes.
check(cA.length === cB.length, "the two probe containers differ in length; the body slice assumes they do not");
check(
  Buffer.compare(Buffer.from(bodyA), Buffer.from(probeA)) !== 0,
  "the sliced window equals the plaintext, so it is not ciphertext and the XOR test proves nothing"
);

// --- what a password attempt will cost, priced before it is spent ----------
//
// `unwrapMasterKey` derives once per slot a supplied secret could match, and
// stops at the first that unwraps. The right password in slot 0 costs one
// derivation; a wrong one costs all of them, before anything is authenticated.
//
// §6 bounds each slot and KEYM2_MAX_SLOTS bounds the count, so the total is
// bounded — just high. Measured on a developer laptop: eight passphrase slots
// at the ceiling cost 41 s with Argon2id and 315 s with PBKDF2. The app cannot
// refuse such a container without stranding a conforming one, so it prices it
// and says so.



/** One real container, then its slot record repeated `n` times. */
function withRepeatedSlots(container: Uint8Array, n: number): Uint8Array {
  const version = container[4] as number;
  const table = keym2SlotTableOffset(version);
  const countAt = keym2SlotCountOffset(version);
  const width = keym2SlotLen(CipherId.AES_256_GCM);
  const record = container.subarray(table, table + width);
  const payload = container.subarray(table + width);
  const out = new Uint8Array(table + n * width + payload.length);
  out.set(container.subarray(0, table), 0);
  out[countAt] = n;
  for (let i = 0; i < n; i++) out.set(record, table + i * width);
  out.set(payload, table + n * width);
  // On v3 this leaves slot_table_mac describing a table that no longer exists,
  // which is correct and irrelevant: pricing an unlock happens before any
  // secret is offered, so it cannot verify a MAC and must not pretend to.
  return out;
}

const oneSlotAes = await encryptKeym2(new TextEncoder().encode("cost model"), PASSWORD, null, {
  kdf: FAST,
  cipher: CipherId.AES_256_GCM,
});

const costOne = keym2UnlockCost(oneSlotAes);
check(costOne !== null, "a real container can be priced");
check(costOne?.passphraseSlots === 1, "an ordinary container declares one passphrase slot");
check(costOne?.hkdfSlots === 0, "an ordinary container declares no HKDF slots");
// PBKDF2 at 600k is 3 normal units by the model's scale (200k per unit), which
// is below the notice threshold — a default container must stay silent.
check(
  describeUnlockCost(costOne) === null,
  "an ordinary container produces no notice",
  `multipleOfNormal=${costOne?.multipleOfNormal}`
);

const eightSlots = keym2UnlockCost(withRepeatedSlots(oneSlotAes, 8));
check(eightSlots?.passphraseSlots === 8, "eight repeated slots are all counted");
check(
  (eightSlots?.multipleOfNormal ?? 0) >= UNLOCK_COST_NOTICE_THRESHOLD,
  "eight slots cross the notice threshold",
  `multipleOfNormal=${eightSlots?.multipleOfNormal}`
);
const eightNotice = describeUnlockCost(eightSlots);
check(eightNotice !== null, "eight slots produce a notice");
check(
  (eightNotice ?? "").includes("8 password slots"),
  "the notice names how many slots will be tried",
  eightNotice ?? ""
);
// The cost is per attempt, and saying so is the point: a user who mistypes
// pays it again. A notice that implied a one-off wait would understate it.
check(
  /every attempt/i.test(eightNotice ?? ""),
  "the notice says the cost is paid on every attempt"
);

// Cost scales with the slot count rather than being a flag.
const fourSlots = keym2UnlockCost(withRepeatedSlots(oneSlotAes, 4));
check(
  Math.abs((eightSlots?.multipleOfNormal ?? 0) - 2 * (fourSlots?.multipleOfNormal ?? 0)) < 0.2,
  "doubling the slots doubles the priced work",
  `4 slots=${fourSlots?.multipleOfNormal}, 8 slots=${eightSlots?.multipleOfNormal}`
);

// §6 pairs Shamir and passkey slots with HKDF, which has no cost parameters,
// and parseKeym2Slot enforces the pairing before any derivation. So an heir
// unlocking with shares cannot be made to pay: only passphrase slots count.
const withShares = await (async () => {
  const { addShamirSlotKeym2 } = await import("../src/lib/keym-v2.ts");
  const set = await addShamirSlotKeym2(oneSlotAes, { password: PASSWORD, keyFile: null }, 2, 3);
  return set.container;
})();
const shareCost = keym2UnlockCost(withShares);
check(shareCost?.hkdfSlots === 1, "the Shamir slot is counted as HKDF");
check(
  shareCost?.passphraseSlots === 1,
  "adding a Shamir slot does not add a passphrase slot to the price"
);
check(
  shareCost?.multipleOfNormal === costOne?.multipleOfNormal,
  "an HKDF slot costs nothing",
  `before=${costOne?.multipleOfNormal} after=${shareCost?.multipleOfNormal}`
);

// Total, not the parser: garbage must price at null rather than throw, because
// this runs on whatever the user pasted.
check(keym2UnlockCost(new Uint8Array(0)) === null, "an empty buffer prices as null");
check(keym2UnlockCost(new Uint8Array(64)) === null, "a zero buffer prices as null");
check(
  keym2UnlockCost(new TextEncoder().encode("not a container at all")) === null,
  "arbitrary text prices as null"
);
check(describeUnlockCost(null) === null, "a null cost produces no notice");
// --- an oversized container is a dead end only in the browser --------------
//
// MAX_PLAINTEXT_SIZE is a property of this build: a tab holds the container
// and the recovered file at once. §5's chunking means the format has no such
// limit, and keym2.py has none either — verified before this message was
// written, not after: a 150 MiB file round-trips through the reference
// byte-identically in about two seconds at ~634 MiB peak RSS.
//
// The old refusal said "maximum size is 100MB" and, on the decrypt side, told
// the reader to choose a smaller file. There is no smaller version of a
// backup. Someone recovering an inheritance would reasonably conclude the
// archive was unusable.

const help = oversizeRecoveryHelp();
check(help.includes("keym2.py"), "the oversize message names the tool that can open it", help);
check(help.includes("decrypt --in"), "the oversize message gives the actual command");
check(help.includes("RECOVERY.md"), "the oversize message points at the full procedure");
check(
  /no size limit/i.test(help),
  "the oversize message says the format is not the limit"
);
// The two failure modes this replaces, neither of which may come back.
check(
  !/smaller file|smaller than/i.test(help),
  "the oversize message must not tell the reader to shrink a backup",
  help
);
check(
  !/^Encrypted data is too large\.?$/i.test(help.trim()),
  "the oversize message is more than a restatement of the limit"
);

// And it is what decryptData actually throws, rather than a string that merely
// exists. Allocating past the ceiling is the only way to reach that branch.
{
  const oversized = new Uint8Array(MAX_CONTAINER_SIZE + 1);
  let message = "";
  try {
    await decryptData(oversized.buffer as ArrayBuffer, PASSWORD, null);
    message = "(no error thrown)";
  } catch (e) {
    message = e instanceof Error ? e.message : String(e);
  }
  check(
    message.includes("keym2.py"),
    "decryptData's too-large error carries the recovery route",
    message.slice(0, 120)
  );
}

// The encrypt side keeps the opposite advice, because there it is correct: a
// file you are about to encrypt genuinely can be replaced with a smaller one.
{
  const oversized = new Uint8Array(MAX_CONTAINER_SIZE + 1);
  let message = "";
  try {
    await encryptData(oversized.buffer as ArrayBuffer, PASSWORD, null);
    message = "(no error thrown)";
  } catch (e) {
    message = e instanceof Error ? e.message : String(e);
  }
  check(
    /too large/i.test(message) && !message.includes("keym2.py"),
    "encrypting an oversized file still says to pick a smaller one",
    message.slice(0, 120)
  );
}

// ---------------------------------------------------------------------------
// The header peek has to cover the largest slot table any version can hold
// ---------------------------------------------------------------------------
//
// The unlock-cost notice is the one thing the app says *before* spending the
// KDF budget, and it is computed from a fixed-size prefix of the container
// rather than the whole file. keym2UnlockCost returns null the moment that
// prefix stops short of the slot table, so a peek that is too small does not
// misprice the unlock — it silently prices nothing, on precisely the container
// the warning exists for.
//
// 1 KiB was chosen against v2 + AES, whose table ends at 777. Two things have
// moved since: v3 put the table at 57 instead of 9, and the chained cipher's
// second tag makes a slot 112 bytes instead of 96. It still fits, but the
// margin is 71 bytes rather than the 247 the original reasoning suggests, so
// the relationship is asserted here against the constants instead of being
// re-derived by hand the next time one of them changes.
{
  const CIPHERS: [string, CipherId][] = [
    ["aes-256-gcm", CipherId.AES_256_GCM],
    ["chacha20-poly1305", CipherId.CHACHA20_POLY1305],
    ["chained", CipherId.CHAINED],
  ];
  let worst = 0;
  let worstLabel = "";
  for (const version of [2, KEYM2_VERSION_V3]) {
    for (const [name, cipher] of CIPHERS) {
      const end = keym2SlotTableOffset(version) + KEYM2_MAX_SLOTS * keym2SlotLen(cipher);
      if (end > worst) {
        worst = end;
        worstLabel = `v${version} + ${name}`;
      }
    }
  }
  check(
    KEYM2_HEADER_PEEK_BYTES >= worst,
    "the header peek covers the largest slot table any version and cipher can produce",
    `worst case is ${worst} bytes (${worstLabel}); the peek reads ${KEYM2_HEADER_PEEK_BYTES}. ` +
      "Below the worst case, keym2UnlockCost returns null and the notice silently stops appearing."
  );
  // A peek that covered everything by being enormous would pass the line above
  // while defeating the point of reading a prefix at all.
  check(
    KEYM2_HEADER_PEEK_BYTES <= 64 * 1024,
    "the header peek is still a prefix rather than the whole container",
    `${KEYM2_HEADER_PEEK_BYTES} bytes`
  );
}

console.log(`\n${passed} passed, ${failures.length} failed`);
if (failures.length) {
  console.log("Version dispatch FAILED.");
  process.exit(1);
}
console.log("Version dispatch verified: v1 unchanged, v2 routed, failures generic.");
