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
  encryptData,
  type KdfParams,
} from "../src/lib/keymaker-crypto.ts";
import {
  KEYM2_ARMOR_PREFIX,
  KEYM2_CORE_HEADER_LEN,
  armorKeym2,
  dearmorKeym2,
  encryptKeym2,
  isKeym2Binary,
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
const v2 = await encryptKeym2(enc.encode("v2 payload"), PASSWORD, null, {
  kdf: FAST,
  cipher: CipherId.AES_256_GCM,
});

check(detectFormat(v1) === "keym-v1", "a v1 container is detected as v1");
check(detectFormat(v2) === "keym-v2", "a v2 container is detected as v2");
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

console.log(`\n${passed} passed, ${failures.length} failed`);
if (failures.length) {
  console.log("Version dispatch FAILED.");
  process.exit(1);
}
console.log("Version dispatch verified: v1 unchanged, v2 routed, failures generic.");
