/**
 * Keymaker crypto regression suite — KEYM v1 format.
 *
 * Run with:  npm run test:keymaker
 *
 * Covers:
 *  - Round-trips for all (2 KDF × 3 cipher) combos, with and without key file
 *  - Wrong-password rejection
 *  - Tampered settings block rejection (header is AAD — flipping any header
 *    byte must fail authentication)
 *  - Tampered ciphertext rejection, AAD authenticity
 *  - Legacy IBTZ v1 + headerless v0 fixture decryption (delegated to the
 *    frozen src/lib/crypto.ts)
 *  - Frozen KEYM ciphertext vectors under scripts/fixtures/keymaker/
 *
 * Fixture policy: APPEND-ONLY. Never modify or delete an existing fixture —
 * each one is a promise that a real user's file still opens. The fixture
 * password and key file are TEST-ONLY and published in this repo; treat them
 * as compromised.
 */
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { webcrypto } from "node:crypto";
import {
  encryptData,
  decryptData,
  detectFormat,
  inspectKeym,
  KdfId,
  CipherId,
  type KdfParams,
} from "../src/lib/keymaker-crypto.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const LEGACY = JSON.parse(readFileSync(join(HERE, "crypto-fixtures.json"), "utf8"));

const enc = new TextEncoder();
const dec = new TextDecoder();

let failures = 0;
let passed = 0;
function check(condition: boolean, label: string) {
  if (condition) {
    passed++;
    console.log(`  ok    ${label}`);
  } else {
    failures++;
    console.error(`  FAIL  ${label}`);
  }
}

function b64ToArrayBuffer(b64: string): ArrayBuffer {
  const buf = Buffer.from(b64, "base64");
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
}

function hexToArrayBuffer(hex: string): ArrayBuffer {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out.buffer as ArrayBuffer;
}

// Faster-than-default KDF params for the live round-trips (params are stored
// in the header, so any value is a valid test of the wire format).
const PBKDF2_FAST: KdfParams = { kdf: KdfId.PBKDF2, params: { iterations: 50_000 } };
const ARGON_FAST: KdfParams = {
  kdf: KdfId.ARGON2ID,
  params: { timeCost: 2, memoryKiB: 16384, parallelism: 2 },
};
const KDFS: Array<[string, KdfParams]> = [
  ["pbkdf2", PBKDF2_FAST],
  ["argon2id", ARGON_FAST],
];
const CIPHERS: Array<[string, CipherId]> = [
  ["aes-256-gcm", CipherId.AES_256_GCM],
  ["chacha20-poly1305", CipherId.CHACHA20_POLY1305],
  ["chained", CipherId.CHAINED],
];

const PASSWORD = "correct horse battery staple — test only";
const KEYFILE = new Uint8Array(
  hexToArrayBuffer("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
);
const PLAINTEXT = "Keymaker round-trip payload · 秘密 · 🔐";

const rejects = async (label: string, fn: () => Promise<unknown>) => {
  try {
    await fn();
    check(false, `${label} (unexpectedly succeeded)`);
  } catch {
    check(true, label);
  }
};

async function main() {
  console.log("\nKeymaker crypto regression (KEYM v1)\n");

  // ---- 1. Round-trips: all (KDF × cipher) combos, ± key file ----
  console.log("Round-trips (2 KDF × 3 cipher, ± key file):");
  for (const [kdfName, kdf] of KDFS) {
    for (const [cipherName, cipher] of CIPHERS) {
      const label = `${kdfName} + ${cipherName}`;
      const ct = await encryptData(enc.encode(PLAINTEXT).buffer as ArrayBuffer, PASSWORD, null, {
        kdf,
        cipher,
      });
      const res = await decryptData(ct.slice(0), PASSWORD, null);
      check(res.format === "keym-v1" && dec.decode(res.data) === PLAINTEXT, label);

      const ctKf = await encryptData(
        enc.encode(PLAINTEXT).buffer as ArrayBuffer,
        PASSWORD,
        KEYFILE.slice(0).buffer as ArrayBuffer,
        { kdf, cipher }
      );
      const resKf = await decryptData(ctKf.slice(0), PASSWORD, KEYFILE.slice(0).buffer as ArrayBuffer);
      check(
        resKf.format === "keym-v1" && resKf.keyFileUsed && dec.decode(resKf.data) === PLAINTEXT,
        `${label} + key file`
      );
    }
  }

  // ---- 2. Container layout ----
  console.log("\nContainer format:");
  const ct = await encryptData(enc.encode(PLAINTEXT).buffer as ArrayBuffer, PASSWORD, null, {
    kdf: ARGON_FAST,
    cipher: CipherId.CHAINED,
  });
  const head = new Uint8Array(ct.slice(0));
  check(head[0] === 0x4b && head[1] === 0x45 && head[2] === 0x59 && head[3] === 0x4d, 'magic bytes are "KEYM"');
  check(head[4] === 0x01, "format version byte is 1");
  check(head[5] === 0x01, "kdf_id is Argon2id (1)");
  check(head[6] === 0x02, "cipher_id is chained (2)");
  // header: 7 + 7 (argon params) + 1 (flags) + 32 (salt) + 24 (two nonces) = 71
  check(ct.byteLength === 71 + PLAINTEXT.length * 0 + enc.encode(PLAINTEXT).length + 16 + 16, "chained header length is 71 bytes");
  check(detectFormat(head) === "keym-v1", "detectFormat identifies KEYM v1");
  const insp = inspectKeym(head);
  check(insp !== null, "inspectKeym parses KEYM v1 header");
  check(
    insp !== null &&
      insp.kdfLabel.includes("Argon2id") &&
      insp.cipherLabel.includes("AES-256-GCM") &&
      insp.cipherLabel.includes("ChaCha20-Poly1305"),
    "inspectKeym labels Argon2id + chained ciphers"
  );
  check(inspectKeym(enc.encode("not a container")) === null, "inspectKeym returns null for non-KEYM data");

  // ---- 3. Negative cases ----
  console.log("\nRejections:");
  await rejects("wrong password rejected", () =>
    decryptData(ct.slice(0), PASSWORD + "wrong", null)
  );
  await rejects("tampered settings block rejected (kdf_id byte)", () => {
    const t = new Uint8Array(ct.slice(0));
    t[5]! ^= 0x01;
    return decryptData(t.buffer as ArrayBuffer, PASSWORD, null);
  });
  await rejects("tampered settings block rejected (flags byte 14)", () => {
    const t = new Uint8Array(ct.slice(0));
    t[14]! ^= 0x01;
    return decryptData(t.buffer as ArrayBuffer, PASSWORD, null);
  });
  await rejects("tampered settings block rejected (salt byte)", () => {
    const t = new Uint8Array(ct.slice(0));
    t[20]! ^= 0xff;
    return decryptData(t.buffer as ArrayBuffer, PASSWORD, null);
  });
  await rejects("tampered settings block rejected (last nonce byte 70)", () => {
    const t = new Uint8Array(ct.slice(0));
    t[70]! ^= 0xff;
    return decryptData(t.buffer as ArrayBuffer, PASSWORD, null);
  });
  await rejects("tampered ciphertext rejected", () => {
    const t = new Uint8Array(ct.slice(0));
    t[t.length - 1]! ^= 0xff;
    return decryptData(t.buffer as ArrayBuffer, PASSWORD, null);
  });
  await rejects("truncated input rejected", () =>
    decryptData(ct.slice(0, 40), PASSWORD, null)
  );

  // AAD authenticity: a ciphertext valid under one settings block must not
  // verify under a different one. Swap the flags byte and re-derive — the
  // AEAD tag check must fail (covered above), and additionally confirm the
  // header byte positions 4..70 all authenticate by flipping a sample.
  console.log("\nAAD authenticity sweep (flip each header byte 4..70):");
  let aadFails = 0;
  for (let i = 4; i <= 70; i++) {
    const t = new Uint8Array(ct.slice(0));
    t[i]! ^= 0x40;
    try {
      await decryptData(t.buffer as ArrayBuffer, PASSWORD, null);
      aadFails++;
    } catch {
      // expected
    }
  }
  check(aadFails === 0, `all ${71 - 4} header byte flips rejected (${aadFails} leaks)`);

  // Missing key file must fail for a file encrypted with one.
  const ctKf = await encryptData(
    enc.encode(PLAINTEXT).buffer as ArrayBuffer,
    PASSWORD,
    KEYFILE.slice(0).buffer as ArrayBuffer,
    { kdf: PBKDF2_FAST, cipher: CipherId.AES_256_GCM }
  );
  await rejects("missing key file rejected", () => decryptData(ctKf.slice(0), PASSWORD, null));

  // ---- 4. Frozen KEYM fixtures ----
  console.log("\nFrozen KEYM fixtures (scripts/fixtures/keymaker/):");
  const fixtureDir = join(HERE, "fixtures", "keymaker");
  let fixtureCount = 0;
  try {
    const meta = JSON.parse(readFileSync(join(fixtureDir, "fixtures.json"), "utf8"));
    for (const fx of meta.fixtures) {
      fixtureCount++;
      const blob = readFileSync(join(fixtureDir, fx.file));
      const ab = blob.buffer.slice(blob.byteOffset, blob.byteOffset + blob.byteLength) as ArrayBuffer;
      const keyFile = fx.keyFile ? KEYFILE.slice(0).buffer as ArrayBuffer : null;
      try {
        const res = await decryptData(ab, meta.password, keyFile);
        check(
          res.format === "keym-v1" && dec.decode(res.data) === fx.plaintext,
          `${fx.name} (${fx.kdf} / ${fx.cipher}${fx.keyFile ? " / +keyfile" : ""})`
        );
      } catch (err) {
        check(false, `${fx.name} — threw: ${(err as Error).message}`);
      }
    }
    check(fixtureCount === 6, `fixture corpus has one vector per KDF/cipher combo (${fixtureCount}/6)`);
  } catch (err) {
    check(false, `fixture load — threw: ${(err as Error).message}`);
  }

  // ---- 5. Legacy backward compatibility ----
  console.log("\nLegacy formats (delegated to frozen crypto.ts):");
  for (const fx of LEGACY.fixtures) {
    const label = `${fx.version} [${fx.format}] ${fx.payload}${fx.keyFile ? " +keyfile" : ""}`;
    try {
      const keyFile = fx.keyFile ? hexToArrayBuffer(LEGACY.keyFileHex) : null;
      const res = await decryptData(b64ToArrayBuffer(fx.base64), LEGACY.password, keyFile);
      const expectedFormat = fx.format === "v1" ? "ibtz-v1" : "ibtz-v0";
      check(
        res.format === expectedFormat && dec.decode(res.data) === fx.plaintext,
        `${label} → detected ${expectedFormat}`
      );
    } catch (err) {
      check(false, `${label} — threw: ${(err as Error).message}`);
    }
  }
  try {
    const res = await decryptData(b64ToArrayBuffer(LEGACY.independent.base64), LEGACY.password, null);
    check(
      res.format === "ibtz-v0" && dec.decode(res.data) === LEGACY.independent.plaintext,
      "v0 raw-primitive layout → detected ibtz-v0"
    );
  } catch (err) {
    check(false, `v0 raw-primitive layout — threw: ${(err as Error).message}`);
  }

  // ---- Summary ----
  console.log(`\n${passed} passed, ${failures} failed`);
  if (failures > 0) {
    console.error("KEYMAKER CRYPTO REGRESSION FAILED — do not ship.\n");
    process.exit(1);
  }
  console.log("All Keymaker crypto regression checks passed.\n");
}

main().catch((err) => {
  console.error("\nFATAL:", err);
  process.exit(1);
});
