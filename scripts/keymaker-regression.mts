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
  isUserFacingError,
  KeymakerError,
  KdfId,
  CipherId,
  type KdfParams,
} from "../src/lib/keymaker-crypto.ts";
import { encryptFile as legacyEncryptFile } from "../src/lib/crypto.ts";

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

// Cheaper-than-default KDF params for the live round-trips (params live in the
// header, so any accepted value exercises the wire format just as well).
//
// PBKDF2 sits at the encryption-time floor rather than below it: encryptData()
// now refuses to *write* a container weaker than the OWASP minimum, so the
// suite has to respect the same policy it ships. Decryption stays deliberately
// permissive, which is why the 100k-iteration fixtures below still open.
const PBKDF2_FAST: KdfParams = { kdf: KdfId.PBKDF2, params: { iterations: 600_000 } };
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

  // ---- KDF cost-parameter bounds (KM-01) ----
  //
  // A KEYM header is unauthenticated until the AEAD tag is verified, and the
  // tag cannot be verified until the key has been derived using the very
  // parameters the header supplies. AAD stops a tampered header from yielding
  // valid plaintext; it cannot stop those parameters from being executed on
  // the way to discovering the tamper. So the parser must bound them itself.
  //
  // Each case below builds a syntactically valid header requesting an absurd
  // cost and asserts we reject it *without* invoking the KDF. The wall-clock
  // assertion is the real test: an unbounded implementation would grind here
  // rather than return.
  console.log("\nKDF parameter bounds (hostile headers must be refused, not executed):");

  const hostileHeader = (opts: {
    kdfId: number;
    params: number[];
    saltLen: number;
  }): ArrayBuffer => {
    const { kdfId, params, saltLen } = opts;
    const total = 7 + params.length + 1 + saltLen + 12 + 16 + 8;
    const h = new Uint8Array(total);
    h.set([0x4b, 0x45, 0x59, 0x4d], 0); // "KEYM"
    h[4] = 1; // version
    h[5] = kdfId;
    h[6] = 0; // AES-256-GCM
    h.set(params, 7);
    // flags, salt, nonce and ciphertext are left as zeroes: parsing must fail
    // on the cost parameters before any of it is reached.
    return h.buffer as ArrayBuffer;
  };

  const u32 = (n: number) => [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
  const u16 = (n: number) => [(n >>> 8) & 0xff, n & 0xff];

  const hostile: Array<[string, ArrayBuffer]> = [
    [
      "PBKDF2 iterations 0xFFFFFFFF",
      hostileHeader({ kdfId: 0, params: u32(0xffffffff), saltLen: 16 }),
    ],
    ["PBKDF2 iterations 0", hostileHeader({ kdfId: 0, params: u32(0), saltLen: 16 })],
    [
      "Argon2id memory 0xFFFFFFFF KiB",
      hostileHeader({ kdfId: 1, params: [...u16(3), ...u32(0xffffffff), 4], saltLen: 32 }),
    ],
    [
      "Argon2id timeCost 65535",
      hostileHeader({ kdfId: 1, params: [...u16(0xffff), ...u32(65536), 4], saltLen: 32 }),
    ],
    [
      "Argon2id parallelism 255",
      hostileHeader({ kdfId: 1, params: [...u16(3), ...u32(65536), 0xff], saltLen: 32 }),
    ],
  ];

  for (const [label, buf] of hostile) {
    const started = process.hrtime.bigint();
    let rejected = false;
    try {
      await decryptData(buf, PASSWORD, null);
    } catch {
      rejected = true;
    }
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    // Generous ceiling: a real derivation at these settings takes minutes to
    // forever. Anything under a second proves the KDF was never entered.
    check(rejected && elapsedMs < 1000, `${label} refused in ${elapsedMs.toFixed(1)}ms`);
  }

  // The encryption path validates caller-supplied options too, so a non-UI
  // caller cannot write a container below the policy floor.
  await rejects("encrypt refused below the PBKDF2 floor", () =>
    encryptData(enc.encode("x").buffer as ArrayBuffer, PASSWORD, null, {
      kdf: { kdf: KdfId.PBKDF2, params: { iterations: 1000 } },
      cipher: CipherId.AES_256_GCM,
    })
  );
  await rejects("encrypt refused above the Argon2id memory ceiling", () =>
    encryptData(enc.encode("x").buffer as ArrayBuffer, PASSWORD, null, {
      kdf: { kdf: KdfId.ARGON2ID, params: { timeCost: 3, memoryKiB: 4_294_967_295, parallelism: 4 } },
      cipher: CipherId.AES_256_GCM,
    })
  );

  // Legacy-friendly: decryption still accepts historically weak-but-sane
  // parameters, since refusing them would strand real files.
  const lowIter = await encryptData(
    enc.encode(PLAINTEXT).buffer as ArrayBuffer,
    PASSWORD,
    null,
    { kdf: { kdf: KdfId.PBKDF2, params: { iterations: 600_000 } }, cipher: CipherId.AES_256_GCM }
  );
  const lowIterOut = await decryptData(lowIter.slice(0), PASSWORD, null);
  check(
    dec.decode(lowIterOut.data) === PLAINTEXT,
    "decrypt still opens containers at the policy floor"
  );

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
      let blob = readFileSync(join(fixtureDir, fx.file));
      // §7.2. A self-extracting page is a container wearing an HTML document.
      // Unwrapping it here rather than special-casing it below means the frozen
      // page takes every check the other vectors take — and the unwrap becomes
      // part of what the corpus freezes, which is the artefact's whole
      // durability claim.
      if (fx.selfextract) {
        const { extractSelfExtract } = await import("../src/lib/keym-v2-selfextract.ts");
        blob = Buffer.from(extractSelfExtract(blob.toString("utf8")));
      }
      const ab = blob.buffer.slice(blob.byteOffset, blob.byteOffset + blob.byteLength) as ArrayBuffer;
      const keyFile = fx.keyFile ? KEYFILE.slice(0).buffer as ArrayBuffer : null;
      // A fixture with no `version` field predates v2 joining the corpus. The
      // default lives here rather than in the JSON so the six v1 entries could
      // stay byte-identical when v2 was added — see the generator's note.
      const version = fx.version ?? 1;
      const expected = version === 2 ? "keym-v2" : "keym-v1";
      try {
        const res = await decryptData(ab, meta.password, keyFile);
        check(
          res.format === expected && dec.decode(res.data) === fx.plaintext,
          `v${version} ${fx.name} (${fx.kdf} / ${fx.cipher}${fx.keyFile ? " / +keyfile" : ""})`
        );
      } catch (err) {
        check(false, `${fx.name} — threw: ${(err as Error).message}`);
      }

      // §4.6. A share-set fixture also promises that these printed strings
      // still open this container — the half of the promise the bytes alone do
      // not carry. Deliberately a *non-leading* subset: taking shares 3, 4 and
      // 5 would catch a reconstruction that had quietly become positional.
      if (fx.shamir) {
        const { decryptKeym2 } = await import("../src/lib/keym-v2.ts");
        const all: string[] = fx.shamir.shares;
        const k: number = fx.shamir.threshold;
        try {
          const viaShares = await decryptKeym2(new Uint8Array(blob), "", null, all.slice(-k));
          check(
            dec.decode(viaShares.data) === fx.plaintext,
            `v2 ${fx.name} — the last ${k} of ${all.length} shares still open it`
          );
        } catch (err) {
          check(false, `${fx.name} shares — threw: ${(err as Error).message}`);
        }
        let refused = false;
        try {
          await decryptKeym2(new Uint8Array(blob), "", null, all.slice(0, k - 1));
        } catch {
          refused = true;
        }
        check(refused, `v2 ${fx.name} — ${k - 1} shares still do not`);
      }
    }
    // Asserting the format as well as the plaintext is what makes these
    // fixtures a dispatch test too: a v1 vector that started coming back as
    // "keym-v2" would mean detectFormat had begun misreading the version byte,
    // and the plaintext alone would not notice.
    const v1Count = meta.fixtures.filter((f: any) => (f.version ?? 1) === 1).length;
    const v2Count = meta.fixtures.filter((f: any) => f.version === 2).length;
    const shamirCount = meta.fixtures.filter((f: any) => f.shamir).length;
    const pageCount = meta.fixtures.filter((f: any) => f.selfextract).length;
    check(
      fixtureCount === 16 && v1Count === 6 && v2Count === 10 &&
        shamirCount === 3 && pageCount === 1,
      `corpus covers both versions and all three ciphers per slot type ` +
        `(${v1Count} v1 + ${v2Count} v2, of which ${shamirCount} share sets and ` +
        `${pageCount} self-extracting page = ${fixtureCount}/16)`
    );
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


  // ---- Phase 1 audit fixes: the error a user is shown must be true ----
  //
  // Three separate defects all surfaced as the same lie: "the password may be
  // incorrect", for files whose password was never the problem. In a backup
  // tool that is the worst available wrong answer — it sends someone hunting
  // for a password when the real fault is a truncated or tampered file.
  console.log("\nDiagnosis accuracy (audit B3/B4/B6, C-L3):");

  const goodCt = await encryptData(enc.encode(PLAINTEXT).buffer as ArrayBuffer, PASSWORD, null, {
    kdf: PBKDF2_FAST,
    cipher: CipherId.AES_256_GCM,
  });

  // B4: a header whose PBKDF2 iteration count has been pushed past the ceiling
  // is a *tampered container*, and must say so rather than blaming the password.
  const overCost = new Uint8Array(goodCt.slice(0));
  new DataView(overCost.buffer).setUint32(7, 10_000_001, false);
  try {
    await decryptData(overCost.buffer as ArrayBuffer, PASSWORD, null);
    check(false, "out-of-range KDF params rejected (unexpectedly succeeded)");
  } catch (err) {
    check(
      isUserFacingError(err) && err.code === "kdf-params-out-of-range",
      `tampered KDF params report the real cause, not "wrong password"`
    );
    check(
      !/password/i.test((err as Error).message),
      "the out-of-range message does not mention the password"
    );
  }

  // B6: 8..13 bytes claiming Argon2id used to read a uint32 past the end and
  // raise a DataView RangeError, which was then re-wrapped as wrong-password.
  for (const len of [8, 9, 10, 11, 12, 13]) {
    const runt = new Uint8Array(len);
    runt.set([0x4b, 0x45, 0x59, 0x4d, 0x01, KdfId.ARGON2ID, CipherId.AES_256_GCM]);
    try {
      await decryptData(runt.buffer as ArrayBuffer, PASSWORD, null);
      check(false, `${len}-byte Argon2id header rejected (unexpectedly succeeded)`);
    } catch (err) {
      check(
        isUserFacingError(err) && err.code === "malformed-container",
        `${len}-byte Argon2id header → malformed-container, not RangeError`
      );
    }
  }

  // C-L3: a 1..4 byte blob that begins "KEYM" is a truncated KEYM file, not a
  // headerless v0 container. It must be rejected without running a KDF at all;
  // the old path burned 1,000,000 PBKDF2 iterations first.
  for (const len of [1, 2, 3, 4]) {
    const stub = new Uint8Array([0x4b, 0x45, 0x59, 0x4d].slice(0, len));
    const t0 = Date.now();
    try {
      await decryptData(stub.buffer as ArrayBuffer, PASSWORD, null);
      check(false, `${len}-byte "KEYM" prefix rejected (unexpectedly succeeded)`);
    } catch (err) {
      const ms = Date.now() - t0;
      check(
        isUserFacingError(err) && err.code === "malformed-container",
        `${len}-byte "KEYM" prefix → malformed-container`
      );
      check(ms < 250, `${len}-byte "KEYM" prefix rejected without a KDF run (${ms} ms)`);
    }
  }

  // The other half of the contract: a genuine authentication failure must stay
  // generic. If this ever becomes a KeymakerError, the oracle is back.
  try {
    await decryptData(goodCt.slice(0), PASSWORD + "x", null);
    check(false, "wrong password rejected (unexpectedly succeeded)");
  } catch (err) {
    check(!isUserFacingError(err), "a wrong password is NOT a user-facing error code");
    check(
      /may be incorrect, or the data may be corrupted/.test((err as Error).message),
      "wrong password still yields the single generic message"
    );
  }
  // ...and so must a flipped ciphertext byte, indistinguishably.
  const flipped = new Uint8Array(goodCt.slice(0));
  flipped[flipped.length - 1]! ^= 0xff;
  try {
    await decryptData(flipped.buffer as ArrayBuffer, PASSWORD, null);
    check(false, "flipped ciphertext rejected (unexpectedly succeeded)");
  } catch (err) {
    check(!isUserFacingError(err), "corrupted ciphertext is NOT a user-facing error code");
  }

  // ---- B5: legacy Unicode normalization ----
  //
  // The KEYM path normalizes to NFC; the frozen legacy core never has. A
  // password typed as NFD on one OS and NFC on another is the same password to
  // every human and a different key to PBKDF2.
  console.log("\nLegacy Unicode normalization (audit B5):");

  const NFC_PASSWORD = "caf\u00e9-Espa\u00f1a-M\u00fcller-2026!";      // composed
  const NFD_PASSWORD = NFC_PASSWORD.normalize("NFD");                     // decomposed
  check(NFC_PASSWORD !== NFD_PASSWORD, "the two normalization forms really do differ as strings");
  check(
    NFC_PASSWORD.normalize("NFC") === NFD_PASSWORD.normalize("NFC"),
    "...and really are canonically equivalent"
  );

  for (const [writeAs, readAs, label] of [
    [NFC_PASSWORD, NFD_PASSWORD, "written NFC, re-typed NFD"],
    [NFD_PASSWORD, NFC_PASSWORD, "written NFD, re-typed NFC"],
  ] as const) {
    const legacy = await legacyEncryptFile(
      enc.encode(PLAINTEXT).buffer as ArrayBuffer,
      writeAs,
      null
    );
    try {
      const res = await decryptData(legacy.slice(0), readAs, null);
      check(dec.decode(res.data) === PLAINTEXT, `legacy IBTZ opens when ${label}`);
    } catch (err) {
      check(false, `legacy IBTZ opens when ${label} — threw: ${(err as Error).message}`);
    }
  }

  // The fallback must not turn a genuinely wrong password into a success.
  const legacyNfc = await legacyEncryptFile(
    enc.encode(PLAINTEXT).buffer as ArrayBuffer,
    NFC_PASSWORD,
    null
  );
  await rejects("a wrong password is still wrong after the normalization retry", () =>
    decryptData(legacyNfc.slice(0), "some-entirely-different-password", null)
  );

  // Key files are zeroed by the frozen core's finally block, so the retry has
  // to hand each attempt its own copy. If it does not, this fails.
  const legacyKf = await legacyEncryptFile(
    enc.encode(PLAINTEXT).buffer as ArrayBuffer,
    NFC_PASSWORD,
    KEYFILE.slice(0).buffer as ArrayBuffer
  );
  try {
    const res = await decryptData(
      legacyKf.slice(0),
      NFD_PASSWORD,
      KEYFILE.slice(0).buffer as ArrayBuffer
    );
    check(dec.decode(res.data) === PLAINTEXT, "legacy IBTZ + key file survives the retry");
  } catch (err) {
    check(false, `legacy IBTZ + key file survives the retry — threw: ${(err as Error).message}`);
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
