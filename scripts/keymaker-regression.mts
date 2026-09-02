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
import { PasskeyError } from "../src/lib/webauthn-prf.ts";

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
      const expected = version === 3 ? "keym-v3" : version === 2 ? "keym-v2" : "keym-v1";
      try {
        const res = await decryptData(ab, meta.password, keyFile);
        check(
          res.format === expected && dec.decode(res.data) === fx.plaintext,
          `v${version} ${fx.name} (${fx.kdf} / ${fx.cipher}${fx.keyFile ? " / +keyfile" : ""})`
        );
        const expectedVerdict =
          version === 3 ? (fx.slotTableAuthentic as boolean) : null;
        check(
          res.slotTableAuthentic === expectedVerdict,
          `v${version} ${fx.name} — slot table reported as ` +
            `${expectedVerdict === null ? "not claimed" : expectedVerdict}`
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
            `v${version} ${fx.name} — the last ${k} of ${all.length} shares still open it`
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
        check(refused, `v${version} ${fx.name} — ${k - 1} shares still do not`);
      }

      // §4.7. Same promise in the other shape: the recorded PRF output is the
      // only way back into this container, and a fixture nobody can open is
      // not a fixture. What it pins is that the derivation from those 32 bytes
      // to this container's master key has not moved.
      if (fx.passkey) {
        const { decryptKeym2 } = await import("../src/lib/keym-v2.ts");
        const prf = Uint8Array.from(Buffer.from(fx.passkey.prfOutputHex, "hex"));
        try {
          const viaPrf = await decryptKeym2(new Uint8Array(blob), "", null, undefined, prf);
          check(
            dec.decode(viaPrf.data) === fx.plaintext,
            `v${version} ${fx.name} — the recorded PRF output still opens it`
          );
        } catch (err) {
          check(false, `${fx.name} passkey — threw: ${(err as Error).message}`);
        }
        let prfRefused = false;
        try {
          await decryptKeym2(new Uint8Array(blob), "", null, undefined, new Uint8Array(32));
        } catch {
          prfRefused = true;
        }
        check(prfRefused, `v${version} ${fx.name} — a wrong PRF output does not`);
      }

      // v3 §1.1, frozen. The heir enrolled on this container had their slot cut
      // out of the table; the PRF output below is the credential that used to
      // open it. Both halves of the attack are asserted, because either one
      // alone reads as something milder than it is: that the heir is now locked
      // out is the *harm*, and that the reader still says the table changed is
      // the only reason anyone finds out.
      if (fx.strippedPasskey) {
        const { decryptKeym2 } = await import("../src/lib/keym-v2.ts");
        const prf = Uint8Array.from(Buffer.from(fx.strippedPasskey.prfOutputHex, "hex"));
        let strippedHeirRefused = false;
        try {
          await decryptKeym2(new Uint8Array(blob), "", null, undefined, prf);
        } catch {
          strippedHeirRefused = true;
        }
        check(
          strippedHeirRefused,
          `v${version} ${fx.name} — the stripped heir's passkey no longer opens it`
        );
      }
    }
    // Asserting the format as well as the plaintext is what makes these
    // fixtures a dispatch test too: a v1 vector that started coming back as
    // "keym-v2" would mean detectFormat had begun misreading the version byte,
    // and the plaintext alone would not notice.
    const v1Count = meta.fixtures.filter((f: any) => (f.version ?? 1) === 1).length;
    const v2Count = meta.fixtures.filter((f: any) => f.version === 2).length;
    const v3Count = meta.fixtures.filter((f: any) => f.version === 3).length;
    const shamirCount = meta.fixtures.filter((f: any) => f.shamir).length;
    const passkeyCount = meta.fixtures.filter((f: any) => f.passkey).length;
    const pageCount = meta.fixtures.filter((f: any) => f.selfextract).length;
    const strippedCount = meta.fixtures.filter((f: any) => f.strippedPasskey).length;
    check(
      fixtureCount === 32 && v1Count === 6 && v2Count === 13 && v3Count === 13 &&
        shamirCount === 6 && passkeyCount === 6 && pageCount === 1 && strippedCount === 1,
      `corpus covers all three versions and all three ciphers per slot type ` +
        `(${v1Count} v1 + ${v2Count} v2 + ${v3Count} v3, of which ${shamirCount} share ` +
        `sets, ${passkeyCount} passkey slots, ${pageCount} self-extracting page and ` +
        `${strippedCount} stripped slot table = ${fixtureCount}/32)`
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

  // A subclass of KeymakerError must still be its own class. The base
  // constructor re-pins the prototype to keep instanceof working through the
  // transpile targets, and doing that with a literal `KeymakerError.prototype`
  // silently demoted every subclass. `PasskeyError`, the one class whose
  // whole job is to carry a `cancelled` flag its catch blocks test for by
  // `instanceof`, reported itself as a plain KeymakerError and every
  // second-tap failure took the generic "Enrolling the passkey failed." branch.
  console.log("\nError classes survive subclassing:");
  class SubclassedError extends KeymakerError {
    constructor() {
      super("invalid-input", "subclass");
    }
  }
  const sub = new SubclassedError();
  check(sub instanceof SubclassedError, "a subclass of KeymakerError is instanceof itself");
  check(sub instanceof KeymakerError, "...and still instanceof KeymakerError");
  check(Object.getPrototypeOf(sub) === SubclassedError.prototype, "its prototype is the subclass's");
  const passkeyCancelled = new PasskeyError("cancelled", true);
  check(passkeyCancelled instanceof PasskeyError, "PasskeyError is instanceof PasskeyError");
  check(isUserFacingError(passkeyCancelled), "PasskeyError is still user-facing");
  check(passkeyCancelled.cancelled, "the cancelled flag survives construction");

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

  // ---- 6. v3 slot-table authentication (docs/FORMAT-V3-DESIGN.md §5) ----
  //
  // The attack the whole revision exists for. §1.1 measured three ways to edit
  // a container with no key material at all, and only one of them did damage:
  // cutting a slot out of the table locks an enrolled heir out permanently,
  // while the owner opens the file exactly as before and nothing about it looks
  // wrong. Reordering was inert and transplanting was refused; stripping was
  // real, silent, and unrecoverable.
  //
  // §5.2 fixes the *detection*, not the file, and is deliberately not a
  // refusal: a reader that finds a bad MAC MUST still return the plaintext,
  // because refusing would convert tampering someone could have noticed into a
  // backup that is simply gone. Both halves are asserted at every case below —
  // either one on its own describes something milder than what happened. A
  // refusal that returns nothing is not this format's behaviour, and a
  // plaintext handed back in silence is just v2.
  console.log("\nKEYM v3 slot-table authentication (§5):");
  {
    const {
      encryptKeym2, decryptKeym2, addPasskeySlotKeym2, addShamirSlotKeym2, keym2SlotLen,
      KEYM2_VERSION_V2, KEYM2_VERSION_V3,
    } = await import("../src/lib/keym-v2.ts");

    // §3's layout, written out rather than imported — the same reason the
    // fixture generator writes it out. A tamper built from the implementation's
    // own idea of where the table starts would move with the implementation and
    // stop being the attack.
    const SLOT_COUNT_AT = 24;
    const TABLE_AT = 57;

    const V3_PT = "an heir needs this";
    const V3_PW = "owner passphrase — test only";

    /** The table with one slot cut out and `slot_count` decremented. */
    const withoutSlot = (c: Uint8Array, drop: number, width: number): Uint8Array => {
      const count = c[SLOT_COUNT_AT] as number;
      const head = c.slice(0, TABLE_AT);
      head[SLOT_COUNT_AT] = count - 1;
      const kept: number[] = [];
      for (let i = 0; i < count; i++) {
        if (i === drop) continue;
        kept.push(...c.subarray(TABLE_AT + i * width, TABLE_AT + (i + 1) * width));
      }
      // `slot_table_mac` at offset 25 is carried through untouched, because
      // that is precisely what the attacker cannot recompute: it is keyed from
      // the master key (§5.1), and holding no slot secret means holding no way
      // to re-seal the table (§5.3).
      return new Uint8Array([...head, ...kept, ...c.subarray(TABLE_AT + count * width)]);
    };

    /** The same two slots, in the other order. */
    const swapFirstTwo = (c: Uint8Array, width: number): Uint8Array => {
      const out = Uint8Array.from(c);
      const a = c.subarray(TABLE_AT, TABLE_AT + width);
      const b = c.subarray(TABLE_AT + width, TABLE_AT + 2 * width);
      out.set(b, TABLE_AT);
      out.set(a, TABLE_AT + width);
      return out;
    };

    /**
     * A decrypt that §5.2 requires to *succeed*, with the throw turned into a
     * named failure instead of an exception.
     *
     * CLAUDE.md's rule about unguarded calls, and this is the section it was
     * written for. The mistake every check below exists to catch — a reader
     * that refuses a container whose MAC does not match — makes `decryptKeym2`
     * *throw*. Left unguarded that ends the run in a traceback three checks
     * early, and a negative control that kills the process is indistinguishable
     * from one that never fired. Verified: with §5.2 rewritten as a refusal
     * this prints the two §5.2 lines as FAIL rather than a stack trace.
     */
    const mustOpen = async (
      label: string,
      run: () => Promise<{ data: Uint8Array; slotTableAuthentic: boolean | null }>
    ): Promise<{ data: Uint8Array; slotTableAuthentic: boolean | null } | null> => {
      try {
        return await run();
      } catch (err) {
        check(false, `${label} — threw instead of opening: ${(err as Error).message}`);
        return null;
      }
    };

    const CIPHERS: Array<[CipherId, string]> = [
      [CipherId.AES_256_GCM, "aes-256-gcm"],
      [CipherId.CHACHA20_POLY1305, "chacha20-poly1305"],
      [CipherId.CHAINED, "chained"],
    ];

    for (const [cipher, label] of CIPHERS) {
      // Every cipher, because `slot_len` follows the tag overhead: a strip that
      // cut the right number of bytes for AES would cut the wrong number for a
      // chained container, and an off-by-one there is indistinguishable from a
      // working detection unless all three are exercised.
      const width = keym2SlotLen(cipher);
      const base = await encryptKeym2(
        enc.encode(V3_PT),
        V3_PW,
        null,
        { kdf: PBKDF2_FAST, cipher },
        KEYM2_VERSION_V3
      );
      const prf = crypto.getRandomValues(new Uint8Array(32));
      const salt = crypto.getRandomValues(new Uint8Array(32));
      // §5.3. Enrolling re-seals the table, so this two-slot container is also
      // the check that a re-sealed MAC verifies at all — if it did not, every
      // `false` below would be right for the wrong reason.
      const two = await addPasskeySlotKeym2(base, { password: V3_PW }, prf, salt);

      const intact = await mustOpen(`${label} untouched`, () => decryptKeym2(two, V3_PW, null));
      check(
        intact !== null && dec.decode(intact.data) === V3_PT &&
          intact.slotTableAuthentic === true,
        `${label} — an enrolled, untouched v3 table authenticates`
      );
      const heir = await mustOpen(`${label} heir`, () =>
        decryptKeym2(two, "", null, undefined, prf)
      );
      check(
        heir !== null && dec.decode(heir.data) === V3_PT && heir.slotTableAuthentic === true,
        `${label} — and the enrolled heir opens it`
      );

      // §1.1, exactly: the heir's slot cut out, count decremented, MAC left as
      // written. No secret needed, and before v3 no trace.
      const stripped = withoutSlot(two, 1, width);
      const afterStrip = await mustOpen(`${label} stripped`, () =>
        decryptKeym2(stripped, V3_PW, null)
      );
      check(
        afterStrip !== null && dec.decode(afterStrip.data) === V3_PT,
        `${label} — a stripped container still returns the plaintext (§5.2)`
      );
      check(
        afterStrip?.slotTableAuthentic === false,
        `${label} — ...and reports that the table is not authentic (§5.2)`
      );
      await rejects(`${label} — the stripped heir is locked out for good`, () =>
        decryptKeym2(stripped, "", null, undefined, prf)
      );

      // The mirror image. Detection that only worked on the last slot would
      // pass every check above and still miss half the attack.
      const ownerGone = withoutSlot(two, 0, width);
      const afterOwnerGone = await mustOpen(`${label} slot 0 stripped`, () =>
        decryptKeym2(ownerGone, "", null, undefined, prf)
      );
      check(
        afterOwnerGone !== null && dec.decode(afterOwnerGone.data) === V3_PT &&
          afterOwnerGone.slotTableAuthentic === false,
        `${label} — stripping slot 0 is caught too, and the heir still opens it`
      );

      // §5.1: "every byte of the table, in order", which pins slot order as a
      // side effect. Reordering is inert as an attack — the unwrap walk tries
      // every slot — and that is what makes it worth asserting: the MAC has to
      // notice a change that changes nothing. A construction that hashed the
      // records as a set rather than a sequence would sail past this.
      const swapped = swapFirstTwo(two, width);
      const afterSwap = await mustOpen(`${label} reordered`, () =>
        decryptKeym2(swapped, V3_PW, null)
      );
      check(
        afterSwap !== null && dec.decode(afterSwap.data) === V3_PT &&
          afterSwap.slotTableAuthentic === false,
        `${label} — reordered slots still open, and are still reported`
      );

      // Tampering that is not a strip at all: one byte inside the heir's
      // record. The owner's slot is untouched and opens the container as
      // usual, so nothing about the length, the count or the unwrap can see
      // this. Only the MAC can.
      const flipped = Uint8Array.from(two);
      flipped[TABLE_AT + width] = (flipped[TABLE_AT + width] as number) ^ 0x01;
      const afterFlip = await mustOpen(`${label} flipped byte`, () =>
        decryptKeym2(flipped, V3_PW, null)
      );
      check(
        afterFlip !== null && dec.decode(afterFlip.data) === V3_PT &&
          afterFlip.slotTableAuthentic === false,
        `${label} — a single flipped byte in another slot is reported`
      );

      // §5.3 step 2. Every check above proves the strip is *detected*; these
      // prove the detection survives the owner continuing to use the app.
      //
      // The owner is the one person who can still open a container whose heir
      // slot was removed, because their slot is the one left. So the owner is
      // the one whose next enrolment recomputes the MAC over the attacker's
      // table and signs it with the real key — after which every reader is
      // told the table is authentic, correctly. Re-sealing without verifying
      // does not miss the evidence, it destroys it.
      await rejects(
        `${label} — enrolling a passkey on a stripped table is refused (§5.3)`,
        () => addPasskeySlotKeym2(stripped, { password: V3_PW },
          crypto.getRandomValues(new Uint8Array(32)),
          crypto.getRandomValues(new Uint8Array(32)))
      );
      await rejects(
        `${label} — enrolling a share set on a stripped table is refused (§5.3)`,
        () => addShamirSlotKeym2(stripped, { password: V3_PW }, 2, 3)
      );

      // The refusal is affordable precisely because §5.2 still holds: the
      // container was not touched, and it still opens. A reader refusing costs
      // the plaintext; a writer refusing costs one edit, and there is another
      // way to make it.
      const afterRefusal = await mustOpen(`${label} after a refused edit`, () =>
        decryptKeym2(stripped, V3_PW, null)
      );
      check(
        afterRefusal !== null && dec.decode(afterRefusal.data) === V3_PT,
        `${label} — a refused edit leaves the backup readable`
      );

      // Not a general block on enrolment: an intact table still takes one.
      const three = await addShamirSlotKeym2(two, { password: V3_PW }, 2, 3);
      const afterEnrol = await mustOpen(`${label} enrolled`, () =>
        decryptKeym2(three.container, V3_PW, null)
      );
      check(
        afterEnrol !== null && afterEnrol.slotTableAuthentic === true,
        `${label} — enrolling on an intact table still works and re-seals it`
      );
    }

    // §5.2's third value, and the one a boolean cannot express. A v2 container
    // carries no `slot_table_mac`, so nothing is claimed about its table — and
    // a reader that collapsed "no claim" into `false` would accuse every backup
    // written before this revision of having been tampered with.
    // Asks for v2 explicitly. This container exists to be the version that
    // carries no slot_table_mac, and the default is v3 now — left implicit it
    // would quietly become a v3 container and assert `null` about a table that
    // has a perfectly good MAC, which is the opposite of the check.
    const v2Container = await encryptKeym2(
      enc.encode(V3_PT),
      V3_PW,
      null,
      { kdf: PBKDF2_FAST, cipher: CipherId.AES_256_GCM },
      KEYM2_VERSION_V2
    );
    const v2Read = await mustOpen("v2 container", () =>
      decryptKeym2(v2Container, V3_PW, null)
    );
    check(
      v2Read !== null && dec.decode(v2Read.data) === V3_PT &&
        v2Read.slotTableAuthentic === null,
      "a v2 container claims nothing about its slot table, rather than claiming it is bad"
    );
  }

  // ---- 7. The unlock walk finishes what it started ----
  //
  // §4.4 says a slot that cannot be used disqualifies itself, never the walk.
  // That was implemented for slots that fail to *unwrap*. A slot that unwraps
  // to the wrong master key is the case it missed, and the case an attacker
  // can arrange on a v2 container:
  //
  //   Take any container whose password you know — your own will do, if the
  //   victim's password is one you also know, or one you set for them. Splice
  //   its slot in *ahead* of theirs and bump slot_count. Their password now
  //   opens your slot first, yields your master key, and the payload fails to
  //   authenticate. A walk that committed to the first unwrap rejects there,
  //   with the victim's own valid slot untouched at index 1.
  //
  // No confidentiality loss — the attacker learns nothing and the payload never
  // opens for them. Availability only, which for a backup is the whole product.
  //
  // v3 closes the way in: container_id is in the slot AAD, so a foreign slot no
  // longer unwraps at all. v2 has no such binding and stays readable forever,
  // which is why this is tested against v2.
  console.log("\nThe unlock walk resumes when a slot yields the wrong key:");
  {
    const {
      encryptKeym2WithExplicitSecrets, decryptKeym2, keym2SlotLen, KEYM2_VERSION_V2,
    } = await import("../src/lib/keym-v2.ts");

    // v2's offsets, written out for the same reason §3's are above.
    const V2_COUNT_AT = 8;
    const V2_TABLE_AT = 9;

    const PW = "the victim's password, which the attacker also knows";
    const MINE = "attacker's own container";
    const THEIRS = "the life savings";
    const opts = {
      kdf: { kdf: KdfId.PBKDF2, params: { iterations: 600_000 } },
      cipher: CipherId.AES_256_GCM,
    } as const;
    const width = keym2SlotLen(CipherId.AES_256_GCM);

    /** `mustOpen` from the §5 block above, which is scoped to it. */
    const opens = async (label: string, run: () => Promise<{ data: Uint8Array }>) => {
      try {
        return await run();
      } catch (e) {
        check(false, `${label} did not open: ${(e as Error).message}`);
        return null;
      }
    };

    // Same salt in both, so the two slots derive the same slot key and the
    // spliced one genuinely verifies. Different master keys, so it unwraps to
    // the wrong one — which is the whole point. Explicit secrets because this
    // attack needs the salts to collide, and a random salt would make the test
    // pass by never reproducing the bug.
    const salt = new Uint8Array(32).fill(0x9e);
    const attacker = await encryptKeym2WithExplicitSecrets(
      enc.encode(MINE), PW, null, opts, salt, new Uint8Array(32).fill(0x01), KEYM2_VERSION_V2
    );
    const victim = await encryptKeym2WithExplicitSecrets(
      enc.encode(THEIRS), PW, null, opts, salt, new Uint8Array(32).fill(0x02), KEYM2_VERSION_V2
    );

    const shadowed = new Uint8Array(victim.length + width);
    shadowed.set(victim.subarray(0, V2_TABLE_AT), 0);
    shadowed[V2_COUNT_AT] = 2;
    shadowed.set(attacker.subarray(V2_TABLE_AT, V2_TABLE_AT + width), V2_TABLE_AT);
    shadowed.set(victim.subarray(V2_TABLE_AT), V2_TABLE_AT + width);

    // The attack has to actually be built before the fix can be said to survive
    // it. If the spliced slot did not unwrap, the walk would skip it for the
    // reason it always did and this would prove nothing.
    const attackerOpens = await opens("the spliced slot's own container", () =>
      decryptKeym2(attacker, PW, null)
    );
    check(
      attackerOpens !== null && dec.decode(attackerOpens.data) === MINE,
      "setup — the spliced slot is a real slot that really opens its own container"
    );

    const opened = await opens("shadowed container", () => decryptKeym2(shadowed, PW, null));
    check(
      opened !== null && dec.decode(opened.data) === THEIRS,
      "a slot spliced ahead of the owner's does not brick the container"
    );
    const shadowedFull = await decryptKeym2(shadowed, PW, null);
    check(
      shadowedFull.slot !== undefined && shadowedFull.keyFileUsed === false,
      "...and the slot reported is the one that actually opened it"
    );

    // The other direction, so the check above cannot be satisfied by a walk
    // that ignores the payload and returns whatever it finds: a container whose
    // every slot is foreign must still fail, and fail the same generic way.
    const allForeign = new Uint8Array(victim.length);
    allForeign.set(victim.subarray(0, V2_TABLE_AT), 0);
    allForeign.set(attacker.subarray(V2_TABLE_AT, V2_TABLE_AT + width), V2_TABLE_AT);
    allForeign.set(victim.subarray(V2_TABLE_AT + width), V2_TABLE_AT + width);
    await rejects(
      "a container with no slot that opens its payload is still refused",
      () => decryptKeym2(allForeign, PW, null)
    );
  }

  // ---- 8. The advisory describes the slot that opened ----
  //
  // §6's floor is write-side, so a container from before it still opens and now
  // says it is old. Which slot that notice is *about* was never decided: the UI
  // read slot 0, because when this was written every container had exactly one.
  //
  // With a share set enrolled it has two, and they no longer agree. An heir
  // unlocking with paper shares — an HKDF slot with no cost parameters, and
  // nothing weak about it — was told the backup was made with 1,000 PBKDF2
  // iterations, which describes a slot they do not hold and cannot use. And
  // since slot order is not fixed, anyone who can write the file chooses which
  // slot the owner is told about.
  //
  // The reader has always known which slot answered. It just did not say.
  console.log("\nThe weak-KDF advisory names the slot that opened, not slot 0:");
  {
    const { dearmorKeym2, addShamirSlotKeym2 } = await import("../src/lib/keym-v2.ts");
    const { decryptData } = await import("../src/lib/keymaker-crypto.ts");
    const weak = JSON.parse(
      readFileSync(join(HERE, "..", "tests", "browser", "fixtures", "weak-legacy-kdf.json"), "utf8")
    ) as { armor: string; password: string; plaintext: string; iterations: number };
    // `describeWeakKdf` formats with a thousands separator, so the bare number
    // never appears in the string it produces.
    const ITERS = weak.iterations.toLocaleString("en-US");

    const oneSlot = dearmorKeym2(weak.armor);
    const buf = (u: Uint8Array): ArrayBuffer =>
      u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;

    // The single-slot case, unchanged: the only slot there is, is the one that
    // opened, so the advisory was already right and must stay right.
    const alone = await decryptData(buf(oneSlot), weak.password, null);
    check(
      dec.decode(new Uint8Array(alone.data)) === weak.plaintext,
      "the pre-floor fixture still opens"
    );
    check(
      alone.weakKdf !== null && alone.weakKdf.includes(ITERS),
      `a one-slot weak container still reports its parameters (got ${alone.weakKdf})`
    );

    // Enrol a share set. Nothing about slot 0 changes; the container simply now
    // has a second way in whose KDF is HKDF, which §6 pins for Shamir slots and
    // which has no cost parameters to be weak.
    const { container: twoSlot, shares } = await addShamirSlotKeym2(
      oneSlot, { password: weak.password, keyFile: null }, 2, 3
    );

    const byPassword = await decryptData(buf(twoSlot), weak.password, null);
    check(
      byPassword.weakKdf !== null && byPassword.weakKdf.includes(ITERS),
      `unlocking the weak slot still reports it (got ${byPassword.weakKdf})`
    );

    const byShares = await decryptData(buf(twoSlot), "", null, shares.slice(0, 2));
    check(
      dec.decode(new Uint8Array(byShares.data)) === weak.plaintext,
      "the heir's shares open the same container"
    );
    check(
      byShares.weakKdf === null,
      `unlocking with shares reported "${byShares.weakKdf}" — that is slot 0's ` +
        `weakness, described to someone holding a slot that has no cost parameters at all`
    );
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
