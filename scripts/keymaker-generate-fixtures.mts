/**
 * One-shot generator for the frozen KEYM fixture corpus under
 * scripts/fixtures/keymaker/. Run ONLY when intentionally adding new
 * fixtures (append-only tradition — never regenerate existing ones):
 *
 *     npx tsx scripts/keymaker-generate-fixtures.mts
 *
 * Produces one ciphertext per (KDF × cipher) combo. KDF params are
 * intentionally modest (PBKDF2 100k, Argon2id 16 MiB) — the wire format
 * stores them, so they remain valid vectors.
 */
import { writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { encryptData, KdfId, CipherId, type KdfParams } from "../src/lib/keymaker-crypto.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const DIR = join(HERE, "fixtures", "keymaker");
mkdirSync(DIR, { recursive: true });

const PASSWORD = "correct horse battery staple — test only";
const KEYFILE_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

function hexToArrayBuffer(hex: string): ArrayBuffer {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out.buffer as ArrayBuffer;
}

const PBKDF2_PARAMS: KdfParams = { kdf: KdfId.PBKDF2, params: { iterations: 100_000 } };
const ARGON_PARAMS: KdfParams = {
  kdf: KdfId.ARGON2ID,
  params: { timeCost: 2, memoryKiB: 16384, parallelism: 2 },
};

const combos = [
  { name: "pbkdf2-aes256gcm", kdf: PBKDF2_PARAMS, cipher: CipherId.AES_256_GCM, kdfName: "pbkdf2", cipherName: "aes-256-gcm" },
  { name: "pbkdf2-chacha20poly1305", kdf: PBKDF2_PARAMS, cipher: CipherId.CHACHA20_POLY1305, kdfName: "pbkdf2", cipherName: "chacha20-poly1305" },
  { name: "pbkdf2-chained", kdf: PBKDF2_PARAMS, cipher: CipherId.CHAINED, kdfName: "pbkdf2", cipherName: "chained" },
  { name: "argon2id-aes256gcm", kdf: ARGON_PARAMS, cipher: CipherId.AES_256_GCM, kdfName: "argon2id", cipherName: "aes-256-gcm" },
  { name: "argon2id-chacha20poly1305", kdf: ARGON_PARAMS, cipher: CipherId.CHACHA20_POLY1305, kdfName: "argon2id", cipherName: "chacha20-poly1305" },
  { name: "argon2id-chained", kdf: ARGON_PARAMS, cipher: CipherId.CHAINED, kdfName: "argon2id", cipherName: "chained" },
];

async function main() {
  const fixtures: any[] = [];
  for (const c of combos) {
    const plaintext = `Keymaker fixture — ${c.kdfName} / ${c.cipherName}`;
    const keyFile = c.cipherName === "chacha20-poly1305" ? hexToArrayBuffer(KEYFILE_HEX) : null;
    const ct = await encryptData(
      new TextEncoder().encode(plaintext).buffer as ArrayBuffer,
      PASSWORD,
      keyFile ? keyFile.slice(0) : null,
      { kdf: c.kdf, cipher: c.cipher }
    );
    const file = `${c.name}.keym`;
    writeFileSync(join(DIR, file), Buffer.from(ct));
    fixtures.push({
      name: c.name,
      file,
      kdf: c.kdfName,
      cipher: c.cipherName,
      keyFile: keyFile !== null,
      plaintext,
    });
    console.log(`wrote ${file} (${ct.byteLength} bytes)`);
  }
  writeFileSync(
    join(DIR, "fixtures.json"),
    JSON.stringify(
      {
        format: "KEYM",
        version: 1,
        password: PASSWORD,
        keyFileHex: KEYFILE_HEX,
        note: "APPEND-ONLY corpus. Test-only credentials — never use for real data.",
        fixtures,
      },
      null,
      2
    ) + "\n"
  );
  console.log("wrote fixtures.json");
}

main().catch((err) => {
  console.error("FATAL:", err);
  process.exit(1);
});
