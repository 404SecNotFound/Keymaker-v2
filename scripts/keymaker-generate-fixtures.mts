/**
 * Generator for the frozen KEYM fixture corpus under scripts/fixtures/keymaker/.
 *
 *     npx tsx scripts/keymaker-generate-fixtures.mts
 *
 * Produces one ciphertext per (version × KDF × cipher) combo. KDF params are
 * intentionally modest (PBKDF2 100k, Argon2id 16 MiB) — the wire format stores
 * them, so they remain valid vectors.
 *
 * ## Additive by construction, not by discipline
 *
 * The corpus is append-only: a fixture is a promise that a container written on
 * a particular day still opens, and regenerating one silently retires the
 * evidence it existed to provide.
 *
 * The first version of this script rewrote every `.keym` file and the whole of
 * `fixtures.json` on each run, so honouring append-only meant remembering not
 * to run it. That is the wrong place for the guarantee. Now a combo whose file
 * already exists is skipped and its metadata entry is carried through
 * untouched — running this twice is a no-op, and adding v2 vectors could not
 * disturb the v1 ones even deliberately.
 *
 * Existing entries are also passed through *exactly* as parsed rather than
 * rebuilt from the combo table, which is why v1 entries have no `version` field
 * and the reader defaults it to 1. Adding the field would have meant editing
 * six entries that are supposed to be frozen, to record something already
 * implied by their bytes.
 */
import { writeFileSync, mkdirSync, existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  encryptData,
  encryptContainer,
  KdfId,
  CipherId,
  type KdfParams,
} from "../src/lib/keymaker-crypto.ts";

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

// v1's vectors were written before §6's *lower* bound existed, at 100k PBKDF2
// iterations. They still open, and must — a reader stays permissive so that
// files written with older or lower settings are not stranded, and proving
// exactly that is half of what those fixtures are for.
//
// New vectors cannot use those numbers: `validateKdfParams(kdf, "encrypt")`
// refuses to *write* below the policy floor, which is the asymmetry working as
// intended. So v2's PBKDF2 vectors sit at the floor itself. Argon2id's 16 MiB
// was already above its floor and is unchanged, which keeps the two versions
// comparable on the axis that did not have to move.
const PBKDF2_V1_PARAMS: KdfParams = { kdf: KdfId.PBKDF2, params: { iterations: 100_000 } };
const PBKDF2_V2_PARAMS: KdfParams = { kdf: KdfId.PBKDF2, params: { iterations: 600_000 } };
const ARGON_PARAMS: KdfParams = {
  kdf: KdfId.ARGON2ID,
  params: { timeCost: 2, memoryKiB: 16384, parallelism: 2 },
};

interface Combo {
  name: string;
  version: 1 | 2;
  kdf: KdfParams;
  cipher: CipherId;
  kdfName: string;
  cipherName: string;
}

// `slug` is what appears in the file name. It is spelled out rather than
// derived from `cipherName`, because the v1 names are load-bearing — they are
// the names of files that already exist and must not be renamed.
const CIPHERS: Array<{ id: CipherId; name: string; slug: string }> = [
  { id: CipherId.AES_256_GCM, name: "aes-256-gcm", slug: "aes256gcm" },
  { id: CipherId.CHACHA20_POLY1305, name: "chacha20-poly1305", slug: "chacha20poly1305" },
  { id: CipherId.CHAINED, name: "chained", slug: "chained" },
];
const combos: Combo[] = [];
for (const version of [1, 2] as const) {
  const kdfs: Array<{ params: KdfParams; name: string }> = [
    { params: version === 1 ? PBKDF2_V1_PARAMS : PBKDF2_V2_PARAMS, name: "pbkdf2" },
    { params: ARGON_PARAMS, name: "argon2id" },
  ];
  for (const kdf of kdfs) {
    for (const cipher of CIPHERS) {
      const base = `${kdf.name}-${cipher.slug}`;
      combos.push({
        name: version === 1 ? base : `v2-${base}`,
        version,
        kdf: kdf.params,
        cipher: cipher.id,
        kdfName: kdf.name,
        cipherName: cipher.name,
      });
    }
  }
}

async function main() {
  const metaPath = join(DIR, "fixtures.json");
  const existing = existsSync(metaPath)
    ? JSON.parse(readFileSync(metaPath, "utf8"))
    : { fixtures: [] };
  const byName = new Map<string, any>(existing.fixtures.map((f: any) => [f.name, f]));

  const fixtures: any[] = [];
  let wrote = 0;
  let kept = 0;

  for (const c of combos) {
    const file = `${c.name}.keym`;
    const prior = byName.get(c.name);

    if (prior && existsSync(join(DIR, file))) {
      // Append-only: the ciphertext and its metadata are both left alone.
      fixtures.push(prior);
      kept++;
      continue;
    }

    const plaintext = `Keymaker fixture — v${c.version} ${c.kdfName} / ${c.cipherName}`;
    const keyFile = c.cipherName === "chacha20-poly1305" ? hexToArrayBuffer(KEYFILE_HEX) : null;
    const write = c.version === 1 ? encryptData : encryptContainer;
    const ct = await write(
      new TextEncoder().encode(plaintext).buffer as ArrayBuffer,
      PASSWORD,
      keyFile ? keyFile.slice(0) : null,
      { kdf: c.kdf, cipher: c.cipher }
    );
    writeFileSync(join(DIR, file), Buffer.from(ct));
    fixtures.push({
      name: c.name,
      file,
      version: c.version,
      kdf: c.kdfName,
      cipher: c.cipherName,
      keyFile: keyFile !== null,
      plaintext,
    });
    wrote++;
    console.log(`wrote ${file} (${ct.byteLength} bytes)`);
  }

  writeFileSync(
    metaPath,
    JSON.stringify(
      {
        format: "KEYM",
        version: 1,
        password: PASSWORD,
        keyFileHex: KEYFILE_HEX,
        note:
          "APPEND-ONLY corpus. Test-only credentials — never use for real data. " +
          "A fixture with no `version` field is v1; the field was added when v2 " +
          "vectors joined the corpus and the v1 entries were left untouched.",
        fixtures,
      },
      null,
      2
    ) + "\n"
  );
  console.log(`wrote fixtures.json — ${kept} kept, ${wrote} new, ${fixtures.length} total`);
}

main().catch((err) => {
  console.error("FATAL:", err);
  process.exit(1);
});
