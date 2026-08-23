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
import {
  addShamirSlotKeym2,
  addPasskeySlotKeym2,
  encryptKeym2,
  keym2SlotLen,
  KEYM2_VERSION_V3,
} from "../src/lib/keym-v2.ts";
import { buildSelfExtractingPage } from "../src/lib/keym-v2-selfextract.ts";

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
  version: 1 | 2 | 3;
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
// v3 reuses v2's KDF parameters exactly. The revision changed the header and
// added a MAC; it did not move the cost floor, and holding the derivation
// settings still is what makes a v2 and a v3 vector comparable on the one axis
// that did change.
for (const version of [1, 2, 3] as const) {
  const kdfs: Array<{ params: KdfParams; name: string }> = [
    { params: version === 1 ? PBKDF2_V1_PARAMS : PBKDF2_V2_PARAMS, name: "pbkdf2" },
    { params: ARGON_PARAMS, name: "argon2id" },
  ];
  for (const kdf of kdfs) {
    for (const cipher of CIPHERS) {
      const base = `${kdf.name}-${cipher.slug}`;
      combos.push({
        name: version === 1 ? base : `v${version}-${base}`,
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
    // v3 goes through `encryptKeym2` directly rather than `encryptContainer`,
    // because the version is not something the container-level entry point
    // takes: it writes whatever `KEYM2_VERSION` currently names, and that is
    // still v2 (keym-v2.ts's note on why). A vector for a version the app does
    // not yet default to has to say which version it wants.
    const ct =
      c.version === 3
        ? await encryptKeym2(
            new TextEncoder().encode(plaintext),
            PASSWORD,
            keyFile ? new Uint8Array(keyFile.slice(0)) : null,
            { kdf: c.kdf, cipher: c.cipher },
            KEYM2_VERSION_V3
          )
        : await (c.version === 1 ? encryptData : encryptContainer)(
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
      // v3 §5.2. Recorded per fixture rather than inferred from the version,
      // so that the one vector below whose table was tampered with states its
      // expectation in the same field as the ones whose table is intact —
      // a reader that inferred "v3 ⇒ authentic" could not express it.
      ...(c.version === 3 ? { slotTableAuthentic: true } : {}),
    });
    wrote++;
    console.log(`wrote ${file} (${ct.byteLength} bytes)`);
  }

  // §4.6. One share-set fixture per cipher, because the wrap uses the
  // container's cipher — a chained container chains its wrap too — so a bug in
  // the chained path would be invisible in an AES-only vector.
  //
  // These carry their shares in the metadata, which is the point: a fixture is
  // a promise that a container written today still opens tomorrow, and for a
  // share set that promise is about the *printed strings*, not only the bytes.
  // The corpus is the only place they can be frozen.
  for (const cipher of CIPHERS) {
    const name = `v2-shamir-${cipher.slug}`;
    const file = `${name}.keym`;
    const prior = byName.get(name);
    if (prior && existsSync(join(DIR, file))) {
      fixtures.push(prior);
      kept++;
      continue;
    }

    const plaintext = `Keymaker fixture — v2 shamir 3-of-5 / ${cipher.name}`;
    const base = await encryptContainer(
      new TextEncoder().encode(plaintext).buffer as ArrayBuffer,
      PASSWORD,
      null,
      { kdf: PBKDF2_V2_PARAMS, cipher: cipher.id }
    );
    const { container, shares } = await addShamirSlotKeym2(
      new Uint8Array(base),
      { password: PASSWORD },
      3,
      5
    );
    writeFileSync(join(DIR, file), Buffer.from(container));
    fixtures.push({
      name,
      file,
      version: 2,
      kdf: "pbkdf2",
      cipher: cipher.name,
      keyFile: false,
      plaintext,
      // Real random secrets, not pinned: byte equality against the reference is
      // crosstest2.py's job. What a fixture pins is that these exact strings
      // keep opening this exact container.
      shamir: { threshold: 3, shares },
    });
    wrote++;
    console.log(`wrote ${file} (${container.byteLength} bytes, 5 shares)`);
  }

  // §4.7. Passkey slots, one per cipher — the slot's length follows the
  // cipher's tag overhead exactly as every other slot's does, so a
  // cipher-specific mistake in the wrap only shows up if all three are frozen.
  //
  // The PRF output is recorded in the metadata for the same reason the shares
  // are: it is the only way back into the container, no authenticator exists
  // here to produce it again, and a fixture nobody can open is not a fixture.
  // It stands in for a security key, which is all a PRF output ever is to the
  // format — 32 bytes that came from somewhere the format does not model.
  for (const cipher of CIPHERS) {
    const name = `v2-passkey-${cipher.slug}`;
    const file = `${name}.keym`;
    const prior = byName.get(name);
    if (prior && existsSync(join(DIR, file))) {
      fixtures.push(prior);
      kept++;
      continue;
    }

    const plaintext = `Keymaker fixture — v2 passkey / ${cipher.name}`;
    const base = await encryptContainer(
      new TextEncoder().encode(plaintext).buffer as ArrayBuffer,
      PASSWORD,
      null,
      { kdf: PBKDF2_V2_PARAMS, cipher: cipher.id }
    );
    // §4.7 keeps the salt out of the record for the PRF, but the *slot* salt is
    // still chosen by the caller here, because deriving the PRF salt needs it
    // before the authenticator is asked anything.
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const prfOutput = crypto.getRandomValues(new Uint8Array(32));
    const container = await addPasskeySlotKeym2(
      new Uint8Array(base),
      { password: PASSWORD },
      prfOutput,
      salt
    );
    writeFileSync(join(DIR, file), Buffer.from(container));
    fixtures.push({
      name,
      file,
      version: 2,
      kdf: "pbkdf2",
      cipher: cipher.name,
      keyFile: false,
      plaintext,
      passkey: { prfOutputHex: Buffer.from(prfOutput).toString("hex") },
    });
    wrote++;
    console.log(`wrote ${file} (${container.byteLength} bytes, passkey slot)`);
  }

  // ---- KEYM v3 (docs/FORMAT-V3-DESIGN.md) ---------------------------------
  //
  // The enrolment paths are the ones worth freezing. §5.3 is where v3 adds work
  // v2 never did: adding or removing a slot must *re-seal* `slot_table_mac`,
  // and a re-seal that produced a MAC nobody could verify afterwards would look
  // exactly like a correct one on the day it was written. Only a container
  // written then and read now can tell those two apart.
  for (const cipher of CIPHERS) {
    const name = `v3-shamir-${cipher.slug}`;
    const file = `${name}.keym`;
    const prior = byName.get(name);
    if (prior && existsSync(join(DIR, file))) {
      fixtures.push(prior);
      kept++;
      continue;
    }

    const plaintext = `Keymaker fixture — v3 shamir 3-of-5 / ${cipher.name}`;
    const base = await encryptKeym2(
      new TextEncoder().encode(plaintext),
      PASSWORD,
      null,
      { kdf: PBKDF2_V2_PARAMS, cipher: cipher.id },
      KEYM2_VERSION_V3
    );
    const { container, shares } = await addShamirSlotKeym2(base, { password: PASSWORD }, 3, 5);
    writeFileSync(join(DIR, file), Buffer.from(container));
    fixtures.push({
      name,
      file,
      version: 3,
      kdf: "pbkdf2",
      cipher: cipher.name,
      keyFile: false,
      plaintext,
      shamir: { threshold: 3, shares },
      slotTableAuthentic: true,
    });
    wrote++;
    console.log(`wrote ${file} (${container.byteLength} bytes, 5 shares, re-sealed table)`);
  }

  for (const cipher of CIPHERS) {
    const name = `v3-passkey-${cipher.slug}`;
    const file = `${name}.keym`;
    const prior = byName.get(name);
    if (prior && existsSync(join(DIR, file))) {
      fixtures.push(prior);
      kept++;
      continue;
    }

    const plaintext = `Keymaker fixture — v3 passkey / ${cipher.name}`;
    const base = await encryptKeym2(
      new TextEncoder().encode(plaintext),
      PASSWORD,
      null,
      { kdf: PBKDF2_V2_PARAMS, cipher: cipher.id },
      KEYM2_VERSION_V3
    );
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const prfOutput = crypto.getRandomValues(new Uint8Array(32));
    const container = await addPasskeySlotKeym2(base, { password: PASSWORD }, prfOutput, salt);
    writeFileSync(join(DIR, file), Buffer.from(container));
    fixtures.push({
      name,
      file,
      version: 3,
      kdf: "pbkdf2",
      cipher: cipher.name,
      keyFile: false,
      plaintext,
      passkey: { prfOutputHex: Buffer.from(prfOutput).toString("hex") },
      slotTableAuthentic: true,
    });
    wrote++;
    console.log(`wrote ${file} (${container.byteLength} bytes, passkey slot, re-sealed table)`);
  }

  // §1.1's attack, frozen as bytes. This is the container v3 exists for.
  //
  // Two slots — the owner's password and an heir's passkey — and then the
  // heir's slot is cut out and `slot_count` decremented, which is the whole of
  // the attack: no key material is needed, the owner still opens the file
  // normally, and before v3 nothing about it looked wrong. The heir is locked
  // out permanently and finds out at the worst possible moment.
  //
  // Freezing it rather than only building one at test time pins the detection
  // against a byte pattern that cannot drift with the generator: if
  // `verifySlotTable` ever quietly started returning true, a container
  // constructed by the same code that verifies it could agree with itself,
  // and this one could not.
  //
  // §5.2 is why it belongs in a corpus of things that *open*. A stripped
  // container must still hand back its plaintext — refusing would turn
  // detectable tampering into a lost backup — so this vector makes the same
  // promise every other one here makes, plus one more: that the reader says so.
  {
    const name = "v3-stripped-aes256gcm";
    const file = `${name}.keym`;
    const prior = byName.get(name);
    if (prior && existsSync(join(DIR, file))) {
      fixtures.push(prior);
      kept++;
    } else {
      const plaintext = "Keymaker fixture — v3 stripped slot / aes-256-gcm";
      const base = await encryptKeym2(
        new TextEncoder().encode(plaintext),
        PASSWORD,
        null,
        { kdf: PBKDF2_V2_PARAMS, cipher: CipherId.AES_256_GCM },
        KEYM2_VERSION_V3
      );
      const salt = crypto.getRandomValues(new Uint8Array(32));
      const prfOutput = crypto.getRandomValues(new Uint8Array(32));
      const enrolled = await addPasskeySlotKeym2(base, { password: PASSWORD }, prfOutput, salt);

      // v3 §3's layout, written out rather than imported. The offsets are the
      // one thing a fixture generator should state for itself: taking them from
      // the implementation under test would make a vector that agrees with
      // whatever that implementation currently believes.
      const SLOT_COUNT_OFFSET_V3 = 24;
      const SLOT_TABLE_OFFSET_V3 = 57;
      const width = keym2SlotLen(CipherId.AES_256_GCM);
      if (enrolled[SLOT_COUNT_OFFSET_V3] !== 2) {
        throw new Error(`expected 2 slots to strip from, found ${enrolled[SLOT_COUNT_OFFSET_V3]}`);
      }
      const head = enrolled.slice(0, SLOT_TABLE_OFFSET_V3);
      head[SLOT_COUNT_OFFSET_V3] = 1;
      const stripped = new Uint8Array([
        ...head,
        // Slot 0 — the owner's passphrase — survives. Slot 1, the heir's, does
        // not. `slot_table_mac` at offset 25 is left exactly as written, which
        // is what the attacker has no way to recompute: it is keyed from the
        // master key (§5.1), and holding no slot secret means holding no way
        // to re-seal (§5.3).
        ...enrolled.subarray(SLOT_TABLE_OFFSET_V3, SLOT_TABLE_OFFSET_V3 + width),
        ...enrolled.subarray(SLOT_TABLE_OFFSET_V3 + 2 * width),
      ]);

      writeFileSync(join(DIR, file), Buffer.from(stripped));
      fixtures.push({
        name,
        file,
        version: 3,
        kdf: "pbkdf2",
        cipher: "aes-256-gcm",
        keyFile: false,
        plaintext,
        // The credential that was cut out. Kept so a reader can prove the harm
        // as well as the detection: this PRF output opened the container before
        // the strip and must not open it after.
        strippedPasskey: { prfOutputHex: Buffer.from(prfOutput).toString("hex") },
        slotTableAuthentic: false,
      });
      wrote++;
      console.log(`wrote ${file} (${stripped.byteLength} bytes, heir's slot stripped)`);
    }
  }

  // §7.2. A self-extracting page, frozen whole.
  //
  // What this pins is narrower and more important than "the container opens":
  // it is that a page written on this day stays *extractable* — that the
  // sentinels, the armor inside them and the way the two are nested do not
  // drift out from under a file already sitting in someone's drawer. The
  // decryptor source in the page will change; the container in it must not have
  // to. That is the artefact's entire durability claim, and a frozen page is
  // the only thing that can hold anyone to it.
  //
  // The date and version are literals rather than the clock, so re-running this
  // generator on a corpus that already has the page is genuinely a no-op.
  {
    const name = "v2-selfextract";
    const file = `${name}.html`;
    const prior = byName.get(name);
    if (prior && existsSync(join(DIR, file))) {
      fixtures.push(prior);
      kept++;
    } else {
      const plaintext = "Keymaker fixture — v2 self-extracting page / aes-256-gcm";
      const container = await encryptContainer(
        new TextEncoder().encode(plaintext).buffer as ArrayBuffer,
        PASSWORD,
        null,
        { kdf: PBKDF2_V2_PARAMS, cipher: CipherId.AES_256_GCM }
      );
      const page = buildSelfExtractingPage({
        container: new Uint8Array(container),
        createdOn: "2026-08-15",
        appVersion: "2.0.0",
      });
      writeFileSync(join(DIR, file), page, "utf8");
      fixtures.push({
        name,
        file,
        version: 2,
        kdf: "pbkdf2",
        cipher: "aes-256-gcm",
        keyFile: false,
        plaintext,
        selfextract: true,
      });
      wrote++;
      console.log(`wrote ${file} (${page.length} bytes)`);
    }
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
          "vectors joined the corpus and the v1 entries were left untouched. " +
          "`slotTableAuthentic` appears only on v3 vectors, which are the only " +
          "ones carrying a slot_table_mac: true where the table is intact, " +
          "false for the one vector whose slot was stripped (v3 §5.2 — it must " +
          "still open, and the reader must still report the table has changed).",
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
