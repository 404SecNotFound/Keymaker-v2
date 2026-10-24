/**
 * The shipping TypeScript against docs/vectors/ (see its README).
 *
 * reference/vectors.py generates the pack from keym2.py and checks keym2.py
 * reproduces it; this checks the app's own code reproduces the same bytes, one
 * vector at a time, each failure named by the vector's id. Python writes and
 * the TypeScript reproduces, never the reverse.
 *
 *   node scripts/keymaker-test.mjs vectors
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { CipherId, KdfId, type KdfParams, loadHashWasm, loadNoble } from "../src/lib/keymaker-crypto.ts";
import {
  armorKeym2,
  armorKeym2Compact,
  decryptKeym2,
  dearmorKeym2,
  encryptKeym2WithExplicitSecrets,
  keym2PaddedLen,
  keym2VectorIntermediates,
} from "../src/lib/keym-v2.ts";
import {
  combineShares,
  decodeShareAny,
  encodeShare,
  encodeShareV2,
  shamirSplit,
  shareSetCode,
  shareSetId,
  shareSetIdV2,
} from "../src/lib/keym-v2-shamir.ts";
import {
  decodePaperPartsAny,
  encodePaperParts,
  encodePaperPartsV2,
  splitPaperParts,
} from "../src/lib/keym-v2-paper.ts";
import { IGNORABLE_CHARS, textLines } from "../src/lib/keym-text.ts";
import { parseShareLines } from "../src/components/encryptor/shared.ts";

// Asserted here and in reference/vectors.py, so a vector that silently stopped
// being listed fails both. Adding a vector means changing both.
const VECTOR_COUNT = 94;
const FAMILIES = ["primitives", "containers", "shares", "parts", "text", "reject", "accept"] as const;

const PACK = join(dirname(fileURLToPath(import.meta.url)), "..", "docs", "vectors");

type Vector = Record<string, any> & { id: string };

let passed = 0;
let failures = 0;
function check(ok: boolean, message: string): void {
  if (ok) {
    passed++;
  } else {
    failures++;
    console.error(`  FAIL  ${message}`);
  }
}

const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const bytes = (h: string): Uint8Array => Uint8Array.from(Buffer.from(h, "hex"));
const same = (a: unknown, b: unknown): boolean => JSON.stringify(a) === JSON.stringify(b);

/**
 * A crash is not a refusal. A reader that throws a TypeError on input it should
 * refuse has a bug the pack exists to find, so it fails the row.
 */
function crashed(e: unknown): boolean {
  return e instanceof TypeError || e instanceof RangeError
    || e instanceof ReferenceError || e instanceof SyntaxError;
}

/** Run one vector's checks; an unexpected throw fails that vector by name. */
async function each(family: string, v: Vector, fn: () => Promise<void>): Promise<void> {
  try {
    await fn();
  } catch (e) {
    check(false, `${family}/${v.id}: threw ${String(e)}`);
  }
}

const pack: Record<string, Vector[]> = {};
let counted = 0;
for (const family of FAMILIES) {
  const file = JSON.parse(readFileSync(join(PACK, `${family}.json`), "utf8"));
  check(file.family === family && file.format === 1, `${family}.json: not in the pack's format`);
  // A vector with an erratum is superseded: frozen as published, held to by
  // nobody. The README tells a third reader to skip it too.
  pack[family] = (file.vectors as Vector[]).filter((v) => v.erratum === undefined);
  counted += (file.vectors as Vector[]).length;
}
const ids = FAMILIES.flatMap((f) => (pack[f] ?? []).map((v) => v.id));
check(new Set(ids).size === ids.length, "an id is used twice in the pack");
const total = counted;
check(total === VECTOR_COUNT, `the pack holds ${total} vectors, VECTOR_COUNT says ${VECTOR_COUNT}`);

// ---- primitives.json: the libraries the app loads, against published values ----
console.log("Primitives (published known answers):");
for (const v of pack.primitives ?? []) {
  await each("primitives", v, async () => {
    if (v.primitive === "hkdf-sha256") {
      const key = await crypto.subtle.importKey("raw", bytes(v.ikm), "HKDF", false, ["deriveBits"]);
      const okm = await crypto.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt: bytes(v.salt), info: bytes(v.info) },
        key,
        v.length * 8
      );
      check(hex(new Uint8Array(okm)) === v.okm, `primitives/${v.id}: WebCrypto HKDF differs`);
      // RFC 5869 §2.2, extract: HMAC with the salt as key, HashLen zeros if absent.
      const salt = v.salt === "" ? new Uint8Array(32) : bytes(v.salt);
      const mac = await crypto.subtle.importKey("raw", salt, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
      const prk = new Uint8Array(await crypto.subtle.sign("HMAC", mac, bytes(v.ikm)));
      check(hex(prk) === v.prk, `primitives/${v.id}: WebCrypto HMAC (HKDF-Extract) differs`);
    } else if (v.primitive === "chacha20-poly1305") {
      const { chacha20poly1305 } = await loadNoble();
      const sealed = chacha20poly1305(bytes(v.key), bytes(v.nonce), bytes(v.aad)).encrypt(bytes(v.plaintext));
      check(hex(sealed) === v.ciphertext + v.tag, `primitives/${v.id}: @noble/ciphers differs`);
    } else if (v.primitive === "aes-256-gcm") {
      const key = await crypto.subtle.importKey("raw", bytes(v.key), { name: "AES-GCM" }, false, ["encrypt"]);
      const sealed = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: bytes(v.nonce), additionalData: bytes(v.aad) },
        key,
        bytes(v.plaintext)
      );
      check(hex(new Uint8Array(sealed)) === v.ciphertext + v.tag, `primitives/${v.id}: WebCrypto AES-GCM differs`);
    } else if (v.primitive === "argon2id") {
      if (v.typescript === false) return; // a secret and associated data hash-wasm cannot take
      const { argon2id } = await loadHashWasm();
      const out = await argon2id({
        password: bytes(v.password),
        salt: bytes(v.salt),
        iterations: v.time_cost,
        memorySize: v.memory_kib,
        parallelism: v.parallelism,
        hashLength: v.length,
        outputType: "binary",
      });
      check(hex(out) === v.output, `primitives/${v.id}: hash-wasm Argon2id differs`);
    } else {
      check(false, `primitives/${v.id}: unknown primitive ${v.primitive}`);
    }
  });
}

// ---- containers.json: each intermediate, then the whole container ----
console.log("Containers (pinned inputs, byte for byte):");
const CIPHERS: Record<string, CipherId> = {
  "aes-256-gcm": CipherId.AES_256_GCM,
  "chacha20-poly1305": CipherId.CHACHA20_POLY1305,
  chained: CipherId.CHAINED,
};
function kdfParams(k: Vector["kdf"]): KdfParams {
  return k.id === "pbkdf2"
    ? { kdf: KdfId.PBKDF2, params: { iterations: k.iterations } }
    : { kdf: KdfId.ARGON2ID, params: { timeCost: k.time_cost, memoryKiB: k.memory_kib, parallelism: k.parallelism } };
}
for (const v of pack.containers ?? []) {
  await each("containers", v, async () => {
    const keyFile = v.keyfile === null ? null : bytes(v.keyfile);
    const kdf = kdfParams(v.kdf);
    const { buildKdfInput, deriveSlotKey, slotTableKey } = keym2VectorIntermediates;
    const kdfInput = await buildKdfInput(v.password, keyFile);
    check(hex(kdfInput) === v.kdf_input, `containers/${v.id}: kdf_input differs`);
    check(hex(await deriveSlotKey(kdfInput, bytes(v.salt), kdf)) === v.slot_key, `containers/${v.id}: slot_key differs`);
    if (v.k_table !== undefined) {
      check(hex(await slotTableKey(bytes(v.master_key))) === v.k_table, `containers/${v.id}: k_table differs`);
    }
    const written = await encryptKeym2WithExplicitSecrets(
      bytes(v.plaintext),
      v.password,
      keyFile,
      { kdf, cipher: CIPHERS[v.cipher]!, enforceWritePolicy: false },
      bytes(v.salt),
      bytes(v.master_key),
      v.version,
      bytes(v.container_id)
    );
    const w = hex(written);
    check(w.startsWith(v.core_header), `containers/${v.id}: core_header differs`);
    if (v.slot_table_mac !== undefined) {
      // v3 §5.1: the MAC sits after the 24-byte core header and slot_count.
      check(w.slice(50, 114) === v.slot_table_mac, `containers/${v.id}: slot_table_mac differs`);
    }
    check(w === v.container, `containers/${v.id}: the container differs`);
    const opened = await decryptKeym2(bytes(v.container), v.password, keyFile);
    check(hex(opened.data) === v.plaintext, `containers/${v.id}: does not open to its plaintext`);
  });
}

// ---- shares.json ----
console.log("Shares (pinned coefficients):");
for (const v of pack.shares ?? []) {
  await each("shares", v, async () => {
    const salt = bytes(v.slot_salt);
    const sid1 = await shareSetId(salt);
    const sid2 = await shareSetIdV2(salt);
    check(hex(sid1) === v.set_id_v1, `shares/${v.id}: set_id_v1 differs`);
    check(hex(sid2) === v.set_id_v2, `shares/${v.id}: set_id_v2 differs`);
    check((await shareSetCode(salt)) === v.set_code, `shares/${v.id}: set_code differs`);
    const split = shamirSplit(bytes(v.secret), v.k, v.n, bytes(v.coefficients));
    check(split.length === v.shares.length, `shares/${v.id}: a different number of shares`);
    for (const [i, s] of (v.shares as Vector[]).entries()) {
      const part = split[i];
      check(part?.index === s.index && hex(part.value) === s.value, `shares/${v.id}: share ${s.index}'s value differs`);
      const share = { setId: sid1, threshold: v.k, index: s.index, value: bytes(s.value) };
      check((await encodeShare(share)) === s.kmshare1, `shares/${v.id}: share ${s.index}'s KMSHARE1 text differs`);
      check((await encodeShareV2({ ...share, setId: sid2 })) === s.kmshare2, `shares/${v.id}: share ${s.index}'s KMSHARE2 text differs`);
    }
    // The reader on each strip: every field, the set id at its full width included.
    for (const s of v.shares as Vector[]) {
      for (const [field, sid] of [["kmshare1", v.set_id_v1], ["kmshare2", v.set_id_v2]] as const) {
        const d = await decodeShareAny(s[field]);
        check(
          same([hex(d.setId), d.threshold, d.index, hex(d.value)], [sid, v.k, s.index, s.value]),
          `shares/${v.id}: share ${s.index}'s ${field} decodes to a different record`
        );
      }
    }
    const lowest = (v.shares as Vector[]).slice(0, v.k);
    check(hex(await combineShares(lowest.map((s) => s.kmshare2), sid2)) === v.secret, `shares/${v.id}: k KMSHARE2 strips do not give secret`);
    check(hex(await combineShares(lowest.map((s) => s.kmshare1), sid2)) === v.secret, `shares/${v.id}: k KMSHARE1 strips do not give secret`);
  });
}

// ---- parts.json ----
console.log("Paper parts:");
for (const v of pack.parts ?? []) {
  await each("parts", v, async () => {
    const container = bytes(v.container);
    check(same(encodePaperParts(container, v.capacity), v.kmpart1), `parts/${v.id}: KMPART1 strings differ`);
    check(same(await encodePaperPartsV2(container, v.capacity), v.kmpart2), `parts/${v.id}: KMPART2 strings differ`);
    check(hex(await decodePaperPartsAny(v.kmpart1)) === v.container, `parts/${v.id}: KMPART1 does not reassemble`);
    check(hex(await decodePaperPartsAny(v.kmpart2)) === v.container, `parts/${v.id}: KMPART2 does not reassemble`);
  });
}

// ---- text.json ----
console.log("Text forms:");
for (const v of pack.text ?? []) {
  await each("text", v, async () => {
    if (v.id === "ignorable") {
      const mine = [...new Set([...IGNORABLE_CHARS].map((c) => c.codePointAt(0)!))].sort((a, b) => a - b);
      check(same(mine, v.ignorable), `text/${v.id}: the app's IGNORABLE set differs`);
    } else if (v.wrapped !== undefined) {
      const container = bytes(v.container);
      check(armorKeym2(container) === v.wrapped, `text/${v.id}: wrapped armor differs`);
      check(armorKeym2Compact(container) === v.compact, `text/${v.id}: compact armor differs`);
      check(hex(dearmorKeym2(v.wrapped)) === v.container, `text/${v.id}: wrapped armor does not dearmor`);
      check(hex(dearmorKeym2(v.compact)) === v.container, `text/${v.id}: compact armor does not dearmor`);
    } else if (v.padded_len !== undefined) {
      for (const [n, want] of v.padded_len as [number, number][]) {
        check(keym2PaddedLen(n) === want, `text/${v.id}: padded_len(${n}) differs`);
      }
    } else {
      check(false, `text/${v.id}: unknown text vector`);
    }
  });
}

// ---- reject.json: every row refused, as an ordinary failure ----
console.log("Must-reject rows:");
for (const v of pack.reject ?? []) {
  let refused = false;
  let detail = "accepted";
  try {
    if (v.kind === "container") await decryptKeym2(bytes(v.input), v.password, null);
    else if (v.kind === "armor") dearmorKeym2(v.input);
    else if (v.kind === "share") await decodeShareAny(v.input);
    else if (v.kind === "combine") await combineShares(textLines(v.input));
    else if (v.kind === "parts") await decodePaperPartsAny(splitPaperParts(v.input));
    else detail = `unknown kind ${v.kind}`;
  } catch (e) {
    // v2 §6: one generic failure for everything but parts, which §7.3 has
    // name the problem. A different message says more than §6 allows.
    const generic = e instanceof Error && e.message === "Decryption failed.";
    refused = v.kind === "parts" ? !crashed(e) : generic;
    detail = refused ? "" : `refused with ${String(e)}, not §6's failure`;
  }
  check(refused, `reject/${v.id}: ${detail} (${v.rule})`);
}

// ---- accept.json: every row opens, though a reader is tempted to refuse ----
console.log("Must-open rows:");
for (const v of pack.accept ?? []) {
  await each("accept", v, async () => {
    if (v.kind === "container") {
      const opened = await decryptKeym2(bytes(v.input), v.password, null);
      check(hex(opened.data) === v.expect, `accept/${v.id}: opens to different bytes (${v.rule})`);
      // v3 §5.2: open a changed table, and say so.
      const table = opened.slotTableAuthentic === false ? "changed" : "authentic";
      check(table === v.slot_table, `accept/${v.id}: reports the slot table ${table}, expected ${v.slot_table}`);
    } else if (v.kind === "armor") {
      check(hex(dearmorKeym2(v.input)) === v.expect, `accept/${v.id}: dearmors to different bytes`);
    } else if (v.kind === "share") {
      const d = await decodeShareAny(v.input);
      check(
        same([hex(d.setId), d.threshold, d.index, hex(d.value)], [v.expect.set_id, v.expect.k, v.expect.index, v.expect.value]),
        `accept/${v.id}: decodes to a different record`
      );
    } else if (v.kind === "combine") {
      check(hex(await combineShares(parseShareLines(v.input))) === v.expect, `accept/${v.id}: combines to a different secret`);
    } else if (v.kind === "parts") {
      check(hex(await decodePaperPartsAny(splitPaperParts(v.input))) === v.expect, `accept/${v.id}: reassembles different bytes`);
    } else {
      check(false, `accept/${v.id}: unknown kind ${v.kind}`);
    }
  });
}

console.log(`\n${passed} checks passed, ${failures} failed, over ${total} vectors`);
if (failures > 0) {
  console.error("Vector pack FAILED for the TypeScript.");
  process.exit(1);
}
console.log("Vector pack: the app reproduces every vector.");
