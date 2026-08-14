/**
 * KEYM v2 — chunked container format with multi-slot envelope keys.
 *
 * Implements `docs/FORMAT-V2-DESIGN.md`. The Python reference
 * (`reference/keym2.py`) was written from that document *first*, across both
 * passes, and found seven places where the prose did not determine the bytes;
 * this file is written against the amended document and is cross-checked
 * against the reference for byte equality, which is the only test that can
 * catch the class of defect the worst of those seven belonged to.
 *
 * ## Why a separate file
 *
 * KEYM v1 must remain readable exactly as it is today, and
 * `scripts/fixtures/keymaker/` is append-only. Physical separation makes that
 * structural rather than a promise: nothing here can change how a v1 container
 * is parsed. `keymaker-crypto.ts` reaches this module through a dynamic import
 * in its version dispatch, which also keeps v2 out of the initial bundle.
 *
 * ## What v2 buys
 *
 * - **Multi-slot envelope keys** (§4). The payload is encrypted under a random
 *   per-container master key; each slot carries that key wrapped under one
 *   secret. Any slot opens the container, re-passwording never touches the
 *   ciphertext, and Phase 4's Shamir and passkey slots need no second format.
 * - **Unambiguous key material** (§4.1). v1's `password || keyfile` made
 *   `("ab","c")` and `("a","bc")` the same KDF input. Length prefixes and a
 *   hashed key file remove that — and make a 100 MB key file cost 32 bytes of
 *   KDF input instead of 100 MB.
 * - **Chunked AEAD** (§5). The plaintext no longer has to be held, encrypted
 *   and authenticated as one buffer, which is what forced the 100 MB cap.
 * - **Armor that cannot be mistaken for the magic** (§7): `keym2:` starts with
 *   0x6B, the magic with 0x4B.
 *
 * ## The one structural surprise
 *
 * There are **two AADs** (§5.3), not one. The payload is authenticated against
 * the 8-byte core header; each slot's wrap against the core header plus its own
 * 48-byte prefix. `slot_count` is deliberately in neither, because a slot table
 * has to be editable by someone holding exactly one slot's secret — see
 * `unwrapMasterKey` for why any other choice makes multi-slot unmaintainable.
 */

import {
  CipherId,
  KdfId,
  KeymakerError,
  loadHashWasm,
  loadNoble,
  secureErase,
  validateKdfParams,
  type KdfParams,
} from "./keymaker-crypto";

// ---------------------------------------------------------------------------
// Constants (§3, §4.4, §5.1, §7)
// ---------------------------------------------------------------------------

export const KEYM2_VERSION = 0x02;

/** §3, bytes [0, 8). The payload AAD. */
export const KEYM2_CORE_HEADER_LEN = 8;
const SLOT_COUNT_OFFSET = 8;
const SLOT_TABLE_OFFSET = 9;

/** §4.4, bytes [0, 48) of a slot — the half its own wrap authenticates. */
const SLOT_PREFIX_LEN = 48;
const SLOT_SALT_OFFSET = 8;
const SLOT_PARAMS_OFFSET = 40;

const SALT_LEN = 32;
const MASTER_KEY_LEN = 32;
const TAG_LEN = 16;

/** §6. Bounded by a constant of the format, never by another field. */
const SLOT_COUNT_MIN = 1;
export const KEYM2_MAX_SLOTS = 8;

/**
 * §5.1. A constant of the format, deliberately not a header field — a header
 * field would be an attacker-controlled allocation size read before
 * authentication. Overhead is 16 bytes per chunk, about 0.0015% at this size.
 */
export const KEYM2_CHUNK_SIZE = 1024 * 1024;

/** §7. Lowercase `k` (0x6B) is what distinguishes armor from the magic (0x4B). */
export const KEYM2_ARMOR_PREFIX = "keym2:";

/** §4.4. Only 0x00 is implemented; 0x01 (passkey PRF) and 0x02 (Shamir) are
 *  reserved for Phase 4 and their layouts are deliberately unspecified until
 *  something implements them. Unknown types are skipped, never rejected. */
const SLOT_TYPE_PASSPHRASE = 0x00;

/** §3.3. The container flags byte is entirely reserved; the key-file hint moved
 *  into the slot, because it describes a slot and not a container. */
const CORE_FLAGS_RESERVED_MASK = 0xff;
const SLOT_FLAG_KEYFILE = 0x01; // §4.4, bit 0 = LSB
const SLOT_FLAGS_RESERVED_MASK = 0xfe;

const textEncoder = new TextEncoder();

// §4.1 / §4.3 domain separation. ASCII, which is byte-identical to UTF-8 here.
const CTX_KDF_INPUT = textEncoder.encode("keymaker.v2.kdf-input");
const CTX_KEYFILE = textEncoder.encode("keymaker.v2.keyfile");
const INFO_AES = textEncoder.encode("keymaker-v2-aes");
const INFO_CHACHA = textEncoder.encode("keymaker-v2-chacha");
const INFO_SLOT_AES = textEncoder.encode("keymaker-v2-slot-aes");
const INFO_SLOT_CHACHA = textEncoder.encode("keymaker-v2-slot-chacha");

const MAGIC = new Uint8Array([0x4b, 0x45, 0x59, 0x4d]); // "KEYM"

/**
 * §4.3. Constant, and deliberately not the slot index.
 *
 * Binding the wrap to its position looks strictly safer and is not: it would
 * lock each slot to its index, so removing one would force every later slot to
 * be re-wrapped — and re-wrapping a slot requires *that slot's* secret, which
 * whoever is removing a different slot does not have. A slot table has to be
 * mutable by someone holding one secret, or slots are not worth having.
 *
 * The trailing 0xFF puts this outside §5.2's nonce space, where every payload
 * nonce ends in 0x00 or 0x01. The keys already differ, so that buys nothing
 * cryptographically — it buys a reviewer seeing at a glance that no wrap nonce
 * and no payload nonce can ever coincide.
 */
const WRAP_NONCE = (() => {
  const n = new Uint8Array(12);
  n[11] = 0xff;
  return n;
})();

/**
 * Every rejection uses this one message.
 *
 * §6: "report every rejection as an ordinary decryption failure, with no detail
 * that distinguishes which check failed." A wrong password, a set reserved bit
 * and a malformed payload length are indistinguishable to the caller.
 */
function reject(): never {
  throw new Error("Decryption failed.");
}

function tagOverheadFor(cipher: CipherId): number {
  return cipher === CipherId.CHAINED ? TAG_LEN * 2 : TAG_LEN;
}

/** §3. 48-byte prefix + the wrapped master key and its tag(s). */
export function keym2SlotLen(cipher: CipherId): number {
  return SLOT_PREFIX_LEN + MASTER_KEY_LEN + tagOverheadFor(cipher);
}

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Core header and slot table (§3, §4.4)
// ---------------------------------------------------------------------------

export interface Keym2CoreHeader {
  cipher: CipherId;
  flags: number;
  /** Tag bytes per AEAD invocation: 16, or 32 for chained (§5.1). */
  tagOverhead: number;
}

export interface Keym2Slot {
  slotType: number;
  kdf: KdfParams;
  slotFlags: number;
  salt: Uint8Array;
  wrappedKey: Uint8Array;
  keyFileUsed: boolean;
}

function packCoreHeader(cipher: CipherId, flags: number): Uint8Array {
  const header = new Uint8Array(KEYM2_CORE_HEADER_LEN);
  header.set(MAGIC, 0);
  header[4] = KEYM2_VERSION;
  header[5] = cipher;
  header[6] = flags;
  // byte 7 stays zero — §3 reserved
  return header;
}

function packSlotPrefix(kdf: KdfParams, slotFlags: number, salt: Uint8Array): Uint8Array {
  const prefix = new Uint8Array(SLOT_PREFIX_LEN);
  prefix[0] = SLOT_TYPE_PASSPHRASE;
  prefix[1] = kdf.kdf;
  prefix[2] = slotFlags;
  // bytes 3..7 stay zero — §4.4 reserved
  prefix.set(salt, SLOT_SALT_OFFSET);

  const view = new DataView(prefix.buffer, prefix.byteOffset, prefix.byteLength);
  if (kdf.kdf === KdfId.PBKDF2) {
    view.setUint32(SLOT_PARAMS_OFFSET, kdf.params.iterations, false);
    // bytes 44..47 stay zero — §3.2 reserved
  } else {
    view.setUint16(SLOT_PARAMS_OFFSET, kdf.params.timeCost, false);
    view.setUint32(SLOT_PARAMS_OFFSET + 2, kdf.params.memoryKiB, false);
    prefix[SLOT_PARAMS_OFFSET + 6] = kdf.params.parallelism;
    // byte 47 stays zero — §3.2 reserved
  }
  return prefix;
}

/**
 * §3 and §6, everything checkable before the slot table is located.
 *
 * Every check here runs before any KDF is invoked, and before a single byte is
 * allocated on the strength of something the container claims about itself.
 */
export function parseKeym2CoreHeader(data: Uint8Array): Keym2CoreHeader {
  if (data.length < SLOT_TABLE_OFFSET) reject();

  for (let i = 0; i < MAGIC.length; i++) {
    if (data[i] !== MAGIC[i]) reject();
  }
  if (data[4] !== KEYM2_VERSION) reject();

  const cipher = data[5] as CipherId;
  const flags = data[6] as number;

  if (cipher !== CipherId.AES_256_GCM && cipher !== CipherId.CHACHA20_POLY1305 && cipher !== CipherId.CHAINED) {
    reject();
  }
  // §3.3 — the container flags byte is entirely reserved since the slot
  // amendment. The header is AAD, so a non-zero reserved bit cannot be
  // attacker-introduced without failing authentication: it can only have been
  // written deliberately by a writer that believed it meant something.
  if (flags & CORE_FLAGS_RESERVED_MASK) reject();
  if (data[7] !== 0) reject(); // §3 reserved

  return { cipher, flags, tagOverhead: tagOverheadFor(cipher) };
}

interface Keym2Container {
  core: Keym2CoreHeader;
  coreBytes: Uint8Array;
  /** Raw fixed-width slot records, unparsed — see `parseKeym2Slot`. */
  records: Uint8Array[];
  payload: Uint8Array;
}

/**
 * Split a container into core header, raw slot records and payload.
 *
 * Slot *contents* are deliberately not parsed here (§4.4, finding F7). A reader
 * validates only the slots it attempts, because validating a slot it is going
 * to skip would let a future slot type make older readers reject containers
 * they could otherwise open through a perfectly valid passphrase slot beside
 * it.
 */
function parseKeym2Container(data: Uint8Array): Keym2Container {
  const core = parseKeym2CoreHeader(data);

  const slotCount = data[SLOT_COUNT_OFFSET] as number;
  if (slotCount < SLOT_COUNT_MIN || slotCount > KEYM2_MAX_SLOTS) reject();

  const width = keym2SlotLen(core.cipher);
  const payloadOffset = SLOT_TABLE_OFFSET + slotCount * width;

  // §6: shorter than payload_offset plus the minimum payload for one chunk.
  // The smallest chunk is zero plaintext bytes and its tag(s).
  if (data.length < payloadOffset + core.tagOverhead) reject();

  const records: Uint8Array[] = [];
  for (let i = 0; i < slotCount; i++) {
    records.push(data.subarray(SLOT_TABLE_OFFSET + i * width, SLOT_TABLE_OFFSET + (i + 1) * width));
  }
  return {
    core,
    coreBytes: data.subarray(0, KEYM2_CORE_HEADER_LEN),
    records,
    payload: data.subarray(payloadOffset),
  };
}

/**
 * §4.4 and §6, for one slot. Returns null when this slot cannot be attempted.
 *
 * Null rather than a throw, because a slot the reader cannot use is not yet a
 * failure — the caller tries the next one. Finding F6: an unknown slot type,
 * a set reserved field and out-of-bounds parameters are all the same event from
 * the reader's side, and only exhausting the slot table is a rejection.
 *
 * Parsing and validation are the same function on purpose. §6 requires every
 * check to run *before* that slot's KDF is invoked, and KM-14 happened because
 * nothing about the shape of the v1 code made an omitted bounds check visible.
 * There is no way to obtain a `Keym2Slot` that has not been bounds-checked.
 */
export function parseKeym2Slot(record: Uint8Array): Keym2Slot | null {
  if (record.length < SLOT_PREFIX_LEN) return null;

  const slotType = record[0] as number;
  const kdfId = record[1] as number;
  const slotFlags = record[2] as number;

  if (slotType !== SLOT_TYPE_PASSPHRASE) return null;
  for (let i = 3; i < 8; i++) if (record[i] !== 0) return null; // §4.4 reserved
  if (slotFlags & SLOT_FLAGS_RESERVED_MASK) return null; // §4.4 reserved bits

  const view = new DataView(record.buffer, record.byteOffset, record.byteLength);

  let kdf: KdfParams;
  if (kdfId === KdfId.PBKDF2) {
    for (let i = 44; i < 48; i++) if (record[i] !== 0) return null; // §3.2 reserved
    kdf = { kdf: KdfId.PBKDF2, params: { iterations: view.getUint32(SLOT_PARAMS_OFFSET, false) } };
  } else if (kdfId === KdfId.ARGON2ID) {
    if (record[47] !== 0) return null; // §3.2 reserved
    kdf = {
      kdf: KdfId.ARGON2ID,
      params: {
        timeCost: view.getUint16(SLOT_PARAMS_OFFSET, false),
        memoryKiB: view.getUint32(SLOT_PARAMS_OFFSET + 2, false),
        parallelism: record[SLOT_PARAMS_OFFSET + 6] as number,
      },
    };
  } else {
    return null;
  }

  // §6's bounds, shared verbatim with v1 — same table, same asymmetry (upper
  // bounds are the security control and apply on read; lower bounds are policy
  // for new containers only). Reusing v1's validator rather than restating the
  // numbers means the two versions cannot drift apart.
  try {
    validateKdfParams(kdf, "decrypt");
  } catch {
    return null;
  }

  return {
    slotType,
    kdf,
    slotFlags,
    salt: record.slice(SLOT_SALT_OFFSET, SLOT_SALT_OFFSET + SALT_LEN),
    wrappedKey: record.slice(SLOT_PREFIX_LEN),
    keyFileUsed: (slotFlags & SLOT_FLAG_KEYFILE) !== 0,
  };
}

/**
 * §5.3 `slot_aad_j = core header || slot j's prefix`.
 *
 * Both halves are contiguous ranges of real container bytes, which is
 * deliberate: an AAD assembled out of fields a reader has to reconstruct is an
 * AAD two implementations can quietly disagree about.
 */
function slotAad(coreBytes: Uint8Array, record: Uint8Array): Uint8Array {
  return concat([coreBytes, record.subarray(0, SLOT_PREFIX_LEN)]);
}

// ---------------------------------------------------------------------------
// Key derivation (§4)
// ---------------------------------------------------------------------------

/** §4.1 `LP(x) = uint32_be(len(x)) || x`. */
function lp(x: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + x.length);
  new DataView(out.buffer).setUint32(0, x.length, false);
  out.set(x, 4);
  return out;
}

/**
 * §4.2. 32 bytes regardless of the key file's size.
 *
 * This is the half of KM-05 that length prefixes alone do not solve, and it is
 * what makes a large key file free: the KDF sees 32 bytes, not 100 MB.
 */
async function keyfileDigest(keyFile: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", concat([CTX_KEYFILE, keyFile]) as BufferSource);
  return new Uint8Array(digest);
}

/**
 * §4.1, the slot secret for `slot_type = 0x00`. Injective over
 * `(password, key file)` pairs.
 *
 * Worth being precise about what closes KM-05, because the obvious answer is
 * wrong: for this particular pair it is §4.2's *hashing*, not the length
 * prefixes. A fixed-width 32-byte field cannot slide, so `("ab","c")` and
 * `("a","bc")` differ either way. What `lp()` buys is injectivity of the
 * concatenation as a whole, which is what keeps the encoding sound as fields
 * are added. (Established by a negative control on the Python reference:
 * stubbing `LP` to the identity left every injectivity test green.)
 */
async function buildKdfInput(password: string, keyFile: Uint8Array | null): Promise<Uint8Array> {
  const normalized = textEncoder.encode(password.normalize("NFC"));
  // "No key file" is LP("") rather than an omitted field — one shape, one code
  // path, and the absent case explicitly encoded. It cannot collide with a
  // present-but-empty key file, which hashes to 32 bytes.
  const digest = keyFile ? await keyfileDigest(keyFile) : new Uint8Array(0);
  return concat([lp(CTX_KDF_INPUT), lp(normalized), lp(digest)]);
}

/** §4.3. The slot key, from that slot's own KDF, salt and parameters. */
async function deriveSlotKey(kdfInput: Uint8Array, salt: Uint8Array, kdf: KdfParams): Promise<Uint8Array> {
  if (kdf.kdf === KdfId.PBKDF2) {
    const baseKey = await crypto.subtle.importKey("raw", kdfInput as BufferSource, "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: salt as BufferSource, iterations: kdf.params.iterations, hash: "SHA-256" },
      baseKey,
      MASTER_KEY_LEN * 8
    );
    return new Uint8Array(bits);
  }
  const { argon2id } = await loadHashWasm();
  const hash = await argon2id({
    password: kdfInput,
    salt,
    iterations: kdf.params.timeCost,
    memorySize: kdf.params.memoryKiB,
    parallelism: kdf.params.parallelism,
    hashLength: MASTER_KEY_LEN,
    outputType: "binary",
  });
  return new Uint8Array(hash);
}

interface AeadKeys {
  aesKey: CryptoKey | null;
  chachaKey: Uint8Array | null;
}

/**
 * §4.3. Chained mode expands a 32-byte key into two independent subkeys.
 *
 * "Zero salt" is passed as 32 explicit zero bytes. An empty salt would be
 * identical — RFC 5869 substitutes HashLen zeros, and HMAC pads a short key
 * with zeros to the block size — but writing it out means a second implementer
 * does not have to derive that to be sure they match.
 */
async function expandKeys(
  key: Uint8Array,
  cipher: CipherId,
  infoAes: Uint8Array,
  infoChacha: Uint8Array
): Promise<AeadKeys> {
  if (cipher === CipherId.AES_256_GCM) {
    const aesKey = await crypto.subtle.importKey("raw", key as BufferSource, { name: "AES-GCM" }, false, [
      "encrypt",
      "decrypt",
    ]);
    return { aesKey, chachaKey: null };
  }
  if (cipher === CipherId.CHACHA20_POLY1305) {
    return { aesKey: null, chachaKey: new Uint8Array(key) };
  }

  const hkdfKey = await crypto.subtle.importKey("raw", key as BufferSource, "HKDF", false, ["deriveBits"]);
  const expand = async (info: Uint8Array): Promise<Uint8Array> => {
    const bits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32) as BufferSource, info: info as BufferSource },
      hkdfKey,
      MASTER_KEY_LEN * 8
    );
    return new Uint8Array(bits);
  };
  const aesBytes = await expand(infoAes);
  const chachaBytes = await expand(infoChacha);
  const aesKey = await crypto.subtle.importKey("raw", aesBytes as BufferSource, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
  secureErase(aesBytes);
  return { aesKey, chachaKey: chachaBytes };
}

/** §4.3. The keys the chunks are sealed under. */
function payloadKeys(master: Uint8Array, cipher: CipherId): Promise<AeadKeys> {
  return expandKeys(master, cipher, INFO_AES, INFO_CHACHA);
}

/**
 * §4.3. The keys one slot's wrap is sealed under.
 *
 * Distinct info strings from `payloadKeys`. A collision would need the slot key
 * and the master key to be equal, and they cannot be — one is a KDF output and
 * the other is CSPRNG — but separating them costs nothing and means the
 * property holds without needing that argument. It is also invisible to every
 * round-trip test, since reusing the payload's strings is self-consistent;
 * byte equality against the reference is what actually pins it.
 */
function wrapKeys(slotKey: Uint8Array, cipher: CipherId): Promise<AeadKeys> {
  return expandKeys(slotKey, cipher, INFO_SLOT_AES, INFO_SLOT_CHACHA);
}

// ---------------------------------------------------------------------------
// Payload (§5)
// ---------------------------------------------------------------------------

/**
 * §5.2 `nonce_i = uint88_be(i) || final_flag`.
 *
 * Eleven bytes of counter, one flag byte. The counter cannot overflow within
 * any container this can produce: 2^88 chunks of 1 MiB is 2^108 bytes, so the
 * design checklist's "no counter overflow reachable" holds by construction
 * rather than by argument. JavaScript numbers only carry 53 bits safely, so
 * the low 6 bytes are written from the number and the high 5 stay zero — which
 * is exact for every index below 2^48, and an index that large is unreachable.
 *
 * Deterministic counter nonces are safe because the payload key is per
 * container: the master key is fresh CSPRNG for every container (§4.5), so no
 * (key, nonce) pair is ever reused. Before the slot amendment this rested on
 * the salt being fresh instead — see the document's §11.1.
 */
function nonceFor(index: number, isFinal: boolean): Uint8Array {
  if (!Number.isSafeInteger(index) || index < 0) reject();
  const nonce = new Uint8Array(12);
  // Write the index big-endian into bytes 5..10 (the low 48 bits of the
  // 88-bit counter); bytes 0..4 remain zero.
  let n = index;
  for (let i = 10; i >= 5; i--) {
    nonce[i] = n & 0xff;
    n = Math.floor(n / 256);
  }
  nonce[11] = isFinal ? 0x01 : 0x00;
  return nonce;
}

/**
 * §5.1, as amended. The number of chunks is `max(1, ceil(n / CHUNK_SIZE))` —
 * the fewest that can hold the plaintext.
 *
 * A plaintext whose length is a positive multiple of the chunk size therefore
 * ends with a **full** final chunk; no empty trailing chunk is emitted. That
 * sentence exists in the specification because the Python reference could not
 * be written without it: the original wording admitted both encodings, they
 * differ by a tag and in every subsequent nonce, and *both decode correctly* —
 * so only a byte-equality check between implementations can catch a
 * disagreement. A round-trip test inside one implementation cannot.
 */
function chunkCount(plaintextLength: number): number {
  return Math.max(1, Math.ceil(plaintextLength / KEYM2_CHUNK_SIZE));
}

/**
 * Recover each chunk's plaintext length from the payload length alone.
 *
 * §6: "reject a payload whose length is not a valid chunk sequence for the
 * declared cipher's tag overhead." With chunks 0..m-1 where the first m-1 are
 * full:
 *
 *     payload = (m-1) * (CHUNK + tag) + r + tag,  0 <= r <= CHUNK
 *
 * so `divmod(payload - tag, CHUNK + tag)` gives m-1 and r directly, and a
 * remainder above CHUNK means a truncated or padded payload.
 */
function chunkLayout(payloadLength: number, tagOverhead: number): number[] {
  if (payloadLength < tagOverhead) reject();
  const stride = KEYM2_CHUNK_SIZE + tagOverhead;
  const rest = payloadLength - tagOverhead;
  const full = Math.floor(rest / stride);
  const remainder = rest - full * stride;
  if (remainder > KEYM2_CHUNK_SIZE) reject();
  const sizes = new Array<number>(full).fill(KEYM2_CHUNK_SIZE);
  sizes.push(remainder);
  return sizes;
}

/** §5.4. Chained is AES inner, ChaCha outer, both under the same nonce —
 *  not a reuse, because the keys are independently derived. The slot wrap uses
 *  this same construction, which is why a chained container chains its wrap. */
async function seal(
  cipher: CipherId,
  keys: AeadKeys,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array
): Promise<Uint8Array> {
  if (cipher === CipherId.AES_256_GCM) {
    const out = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce as BufferSource, additionalData: aad as BufferSource },
      keys.aesKey!,
      plaintext as BufferSource
    );
    return new Uint8Array(out);
  }
  const { chacha20poly1305 } = await loadNoble();
  if (cipher === CipherId.CHACHA20_POLY1305) {
    return chacha20poly1305(keys.chachaKey!, nonce, aad).encrypt(plaintext);
  }
  const inner = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce as BufferSource, additionalData: aad as BufferSource },
    keys.aesKey!,
    plaintext as BufferSource
  );
  return chacha20poly1305(keys.chachaKey!, nonce, aad).encrypt(new Uint8Array(inner));
}

/**
 * §5.4. Chained verifies the outer layer before the inner one.
 *
 * Returns null rather than throwing, because the slot walk needs "this one did
 * not open" to be an ordinary outcome. Callers that have run out of slots — or
 * that are opening a payload chunk, where there is nothing else to try — turn
 * the null into a rejection themselves.
 */
async function open(
  cipher: CipherId,
  keys: AeadKeys,
  nonce: Uint8Array,
  blob: Uint8Array,
  aad: Uint8Array
): Promise<Uint8Array | null> {
  try {
    if (cipher === CipherId.AES_256_GCM) {
      const out = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce as BufferSource, additionalData: aad as BufferSource },
        keys.aesKey!,
        blob as BufferSource
      );
      return new Uint8Array(out);
    }
    const { chacha20poly1305 } = await loadNoble();
    if (cipher === CipherId.CHACHA20_POLY1305) {
      return chacha20poly1305(keys.chachaKey!, nonce, aad).decrypt(blob);
    }
    const inner = chacha20poly1305(keys.chachaKey!, nonce, aad).decrypt(blob);
    const out = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce as BufferSource, additionalData: aad as BufferSource },
      keys.aesKey!,
      inner as BufferSource
    );
    return new Uint8Array(out);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// The envelope (§4.3)
// ---------------------------------------------------------------------------

/** §4.3. Seal the master key under one slot's key. */
async function wrapMasterKey(
  cipher: CipherId,
  slotKey: Uint8Array,
  masterKey: Uint8Array,
  aad: Uint8Array
): Promise<Uint8Array> {
  const keys = await wrapKeys(slotKey, cipher);
  try {
    return await seal(cipher, keys, WRAP_NONCE, masterKey, aad);
  } finally {
    secureErase(keys.chachaKey);
  }
}

/**
 * Walk the slot table until one opens, returning the master key.
 *
 * §4.4 and finding F6: a slot is passed over when its type is not implemented,
 * when its reserved fields or parameters are bad, or when its secret is not the
 * one we hold. All three are the same event here — this slot did not open it —
 * and only exhausting the table is a failure.
 *
 * This stops at the first slot that unwraps. §4.4 does not require it to, and
 * attempting every slot regardless would hide *which* slot matched from an
 * observer timing the unlock. Eight Argon2id invocations to open a file that
 * opened on the first one is not a price worth paying to conceal an index from
 * someone already holding the container.
 */
async function unwrapMasterKey(
  container: Keym2Container,
  kdfInput: Uint8Array
): Promise<{ master: Uint8Array; slot: Keym2Slot }> {
  for (const record of container.records) {
    const slot = parseKeym2Slot(record);
    if (slot === null) continue;

    const slotKey = await deriveSlotKey(kdfInput, slot.salt, slot.kdf);
    const keys = await wrapKeys(slotKey, container.core.cipher);
    let master: Uint8Array | null;
    try {
      master = await open(
        container.core.cipher,
        keys,
        WRAP_NONCE,
        slot.wrappedKey,
        slotAad(container.coreBytes, record)
      );
    } finally {
      secureErase(keys.chachaKey);
      secureErase(slotKey);
    }
    if (master !== null && master.length === MASTER_KEY_LEN) {
      return { master, slot };
    }
  }
  reject();
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface Keym2Options {
  kdf: KdfParams;
  cipher: CipherId;
}

/**
 * Encrypt into a KEYM v2 container with a single passphrase slot.
 *
 * The master key and the slot salt are both freshly generated here. §4.5 makes
 * master-key freshness the load-bearing requirement — nonces are a
 * deterministic counter (§5.2), so reusing a master key reuses every nonce in
 * the container. See `encryptKeym2WithExplicitSecrets` for the one caller that
 * needs otherwise.
 */
export async function encryptKeym2(
  plaintext: Uint8Array,
  password: string,
  keyFile: Uint8Array | null,
  options: Keym2Options
): Promise<Uint8Array> {
  const salt = new Uint8Array(SALT_LEN);
  crypto.getRandomValues(salt);
  const masterKey = new Uint8Array(MASTER_KEY_LEN);
  crypto.getRandomValues(masterKey);
  return encryptKeym2WithExplicitSecrets(plaintext, password, keyFile, options, salt, masterKey);
}

/**
 * Encrypt with a caller-supplied salt and master key. **Conformance harnesses
 * only.**
 *
 * This exists because byte-equality against `reference/keym2.py` is the only
 * check that can catch a chunking, nonce or slot-layout disagreement — both
 * implementations decode each other's output happily even when they disagree
 * about how to write it, which is exactly the defect the reference found in
 * §5.1. Comparing bytes requires both values pinned.
 *
 * **Do not call this from application code.** §4.5 forbids it. Reusing a master
 * key reuses every (key, nonce) pair in the container, which for an AEAD means
 * recoverable plaintext and forgeable tags. `encryptKeym2` is the API.
 */
export async function encryptKeym2WithExplicitSecrets(
  plaintext: Uint8Array,
  password: string,
  keyFile: Uint8Array | null,
  options: Keym2Options,
  salt: Uint8Array,
  masterKey: Uint8Array
): Promise<Uint8Array> {
  if (!password) {
    throw new KeymakerError("credential-required", "A password is required for encryption.");
  }
  if (salt.length !== SALT_LEN) {
    throw new KeymakerError("invalid-input", "KEYM v2 requires a 32-byte salt.");
  }
  if (masterKey.length !== MASTER_KEY_LEN) {
    throw new KeymakerError("invalid-input", "KEYM v2 requires a 32-byte master key.");
  }
  validateKdfParams(options.kdf, "encrypt");

  const coreBytes = packCoreHeader(options.cipher, 0);
  const prefix = packSlotPrefix(options.kdf, keyFile ? SLOT_FLAG_KEYFILE : 0, salt);

  // Round-trip both through the reader's own validators. A writer that can emit
  // a container its own parser rejects is a bug worth catching here rather than
  // in someone's backup.
  parseKeym2CoreHeader(concat([coreBytes, new Uint8Array([1])]));
  if (parseKeym2Slot(concat([prefix, new Uint8Array(MASTER_KEY_LEN + tagOverheadFor(options.cipher))])) === null) {
    throw new KeymakerError("invalid-input", "KEYM v2 refused to write a slot its own parser rejects.");
  }

  const kdfInput = await buildKdfInput(password, keyFile);
  const slotKey = await deriveSlotKey(kdfInput, salt, options.kdf);
  secureErase(kdfInput);

  let record: Uint8Array;
  try {
    record = concat([
      prefix,
      await wrapMasterKey(options.cipher, slotKey, masterKey, concat([coreBytes, prefix])),
    ]);
  } finally {
    secureErase(slotKey);
  }

  const keys = await payloadKeys(masterKey, options.cipher);
  try {
    const count = chunkCount(plaintext.length);
    const parts: Uint8Array[] = [coreBytes, new Uint8Array([1]), record];
    for (let i = 0; i < count; i++) {
      const chunk = plaintext.subarray(i * KEYM2_CHUNK_SIZE, (i + 1) * KEYM2_CHUNK_SIZE);
      parts.push(await seal(options.cipher, keys, nonceFor(i, i === count - 1), chunk, coreBytes));
    }
    return concat(parts);
  } finally {
    secureErase(keys.chachaKey);
  }
}

export interface Keym2DecryptResult {
  data: Uint8Array;
  keyFileUsed: boolean;
  core: Keym2CoreHeader;
  /** Which slot opened it. Zero for every container this version writes. */
  slot: Keym2Slot;
}

/**
 * Decrypt a KEYM v2 container.
 *
 * Returns the whole plaintext rather than yielding chunks, and that is a
 * deliberate reading of §5.5: "a prefix of verified chunks is not a verified
 * prefix of the file". A container whose chunk 900 fails has already produced
 * 899 genuine chunks, and an implementation that streamed those somewhere has
 * written 899 MB of attacker-chosen truncation. Nothing is returned until the
 * final chunk verifies *and* carries `final_flag`, so a caller cannot treat a
 * partial result as a success by accident.
 */
export async function decryptKeym2(
  container: Uint8Array,
  password: string,
  keyFile: Uint8Array | null
): Promise<Keym2DecryptResult> {
  const parsed = parseKeym2Container(container); // every structural §6 check
  const sizes = chunkLayout(parsed.payload.length, parsed.core.tagOverhead); // also before any KDF

  const kdfInput = await buildKdfInput(password, keyFile);
  let master: Uint8Array;
  let slot: Keym2Slot;
  try {
    ({ master, slot } = await unwrapMasterKey(parsed, kdfInput));
  } finally {
    secureErase(kdfInput);
  }

  const keys = await payloadKeys(master, parsed.core.cipher);
  secureErase(master);

  try {
    const out: Uint8Array[] = [];
    let offset = 0;
    const last = sizes.length - 1;
    for (let i = 0; i < sizes.length; i++) {
      const size = sizes[i];
      if (size === undefined) reject();
      const blobLen = size + parsed.core.tagOverhead;
      const blob = parsed.payload.subarray(offset, offset + blobLen);
      if (blob.length !== blobLen) reject();
      offset += blobLen;
      // §5.2, normative: the last chunk consumed must carry final_flag = 1.
      //
      // Enforced by construction — there is no flag to read, only a nonce to
      // get right. Chunk `last` is opened with final_flag = 1, so a truncated
      // container (whose surviving last chunk was sealed with 0) fails
      // authentication. That is the case a length check alone cannot catch:
      // truncation exactly on a chunk boundary leaves a perfectly valid
      // payload length.
      const plain = await open(parsed.core.cipher, keys, nonceFor(i, i === last), blob, parsed.coreBytes);
      if (plain === null) reject();
      out.push(plain);
    }
    if (offset !== parsed.payload.length) reject();
    return { data: concat(out), keyFileUsed: slot.keyFileUsed, core: parsed.core, slot };
  } finally {
    secureErase(keys.chachaKey);
  }
}

// ---------------------------------------------------------------------------
// Armor and detection (§7)
// ---------------------------------------------------------------------------

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(text: string): Uint8Array {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/** §7 `keym2:<base64url-unpadded>`. */
export function armorKeym2(container: Uint8Array): string {
  return KEYM2_ARMOR_PREFIX + toBase64Url(container);
}

/**
 * §7, case-sensitive and matched byte-for-byte.
 *
 * Accepting `KEYM2:` would put back the exact collision this encoding removes:
 * a reader sniffing four bytes would see the binary magic again, which is the
 * bug v1's `KEYM1:` armor had.
 */
export function dearmorKeym2(text: string): Uint8Array {
  const trimmed = text.trim();
  if (!trimmed.startsWith(KEYM2_ARMOR_PREFIX)) reject();
  try {
    return fromBase64Url(trimmed.slice(KEYM2_ARMOR_PREFIX.length).replace(/\s+/g, ""));
  } catch {
    reject();
  }
}

/** Does this look like a v2 binary container? Byte 4 is the discriminator. */
export function isKeym2Binary(data: Uint8Array): boolean {
  if (data.length < 5) return false;
  for (let i = 0; i < MAGIC.length; i++) if (data[i] !== MAGIC[i]) return false;
  return data[4] === KEYM2_VERSION;
}
