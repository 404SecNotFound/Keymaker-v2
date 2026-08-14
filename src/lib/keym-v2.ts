/**
 * KEYM v2 — chunked container format.
 *
 * Implements `docs/FORMAT-V2-DESIGN.md`. The Python reference
 * (`reference/keym2.py`) was written from that document *first*, and found four
 * places where the prose did not determine the bytes; this file is written
 * against the amended document and is cross-checked against the reference for
 * byte equality, which is the only test that can catch the class of defect the
 * worst of those four belonged to.
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
 * - **Unambiguous key material** (§4.1). v1's `password || keyfile` made
 *   `("ab","c")` and `("a","bc")` the same KDF input. Length prefixes and a
 *   hashed key file remove that — and make a 100 MB key file cost 32 bytes of
 *   KDF input instead of 100 MB.
 * - **Chunked AEAD** (§5). The plaintext no longer has to be held, encrypted
 *   and authenticated as one buffer, which is what forced the 100 MB cap.
 * - **A fixed 48-byte header** (§3). One layout, every offset a constant.
 * - **Armor that cannot be mistaken for the magic** (§7): `keym2:` starts with
 *   0x6B, the magic with 0x4B.
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
// Constants (§3, §5.1, §7)
// ---------------------------------------------------------------------------

export const KEYM2_VERSION = 0x02;
export const KEYM2_HEADER_LEN = 48;
const SALT_LEN = 32;
const MASTER_KEY_LEN = 32;
const TAG_LEN = 16;

/**
 * §5.1. A constant of the format, deliberately not a header field — a header
 * field would be an attacker-controlled allocation size read before
 * authentication. Overhead is 16 bytes per chunk, about 0.0015% at this size.
 */
export const KEYM2_CHUNK_SIZE = 1024 * 1024;

/** §7. Lowercase `k` (0x6B) is what distinguishes armor from the magic (0x4B). */
export const KEYM2_ARMOR_PREFIX = "keym2:";

const FLAG_KEYFILE = 0x01; // §3.3, bit 0 = LSB
const FLAG_RESERVED_MASK = 0xfe;

const textEncoder = new TextEncoder();

// §4.1 / §4.3 domain separation. ASCII, which is byte-identical to UTF-8 here.
const CTX_KDF_INPUT = textEncoder.encode("keymaker.v2.kdf-input");
const CTX_KEYFILE = textEncoder.encode("keymaker.v2.keyfile");
const INFO_AES = textEncoder.encode("keymaker-v2-aes");
const INFO_CHACHA = textEncoder.encode("keymaker-v2-chacha");

const MAGIC = new Uint8Array([0x4b, 0x45, 0x59, 0x4d]); // "KEYM"

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

// ---------------------------------------------------------------------------
// Header (§3)
// ---------------------------------------------------------------------------

export interface Keym2Header {
  kdf: KdfParams;
  cipher: CipherId;
  flags: number;
  salt: Uint8Array;
  keyFileUsed: boolean;
  /** Tag bytes per chunk: 16, or 32 for chained (§5.1). */
  tagOverhead: number;
}

function tagOverheadFor(cipher: CipherId): number {
  return cipher === CipherId.CHAINED ? TAG_LEN * 2 : TAG_LEN;
}

function packHeader(kdf: KdfParams, cipher: CipherId, flags: number, salt: Uint8Array): Uint8Array {
  const header = new Uint8Array(KEYM2_HEADER_LEN);
  header.set(MAGIC, 0);
  header[4] = KEYM2_VERSION;
  header[5] = kdf.kdf;
  header[6] = cipher;
  header[7] = flags;
  header.set(salt, 8);

  const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
  if (kdf.kdf === KdfId.PBKDF2) {
    view.setUint32(40, kdf.params.iterations, false);
    // bytes 44..47 stay zero — §3.2 reserved
  } else {
    view.setUint16(40, kdf.params.timeCost, false);
    view.setUint32(42, kdf.params.memoryKiB, false);
    header[46] = kdf.params.parallelism;
    // byte 47 stays zero — §3.2 reserved
  }
  return header;
}

/**
 * Parse and fully validate the 48-byte header.
 *
 * Parsing and validation are the same function on purpose. §6 requires every
 * check to run *before* the KDF is invoked, and KM-14 happened because nothing
 * about the shape of the v1 code made an omitted bounds check visible. Here
 * there is no way to obtain a `Keym2Header` that has not been bounds-checked,
 * so no caller can forget.
 */
export function parseKeym2Header(data: Uint8Array): Keym2Header {
  if (data.length < KEYM2_HEADER_LEN) reject();

  for (let i = 0; i < MAGIC.length; i++) {
    if (data[i] !== MAGIC[i]) reject();
  }
  if (data[4] !== KEYM2_VERSION) reject();

  // noUncheckedIndexedAccess is on, so every index read is number | undefined.
  // The length check above already guarantees these are present; `at` makes
  // that explicit rather than asserting it away with `!` at each use.
  const at = (i: number): number => {
    const v = data[i];
    if (v === undefined) reject();
    return v;
  };

  const kdfId = at(5);
  const cipher = at(6) as CipherId;
  const flags = at(7);

  if (cipher !== CipherId.AES_256_GCM && cipher !== CipherId.CHACHA20_POLY1305 && cipher !== CipherId.CHAINED) {
    reject();
  }

  // §3.3 — stricter than v1, which says ignore. The header is AAD, so a
  // non-zero reserved bit cannot be attacker-introduced without failing
  // authentication: it can only have been written deliberately by a writer
  // that believed it meant something. Decrypting anyway would decrypt under an
  // interpretation the author did not intend.
  if (flags & FLAG_RESERVED_MASK) reject();

  const salt = data.slice(8, 40);
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);

  let kdf: KdfParams;
  if (kdfId === KdfId.PBKDF2) {
    for (let i = 44; i < 48; i++) if (at(i) !== 0) reject(); // §3.2 reserved
    kdf = { kdf: KdfId.PBKDF2, params: { iterations: view.getUint32(40, false) } };
  } else if (kdfId === KdfId.ARGON2ID) {
    if (at(47) !== 0) reject(); // §3.2 reserved
    kdf = {
      kdf: KdfId.ARGON2ID,
      params: {
        timeCost: view.getUint16(40, false),
        memoryKiB: view.getUint32(42, false),
        parallelism: at(46),
      },
    };
  } else {
    reject();
  }

  // §6's bounds, shared verbatim with v1 — same table, same asymmetry (upper
  // bounds are the security control and apply on read; lower bounds are policy
  // for new containers only). Reusing v1's validator rather than restating the
  // numbers means the two versions cannot drift apart.
  try {
    validateKdfParams(kdf, "decrypt");
  } catch {
    reject();
  }

  return {
    kdf,
    cipher,
    flags,
    salt,
    keyFileUsed: (flags & FLAG_KEYFILE) !== 0,
    tagOverhead: tagOverheadFor(cipher),
  };
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
 * §4.1. Injective over `(password, key file)` pairs.
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

async function deriveMasterKey(kdfInput: Uint8Array, salt: Uint8Array, kdf: KdfParams): Promise<Uint8Array> {
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

interface ChunkKeys {
  aesKey: CryptoKey | null;
  chachaKey: Uint8Array | null;
}

/**
 * §4.3. Chained mode expands the master key into two independent subkeys.
 *
 * The info strings differ from v1's (`keymaker-aes` / `keymaker-chacha`)
 * deliberately: a v1 master key and a v2 master key can never expand to the
 * same subkey, even if some future bug fed one into the other's path.
 *
 * "Zero salt" is passed as 32 explicit zero bytes. An empty salt would be
 * identical — RFC 5869 substitutes HashLen zeros, and HMAC pads a short key
 * with zeros to the block size — but writing it out means a second implementer
 * does not have to derive that to be sure they match.
 */
async function deriveChunkKeys(master: Uint8Array, cipher: CipherId): Promise<ChunkKeys> {
  if (cipher === CipherId.AES_256_GCM) {
    const aesKey = await crypto.subtle.importKey("raw", master as BufferSource, { name: "AES-GCM" }, false, [
      "encrypt",
      "decrypt",
    ]);
    return { aesKey, chachaKey: null };
  }
  if (cipher === CipherId.CHACHA20_POLY1305) {
    return { aesKey: null, chachaKey: new Uint8Array(master) };
  }

  const hkdfKey = await crypto.subtle.importKey("raw", master as BufferSource, "HKDF", false, ["deriveBits"]);
  const expand = async (info: Uint8Array): Promise<Uint8Array> => {
    const bits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32) as BufferSource, info: info as BufferSource },
      hkdfKey,
      MASTER_KEY_LEN * 8
    );
    return new Uint8Array(bits);
  };
  const aesBytes = await expand(INFO_AES);
  const chachaBytes = await expand(INFO_CHACHA);
  const aesKey = await crypto.subtle.importKey("raw", aesBytes as BufferSource, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
  secureErase(aesBytes);
  return { aesKey, chachaKey: chachaBytes };
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
 *  not a reuse, because the keys are independently derived. */
async function sealChunk(
  cipher: CipherId,
  keys: ChunkKeys,
  nonce: Uint8Array,
  chunk: Uint8Array,
  aad: Uint8Array
): Promise<Uint8Array> {
  if (cipher === CipherId.AES_256_GCM) {
    const out = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce as BufferSource, additionalData: aad as BufferSource },
      keys.aesKey!,
      chunk as BufferSource
    );
    return new Uint8Array(out);
  }
  const { chacha20poly1305 } = await loadNoble();
  if (cipher === CipherId.CHACHA20_POLY1305) {
    return chacha20poly1305(keys.chachaKey!, nonce, aad).encrypt(chunk);
  }
  const inner = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce as BufferSource, additionalData: aad as BufferSource },
    keys.aesKey!,
    chunk as BufferSource
  );
  return chacha20poly1305(keys.chachaKey!, nonce, aad).encrypt(new Uint8Array(inner));
}

/** §5.4. Chained verifies the outer layer before the inner one. */
async function openChunk(
  cipher: CipherId,
  keys: ChunkKeys,
  nonce: Uint8Array,
  blob: Uint8Array,
  aad: Uint8Array
): Promise<Uint8Array> {
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
    reject();
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface Keym2Options {
  kdf: KdfParams;
  cipher: CipherId;
}

/**
 * Encrypt into a KEYM v2 container.
 *
 * The salt is always freshly generated here. §2 requires "fresh CSPRNG salt per
 * container", and in v2 that requirement is load-bearing in a way it was not in
 * v1: nonces are a deterministic counter (§5.2), so reusing a salt with the
 * same password reuses the master key *and every nonce in the container*. In v1
 * the nonces were random, so salt reuse was merely bad. See
 * `encryptKeym2WithExplicitSalt` for the one caller that needs otherwise.
 */
export async function encryptKeym2(
  plaintext: Uint8Array,
  password: string,
  keyFile: Uint8Array | null,
  options: Keym2Options
): Promise<Uint8Array> {
  const salt = new Uint8Array(SALT_LEN);
  crypto.getRandomValues(salt);
  return encryptKeym2WithExplicitSalt(plaintext, password, keyFile, options, salt);
}

/**
 * Encrypt with a caller-supplied salt. **Conformance harnesses only.**
 *
 * This exists because byte-equality against `reference/keym2.py` is the only
 * check that can catch a chunking or nonce disagreement — both implementations
 * decode each other's output happily even when they disagree about how to
 * write it, which is exactly the defect the reference found in §5.1. Comparing
 * bytes requires a shared salt.
 *
 * **Do not call this from application code.** Reusing a salt with the same
 * password reuses every (key, nonce) pair in the container, which for an AEAD
 * means recoverable plaintext and forgeable tags. `encryptKeym2` is the API.
 */
export async function encryptKeym2WithExplicitSalt(
  plaintext: Uint8Array,
  password: string,
  keyFile: Uint8Array | null,
  options: Keym2Options,
  salt: Uint8Array
): Promise<Uint8Array> {
  if (!password) {
    throw new KeymakerError("credential-required", "A password is required for encryption.");
  }
  if (salt.length !== SALT_LEN) {
    throw new KeymakerError("invalid-input", "KEYM v2 requires a 32-byte salt.");
  }
  validateKdfParams(options.kdf, "encrypt");

  const flags = keyFile ? FLAG_KEYFILE : 0;
  const header = packHeader(options.kdf, options.cipher, flags, salt);

  // Round-trip the header through the reader's own validator. A writer that can
  // emit a container its own parser rejects is a bug worth catching here rather
  // than in someone's backup.
  parseKeym2Header(header);

  const kdfInput = await buildKdfInput(password, keyFile);
  const master = await deriveMasterKey(kdfInput, salt, options.kdf);
  secureErase(kdfInput);
  const keys = await deriveChunkKeys(master, options.cipher);
  secureErase(master);

  try {
    const count = chunkCount(plaintext.length);
    const parts: Uint8Array[] = [header];
    for (let i = 0; i < count; i++) {
      const chunk = plaintext.subarray(i * KEYM2_CHUNK_SIZE, (i + 1) * KEYM2_CHUNK_SIZE);
      parts.push(await sealChunk(options.cipher, keys, nonceFor(i, i === count - 1), chunk, header));
    }
    return concat(parts);
  } finally {
    secureErase(keys.chachaKey);
  }
}

export interface Keym2DecryptResult {
  data: Uint8Array;
  keyFileUsed: boolean;
  header: Keym2Header;
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
  const header = parseKeym2Header(container); // every §6 check, before the KDF
  const aad = container.subarray(0, KEYM2_HEADER_LEN);
  const payload = container.subarray(KEYM2_HEADER_LEN);
  const sizes = chunkLayout(payload.length, header.tagOverhead); // also before the KDF

  const kdfInput = await buildKdfInput(password, keyFile);
  const master = await deriveMasterKey(kdfInput, header.salt, header.kdf);
  secureErase(kdfInput);
  const keys = await deriveChunkKeys(master, header.cipher);
  secureErase(master);

  try {
    const out: Uint8Array[] = [];
    let offset = 0;
    const last = sizes.length - 1;
    for (let i = 0; i < sizes.length; i++) {
      const size = sizes[i];
      if (size === undefined) reject();
      const blobLen = size + header.tagOverhead;
      const blob = payload.subarray(offset, offset + blobLen);
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
      out.push(await openChunk(header.cipher, keys, nonceFor(i, i === last), blob, aad));
    }
    if (offset !== payload.length) reject();
    return { data: concat(out), keyFileUsed: header.keyFileUsed, header };
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
