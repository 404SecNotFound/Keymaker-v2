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
 *   and authenticated as one buffer, which is what forced the *format* to cap
 *   payloads at 100 MB. The app still caps them there — MAX_PLAINTEXT_SIZE,
 *   enforced by the UI — because this build assembles the plaintext as one
 *   array before encrypting and again after decrypting. The format is
 *   unbounded; the browser is not, and lifting the limit without streaming
 *   those paths would swap a clear refusal for an out-of-memory tab.
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
  describeWeakKdf,
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

export const KEYM2_VERSION_V2 = 0x02;
export const KEYM2_VERSION_V3 = 0x03;

/**
 * The version this implementation *writes* by default.
 *
 * v3 §6 says writers SHOULD emit v3. This one does not yet, and the reason is
 * the same one `reference/keym2.py` gives: the app's containers are what the
 * frozen fixtures and the byte-equality cross-test are built from, and moving
 * the default before v3 has fixtures of its own would retire that coverage
 * rather than extend it.
 *
 * That argument was spent once v3 had thirteen vectors of its own in the corpus
 * and both implementations were held to them. What remained was a product
 * question — every reader that opens a v3 container has to have shipped first,
 * and a backup is the last place to find out one did not — and it has now been
 * answered: **new containers are v3.**
 *
 * Three readers had to learn v3 before this line could move, and the third is
 * the one that constrains it. `keym2.py` and this module are updatable. The
 * decryptor embedded in a self-extracting page (§7.2) is not: it ships *inside*
 * the backup, so a page written today runs the reader it was born with,
 * forever. That reader understands v2 and v3 as of this change, which is what
 * makes writing v3 safe rather than merely permitted.
 *
 * Nothing rewrites an existing backup. v1 and v2 containers stay readable
 * indefinitely (v3 §6), and moving one to v3 means decrypting and re-encrypting
 * it, which is the owner's decision and needs their secret.
 */
export const KEYM2_VERSION = KEYM2_VERSION_V3;

/** §3, bytes [0, 8) in v2. The payload AAD. */
export const KEYM2_CORE_HEADER_LEN = 8;
const SLOT_TABLE_OFFSET = 9;


/**
 * v3 §3. The core header grows by a 16-byte `container_id`, and
 * `slot_table_mac` sits between `slot_count` and the table — at a fixed offset,
 * so a reader reaches it without first trusting `slot_count`.
 */
const CONTAINER_ID_LEN = 16;
const SLOT_TABLE_MAC_LEN = 32;
const CORE_HEADER_LEN_V3 = 24;
const SLOT_COUNT_OFFSET_V3 = 24;
const SLOT_TABLE_MAC_OFFSET_V3 = 25;
const SLOT_TABLE_OFFSET_V3 = 57;

/**
 * Version-dependent header geometry. Functions rather than lookup tables so an
 * unknown version is a loud failure at the point of use: a reader that has
 * passed `parseKeym2CoreHeader` cannot reach these with a bad version, but a
 * writer assembling a header by hand can, and should hear about it.
 */
function coreHeaderLen(version: number): number {
  if (version === KEYM2_VERSION_V2) return KEYM2_CORE_HEADER_LEN;
  if (version === KEYM2_VERSION_V3) return CORE_HEADER_LEN_V3;
  reject();
}

export function keym2SlotCountOffset(version: number): number {
  return coreHeaderLen(version);
}

export function keym2SlotTableOffset(version: number): number {
  if (version === KEYM2_VERSION_V2) return SLOT_TABLE_OFFSET;
  if (version === KEYM2_VERSION_V3) return SLOT_TABLE_OFFSET_V3;
  reject();
}


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

/**
 * §7. Column width for armored output. Line breaks are **not** part of the
 * encoding — every reader strips whitespace — so this is presentation only and
 * changing it breaks nothing.
 *
 * Wrapped because one unbroken line is genuinely hostile, and measurably so.
 * A `<textarea>` laying out a single 1 MiB line blocks the main thread for
 * ~12 400 ms; the same megabyte wrapped costs ~407 ms. Since Keymaker's armor
 * is what a user copies out and pastes back into Decrypt, emitting one line
 * meant the app handed people input it then choked on — the self-inflicted
 * half of U4.
 *
 * 64 rather than MIME's 76: it is what PGP has always used, it survives
 * quoted-printable mail without re-wrapping, and it fits an 80-column terminal
 * with room for a quote marker.
 */
export const KEYM2_ARMOR_COLUMNS = 64;

/** §4.4. Unknown types are skipped, never rejected — getting that wrong is a
 *  data-loss bug, not an interop one. */
const SLOT_TYPE_PASSPHRASE = 0x00;
/** §4.7. Same 48-byte prefix again; nothing identifies the credential. */
export const KEYM2_SLOT_TYPE_PASSKEY = 0x01;
/** §4.6. Same 48-byte prefix; only the slot secret's origin differs. */
export const KEYM2_SLOT_TYPE_SHAMIR = 0x02;

/**
 * §3.2, HKDF-SHA-256 — added by §4.6, with no cost parameters on purpose.
 *
 * Deliberately *not* a new member of `KdfId`. That enum is v1's, v1 is frozen,
 * and widening it would mean a v1 header declaring 0x02 became parseable. The
 * v2 slot parser is the only thing that should ever see this value, so it is
 * defined here and the slot's KDF type is widened locally.
 */
export const KEYM2_KDF_HKDF = 0x02;
export type Keym2KdfParams = KdfParams | { kdf: typeof KEYM2_KDF_HKDF };

/**
 * §6, and normative in both directions. A passphrase under HKDF is a password
 * with no stretching at all and nothing in any output would reveal it; a
 * 32-byte CSPRNG secret under Argon2id is a memory-hard cost paid to defend an
 * unguessable value. Only the first is a vulnerability, but a rule that admits
 * the second invites a writer to read the pairing as advice.
 */
function kdfIsLegalForSlotType(slotType: number, kdfId: number): boolean {
  if (slotType === SLOT_TYPE_PASSPHRASE) return kdfId === KdfId.PBKDF2 || kdfId === KdfId.ARGON2ID;
  if (slotType === KEYM2_SLOT_TYPE_SHAMIR) return kdfId === KEYM2_KDF_HKDF;
  if (slotType === KEYM2_SLOT_TYPE_PASSKEY) return kdfId === KEYM2_KDF_HKDF;
  return false;
}

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

// §4.6. The input string differs from CTX_KDF_INPUT so a 32-byte passphrase and
// a 32-byte share secret can never derive the same slot key.
const CTX_SHAMIR_INPUT = textEncoder.encode("keymaker.v2.shamir-input");
const INFO_SLOT_KEY = textEncoder.encode("keymaker.v2.slot-key");

// §4.7, the same argument a third time: a passphrase, a share secret and a PRF
// output are all 32 bytes and must not reach the same slot key.
const CTX_PASSKEY_INPUT = textEncoder.encode("keymaker.v2.passkey-input");
// §4.7. The PRF salt is derived from slot_salt rather than stored. This differs
// from INFO_SLOT_KEY as hygiene rather than as a load-bearing separation: the
// two HKDF calls already take different IKMs, 32 bytes against 65.
const INFO_PRF_SALT = textEncoder.encode("keymaker.v2.prf-salt");

/**
 * v3 §5.1. The info string for the slot-table MAC key. It carries "v3" where
 * every string above carries "v2", which is the whole of the domain separation
 * required: `K_table` cannot collide with a payload key, a slot key or a PRF
 * salt, because no v2 derivation is ever handed this info string.
 */
const INFO_SLOT_TABLE = textEncoder.encode("keymaker.v3.slot-table");

/** A v2 container's absent `container_id`, named so the intent reads. */
const EMPTY = new Uint8Array(0);



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
  /** 0x02 or 0x03. v3 §3 widens the header; everything else is v2's. */
  version: number;
  /**
   * v3 §4. Empty for v2, where the field does not exist. **Not a secret** — it
   * appears in the clear in every copy of the backup, and two copies of the
   * same backup share it. Its only job is to make the slot AAD and the payload
   * AAD differ between containers that would otherwise be byte-identical.
   */
  containerId: Uint8Array;
}


export interface Keym2Slot {
  slotType: number;
  kdf: Keym2KdfParams;
  slotFlags: number;
  salt: Uint8Array;
  wrappedKey: Uint8Array;
  keyFileUsed: boolean;
}

function packCoreHeader(
  cipher: CipherId,
  flags: number,
  version: number = KEYM2_VERSION_V2,
  containerId: Uint8Array = EMPTY
): Uint8Array {
  if (version === KEYM2_VERSION_V3 && containerId.length !== CONTAINER_ID_LEN) {
    throw new KeymakerError("invalid-input", "KEYM v3 requires a 16-byte container id.");
  }
  if (version === KEYM2_VERSION_V2 && containerId.length !== 0) {
    throw new KeymakerError("invalid-input", "KEYM v2 containers have no container id.");
  }
  const header = new Uint8Array(coreHeaderLen(version));
  header.set(MAGIC, 0);
  header[4] = version;
  header[5] = cipher;
  header[6] = flags;
  // byte 7 stays zero — §3 reserved
  if (version === KEYM2_VERSION_V3) header.set(containerId, 8);
  return header;
}


function packSlotPrefix(
  kdf: Keym2KdfParams,
  slotFlags: number,
  salt: Uint8Array,
  slotType: number = SLOT_TYPE_PASSPHRASE
): Uint8Array {
  const prefix = new Uint8Array(SLOT_PREFIX_LEN);
  prefix[0] = slotType;
  prefix[1] = kdf.kdf;
  prefix[2] = slotFlags;
  // bytes 3..7 stay zero — §4.4 reserved, for every slot type. §4.6 considered
  // spending them on a digest of the reconstructed secret and did not.
  prefix.set(salt, SLOT_SALT_OFFSET);

  // §3.2. HKDF's whole parameter block is reserved, so the prefix is finished.
  if (kdf.kdf === KEYM2_KDF_HKDF) return prefix;

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
  // Enough bytes to read the version before dispatching on it. Five is the
  // magic plus the version byte, and it is all this first check can assume:
  // how much more is required depends on the answer.
  if (data.length < 5) reject();

  for (let i = 0; i < MAGIC.length; i++) {
    if (data[i] !== MAGIC[i]) reject();
  }
  const version = data[4] as number;
  // v3 §6: a v3 reader MUST open v1, v2 and v3. v1 has its own module; here the
  // bound is v2 or v3, and anything else is an unknown version.
  if (version !== KEYM2_VERSION_V2 && version !== KEYM2_VERSION_V3) reject();
  if (data.length < keym2SlotTableOffset(version)) reject();


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

  return {
    cipher,
    flags,
    tagOverhead: tagOverheadFor(cipher),
    version,
    containerId: version === KEYM2_VERSION_V3 ? data.slice(8, 8 + CONTAINER_ID_LEN) : EMPTY,
  };
}


interface Keym2Container {
  core: Keym2CoreHeader;
  coreBytes: Uint8Array;
  /** Raw fixed-width slot records, unparsed — see `parseKeym2Slot`. */
  records: Uint8Array[];
  payload: Uint8Array;
  /** v3 §3, the stored `slot_table_mac`; null for a v2 container. */
  slotTableMac: Uint8Array | null;
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

  const slotCount = data[keym2SlotCountOffset(core.version)] as number;
  if (slotCount < SLOT_COUNT_MIN || slotCount > KEYM2_MAX_SLOTS) reject();

  const width = keym2SlotLen(core.cipher);
  const table = keym2SlotTableOffset(core.version);
  const payloadOffset = table + slotCount * width;

  // §6: shorter than payload_offset plus the minimum payload for one chunk.
  // The smallest chunk is zero plaintext bytes and its tag(s).
  if (data.length < payloadOffset + core.tagOverhead) reject();

  const records: Uint8Array[] = [];
  for (let i = 0; i < slotCount; i++) {
    records.push(data.subarray(table + i * width, table + (i + 1) * width));
  }
  return {
    core,
    coreBytes: data.subarray(0, coreHeaderLen(core.version)),
    records,
    payload: data.subarray(payloadOffset),
    // Read at a fixed offset, deliberately without consulting `slot_count` —
    // that is why v3 §3 puts the MAC *before* the table rather than after it.
    slotTableMac:
      core.version === KEYM2_VERSION_V3
        ? data.subarray(SLOT_TABLE_MAC_OFFSET_V3, SLOT_TABLE_MAC_OFFSET_V3 + SLOT_TABLE_MAC_LEN)
        : null,
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

  if (
    slotType !== SLOT_TYPE_PASSPHRASE &&
    slotType !== KEYM2_SLOT_TYPE_SHAMIR &&
    slotType !== KEYM2_SLOT_TYPE_PASSKEY
  ) {
    return null;
  }
  for (let i = 3; i < 8; i++) if (record[i] !== 0) return null; // §4.4 reserved
  if (slotFlags & SLOT_FLAGS_RESERVED_MASK) return null; // §4.4 reserved bits
  // §6, the slot_type/slot_kdf_id pairing, checked before any KDF runs. This is
  // what makes "a passphrase slot declaring HKDF" unreachable rather than
  // merely discouraged.
  if (!kdfIsLegalForSlotType(slotType, kdfId)) return null;

  const view = new DataView(record.buffer, record.byteOffset, record.byteLength);

  let kdf: Keym2KdfParams;
  if (kdfId === KEYM2_KDF_HKDF) {
    // §3.2. All eight parameter bytes reserved, so there is nothing to bound
    // and validateKdfParams has nothing to say about this slot.
    for (let i = SLOT_PARAMS_OFFSET; i < SLOT_PARAMS_OFFSET + 8; i++) {
      if (record[i] !== 0) return null;
    }
    return {
      slotType,
      kdf: { kdf: KEYM2_KDF_HKDF },
      slotFlags,
      salt: record.slice(SLOT_SALT_OFFSET, SLOT_SALT_OFFSET + SALT_LEN),
      wrappedKey: record.slice(SLOT_PREFIX_LEN),
      keyFileUsed: false,
    };
  }
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
// Slot table authentication (v3 §5)
// ---------------------------------------------------------------------------
//
// What v3 adds, and the only thing it adds. A v2 slot table is authenticated
// slot-by-slot and never as a whole, so an attacker who can write the file can
// delete a slot and the container still opens for everyone else — silently, and
// permanently for whoever was enrolled in the deleted slot.
//
// The fix survives the constraint stated at WRAP_NONCE — a slot table has to be
// mutable by someone holding one secret — because recomputing this MAC needs
// the master key, and unwrapping any one slot yields the master key.

/** v3 §5.1. `HKDF-SHA-256(ikm = master_key, salt = "", info = "keymaker.v3.slot-table")`. */
async function slotTableKey(master: Uint8Array): Promise<Uint8Array> {
  const hkdfKey = await crypto.subtle.importKey("raw", master as BufferSource, "HKDF", false, ["deriveBits"]);
  // The empty salt is written out rather than omitted, matching the reference:
  // RFC 5869 substitutes HashLen zeros for an absent salt and HMAC zero-pads a
  // short key to the block size, so an empty salt and a 32-zero-byte salt give
  // the same PRK. Saying so beats making a second implementer derive it.
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: EMPTY as BufferSource, info: INFO_SLOT_TABLE as BufferSource },
    hkdfKey,
    SLOT_TABLE_MAC_LEN * 8
  );
  return new Uint8Array(bits);
}

/**
 * v3 §5.1. `HMAC-SHA-256` over `core_header ‖ slot_count ‖ every slot record`.
 *
 * Whole records, not just prefixes. The wrapped key and its tag are already
 * authenticated by the slot itself, so covering them adds no cryptographic
 * strength — it adds simplicity. "Every byte of the table, in order" has no
 * edge cases, and it pins slot order as a side effect.
 */
async function computeSlotTableMac(
  coreBytes: Uint8Array,
  records: Uint8Array[],
  master: Uint8Array
): Promise<Uint8Array> {
  const tableKey = await slotTableKey(master);
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      tableKey as BufferSource,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const msg = concat([coreBytes, new Uint8Array([records.length]), ...records]);
    return new Uint8Array(await crypto.subtle.sign("HMAC", key, msg as BufferSource));
  } finally {
    secureErase(tableKey);
  }
}

/**
 * v3 §5.2. True/false for a v3 container, **null for a v2 one** — which has no
 * MAC to check, and about which nothing is therefore claimed.
 *
 * Three states rather than a bool on purpose. Collapsing null into true would
 * have every v2 container assert an assurance the format cannot give: v2's
 * table is strippable and the strip is undetectable.
 */
async function verifySlotTable(parsed: Keym2Container, master: Uint8Array): Promise<boolean | null> {
  if (parsed.slotTableMac === null) return null;
  const expected = await computeSlotTableMac(parsed.coreBytes, parsed.records, master);
  // Constant-time. Not because a timing signal here is worth much — reaching
  // this point requires having already unwrapped a slot — but because a MAC
  // comparison written the other way gets copied somewhere it does matter.
  let diff = expected.length ^ parsed.slotTableMac.length;
  for (let i = 0; i < expected.length && i < parsed.slotTableMac.length; i++) {
    diff |= (expected[i] as number) ^ (parsed.slotTableMac[i] as number);
  }
  secureErase(expected);
  return diff === 0;
}

const SLOT_TABLE_CHANGED_WRITE =
  "This backup's list of unlock methods has changed since it was created, so Keymaker will not edit it. " +
  "Making a change now would re-sign the altered list and permanently destroy the evidence that it was altered. " +
  "The backup itself is untouched and still opens: unlock it, and save a fresh copy instead.";

/**
 * v3 §5.3 step 2. Refuse to rewrite a slot table that does not verify, and
 * erase the master key on the way out.
 *
 * The deliberate opposite of §5.2, for a reason that is about who pays. A
 * *reader* that refuses costs someone their plaintext, so it reports instead
 * and hands the data over. A *writer* that refuses costs one edit that can be
 * made another way; a writer that proceeds signs the attacker's table with the
 * real key, and is irreversible.
 *
 * Without this, v3 detects a strip only until the victim next uses the app.
 * The owner is the one person who can still open a container whose heir slot
 * was removed — their own slot is the one left — so the owner is the one whose
 * next enrolment launders it, and every reader afterwards is told the table is
 * authentic. Which it now is.
 *
 * `=== false` rather than a falsy test: `verifySlotTable` answers `null` for a
 * v2 container, which claims nothing and must keep the enrolment it always
 * allowed.
 */
async function requireAuthenticSlotTable(parsed: Keym2Container, master: Uint8Array): Promise<void> {
  if ((await verifySlotTable(parsed, master)) === false) {
    secureErase(master);
    throw new KeymakerError("invalid-input", SLOT_TABLE_CHANGED_WRITE);
  }
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

/**
 * §4.6, the slot secret for `slot_type = 0x02`.
 *
 * Same shape as `buildKdfInput` with a different domain string, which is the
 * entire reason a 32-byte passphrase and a 32-byte share secret cannot collide
 * into the same slot key.
 */
function buildShamirInput(shareSecret: Uint8Array): Uint8Array {
  if (shareSecret.length !== MASTER_KEY_LEN) reject();
  return concat([lp(CTX_SHAMIR_INPUT), lp(shareSecret)]);
}

/** §4.7. WebAuthn's PRF extension returns 32 bytes. */
export const KEYM2_PRF_OUTPUT_LEN = 32;

/**
 * §4.7. The salt to hand the authenticator, derived from the slot's own salt
 * rather than stored beside it.
 *
 * Exported because the caller needs it *before* it has a PRF output: the salt
 * is an input the authenticator requires, so unlocking is "read the slot,
 * derive this, ask the key, then come back".
 */
export async function derivePrfSalt(slotSalt: Uint8Array): Promise<Uint8Array> {
  if (slotSalt.length !== SALT_LEN) reject();
  const baseKey = await crypto.subtle.importKey("raw", slotSalt as BufferSource, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0) as BufferSource,
      info: INFO_PRF_SALT as BufferSource,
    },
    baseKey,
    KEYM2_PRF_OUTPUT_LEN * 8
  );
  return new Uint8Array(bits);
}

/**
 * §4.7, the slot secret for `slot_type = 0x01`.
 *
 * Same shape as the other two, third domain string.
 */
function buildPasskeyInput(prfOutput: Uint8Array): Uint8Array {
  if (prfOutput.length !== KEYM2_PRF_OUTPUT_LEN) reject();
  return concat([lp(CTX_PASSKEY_INPUT), lp(prfOutput)]);
}

/** §4.3. The slot key, from that slot's own KDF, salt and parameters. */
async function deriveSlotKey(kdfInput: Uint8Array, salt: Uint8Array, kdf: Keym2KdfParams): Promise<Uint8Array> {
  if (kdf.kdf === KEYM2_KDF_HKDF) {
    // §3.2. No cost parameters, because the secret this stretches is already 32
    // CSPRNG bytes and 2^256 does not get larger when multiplied by a work
    // factor. `parseKeym2Slot`'s pairing check is what guarantees this branch is
    // only reachable for a slot type whose secret has that property.
    const baseKey = await crypto.subtle.importKey("raw", kdfInput as BufferSource, "HKDF", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: salt as BufferSource, info: INFO_SLOT_KEY as BufferSource },
      baseKey,
      MASTER_KEY_LEN * 8
    );
    return new Uint8Array(bits);
  }
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
 * What the caller can offer a slot: a passphrase, a set of shares, or both.
 *
 * Both is the ordinary inheritance shape — slot 0 the owner's password, slot 1
 * the heirs' share set — and either alone must be enough.
 */
export interface Keym2Secrets {
  password?: string | undefined;
  keyFile?: Uint8Array | null | undefined;
  shares?: string[] | undefined;
  /** §4.7. 32 bytes from the authenticator, for this slot's derived salt. */
  prfOutput?: Uint8Array | undefined;
}

/**
 * §4.1 / §4.6. The slot secret this caller can offer *this* slot, or null if it
 * holds nothing of the kind the slot wants.
 *
 * This is the whole of what §4.6 changed about the read path. The walk below is
 * unchanged; only the question "what secret does this slot take" grew a second
 * answer.
 */
async function slotSecretFor(slot: Keym2Slot, secrets: Keym2Secrets): Promise<Uint8Array | null> {
  if (slot.slotType === SLOT_TYPE_PASSPHRASE) {
    if (secrets.password === undefined) return null;
    return buildKdfInput(secrets.password, secrets.keyFile ?? null);
  }

  if (slot.slotType === KEYM2_SLOT_TYPE_SHAMIR) {
    if (!secrets.shares || secrets.shares.length === 0) return null;
    const { combineShares, shareSetId } = await import("./keym-v2-shamir");
    try {
      // Checked against *this* slot's salt, so a share set belonging to a
      // different Shamir slot declines rather than reconstructing a clean
      // secret that is simply the wrong one.
      const shareSecret = await combineShares(secrets.shares, await shareSetId(slot.salt));
      const input = buildShamirInput(shareSecret);
      secureErase(shareSecret);
      return input;
    } catch {
      return null;
    }
  }

  if (slot.slotType === KEYM2_SLOT_TYPE_PASSKEY) {
    if (!secrets.prfOutput) return null;
    // There is no equivalent of the Shamir set-id check, and there cannot be:
    // §4.7 stores nothing identifying the credential, so a PRF output from the
    // wrong passkey simply fails to unwrap. By §6 that is indistinguishable
    // from a wrong password — deliberately, and at the cost of never being able
    // to tell the user which of the two happened.
    if (secrets.prfOutput.length !== KEYM2_PRF_OUTPUT_LEN) return null;
    return buildPasskeyInput(secrets.prfOutput);
  }

  return null;
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
  secrets: Keym2Secrets
): Promise<{ master: Uint8Array; slot: Keym2Slot }> {
  for (const record of container.records) {
    const slot = parseKeym2Slot(record);
    if (slot === null) continue;

    const slotSecret = await slotSecretFor(slot, secrets);
    if (slotSecret === null) continue;

    // §4.4/F6: a slot that cannot be used disqualifies *itself*, never the
    // walk. Every other per-slot failure here is a `continue`; this one was an
    // exception that escaped decryptKeym2 entirely.
    //
    // §6 bounds memory_kib and parallelism independently, but Argon2id also
    // requires memory_kib >= 8 * parallelism. A slot declaring mem=1, p=8
    // passes every §6 check and then throws inside hash-wasm. So does a legal
    // mem=262144 slot on a device that cannot allocate it. Either way the
    // throw took the whole container with it: rewriting six bytes of slot 0
    // made a two-slot container permanently unopenable through the untouched,
    // valid slot 1 — the exact data-loss outcome the skip rule exists to
    // prevent, achievable by anyone who can write the file and needing no key.
    //
    // Also §6's indistinguishability: the raw "Memory size should be at least
    // 8 * parallelism." reached decryptData's callers.
    let slotKey: Uint8Array;
    try {
      slotKey = await deriveSlotKey(slotSecret, slot.salt, slot.kdf);
    } catch {
      secureErase(slotSecret);
      continue;
    }
    // Unconditional. This was guarded on Shamir-or-passkey, which left the one
    // case that carries the password unerased: for a passphrase slot
    // `slotSecretFor` returns a fresh `buildKdfInput` allocation holding the
    // password bytes and the key-file digest, owned by nobody else, and one
    // copy was leaked per slot the walk attempted. The encrypt path has always
    // erased the same buffer — see `encryptKeym2WithExplicitSecrets` — so this
    // was an inconsistency rather than a decision.
    //
    // Safe for every branch: each iteration builds its own, so there is no
    // shared buffer a later slot could need.
    secureErase(slotSecret);
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
  options: Keym2Options,
  version: number = KEYM2_VERSION
): Promise<Uint8Array> {
  const salt = new Uint8Array(SALT_LEN);
  crypto.getRandomValues(salt);
  const masterKey = new Uint8Array(MASTER_KEY_LEN);
  crypto.getRandomValues(masterKey);
  // v3 §4. Drawn once, here, and never changed for the life of the file — not
  // on enrolment, not on revocation. Not a secret, so it is not erased.
  const containerId = version === KEYM2_VERSION_V3 ? new Uint8Array(CONTAINER_ID_LEN) : EMPTY;
  if (version === KEYM2_VERSION_V3) crypto.getRandomValues(containerId);
  try {
    return await encryptKeym2WithExplicitSecrets(
      plaintext,
      password,
      keyFile,
      options,
      salt,
      masterKey,
      version,
      containerId
    );

  } finally {
    // This key opens every chunk in the container, and until now it was the
    // one secret the write path left behind: addShamirSlotKeym2,
    // addPasskeySlotKeym2 and decryptKeym2 all erase theirs, and encryption —
    // the path every container goes through — did not.
    //
    // Erased here rather than inside encryptKeym2WithExplicitSecrets because
    // ownership differs. That function takes the salt and master key from its
    // caller so conformance tests can pin exact bytes; erasing a buffer it was
    // lent would be a function destroying an argument it does not own. This
    // one generated the key two lines up, so it is the one that may destroy
    // it.
    //
    // `await` above is load-bearing: returning the promise directly would run
    // this `finally` before the encryption it is protecting had finished with
    // the key.
    secureErase(masterKey);
  }
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
  masterKey: Uint8Array,
  version: number = KEYM2_VERSION,
  containerId: Uint8Array = EMPTY
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

  if (version !== KEYM2_VERSION_V2 && version !== KEYM2_VERSION_V3) {
    throw new KeymakerError("invalid-input", `KEYM: unknown container version ${version}.`);
  }
  const coreBytes = packCoreHeader(options.cipher, 0, version, containerId);
  const prefix = packSlotPrefix(options.kdf, keyFile ? SLOT_FLAG_KEYFILE : 0, salt);

  // Round-trip both through the reader's own validators. A writer that can emit
  // a container its own parser rejects is a bug worth catching here rather than
  // in someone's backup.
  //
  // The filler after the core header has to reach the version's slot-table
  // offset, not v2's: a v3 header followed by one byte is shorter than
  // `parseKeym2CoreHeader` requires, and would fail this self-check for a
  // reason that has nothing to do with the header being wrong.
  parseKeym2CoreHeader(concat([coreBytes, new Uint8Array(keym2SlotTableOffset(version) - coreBytes.length)]));

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
    // v3 §3 puts the MAC between slot_count and the table. It is computed over
    // the finished record, so the table has to exist before the head does.
    const head: Uint8Array[] = [coreBytes, new Uint8Array([1])];
    if (version === KEYM2_VERSION_V3) {
      head.push(await computeSlotTableMac(coreBytes, [record], masterKey));
    }
    const parts: Uint8Array[] = [...head, record];
    for (let i = 0; i < count; i++) {
      const chunk = plaintext.subarray(i * KEYM2_CHUNK_SIZE, (i + 1) * KEYM2_CHUNK_SIZE);
      parts.push(await seal(options.cipher, keys, nonceFor(i, i === count - 1), chunk, coreBytes));
    }
    return concat(parts);
  } finally {
    secureErase(keys.chachaKey);
  }
}


export interface Keym2ShareSet {
  container: Uint8Array;
  /** The share texts, produced once. Nothing can reissue them. */
  shares: string[];
}

/**
 * §4.6. Enrol a k-of-n share set on an existing container, holding one other
 * secret. Returns the new container and the shares.
 *
 * This is the composition the envelope was built for: slot 0 stays the
 * passphrase the owner uses daily, slot 1 becomes shares for whoever inherits
 * it, neither knows the other exists, and **the payload is not re-encrypted**
 * however large it is.
 *
 * The share secret is discarded before this returns. The only way back to it is
 * `k` shares, so the returned strings are the only copy that will ever exist.
 *
 * `explicit` is for conformance harnesses only (§4.5), and is more directly
 * dangerous than a fixed salt: the coefficients are the only thing standing
 * between one share and the secret.
 */
export async function addShamirSlotKeym2(
  container: Uint8Array,
  secrets: Keym2Secrets,
  threshold: number,
  count: number,
  explicit?: { salt?: Uint8Array; shareSecret?: Uint8Array; coefficients?: Uint8Array }
): Promise<Keym2ShareSet> {
  const { shamirSplit, shareSetId, encodeShare, SHARE_VALUE_LEN } = await import("./keym-v2-shamir");

  const parsed = parseKeym2Container(container);
  if (parsed.records.length >= KEYM2_MAX_SLOTS) {
    throw new KeymakerError("invalid-input", `A container can hold at most ${KEYM2_MAX_SLOTS} slots.`);
  }
  const { master } = await unwrapMasterKey(parsed, secrets);
  // Before the KDF, not after: a refused edit should be the cheap outcome.
  await requireAuthenticSlotTable(parsed, master);

  // The salt is chosen before the shares exist, because share_set_id derives
  // from it (§4.6). Two slots cannot share a salt without sharing a set id.
  const salt = explicit?.salt ?? crypto.getRandomValues(new Uint8Array(SALT_LEN));
  if (salt.length !== SALT_LEN) {
    throw new KeymakerError("invalid-input", "KEYM v2 requires a 32-byte salt.");
  }
  const shareSecret = explicit?.shareSecret ?? crypto.getRandomValues(new Uint8Array(SHARE_VALUE_LEN));

  const prefix = packSlotPrefix({ kdf: KEYM2_KDF_HKDF }, 0, salt, KEYM2_SLOT_TYPE_SHAMIR);
  // Same round-trip through the reader's own validator as the passphrase path.
  if (parseKeym2Slot(concat([prefix, new Uint8Array(MASTER_KEY_LEN + parsed.core.tagOverhead)])) === null) {
    throw new KeymakerError("invalid-input", "KEYM v2 refused to write a slot its own parser rejects.");
  }

  const slotSecret = buildShamirInput(shareSecret);
  const slotKey = await deriveSlotKey(slotSecret, salt, { kdf: KEYM2_KDF_HKDF });
  secureErase(slotSecret);

  let record: Uint8Array;
  // v3 §5.3. Recomputed here, inside the try, because `master` is erased on the
  // way out of it and the MAC is the last thing that needs it. Enrolment
  // re-seals the table; it does not touch any other slot or the payload.
  let tableMac: Uint8Array | null = null;
  try {
    record = concat([prefix, await wrapMasterKey(parsed.core.cipher, slotKey, master, concat([parsed.coreBytes, prefix]))]);
    if (parsed.core.version === KEYM2_VERSION_V3) {
      tableMac = await computeSlotTableMac(parsed.coreBytes, [...parsed.records, record], master);
    }
  } finally {
    secureErase(slotKey);
    secureErase(master);
  }

  const setId = await shareSetId(salt);

  const shares: string[] = [];
  for (const part of shamirSplit(shareSecret, threshold, count, explicit?.coefficients)) {
    shares.push(await encodeShare({ setId, threshold, index: part.index, value: part.value }));
  }
  if (explicit?.shareSecret === undefined) secureErase(shareSecret);

  const records = [...parsed.records, record];
  return {
    container: concat([
      parsed.coreBytes,
      new Uint8Array([records.length]),
      ...(tableMac ? [tableMac] : []),
      ...records,
      parsed.payload,
    ]),
    shares,

  };
}

/**
 * §4.7. The slot salts of every passkey slot in a container.
 *
 * Needed before unlocking, and that ordering is the whole shape of a passkey
 * unlock: the PRF salt derives from the slot salt, so a reader has to open the
 * file, find the slot, derive the salt, and only then ask the authenticator
 * anything. A passphrase unlock can ask for the secret first; this cannot.
 *
 * Returns one entry per passkey slot rather than the first, because a container
 * may carry more than one enrolled key and each has its own salt. A caller with
 * one authenticator tries them in turn; §4.7 stores nothing that would let it
 * pick.
 *
 * Structural parse errors propagate. A container this cannot read is not a
 * container with no passkey slots, and saying so by returning an empty array
 * would turn a malformed file into "no passkey enrolled".
 */
export function passkeySlotSaltsKeym2(container: Uint8Array): Uint8Array[] {
  const parsed = parseKeym2Container(container);
  const salts: Uint8Array[] = [];
  for (const record of parsed.records) {
    const slot = parseKeym2Slot(record);
    if (slot !== null && slot.slotType === KEYM2_SLOT_TYPE_PASSKEY) salts.push(slot.salt);
  }
  return salts;
}

/**
 * True when every slot a reader could attempt is a passkey slot.
 *
 * An unparseable record counts as *not* a passkey slot, which is the
 * conservative direction: a slot this build cannot read may be one a newer
 * build can, and refusing to write on the strength of a record we do not
 * understand would block a legitimate container.
 */
function passkeyOnly(records: Uint8Array[]): boolean {
  if (records.length === 0) return false;
  return records.every((r) => {
    const slot = parseKeym2Slot(r);
    return slot !== null && slot.slotType === KEYM2_SLOT_TYPE_PASSKEY;
  });
}

/**
 * §4.7. Enrol a passkey on a container that already opens some other way.
 *
 * There is deliberately no `encryptKeym2(..., prfOutput)` counterpart. A
 * container is created with a passphrase and a passkey is *added*, so the state
 * §4.7 forbids — a container only a piece of hardware opens — is not reachable
 * by following the obvious path. That is the only kind of rule that holds.
 *
 * `prfOutput` is what the authenticator returned for `derivePrfSalt(salt)`, so
 * the caller has to choose the salt, ask the key, and then call this. The salt
 * is therefore a parameter rather than generated here.
 */
export async function addPasskeySlotKeym2(
  container: Uint8Array,
  secrets: Keym2Secrets,
  prfOutput: Uint8Array,
  salt: Uint8Array
): Promise<Uint8Array> {
  if (prfOutput.length !== KEYM2_PRF_OUTPUT_LEN) {
    throw new KeymakerError("invalid-input", "A WebAuthn PRF output is 32 bytes.");
  }
  if (salt.length !== SALT_LEN) {
    throw new KeymakerError("invalid-input", "KEYM v2 requires a 32-byte salt.");
  }

  const parsed = parseKeym2Container(container);
  if (parsed.records.length >= KEYM2_MAX_SLOTS) {
    throw new KeymakerError("invalid-input", `A container can hold at most ${KEYM2_MAX_SLOTS} slots.`);
  }
  const { master } = await unwrapMasterKey(parsed, secrets);
  // Before the KDF, not after: a refused edit should be the cheap outcome.
  await requireAuthenticSlotTable(parsed, master);

  const prefix = packSlotPrefix({ kdf: KEYM2_KDF_HKDF }, 0, salt, KEYM2_SLOT_TYPE_PASSKEY);
  // Same round-trip through the reader's own validator as the other builders.
  if (parseKeym2Slot(concat([prefix, new Uint8Array(MASTER_KEY_LEN + parsed.core.tagOverhead)])) === null) {
    throw new KeymakerError("invalid-input", "KEYM v2 refused to write a slot its own parser rejects.");
  }

  const slotSecret = buildPasskeyInput(prfOutput);
  const slotKey = await deriveSlotKey(slotSecret, salt, { kdf: KEYM2_KDF_HKDF });
  secureErase(slotSecret);

  let record: Uint8Array;
  // v3 §5.3, as in addShamirSlotKeym2: re-seal the table before `master` goes.
  let tableMac: Uint8Array | null = null;
  try {
    record = concat([prefix, await wrapMasterKey(parsed.core.cipher, slotKey, master, concat([parsed.coreBytes, prefix]))]);
    if (parsed.core.version === KEYM2_VERSION_V3) {
      tableMac = await computeSlotTableMac(parsed.coreBytes, [...parsed.records, record], master);
    }
  } finally {
    secureErase(slotKey);
    secureErase(master);
  }

  const records = [...parsed.records, record];

  // §4.7's one normative rule that is not about bytes. Asked of the result
  // rather than the input, so slot ordering cannot walk around it.
  if (passkeyOnly(records)) {
    throw new KeymakerError(
      "invalid-input",
      "A container cannot have a passkey as its only unlock path: a passkey is hardware, and a container only a lost key opens is lost data."
    );
  }
  return concat([
    parsed.coreBytes,
    new Uint8Array([records.length]),
    ...(tableMac ? [tableMac] : []),
    ...records,
    parsed.payload,
  ]);
}


export interface Keym2DecryptResult {
  data: Uint8Array;
  keyFileUsed: boolean;
  core: Keym2CoreHeader;
  /** Which slot opened it. Zero for every container this version writes. */
  slot: Keym2Slot;
  /**
   * v3 §5.2. Whether the slot table authenticates: true, false, or **null for
   * a v2 container**, which has no MAC and about which nothing is claimed.
   *
   * A false here does **not** mean the data is suspect. The payload is
   * independently authenticated and has already verified by the time this is
   * returned; what changed is the container's *recovery options*. §5.2 requires
   * the plaintext to be returned anyway — refusing would convert detectable
   * tampering into a lost backup, which is the more severe outcome.
   *
   * It cannot say *which* slot changed. The MAC covers the table as a whole and
   * the sealed table is not recoverable from the tampered one, so "the slot
   * table has changed since this backup was created" is the whole of what is
   * known.
   */
  slotTableAuthentic: boolean | null;
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
  keyFile: Uint8Array | null,
  shares?: string[],
  prfOutput?: Uint8Array
): Promise<Keym2DecryptResult> {
  const parsed = parseKeym2Container(container); // every structural §6 check
  const sizes = chunkLayout(parsed.payload.length, parsed.core.tagOverhead); // also before any KDF

  // An heir holds shares and no password, so an empty password must not become
  // a passphrase attempt: it would burn a full Argon2id derivation per slot to
  // reach the same failure, on the one path where the caller is least likely to
  // understand what went wrong.
  // §4.7 joins §4.6 here: someone unlocking with a passkey has no password
  // either, so an empty one must not become a passphrase attempt that burns a
  // full Argon2id derivation per slot on its way to the same failure.
  const hasOtherSecret = (shares !== undefined && shares.length > 0) || prfOutput !== undefined;
  const { master, slot } = await unwrapMasterKey(parsed, {
    password: password === "" && hasOtherSecret ? undefined : password,
    keyFile,
    shares,
    prfOutput,
  });

  // Verified before the master key is erased, and before any plaintext is
  // returned — but *after* a slot has already opened, which is what makes this
  // exception to §6's generic-error rule leak nothing: an attacker who cannot
  // open the container never reaches it, so there is no oracle.
  const slotTableAuthentic = await verifySlotTable(parsed, master);

  const keys = await payloadKeys(master, parsed.core.cipher);
  secureErase(master);


  // Declared outside the try so the `finally` can reach it: a mid-container
  // authentication failure still leaves real plaintext in the chunks decoded
  // before it.
  const out: Uint8Array[] = [];
  try {
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
    // `concat` copies, so every chunk is now duplicated: the returned buffer
    // and the originals. Only the caller's copy should survive — on a 100 MB
    // file the difference is a second complete copy of the plaintext sitting
    // in memory until the collector happens to reach it.
    const data = concat(out);
    for (const chunk of out) secureErase(chunk);
    out.length = 0;
    return { data, keyFileUsed: slot.keyFileUsed, core: parsed.core, slot, slotTableAuthentic };

  } finally {
    secureErase(keys.chachaKey);
    // Also on the way out of a failure. A container that authenticates for
    // nine chunks and fails on the tenth has already produced nine chunks of
    // real plaintext, and `reject()` used to walk past all of them.
    for (const chunk of out) secureErase(chunk);
  }
}

// ---------------------------------------------------------------------------
// Armor and detection (§7)
// ---------------------------------------------------------------------------

/**
 * Chunked, because the spread in `btoa(String.fromCharCode(...arr))` exceeds
 * the maximum call stack for buffers over roughly 65 KB. 32 KB is well under
 * any engine's argument limit.
 *
 * Collected into an array and joined once rather than accumulated with `+=`.
 * That is finding **B9**, which was fixed in the v1 text path and would have
 * come straight back here: at the 100 MB ceiling this is ~3,200 fragments, and
 * an engine that flattens the rope on every concatenation turns it into O(n²).
 * Since the product writes v2, this is the only base64 path the text output has
 * left, so it is the one that has to hold the line.
 */
function toBase64Url(bytes: Uint8Array): string {
  const CHUNK = 0x8000;
  const parts: string[] = [];
  for (let i = 0; i < bytes.length; i += CHUNK) {
    parts.push(String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK) as unknown as number[]));
  }
  return btoa(parts.join("")).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
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
  const body = toBase64Url(container);
  const lines: string[] = [];
  for (let i = 0; i < body.length; i += KEYM2_ARMOR_COLUMNS) {
    lines.push(body.slice(i, i + KEYM2_ARMOR_COLUMNS));
  }
  return KEYM2_ARMOR_PREFIX + lines.join("\n");
}

/**
 * Armored text with every line break removed.
 *
 * For channels that are not line-oriented and where each byte costs — a QR
 * code, where capacity is a hard cliff at QR_MAX_BYTES and newlines would be
 * ~1.5% of pure overhead. Whitespace is not part of the encoding, so this and
 * `armorKeym2` decode to the same container.
 */
export function armorKeym2Compact(container: Uint8Array): string {
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

/**
 * Describe a v2 container from its opening bytes, without opening it.
 *
 * The mirror of `inspectKeym` for v1, and it exists so that switching the
 * product to v2 does not silently drop the "· Argon2id · AES-256-GCM" half of
 * the line the decrypt panel has always shown. Returns null rather than
 * throwing for anything it cannot read — this drives a label, not a decision.
 *
 * The KDF reported is **slot 0's**, because the KDF is a property of a slot
 * now, not of the container. That is exact for everything this version writes
 * and stays honest for the rest: the slot count is reported alongside it, so a
 * multi-slot container from Phase 4 says so rather than implying its one
 * visible KDF is the whole story.
 */
/**
 * What a *password* attempt on this container will cost, read from the header
 * alone and before any secret is supplied.
 *
 * ## Why this exists
 *
 * `unwrapMasterKey` walks the slot table and derives a key for every slot a
 * supplied secret could match, stopping at the first that unwraps. With the
 * right password in slot 0 that is one derivation. With the wrong password —
 * or the right one in the last slot — it is all of them, and every one of them
 * happens before anything has been authenticated.
 *
 * §6 bounds each slot and `KEYM2_MAX_SLOTS` bounds the count, so the total is
 * bounded rather than open-ended. It is just bounded high. Measured on a
 * developer laptop, eight passphrase slots at the ceiling cost **41 s** with
 * Argon2id and **315 s** with PBKDF2 — the PBKDF2 case being the worse one,
 * and the one an external review that quoted "~30 s" had not reached.
 *
 * Nothing here refuses such a container. It cannot: the format permits it,
 * `reference/keym2.py` opens it, and a limit low enough to catch the hostile
 * case would also strand a conforming backup that the app itself could have
 * written. Refusing would trade a slow unlock for a lost one. So the app
 * *discloses* instead, and the user decides whether to wait.
 *
 * ## Only passphrase slots are counted, and that is not an approximation
 *
 * §6 pairs slot types with KDFs and `parseKeym2Slot` enforces it before any
 * derivation: a Shamir or passkey slot must declare HKDF, which takes no cost
 * parameters at all. So a hostile container cannot make an heir's share-based
 * or passkey unlock expensive — the only slots with a cost to inflate are the
 * ones a *password* reaches.
 *
 * That is also why a container carrying more than one passphrase slot is
 * already unusual: neither this app nor `keym2.py` can write a second one.
 * `addShamirSlotKeym2` and `addPasskeySlotKeym2` are the only slot-adders in
 * either implementation.
 *
 * ## The unit is declared work, not predicted time
 *
 * `multipleOfNormal` compares the parameters in the header against this
 * build's default (Argon2id, 64 MiB, t=3), treating Argon2id cost as
 * `memory x time_cost` and PBKDF2 as iterations scaled to match.
 *
 * It is deliberately **not** a seconds estimate. Argon2id's running time is
 * not linear through the origin — there is a fixed per-call overhead, which is
 * exactly why `kdf-calibration.ts` fits two points and an intercept — and
 * `parallelism` is not modelled at all. Measured, the linear ratio
 * over-estimates the Argon2id ceiling by about 2.3x. A number presented as
 * seconds and wrong by that much is worse than no number; a multiple, labelled
 * as a multiple, is honest and is what the decision actually needs.
 *
 * Returns null for anything that is not a readable v2 container, and never
 * throws: it is called on whatever the user pasted.
 */
export interface Keym2UnlockCost {
  /** Slots a password attempt would derive against. */
  passphraseSlots: number;
  /** Slots using HKDF — Shamir and passkey. Free, and listed for context. */
  hkdfSlots: number;
  /** Total declared work over the passphrase slots, as a multiple of one
   *  default unlock. 1 for an ordinary single-slot container. */
  multipleOfNormal: number;
}

/** One default unlock: Argon2id at 64 MiB, t=3. The denominator of the ratio. */
const NORMAL_ARGON2_UNITS = 64 * 1024 * 3;

/**
 * PBKDF2 iterations worth one default Argon2id unlock.
 *
 * Measured rather than assumed: PBKDF2 at 1,000,000 iterations took 4369 ms
 * against 874 ms for Argon2id at (64 MiB, t=3, p=4) on the same machine, so
 * one default unlock is about 200,000 iterations. Only the order of magnitude
 * matters — this decides whether the UI says "about 3x" or "about 40x", and
 * both readings lead the user to the same decision.
 */
const PBKDF2_ITERS_PER_NORMAL_UNIT = 200_000;

export function keym2UnlockCost(data: Uint8Array): Keym2UnlockCost | null {
  try {
    const core = parseKeym2CoreHeader(data);
    // Version-dependent, not the v2 constant. Reading slot_count from offset 8
    // in a v3 container reads the first byte of container_id — a random value,
    // so a v3 container would be priced from a random slot count or, more
    // often, silently refuse to be priced at all.
    const table = keym2SlotTableOffset(core.version);
    const slotCount = data[keym2SlotCountOffset(core.version)] as number;
    if (slotCount < SLOT_COUNT_MIN || slotCount > KEYM2_MAX_SLOTS) return null;

    const width = keym2SlotLen(core.cipher);
    if (data.length < table + slotCount * width) return null;

    let passphraseSlots = 0;
    let hkdfSlots = 0;
    let units = 0;
    for (let i = 0; i < slotCount; i++) {
      const at = table + i * width;

      const slot = parseKeym2Slot(data.subarray(at, at + width));
      // §4.4: a slot that will not parse is skipped by the walk, so it costs
      // nothing and must not be counted here either.
      if (slot === null) continue;
      if (slot.kdf.kdf === KEYM2_KDF_HKDF) {
        hkdfSlots++;
        continue;
      }
      passphraseSlots++;
      units +=
        slot.kdf.kdf === KdfId.PBKDF2
          ? slot.kdf.params.iterations / PBKDF2_ITERS_PER_NORMAL_UNIT
          : (slot.kdf.params.memoryKiB * slot.kdf.params.timeCost) / NORMAL_ARGON2_UNITS;
    }

    return {
      passphraseSlots,
      hkdfSlots,
      multipleOfNormal: Math.round(units * 10) / 10,
    };
  } catch {
    return null;
  }
}

/**
 * A sentence for the decrypt panel, or null when there is nothing worth
 * saying.
 *
 * Silent below the threshold on purpose. A notice that appears on every
 * ordinary unlock is one nobody reads by the time it matters, and the
 * container this exists for is not ordinary.
 */
export function describeUnlockCost(cost: Keym2UnlockCost | null): string | null {
  if (cost === null) return null;
  if (cost.multipleOfNormal < UNLOCK_COST_NOTICE_THRESHOLD) return null;
  const slots =
    cost.passphraseSlots > 1
      ? `${cost.passphraseSlots} password slots, each tried in turn,`
      : "settings well above this build's defaults,";
  return (
    `This backup declares ${slots} so unlocking it will take roughly ` +
    `${Math.round(cost.multipleOfNormal)}x as long as usual — and that cost is paid ` +
    `on every attempt, including a wrong password. Nothing is wrong with the file; ` +
    `it is what the container asks for. You can cancel while it runs.`
  );
}

/**
 * Where "slow" starts. 4x a default unlock is comfortably above anything the
 * app writes at its own ceiling for a single slot (Argon2id at 256 MiB t=10 is
 * 13.3 units by this measure, but that is one deliberate choice by the person
 * who made the backup, not a surprise) and well below the multi-slot shapes
 * this is for.
 */
export const UNLOCK_COST_NOTICE_THRESHOLD = 4;

export function inspectKeym2(
  data: Uint8Array
): { kdfLabel: string; cipherLabel: string; slots: number; weakKdf: string | null } | null {
  try {
    const core = parseKeym2CoreHeader(data);
    const table = keym2SlotTableOffset(core.version);
    const slotCount = data[keym2SlotCountOffset(core.version)] as number;
    if (slotCount < SLOT_COUNT_MIN || slotCount > KEYM2_MAX_SLOTS) return null;

    const width = keym2SlotLen(core.cipher);
    if (data.length < table + width) return null;
    const slot = parseKeym2Slot(data.subarray(table, table + width));


    const kdfLabel =
      slot === null
        ? "unrecognised slot"
        : // §4.6 and §4.7 both pair with HKDF, so this has to branch on the slot
          // *type*: on the KDF alone, a passkey slot would be reported as a
          // share set. Neither invents what the container does not carry — no k
          // or n for a share set, and nothing at all naming a credential.
          slot.slotType === KEYM2_SLOT_TYPE_PASSKEY
          ? "passkey / WebAuthn PRF (HKDF-SHA-256)"
          : slot.slotType === KEYM2_SLOT_TYPE_SHAMIR
          ? "Shamir share set (HKDF-SHA-256)"
          : // Unreachable for the three types above, since §6 forbids a
            // passphrase slot from declaring HKDF and the parser enforces it.
            // Kept as the default for a *future* HKDF slot type, which should
            // degrade to a plain label rather than fall through to a branch
            // that reads cost parameters HKDF does not have.
            slot.kdf.kdf === KEYM2_KDF_HKDF
          ? "HKDF-SHA-256"
          : slot.kdf.kdf === KdfId.PBKDF2
            ? `PBKDF2 (${slot.kdf.params.iterations.toLocaleString("en-US")} iters)`
            : `Argon2id (${Math.round(slot.kdf.params.memoryKiB / 1024)} MiB, t=${slot.kdf.params.timeCost}, p=${slot.kdf.params.parallelism})`;
    const cipherLabel =
      core.cipher === CipherId.AES_256_GCM
        ? "AES-256-GCM"
        : core.cipher === CipherId.CHACHA20_POLY1305
          ? "ChaCha20-Poly1305"
          : "AES-256-GCM + ChaCha20-Poly1305";
    // Only a passphrase slot has cost parameters to be weak. A Shamir or
    // passkey slot carries a 32-byte CSPRNG secret through HKDF, where "more
    // iterations" is not a thing that exists — reporting a floor for those
    // would be inventing a concern the construction does not have.
    const weakKdf =
      slot !== null &&
      slot.slotType !== KEYM2_SLOT_TYPE_PASSKEY &&
      slot.slotType !== KEYM2_SLOT_TYPE_SHAMIR &&
      slot.kdf.kdf !== KEYM2_KDF_HKDF
        ? describeWeakKdf(slot.kdf)
        : null;

    return { kdfLabel, cipherLabel, slots: slotCount, weakKdf };
  } catch {
    return null;
  }
}

/**
 * Does this look like a binary container this module handles — v2 or v3?
 *
 * The versions are named rather than compared against `KEYM2_VERSION`. Written
 * that way this asked "is this the version we currently *write*", which is a
 * different question and answered wrongly the moment the default moved: every
 * v2 backup in existence would have stopped being recognised as one, by a
 * module that opens them perfectly well.
 */
export function isKeym2Binary(data: Uint8Array): boolean {
  if (data.length < 5) return false;
  for (let i = 0; i < MAGIC.length; i++) if (data[i] !== MAGIC[i]) return false;
  return data[4] === KEYM2_VERSION_V2 || data[4] === KEYM2_VERSION_V3;
}
