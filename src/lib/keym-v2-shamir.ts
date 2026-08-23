/**
 * Shamir share sets for KEYM v2 — `docs/FORMAT-V2-DESIGN.md` §4.6.
 *
 * The container layout is untouched by everything in this file. A share set is
 * a slot whose secret is reconstructed from paper instead of typed; §4.3 onward
 * is unchanged, which is what the multi-slot envelope was built to allow.
 *
 * ## Why this is its own file
 *
 * The field arithmetic and the share encoding have no dependency on the
 * container at all — they turn 32 bytes into `n` strings and back. Keeping them
 * separable means they can be tested as arithmetic, which is what the negative
 * control in §4.5 needs: it has to build a *deliberately broken* split and show
 * an attack succeeds against it.
 *
 * ## The one thing to be careful about
 *
 * §4.5 requires the polynomial coefficients to be independent per byte position
 * *and* per coefficient index. Sharing one coefficient set across all 32
 * positions still round-trips perfectly — every test anyone would naturally
 * write still passes — while leaving each share equal to the secret XOR a single
 * repeated byte, so 256 candidates exhaust it from one share. `shamirSplit`
 * draws `(k-1) * 32` bytes in one go for that reason, and the test suite carries
 * the attack in both directions.
 */

import { KeymakerError, secureErase } from "./keymaker-crypto";

/** §4.6, the share record: set id, threshold, index, value, checksum. */
export const SHARE_SET_ID_LEN = 4;
export const SHARE_VALUE_LEN = 32;
export const SHARE_CHECKSUM_LEN = 4;
export const SHARE_BODY_LEN = SHARE_SET_ID_LEN + 1 + 1 + SHARE_VALUE_LEN; // 38
export const SHARE_LEN = SHARE_BODY_LEN + SHARE_CHECKSUM_LEN; // 42

/**
 * §4.6. `k` binds on read; `n` is absent from the share record, so its bound
 * binds the writer only. 16 is a print-kit bound rather than a field bound —
 * the index byte allows 255 — so it can be raised without touching the
 * encoding.
 */
export const SHAMIR_K_MIN = 2;
export const SHAMIR_K_MAX = 16;
export const SHAMIR_N_MAX = 16;

/**
 * §4.6. Uppercase, so the whole string stays inside QR alphanumeric mode at 5.5
 * bits per character. It deliberately does not begin `KEYM`: that is the binary
 * magic, and §7 exists because `KEYM1:` colliding with it made a text backup
 * pasted into the app report "unsupported version 49".
 */
export const SHARE_PREFIX = "KMSHARE1:";
const SHARE_GROUP = 4;

/** Crockford's alphabet, which omits I, L, O and U. */
const B32_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/**
 * Explicitly ASCII rather than a Unicode-aware `\s`. Two implementations that
 * disagree about whether U+00A0 is whitespace disagree about whether a printed
 * share decodes.
 */
const ASCII_WHITESPACE = " \t\n\r\v\f";

/** GF(2^8) modulo x^8 + x^4 + x^3 + x + 1 — the AES field. */
const GF_REDUCTION = 0x1b;

const textEncoder = new TextEncoder();
const CTX_SHARE_SET = textEncoder.encode("keymaker.v2.share-set");
const CTX_SHARE_CHECKSUM = textEncoder.encode("keymaker.v2.share-checksum");

function reject(): never {
  throw new Error("Decryption failed.");
}

function usage(message: string): never {
  throw new KeymakerError("invalid-input", message);
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
// The field (§4.6)
// ---------------------------------------------------------------------------

/**
 * §4.6. Multiply in GF(2^8), carry-less, with both conditionals as arithmetic
 * masks.
 *
 * §4.6 forbids the log/antilog table version, and not as a style preference:
 * every value multiplied here is a share value or a coefficient, so a table
 * indexed by one of them is a cache-timing oracle on the secret. `-(x & 1)` is
 * 0 or -1 under `|0`, and `-1 & v === v`.
 */
export function gfMul(a: number, b: number): number {
  let p = 0;
  let x = a & 0xff;
  let y = b & 0xff;
  for (let i = 0; i < 8; i++) {
    p ^= x & -(y & 1);
    y >>= 1;
    const high = x & 0x80;
    x = (x << 1) & 0xff;
    x ^= GF_REDUCTION & -(high >> 7);
  }
  return p & 0xff;
}

/**
 * §4.6. `a^254 === a^-1`, by Fermat: the multiplicative group has order 255.
 *
 * Square-and-multiply over the *public* constant 254, so branching on the
 * exponent's bits is not a secret-dependent branch. `gfInv(0)` is 0 and is never
 * reached — the only inversions here are of `x_i ^ x_m` for distinct indices,
 * and duplicates are rejected before this runs.
 */
export function gfInv(a: number): number {
  let result = 1;
  const bits = [1, 1, 1, 1, 1, 1, 1, 0]; // 254, most significant bit first
  for (const bit of bits) {
    result = gfMul(result, result);
    if (bit) result = gfMul(result, a);
  }
  return result;
}

export interface ShamirPart {
  index: number;
  value: Uint8Array;
}

/**
 * §4.6. Split a 32-byte secret into `n` parts, any `k` of which reconstruct it.
 *
 * `coefficients` exists for cross-implementation byte comparison and nothing
 * else — §4.5 forbids caller-supplied values in any interface meant for real
 * data, and the reason is unusually direct here: the coefficients are the only
 * thing standing between one share and the secret. Layout is `(k-1)` blocks of
 * 32 bytes, block `c-1` holding `a_{c,j}` for every byte position `j`, matching
 * `reference/keym2.py` so `crosstest2.py` can drive both.
 */
export function shamirSplit(
  secret: Uint8Array,
  k: number,
  n: number,
  coefficients?: Uint8Array
): ShamirPart[] {
  if (!Number.isInteger(k) || k < SHAMIR_K_MIN || k > SHAMIR_K_MAX) {
    usage(`Shamir threshold must be ${SHAMIR_K_MIN}..${SHAMIR_K_MAX}.`);
  }
  if (!Number.isInteger(n) || n < k || n > SHAMIR_N_MAX) {
    usage(`Shamir share count must be ${k}..${SHAMIR_N_MAX}.`);
  }
  if (secret.length !== SHARE_VALUE_LEN) usage("Share secret must be 32 bytes.");

  const width = SHARE_VALUE_LEN;
  const need = (k - 1) * width;
  let coeffs: Uint8Array;
  if (coefficients === undefined) {
    // §4.5: independently per byte position *and* per coefficient index. One
    // draw of (k-1)*32 is exactly that; the failure mode the section describes
    // is drawing (k-1) bytes and reusing them across positions.
    coeffs = crypto.getRandomValues(new Uint8Array(need));
  } else {
    if (coefficients.length !== need) usage(`Expected ${need} coefficient bytes for k=${k}.`);
    coeffs = coefficients;
  }

  const parts: ShamirPart[] = [];
  for (let x = 1; x <= n; x++) {
    const value = new Uint8Array(width);
    for (let j = 0; j < width; j++) {
      // Horner, from the highest-degree coefficient down to the secret byte.
      let acc = 0;
      for (let c = k - 1; c >= 1; c--) {
        acc = gfMul(acc, x) ^ (coeffs[(c - 1) * width + j] as number);
      }
      value[j] = gfMul(acc, x) ^ (secret[j] as number);
    }
    parts.push({ index: x, value });
  }
  return parts;
}

/**
 * §4.6. Lagrange interpolation at x = 0, per byte position.
 *
 * `s_j = XOR_i  y_i,j * PROD_{m != i} x_m * inv(x_i ^ x_m)`
 *
 * Both subtractions from the textbook form vanished in characteristic 2:
 * `(0 - x_m)` is `x_m` and `(x_i - x_m)` is `x_i ^ x_m`. Transcribing the
 * rational version and leaving a minus sign in is the classic way to end up
 * with something that is wrong only for some inputs.
 *
 * Reconstructs from exactly the parts given; §4.6's "k lowest-indexed distinct"
 * selection belongs to `combineShares`.
 */
export function shamirCombine(parts: ShamirPart[]): Uint8Array {
  if (parts.length === 0) reject();
  const xs = parts.map((p) => p.index);
  if (new Set(xs).size !== xs.length) reject();
  if (xs.some((x) => x === 0)) reject();
  const width = (parts[0] as ShamirPart).value.length;
  if (parts.some((p) => p.value.length !== width)) reject();

  const out = new Uint8Array(width);
  for (const { index: xi, value: yi } of parts) {
    let num = 1;
    let den = 1;
    for (const { index: xm } of parts) {
      if (xm === xi) continue;
      num = gfMul(num, xm);
      den = gfMul(den, xi ^ xm);
    }
    const basis = gfMul(num, gfInv(den));
    for (let j = 0; j < width; j++) {
      out[j] = (out[j] as number) ^ gfMul(yi[j] as number, basis);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// The share record (§4.6)
// ---------------------------------------------------------------------------

/**
 * §4.6. Derived from the slot salt, not stored.
 *
 * The salt is already in the container in the clear, so this lets a reader
 * reject a share from a different set before doing any field arithmetic. Mixing
 * two sets otherwise reconstructs a perfectly clean secret that happens to be
 * the wrong one, and fails at the unwrap with the same generic error as a wrong
 * password — the specific confusion this catches.
 */
export async function shareSetId(slotSalt: Uint8Array): Promise<Uint8Array> {
  if (slotSalt.length !== 32) usage("Slot salt must be 32 bytes.");
  const digest = await crypto.subtle.digest("SHA-256", concat([CTX_SHARE_SET, slotSalt]) as BufferSource);
  return new Uint8Array(digest).slice(0, SHARE_SET_ID_LEN);
}

async function shareChecksum(body: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", concat([CTX_SHARE_CHECKSUM, body]) as BufferSource);
  return new Uint8Array(digest).slice(0, SHARE_CHECKSUM_LEN);
}

export interface Share {
  setId: Uint8Array;
  threshold: number;
  index: number;
  value: Uint8Array;
}

export async function packShare(share: Share): Promise<Uint8Array> {
  if (share.setId.length !== SHARE_SET_ID_LEN) usage("Share set id must be 4 bytes.");
  if (share.value.length !== SHARE_VALUE_LEN) usage("Share value must be 32 bytes.");
  if (share.threshold < SHAMIR_K_MIN || share.threshold > SHAMIR_K_MAX) {
    usage(`Share threshold must be ${SHAMIR_K_MIN}..${SHAMIR_K_MAX}.`);
  }
  if (share.index < 1 || share.index > 255) usage("Share index must be 1..255.");

  const body = concat([share.setId, new Uint8Array([share.threshold, share.index]), share.value]);
  return concat([body, await shareChecksum(body)]);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}

/** §4.6 and §6, for one share. Parsing is validation, as with `parseKeym2Slot`. */
export async function parseShare(record: Uint8Array): Promise<Share> {
  if (record.length !== SHARE_LEN) reject();
  const body = record.subarray(0, SHARE_BODY_LEN);
  const checksum = record.subarray(SHARE_BODY_LEN);
  if (!bytesEqual(checksum, await shareChecksum(body))) reject();

  const threshold = body[SHARE_SET_ID_LEN] as number;
  const index = body[SHARE_SET_ID_LEN + 1] as number;
  if (threshold < SHAMIR_K_MIN || threshold > SHAMIR_K_MAX) reject();
  if (index === 0) reject();

  return {
    setId: body.slice(0, SHARE_SET_ID_LEN),
    threshold,
    index,
    value: body.slice(SHARE_SET_ID_LEN + 2),
  };
}

// ---------------------------------------------------------------------------
// Share text (§4.6)
// ---------------------------------------------------------------------------

/** §4.6. Crockford base32, no padding character, zero padding bits. */
export function b32Encode(data: Uint8Array): string {
  const nchars = Math.ceil((data.length * 8) / 5);

  // Bit-at-a-time rather than a BigInt: the same arithmetic, no allocation, and
  // the trailing partial group is zero-filled, which is what makes the decoder's
  // padding check meaningful.
  let out = "";
  let acc = 0;
  let bits = 0;
  for (const byte of data) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(acc >> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET[(acc << (5 - bits)) & 31];
  if (out.length !== nchars) reject();
  return out;
}

/**
 * §4.6. Case-insensitive, I/L map to 1, O maps to 0, hyphens and ASCII
 * whitespace ignored, everything else rejected.
 *
 * Non-zero padding bits in the final character are rejected so one share has
 * exactly one encoding. Without that check the last character has 16 spellings
 * and two people cannot compare printed shares by eye.
 */
export function b32Decode(text: string, nbytes: number): Uint8Array {
  const values: number[] = [];
  for (const ch of text) {
    if (ch === "-" || ASCII_WHITESPACE.includes(ch)) continue;
    let u = ch.toUpperCase();
    if (u === "I" || u === "L") u = "1";
    else if (u === "O") u = "0";
    const pos = B32_ALPHABET.indexOf(u);
    if (pos < 0) reject();
    values.push(pos);
  }

  const nchars = Math.ceil((nbytes * 8) / 5);
  if (values.length !== nchars) reject();

  const out = new Uint8Array(nbytes);
  let acc = 0;
  let bits = 0;
  let at = 0;
  for (const v of values) {
    acc = (acc << 5) | v;
    bits += 5;
    if (bits >= 8) {
      out[at++] = (acc >> (bits - 8)) & 0xff;
      bits -= 8;
    }
  }
  // Whatever is left is padding, and §4.6 requires it to be zero.
  if (bits > 0 && (acc & ((1 << bits) - 1)) !== 0) reject();
  if (at !== nbytes) reject();
  return out;
}

export async function encodeShare(share: Share): Promise<string> {
  const body = b32Encode(await packShare(share));
  const groups: string[] = [];
  for (let i = 0; i < body.length; i += SHARE_GROUP) {
    groups.push(body.slice(i, i + SHARE_GROUP));
  }
  return SHARE_PREFIX + groups.join("-");
}

export async function decodeShare(text: string): Promise<Share> {
  const stripped = text.trim();
  if (!stripped.toUpperCase().startsWith(SHARE_PREFIX)) reject();
  return parseShare(b32Decode(stripped.slice(SHARE_PREFIX.length), SHARE_LEN));
}

/**
 * §4.6 and §6. Decode, validate as a set, and reconstruct the share secret.
 *
 * The set-level rules live here rather than in `parseShare` because none of them
 * are properties of one share: agreement on `k`, distinct indices, and "exactly
 * the `k` lowest-indexed distinct shares".
 *
 * That last rule is why this sorts. With genuine shares every k-subset gives the
 * same answer, so it looks like it cannot matter — but with one corrupt share
 * the subsets give *different* wrong answers, and two implementations that
 * disagree about which wrong answer they produce cannot be compared by whoever
 * is trying to work out which share is bad.
 */
export async function combineShares(texts: string[], expectedSetId?: Uint8Array): Promise<Uint8Array> {
  if (texts.length === 0) reject();
  const shares = await Promise.all(texts.map((t) => decodeShare(t)));

  // Everything from here is inside the `finally`, because a decoded share value
  // is key material of the same class as the secret it reconstructs — k of them
  // *are* the secret — and every exit from this function is a `reject()` from
  // one of the set-level rules below. The caller erases what this returns; the
  // inputs it was built from are this function's to clean up, and nobody else
  // holds a reference to them. `shamirCombine` allocates its own output, so
  // erasing the parts afterwards cannot reach it.
  try {
    const thresholds = new Set(shares.map((s) => s.threshold));
    if (thresholds.size !== 1) reject();
    const k = shares[0]?.threshold as number;

    const first = shares[0] as Share;
    if (shares.some((s) => !bytesEqual(s.setId, first.setId))) reject();
    if (expectedSetId !== undefined && !bytesEqual(first.setId, expectedSetId)) reject();

    const indices = shares.map((s) => s.index);
    if (new Set(indices).size !== indices.length) reject();
    if (shares.length < k) reject();

    const chosen = [...shares].sort((a, b) => a.index - b.index).slice(0, k);
    return shamirCombine(chosen.map((s) => ({ index: s.index, value: s.value })));
  } finally {
    for (const share of shares) secureErase(share.value);
  }
}

/** §7 as amended by §4.6 — a share is not a container, and must not be read as one. */
export function isKeym2Share(text: string): boolean {
  return text.trimStart().toUpperCase().startsWith(SHARE_PREFIX);
}
