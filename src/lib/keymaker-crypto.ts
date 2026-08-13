"use client";

/**
 * Keymaker crypto core — KEYM v1 self-describing container format.
 *
 * Ported features from the Morpheus project:
 *  - Self-describing header (KDF id, cipher id, KDF params, flags) that is
 *    tamper-authenticated by being passed as AAD to the AEAD.
 *  - Argon2id (via hash-wasm, lazily loaded) in addition to PBKDF2.
 *  - ChaCha20-Poly1305 (via @noble/ciphers) in addition to AES-256-GCM,
 *    plus a chained mode (AES-256-GCM then ChaCha20-Poly1305) with
 *    independent subkeys derived via HKDF-SHA-256.
 *  - NFC password normalization.
 *
 * Backward compatibility: `decryptData()` auto-detects KEYM v1, legacy
 * IBTZ v1 and headerless v0, delegating the latter two to the frozen
 * `src/lib/crypto.ts`.
 *
 * Byte layout (all multi-byte integers big-endian):
 *   magic "KEYM" (4) || version 0x01 (1)
 *   kdf_id (1): 0 = PBKDF2-HMAC-SHA-256, 1 = Argon2id
 *   cipher_id (1): 0 = AES-256-GCM, 1 = ChaCha20-Poly1305, 2 = chained
 *   kdf params: PBKDF2 → iterations uint32
 *               Argon2id → time_cost uint16 || memory_kib uint32 || parallelism uint8
 *   flags (1): bit0 = key file was used (UX hint only)
 *   salt: 16 bytes (PBKDF2) or 32 bytes (Argon2id)
 *   nonces: one 12-byte nonce (cipher 0/1) or two 12-byte nonces (cipher 2)
 *   ciphertext
 *
 * The settings block (magic through the last nonce byte) is passed as AAD
 * to every AEAD layer.
 */

import { decryptFile as legacyDecryptFile } from "./crypto";

export const KEYM_MAGIC = new Uint8Array([0x4b, 0x45, 0x59, 0x4d]); // "KEYM"
export const KEYM_VERSION = 1;

export enum KdfId {
  PBKDF2 = 0,
  ARGON2ID = 1,
}

export enum CipherId {
  AES_256_GCM = 0,
  CHACHA20_POLY1305 = 1,
  CHAINED = 2,
}

export interface Pbkdf2Params {
  iterations: number; // uint32
}

export interface Argon2idParams {
  timeCost: number; // uint16
  memoryKiB: number; // uint32
  parallelism: number; // uint8
}

export type KdfParams =
  | { kdf: KdfId.PBKDF2; params: Pbkdf2Params }
  | { kdf: KdfId.ARGON2ID; params: Argon2idParams };

export interface KeymakerOptions {
  kdf?: KdfParams;
  cipher?: CipherId;
}

export const DEFAULT_PBKDF2: Pbkdf2Params = { iterations: 1_000_000 };
export const DEFAULT_ARGON2ID: Argon2idParams = {
  timeCost: 3,
  memoryKiB: 65536,
  parallelism: 4,
};

export type DetectedFormat = "keym-v1" | "ibtz-v1" | "ibtz-v0";

const SALT_LEN_PBKDF2 = 16;
const SALT_LEN_ARGON2ID = 32;
const NONCE_LEN = 12;
const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100 MB
const MAX_PASSWORD_LENGTH = 1024;

/**
 * Largest container we will even attempt to decrypt: the 100 MB plaintext cap
 * plus the largest possible header (71 B) and tags (32 B), rounded up.
 *
 * The file picker already refuses oversized files, but pasted base64 reaches
 * decryptData() without passing that check. A core crypto API should enforce
 * its own resource limits rather than trusting whichever UI calls it.
 */
const MAX_CIPHERTEXT_SIZE = MAX_FILE_SIZE + 4096;

/**
 * Bounds on KDF cost parameters.
 *
 * These matter because a KEYM header is unauthenticated until the AEAD tag is
 * checked, and the tag cannot be checked until after the key is derived. That
 * ordering is forced by the format: the parameters say how to derive the key,
 * so they must be read first. AAD therefore stops an attacker from tampering
 * with parameters and still obtaining valid plaintext — but it cannot stop
 * those attacker-chosen values from being *executed* on the way to finding
 * that out.
 *
 * Unbounded, a hostile 200-byte file could request PBKDF2 with 4,294,967,295
 * iterations, or Argon2id with 4 TiB of memory, and the tab would hang or the
 * allocation would abort long before authentication ever ran.
 *
 * MAX values are the security control and apply everywhere. MIN values are
 * policy for *new* encryptions only — decryption deliberately accepts weaker
 * historical parameters, since refusing them would strand files that were
 * legitimately created with older or lower settings.
 */
export const KDF_LIMITS = {
  pbkdf2: {
    /** OWASP's current floor for PBKDF2-HMAC-SHA-256. Enforced on encrypt. */
    minIterations: 600_000,
    /** 10x the default. Beyond this, refuse rather than hang. */
    maxIterations: 10_000_000,
  },
  argon2id: {
    minTimeCost: 1,
    maxTimeCost: 10,
    /** 8 MiB .. 256 MiB, matching the range the UI exposes. */
    minMemoryKiB: 8 * 1024,
    maxMemoryKiB: 256 * 1024,
    minParallelism: 1,
    maxParallelism: 8,
  },
} as const;

/**
 * Reject KDF parameters we are not willing to execute.
 *
 * Called immediately after parsing a header and before any key derivation, and
 * again on caller-supplied encryption options so that a non-UI caller (a CLI, a
 * test, a future refactor) cannot bypass the validation the sliders imply.
 */
export function validateKdfParams(kdf: KdfParams, mode: "encrypt" | "decrypt"): void {
  const enforceMinimums = mode === "encrypt";

  const check = (name: string, value: number, min: number, max: number) => {
    if (!Number.isInteger(value)) {
      throw new Error(`Invalid KDF parameter: ${name} must be an integer.`);
    }
    // On decrypt, only the ceiling is a security control; the floor is policy.
    // Still require >= 1 — zero or negative is malformed under any reading.
    const effectiveMin = enforceMinimums ? min : 1;
    if (value < effectiveMin || value > max) {
      throw new Error(
        `KDF parameter out of range: ${name} is ${value}, expected ${effectiveMin}..${max}. ` +
          `Refusing to run a key derivation with unsafe cost parameters.`
      );
    }
  };

  if (kdf.kdf === KdfId.PBKDF2) {
    const { minIterations, maxIterations } = KDF_LIMITS.pbkdf2;
    check("PBKDF2 iterations", kdf.params.iterations, minIterations, maxIterations);
    return;
  }

  const a = KDF_LIMITS.argon2id;
  check("Argon2id timeCost", kdf.params.timeCost, a.minTimeCost, a.maxTimeCost);
  check("Argon2id memoryKiB", kdf.params.memoryKiB, a.minMemoryKiB, a.maxMemoryKiB);
  check("Argon2id parallelism", kdf.params.parallelism, a.minParallelism, a.maxParallelism);
}

const textEncoder = new TextEncoder();

/** Best-effort secure erase: zero-fill. Never uses Math.random. */
export function secureErase(buffer: ArrayBuffer | Uint8Array | null | undefined): void {
  if (!buffer) return;
  const view =
    buffer instanceof ArrayBuffer
      ? new Uint8Array(buffer)
      : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  view.fill(0);
}

/** Lazy-load hash-wasm (inlines its WASM as base64 — works fully offline). */
let hashWasmPromise: Promise<typeof import("hash-wasm")> | null = null;
function loadHashWasm(): Promise<typeof import("hash-wasm")> {
  if (!hashWasmPromise) {
    hashWasmPromise = import("hash-wasm");
  }
  return hashWasmPromise;
}

type NobleCiphers = typeof import("@noble/ciphers/chacha.js");
let noblePromise: Promise<NobleCiphers> | null = null;
function loadNoble(): Promise<NobleCiphers> {
  if (!noblePromise) {
    noblePromise = import("@noble/ciphers/chacha.js");
  }
  return noblePromise;
}

function validateCommon(dataBuffer: ArrayBuffer, password: string, isEncryption: boolean): void {
  if (!dataBuffer || !(dataBuffer instanceof ArrayBuffer)) {
    throw new Error("Valid data buffer is required.");
  }
  if (dataBuffer.byteLength === 0) {
    throw new Error("Cannot process empty data.");
  }
  if (isEncryption && dataBuffer.byteLength > MAX_FILE_SIZE) {
    throw new Error(`File is too large. Maximum size is ${MAX_FILE_SIZE / 1024 / 1024}MB.`);
  }
  // Decryption needs its own ceiling. The file picker enforces one, but pasted
  // base64 reaches decryptData() without going through it, and by then the
  // bytes have already been allocated and are about to hit a KDF.
  if (!isEncryption && dataBuffer.byteLength > MAX_CIPHERTEXT_SIZE) {
    throw new Error(`Encrypted data is too large. Maximum size is ${MAX_FILE_SIZE / 1024 / 1024}MB.`);
  }
  if (typeof password !== "string") {
    throw new Error("Password must be a string.");
  }
  if (password.length > MAX_PASSWORD_LENGTH) {
    throw new Error("Password is too long.");
  }
  if (password.includes("\0")) {
    throw new Error("Password contains invalid characters.");
  }
}

/**
 * Build KDF input material: NFC-normalized password bytes with optional
 * key file bytes appended after (same convention as the legacy format).
 */
function buildBaseMaterial(password: string, keyFileData: ArrayBuffer | null): Uint8Array {
  const passwordBytes = textEncoder.encode(password.normalize("NFC"));
  if (!keyFileData) {
    const out = new Uint8Array(new ArrayBuffer(passwordBytes.length));
    out.set(passwordBytes);
    return out;
  }
  const out = new Uint8Array(passwordBytes.length + keyFileData.byteLength);
  out.set(passwordBytes, 0);
  out.set(new Uint8Array(keyFileData), passwordBytes.length);
  return out;
}

/** Derive a 32-byte master key using the requested KDF. */
async function deriveMasterKey(
  baseMaterial: Uint8Array,
  salt: Uint8Array,
  kdf: KdfParams
): Promise<Uint8Array> {
  if (kdf.kdf === KdfId.PBKDF2) {
    const baseKey = await crypto.subtle.importKey("raw", baseMaterial as BufferSource, "PBKDF2", false, [
      "deriveBits",
    ]);
    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: salt as BufferSource,
        iterations: kdf.params.iterations,
        hash: "SHA-256",
      },
      baseKey,
      256
    );
    return new Uint8Array(bits);
  }
  const { argon2id } = await loadHashWasm();
  const p = kdf.params;
  // hash-wasm names: iterations = time_cost, memorySize = memory_kib
  const hash = await argon2id({
    password: baseMaterial,
    salt,
    iterations: p.timeCost,
    memorySize: p.memoryKiB,
    parallelism: p.parallelism,
    hashLength: 32,
    outputType: "binary",
  });
  return new Uint8Array(hash);
}

export interface CipherKeys {
  /** WebCrypto AES-GCM key (cipher 0), or null. */
  aesKey: CryptoKey | null;
  /** Raw 32-byte key for ChaCha20-Poly1305 (cipher 1), or null. */
  chachaKey: Uint8Array | null;
  /** Chained mode (cipher 2) subkeys, or null. */
  chained: { aesKey: CryptoKey; chachaKey: Uint8Array } | null;
  /** Raw master key material to erase after use (null when consumed into CryptoKey with no copy retained). */
  masterRaw: Uint8Array | null;
}

/** Turn a 32-byte master key into cipher-specific keys. */
async function masterToCipherKeys(master: Uint8Array, cipher: CipherId): Promise<CipherKeys> {
  if (cipher === CipherId.AES_256_GCM) {
    const aesKey = await crypto.subtle.importKey("raw", master as BufferSource, { name: "AES-GCM" }, false, [
      "encrypt",
      "decrypt",
    ]);
    return { aesKey, chachaKey: null, chained: null, masterRaw: master };
  }
  if (cipher === CipherId.CHACHA20_POLY1305) {
    const chachaKey = new Uint8Array(master); // copy; master will be erased by caller
    return { aesKey: null, chachaKey, chained: null, masterRaw: master };
  }
  // Chained: HKDF-SHA-256 expand into two independent 32-byte subkeys.
  const hkdfKey = await crypto.subtle.importKey("raw", master as BufferSource, "HKDF", false, ["deriveBits"]);
  const deriveSubkey = async (info: string): Promise<Uint8Array> => {
    const bits = await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(32), // salt-free expansion; master key already uniform
        info: textEncoder.encode(info) as BufferSource,
      },
      hkdfKey,
      256
    );
    return new Uint8Array(bits);
  };
  const aesBytes = await deriveSubkey("keymaker-aes");
  const chachaBytes = await deriveSubkey("keymaker-chacha");
  const aesKey = await crypto.subtle.importKey("raw", aesBytes as BufferSource, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
  secureErase(aesBytes);
  return {
    aesKey: null,
    chachaKey: null,
    chained: { aesKey, chachaKey: chachaBytes },
    masterRaw: master,
  };
}

function kdfHeaderLength(kdf: KdfParams): number {
  // magic(4) + version(1) + kdf_id(1) + cipher_id(1) + params + flags(1) + salt + nonces
  const paramLen = kdf.kdf === KdfId.PBKDF2 ? 4 : 2 + 4 + 1;
  const saltLen = kdf.kdf === KdfId.PBKDF2 ? SALT_LEN_PBKDF2 : SALT_LEN_ARGON2ID;
  return 4 + 1 + 1 + 1 + paramLen + 1 + saltLen; // excludes nonces
}

/**
 * Encrypt data into a KEYM v1 container.
 * NOTE: the caller's keyFileBuffer is zeroed in-place after use.
 */
export async function encryptData(
  dataBuffer: ArrayBuffer,
  password: string,
  keyFileBuffer: ArrayBuffer | null,
  options: KeymakerOptions = {}
): Promise<ArrayBuffer> {
  validateCommon(dataBuffer, password, true);
  if (!password) {
    throw new Error("A password is required for encryption.");
  }
  if (!crypto.subtle) {
    throw new Error("Web Crypto API not available.");
  }

  const kdf: KdfParams = options.kdf ?? { kdf: KdfId.PBKDF2, params: { ...DEFAULT_PBKDF2 } };
  const cipher = options.cipher ?? CipherId.AES_256_GCM;

  // Validate caller-supplied options rather than trusting that a UI slider
  // constrained them. Encryption enforces the policy floor as well as the
  // ceiling: writing a new file at 1,000 PBKDF2 iterations is a mistake worth
  // refusing, even though we will still *read* such a file.
  validateKdfParams(kdf, "encrypt");
  if (cipher !== CipherId.AES_256_GCM && cipher !== CipherId.CHACHA20_POLY1305 && cipher !== CipherId.CHAINED) {
    throw new Error(`Invalid cipher id: ${cipher}.`);
  }

  const saltLen = kdf.kdf === KdfId.PBKDF2 ? SALT_LEN_PBKDF2 : SALT_LEN_ARGON2ID;
  const salt = crypto.getRandomValues(new Uint8Array(saltLen));
  const nonceCount = cipher === CipherId.CHAINED ? 2 : 1;
  const nonces: Uint8Array[] = [];
  for (let i = 0; i < nonceCount; i++) {
    nonces.push(crypto.getRandomValues(new Uint8Array(NONCE_LEN)));
  }

  const headerLen = kdfHeaderLength(kdf) + nonceCount * NONCE_LEN;
  const header = new Uint8Array(headerLen);
  let o = 0;
  header.set(KEYM_MAGIC, o);
  o += 4;
  header[o++] = KEYM_VERSION;
  header[o++] = kdf.kdf;
  header[o++] = cipher;
  if (kdf.kdf === KdfId.PBKDF2) {
    new DataView(header.buffer).setUint32(o, kdf.params.iterations, false);
    o += 4;
  } else {
    const dv = new DataView(header.buffer);
    dv.setUint16(o, kdf.params.timeCost, false);
    o += 2;
    dv.setUint32(o, kdf.params.memoryKiB, false);
    o += 4;
    header[o++] = kdf.params.parallelism;
  }
  header[o++] = keyFileBuffer ? 0x01 : 0x00;
  header.set(salt, o);
  o += salt.length;
  for (const n of nonces) {
    header.set(n, o);
    o += n.length;
  }

  let baseMaterial: Uint8Array | null = null;
  let keys: CipherKeys | null = null;
  let ciphertext: Uint8Array | null = null;

  try {
    baseMaterial = buildBaseMaterial(password, keyFileBuffer);
    const master = await deriveMasterKey(baseMaterial, salt, kdf);
    keys = await masterToCipherKeys(master, cipher);

    // The settings block IS the header — pass it as AAD.
    const aad = header as BufferSource;
    const plain = new Uint8Array(dataBuffer);

    if (cipher === CipherId.AES_256_GCM) {
      const ct = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonces[0] as BufferSource, additionalData: aad },
        keys.aesKey!,
        plain as BufferSource
      );
      ciphertext = new Uint8Array(ct);
    } else if (cipher === CipherId.CHACHA20_POLY1305) {
      const { chacha20poly1305 } = await loadNoble();
      ciphertext = chacha20poly1305(keys.chachaKey!, nonces[0]!, header).encrypt(plain);
    } else {
      // Chained: inner AES-256-GCM (AAD = settings block), then outer
      // ChaCha20-Poly1305 (AAD = settings block).
      const inner = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonces[0] as BufferSource, additionalData: aad },
        keys.chained!.aesKey,
        plain as BufferSource
      );
      const { chacha20poly1305 } = await loadNoble();
      ciphertext = chacha20poly1305(keys.chained!.chachaKey, nonces[1]!, header).encrypt(new Uint8Array(inner));
      secureErase(new Uint8Array(inner));
    }

    const out = new Uint8Array(header.length + ciphertext.length);
    out.set(header, 0);
    out.set(ciphertext, header.length);
    return out.buffer;
  } catch (error) {
    if (error instanceof Error && /required|too (large|long)|invalid characters|not available/i.test(error.message)) {
      throw error;
    }
    throw new Error("Encryption failed. Please try again.");
  } finally {
    if (baseMaterial) secureErase(baseMaterial);
    if (keyFileBuffer) secureErase(keyFileBuffer);
    secureErase(salt);
    for (const n of nonces) secureErase(n);
    if (keys) {
      if (keys.masterRaw) secureErase(keys.masterRaw);
      if (keys.chachaKey) secureErase(keys.chachaKey);
      if (keys.chained) secureErase(keys.chained.chachaKey);
    }
    if (ciphertext) secureErase(ciphertext);
  }
}

interface ParsedKeym {
  kdf: KdfParams;
  cipher: CipherId;
  flags: number;
  salt: Uint8Array;
  nonces: Uint8Array[];
  settingsBlock: Uint8Array; // magic .. last nonce byte (AAD)
  ciphertext: Uint8Array;
}

function parseKeym(data: Uint8Array): ParsedKeym {
  if (data.length < 8) throw new Error("Invalid KEYM data: too short.");
  if (data[4] !== KEYM_VERSION) {
    throw new Error("This file was encrypted with a newer KEYM version. Please update the app.");
  }
  const kdfId = data[5]!;
  const cipherId = data[6]!;
  if (kdfId !== KdfId.PBKDF2 && kdfId !== KdfId.ARGON2ID) {
    throw new Error("Invalid KEYM data: unknown KDF id.");
  }
  if (cipherId < 0 || cipherId > 2) {
    throw new Error("Invalid KEYM data: unknown cipher id.");
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let o = 7;
  let kdf: KdfParams;
  if (kdfId === KdfId.PBKDF2) {
    kdf = { kdf: KdfId.PBKDF2, params: { iterations: dv.getUint32(o, false) } };
    o += 4;
  } else {
    kdf = {
      kdf: KdfId.ARGON2ID,
      params: { timeCost: dv.getUint16(o, false), memoryKiB: dv.getUint32(o + 2, false), parallelism: data[o + 6]! },
    };
    o += 7;
  }
  // Bound the cost parameters the moment they are read, and before any caller
  // can reach deriveMasterKey() with them. Everything above this line is
  // attacker-controlled: the AEAD tag that authenticates these bytes cannot be
  // verified until after the key has been derived from them, so the header is
  // untrusted input right up to that point.
  validateKdfParams(kdf, "decrypt");

  const flags = data[o++]!;
  const saltLen = kdfId === KdfId.PBKDF2 ? SALT_LEN_PBKDF2 : SALT_LEN_ARGON2ID;
  const nonceCount = cipherId === CipherId.CHAINED ? 2 : 1;
  const minLen = o + saltLen + nonceCount * NONCE_LEN + 16; // + AEAD tag
  if (data.length < minLen) throw new Error("Invalid KEYM data: too short.");
  const salt = data.slice(o, o + saltLen);
  o += saltLen;
  const nonces: Uint8Array[] = [];
  for (let i = 0; i < nonceCount; i++) {
    nonces.push(data.slice(o, o + NONCE_LEN));
    o += NONCE_LEN;
  }
  const settingsBlock = data.slice(0, o);
  const ciphertext = data.slice(o);
  return { kdf, cipher: cipherId as CipherId, flags, salt, nonces, settingsBlock, ciphertext };
}

/** Detect the wire format of an encrypted blob. */
export function detectFormat(data: Uint8Array): DetectedFormat {
  if (
    data.length >= 5 &&
    data[0] === KEYM_MAGIC[0] &&
    data[1] === KEYM_MAGIC[1] &&
    data[2] === KEYM_MAGIC[2] &&
    data[3] === KEYM_MAGIC[3]
  ) {
    return "keym-v1";
  }
  if (
    data.length >= 5 &&
    data[0] === 0x49 && // I
    data[1] === 0x42 && // B
    data[2] === 0x54 && // T
    data[3] === 0x5a // Z
  ) {
    return "ibtz-v1";
  }
  return "ibtz-v0";
}

export interface KeymInspection {
  /** Human-readable KDF description, e.g. "Argon2id (64 MiB, t=3, p=4)". */
  kdfLabel: string;
  /** Human-readable cipher description. */
  cipherLabel: string;
}

/**
 * Read the self-describing KEYM v1 header and return plain-English labels
 * for its parameters. Returns null for non-KEYM or unparsable data.
 * UX-only helper — decryption derives everything it needs itself.
 */
export function inspectKeym(data: Uint8Array): KeymInspection | null {
  try {
    if (detectFormat(data) !== "keym-v1") return null;
    const parsed = parseKeym(data);
    const kdfLabel =
      parsed.kdf.kdf === KdfId.PBKDF2
        ? `PBKDF2 (${parsed.kdf.params.iterations.toLocaleString("en-US")} iters)`
        : `Argon2id (${Math.round(parsed.kdf.params.memoryKiB / 1024)} MiB, t=${parsed.kdf.params.timeCost}, p=${parsed.kdf.params.parallelism})`;
    const cipherLabel =
      parsed.cipher === CipherId.AES_256_GCM
        ? "AES-256-GCM"
        : parsed.cipher === CipherId.CHACHA20_POLY1305
          ? "ChaCha20-Poly1305"
          : "AES-256-GCM + ChaCha20-Poly1305";
    return { kdfLabel, cipherLabel };
  } catch {
    return null;
  }
}

export interface DecryptResult {
  data: ArrayBuffer;
  format: DetectedFormat;
  /** True when the KEYM header's key-file flag was set (UX hint only). */
  keyFileUsed: boolean;
}

/**
 * Decrypt a KEYM v1, IBTZ v1, or headerless v0 blob. Format is
 * auto-detected; legacy formats are delegated to the frozen crypto.ts.
 * NOTE: the caller's keyFileBuffer is zeroed in-place after use.
 */
export async function decryptData(
  encryptedBuffer: ArrayBuffer,
  password: string,
  keyFileBuffer: ArrayBuffer | null
): Promise<DecryptResult> {
  validateCommon(encryptedBuffer, password, false);
  if (!password && !keyFileBuffer) {
    throw new Error("A password or key file is required for decryption.");
  }
  if (!crypto.subtle) {
    throw new Error("Web Crypto API not available.");
  }

  const fullData = new Uint8Array(encryptedBuffer);
  const format = detectFormat(fullData);

  if (format !== "keym-v1") {
    const data = await legacyDecryptFile(encryptedBuffer, password, keyFileBuffer);
    return { data, format, keyFileUsed: keyFileBuffer !== null };
  }

  let parsed: ParsedKeym | null = null;
  let baseMaterial: Uint8Array | null = null;
  let keys: CipherKeys | null = null;

  try {
    parsed = parseKeym(fullData);
    baseMaterial = buildBaseMaterial(password, keyFileBuffer);
    const master = await deriveMasterKey(baseMaterial, parsed.salt, parsed.kdf);
    keys = await masterToCipherKeys(master, parsed.cipher);

    const aad = parsed.settingsBlock as BufferSource;
    let plain: ArrayBuffer | Uint8Array;

    if (parsed.cipher === CipherId.AES_256_GCM) {
      plain = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: parsed.nonces[0] as BufferSource, additionalData: aad },
        keys.aesKey!,
        parsed.ciphertext as BufferSource
      );
    } else if (parsed.cipher === CipherId.CHACHA20_POLY1305) {
      const { chacha20poly1305 } = await loadNoble();
      plain = chacha20poly1305(keys.chachaKey!, parsed.nonces[0]!, parsed.settingsBlock).decrypt(parsed.ciphertext);
    } else {
      // Chained: outer ChaCha20-Poly1305 then inner AES-256-GCM, both with
      // the settings block as AAD.
      const { chacha20poly1305 } = await loadNoble();
      const inner = chacha20poly1305(keys.chained!.chachaKey, parsed.nonces[1]!, parsed.settingsBlock).decrypt(
        parsed.ciphertext
      );
      try {
        plain = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: parsed.nonces[0] as BufferSource, additionalData: aad },
          keys.chained!.aesKey,
          inner as BufferSource
        );
      } finally {
        secureErase(inner);
      }
    }

    const out =
      plain instanceof Uint8Array
        ? (plain.buffer.slice(plain.byteOffset, plain.byteOffset + plain.byteLength) as ArrayBuffer)
        : plain;
    return { data: out, format, keyFileUsed: (parsed.flags & 0x01) !== 0 };
  } catch (error) {
    if (error instanceof Error && /required|not available|newer KEYM version/i.test(error.message)) {
      throw error;
    }
    throw new Error(
      "Decryption failed. The password or key file may be incorrect, or the data may be corrupted."
    );
  } finally {
    if (parsed) {
      secureErase(parsed.salt);
      for (const n of parsed.nonces) secureErase(n);
      secureErase(parsed.ciphertext);
    }
    if (baseMaterial) secureErase(baseMaterial);
    if (keyFileBuffer) secureErase(keyFileBuffer);
    if (keys) {
      if (keys.masterRaw) secureErase(keys.masterRaw);
      if (keys.chachaKey) secureErase(keys.chachaKey);
      if (keys.chained) secureErase(keys.chained.chachaKey);
    }
  }
}
