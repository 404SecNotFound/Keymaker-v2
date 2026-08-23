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

/**
 * Algorithm selection for encryption. Both fields are **required**.
 *
 * They used to be optional, falling back to PBKDF2 + AES-256-GCM. That made
 * `encryptData(data, password, keyFile)` a valid call that silently produced
 * the weaker KDF — fine for the UI, which always passes explicit values, but a
 * trap for a CLI, an extension, or a future refactor. Choosing a KDF is policy
 * and belongs to the caller; a crypto primitive should not quietly decide it.
 *
 * DEFAULT_PBKDF2 and DEFAULT_ARGON2ID remain exported for callers that want
 * the recommended parameters — they just have to say so.
 */
export interface KeymakerOptions {
  kdf: KdfParams;
  cipher: CipherId;
}

export const DEFAULT_PBKDF2: Pbkdf2Params = { iterations: 1_000_000 };
export const DEFAULT_ARGON2ID: Argon2idParams = {
  timeCost: 3,
  memoryKiB: 65536,
  parallelism: 4,
};

export type DetectedFormat = "keym-v1" | "keym-v2" | "ibtz-v1" | "ibtz-v0";

const SALT_LEN_PBKDF2 = 16;
const SALT_LEN_ARGON2ID = 32;
const NONCE_LEN = 12;
/**
 * Largest plaintext we will encrypt. Exported so the UI enforces the *same*
 * number rather than declaring a parallel copy that can drift.
 */
export const MAX_PLAINTEXT_SIZE = 100 * 1024 * 1024; // 100 MB
const MAX_FILE_SIZE = MAX_PLAINTEXT_SIZE;
/**
 * Longest password we will accept.
 *
 * Exported (U24) because the UI now discloses it. A second copy of the number
 * in the component would be free to drift from the one actually enforced here,
 * and a stated limit that disagrees with the real one is worse than no stated
 * limit at all.
 */
export const MAX_PASSWORD_LENGTH = 1024;

/**
 * Largest container we will even attempt to decrypt: the 100 MB plaintext cap
 * plus the largest possible header (71 B) and tags (32 B), rounded up.
 *
 * The file picker already refuses oversized files, but pasted base64 reaches
 * decryptData() without passing that check. A core crypto API should enforce
 * its own resource limits rather than trusting whichever UI calls it.
 */
/**
 * What to tell someone whose backup is too big for this app to open.
 *
 * The cap is a property of *this build*, not of the format and not of their
 * file. §5 of FORMAT-V2-DESIGN.md is chunked precisely so a payload need never
 * be held whole; the browser holds it anyway, twice — once as the container
 * and once as the assembled plaintext — so 100 MB is where a tab stops being
 * reliable. `reference/keym2.py` has no such limit.
 *
 * Until now both refusals said a variant of "maximum size is 100MB", which on
 * the *decrypt* side is not merely unhelpful but wrong: it presents a dead end
 * as a property of the backup and tells the reader to pick a smaller file,
 * which is not a thing that can be done to a backup. Someone recovering an
 * inheritance would reasonably conclude the archive was unusable.
 *
 * Verified rather than asserted before being promised to anyone: a 150 MiB
 * file encrypted and decrypted through `keym2.py` round-trips byte-identically
 * in about two seconds each way, at roughly 634 MiB peak RSS.
 */
export function oversizeRecoveryHelp(): string {
  return (
    `This backup is larger than the ${MAX_PLAINTEXT_SIZE / 1024 / 1024} MB this app can open in a ` +
    `browser tab, which has to hold the container and the recovered file in memory at once. ` +
    `Nothing is wrong with the backup and the KEYM v2 format has no size limit — the ` +
    `command-line reference opens it:\n\n` +
    `    python3 keym2.py decrypt --in <your-backup> --out <destination>\n\n` +
    `It ships in the recovery kit linked in the footer; docs/RECOVERY.md has the full procedure.`
  );
}

export const MAX_CONTAINER_SIZE = MAX_PLAINTEXT_SIZE + 4096;
const MAX_CIPHERTEXT_SIZE = MAX_CONTAINER_SIZE;

/**
 * Longest base64 text we will even decode.
 *
 * A container is at most MAX_CONTAINER_SIZE bytes, and base64 expands by 4/3
 * plus padding. Callers must check the *encoded* length before calling atob(),
 * because atob() plus the byte-copy allocates roughly 1.75x the string's size
 * before decryptData() ever sees a buffer to measure. The core size check
 * protects the KDF; this protects the allocation that precedes it.
 */
export const MAX_BASE64_INPUT_CHARS = Math.ceil(MAX_CONTAINER_SIZE / 3) * 4 + 4;

/**
 * What the *text* fields will accept, as opposed to what the crypto core can
 * process. Two different questions, and conflating them is what made a paste
 * able to kill the tab (U4).
 *
 * ## Measured, not chosen
 *
 * The limits above bound the crypto. Nothing bounded the textarea, so a paste
 * reached React state and the DOM before any check ran. The reported symptom
 * was a renderer OOM at ~140 MB; measuring it found something both smaller and
 * more ordinary. Worst main-thread block, production build, headless Chromium:
 *
 * |   pasted | as one line | wrapped at 76 cols |
 * |----------|-------------|--------------------|
 * |   64 KiB |      833 ms |                  — |
 * |  256 KiB |    3 245 ms |                  — |
 * |    1 MiB |   12 434 ms |             407 ms |
 *
 * Three findings, each of which changes the fix:
 *
 * 1. **The cost is not in our handler.** `onChange` returns in 3–7 ms at every
 *    size. The block happens afterwards, in Chromium laying out the field.
 * 2. **It is not the BIP-39 check.** Encrypt and decrypt block identically, and
 *    that check only runs on encrypt.
 * 3. **It is line length, not total length** — 30x between the same megabyte as
 *    one line and as wrapped lines. A `<textarea>` holding one enormous line is
 *    a pathological layout case.
 *
 * Point 3 is why this is not only an adversarial-paste problem: **Keymaker's own
 * armored output is a single unbroken line**, so a user copying their backup out
 * and pasting it back into Decrypt walks straight into it on the normal
 * recovery path. 100 MB was never a real limit for this field; it was a number
 * that had not been tested.
 *
 * ## The two caps
 *
 * They are asymmetric on purpose. Armor expands by 4/3, so a symmetric pair
 * would let the app produce text it then refuses to take back — a trap that is
 * worse than either limit. The decrypt cap is sized to comfortably clear
 * `MAX_TEXT_PLAINTEXT_BYTES` of armor plus its prefix.
 *
 * Anything larger belongs in file mode, which never goes through a textarea and
 * is unaffected by any of this.
 */
export const MAX_TEXT_PLAINTEXT_BYTES = 32 * 1024;
export const MAX_TEXT_ARMOR_CHARS = 64 * 1024;

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
 * An error that is safe to show the user verbatim.
 *
 * The distinction this class encodes is the whole point of it, so it is worth
 * stating precisely. There are two kinds of failure here:
 *
 *  1. **Structural or configuration failures.** The container is truncated, its
 *     KDF id is unknown, its cost parameters are outside the permitted range,
 *     the input is larger than the ceiling, the password is not a string. These
 *     describe the *file* or the *call*, both of which an attacker submitting a
 *     container already knows everything about. Reporting them precisely leaks
 *     nothing and saves the user from a wrong diagnosis.
 *
 *  2. **Authentication failures.** The AEAD tag did not verify. Wrong password,
 *     wrong key file, and flipped ciphertext bits are indistinguishable here and
 *     must stay that way — telling them apart is the oracle.
 *
 * Only the first kind is a KeymakerError. The second is a plain Error carrying
 * the single generic message, and callers must not try to look inside it.
 *
 * Before this existed, both the library and the UI decided which was which by
 * matching error strings — the library with a regex, the UI with an exact-match
 * array. Neither could match `KDF parameter out of range: …`, whose text is
 * interpolated, so a *tampered* container was reported to the user as a wrong
 * password. In a tool people use for backups, telling someone their password is
 * wrong when the file is actually corrupt is the worst possible wrong answer.
 */
export type KeymakerErrorCode =
  | "invalid-input"
  | "empty-input"
  | "too-large"
  | "password-invalid"
  | "credential-required"
  | "webcrypto-unavailable"
  | "unsupported-version"
  | "malformed-container"
  | "kdf-params-out-of-range"
  | "unsupported-config";

export class KeymakerError extends Error {
  readonly code: KeymakerErrorCode;

  constructor(code: KeymakerErrorCode, message: string) {
    super(message);
    this.name = "KeymakerError";
    this.code = code;
    // Preserve instanceof across the esbuild/Next transpile targets used here.
    Object.setPrototypeOf(this, KeymakerError.prototype);
  }
}

/** True for failures whose message may be shown to the user as-is. */
export function isUserFacingError(error: unknown): error is KeymakerError {
  return error instanceof KeymakerError;
}

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
      throw new KeymakerError("kdf-params-out-of-range", `Invalid KDF parameter: ${name} must be an integer.`);
    }
    // On decrypt, only the ceiling is a security control; the floor is policy.
    // Still require >= 1 — zero or negative is malformed under any reading.
    const effectiveMin = enforceMinimums ? min : 1;
    if (value < effectiveMin || value > max) {
      throw new KeymakerError(
        "kdf-params-out-of-range",
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

/**
 * Describe why a container's KDF parameters are weaker than anything this
 * version would write, or null when they are not.
 *
 * This reports; it never refuses. `validateKdfParams` deliberately enforces
 * minimums on encrypt only, because a backup tool that declines to open old
 * files has failed at the one job it exists for — a container written in 2019
 * must still open in 2039, on whatever terms it was written. That stays exactly
 * as it was.
 *
 * What was missing is that the user was never told. A v1-era container at a
 * thousand PBKDF2 iterations opens with no more ceremony than one at a million,
 * so the weakness is inherited silently and the owner has no reason to consider
 * re-encrypting. Saying so turns that into a decision they get to make.
 *
 * The threshold is the encrypt floor rather than a number invented here, so
 * "weaker than we would write" means exactly that, and the two cannot drift.
 */
export function describeWeakKdf(kdf: KdfParams): string | null {
  if (kdf.kdf === KdfId.PBKDF2) {
    const { minIterations } = KDF_LIMITS.pbkdf2;
    if (kdf.params.iterations >= minIterations) return null;
    return (
      `${kdf.params.iterations.toLocaleString("en-US")} PBKDF2 iterations, below the ` +
      `${minIterations.toLocaleString("en-US")} this version writes`
    );
  }

  const a = KDF_LIMITS.argon2id;
  const below: string[] = [];
  if (kdf.params.memoryKiB < a.minMemoryKiB) {
    below.push(`${Math.round(kdf.params.memoryKiB / 1024)} MiB memory`);
  }
  if (kdf.params.timeCost < a.minTimeCost) below.push(`time cost ${kdf.params.timeCost}`);
  if (kdf.params.parallelism < a.minParallelism) below.push(`parallelism ${kdf.params.parallelism}`);
  return below.length > 0 ? `${below.join(", ")} — below what this version writes` : null;
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

/**
 * Lazy-load hash-wasm (inlines its WASM as base64 — works fully offline).
 *
 * Exported so keym-v2.ts shares the same promise rather than opening a second
 * one: `import()` is cached per specifier, so both paths resolve the same
 * module instance and warmCryptoDependencies() warms them together.
 */
let hashWasmPromise: Promise<typeof import("hash-wasm")> | null = null;
export function loadHashWasm(): Promise<typeof import("hash-wasm")> {
  if (!hashWasmPromise) {
    hashWasmPromise = import("hash-wasm");
  }
  return hashWasmPromise;
}

/**
 * Can Argon2id actually run in this environment?
 *
 * Argon2id needs WebAssembly, and WebAssembly needs a CSP that permits it.
 * A policy of `script-src 'self'` without 'wasm-unsafe-eval' blocks module
 * compilation outright, and the failure surfaces deep inside a lazy import()
 * — which once meant the Encrypt button silently did nothing.
 *
 * So availability is *probed*, not assumed: compile an empty module to test
 * the policy, then actually load the library. Callers that offer Argon2id as
 * the default must await this and fall back rather than presenting an option
 * that cannot work.
 *
 * The result is cached — the answer cannot change within a page lifetime.
 */
/**
 * Pull every lazily-imported crypto dependency into the page.
 *
 * The README promises the app works air-gapped after first load. That is only
 * true for code the browser has actually fetched, because the service worker
 * runtime-caches a chunk when it is *requested* — it does not precache the
 * whole static tree. A dependency that is only imported when a particular
 * cipher is first selected would therefore be missing for a user who goes
 * offline and then reaches for that cipher for the first time.
 *
 * Today `@noble/ciphers` happens to also be duplicated into the eagerly loaded
 * bundle, so ChaCha survives that scenario by accident. That is a bundler
 * chunking decision, not a guarantee, and it can change silently on any
 * dependency or toolchain bump. Warming it explicitly turns the accident into
 * a property, and the offline browser tests assert it for all six KDF/cipher
 * combinations on first use.
 *
 * Fire-and-forget: failures are ignored, since every call site still awaits
 * its own import and will surface a real error there.
 */
export function warmCryptoDependencies(): void {
  void loadNoble().catch(() => {});
  void loadHashWasm().catch(() => {});
}

let argon2AvailabilityPromise: Promise<boolean> | null = null;
export function isArgon2idAvailable(): Promise<boolean> {
  if (!argon2AvailabilityPromise) {
    argon2AvailabilityPromise = (async () => {
      try {
        if (typeof WebAssembly === "undefined") return false;
        // Smallest valid module: the 8-byte header alone. Compiling it costs
        // nothing and fails precisely when CSP forbids WASM.
        await WebAssembly.instantiate(new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]));
        await loadHashWasm();
        return true;
      } catch {
        return false;
      }
    })();
  }
  return argon2AvailabilityPromise;
}

export type NobleCiphers = typeof import("@noble/ciphers/chacha.js");
let noblePromise: Promise<NobleCiphers> | null = null;
export function loadNoble(): Promise<NobleCiphers> {
  if (!noblePromise) {
    noblePromise = import("@noble/ciphers/chacha.js");
  }
  return noblePromise;
}

function validateCommon(dataBuffer: ArrayBuffer, password: string, isEncryption: boolean): void {
  if (!dataBuffer || !(dataBuffer instanceof ArrayBuffer)) {
    throw new KeymakerError("invalid-input", "Valid data buffer is required.");
  }
  if (dataBuffer.byteLength === 0) {
    throw new KeymakerError("empty-input", "Cannot process empty data.");
  }
  if (isEncryption && dataBuffer.byteLength > MAX_FILE_SIZE) {
    throw new KeymakerError("too-large", `File is too large. Maximum size is ${MAX_FILE_SIZE / 1024 / 1024}MB.`);
  }
  // Decryption needs its own ceiling. The file picker enforces one, but pasted
  // base64 reaches decryptData() without going through it, and by then the
  // bytes have already been allocated and are about to hit a KDF.
  if (!isEncryption && dataBuffer.byteLength > MAX_CIPHERTEXT_SIZE) {
    // Not "pick a smaller file": there is no smaller version of a backup.
    throw new KeymakerError("too-large", oversizeRecoveryHelp());
  }
  if (typeof password !== "string") {
    throw new KeymakerError("password-invalid", "Password must be a string.");
  }
  if (password.length > MAX_PASSWORD_LENGTH) {
    throw new KeymakerError("password-invalid", "Password is too long.");
  }
  if (password.includes("\0")) {
    throw new KeymakerError("password-invalid", "Password contains invalid characters.");
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
  options: KeymakerOptions
): Promise<ArrayBuffer> {
  validateCommon(dataBuffer, password, true);
  if (!password) {
    throw new KeymakerError("credential-required", "A password is required for encryption.");
  }
  if (!crypto.subtle) {
    throw new KeymakerError("webcrypto-unavailable", "Web Crypto API not available.");
  }

  // No fallback: the caller states the algorithms, or this throws. See the
  // note on KeymakerOptions for why an implicit default was a footgun.
  if (!options || !options.kdf || options.cipher === undefined) {
    throw new Error(
      "encryptData requires explicit kdf and cipher options — algorithm selection is the caller's decision."
    );
  }
  const kdf: KdfParams = options.kdf;
  const cipher = options.cipher;

  // Validate caller-supplied options rather than trusting that a UI slider
  // constrained them. Encryption enforces the policy floor as well as the
  // ceiling: writing a new file at 1,000 PBKDF2 iterations is a mistake worth
  // refusing, even though we will still *read* such a file.
  validateKdfParams(kdf, "encrypt");
  if (cipher !== CipherId.AES_256_GCM && cipher !== CipherId.CHACHA20_POLY1305 && cipher !== CipherId.CHAINED) {
    throw new KeymakerError("unsupported-config", `Invalid cipher id: ${cipher}.`);
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

/**
 * Encrypt into the current container format, which since Phase 3 is **KEYM v2**.
 *
 * This is the application's writer. `encryptData` above still produces v1 and
 * is deliberately kept, for one reason: `reference/crosstest.py` has to be able
 * to *construct* v1 containers in order to prove the v1 reader still opens
 * them, and the frozen fixture corpus was generated the same way. Retiring the
 * v1 writer outright would mean the v1 reader's strongest test could no longer
 * be written.
 *
 * FORMAT-V2-DESIGN §9.2 is about the product, and the product does not reach
 * it: nothing under `src/components`, `crypto-worker.ts` or `crypto-client.ts`
 * calls `encryptData` any more. "Two writable formats means two formats to keep
 * correct, and there is no reason to author new v1 files."
 *
 * The v2 module arrives through a dynamic import for the same reason
 * `decryptData`'s v2 branch uses one: the dependency runs one way, so v2 work
 * is structurally unable to change how a v1 container is written or parsed, and
 * v2 stays out of the initial bundle until something actually needs it.
 */
export async function encryptContainer(
  dataBuffer: ArrayBuffer,
  password: string,
  keyFileBuffer: ArrayBuffer | null,
  options: KeymakerOptions
): Promise<ArrayBuffer> {
  validateCommon(dataBuffer, password, true);
  if (!password) {
    throw new KeymakerError("credential-required", "A password is required for encryption.");
  }
  if (!crypto.subtle) {
    throw new KeymakerError("webcrypto-unavailable", "Web Crypto API not available.");
  }
  // Same contract as encryptData: the caller states the algorithms, or this
  // throws. See the note on KeymakerOptions for why an implicit default was a
  // footgun.
  if (!options || !options.kdf || options.cipher === undefined) {
    throw new Error(
      "encryptContainer requires explicit kdf and cipher options — algorithm selection is the caller's decision."
    );
  }
  validateKdfParams(options.kdf, "encrypt");
  const cipher = options.cipher;
  if (cipher !== CipherId.AES_256_GCM && cipher !== CipherId.CHACHA20_POLY1305 && cipher !== CipherId.CHAINED) {
    throw new KeymakerError("unsupported-config", `Invalid cipher id: ${cipher}.`);
  }

  try {
    const { encryptKeym2 } = await import("./keym-v2");
    const out = await encryptKeym2(
      new Uint8Array(dataBuffer),
      password,
      keyFileBuffer ? new Uint8Array(keyFileBuffer) : null,
      { kdf: options.kdf, cipher }
    );
    return out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength) as ArrayBuffer;
  } catch (error) {
    if (isUserFacingError(error)) throw error;
    if (error instanceof Error && /required|too (large|long)|invalid characters|not available/i.test(error.message)) {
      throw error;
    }
    throw new Error("Encryption failed. Please try again.");
  } finally {
    // Same contract as every other path here: the caller's key file buffer is
    // zeroed in place once used.
    if (keyFileBuffer) secureErase(keyFileBuffer);
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
  if (data.length < 8) throw new KeymakerError("malformed-container", "Invalid KEYM data: too short.");
  if (data[4] !== KEYM_VERSION) {
    throw new KeymakerError("unsupported-version", "This file was encrypted with a newer KEYM version. Please update the app.");
  }
  const kdfId = data[5]!;
  const cipherId = data[6]!;
  if (kdfId !== KdfId.PBKDF2 && kdfId !== KdfId.ARGON2ID) {
    throw new KeymakerError("malformed-container", "Invalid KEYM data: unknown KDF id.");
  }
  if (cipherId < 0 || cipherId > 2) {
    throw new KeymakerError("malformed-container", "Invalid KEYM data: unknown cipher id.");
  }
  // Establish the full length requirement *before* reading a single field.
  //
  // The layout is fully determined by kdf_id and cipher_id, both already
  // validated above, so the exact size can be computed up front. Doing it here
  // rather than after the parameter reads is the fix for a real defect: the
  // old code checked only `length < 8`, then read a uint16 at offset 7, a
  // uint32 at 9 and a byte at 13 for Argon2id — so an 8-to-13-byte container
  // threw a DataView RangeError, which the caller then re-wrapped as "the
  // password may be incorrect". A truncated file was reported as a bad
  // password. Bounds first, reads second.
  const kdfParamLen = kdfId === KdfId.PBKDF2 ? 4 : 7;
  const saltLen = kdfId === KdfId.PBKDF2 ? SALT_LEN_PBKDF2 : SALT_LEN_ARGON2ID;
  const nonceCount = cipherId === CipherId.CHAINED ? 2 : 1;
  const headerLen = 7 + kdfParamLen + 1 /* flags */ + saltLen + nonceCount * NONCE_LEN;
  if (data.length < headerLen + 16 /* at least one AEAD tag */) {
    throw new KeymakerError("malformed-container", "Invalid KEYM data: too short.");
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

/** How many leading bytes of `data` equal the corresponding bytes of `magic`. */
function magicPrefixLen(data: Uint8Array, magic: ArrayLike<number>): number {
  const n = Math.min(data.length, magic.length);
  let i = 0;
  while (i < n && data[i] === magic[i]) i++;
  return i;
}

const IBTZ_MAGIC = [0x49, 0x42, 0x54, 0x5a]; // "IBTZ"

/**
 * Detect the wire format of an encrypted blob.
 *
 * The legacy v0 format is headerless, so it is the fallback for anything that
 * does not announce itself — which makes "unrecognised" and "v0" the same
 * answer. That is unavoidable for real v0 files, but it should not swallow
 * input that was *clearly* trying to be something else.
 *
 * A blob whose first bytes match "KEYM" but which is too short to carry a
 * header used to fall through to v0 and run a full 1,000,000-iteration PBKDF2
 * derivation before failing — a free CPU burn for a caller who supplies four
 * bytes, and a second, less accurate error channel for the user. A partial
 * magic match is now treated as a malformed container of that format, which is
 * what it is.
 */
export function detectFormat(data: Uint8Array): DetectedFormat {
  if (data.length >= 5 && magicPrefixLen(data, KEYM_MAGIC) === KEYM_MAGIC.length) {
    // The version byte is the discriminator, exactly as FORMAT-V2-DESIGN §3
    // says: "a reader dispatches on bytes 0-4 exactly as v1's decryptData()
    // already does, so v1 containers are unaffected". An unknown version stays
    // "keym-v1" so that parseKeym reports it as an unsupported version rather
    // than the blob falling through to the headerless legacy path and burning
    // a million PBKDF2 iterations before saying so.
    return data[4] === 2 ? "keym-v2" : "keym-v1";
  }
  if (data.length >= 5 && magicPrefixLen(data, IBTZ_MAGIC) === IBTZ_MAGIC.length) {
    return "ibtz-v1";
  }
  // Fewer than five bytes, but every one of them matches the start of "KEYM".
  // A real v0 container is salt(16) || IV(12) || ciphertext, so it can never be
  // this short; the only thing this can be is a truncated KEYM file. Classify
  // it as such and let parseKeym say "too short", which is both true and
  // instant. Left as v0 it ran a 1,000,000-iteration PBKDF2 derivation on four
  // bytes before reporting a wrong password.
  //
  // Deliberately total: this function stays a pure classifier so that every
  // existing caller keeps working. The rejection belongs to the parser.
  if (data.length > 0 && data.length < 5 && magicPrefixLen(data, KEYM_MAGIC) === data.length) {
    return "keym-v1";
  }
  return "ibtz-v0";
}

export interface KeymInspection {
  /** Human-readable KDF description, e.g. "Argon2id (64 MiB, t=3, p=4)". */
  kdfLabel: string;
  /** Human-readable cipher description. */
  cipherLabel: string;
  /**
   * Why this container's derivation is weaker than one written today, or null.
   * Informational only — the container still opens either way.
   */
  weakKdf: string | null;
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
    return { kdfLabel, cipherLabel, weakKdf: describeWeakKdf(parsed.kdf) };
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
/**
 * Open a legacy IBTZ container, retrying across Unicode normalization forms.
 *
 * KEYM normalizes the password to NFC before derivation; the legacy core never
 * did, and it must not start — it is frozen, and changing what bytes it feeds
 * the KDF would strand every file it has ever produced. So the retry lives
 * here, outside it.
 *
 * The failure this repairs is real and unpleasant. A password containing any
 * composed character — "café", "Müller", most non-Latin scripts — is delivered
 * as NFC by some input methods and NFD by others. macOS filesystems and some
 * IMEs favour NFD; most Linux and Windows paths produce NFC. The two are
 * canonically equivalent and visually identical, and they hash to different
 * keys. A user who encrypted on one machine and re-typed the same password on
 * another got "wrong password" for a password that was, in every sense a human
 * cares about, right.
 *
 * Trying each distinct form costs one extra KDF run per form only on the
 * failure path, and the forms are deduplicated so ASCII passwords — where all
 * four normalizations are identical — cost exactly nothing.
 *
 * This does not weaken anything: every candidate is a canonical form of the
 * password the user actually supplied, not a mutation of it. An attacker
 * guessing passwords gains no new candidates, only the same small constant
 * factor the legitimate user gets.
 */
async function legacyDecryptWithNormalizationFallback(
  encryptedBuffer: ArrayBuffer,
  password: string,
  keyFileBuffer: ArrayBuffer | null
): Promise<ArrayBuffer> {
  // As-typed first, so the overwhelmingly common case is unchanged and costs
  // no extra work.
  const candidates: string[] = [password];
  for (const form of ["NFC", "NFD", "NFKC", "NFKD"] as const) {
    let normalized: string;
    try {
      normalized = password.normalize(form);
    } catch {
      continue; // Environment without full ICU; skip rather than fail.
    }
    if (!candidates.includes(normalized)) candidates.push(normalized);
  }

  // An ASCII password normalizes to itself under all four forms, so there is
  // exactly one candidate and nothing changes: same call, same buffer, no copy.
  if (candidates.length === 1) {
    return await legacyDecryptFile(encryptedBuffer, password, keyFileBuffer);
  }

  // Past this point we may call the legacy core more than once, and its
  // `finally` block zeroes the key-file buffer it is handed — the caller's
  // buffer, not a copy. Retrying with the same one would derive the second
  // candidate against an all-zero key file and fail for the wrong reason. So
  // each attempt gets its own copy, taken before the first call.
  //
  // The ciphertext needs no such care: the legacy core slices salt, IV and body
  // out of it, and slices are copies.
  const keyFileSnapshot = keyFileBuffer ? new Uint8Array(keyFileBuffer).slice() : null;

  try {
    let firstError: unknown;
    for (const candidate of candidates) {
      const attemptKeyFile = keyFileSnapshot
        ? (keyFileSnapshot.slice().buffer as ArrayBuffer)
        : null;
      try {
        return await legacyDecryptFile(encryptedBuffer, candidate, attemptKeyFile);
      } catch (error) {
        // A structural complaint means the *file* is wrong, not the password,
        // so no other normalization will help. Fail immediately.
        if (isUserFacingError(error)) throw error;
        if (firstError === undefined) firstError = error;
      }
    }
    throw firstError ?? new Error("Decryption failed.");
  } finally {
    if (keyFileSnapshot) secureErase(keyFileSnapshot);
  }
}

export async function decryptData(
  encryptedBuffer: ArrayBuffer,
  password: string,
  keyFileBuffer: ArrayBuffer | null,
  /**
   * KEYM v2 §4.6 recovery shares. Additive and v2-only: a v1 container has no
   * slot table to hold a share set, so this reaches nothing but the v2 branch
   * below.
   *
   * A fourth optional parameter rather than an options object, because every
   * existing caller — the worker, the conformance bridge, four test suites —
   * passes three arguments, and widening is the change that cannot disturb the
   * v1 path.
   */
  shares?: string[],
  /** §4.7. 32 bytes from an authenticator, obtained by the caller. */
  prfOutput?: Uint8Array
): Promise<DecryptResult> {
  validateCommon(encryptedBuffer, password, false);
  const hasShares = !!shares && shares.length > 0;
  if (!password && !keyFileBuffer && !hasShares && !prfOutput) {
    throw new KeymakerError(
      "credential-required",
      "A password, key file, recovery shares, or a passkey is required for decryption."
    );
  }
  if (!crypto.subtle) {
    throw new Error("Web Crypto API not available.");
  }

  const fullData = new Uint8Array(encryptedBuffer);
  const format = detectFormat(fullData);

  if (format === "keym-v2") {
    // Dynamically imported so keymaker-crypto.ts does not depend on keym-v2.ts
    // at module-evaluation time — the dependency runs one way, which is what
    // keeps the v1 path structurally unable to be changed by v2 work. It also
    // keeps v2 out of the initial bundle until a v2 container is actually
    // opened.
    const { decryptKeym2 } = await import("./keym-v2");
    try {
      const result = await decryptKeym2(
        fullData,
        password,
        keyFileBuffer ? new Uint8Array(keyFileBuffer) : null,
        shares,
        prfOutput
      );
      return {
        data: result.data.buffer.slice(
          result.data.byteOffset,
          result.data.byteOffset + result.data.byteLength
        ) as ArrayBuffer,
        format,
        keyFileUsed: result.keyFileUsed,
      };
    } finally {
      // Same contract as every other path here: the caller's key file buffer
      // is zeroed in place once used.
      if (keyFileBuffer) secureErase(keyFileBuffer);
    }
  }

  if (format !== "keym-v1") {
    const data = await legacyDecryptWithNormalizationFallback(
      encryptedBuffer,
      password,
      keyFileBuffer
    );
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
    // Structural and configuration failures pass through with their real
    // message; everything else collapses to the one generic string. This used
    // to be a regex over error text, which could not match the interpolated
    // "KDF parameter out of range: …" and so reported a *tampered* container as
    // a possible wrong password. The type carries the distinction now.
    if (isUserFacingError(error)) throw error;
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
