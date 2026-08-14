/**
 * Thin CLI over the TypeScript KEYM implementation, so the Python reference
 * can drive it as a black box during cross-testing.
 *
 * This is the *only* point of contact between the two implementations. The
 * reference in keym.py imports nothing from here — it was written from
 * docs/FORMAT.md alone. This bridge exists so a cross-test can ask the real
 * implementation to encrypt or decrypt a byte string, nothing more.
 *
 *   bridge encrypt  --password P [--keyfile HEX] --kdf pbkdf2|argon2id
 *                   --cipher aes|chacha|chained --in FILE --out FILE
 *   bridge decrypt  --password P [--keyfile HEX] --in FILE --out FILE
 *   bridge encrypt2 ... --salt HEX          (KEYM v2, deterministic salt)
 *   bridge decrypt2 ...                     (KEYM v2)
 *
 * ## Why encrypt2 takes a salt
 *
 * For v1, bidirectional round-trips are a sufficient cross-check. For v2 they
 * are not, and the reference proved why: the original §5.1 admitted two
 * different chunkings for a plaintext that is an exact multiple of the chunk
 * size, and *both decode correctly*. Python writing one and TypeScript writing
 * the other would round-trip perfectly in both directions while producing
 * different files.
 *
 * Only comparing bytes catches that, and comparing bytes needs a shared salt.
 * The v2 module keeps this behind a separately named export whose doc comment
 * spells out that reusing a salt reuses every nonce in the container — in v2
 * the nonces are a deterministic counter, so salt reuse is far worse than it
 * was in v1, where they were random.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
import { encryptData, decryptData, CipherId, KdfId, type KdfParams } from "../src/lib/keymaker-crypto.ts";
import { encryptKeym2WithExplicitSalt, decryptKeym2 } from "../src/lib/keym-v2.ts";

if (!globalThis.crypto) {
  (globalThis as { crypto?: Crypto }).crypto = webcrypto as unknown as Crypto;
}

function flag(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? undefined : process.argv[i + 1];
}

const cmd = process.argv[2];
const password = flag("password") ?? "";
const keyfileHex = flag("keyfile");
const inFile = flag("in")!;
const outFile = flag("out")!;

const keyFile = keyfileHex
  ? (() => {
      const b = Buffer.from(keyfileHex, "hex");
      return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;
    })()
  : null;

const input = readFileSync(inFile);
const inputBuf = input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength) as ArrayBuffer;

const CIPHERS: Record<string, CipherId> = {
  aes: CipherId.AES_256_GCM,
  chacha: CipherId.CHACHA20_POLY1305,
  chained: CipherId.CHAINED,
};

try {
  if (cmd === "encrypt") {
    const kdf: KdfParams =
      flag("kdf") === "argon2id"
        ? {
            kdf: KdfId.ARGON2ID,
            params: {
              timeCost: Number(flag("time") ?? 2),
              memoryKiB: Number(flag("mem") ?? 16384),
              parallelism: Number(flag("par") ?? 2),
            },
          }
        : { kdf: KdfId.PBKDF2, params: { iterations: Number(flag("iterations") ?? 600_000) } };

    const out = await encryptData(inputBuf, password, keyFile, {
      kdf,
      cipher: CIPHERS[flag("cipher") ?? "aes"]!,
    });
    writeFileSync(outFile, Buffer.from(out));
  } else if (cmd === "decrypt") {
    const out = await decryptData(inputBuf, password, keyFile);
    writeFileSync(outFile, Buffer.from(out.data));
  } else if (cmd === "encrypt2") {
    const kdf: KdfParams =
      flag("kdf") === "argon2id"
        ? {
            kdf: KdfId.ARGON2ID,
            params: {
              timeCost: Number(flag("time") ?? 2),
              memoryKiB: Number(flag("mem") ?? 16384),
              parallelism: Number(flag("par") ?? 2),
            },
          }
        : { kdf: KdfId.PBKDF2, params: { iterations: Number(flag("iterations") ?? 600_000) } };

    const out = await encryptKeym2WithExplicitSalt(
      new Uint8Array(inputBuf),
      password,
      keyFile ? new Uint8Array(keyFile) : null,
      { kdf, cipher: CIPHERS[flag("cipher") ?? "aes"]! },
      Uint8Array.from(Buffer.from(flag("salt")!, "hex"))
    );
    writeFileSync(outFile, Buffer.from(out));
  } else if (cmd === "decrypt2") {
    // Deliberately the v2 module directly rather than decryptData(), so a
    // failure here points at the format code instead of at the dispatch. The
    // dispatch has its own test.
    const out = await decryptKeym2(
      new Uint8Array(inputBuf),
      password,
      keyFile ? new Uint8Array(keyFile) : null
    );
    writeFileSync(outFile, Buffer.from(out.data));
  } else {
    throw new Error(`unknown command: ${cmd}`);
  }
} catch (e) {
  console.error(`bridge error: ${(e as Error).message}`);
  process.exit(1);
}
