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
 *   bridge encrypt2 ... --salt HEX --master-key HEX   (KEYM v2, deterministic)
 *   bridge encryptapp ...                             (KEYM v2, the real writer)
 *   bridge decrypt2 ...                               (KEYM v2)
 *   bridge addshares --threshold K --shares N --salt HEX --share-secret HEX
 *                    --share-coefficients HEX --shares-out FILE  (§4.6)
 *   bridge decrypt2 --share-file FILE                 (§4.6, no password)
 *
 * `encryptapp` goes through `encryptContainer` — the function the worker and
 * the UI actually call, with real random secrets. `recovery_test.py` uses it,
 * because the promise docs/RECOVERY.md makes is about containers the *app*
 * wrote, and a conformance entry point with pinned secrets is not that.
 *
 * ## Why encrypt2 takes a salt *and* a master key
 *
 * For v1, bidirectional round-trips are a sufficient cross-check. For v2 they
 * are not, and the reference proved why: the original §5.1 admitted two
 * different chunkings for a plaintext that is an exact multiple of the chunk
 * size, and *both decode correctly*. Python writing one and TypeScript writing
 * the other would round-trip perfectly in both directions while producing
 * different files.
 *
 * Only comparing bytes catches that, and comparing bytes needs both random
 * inputs pinned. Before the slot amendment the salt was the only one; since
 * §4.3 the payload is encrypted under a random master key, so that has to be
 * fixed too or two runs differ in every payload byte.
 *
 * The v2 module keeps this behind a separately named export whose doc comment
 * spells out the hazard: §4.5 forbids caller-supplied values for either on real
 * data, because reusing a master key reuses every nonce in the container.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
import {
  encryptData,
  encryptContainer,
  decryptData,
  CipherId,
  KdfId,
  type KdfParams,
} from "../src/lib/keymaker-crypto.ts";
import {
  encryptKeym2WithExplicitSecrets,
  decryptKeym2,
  addShamirSlotKeym2,
} from "../src/lib/keym-v2.ts";

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

    const out = await encryptKeym2WithExplicitSecrets(
      new Uint8Array(inputBuf),
      password,
      keyFile ? new Uint8Array(keyFile) : null,
      { kdf, cipher: CIPHERS[flag("cipher") ?? "aes"]! },
      Uint8Array.from(Buffer.from(flag("salt")!, "hex")),
      Uint8Array.from(Buffer.from(flag("master-key")!, "hex"))
    );
    writeFileSync(outFile, Buffer.from(out));
  } else if (cmd === "encryptapp") {
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

    const out = await encryptContainer(inputBuf, password, keyFile, {
      kdf,
      cipher: CIPHERS[flag("cipher") ?? "aes"]!,
    });
    writeFileSync(outFile, Buffer.from(out));
  } else if (cmd === "addshares") {
    // §4.6. Every random input pinned, for the same reason encrypt2 pins the
    // salt and master key: the two implementations decode each other's shares
    // happily even if they disagree about how to *write* them, and only
    // comparing bytes catches that. The coefficients matter most — they are the
    // one input that changes every share byte.
    const { container, shares } = await addShamirSlotKeym2(
      new Uint8Array(inputBuf),
      { password, keyFile: keyFile ? new Uint8Array(keyFile) : null },
      Number(flag("threshold")),
      Number(flag("shares")),
      {
        salt: Uint8Array.from(Buffer.from(flag("salt")!, "hex")),
        shareSecret: Uint8Array.from(Buffer.from(flag("share-secret")!, "hex")),
        coefficients: Uint8Array.from(Buffer.from(flag("share-coefficients")!, "hex")),
      }
    );
    writeFileSync(outFile, Buffer.from(container));
    writeFileSync(flag("shares-out")!, shares.join("\n") + "\n");
  } else if (cmd === "decrypt2") {
    // Deliberately the v2 module directly rather than decryptData(), so a
    // failure here points at the format code instead of at the dispatch. The
    // dispatch has its own test.
    const shareFile = flag("share-file");
    const shares = shareFile
      ? readFileSync(shareFile, "utf8").split("\n").map((l) => l.trim()).filter(Boolean)
      : undefined;
    const out = await decryptKeym2(
      new Uint8Array(inputBuf),
      password,
      keyFile ? new Uint8Array(keyFile) : null,
      shares
    );
    writeFileSync(outFile, Buffer.from(out.data));
  } else {
    throw new Error(`unknown command: ${cmd}`);
  }
} catch (e) {
  console.error(`bridge error: ${(e as Error).message}`);
  process.exit(1);
}
