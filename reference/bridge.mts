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
 *   bridge addpasskey --prf-output HEX --salt HEX     (§4.7)
 *   bridge decrypt2 --prf-output HEX                  (§4.7, no password)
 *   bridge prfsalt --slot-salt HEX                    (§4.7, prints hex)
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
  encryptKeym2,
  encryptKeym2WithExplicitSecrets,
  decryptKeym2,
  KEYM2_VERSION_V2,
  KEYM2_VERSION_V3,

  addShamirSlotKeym2,
  addPasskeySlotKeym2,
  derivePrfSalt,
} from "../src/lib/keym-v2.ts";
import { encodePaperParts, decodePaperParts } from "../src/lib/keym-v2-paper.ts";
import {
  buildSelfExtractingPage,
  embedSelfExtract,
  extractSelfExtract,
  webcryptoProfileViolations,
} from "../src/lib/keym-v2-selfextract.ts";

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

// `undefined` and `""` are different answers, and the truthiness test that used
// to be here collapsed them. §4.1 encodes "no key file" as LP("") and a
// present-but-empty one as LP(sha256(b"")) — 32 bytes — precisely so the two
// cannot collide, and this harness could not express the second case at all.
// So the one property §4.1 goes out of its way to provide was the one property
// crosstest2 structurally could not check.
//
// `--keyfile` absent  -> null, no key file.
// `--keyfile ""`      -> a present key file that happens to be zero bytes.
const keyFile =
  keyfileHex === undefined
    ? null
    : (() => {
        const b = Buffer.from(keyfileHex, "hex");
        return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;
      })();

// `prfsalt` is the one command with no container: it derives 32 bytes from a
// slot salt and prints them. Everything else reads its input here.
const input = cmd === "prfsalt" ? Buffer.alloc(0) : readFileSync(inFile);
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

    // v3 §3. Both pinned by the caller, because byte equality is the point:
    // a container_id drawn here would differ between the two implementations
    // and every comparison would fail for a reason that is not a disagreement.
    const containerId = flag("container-id");
    const out = await encryptKeym2WithExplicitSecrets(
      new Uint8Array(inputBuf),
      password,
      keyFile ? new Uint8Array(keyFile) : null,
      { kdf, cipher: CIPHERS[flag("cipher") ?? "aes"]! },
      Uint8Array.from(Buffer.from(flag("salt")!, "hex")),
      Uint8Array.from(Buffer.from(flag("master-key")!, "hex")),
      containerId === undefined ? KEYM2_VERSION_V2 : KEYM2_VERSION_V3,
      containerId === undefined ? new Uint8Array(0) : Uint8Array.from(Buffer.from(containerId, "hex"))
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

    // `--version` exists for one caller: recovery_test.py, which has to be able
    // to produce an app-written container of a version the app no longer writes
    // by default. An heir opening a v2 backup is following the same document as
    // one opening a v3 backup, so the document has to be executed against both.
    // Omitted, this is exactly `encryptContainer` — what the worker and the UI
    // call, with real random secrets.
    const appVersion = flag("version");
    const out =
      appVersion === undefined
        ? await encryptContainer(inputBuf, password, keyFile, {
            kdf,
            cipher: CIPHERS[flag("cipher") ?? "aes"]!,
          })
        : (
            await encryptKeym2(
              new Uint8Array(inputBuf),
              password,
              keyFile ? new Uint8Array(keyFile) : null,
              { kdf, cipher: CIPHERS[flag("cipher") ?? "aes"]! },
              Number(appVersion)
            )
          ).buffer;
    writeFileSync(outFile, Buffer.from(out as ArrayBuffer));
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
  } else if (cmd === "addpasskey") {
    // §4.7. Both random inputs pinned, for the same reason addshares pins its
    // three: the salt, because the PRF salt derives from it and so does every
    // wrapped byte, and the PRF output, because it stands in for an
    // authenticator this process does not have.
    const out = await addPasskeySlotKeym2(
      new Uint8Array(inputBuf),
      { password, keyFile: keyFile ? new Uint8Array(keyFile) : null },
      Uint8Array.from(Buffer.from(flag("prf-output")!, "hex")),
      Uint8Array.from(Buffer.from(flag("salt")!, "hex"))
    );
    writeFileSync(outFile, Buffer.from(out));
  } else if (cmd === "prfsalt") {
    // §4.7. Printed rather than written to --out, because it is 32 bytes of
    // derivation with no container involved — the one thing the two
    // implementations must agree on before either can ask an authenticator
    // anything.
    const salt = await derivePrfSalt(Uint8Array.from(Buffer.from(flag("slot-salt")!, "hex")));
    process.stdout.write(Buffer.from(salt).toString("hex") + "\n");
  } else if (cmd === "split") {
    // §7.1. Emitted so crosstest2.py can compare the *strings*, not only the
    // reassembled container: transposing a slice boundary leaves reassembly
    // correct and the two implementations' printed pages mutually unusable.
    const parts = encodePaperParts(new Uint8Array(inputBuf), Number(flag("capacity") ?? 1734));
    writeFileSync(outFile, parts.join("\n") + "\n");
  } else if (cmd === "selfextract") {
    // §7.2. The whole page, so the conformance suite can check that Python
    // extracts a container out of the artefact the app actually writes rather
    // than out of a hand-built approximation of it.
    //
    // The date and version are arguments rather than read from the clock, so
    // the same container always produces the same page — a fixture whose bytes
    // moved every run would be a fixture nobody could freeze.
    writeFileSync(
      outFile,
      buildSelfExtractingPage({
        container: new Uint8Array(inputBuf),
        createdOn: flag("created-on") ?? "2026-01-01",
        appVersion: flag("app-version") ?? "0.0.0",
      }),
      "utf8"
    );
  } else if (cmd === "embed") {
    // Just the sentinel block, which is the part the format actually specifies.
    writeFileSync(outFile, embedSelfExtract(new Uint8Array(inputBuf)) + "\n", "utf8");
  } else if (cmd === "unselfextract") {
    writeFileSync(outFile, Buffer.from(extractSelfExtract(readFileSync(inFile, "utf8"))));
  } else if (cmd === "profile") {
    // Exit code carries the verdict; stdout carries the reasons. Both matter —
    // the reasons are what a user is shown, and an empty list must mean the page
    // will actually open.
    const reasons = webcryptoProfileViolations(new Uint8Array(inputBuf));
    writeFileSync(outFile, reasons.join("\n") + (reasons.length ? "\n" : ""), "utf8");
    process.exit(reasons.length ? 3 : 0);
  } else if (cmd === "join") {
    const lines = readFileSync(inFile, "utf8")
      .split("\n")
      .filter((l) => l.trim() && !l.trimStart().startsWith("#"));
    writeFileSync(outFile, Buffer.from(decodePaperParts(lines)));
  } else if (cmd === "decrypt2") {
    // Deliberately the v2 module directly rather than decryptData(), so a
    // failure here points at the format code instead of at the dispatch. The
    // dispatch has its own test.
    const shareFile = flag("share-file");
    const shares = shareFile
      ? readFileSync(shareFile, "utf8").split("\n").map((l) => l.trim()).filter(Boolean)
      : undefined;
    const prfFlag = flag("prf-output");
    const out = await decryptKeym2(
      new Uint8Array(inputBuf),
      password,
      keyFile ? new Uint8Array(keyFile) : null,
      shares,
      prfFlag ? Uint8Array.from(Buffer.from(prfFlag, "hex")) : undefined
    );
    writeFileSync(outFile, Buffer.from(out.data));
    // v3 §5.2's report, on stdout so the cross-test can assert it. Three
    // states, printed as three distinct words: "absent" is a v2 container with
    // no MAC to check, and is deliberately not spelled the same as "authentic".
    console.log(
      `slot-table: ${
        out.slotTableAuthentic === null ? "absent" : out.slotTableAuthentic ? "authentic" : "not-authentic"
      }`
    );

  } else {
    throw new Error(`unknown command: ${cmd}`);
  }
} catch (e) {
  console.error(`bridge error: ${(e as Error).message}`);
  process.exit(1);
}
