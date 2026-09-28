#!/usr/bin/env node
/**
 * A new backup's ways in are written in one operation (roadmap 9.3, Section 05).
 *
 * Creating a backup that opens with a password or a share set or a passkey
 * used to be three steps: write the passphrase slot, then enrol the share set,
 * then enrol the passkey. Each enrolment has to open the container to reach its
 * master key, which means deriving the password again, so a backup with every
 * way in cost three full password derivations (roadmap 9.0 measured 1, 2, 3).
 * `encryptKeym2WithSlots` writes every slot while the master key it generated
 * is still in hand, so the password is derived once.
 *
 * This holds that to five things:
 *
 *  1. **One derivation.** Through the shipping worker, loaded as-is with a
 *     stand-in `self`, every creation the form can ask for derives the password
 *     exactly once. PBKDF2 is counted at `crypto.subtle.deriveBits`, Argon2id
 *     at hash-wasm's `argon2id` (a shim wraps the real module), separately.
 *  2. **The same bytes.** With every random input pinned, the one-operation
 *     container and its share strings are byte-identical to the three-step
 *     path's, for every cipher, every version and every slot combination. The
 *     three-step path is what `crosstest2.py` already compares against the
 *     Python reference, and it compares this one too.
 *  3. **Every way in opens it.** A worker-written backup with every slot opens
 *     with the password, with k strips, and with the passkey, to the same
 *     payload.
 *  4. **Refused before the KDF.** A threshold above the count, a threshold of
 *     one, a PRF output or passkey salt of the wrong size, and §4.8 with a
 *     passkey are each refused with no password derivation at all.
 *  5. **No partial success.** A failure injected after the slots are wrapped
 *     reaches the page as an error with no container and no shares.
 *
 * Buffer cleanup for the same function is in `secret-erase-core-test.mjs`,
 * which has the allocation census this needs.
 */
import esbuild from "esbuild";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
const LIB = join(HERE, "..", "src", "lib");
const OUT = mkdtempSync(join(tmpdir(), "slot-tx-"));
const require = createRequire(import.meta.url);

let failed = 0;
let passed = 0;
const ok = (cond, msg, detail = "") => {
  if (!cond) { console.error("FAIL:", msg, detail); failed++; }
  else { console.log("ok   ", msg); passed++; }
};

// ---------------------------------------------------------------------------
// Counting derivations.
// ---------------------------------------------------------------------------
globalThis.__argon2Calls = 0;
let pbkdf2Calls = 0;
const subtle = crypto.subtle;
const nativeDeriveBits = subtle.deriveBits.bind(subtle);
subtle.deriveBits = (algorithm, ...rest) => {
  if (algorithm?.name === "PBKDF2") pbkdf2Calls++;
  return nativeDeriveBits(algorithm, ...rest);
};
const nativeEncrypt = subtle.encrypt.bind(subtle);
let encryptBudget = Infinity;
subtle.encrypt = (...args) => {
  if (encryptBudget-- <= 0) return Promise.reject(new Error("injected: encrypt refused"));
  return nativeEncrypt(...args);
};
const passwordDerivations = () => pbkdf2Calls + globalThis.__argon2Calls;
const resetCounts = () => { pbkdf2Calls = 0; globalThis.__argon2Calls = 0; };

const REAL_HASH_WASM = require.resolve("hash-wasm");
const countArgon2 = {
  name: "count-argon2",
  setup(build) {
    build.onResolve({ filter: /^hash-wasm$/ }, () => ({ path: "hash-wasm-counted", namespace: "shim" }));
    build.onLoad({ filter: /.*/, namespace: "shim" }, () => ({
      contents:
        `import * as real from ${JSON.stringify(REAL_HASH_WASM)};\n` +
        `export * from ${JSON.stringify(REAL_HASH_WASM)};\n` +
        `export async function argon2id(options) { globalThis.__argon2Calls++; return real.argon2id(options); }\n`,
      resolveDir: LIB,
      loader: "js",
    }));
  },
};

// ---------------------------------------------------------------------------
// The shipping worker, loaded as-is with a stand-in `self`, in the same bundle
// as the library functions so both share one module instance.
// ---------------------------------------------------------------------------
let handler = null;
const posted = [];
globalThis.self = {
  addEventListener: (_type, h) => { handler = h; },
  postMessage: (message) => { posted.push(message); },
};
const outfile = join(OUT, "slot-tx.mjs");
await esbuild.build({
  stdin: {
    contents: `import "./crypto-worker";
      export {
        encryptKeym2WithSlots, encryptKeym2WithExplicitSecrets, addShamirSlotKeym2, addPasskeySlotKeym2,
        decryptKeym2, KEYM2_VERSION_V2, KEYM2_VERSION_V3, KEYM2_VERSION_V4,
      } from "./keym-v2";
      export { KdfId, CipherId } from "./keymaker-crypto";`,
    resolveDir: LIB, loader: "ts", sourcefile: "slot-tx.ts",
  },
  bundle: true, format: "esm", platform: "node", outfile, logLevel: "warning", plugins: [countArgon2],
});
const m = await import(pathToFileURL(outfile).href);

let nextId = 0;
async function send(req) {
  posted.length = 0;
  await handler({ data: { id: ++nextId, ...req } });
  return posted[0];
}

const enc = new TextEncoder();
const dec = new TextDecoder();
const PASSWORD = "synthetic slot-transaction password 3e7b";
const PLAINTEXT = "synthetic slot-transaction payload: one derivation, three ways in";
const bytes = (n, seed) => Uint8Array.from({ length: n }, (_, i) => (i * seed + 17) & 0xff);
const same = (a, b) => Buffer.from(a).equals(Buffer.from(b));
const ab = (u) => u.slice().buffer;

const PBKDF2 = { kdf: m.KdfId.PBKDF2, params: { iterations: 600_000 } };
const ARGON2 = { kdf: m.KdfId.ARGON2ID, params: { timeCost: 1, memoryKiB: 8 * 1024, parallelism: 1 } };

// ---------------------------------------------------------------------------
// 1. One derivation, through the worker, for every creation the form can ask for.
// ---------------------------------------------------------------------------
const CREATIONS = [
  { label: "password", shamir: undefined, passkey: false },
  { label: "password or shares", shamir: { threshold: 2, count: 3 }, passkey: false },
  { label: "password or passkey", shamir: undefined, passkey: true },
  { label: "password or shares or passkey", shamir: { threshold: 2, count: 3 }, passkey: true },
  { label: "password and shares (§4.8)", shamir: { threshold: 2, count: 3, withPassword: true }, passkey: false },
];
const written = {};
for (const [kdfName, kdf] of [["PBKDF2", PBKDF2], ["Argon2id", ARGON2]]) {
  for (const c of CREATIONS) {
    resetCounts();
    const res = await send({
      op: "encrypt",
      data: ab(enc.encode(PLAINTEXT)),
      password: PASSWORD,
      keyFile: null,
      options: { kdf, cipher: m.CipherId.AES_256_GCM },
      shamir: c.shamir,
      passkey: c.passkey ? { prfOutput: bytes(32, 5), salt: bytes(32, 7) } : undefined,
    });
    const n = kdfName === "PBKDF2" ? pbkdf2Calls : globalThis.__argon2Calls;
    ok(res?.ok === true && n === 1 && passwordDerivations() === 1,
       `${kdfName}, ${c.label}: the password is derived once`,
       res?.ok ? `${n} ${kdfName} derivation(s), ${passwordDerivations()} in all` : String(res?.message));
    if (kdfName === "PBKDF2") written[c.label] = res;
  }
}

// ---------------------------------------------------------------------------
// 2. Byte-identical to the three-step path, every random input pinned.
// ---------------------------------------------------------------------------
const SALT = bytes(32, 3);
const MASTER = bytes(32, 11);
const CID = bytes(16, 13);
const SHARE_SALT = bytes(32, 19);
const SHARE_SECRET = bytes(32, 23);
const COEFFS = bytes(64, 29); // k = 3
const PRF = bytes(32, 31);
const PK_SALT = bytes(32, 37);
const KEY_FILE = bytes(40, 41);

for (const cipher of [m.CipherId.AES_256_GCM, m.CipherId.CHACHA20_POLY1305, m.CipherId.CHAINED]) {
  for (const version of [m.KEYM2_VERSION_V2, m.KEYM2_VERSION_V3, m.KEYM2_VERSION_V4]) {
    for (const combo of ["shares", "passkey", "shares+passkey"]) {
      for (const keyFile of [null, KEY_FILE]) {
        const withShares = combo.includes("shares");
        const withPasskey = combo.includes("passkey");
        const cid = version === m.KEYM2_VERSION_V2 ? new Uint8Array(0) : CID;
        const options = { kdf: PBKDF2, cipher };
        const label = `cipher ${cipher}, v${version}, ${combo}${keyFile ? ", key file" : ""}`;
        try {
          // The three-step path.
          let old = await m.encryptKeym2WithExplicitSecrets(
            enc.encode(PLAINTEXT), PASSWORD, keyFile, options, SALT, MASTER, version, cid
          );
          let oldShares;
          if (withShares) {
            const r = await m.addShamirSlotKeym2(old, { password: PASSWORD, keyFile }, 3, 5, {
              salt: SHARE_SALT, shareSecret: SHARE_SECRET, coefficients: COEFFS,
            });
            old = r.container;
            oldShares = r.shares;
          }
          if (withPasskey) old = await m.addPasskeySlotKeym2(old, { password: PASSWORD, keyFile }, PRF, PK_SALT);

          // The one-operation path.
          const tx = await m.encryptKeym2WithSlots(
            enc.encode(PLAINTEXT), PASSWORD, keyFile, options,
            {
              shamir: withShares ? { threshold: 3, count: 5 } : undefined,
              passkey: withPasskey ? { prfOutput: PRF, salt: PK_SALT } : undefined,
            },
            version,
            { salt: SALT, masterKey: MASTER, containerId: cid, shareSalt: SHARE_SALT, shareSecret: SHARE_SECRET, coefficients: COEFFS }
          );
          ok(same(tx.container, old), `${label}: the container is byte-identical to the three-step path`,
             `tx=${tx.container.length}B old=${old.length}B`);
          if (withShares) {
            ok(JSON.stringify(tx.shares) === JSON.stringify(oldShares),
               `${label}: all five share strings are identical`);
          }
        } catch (e) {
          ok(false, `${label}: both paths write a container`, String(e?.message ?? e));
        }
      }
    }
  }
}
ok(same(SHARE_SECRET, bytes(32, 23)) && same(COEFFS, bytes(64, 29)) && same(PRF, bytes(32, 31)) && same(MASTER, bytes(32, 11)),
   "pinned inputs are the caller's and come back unchanged, so the comparison above compared like with like");

// ---------------------------------------------------------------------------
// 3. Every way in opens the worker-written backup, to the same payload.
// ---------------------------------------------------------------------------
{
  const res = written["password or shares or passkey"];
  const container = res?.ok ? new Uint8Array(res.data) : null;
  const open = async (secrets) => {
    try {
      const r = await m.decryptKeym2(container, secrets.password ?? "", null, secrets.shares, secrets.prfOutput);
      return dec.decode(r.data);
    } catch (e) {
      return `threw: ${e?.message ?? e}`;
    }
  };
  if (container) {
    ok(await open({ password: PASSWORD }) === PLAINTEXT, "the backup with every way in opens with the password");
    ok(await open({ shares: res.shares.slice(0, 2) }) === PLAINTEXT, "it opens with 2 of its 3 strips alone");
    ok(await open({ shares: [res.shares[2], res.shares[0]] }) === PLAINTEXT, "it opens with a different 2 of 3");
    ok(await open({ prfOutput: bytes(32, 5) }) === PLAINTEXT, "it opens with the passkey alone");
    ok((await open({ shares: res.shares.slice(0, 1) })).startsWith("threw"), "one strip alone does not open it");
    ok((await open({ password: `${PASSWORD}!` })).startsWith("threw"), "a wrong password does not open it");
  } else {
    ok(false, "the worker wrote the backup with every way in", String(res?.message));
  }
}

// ---------------------------------------------------------------------------
// 4. Everything refusable is refused before the password is derived.
// ---------------------------------------------------------------------------
const REFUSALS = [
  { label: "a threshold above the share count", shamir: { threshold: 4, count: 3 } },
  { label: "a threshold of one", shamir: { threshold: 1, count: 3 } },
  { label: "a PRF output of 31 bytes", passkey: { prfOutput: bytes(31, 5), salt: bytes(32, 7) } },
  { label: "a passkey salt of 16 bytes", passkey: { prfOutput: bytes(32, 5), salt: bytes(16, 7) } },
  { label: "§4.8 with a passkey", shamir: { threshold: 2, count: 3, withPassword: true }, passkey: { prfOutput: bytes(32, 5), salt: bytes(32, 7) } },
];
for (const [kdfName, kdf] of [["PBKDF2", PBKDF2], ["Argon2id", ARGON2]]) {
  for (const r of REFUSALS) {
    resetCounts();
    const res = await send({
      op: "encrypt", data: ab(enc.encode(PLAINTEXT)), password: PASSWORD, keyFile: null,
      options: { kdf, cipher: m.CipherId.AES_256_GCM }, shamir: r.shamir, passkey: r.passkey,
    });
    ok(res?.ok === false && passwordDerivations() === 0,
       `${kdfName}: ${r.label} is refused before the password is derived`,
       `ok=${res?.ok}, ${passwordDerivations()} derivation(s), ${res?.message ?? ""}`);
  }
}

// ---------------------------------------------------------------------------
// 5. A failure after the slots exist returns no container and no shares.
// ---------------------------------------------------------------------------
{
  // AES-GCM: one subtle.encrypt per wrapped slot, then the payload. Three slots
  // wrapped, then the payload's first seal refused.
  encryptBudget = 3;
  const res = await send({
    op: "encrypt", data: ab(enc.encode(PLAINTEXT)), password: PASSWORD, keyFile: null,
    options: { kdf: PBKDF2, cipher: m.CipherId.AES_256_GCM },
    shamir: { threshold: 2, count: 3 }, passkey: { prfOutput: bytes(32, 5), salt: bytes(32, 7) },
  });
  const spent = encryptBudget;
  encryptBudget = Infinity;
  ok(spent < 0, "the injected failure landed after all three slots were wrapped (not vacuous)", `budget left ${spent}`);
  ok(res?.ok === false && !("data" in res) && !("shares" in res),
     "a write that failed after its slots existed hands the page no container and no shares",
     JSON.stringify(Object.keys(res ?? {})));
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
