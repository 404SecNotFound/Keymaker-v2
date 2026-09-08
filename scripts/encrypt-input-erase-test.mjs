#!/usr/bin/env node
/**
 * The page's plaintext input buffer is erased after an encrypt that falls back
 * to the main thread because no Worker could be constructed.
 *
 * On the worker path the plaintext ArrayBuffer is *transferred* to the worker,
 * which detaches it and so erases this side's only copy. The no-worker fallback
 * never transfers it — it hands the buffer to `encryptContainer` in-thread — and
 * neither `encryptContainer` nor `encryptKeym2` erases its plaintext input (they
 * erase the key file and the master key, not the plaintext). So on a browser
 * where the Worker failed to start, the secret being encrypted was left in the
 * page heap until GC, while the same call on a working browser wiped it. The
 * caller hands the buffer to the client as owned on both paths, so both must
 * clean it up the same way.
 *
 * This drives `crypto-client.ts` with a `Worker` whose constructor throws, so
 * `spawn()` returns null and the in-thread fallback is taken (`lastRunUsedWorker`
 * is false, asserted below). esbuild bundles the TS the way the rest of the
 * project reaches its `.ts`; the fallback runs a real PBKDF2 encryption.
 *
 * The control bites: with `secureErase(data)` removed from the fallback branch,
 * the plaintext buffer below stays non-zero after the call.
 */
import esbuild from "esbuild";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
const src = join(HERE, "..", "src", "lib", "crypto-client.ts");
const out = join(mkdtempSync(join(tmpdir(), "cc-")), "crypto-client.mjs");
await esbuild.build({ entryPoints: [src], bundle: true, format: "esm", platform: "node", outfile: out });

let failed = 0;
const ok = (cond, msg) => {
  if (!cond) { console.error("FAIL:", msg); failed++; }
  else console.log("ok   ", msg);
};

// A Worker that cannot be built. spawn() catches the throw, marks the worker
// unavailable, and every operation runs in-thread — the exact browser this fix
// is for (a policy or embedding that blocks Worker construction).
globalThis.Worker = class {
  constructor() { throw new Error("Worker construction is blocked in this environment"); }
};

const m = await import(pathToFileURL(out).href);
// PBKDF2 (kdf id 0) at OWASP's enforced floor — fast in Node's WebCrypto, and it
// keeps the fallback off the lazily-loaded Argon2id path.
const OPTIONS = { kdf: { kdf: 0, params: { iterations: 600_000 } }, cipher: 0 };

// A distinctive, all-non-zero plaintext so "every byte is zero" is a real test.
const plaintext = Uint8Array.from({ length: 64 }, (_, i) => (i * 7 + 1) & 0xff || 0x5a);
const buf = plaintext.buffer;

const res = await m.encryptViaWorker(buf, "correct horse battery staple", null, OPTIONS);

ok(m.lastRunUsedWorker === false, "the encrypt fell back to the main thread (no Worker)");
ok(res && res.data instanceof ArrayBuffer && res.data.byteLength > 0,
   "the fallback still produced a container");
ok(buf.byteLength === 64 && new Uint8Array(buf).every((b) => b === 0),
   "the page's plaintext input buffer is zeroed after a no-worker fallback encrypt");

console.log(failed === 0 ? "\nAll encrypt-input-erase checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
