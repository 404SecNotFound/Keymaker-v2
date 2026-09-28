#!/usr/bin/env node
/**
 * The page's key-file buffer is erased after an encrypt-via-worker that enrols a
 * share or passkey slot.
 *
 * On the worker path most buffers reach the worker by *transfer*, which detaches
 * (and so effectively erases) the page's copy. The key file is the exception: a
 * Shamir or passkey enrolment needs it twice — once for the container, once to
 * unwrap the slot being added — so it is structured-cloned rather than
 * transferred. The worker erases only its own clone; the page's copy — half the
 * key material — was left in this heap until GC.
 *
 * The browser suite can't see this: the key-file ArrayBuffer is internal to the
 * client call. So this drives `crypto-client.ts` directly with a stubbed
 * `Worker` (the review's "mocked boundary") that answers the readiness ping and
 * the encrypt request, and detaches whatever the client actually transfers — so
 * the transfer-vs-clone distinction the fix turns on is modelled faithfully.
 * esbuild bundles the TS the way the rest of the project reaches its `.ts`.
 *
 * The control bites: with the erase removed, the key file below stays non-zero.
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

// A stubbed crypto worker. It answers the readiness ping and the encrypt
// request, and — crucially — detaches every buffer the client passes in the
// transfer list, exactly as a real Worker's postMessage does. So a buffer the
// client transfers ends up detached here, and one it structured-clones would
// stay intact. Since roadmap 9.3 the key file is transferred on every path,
// share set and passkey included, so none is left on the page.
class FakeWorker {
  constructor() { this.messageListeners = []; }
  addEventListener(type, fn) { if (type === "message") this.messageListeners.push(fn); }
  removeEventListener() {}
  terminate() {}
  postMessage(req, transfer) {
    for (const buf of transfer || []) {
      // Model the structured-clone transfer: detach the buffer on this side.
      try { structuredClone(buf, { transfer: [buf] }); } catch { /* already detached */ }
    }
    queueMicrotask(() => {
      let res;
      if (req.op === "ping") res = { id: req.id, op: "ping", ok: true };
      else if (req.op === "encrypt") {
        res = {
          id: req.id, op: "encrypt", ok: true,
          data: new Uint8Array([1, 2, 3, 4]).buffer,
          shares: req.shamir ? ["a", "b", "c"] : undefined,
        };
      } else res = { id: req.id, ok: false, message: `unexpected op ${req.op}` };
      for (const fn of this.messageListeners) fn({ data: res });
    });
  }
}
globalThis.Worker = FakeWorker;

const m = await import(pathToFileURL(out).href);
const OPTIONS = { kdf: { kdf: 1, params: { timeCost: 3, memoryKiB: 65536, parallelism: 1 } }, cipher: 0 };
const keyBytes = (n) => Uint8Array.from({ length: n }, (_, i) => (i * 13 + 7) & 0xff);

// 1. Key file + a Shamir share set, on the worker path. This used to clone the
// key file and erase the page's copy afterwards; it is now transferred.
{
  const keyFile = keyBytes(48);
  const buf = keyFile.buffer;
  const res = await m.encryptViaWorker(
    new Uint8Array([9, 9, 9]).buffer, "pw", buf, OPTIONS, { threshold: 2, count: 3 }
  );
  ok(res && Array.isArray(res.shares) && res.shares.length === 3, "worker path enrolled the share set");
  // Roadmap 9.3: the worker writes every slot in one call and reads the key
  // file once, so it is transferred like the plain path's. Detached is
  // stronger than zeroed: there is no page copy left to erase.
  ok(buf.byteLength === 0,
     "the page keeps no key-file copy after an encrypt-with-shares (transferred, so detached)");
}

// 2. Same for a passkey slot: the key file is transferred, so nothing is left here.
{
  const keyFile = keyBytes(48);
  const buf = keyFile.buffer;
  await m.encryptViaWorker(
    new Uint8Array([9, 9, 9]).buffer, "pw", buf, OPTIONS, undefined,
    { prfOutput: new Uint8Array(32).fill(5), salt: new Uint8Array(32).fill(6) }
  );
  ok(buf.byteLength === 0,
     "the page keeps no key-file copy after an encrypt-with-passkey (transferred, so detached)");
}

// 3. Control that the erase is scoped, not blind: with no share/passkey slot the
// key file IS transferred, so the client must NOT call secureErase on it (that
// would throw on the detached buffer). Reaching here without throwing, with the
// buffer detached by the transfer, is the evidence.
{
  const keyFile = keyBytes(48);
  const buf = keyFile.buffer;
  await m.encryptViaWorker(new Uint8Array([9, 9, 9]).buffer, "pw", buf, OPTIONS);
  ok(buf.byteLength === 0, "a plain encrypt transfers the key file (detached), and erasing is skipped for it");
}

console.log(failed === 0 ? "\nAll secret-erase checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
