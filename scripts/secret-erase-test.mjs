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
// client transfers ends up detached here, and one it structured-clones (the key
// file, on the share/passkey path) stays intact — which is the whole point.
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

// 1. The finding: key file + a Shamir share set, on the worker path. The key
// file is not transferred (it is cloned), so the page's copy must be erased.
{
  const keyFile = keyBytes(48);
  const buf = keyFile.buffer;
  const res = await m.encryptViaWorker(
    new Uint8Array([9, 9, 9]).buffer, "pw", buf, OPTIONS, { threshold: 2, count: 3 }
  );
  ok(res && Array.isArray(res.shares) && res.shares.length === 3, "worker path enrolled the share set");
  ok(buf.byteLength === 48 && new Uint8Array(buf).every((b) => b === 0),
     "the page's key-file copy is zeroed after an encrypt-with-shares (not transferred, so still ours)");
}

// 2. Same for a passkey slot: key file cloned, not transferred → must be erased.
{
  const keyFile = keyBytes(48);
  const buf = keyFile.buffer;
  await m.encryptViaWorker(
    new Uint8Array([9, 9, 9]).buffer, "pw", buf, OPTIONS, undefined,
    { prfOutput: new Uint8Array(32).fill(5), salt: new Uint8Array(32).fill(6) }
  );
  ok(buf.byteLength === 48 && new Uint8Array(buf).every((b) => b === 0),
     "the page's key-file copy is zeroed after an encrypt-with-passkey");
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
