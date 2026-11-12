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
/**
 * How the stub answers the streaming ops: "ok" streams two chunks and then
 * answers once both are acknowledged; "fail" answers ok:false; "hang" never
 * answers, so only Stop can end the operation.
 */
let streamMode = "ok";
const workers = [];
class FakeWorker {
  constructor() { this.messageListeners = []; this.terminated = false; this.requests = []; this.acks = 0; workers.push(this); }
  addEventListener(type, fn) { if (type === "message") this.messageListeners.push(fn); }
  removeEventListener() {}
  terminate() { this.terminated = true; }
  emit(res) { for (const fn of this.messageListeners) fn({ data: res }); }
  postMessage(req, transfer) {
    for (const buf of transfer || []) {
      // Model the structured-clone transfer: detach the buffer on this side.
      try { structuredClone(buf, { transfer: [buf] }); } catch { /* already detached */ }
    }
    this.requests.push(req);
    if (req.op === "ack") {
      // The final answer comes only once every chunk is acknowledged, as the
      // real worker's does.
      if (++this.acks === 2) queueMicrotask(() => this.emit({
        id: req.stream, ok: true, op: "encrypt-stream", bytes: 8,
        head: new Uint8Array([1, 2, 3, 4]).buffer, digest: "ab".repeat(32),
      }));
      return;
    }
    if (req.op === "encrypt-stream" || req.op === "open-stream") {
      if (streamMode === "hang") return;
      queueMicrotask(() => {
        if (streamMode === "fail") {
          this.emit({ id: req.id, ok: false, code: null, message: "Decryption failed." });
        } else if (req.op === "open-stream") {
          this.emit({
            id: req.id, ok: true, op: "verify", format: "keym-v3", bytes: 3, openedBy: "passkey",
            keyFileUsed: false, slotTable: "authentic", weakKdf: null, digest: "cd".repeat(32),
          });
        } else {
          this.emit({ id: req.id, ok: true, op: "chunk", seq: 0, data: new Uint8Array([1, 2, 3, 4]).buffer });
          this.emit({ id: req.id, ok: true, op: "chunk", seq: 1, data: new Uint8Array([5, 6, 7, 8]).buffer });
        }
      });
      return;
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

// ---- The streaming calls ----
//
// encryptFileViaWorker and verifyFileViaWorker take a PRF output that is
// structured-cloned to the worker, not transferred, so the page's copy is the
// client's to erase: on success, on a failure the worker reports, on Stop, and
// (for encrypt) when the page's own writer fails. The key file is transferred,
// so it is detached on every path that reached the worker.
//
// The control bites: with the erases removed from the two functions'
// `finally`, every PRF check below fails.
{
  const zeroed = (u) => u.byteLength === 32 && u.every((b) => b === 0);
  const prf = () => new Uint8Array(32).fill(5);
  const passkey = (p) => ({ prfOutput: p, salt: new Uint8Array(32).fill(6) });
  const file = () => new File([new Uint8Array([9, 9, 9])], "plain.bin");
  const settle = async (p) => { try { return { value: await p }; } catch (error) { return { error }; } };
  const lastWorker = () => workers.at(-1);
  const tick = () => new Promise((r) => setTimeout(r, 10));

  // Encrypt, success: both chunks reach the writer in order, each is
  // acknowledged after its write, and the call resolves after the last.
  {
    streamMode = "ok";
    const p = prf();
    const key = keyBytes(48).buffer;
    const written = [];
    const r = await settle(m.encryptFileViaWorker(file(), "pw", key, OPTIONS, async (b) => { written.push([...b]); }, undefined, passkey(p)));
    ok(!r.error && r.value.bytes === 8 && r.value.digest === "ab".repeat(32) && r.value.head.length === 4,
       "a streamed encrypt resolves with the worker's summary");
    ok(JSON.stringify(written) === JSON.stringify([[1, 2, 3, 4], [5, 6, 7, 8]]), "both chunks reached the writer, in order");
    const acks = lastWorker().requests.filter((q) => q.op === "ack").map((q) => q.seq);
    ok(JSON.stringify(acks) === "[0,1]", "each chunk was acknowledged once it had been written");
    ok(zeroed(p), "the page's PRF output is erased after a streamed encrypt");
    ok(key.byteLength === 0, "the key file was transferred (detached) by a streamed encrypt");
  }
  // Encrypt, the worker reports a failure.
  {
    streamMode = "fail";
    const p = prf();
    const key = keyBytes(48).buffer;
    const r = await settle(m.encryptFileViaWorker(file(), "pw", key, OPTIONS, async () => {}, undefined, passkey(p)));
    ok(r.error instanceof Error, "a streamed encrypt the worker fails rejects");
    ok(zeroed(p), "the page's PRF output is erased after a failed streamed encrypt");
    ok(key.byteLength === 0, "and the key file had been transferred");
  }
  // Encrypt, Stop while the worker is working.
  {
    streamMode = "hang";
    const p = prf();
    const key = keyBytes(48).buffer;
    const pending = settle(m.encryptFileViaWorker(file(), "pw", key, OPTIONS, async () => {}, undefined, passkey(p)));
    await tick();
    const w = lastWorker();
    ok(m.cancelAllCryptoWork() === true, "Stop terminates a streaming operation");
    const r = await pending;
    ok(r.error instanceof m.CryptoCancelled && w.terminated, "the streamed encrypt rejects as cancelled, and the worker is gone");
    ok(zeroed(p), "the page's PRF output is erased after a stopped streamed encrypt");
  }
  // Encrypt, the page's writer fails (a full disk): the worker is terminated
  // and the call rejects with the writer's own error, not a cancellation.
  {
    streamMode = "ok";
    const p = prf();
    const diskFull = new Error("disk full");
    const r = await settle(m.encryptFileViaWorker(file(), "pw", null, OPTIONS, async () => { throw diskFull; }, undefined, passkey(p)));
    const w = lastWorker();
    ok(r.error === diskFull, "a writer that fails rejects the streamed encrypt with that error", String(r.error));
    ok(w.terminated, "and the worker is terminated");
    ok(!w.requests.some((q) => q.op === "ack"), "and nothing it did not write was acknowledged");
    ok(zeroed(p), "the page's PRF output is erased after the writer failed");
  }
  // Verify: success, failure and Stop.
  {
    streamMode = "ok";
    const p = prf();
    const key = keyBytes(48).buffer;
    const r = await settle(m.verifyFileViaWorker(file(), "", key, undefined, p, { digest: true }));
    ok(!r.error && r.value.bytes === 3 && r.value.digest === "cd".repeat(32) && r.value.inWorker === true,
       "a streamed verify resolves with the count and the digest");
    const sent = lastWorker().requests.find((q) => q.op === "open-stream");
    ok(sent && sent.purpose === "verify" && sent.digest === true, "it asks for purpose verify, with the digest");
    ok(zeroed(p), "the page's PRF output is erased after a streamed verify");
    ok(key.byteLength === 0, "the key file was transferred (detached) by a streamed verify");
  }
  {
    streamMode = "fail";
    const p = prf();
    const r = await settle(m.verifyFileViaWorker(file(), "", null, undefined, p));
    ok(r.error instanceof Error, "a streamed verify the worker fails rejects");
    ok(zeroed(p), "the page's PRF output is erased after a failed streamed verify");
  }
  {
    streamMode = "hang";
    const p = prf();
    const pending = settle(m.verifyFileViaWorker(file(), "", null, undefined, p));
    await tick();
    ok(m.cancelAllCryptoWork() === true, "Stop terminates a streamed verify");
    const r = await pending;
    ok(r.error instanceof m.CryptoCancelled, "the streamed verify rejects as cancelled");
    ok(zeroed(p), "the page's PRF output is erased after a stopped streamed verify");
  }
}

console.log(failed === 0 ? "\nAll secret-erase checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
