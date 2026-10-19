#!/usr/bin/env node
/**
 * The crypto worker answers every message, including the ones it does not
 * understand.
 *
 * Only the page can post to the worker, so a malformed message is a page bug
 * rather than an attack — but the failure mode matters: the listener is
 * `async`, so a throw inside it became a rejected promise nobody held. No
 * `error` event reached the page, no response was posted, and the client's
 * pending promise waited for ever. A `null` message did exactly that, and an
 * op the worker does not know fell through to the decrypt branch and answered
 * with "Valid data buffer is required." about a decrypt nobody asked for.
 *
 * This runs the worker bundle the way scripts/build-crypto-worker.mjs builds
 * it, inside a stand-in DedicatedWorkerGlobalScope, and posts the shapes a
 * confused page could send. Every one must get a response carrying its id
 * (or -1 when it had none) and `ok: false`; a well-formed ping must still get
 * `ok: true`. No throw may escape the listener, synchronously or as an
 * unhandled rejection.
 *
 * The control bites: with the shape guard removed, `null` gets no response
 * and the check for it fails; with the unknown-op throw removed, "bogus" is
 * answered as a failed decrypt rather than as an unknown operation.
 */
import { build } from "esbuild";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import vm from "node:vm";

const HERE = dirname(fileURLToPath(import.meta.url));
const ENTRY = join(HERE, "..", "src", "lib", "crypto-worker.ts");
const out = join(mkdtempSync(join(tmpdir(), "km-worker-")), "crypto-worker.js");
await build({
  entryPoints: [ENTRY],
  outfile: out,
  bundle: true,
  format: "iife",
  platform: "browser",
  target: ["es2022"],
  define: { "process.env.NODE_ENV": '"production"' },
  logLevel: "error",
});

let failed = 0;
const ok = (cond, msg, detail = "") => {
  if (!cond) {
    console.error("FAIL:", msg, detail);
    failed++;
  } else console.log("ok   ", msg);
};

// A stand-in worker scope: the bundle registers its listener on `self`, and
// answers through `postMessage`. Everything else it reaches for is the
// platform's.
const listeners = [];
const posted = [];
const scope = {
  addEventListener: (type, fn) => listeners.push([type, fn]),
  postMessage: (message) => posted.push(message),
  crypto: globalThis.crypto,
  performance: globalThis.performance,
  TextEncoder,
  TextDecoder,
  Uint8Array,
  ArrayBuffer,
  Promise,
  setTimeout,
  console,
  WebAssembly: globalThis.WebAssembly,
  atob,
  btoa,
  Error,
  RangeError,
  TypeError,
  Object,
  Array,
  Math,
  Number,
  Symbol,
  Map,
  Set,
  DataView,
  Uint32Array,
  Int32Array,
  Uint16Array,
  BigInt,
  JSON,
  String,
  Reflect,
  Proxy,
  navigator: {},
};
scope.self = scope;
scope.globalThis = scope;
vm.createContext(scope);
vm.runInContext(readFileSync(out, "utf8"), scope);

const onMessage = listeners.find(([type]) => type === "message")?.[1];
ok(typeof onMessage === "function", "the worker registered a message listener");

let unhandled = 0;
process.on("unhandledRejection", () => {
  unhandled++;
});

/** Post one message and collect what came back within a short wait. */
async function send(data) {
  let threw = null;
  try {
    const r = onMessage({ data });
    if (r && typeof r.then === "function") await r;
  } catch (e) {
    threw = e;
  }
  await new Promise((resolve) => setTimeout(resolve, 20));
  return { threw, responses: posted.splice(0) };
}

const cases = [
  [null, -1],
  [undefined, -1],
  [42, -1],
  ["ping", -1],
  [{}, -1],
  [{ id: 7 }, 7],
  [{ id: "7", op: "ping" }, -1],
  [{ id: 8, op: "bogus" }, 8],
  [{ id: 9, op: 11 }, 9],
];
for (const [data, id] of cases) {
  const { threw, responses } = await send(data);
  const label = JSON.stringify(data) ?? String(data);
  ok(threw === null, `${label}: nothing escaped the listener`, threw ? String(threw) : "");
  ok(responses.length === 1, `${label}: exactly one response`, `${responses.length} responses`);
  const r = responses[0];
  ok(r && r.ok === false && r.id === id, `${label}: answered with ok:false and id ${id}`, JSON.stringify(r));
  ok(r && typeof r.message === "string" && r.message.length > 0, `${label}: the response carries a message`);
}

{
  const { responses } = await send({ id: 8, op: "bogus" });
  ok(
    responses[0] && /unknown operation/i.test(responses[0].message),
    "an unknown op is named as unknown, not treated as a failed decrypt",
    JSON.stringify(responses[0])
  );
}

{
  const { threw, responses } = await send({ id: 3, op: "ping" });
  ok(threw === null && responses.length === 1 && responses[0].ok === true && responses[0].id === 3,
    "a well-formed ping is still answered ok:true with its id", JSON.stringify(responses[0]));
}

// A decrypt with the wrong shape of arguments stays a typed, user-facing
// refusal: the branch after the guard must not have become reachable with
// something the core cannot describe.
{
  const { threw, responses } = await send({ id: 4, op: "decrypt" });
  ok(threw === null && responses.length === 1 && responses[0].ok === false && responses[0].id === 4,
    "a decrypt with no buffer is refused as a response, not a crash", JSON.stringify(responses[0]));
}

await new Promise((resolve) => setTimeout(resolve, 50));
ok(unhandled === 0, "no unhandled rejection left the worker", `${unhandled} seen`);

if (failed) {
  console.error(`\n${failed} check(s) failed`);
  process.exit(1);
}
console.log("\nThe worker answers every message.");
