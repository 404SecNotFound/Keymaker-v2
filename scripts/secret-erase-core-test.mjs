#!/usr/bin/env node
/**
 * The copies of a secret that the crypto core makes for itself are erased
 * before it returns, on success and on failure.
 *
 * `secret-erase-test.mjs` checks buffers the caller can see. The ones here are
 * internal: the length-prefixed copy of a password inside the KDF input, the
 * joined key file a digest is taken over, a share value decoded from a set that
 * then turned out to contain a malformed share. None of them is reachable from
 * outside the call that made it, so this takes a census instead.
 *
 * ## The census
 *
 * While an operation runs, every `Uint8Array` the core allocates is recorded:
 * the global constructor is wrapped in a Proxy (so `new Uint8Array(n)`,
 * `new Uint8Array(arrayBuffer)` and `Uint8Array.from` are seen), and so are
 * `Uint8Array.prototype.slice` and `TextEncoder.prototype.encode`, the two
 * other ways the core makes a fresh buffer. The instances are ordinary
 * intrinsic Uint8Arrays, so `instanceof` and the libraries behave as normal.
 * When the operation settles, each recorded buffer is searched for the secret.
 * A buffer that still holds it is a copy nobody will erase, because nobody but
 * the census holds a reference to it.
 *
 * What the census cannot see is said here rather than implied: copies made
 * inside Web Crypto (an imported key, a digest input) are engine memory with no
 * JS handle, and JS strings are immutable. Neither is erasable from JS, so
 * neither is tested.
 *
 * Each section names the finding it pins; every one fails with its fix
 * reverted (see the commit that introduced it for the control output).
 */
import esbuild from "esbuild";
import { createHash } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const LIB = join(ROOT, "src", "lib");
const OUT = mkdtempSync(join(tmpdir(), "erase-core-"));
const FIXTURES = join(HERE, "fixtures", "keymaker");

let failed = 0;
const ok = (cond, msg, detail = "") => {
  if (!cond) { console.error("FAIL:", msg, detail); failed++; }
  else console.log("ok   ", msg);
};

// ---------------------------------------------------------------------------
// The census. Installed before any bundle is imported, and only *recording*
// while `observe` is running, so the test's own buffers are never counted.
// ---------------------------------------------------------------------------
const U8 = globalThis.Uint8Array;
let census = null;
const note = (view) => {
  if (census) census.push(view);
  return view;
};
const Recording = new Proxy(U8, {
  construct(target, args, newTarget) {
    return note(Reflect.construct(target, args, newTarget === Recording ? target : newTarget));
  },
});
globalThis.Uint8Array = Recording;
const nativeSlice = U8.prototype.slice;
U8.prototype.slice = function (...args) {
  return note(nativeSlice.apply(this, args));
};
const nativeEncode = TextEncoder.prototype.encode;
TextEncoder.prototype.encode = function (text) {
  return note(nativeEncode.call(this, text));
};

/**
 * Run `fn` with the census recording. `settleMs` keeps it recording after `fn`
 * settles, for work `fn` started and did not wait for: exactly the stragglers a
 * `Promise.all` that rejected early leaves behind.
 */
async function observe(fn, settleMs = 0) {
  census = [];
  let value;
  let error = null;
  try {
    value = await fn();
  } catch (e) {
    error = e;
  }
  if (settleMs) await new Promise((r) => setTimeout(r, settleMs));
  const seen = census;
  census = null;
  return { value, error, seen };
}

/**
 * Sizes of the recorded buffers still holding `needle`. `exact` matches a
 * buffer that *is* the needle rather than one containing it; `except` names
 * buffers that are allowed to hold it (the caller's own, or the one returned).
 */
function holders(seen, needle, { exact = false, except = [] } = {}) {
  const want = Buffer.from(needle.buffer, needle.byteOffset, needle.byteLength);
  const visited = new Set();
  const found = [];
  for (const view of seen) {
    const buf = view.buffer;
    if (visited.has(buf) || except.includes(buf)) continue;
    visited.add(buf);
    if (buf.byteLength === 0) continue; // detached by a transfer
    const hay = Buffer.from(buf);
    if (exact ? hay.equals(want) : hay.indexOf(want) !== -1) found.push(hay.length);
  }
  return found;
}

const none = (found) => (found.length ? `${found.length} buffer(s) still hold it, sizes [${found.join(", ")}]` : "");
const toAB = (bytes) => {
  const copy = new U8(bytes.length);
  copy.set(bytes);
  return copy.buffer;
};
const hex = (s) => U8.from(Buffer.from(s, "hex"));

async function bundle(name, contents, plugins = []) {
  const outfile = join(OUT, `${name}.mjs`);
  await esbuild.build({
    stdin: { contents, resolveDir: LIB, loader: "ts", sourcefile: `${name}.ts` },
    bundle: true,
    format: "esm",
    platform: "node",
    outfile,
    logLevel: "warning",
    plugins,
  });
  return import(pathToFileURL(outfile).href);
}

const m = await bundle(
  "core",
  `export { decryptData, encryptContainer, KdfId, CipherId } from "./keymaker-crypto";
   export { combineShares, decodeShareAny } from "./keym-v2-shamir";`
);

const meta = JSON.parse(readFileSync(join(FIXTURES, "fixtures.json"), "utf8"));
const fixture = (name) => {
  const entry = meta.fixtures.find((f) => f.name === name);
  if (!entry) throw new Error(`fixture ${name} is missing from fixtures.json`);
  return { entry, bytes: U8.from(readFileSync(join(FIXTURES, entry.file))) };
};

const PASSWORD = "erase-canary: correct horse battery staple 7f3a9c";
const PASSWORD_BYTES = U8.from(Buffer.from(PASSWORD.normalize("NFC"), "utf8"));
const KEY_FILE = U8.from({ length: 64 }, (_, i) => (i * 29 + 101) & 0xff);
// §4.2: SHA-256("keymaker.v2.keyfile" || key file). The domain string is spec
// text; the tripwire below keeps this needle from going stale silently, which
// would turn the digest checks into checks for a value that never exists.
const KEY_FILE_DIGEST = U8.from(createHash("sha256").update("keymaker.v2.keyfile").update(KEY_FILE).digest());
ok(readFileSync(join(LIB, "keym-v2.ts"), "utf8").includes('"keymaker.v2.keyfile"'),
   "tripwire: the key-file digest needle uses the domain string keym-v2.ts actually hashes with");
const OPTIONS = { kdf: { kdf: m.KdfId.PBKDF2, params: { iterations: 600_000 } }, cipher: m.CipherId.AES_256_GCM };
const settle = () => new Promise((r) => setTimeout(r, 25));

// ---------------------------------------------------------------------------
// Finding 1: the passphrase slot's KDF input. `buildKdfInput` left the NFC
// password bytes and their length-prefixed copy unerased, `keyfileDigest`'s
// join left a whole key-file copy, and the digest itself (the key file's half
// of the slot secret) was never erased either. Once per slot, every unlock and
// every enrolment.
// ---------------------------------------------------------------------------
let container;
{
  const plaintext = U8.from(Buffer.from("erase-canary plaintext for the passphrase slot"));
  const enc = await observe(() => m.encryptContainer(toAB(plaintext), PASSWORD, toAB(KEY_FILE), OPTIONS));
  ok(enc.error === null && enc.value instanceof ArrayBuffer, "encrypt with password + key file succeeds", String(enc.error));
  container = enc.value;
  ok(holders(enc.seen, PASSWORD_BYTES).length === 0,
     "encrypt: no copy of the password bytes survives", none(holders(enc.seen, PASSWORD_BYTES)));
  ok(holders(enc.seen, KEY_FILE).length === 0,
     "encrypt: no copy of the key file survives", none(holders(enc.seen, KEY_FILE)));
  ok(holders(enc.seen, KEY_FILE_DIGEST).length === 0,
     "encrypt: no copy of the key-file digest survives", none(holders(enc.seen, KEY_FILE_DIGEST)));

  const dec = await observe(() => m.decryptData(container.slice(0), PASSWORD, toAB(KEY_FILE)));
  ok(dec.error === null && Buffer.from(dec.value.data).equals(Buffer.from(plaintext)),
     "decrypt with password + key file round-trips", String(dec.error));
  // The census is not blind: the core assembled this plaintext in a buffer it
  // allocated, so at least one recorded buffer has to hold it. If none did,
  // every "no copy survives" line in this file would be vacuous.
  ok(holders(dec.seen, plaintext).length > 0,
     "tripwire: the census records the core's own allocations (it saw the decrypted plaintext)");
  ok(holders(dec.seen, PASSWORD_BYTES).length === 0,
     "unlock: no copy of the password bytes survives", none(holders(dec.seen, PASSWORD_BYTES)));
  ok(holders(dec.seen, KEY_FILE).length === 0,
     "unlock: no copy of the key file survives", none(holders(dec.seen, KEY_FILE)));
  ok(holders(dec.seen, KEY_FILE_DIGEST).length === 0,
     "unlock: no copy of the key-file digest survives", none(holders(dec.seen, KEY_FILE_DIGEST)));
}

// Finding 1, the other two slot types: `lp()` made a length-prefixed copy of
// the share secret and of the PRF output, and nothing erased it.
{
  const { entry, bytes } = fixture("v3-shamir-aes256gcm");
  const shares = entry.shamir.shares.slice(0, entry.shamir.threshold);
  const secret = await m.combineShares(shares); // census off: the test's own copy
  const dec = await observe(() => m.decryptData(toAB(bytes), "", null, shares));
  ok(dec.error === null && Buffer.from(dec.value.data).toString() === entry.plaintext,
     "unlock with a share set succeeds", String(dec.error));
  ok(holders(dec.seen, secret).length === 0,
     "unlock: no copy of the reconstructed share secret survives", none(holders(dec.seen, secret)));
}
{
  const { entry, bytes } = fixture("v3-passkey-aes256gcm");
  const prf = hex(entry.passkey.prfOutputHex);
  const dec = await observe(() => m.decryptData(toAB(bytes), "", null, undefined, prf));
  ok(dec.error === null && Buffer.from(dec.value.data).toString() === entry.plaintext,
     "unlock with a passkey PRF output succeeds", String(dec.error));
  ok(holders(dec.seen, prf, { except: [prf.buffer] }).length === 0,
     "unlock: no copy of the PRF output survives (the caller's own excepted)",
     none(holders(dec.seen, prf, { except: [prf.buffer] })));
}

// ---------------------------------------------------------------------------
// Finding 2: decryptData returned `result.data.buffer.slice(...)`, which always
// copies, and never erased what it copied from: a second complete plaintext per
// decrypt, 100 MB of it at the cap. The v1 ChaCha path had the same slice.
// ---------------------------------------------------------------------------
for (const [name, password, keyFile] of [
  ["v3-pbkdf2-aes256gcm", meta.password, null],
  ["pbkdf2-chacha20poly1305", meta.password, hex(meta.keyFileHex)],
]) {
  const { entry, bytes } = fixture(name);
  if (entry.keyFile !== (keyFile !== null)) throw new Error(`${name}: key-file expectation drifted`);
  const want = U8.from(Buffer.from(entry.plaintext));
  const dec = await observe(() => m.decryptData(toAB(bytes), password, keyFile ? toAB(keyFile) : null));
  ok(dec.error === null && Buffer.from(dec.value.data).equals(Buffer.from(want)),
     `${name}: decrypts`, String(dec.error));
  const extra = dec.error ? [] : holders(dec.seen, want, { except: [dec.value.data] });
  ok(extra.length === 0, `${name}: the returned buffer is the only plaintext copy left`, none(extra));
}

// ---------------------------------------------------------------------------
// Finding 4: combineShares decoded with a `Promise.all` that sat outside its
// `try/finally`. One malformed share rejected it before the `try` was entered,
// so the shares that decoded were never erased, and those still decoding
// resolved afterwards with no one left to erase them.
//
// Matched exactly (a buffer that *is* a share value), because the decoded
// record b32Decode returns also carries the value inside it, and that buffer
// belongs to decodeShare, not to combineShares. It is not asserted here.
// ---------------------------------------------------------------------------
{
  const { entry } = fixture("v3-shamir-aes256gcm");
  const good = entry.shamir.shares.slice(0, 2);
  const values = [];
  for (const text of good) values.push((await m.decodeShareAny(text)).value);
  const bad = "KMSHARE1:NOT-A-SHARE";
  const run = await observe(() => m.combineShares([...good, bad]), 100);
  ok(run.error !== null, "combineShares rejects a set containing a malformed share");
  const left = values.flatMap((v) => holders(run.seen, v, { exact: true }));
  ok(left.length === 0, "the shares that did decode are erased when another one is malformed", none(left));
}

// ---------------------------------------------------------------------------
// Finding 3: the worker's copy of the key file (taken so a share or passkey
// enrolment can still read it after encryptContainer zeroes the original) was
// erased after the enrolments, not in a `finally`. The handler's `catch` turns
// a throw into an ordinary response, so a failed enrolment left it in the
// worker heap. Driven through the real message handler with a stub `self`.
// ---------------------------------------------------------------------------
{
  const listeners = [];
  const posted = [];
  const previousSelf = globalThis.self;
  globalThis.self = {
    addEventListener: (type, fn) => { if (type === "message") listeners.push(fn); },
    postMessage: (msg) => posted.push(msg),
  };
  await bundle("worker", `import "./crypto-worker";`);
  globalThis.self = previousSelf;
  ok(listeners.length === 1, "the worker registered its message handler");

  const request = (id, shamir) => ({
    data: {
      id, op: "encrypt", data: toAB(U8.from(Buffer.from("worker plaintext"))), password: PASSWORD,
      keyFile: toAB(KEY_FILE), options: OPTIONS, shamir,
    },
  });

  // threshold 1 is below §4.6's minimum: shamirSplit throws, after the slot has
  // been unwrapped with the key-file copy, inside the enrolment.
  const failing = await observe(() => listeners[0](request(1, { threshold: 1, count: 3 })));
  const failRes = posted.find((p) => p.id === 1);
  ok(failRes && failRes.ok === false, "an enrolment that throws comes back as an error response", JSON.stringify(failRes));
  ok(holders(failing.seen, KEY_FILE).length === 0,
     "worker: the key-file copy is erased when the enrolment throws", none(holders(failing.seen, KEY_FILE)));

  const passing = await observe(() => listeners[0](request(2, { threshold: 2, count: 3 })));
  const passRes = posted.find((p) => p.id === 2);
  ok(passRes && passRes.ok === true && passRes.shares?.length === 3,
     "worker: the same request with a valid threshold still enrols the share set", JSON.stringify(passRes?.message));
  ok(holders(passing.seen, KEY_FILE).length === 0,
     "worker: the key-file copy is erased on success too", none(holders(passing.seen, KEY_FILE)));
}

// ---------------------------------------------------------------------------
// Finding 6 (not an erasure, but the same unlock path): the Shamir module is a
// separate chunk on the main-thread fallback, and a chunk that fails to load
// used to reach the user as "the password or key file may be incorrect".
//
// Modelled faithfully rather than mocked: this bundle leaves `keym-v2-shamir`
// as a real dynamic import of a file that does not exist yet, so the failure is
// the runtime's own module-not-found, exactly what an unreachable chunk is.
// Then the file is written and the same call is made again, which is what
// "the failure is not cached" has to mean to someone who reconnects.
// ---------------------------------------------------------------------------
{
  const CHUNK = "keym-v2-shamir.late-chunk.mjs";
  const missingChunk = {
    name: "missing-shamir-chunk",
    setup(build) {
      build.onResolve({ filter: /keym-v2-shamir$/ }, () => ({ path: `./${CHUNK}`, external: true }));
    },
  };
  const offline = await bundle(
    "offline",
    `export { decryptData, isUserFacingError } from "./keymaker-crypto";`,
    [missingChunk]
  );
  const { entry, bytes } = fixture("v3-shamir-aes256gcm");
  const shares = entry.shamir.shares.slice(0, entry.shamir.threshold);

  let first = null;
  try {
    await offline.decryptData(toAB(bytes), "", null, shares);
  } catch (e) {
    first = e;
  }
  ok(first !== null && offline.isUserFacingError(first) && first.code === "dependency-unavailable",
     "a Shamir chunk that fails to load is a typed dependency-unavailable error, not a wrong password",
     first ? `${first.code ?? "(untyped)"}: ${String(first.message).slice(0, 100)}` : "no error");
  ok(first !== null && /were not checked/.test(first.message),
     "and it tells the user the file and password were never checked", first ? first.message.slice(0, 100) : "");

  // The chunk arrives: bundle the real Shamir module at the path the first
  // attempt could not reach, and try again with the same bundle.
  await esbuild.build({
    entryPoints: [join(LIB, "keym-v2-shamir.ts")],
    bundle: true, format: "esm", platform: "node", outfile: join(OUT, CHUNK), logLevel: "warning",
  });
  let second = null;
  let opened = null;
  try {
    opened = await offline.decryptData(toAB(bytes), "", null, shares);
  } catch (e) {
    second = e;
  }
  ok(second === null && Buffer.from(opened.data).toString() === entry.plaintext,
     "once the chunk is reachable the same call opens the container (the failure was not cached)",
     second ? String(second.message).slice(0, 100) : "");
}

await settle();
console.log(failed === 0 ? "\nAll core secret-erase checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
