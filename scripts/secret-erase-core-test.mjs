#!/usr/bin/env node
/**
 * The copies of a secret that the crypto core makes for itself are erased
 * before it returns, on success and on failure.
 *
 * `secret-erase-test.mjs` checks buffers the caller can see. The ones here are
 * internal: the length-prefixed copy of a password inside the KDF input, the
 * joined key file a digest is taken over, a share value decoded from a set that
 * then turned out to contain a malformed share, the decoded share record itself.
 * None of them is reachable from outside the call that made it, so this takes a
 * census instead.
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
import { mkdtempSync, readdirSync, readFileSync } from "node:fs";
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
// belongs to decodeShare, not to combineShares. The finding-7 block below
// asserts it.
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

// ---------------------------------------------------------------------------
// Finding 7: the record b32Decode returns is the whole share, value included,
// and parseShare copies what it keeps. Nothing erased the record, nor the
// checksum input built from it, nor a record b32Decode itself refused for its
// padding bits. And two callers decoded a share only for its set id or index
// and dropped the value unerased: sharesNeedPasswordKeym2 and the printout
// check. The finding-4 block above could not assert any of this because the
// record was nobody's to erase; decodeShare owns it now.
// ---------------------------------------------------------------------------
{
  const extra = await bundle(
    "share-callers",
    `export { sharesNeedPasswordKeym2 } from "./keym-v2";
     export { checkPrintoutCode } from "./printout-check";`
  );
  const B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  const { entry: v1Entry, bytes: v1Bytes } = fixture("v3-shamir-aes256gcm");
  const { entry: bothEntry, bytes: bothBytes } = fixture("v3-both-aes256gcm");
  const v1Shares = v1Entry.shamir.shares.slice(0, v1Entry.shamir.threshold);
  const v2Shares = bothEntry.both.shares.slice(0, bothEntry.both.threshold);
  const valueOf = async (text) => (await m.decodeShareAny(text)).value; // census off
  const survivors = (seen, values, except = []) =>
    values.flatMap((v) => holders(seen, v, { except }));

  for (const [label, text] of [["KMSHARE1", v1Shares[0]], ["KMSHARE2", v2Shares[0]]]) {
    const value = await valueOf(text);
    const run = await observe(() => m.decodeShareAny(text));
    ok(run.error === null, `${label}: decodes`, String(run.error));
    const left = run.error ? [] : holders(run.seen, value, { except: [run.value.value.buffer] });
    ok(left.length === 0, `${label}: decoding leaves no copy of the value but the one returned`, none(left));
  }

  for (const [label, shares] of [["KMSHARE1", v1Shares], ["KMSHARE2", v2Shares]]) {
    const values = await Promise.all(shares.map(valueOf));
    const run = await observe(() => m.combineShares(shares));
    ok(run.error === null, `${label}: a good set combines`, String(run.error));
    const left = survivors(run.seen, values);
    ok(left.length === 0, `${label}: no share value survives a successful combine`, none(left));
  }

  // A checksum character changed: the record decodes, parseShare refuses it,
  // and the value in it is still the genuine one. Group 5 onward is past the
  // 4-byte set id, the two header bytes and the 32-byte value.
  {
    const text = v1Shares[0];
    const value = await valueOf(text);
    const at = text.length - 3;
    const swapped = text.slice(0, at) + (text[at] === "0" ? "1" : "0") + text.slice(at + 1);
    const run = await observe(() => m.combineShares([swapped, ...v1Shares.slice(1)]), 100);
    ok(run.error !== null, "a share whose checksum no longer matches is refused");
    const left = holders(run.seen, value);
    ok(left.length === 0, "the refused share's value is erased with its record", none(left));
  }

  // Padding bits set in the last character: b32Decode has decoded the whole
  // record, value included, before it looks at them.
  {
    const text = v1Shares[0];
    const value = await valueOf(text);
    const last = B32.indexOf(text[text.length - 1]);
    const padded = text.slice(0, -1) + B32[last | 1];
    ok(padded !== text, "the padding-bit share really differs from the original");
    const run = await observe(() => m.combineShares([padded, ...v1Shares.slice(1)]), 100);
    ok(run.error !== null, "a share with non-zero padding bits is refused");
    const left = holders(run.seen, value);
    ok(left.length === 0, "b32Decode erases a record it refuses for its padding", none(left));
  }

  {
    const values = await Promise.all(v2Shares.map(valueOf));
    const run = await observe(() => extra.sharesNeedPasswordKeym2(bothBytes, v2Shares));
    ok(run.error === null && run.value === true, "sharesNeedPasswordKeym2 sees the password-and-shares slot",
       String(run.error ?? run.value));
    const left = survivors(run.seen, values);
    ok(left.length === 0, "sharesNeedPasswordKeym2 keeps no share value", none(left));
  }

  {
    const value = await valueOf(v1Shares[0]);
    const run = await observe(() => extra.checkPrintoutCode(v1Shares[0], { container: v1Bytes, header: null }));
    ok(run.error === null && run.value?.kind === "strip" && run.value?.belongs === "yes",
       "the printout check reads a strip and places it in its backup",
       String(run.error ?? JSON.stringify(run.value)));
    const left = holders(run.seen, value);
    ok(left.length === 0, "the printout check keeps no share value", none(left));
  }
}

// ---------------------------------------------------------------------------
// The same failure one level up. keymaker-crypto.ts reaches keym-v2.ts through a
// dynamic import on every v2/v3 path (decrypt, encrypt, encrypt-with-shares),
// and addShamirSlotKeym2 reached the Shamir module through a bare import() of
// its own rather than loadShamir(). Each rejected with the runtime's error, so
// an unreachable chunk surfaced as a wrong password or "Encryption failed".
// Modelled the way the block above is: a real dynamic import of a file that
// does not exist yet, then the file is written and the call is made again.
// ---------------------------------------------------------------------------
{
  const CHUNK = "keym-v2.late-chunk.mjs";
  const missingKeym2 = {
    name: "missing-keym2-chunk",
    setup(build) {
      build.onResolve({ filter: /\/keym-v2$/ }, () => ({ path: `./${CHUNK}`, external: true }));
    },
  };
  const offline = await bundle(
    "offline-keym2",
    `export { decryptData, encryptContainer, encryptContainerWithSharesRequired, isUserFacingError, KdfId, CipherId } from "./keymaker-crypto";`,
    [missingKeym2]
  );
  const typed = (e) => e !== null && offline.isUserFacingError(e) && e.code === "dependency-unavailable";
  const why = (e) => (e ? `${e.code ?? "(untyped)"}: ${String(e.message).slice(0, 100)}` : "no error");
  const attempt = async (fn) => {
    try {
      return { value: await fn(), error: null };
    } catch (e) {
      return { value: null, error: e };
    }
  };
  const OPTS = { kdf: { kdf: offline.KdfId.PBKDF2, params: { iterations: 600_000 } }, cipher: offline.CipherId.AES_256_GCM };
  const { entry, bytes } = fixture("v3-shamir-aes256gcm");
  const shares = entry.shamir.shares.slice(0, entry.shamir.threshold);

  const dec = await attempt(() => offline.decryptData(toAB(bytes), "", null, shares));
  ok(typed(dec.error), "a keym-v2 chunk that fails to load is a typed error on decrypt, not a wrong password", why(dec.error));
  const enc = await attempt(() => offline.encryptContainer(toAB(U8.from([1, 2, 3])), PASSWORD, null, OPTS));
  ok(typed(enc.error), "a keym-v2 chunk that fails to load is a typed error on encrypt", why(enc.error));
  const both = await attempt(() =>
    offline.encryptContainerWithSharesRequired(toAB(U8.from([1, 2, 3])), PASSWORD, null, OPTS, 2, 3));
  ok(typed(both.error), "a keym-v2 chunk that fails to load is a typed error on encrypt with shares", why(both.error));

  await esbuild.build({
    entryPoints: [join(LIB, "keym-v2.ts")],
    bundle: true, format: "esm", platform: "node", outfile: join(OUT, CHUNK), logLevel: "warning",
  });
  const again = await attempt(() => offline.decryptData(toAB(bytes), "", null, shares));
  ok(again.error === null && Buffer.from(again.value.data).toString() === entry.plaintext,
     "once the keym-v2 chunk is reachable the same call opens the container (the failure was not cached)",
     why(again.error));
}

// ---------------------------------------------------------------------------
// The two loaders above are the only dynamic imports of keym-v2.ts and
// keym-v2-shamir.ts in src. Twenty-one other sites (the page, crypto-client.ts's
// fallback, the worker) used a bare `import()`. None can fail today: the page
// imports keym-v2 statically and the worker is one bundle. But each is where the
// untyped failure would come back the day that stops being true, and no call
// can model it while the static import is there. So it is checked in the source.
// ---------------------------------------------------------------------------
{
  const LOADERS = new Map([
    ["keymaker-crypto.ts", 'keym2Promise = import("./keym-v2")'],
    ["keym-v2.ts", 'shamirModulePromise = import("./keym-v2-shamir")'],
  ]);
  const bare = /(?<!typeof\s)\bimport\s*\(\s*["'`][^"'`]*\bkeym-v2(?:-shamir)?["'`]\s*\)/g;
  const offenders = [];
  const walk = (dir) => {
    for (const d of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, d.name);
      if (d.isDirectory()) walk(path);
      else if (/\.(ts|tsx|mts|js|mjs)$/.test(d.name)) {
        readFileSync(path, "utf8").split("\n").forEach((line, i) => {
          for (const m of line.matchAll(bare)) {
            if (LOADERS.get(d.name) && line.includes(LOADERS.get(d.name))) continue;
            offenders.push(`${path.slice(ROOT.length + 1)}:${i + 1}: ${m[0]}`);
          }
        });
      }
    }
  };
  walk(join(ROOT, "src"));
  ok(offenders.length === 0,
     "keym-v2 and keym-v2-shamir are imported lazily only through loadKeym2 and loadShamir",
     offenders.join("; "));
  // The pattern itself has to see the forms it guards against, or a clean
  // result means nothing.
  for (const form of ['await import("@/lib/keym-v2")', "import('./keym-v2-shamir')", "import( \"../lib/keym-v2\" )"]) {
    ok(form.match(bare) !== null, `the guard recognises ${form}`);
  }
  ok('Promise<typeof import("./keym-v2")>'.match(bare) === null, "the guard ignores a type-only import()");
}
{
  const CHUNK = "keym-v2-shamir.enrol-chunk.mjs";
  const missingShamir = {
    name: "missing-shamir-chunk-enrol",
    setup(build) {
      build.onResolve({ filter: /keym-v2-shamir$/ }, () => ({ path: `./${CHUNK}`, external: true }));
    },
  };
  const offline = await bundle(
    "offline-enrol",
    `export { addShamirSlotKeym2 } from "./keym-v2"; export { isUserFacingError } from "./keymaker-crypto";`,
    [missingShamir]
  );
  const { bytes: pwBytes } = fixture("v3-pbkdf2-aes256gcm");
  const enrol = async () => {
    try {
      return { value: await offline.addShamirSlotKeym2(pwBytes, { password: meta.password, keyFile: null }, 2, 3), error: null };
    } catch (e) {
      return { value: null, error: e };
    }
  };
  const first = await enrol();
  ok(first.error !== null && offline.isUserFacingError(first.error) && first.error.code === "dependency-unavailable",
     "enrolling a share set with the Shamir chunk unreachable is a typed dependency-unavailable error",
     first.error ? `${first.error.code ?? "(untyped)"}: ${String(first.error.message).slice(0, 100)}` : "no error");

  await esbuild.build({
    entryPoints: [join(LIB, "keym-v2-shamir.ts")],
    bundle: true, format: "esm", platform: "node", outfile: join(OUT, CHUNK), logLevel: "warning",
  });
  const second = await enrol();
  ok(second.error === null && second.value?.shares?.length === 3,
     "once the Shamir chunk is reachable the same enrolment succeeds (the failure was not cached)",
     second.error ? String(second.error.message).slice(0, 100) : "");
}

/** Erase a buffer the test itself was handed, so the next census does not find it. */
const secureEraseLocal = (v) => v && v.fill(0);

// ---------------------------------------------------------------------------
// Roadmap 9.4 and Section 04: buffers the Shamir code generates for itself.
//
// The coefficients `shamirSplit` draws are the only thing between one share
// and the secret; the share secret and the master key are the secret. None of
// them is reachable from outside the call, so every `getRandomValues` draw made
// during an operation is copied the moment it is drawn, and afterwards the
// census is searched for each copy. A draw that is still anywhere in memory is
// one nobody will erase. Draws shorter than 32 bytes are nonces, which are
// written into the container in the clear, and are not searched for. Salts and
// container ids are passed in explicitly below, so no public 32-byte value is
// drawn.
//
// Failures are injected by making `crypto.subtle.encrypt` throw once the
// operation is under way. The error the caller sees has to be that one: a
// cleanup that threw would replace it.
//
// And the other side of ownership: buffers the caller passed in (the
// conformance path's fixed coefficients, a share's value, a PRF output, the
// secret being split) come back byte for byte unchanged.
// ---------------------------------------------------------------------------
{
  const s = await bundle(
    "shamir-owned",
    `export { shamirSplit, encodeShareV2, combineShares, SHARE_VALUE_LEN } from "./keym-v2-shamir";
     export {
       addShamirSlotKeym2, addPasskeySlotKeym2, encryptKeym2WithExplicitSecrets,
       encryptKeym2WithSharesRequired, encryptKeym2WithSlots, KEYM2_VERSION_V3,
     } from "./keym-v2";
     export { KdfId, CipherId } from "./keymaker-crypto";`
  );

  const nativeRandom = crypto.getRandomValues.bind(crypto);
  let draws = null;
  crypto.getRandomValues = (view) => {
    const filled = nativeRandom(view);
    if (draws) draws.push({ view, copy: Buffer.from(view.buffer, view.byteOffset, view.byteLength).toString("hex") });
    return filled;
  };
  const subtle = crypto.subtle;
  const nativeDeriveBits = subtle.deriveBits.bind(subtle);
  let derivations = 0;
  subtle.deriveBits = (...args) => {
    derivations++;
    return nativeDeriveBits(...args);
  };
  const nativeEncrypt = subtle.encrypt.bind(subtle);
  let failEncrypt = false;
  subtle.encrypt = (...args) => {
    if (failEncrypt) return Promise.reject(new Error("injected: encrypt refused"));
    return nativeEncrypt(...args);
  };

  /** observe(), recording draws as well. */
  const watch = async (fn) => {
    draws = [];
    const run = await observe(fn);
    const drawn = draws;
    draws = null;
    return { ...run, drawn };
  };
  /** Secret draws (32 bytes and over) still held anywhere the census saw, as "size@index". */
  const survivingDraws = (seen, drawn) =>
    drawn
      .map((d, i) => ({ d, i }))
      .filter(({ d }) => d.view.byteLength >= 32)
      .flatMap(({ d, i }) => holders(seen, hex(d.copy)).map((size) => `${d.view.byteLength}-byte draw #${i} in a ${size}-byte buffer`));
  const secretDraws = (drawn) => drawn.filter((d) => d.view.byteLength >= 32);

  const OPTIONS = { kdf: { kdf: s.KdfId.PBKDF2, params: { iterations: 600_000 } }, cipher: s.CipherId.AES_256_GCM };
  const PLAIN = U8.from(Buffer.from("owned-buffer canary payload 4c1d", "utf8"));
  const SALT = U8.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff);
  const SALT2 = U8.from({ length: 32 }, (_, i) => (i * 11 + 5) & 0xff);
  const CID = U8.from({ length: 16 }, (_, i) => (i * 13 + 1) & 0xff);
  const MASTER = U8.from({ length: 32 }, (_, i) => (i * 17 + 9) & 0xff);
  const same = (a, b) => Buffer.from(a).equals(Buffer.from(b));

  // -- shamirSplit, drawing its own coefficients ------------------------------
  for (const [k, n] of [[2, 3], [3, 5], [8, 16]]) {
    const secret = U8.from({ length: 32 }, (_, i) => (i * 5 + k) & 0xff);
    const before = U8.from(secret);
    const run = await watch(() => s.shamirSplit(secret, k, n));
    const coeffDraws = run.drawn.filter((d) => d.view.byteLength === (k - 1) * 32);
    ok(run.error === null && coeffDraws.length === 1,
       `${k}-of-${n}: the split draws its (k-1)*32 coefficient bytes in one call (the check below is not vacuous)`,
       run.error ? String(run.error) : `${coeffDraws.length} draws of ${(k - 1) * 32} bytes`);
    ok(coeffDraws.every((d) => d.view.every((b) => b === 0)),
       `${k}-of-${n}: the coefficients are zero once the split returns`);
    ok(survivingDraws(run.seen, run.drawn).length === 0,
       `${k}-of-${n}: no copy of the coefficients survives the split`, survivingDraws(run.seen, run.drawn).join("; "));
    ok(same(secret, before), `${k}-of-${n}: the secret being split is the caller's and is not modified`);
    for (const part of run.value ?? []) secureEraseLocal(part.value);
  }

  // -- shamirSplit, conformance path: caller-supplied coefficients ------------
  {
    const secret = U8.from({ length: 32 }, (_, i) => (i * 3 + 1) & 0xff);
    const coeffs = U8.from({ length: 64 }, (_, i) => (i * 19 + 7) & 0xff);
    const coeffsBefore = U8.from(coeffs);
    const first = s.shamirSplit(secret, 3, 5, coeffs);
    const second = s.shamirSplit(secret, 3, 5, coeffs);
    ok(same(coeffs, coeffsBefore), "caller-supplied coefficients are the caller's: unchanged after the split");
    ok(first.every((p, i) => same(p.value, second[i].value)),
       "with fixed coefficients the split is deterministic, so conformance vectors still compare byte for byte");
  }

  // -- encodeShareV2 -----------------------------------------------------------
  {
    const value = U8.from({ length: 32 }, (_, i) => (i * 23 + 11) & 0xff);
    const share = { setId: U8.from({ length: 16 }, (_, i) => i), threshold: 3, index: 2, value };
    const run = await observe(() => s.encodeShareV2(share));
    ok(run.error === null && typeof run.value === "string", "encodeShareV2 encodes a share");
    const left = holders(run.seen, value, { except: [value.buffer] });
    ok(left.length === 0, "encoding a share leaves no copy of its value behind (the packed record and its body)", none(left));
    ok(same(share.value, U8.from({ length: 32 }, (_, i) => (i * 23 + 11) & 0xff)),
       "the share value passed in is the caller's: unchanged after encoding");
  }

  // A v3 AES container with a known master key, to enrol into.
  const base = await s.encryptKeym2WithExplicitSecrets(PLAIN, PASSWORD, null, OPTIONS, SALT, U8.from(MASTER), s.KEYM2_VERSION_V3, CID);

  // -- addShamirSlotKeym2, success --------------------------------------------
  {
    const run = await watch(() => s.addShamirSlotKeym2(base, { password: PASSWORD, keyFile: null }, 3, 5, { salt: SALT2 }));
    ok(run.error === null && run.value?.shares?.length === 5, "a 3-of-5 share set enrols", run.error ? String(run.error) : "");
    ok(secretDraws(run.drawn).length === 2,
       "the enrolment draws two secrets of its own, the share secret and the coefficients (the checks below are not vacuous)",
       `${secretDraws(run.drawn).length} draws`);
    const leftDraws = survivingDraws(run.seen, run.drawn);
    ok(leftDraws.length === 0, "after an enrolment no copy of the share secret or the coefficients survives", leftDraws.join("; "));
    const leftMaster = holders(run.seen, MASTER);
    ok(leftMaster.length === 0, "after an enrolment no copy of the unwrapped master key survives", none(leftMaster));
    // Guarded: if the enrolment threw, the lines below would throw too and
    // take every later check in this section with them, which hides exactly
    // the failure a control is looking for. The failure is already recorded.
    if (run.error === null && secretDraws(run.drawn).length === 2) {
      // The share values, recomputed outside the census from the drawn secrets.
      const [secretDraw, coeffDraw] = secretDraws(run.drawn);
      const parts = s.shamirSplit(hex(secretDraw.copy), 3, 5, hex(coeffDraw.copy));
      const leftParts = parts.flatMap((p) => holders(run.seen, p.value, { exact: true }));
      ok(leftParts.length === 0, "after an enrolment no share value survives outside the strings returned", none(leftParts));
      // The returned strings still open the container, so erasing did not reach them.
      const recovered = await s.combineShares(run.value.shares.slice(0, 3));
      ok(same(recovered, hex(secretDraw.copy)), "the shares returned reconstruct the share secret that was drawn");
    }
  }

  // -- addShamirSlotKeym2, a failure after the secrets exist ------------------
  {
    failEncrypt = true;
    const run = await watch(() => s.addShamirSlotKeym2(base, { password: PASSWORD, keyFile: null }, 3, 5, { salt: SALT2 }));
    failEncrypt = false;
    ok(run.error?.message === "injected: encrypt refused",
       "a failure while wrapping the new slot reaches the caller as itself", run.error ? String(run.error.message) : "no error");
    ok(secretDraws(run.drawn).length === 2, "the share secret and coefficients existed when it failed (the check is not vacuous)",
       `${secretDraws(run.drawn).length} draws`);
    const leftDraws = survivingDraws(run.seen, run.drawn);
    ok(leftDraws.length === 0, "after a failed enrolment no copy of the share secret or the coefficients survives", leftDraws.join("; "));
    const leftMaster = holders(run.seen, MASTER);
    ok(leftMaster.length === 0, "after a failed enrolment no copy of the unwrapped master key survives", none(leftMaster));
  }

  // -- addShamirSlotKeym2, refused after the master key is unwrapped ----------
  {
    const run = await watch(() =>
      s.addShamirSlotKeym2(base, { password: PASSWORD, keyFile: null }, 3, 5, { salt: U8.from({ length: 16 }) })
    );
    ok(run.error?.code === "invalid-input", "an enrolment with a 16-byte salt is refused",
       run.error ? `${run.error.code}: ${run.error.message}` : "no error");
    const leftMaster = holders(run.seen, MASTER);
    ok(leftMaster.length === 0, "a refused enrolment leaves no copy of the master key", none(leftMaster));
  }

  // -- addShamirSlotKeym2, an invalid threshold is refused before the KDF -----
  {
    derivations = 0;
    const run = await watch(() => s.addShamirSlotKeym2(base, { password: PASSWORD, keyFile: null }, 9, 5, { salt: SALT2 }));
    ok(run.error?.code === "invalid-input", "a threshold above the share count is refused",
       run.error ? `${run.error.code}: ${run.error.message}` : "no error");
    ok(derivations === 0, "it is refused before any key is derived, so the master key is never unwrapped",
       `${derivations} derivation(s)`);
    const leftDraws = survivingDraws(run.seen, run.drawn);
    ok(leftDraws.length === 0, "and the share secret drawn before the refusal does not survive it", leftDraws.join("; "));
  }

  // -- addPasskeySlotKeym2 -----------------------------------------------------
  {
    const prf = U8.from({ length: 32 }, (_, i) => (i * 31 + 13) & 0xff);
    const prfBefore = U8.from(prf);
    const good = await observe(() => s.addPasskeySlotKeym2(base, { password: PASSWORD, keyFile: null }, prf, SALT2));
    ok(good.error === null, "a passkey slot enrols", good.error ? String(good.error) : "");
    ok(same(prf, prfBefore), "the PRF output is the caller's: unchanged after the enrolment (the client erases its own copy)");
    const leftGood = holders(good.seen, MASTER);
    ok(leftGood.length === 0, "after a passkey enrolment no copy of the master key survives", none(leftGood));

    failEncrypt = true;
    const bad = await observe(() => s.addPasskeySlotKeym2(base, { password: PASSWORD, keyFile: null }, prf, SALT2));
    failEncrypt = false;
    ok(bad.error?.message === "injected: encrypt refused", "a failed passkey wrap reaches the caller as itself",
       bad.error ? String(bad.error.message) : "no error");
    const leftBad = holders(bad.seen, MASTER);
    ok(leftBad.length === 0, "after a failed passkey enrolment no copy of the master key survives", none(leftBad));
  }

  // -- encryptKeym2WithSharesRequired (§4.8) ------------------------------------
  for (const inject of [false, true]) {
    failEncrypt = inject;
    const run = await watch(() =>
      s.encryptKeym2WithSharesRequired(PLAIN, PASSWORD, null, OPTIONS, 3, 5, s.KEYM2_VERSION_V3, { salt: SALT, containerId: CID })
    );
    failEncrypt = false;
    const label = inject ? "a failed §4.8 write" : "a §4.8 write";
    ok(inject ? run.error?.message === "injected: encrypt refused" : run.error === null,
       inject ? "a failure during the §4.8 write reaches the caller as itself" : "a §4.8 container with a 3-of-5 set is written",
       run.error ? String(run.error.message) : "");
    const draws3 = secretDraws(run.drawn);
    ok(draws3.length === 3, `${label} draws the master key, the share secret and the coefficients (not vacuous)`, `${draws3.length} draws`);
    const leftDraws = survivingDraws(run.seen, run.drawn);
    ok(leftDraws.length === 0, `after ${label} no copy of the master key, the share secret or the coefficients survives`,
       leftDraws.join("; "));
    if (draws3.length === 3) {
      const parts = s.shamirSplit(hex(draws3[1].copy), 3, 5, hex(draws3[2].copy));
      const leftParts = parts.flatMap((p) => holders(run.seen, p.value, { exact: true }));
      ok(leftParts.length === 0, `after ${label} no share value survives outside the strings returned`, none(leftParts));
    }
  }

  // -- encryptKeym2WithSlots (roadmap 9.3): every way in, in one write ---------
  // Salts and the container id are pinned so every 32-byte draw is a secret:
  // the master key, the share secret, and the coefficients.
  for (const inject of [false, true]) {
    const prf = U8.from({ length: 32 }, (_, i) => (i * 43 + 3) & 0xff);
    const prfBefore = U8.from(prf);
    failEncrypt = inject;
    const run = await watch(() =>
      s.encryptKeym2WithSlots(PLAIN, PASSWORD, null, OPTIONS,
        { shamir: { threshold: 3, count: 5 }, passkey: { prfOutput: prf, salt: SALT2 } },
        s.KEYM2_VERSION_V3, { salt: SALT, containerId: CID, shareSalt: SALT2 })
    );
    failEncrypt = false;
    const label = inject ? "a failed one-operation write" : "a one-operation write";
    ok(inject ? run.error?.message === "injected: encrypt refused" : run.error === null && run.value?.shares?.length === 5,
       inject ? "a failure during the one-operation write reaches the caller as itself"
              : "a backup with a password, a 3-of-5 share set and a passkey is written in one operation",
       run.error ? String(run.error.message) : "");
    const drawn = secretDraws(run.drawn);
    ok(drawn.length === 3, `${label} draws the master key, the share secret and the coefficients (not vacuous)`,
       `${drawn.length} draws`);
    const leftDraws = survivingDraws(run.seen, run.drawn);
    ok(leftDraws.length === 0, `after ${label} no copy of the master key, the share secret or the coefficients survives`,
       leftDraws.join("; "));
    if (drawn.length === 3) {
      const parts = s.shamirSplit(hex(drawn[1].copy), 3, 5, hex(drawn[2].copy));
      const leftParts = parts.flatMap((p) => holders(run.seen, p.value, { exact: true }));
      ok(leftParts.length === 0, `after ${label} no share value survives outside the strings returned`, none(leftParts));
    }
    ok(same(prf, prfBefore), `${label} leaves the caller's PRF output unchanged`);
  }

  crypto.getRandomValues = nativeRandom;
  subtle.encrypt = nativeEncrypt;
  subtle.deriveBits = nativeDeriveBits;
}

// ---------------------------------------------------------------------------
// The streaming core. Every writer and `decryptKeym2` now run through
// `writeKeym2SlotsToSink` and `openKeym2Stream`, which read the plaintext a
// chunk at a time and hand output to a sink. What they own and must erase,
// on success and on every way out of a failure:
//
// - the writer: the master key it draws, the KDF input, every plaintext
//   buffer it reads from its source, including when the sink throws
//   mid-stream and when sealing a chunk throws with that chunk in hand;
// - the reader: the payload key and chunk 0's plaintext it holds between
//   open and drain, on `discard` and when `drain` fails part-way.
//
// Plaintext needles are 64-byte windows of a pseudo-random plaintext taken
// from chunks 0, 1 and 2, searched for everywhere but the caller's own
// buffer. The ChaCha payload key is a copy of the master key, so the reader's
// checks search for the master key itself. Each check fails with the
// streaming core's `finally` erases removed.
// ---------------------------------------------------------------------------
{
  const st = await bundle(
    "stream-core",
    `export { encryptKeym2ToSink, encryptKeym2WithExplicitSecrets, openKeym2Stream, bytesSource,
       KEYM2_VERSION_V3, KEYM2_CHUNK_SIZE } from "./keym-v2";
     export { KdfId, CipherId } from "./keymaker-crypto";`
  );
  const C = st.KEYM2_CHUNK_SIZE;
  const OPTS = { kdf: { kdf: st.KdfId.PBKDF2, params: { iterations: 600_000 } }, cipher: st.CipherId.AES_256_GCM };
  const PLAIN = new U8(2 * C + 10);
  for (let i = 0, x = 0x9e3779b9; i < PLAIN.length; i++) {
    x = (Math.imul(x, 1103515245) + 12345) >>> 0;
    PLAIN[i] = x >>> 24;
  }
  // Chunk 2 holds only the last 10 bytes, so its window is 9 of them.
  const needles = [[100, 64], [C + 100, 64], [2 * C + 1, 9]].map(([at, n]) => U8.from(PLAIN.subarray(at, at + n)));
  const SALT = U8.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff);
  const CID = U8.from({ length: 16 }, (_, i) => (i * 13 + 1) & 0xff);
  const MASTER = U8.from({ length: 32 }, (_, i) => (i * 17 + 9) & 0xff);
  const plaintextLeft = (seen) =>
    needles.flatMap((n, i) => holders(seen, n, { except: [PLAIN.buffer] }).map((size) => `chunk ${i} window in a ${size}-byte buffer`));

  const nativeRandom = crypto.getRandomValues.bind(crypto);
  let draws = null;
  crypto.getRandomValues = (view) => {
    const filled = nativeRandom(view);
    if (draws) draws.push(U8.from(view));
    return filled;
  };
  const subtle = crypto.subtle;
  const nativeEncrypt = subtle.encrypt.bind(subtle);
  let encryptCalls = 0;
  let failEncryptAt = 0;
  subtle.encrypt = (...args) => {
    encryptCalls++;
    if (failEncryptAt && encryptCalls === failEncryptAt) return Promise.reject(new Error("injected: chunk seal refused"));
    return nativeEncrypt(...args);
  };

  // -- the writer ---------------------------------------------------------------
  // Writes, in order: the head (1), chunk 0 (2), chunk 1 (3), chunk 2 (4).
  // AES encrypt calls: the slot wrap (1), chunk 0 (2), chunk 1 (3), chunk 2 (4).
  const sinkError = new Error("injected: the destination refused a write");
  for (const [label, failWrite, failSeal] of [
    ["a streamed write", 0, 0],
    ["a streamed write whose sink throws mid-stream", 3, 0],
    ["a streamed write whose chunk seal throws with the chunk in hand", 0, 3],
  ]) {
    let writes = 0;
    const sink = {
      write: async () => {
        writes++;
        if (writes === failWrite) throw sinkError;
      },
    };
    draws = [];
    encryptCalls = 0;
    failEncryptAt = failSeal;
    const run = await observe(() =>
      st.encryptKeym2ToSink(st.bytesSource(PLAIN), PASSWORD, U8.from(KEY_FILE), OPTS, sink, st.KEYM2_VERSION_V3)
    );
    failEncryptAt = 0;
    const drawn = draws.filter((d) => d.length === 32);
    draws = null;
    const expectError = failWrite ? sinkError.message : failSeal ? "injected: chunk seal refused" : null;
    ok(expectError ? run.error?.message === expectError : run.error === null && run.value?.bytes > 2 * C,
       expectError ? `${label}: the failure reaches the caller as itself` : `${label} completes`,
       run.error ? String(run.error.message) : "");
    ok(drawn.length === 2, `${label}: draws the salt and then the master key (the master-key check is not vacuous)`,
       `${drawn.length} 32-byte draws`);
    ok(run.seen.some((v) => v.length === C), `${label}: the census saw the chunk-sized plaintext reads (not vacuous)`);
    if (drawn.length === 2) {
      const leftMaster = holders(run.seen, drawn[1]);
      ok(leftMaster.length === 0, `${label}: no copy of the master key survives`, none(leftMaster));
    }
    ok(holders(run.seen, PASSWORD_BYTES).length === 0, `${label}: no copy of the password bytes (the KDF input) survives`,
       none(holders(run.seen, PASSWORD_BYTES)));
    ok(holders(run.seen, KEY_FILE_DIGEST).length === 0, `${label}: no copy of the key-file digest survives`,
       none(holders(run.seen, KEY_FILE_DIGEST)));
    const left = plaintextLeft(run.seen);
    ok(left.length === 0, `${label}: no plaintext buffer the writer read survives`, left.join("; "));
  }

  // -- the reader ---------------------------------------------------------------
  const chacha = { ...OPTS, cipher: st.CipherId.CHACHA20_POLY1305 };
  const container = await st.encryptKeym2WithExplicitSecrets(PLAIN, PASSWORD, null, chacha, SALT, U8.from(MASTER),
    st.KEYM2_VERSION_V3, CID);
  {
    const run = await observe(() => st.openKeym2Stream(st.bytesSource(container), PASSWORD, null));
    ok(run.error === null, "a streamed ChaCha container opens", String(run.error));
    if (run.error === null) {
      ok(holders(run.seen, MASTER).length > 0 && holders(run.seen, needles[0]).length > 0,
         "before discard the census sees the held payload key and chunk 0's plaintext (not vacuous)");
      run.value.discard();
      ok(holders(run.seen, MASTER).length === 0, "after discard no copy of the payload key survives",
         none(holders(run.seen, MASTER)));
      const left = plaintextLeft(run.seen);
      ok(left.length === 0, "after discard chunk 0's held plaintext does not survive", left.join("; "));
    }
  }
  {
    // Chunk 2 tampered: chunks 0 and 1 verify and reach the sink, chunk 2 does
    // not. The sink is a temporary destination and discards what it was
    // handed when drain rejects, as §5.5 requires of a caller.
    const tampered = U8.from(container);
    tampered[tampered.length - 3] ^= 0x01;
    let handed = 0;
    const run = await observe(async () => {
      const stream = await st.openKeym2Stream(st.bytesSource(tampered), PASSWORD, null);
      const temporary = [];
      try {
        await stream.drain({ write: async (bytes) => { handed++; temporary.push(bytes); } });
      } catch (e) {
        for (const b of temporary) b.fill(0);
        throw e;
      }
    });
    ok(run.error?.message === "Decryption failed.", "a drain that fails on chunk 2 rejects with the generic error",
       run.error ? String(run.error.message) : "no error");
    ok(handed === 2, "chunks 0 and 1 reached the sink before it failed (not vacuous)", `${handed} write(s)`);
    ok(holders(run.seen, MASTER).length === 0, "after a failed drain no copy of the payload key survives",
       none(holders(run.seen, MASTER)));
    const left = plaintextLeft(run.seen);
    ok(left.length === 0, "after a failed drain no plaintext copy of the core's survives", left.join("; "));
  }

  crypto.getRandomValues = nativeRandom;
  subtle.encrypt = nativeEncrypt;
}

// ---------------------------------------------------------------------------
// The key-file contract on a refusal. `encryptData`, `encryptContainer`,
// `encryptContainerWithSlots` and `encryptContainerWithSharesRequired` document
// that the caller's key-file buffer is zeroed once used, and so does
// `decryptData`. Each of them ran its input checks *before* the `try` whose
// `finally` does the erase, so an input the function refused (plaintext over
// the cap, a bad password string, a KDF below the floor, ...) threw with the
// key file still intact. `encryptContainerToSink` keeps its checks inside the
// `try` and is the model; this holds the others to it.
//
// Every refusal is driven for every function that makes it, and each is
// checked twice: the key file is all zeroes afterwards, and the error is the
// one the function has always raised (code and text, matched against literals
// here rather than against anything derived from the source), so a change
// that moves a check cannot quietly change what the user is told.
//
// Only refusals that happen with a key file in hand are reachable: a decrypt
// with no password, no shares and no PRF output is refused for want of a
// credential, but a key file *is* a credential, so that refusal cannot have
// one to leak.
// ---------------------------------------------------------------------------
{
  const refusal = await bundle(
    "refusal",
    `export { encryptData, encryptContainer, encryptContainerWithSharesRequired,
       encryptContainerWithSlots, decryptData, isUserFacingError,
       MAX_PLAINTEXT_SIZE, MAX_CONTAINER_SIZE } from "./keymaker-crypto";`
  );
  // The KEYM v2 module unreachable, as a chunk that failed to load is. A real
  // dynamic import of a file that does not exist, as in Finding 6.
  const missingKeym2 = {
    name: "missing-keym2-chunk",
    setup(build) {
      build.onResolve({ filter: /\/keym-v2$/ }, () => ({ path: "./keym-v2.never-arrives.mjs", external: true }));
    },
  };
  const noKeym2 = await bundle("refusal-no-keym2", `export { decryptData } from "./keymaker-crypto";`, [missingKeym2]);

  const zeroed = (u) => u.byteLength > 0 && u.every((b) => b === 0);
  const freshKey = () => U8.from({ length: 48 }, (_, i) => (i * 13 + 7) & 0xff || 1);
  const goodData = () => toAB(U8.from(Buffer.from("refusal plaintext")));
  const good = "correct horse battery staple";
  const KDF_FLOOR = /^KDF parameter out of range: PBKDF2 iterations is 1, expected \d+\.\.\d+\. Refusing to run a key derivation with unsafe cost parameters\.$/;

  const run = (name, { data, password, key, options }) => {
    const shamir = { threshold: 2, count: 3 };
    switch (name) {
      case "encryptData": return refusal.encryptData(data, password, key, options);
      case "encryptContainer": return refusal.encryptContainer(data, password, key, options);
      case "encryptContainerWithSlots": return refusal.encryptContainerWithSlots(data, password, key, options, { shamir });
      case "encryptContainerWithSharesRequired":
        return refusal.encryptContainerWithSharesRequired(data, password, key, options, 2, 3);
      default: throw new Error(`unknown function ${name}`);
    }
  };
  const caught = async (fn) => { try { await fn(); return null; } catch (e) { return e; } };
  const same = (e, want) =>
    e !== null &&
    (want.code === undefined ? e.code === undefined && !refusal.isUserFacingError(e) : e.code === want.code) &&
    (typeof want.message === "string" ? e.message === want.message : want.message.test(e.message));
  const show = (e) => (e ? `${e.code ?? "(untyped)"}: ${String(e.message).slice(0, 90)}` : "no error");

  const tooLarge = `File is too large. Maximum size is ${refusal.MAX_PLAINTEXT_SIZE / 1024 / 1024}MB.`;
  const optionsMissing = {
    encryptData: "encryptData requires explicit kdf and cipher options — algorithm selection is the caller's decision.",
    encryptContainer: "encryptContainer requires explicit kdf and cipher options — algorithm selection is the caller's decision.",
    encryptContainerWithSlots: "encryptContainerWithSlots requires explicit kdf and cipher options.",
    encryptContainerWithSharesRequired: "encryptContainerWithSharesRequired requires explicit kdf and cipher options.",
  };
  // `applies`: which functions make the refusal at all. The shares-required
  // writer has no cipher or Web Crypto check of its own.
  const encryptCases = [
    { why: "plaintext over the cap",
      args: () => ({ data: new ArrayBuffer(refusal.MAX_PLAINTEXT_SIZE + 1), password: good, options: OPTIONS }),
      want: () => ({ code: "too-large", message: tooLarge }) },
    { why: "empty plaintext",
      args: () => ({ data: new ArrayBuffer(0), password: good, options: OPTIONS }),
      want: () => ({ code: "empty-input", message: "Cannot process empty data." }) },
    { why: "a password with a NUL in it",
      args: () => ({ data: goodData(), password: "bad\0password", options: OPTIONS }),
      want: () => ({ code: "password-invalid", message: "Password contains invalid characters." }) },
    { why: "a password that is not a string",
      args: () => ({ data: goodData(), password: 12345, options: OPTIONS }),
      want: () => ({ code: "password-invalid", message: "Password must be a string." }) },
    { why: "an empty password",
      args: () => ({ data: goodData(), password: "", options: OPTIONS }),
      want: () => ({ code: "credential-required", message: "A password is required for encryption." }) },
    { why: "no kdf and cipher options",
      args: () => ({ data: goodData(), password: good, options: {} }),
      want: (name) => ({ code: undefined, message: optionsMissing[name] }) },
    { why: "a KDF cost below the floor",
      args: () => ({ data: goodData(), password: good, options: { ...OPTIONS, kdf: { kdf: m.KdfId.PBKDF2, params: { iterations: 1 } } } }),
      want: () => ({ code: "kdf-params-out-of-range", message: KDF_FLOOR }) },
    { why: "an unknown cipher id",
      applies: (name) => name !== "encryptContainerWithSharesRequired",
      args: () => ({ data: goodData(), password: good, options: { ...OPTIONS, cipher: 99 } }),
      want: () => ({ code: "unsupported-config", message: "Invalid cipher id: 99." }) },
    { why: "no Web Crypto",
      applies: (name) => name !== "encryptContainerWithSharesRequired",
      noSubtle: true,
      args: () => ({ data: goodData(), password: good, options: OPTIONS }),
      want: () => ({ code: "webcrypto-unavailable", message: "Web Crypto API not available." }) },
  ];

  // Web Crypto withdrawn for the span of one call, and put back on every exit.
  const withoutSubtle = async (fn) => {
    Object.defineProperty(globalThis.crypto, "subtle", { value: undefined, configurable: true });
    try { return await fn(); } finally { delete globalThis.crypto.subtle; }
  };

  for (const name of Object.keys(optionsMissing)) {
    for (const c of encryptCases) {
      if (c.applies && !c.applies(name)) continue;
      const key = freshKey();
      const call = () => run(name, { ...c.args(), key: key.buffer });
      const error = await caught(() => (c.noSubtle ? withoutSubtle(call) : call()));
      ok(same(error, c.want(name)), `${name}: ${c.why} is refused with the same error`, show(error));
      ok(zeroed(key), `${name}: the key file is zeroed when it refuses ${c.why}`);
    }
  }
  ok(crypto.subtle !== undefined, "tripwire: Web Crypto is back after the checks that withdrew it");

  // decryptData: the same two checks, for the refusals it can make with a key
  // file in hand.
  const legacyTooShort = () => toAB(U8.from({ length: 10 }, () => 0x41));
  const decryptCases = [
    { why: "a container over the cap",
      args: () => ({ data: new ArrayBuffer(refusal.MAX_CONTAINER_SIZE + 1), password: good }),
      want: { code: "too-large", message: /^This backup is larger than the 100 MB this app can open in a browser tab/ } },
    { why: "an empty container",
      args: () => ({ data: new ArrayBuffer(0), password: good }),
      want: { code: "empty-input", message: "Cannot process empty data." } },
    { why: "a password with a NUL in it",
      args: () => ({ data: legacyTooShort(), password: "bad\0password" }),
      want: { code: "password-invalid", message: "Password contains invalid characters." } },
    { why: "no Web Crypto",
      noSubtle: true,
      args: () => ({ data: legacyTooShort(), password: good }),
      want: { code: undefined, message: "Web Crypto API not available." } },
    { why: "a KEYM v2 reader that cannot be loaded",
      lib: noKeym2,
      args: () => ({ data: toAB(fixture("v3-pbkdf2-aes256gcm").bytes), password: meta.password }),
      want: { code: "dependency-unavailable", message: /the KEYM v2 reader and writer, could not be loaded/ } },
    { why: "a legacy blob too short to hold its header",
      args: () => ({ data: legacyTooShort(), password: good }),
      want: { code: undefined, message: "Invalid encrypted data format." } },
  ];
  for (const c of decryptCases) {
    const key = freshKey();
    const { data, password } = c.args();
    const decrypt = () => (c.lib ?? refusal).decryptData(data, password, key.buffer);
    const error = await caught(() => (c.noSubtle ? withoutSubtle(decrypt) : decrypt()));
    ok(same(error, c.want), `decryptData: ${c.why} is refused with the same error`, show(error));
    ok(zeroed(key), `decryptData: the key file is zeroed when it refuses ${c.why}`);
  }
  ok(crypto.subtle !== undefined, "tripwire: Web Crypto is back after the decrypt checks");
}

await settle();
console.log(failed === 0 ? "\nAll core secret-erase checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
