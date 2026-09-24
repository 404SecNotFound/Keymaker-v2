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

await settle();
console.log(failed === 0 ? "\nAll core secret-erase checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
