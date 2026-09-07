#!/usr/bin/env node
/**
 * §4.7 passkey enrolment binds its second tap to the credential it just made.
 *
 * The browser suite (tests/browser/passkey.spec.ts) drives a CDP virtual
 * authenticator that always consents and holds one credential, so it proves the
 * happy-path wiring but cannot exercise the case this guards: a device holding
 * *more than one* Keymaker passkey, where an empty `allowCredentials` on
 * enrolment's assertion lets the second tap be answered by the wrong one. The
 * backup would then be keyed to a credential the user did not just create, and
 * deleting that older credential would silently remove access.
 *
 * So this drives `webauthn-prf.ts` directly with a mocked `navigator.credentials`
 * — the review's "mocked boundary" — where create() and get() can disagree
 * about which credential answered. The controls bite: without the binding, the
 * mismatch check below would accept a different credential's output. esbuild
 * bundles the TS the same way the rest of the project reaches its `.ts`.
 */
import esbuild from "esbuild";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
const src = join(HERE, "..", "src", "lib", "webauthn-prf.ts");
const out = join(mkdtempSync(join(tmpdir(), "prf-")), "webauthn-prf.mjs");
await esbuild.build({ entryPoints: [src], bundle: true, format: "esm", platform: "node", outfile: out });

let failed = 0;
const ok = (cond, msg) => {
  if (!cond) { console.error("FAIL:", msg); failed++; }
  else console.log("ok   ", msg);
};
const rejects = async (fn, needle, msg) => {
  try { await fn(); ok(false, msg + " (did not throw)"); }
  catch (e) { ok(String(e.message).includes(needle), `${msg} (${String(e.message).slice(0, 60)})`); }
};

const idBuf = (n) => Uint8Array.from({ length: 16 }, (_, i) => (n * 31 + i) & 0xff).buffer;
const prf32 = () => Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 1) & 0xff).buffer;
const bytesOf = (x) => (x instanceof ArrayBuffer ? new Uint8Array(x) : new Uint8Array(x.buffer ?? x));
const eq = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

// A fake authenticator whose create() and get() can return different ids.
let state;
function installNavigator() {
  const nav = {
    credentials: {
      async create({ publicKey }) {
        state.created = idBuf(state.createId);
        return {
          rawId: state.created,
          getClientExtensionResults: () => ({ prf: { enabled: true } }),
        };
      },
      async get({ publicKey }) {
        state.getAllow = publicKey.allowCredentials;
        return {
          rawId: idBuf(state.assertId),
          getClientExtensionResults: () => ({ prf: { results: { first: prf32() } } }),
        };
      },
    },
  };
  Object.defineProperty(globalThis, "navigator", { value: nav, configurable: true, writable: true });
}
installNavigator();

const m = await import(pathToFileURL(out).href);
const salt = new Uint8Array(32).fill(9);

// 1. Enrolment restricts the second tap to the credential it just created.
state = { createId: 1, assertId: 1 };
const outBytes = await m.enrolPasskey(salt);
ok(outBytes instanceof Uint8Array && outBytes.length === 32, "enrolment returns the 32-byte PRF output");
ok(
  Array.isArray(state.getAllow) && state.getAllow.length === 1 &&
    eq(bytesOf(state.getAllow[0].id), bytesOf(idBuf(1))),
  "enrolment's assertion is restricted to the created credential's id"
);

// 2. The control: when the authenticator answers with a *different* credential,
// enrolment refuses rather than keying the backup to the wrong passkey.
state = { createId: 1, assertId: 2 };
await rejects(() => m.enrolPasskey(salt), "different passkey", "a mismatched assertion is refused");

// 3. Recovery keeps its picker: no binding means an empty allowCredentials.
state = { createId: 1, assertId: 1 };
await m.assertPasskeyPrf(salt);
ok(Array.isArray(state.getAllow) && state.getAllow.length === 0,
   "ordinary recovery still passes an empty allowCredentials (the picker)");

// 4. assertPasskeyPrf bound to an id verifies it, and refuses a mismatch.
state = { createId: 1, assertId: 2 };
await rejects(() => m.assertPasskeyPrf(salt, "test", bytesOf(idBuf(1))),
              "different passkey", "a bound assertion refuses a different credential");
state = { createId: 1, assertId: 1 };
const bound = await m.assertPasskeyPrf(salt, "test", bytesOf(idBuf(1)));
ok(bound instanceof Uint8Array && bound.length === 32, "a bound assertion accepts the matching credential");

console.log(failed === 0 ? "\nAll passkey-binding checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
