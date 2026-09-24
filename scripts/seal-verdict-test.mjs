#!/usr/bin/env node
/**
 * The "sealed" verdict requires the whole egress-relevant directive set, not
 * connect-src alone.
 *
 * The sealed panel used to claim total egress prevention ("forbidden to talk to
 * any server, for every request to anywhere"); the last section pins the
 * narrower claim it makes now. `connect-src 'none'` earns only part
 * of that — fetch/XHR/WebSocket/EventSource/sendBeacon — while a `<form>` POST
 * is governed by `form-action`, which does not fall back to `default-src`. So a
 * build that kept `connect-src 'none'` but dropped `form-action 'none'` could
 * still exfiltrate, and the old verdict called it sealed anyway.
 *
 * This drives the pure verdict (esbuild bundles the React-free module). The
 * control bites: reverted to a connect-src-only check, the "form-action
 * dropped" and "default-src dropped" cases below flip back to sealed.
 */
import esbuild from "esbuild";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
const src = join(HERE, "..", "src", "lib", "seal-verdict.ts");
const out = join(mkdtempSync(join(tmpdir(), "seal-")), "seal-verdict.mjs");
await esbuild.build({ entryPoints: [src], bundle: true, format: "esm", platform: "node", outfile: out });

const { isSealed, pickDirective, SEALED_CLAIM } = await import(pathToFileURL(out).href);

let failed = 0;
const ok = (cond, msg) => {
  if (!cond) { console.error("FAIL:", msg); failed++; }
  else console.log("ok   ", msg);
};

// The production policy, verbatim from src/app/layout.tsx.
const PROD =
  "default-src 'none'; script-src 'self' 'wasm-unsafe-eval' 'unsafe-inline'; " +
  "style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; " +
  "connect-src 'none'; worker-src 'self'; manifest-src 'self'; object-src 'none'; " +
  "base-uri 'none'; form-action 'none'";

// Positive: the real export is sealed.
ok(isSealed(PROD) === true, "the production CSP is sealed");

// Each of the three egress directives is load-bearing: drop or weaken any one
// and the verdict must fail. The form-action and default-src cases are the ones
// a connect-src-only check would wrongly pass — the bite.
ok(isSealed(PROD.replace("; form-action 'none'", "")) === false,
   "dropping form-action is not sealed (a form POST could still leave)");
ok(isSealed(PROD.replace("default-src 'none'; ", "")) === false,
   "dropping default-src is not sealed");
ok(isSealed(PROD.replace("connect-src 'none'", "connect-src 'self'")) === false,
   "connect-src 'self' is not sealed");
ok(isSealed(PROD.replace("form-action 'none'", "form-action 'self'")) === false,
   "form-action 'self' is not sealed");

// No policy at all: not sealed, and never throws on empty/nullish input.
ok(isSealed("") === false, "an empty policy is not sealed");
ok(isSealed(null) === false, "a null policy is not sealed");
ok(isSealed(undefined) === false, "an undefined policy is not sealed");

// pickDirective reads the exact directive text, matches the name exactly, and
// collapses whitespace.
ok(pickDirective(PROD, "connect-src") === "connect-src 'none'", "pickDirective returns the exact directive");
ok(pickDirective(PROD, "form-action") === "form-action 'none'", "pickDirective finds form-action");
ok(pickDirective(PROD, "frame-src") === null, "pickDirective returns null for an absent directive");
ok(pickDirective("default-src  'none' ", "default-src") === "default-src 'none'", "pickDirective collapses whitespace");
// A longer name must not be picked up by a shorter query.
ok(pickDirective("connect-src-elem 'self'", "connect-src") === null, "pickDirective does not match a longer directive name");

// The words the panel shows for a sealed page. The three directives do not
// govern moving the tab to another address, WebRTC, requests for the site's own
// files, or workers, so a claim of "any server" or "every request" is false and
// one that stops naming those limits overclaims by omission.
{
  ok(SEALED_CLAIM !== undefined, "seal-verdict.ts exports SEALED_CLAIM");
  const claim = SEALED_CLAIM ? `${SEALED_CLAIM.title} ${SEALED_CLAIM.text}` : "";
  for (const total of [/any server/i, /every request/i, /anywhere/i]) {
    ok(!total.test(claim), `the sealed claim does not say "${total.source}"`);
  }
  for (const [limit, name] of [
    [/another address/i, "moving the tab to another address"],
    [/WebRTC/, "WebRTC"],
    [/own files/i, "requests for the site's own files"],
    [/workers/i, "workers"],
  ]) {
    ok(limit.test(claim), `the sealed claim names what it does not cover: ${name}`);
  }

  // And the panel shows these words rather than its own. A copy typed into the
  // component would pass every check above while the panel said something else.
  const panelSrc = readFileSync(join(HERE, "..", "src", "components", "sealed-status.tsx"), "utf8");
  ok(/SEALED_CLAIM\.title/.test(panelSrc) && /SEALED_CLAIM\.text/.test(panelSrc),
     "sealed-status.tsx renders SEALED_CLAIM");
  for (const total of [/any server/i, /every request/i, /forbids every/i]) {
    ok(!total.test(panelSrc), `sealed-status.tsx does not say "${total.source}"`);
  }
}

console.log(failed === 0 ? "\nAll seal-verdict checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
