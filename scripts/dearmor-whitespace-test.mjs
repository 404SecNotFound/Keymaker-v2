#!/usr/bin/env node
/**
 * §7: the armor dearmor strips ASCII whitespace only, matching keym2.py.
 *
 * keym2.py trims the ends with `str.strip()` (Unicode-aware) and then removes
 * whitespace *inside* the body with `bytes.split()`, which is ASCII-only — so a
 * non-ASCII space (U+00A0, a stray BOM) in the middle of the base64 body is
 * kept and the strict base64 decode rejects it. The app's `dearmorKeym2` used
 * `\s`, which is Unicode-aware, so it silently stripped that character and
 * opened a container the durable Python decryptor refuses — stranding the heir
 * on the one recovery path that has no browser.
 *
 * This drives `dearmorKeym2` directly (esbuild bundles the TS the way the rest
 * of the project reaches its `.ts`). The control bites: with the internal strip
 * back on `\s`, the two rejection cases below open instead of throwing.
 */
import esbuild from "esbuild";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
const src = join(HERE, "..", "src", "lib", "keym-v2.ts");
const out = join(mkdtempSync(join(tmpdir(), "km2-")), "keym-v2.mjs");
await esbuild.build({ entryPoints: [src], bundle: true, format: "esm", platform: "node", outfile: out });

let failed = 0;
const ok = (cond, msg) => {
  if (!cond) { console.error("FAIL:", msg); failed++; }
  else console.log("ok   ", msg);
};
const rejects = (fn, msg) => {
  try { fn(); ok(false, msg + " (did not throw)"); }
  catch { ok(true, msg); }
};
const eq = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

const m = await import(pathToFileURL(out).href);
const secret = Uint8Array.from({ length: 200 }, (_, i) => (i * 37 + 5) & 0xff);
const clean = m.armorKeym2(secret); // "keym2:" + base64url wrapped at 64 cols with \n

// 1. The clean armor round-trips, including the ASCII line breaks armorKeym2 adds.
ok(eq(m.dearmorKeym2(clean), secret), "clean line-wrapped armor decodes to the original bytes");

// A splice point inside the base64 body (after the "keym2:" prefix and a few chars).
const at = "keym2:".length + 10;
const inject = (ch) => clean.slice(0, at) + ch + clean.slice(at);

// 2. A non-ASCII space inside the body is kept and rejected — matching keym2.py,
//    which is exactly the divergence this fixes.
rejects(() => m.dearmorKeym2(inject(" ")), "a U+00A0 inside the body is rejected (not silently stripped)");
rejects(() => m.dearmorKeym2(inject("﻿")), "a BOM inside the body is rejected");

// 3. ASCII whitespace inside the body is still stripped (so real line-wrapping,
//    tabs and CRLF keep working).
ok(eq(m.dearmorKeym2(inject(" \t\r\n")), secret), "ASCII whitespace inside the body is still stripped");

// 4. Leading/trailing whitespace — including non-ASCII — is trimmed at the ends,
//    matching keym2.py's str.strip(), so a stray wrapper does not break a paste.
ok(eq(m.dearmorKeym2(" \n  " + clean + "   \n"), secret),
   "leading/trailing whitespace (ASCII and non-ASCII) is trimmed at the ends");

console.log(failed === 0 ? "\nAll dearmor-whitespace checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
