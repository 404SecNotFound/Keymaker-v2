#!/usr/bin/env node
/**
 * §7, "Characters a reader ignores": dearmor ignores exactly the IGNORABLE set
 * (Unicode White_Space plus U+FEFF), at the ends and inside the body, and
 * rejects everything else, the same set keym2.py uses.
 *
 * The history is why this is a named set. The app first stripped with `\s`,
 * which is Unicode-aware, while keym2.py stripped the body with bytes.split(),
 * which is ASCII-only, so the app opened backups the Python decryptor refused.
 * The first fix made the app ASCII-only inside the body to match, which only
 * moved the disagreement: the ends still used JavaScript's trim() against
 * Python's strip(), which differ on U+FEFF (a Windows editor's byte order mark),
 * U+0085 and U+001C..U+001F. Both implementations now name the set, and
 * crosstest2.py holds them to the same verdicts.
 *
 * This drives `dearmorKeym2` directly (esbuild bundles the TS the way the rest
 * of the project reaches its `.ts`). Controls: going back to `trim()` fails the
 * U+0085 ends case; going back to an ASCII-only body strip fails the U+00A0 and
 * BOM body cases.
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
// Guarded, so a regression is reported as the check it breaks rather than as a
// crash that hides which one (CLAUDE.md, "an unguarded call").
const decodes = (text) => {
  try { return m.dearmorKeym2(text); } catch { return new Uint8Array(0); }
};

const m = await import(pathToFileURL(out).href);
const secret = Uint8Array.from({ length: 200 }, (_, i) => (i * 37 + 5) & 0xff);
const clean = m.armorKeym2(secret); // "keym2:" + base64url wrapped at 64 cols with \n

// 1. The clean armor round-trips, including the ASCII line breaks armorKeym2 adds.
ok(eq(decodes(clean), secret), "clean line-wrapped armor decodes to the original bytes");

// A splice point inside the base64 body (after the "keym2:" prefix and a few chars).
const at = "keym2:".length + 10;
const inject = (ch) => clean.slice(0, at) + ch + clean.slice(at);

// 2. IGNORABLE characters inside the body are ignored: a no-break space or a
//    byte order mark that a notes app put there is not base64 and cannot
//    change what the body decodes to.
ok(eq(decodes(inject("\u00a0")), secret), "a U+00A0 inside the body is ignored");
ok(eq(decodes(inject("\ufeff")), secret), "a BOM inside the body is ignored");
// 3. ASCII whitespace inside the body is still stripped (so real line-wrapping,
//    tabs and CRLF keep working).
ok(eq(decodes(inject(" \t\r\n")), secret), "ASCII whitespace inside the body is still stripped");
// 4. Leading and trailing IGNORABLE characters are removed, including the byte
//    order mark a Windows editor writes at the start of a UTF-8 file.
ok(eq(decodes("\ufeff \n\u0085  " + clean + "  \u00a0\n"), secret),
   "a leading BOM and U+0085/U+00A0 at the ends are removed");
// 5. Characters outside the set are rejected, wherever they are: a zero-width
//    space is not White_Space, and U+001C..U+001F are control characters.
rejects(() => m.dearmorKeym2(inject("\u200b")), "a zero-width space inside the body is rejected");
rejects(() => m.dearmorKeym2(clean + "\u001f"), "a trailing U+001F is rejected");
rejects(() => m.dearmorKeym2("\u001c" + clean), "a leading U+001C is rejected");

console.log(failed === 0 ? "\nAll dearmor-whitespace checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
