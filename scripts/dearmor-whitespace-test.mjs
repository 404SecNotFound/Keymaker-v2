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

// 6. The self-extracting page's own dearmor, the third reader, agrees. It once
//    matched keym2.py's old behaviour (trim at the ends, ASCII whitespace
//    inside); both of the other readers then moved to §7's set, and a no-break
//    space or a BOM that a mail client dropped into the page's text opened in
//    the app and in keym2.py and was refused by the page alone. The function
//    is lifted out of the page the app really writes, not re-typed here.
{
  const seSrc = join(HERE, "..", "src", "lib", "keym-v2-selfextract.ts");
  const seOut = join(mkdtempSync(join(tmpdir(), "km2se-")), "keym-v2-selfextract.mjs");
  await esbuild.build({ entryPoints: [seSrc], bundle: true, format: "esm", platform: "node", outfile: seOut });
  const se = await import(pathToFileURL(seOut).href);
  // The page accepts only the WebCrypto subset: PBKDF2 and AES-256-GCM.
  const subset = await m.encryptKeym2(secret, "page dearmor password", null, {
    kdf: { kdf: 0, params: { iterations: 600_000 } },
    cipher: 0,
  });
  const html = se.buildSelfExtractingPage({ container: subset, createdOn: "today", appVersion: "test" });
  const script = html.match(/<script>([\s\S]*?)<\/script>/)?.[1] ?? "";
  const lifted = script.match(/var IGNORABLE = [^\n]+\n[\s\S]*?function dearmor\(text\) \{[\s\S]*?\n\}/)?.[0];
  ok(typeof lifted === "string" && lifted.length > 0, "the page's dearmor could be lifted out of the page");
  const pageDearmor = new Function(`${lifted}\nreturn dearmor;`)();
  const pageArmor = m.armorKeym2(subset);
  const pageInject = (ch) => pageArmor.slice(0, 20) + ch + pageArmor.slice(20);
  const pageDecodes = (text) => {
    try { return pageDearmor(text); } catch { return new Uint8Array(0); }
  };
  ok(eq(pageDecodes(pageArmor), subset), "the page opens its own armor");
  ok(eq(pageDecodes(pageInject(" ")), subset), "the page ignores a U+00A0 inside the body, as the app does");
  ok(eq(pageDecodes(pageInject("﻿")), subset), "the page ignores a BOM inside the body, as the app does");
  ok(eq(pageDecodes(pageInject(" ")), subset), "the page ignores a U+2028 inside the body, as the app does");
  ok(eq(pageDecodes("﻿" + pageArmor + "\u0085"), subset), "the page removes a BOM and U+0085 at the ends, as the app does");
  rejects(() => pageDearmor(pageInject("​")), "the page still rejects a zero-width space, as the app does");
}

console.log(failed === 0 ? "\nAll dearmor-whitespace checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
