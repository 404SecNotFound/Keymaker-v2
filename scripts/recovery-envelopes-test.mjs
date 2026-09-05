#!/usr/bin/env node
/**
 * §7.3 KMPART2, tested on the TypeScript side directly.
 *
 * The conformance suite already proves the TypeScript and the Python reference
 * emit byte-identical v2 envelopes and reassemble each other's. What that gate
 * does not exercise is the *diagnosis* KMPART2 exists for: a corrupt part named
 * by index, a truncated tail caught by length or fingerprint, a mixed set
 * refused. Those are the whole reason the version exists, so they get a test
 * whose controls bite, and it fails whether the decoder accepts damage it should
 * refuse or refuses a set it should accept. Node cannot run the TS directly, so
 * it is esbuild-bundled first, the same way the rest of the project reaches its
 * `.ts`. The paper module needs only `crypto.subtle` and base64, no heavy deps.
 */
import esbuild from "esbuild";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
const src = join(HERE, "..", "src", "lib", "keym-v2-paper.ts");
const out = join(mkdtempSync(join(tmpdir(), "envv2-")), "keym-v2-paper.mjs");
await esbuild.build({ entryPoints: [src], bundle: true, format: "esm", platform: "node", outfile: out });
const m = await import(pathToFileURL(out).href);

let failed = 0;
const ok = (cond, msg) => {
  if (!cond) { console.error("FAIL:", msg); failed++; }
  else console.log("ok   ", msg);
};
const rejects = async (fn, needle, msg) => {
  try { await fn(); ok(false, msg + " (did not throw)"); }
  catch (e) { ok(String(e.message).includes(needle), `${msg} (${String(e.message).slice(0, 50)})`); }
};

// A real-ish container: any bytes, split small so there are several parts.
const container = Uint8Array.from({ length: 500 }, (_, i) => (i * 7 + 3) & 0xff);
const parts = await m.encodePaperPartsV2(container, 120);
ok(parts.length > 1, "a container spans several v2 parts");
ok(parts.every((p) => p.startsWith("KMPART2:")), "every part is a KMPART2");

// Round-trip, and out of order, and via the version dispatcher.
const back = await m.decodePaperPartsV2(parts);
ok(back.length === container.length && back.every((b, i) => b === container[i]), "v2 parts round-trip");
ok((await m.decodePaperPartsV2([...parts].reverse())).length === container.length, "v2 parts reassemble out of order");
ok((await m.decodePaperPartsAny(parts)).length === container.length, "decodePaperPartsAny reads a v2 set");

// A corrupt part is named by index, not blamed on the whole set.
const corrupt = [...parts];
const f = corrupt[1].split(":");
f[4] = (f[4][0] === "A" ? "B" : "A") + f[4].slice(1);
corrupt[1] = f.join(":");
await rejects(() => m.decodePaperPartsV2(corrupt), "Part 2", "a corrupt part is named by its index");

// A truncated tail whose per-part checksum was recomputed still cannot pass:
// the length and the whole-container fingerprint are the guarantees.
const enc = (b) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const dec = (t) => Uint8Array.from(atob(t.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (t.length % 4)) % 4)), (c) => c.charCodeAt(0));
async function sha(...parts) {
  let n = 0; for (const p of parts) n += p.length;
  const buf = new Uint8Array(n); let at = 0; for (const p of parts) { buf.set(p, at); at += p.length; }
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
}
const CTX = new TextEncoder().encode("keymaker.v2.part-checksum");
const tail = parts[parts.length - 1].split(":");
const shortSlice = dec(tail[4]).slice(0, -1);
tail[4] = enc(shortSlice);
tail[5] = enc((await sha(CTX, shortSlice)).slice(0, 4));
const forged = [...parts.slice(0, -1), tail.join(":")];
await rejects(() => m.decodePaperPartsV2(forged), "", "a truncated tail is caught by length or fingerprint");

// Two backups do not silently merge: the fingerprints differ.
const other = await m.encodePaperPartsV2(Uint8Array.from({ length: 300 }, () => 9), 120);
await rejects(() => m.decodePaperPartsV2([parts[0], other[1]]), "different backups", "parts from different backups are refused");

// A wrong-shaped line is refused, not silently skipped.
await rejects(() => m.decodePaperPartsV2(["KMPART2:not-a-real-part"]), "Not a v2 paper part", "a wrong-shaped line is refused");

// looksLikePaperPart / describePaperPart read v2, as the wrong-box report needs.
ok(m.looksLikePaperPart(parts[0]), "looksLikePaperPart recognises a v2 part");
const d = m.describePaperPart(parts[2]);
ok(d && d.index === 3 && d.total === parts.length, "describePaperPart reads a v2 part's i of n");

console.log(failed === 0 ? "\nAll recovery-envelope checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
