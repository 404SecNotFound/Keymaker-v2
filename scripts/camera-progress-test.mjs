#!/usr/bin/env node
/**
 * The camera scanner's stopping rule (src/lib/camera-progress.ts), without a
 * camera: when is enough read, and what is said while it is not.
 *
 * Real strips and parts, from real share sets and a real container, so the
 * headers it reads are the ones the paper carries. The cases that matter most
 * are the ones that must not stop the camera: a strip held up twice, a strip
 * from a different backup's set, and a set of container symbols one short.
 *
 * Controls, each shown to fail this suite: counting a repeated strip twice;
 * counting a strip from another set; treating strips alone as complete when
 * container symbols have been started.
 */
import esbuild from "esbuild";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
const LIB = join(HERE, "..", "src", "lib");
const dir = mkdtempSync(join(tmpdir(), "km-camera-progress-"));
const entry = join(dir, "entry.ts");
writeFileSync(
  entry,
  [
    `export * from ${JSON.stringify(join(LIB, "camera-progress.ts"))};`,
    `export { encryptKeym2, addShamirSlotKeym2, armorKeym2 } from ${JSON.stringify(join(LIB, "keym-v2.ts"))};`,
    `export { encodePaperPartsV2, encodePaperParts } from ${JSON.stringify(join(LIB, "keym-v2-paper.ts"))};`,
    `export { encodeShare, shareSetId } from ${JSON.stringify(join(LIB, "keym-v2-shamir.ts"))};`,
    `export { KdfId, CipherId } from ${JSON.stringify(join(LIB, "keymaker-crypto.ts"))};`,
  ].join("\n")
);
const out = join(dir, "bundle.mjs");
await esbuild.build({ entryPoints: [entry], bundle: true, format: "esm", platform: "node", outfile: out, logLevel: "error" });
const m = await import(out);

let failed = 0;
const ok = (cond, msg, detail = "") => {
  if (!cond) {
    console.error("FAIL:", msg, detail);
    failed++;
  } else console.log("ok   ", msg);
};

const PASSWORD = "camera progress password 5521";
const opts = { kdf: { kdf: m.KdfId.PBKDF2, params: { iterations: 600_000 } }, cipher: m.CipherId.AES_256_GCM };
const base = await m.encryptKeym2(new TextEncoder().encode("x".repeat(3000)), PASSWORD, null, opts);
const A = await m.addShamirSlotKeym2(base, { password: PASSWORD }, 2, 3);
const B = await m.addShamirSlotKeym2(base, { password: PASSWORD }, 3, 5);
const parts = await m.encodePaperPartsV2(A.container, 800);
ok(parts.length >= 3, `the container prints as ${parts.length} parts`);
const p = (codes) => m.cameraProgress(codes);
const say = (codes) => m.describeCameraProgress(p(codes)).join(" ");

ok(!p([]).complete, "nothing read is not complete");
ok(/Hold a recovery strip/.test(say([])), "and says what to do");

ok(!p([A.shares[0]]).complete, "one strip of a 2-of-3 set is not enough");
ok(/1 of the 2 needed\. Show the next strip\./.test(say([A.shares[0]])), "and asks for the next strip", say([A.shares[0]]));
ok(p([A.shares[0], A.shares[2]]).complete, "two strips of a 2-of-3 set are enough");
ok(/That is 2, which is enough/.test(say([A.shares[0], A.shares[2]])), "and says so");

// The same strip, read again with different spacing and case: one strip.
const again = A.shares[0].toLowerCase().replace(/-/g, " ");
ok(!p([A.shares[0], again]).complete, "the same strip held up twice counts once");

// A strip from a different set does not make up the number.
ok(!p([A.shares[0], B.shares[1]]).complete, "a strip from another set is not counted");
ok(/from a different set/.test(say([A.shares[0], B.shares[1]])), "and is named", say([A.shares[0], B.shares[1]]));

// B needs three.
ok(!p(B.shares.slice(0, 2)).complete && p(B.shares.slice(0, 3)).complete, "a 3-of-5 set needs three");

// Container symbols: every one, and strips too once both have been started.
ok(!p(parts.slice(1)).complete, "one symbol short is not complete");
ok(/Still needed: 1\./.test(say(parts.slice(1))), "and names the missing symbol", say(parts.slice(1)));
ok(p(parts).complete, "every symbol is complete");
ok(!p([...parts.slice(1), A.shares[0], A.shares[1]]).complete, "enough strips do not make up for a missing symbol");
ok(!p([...parts, A.shares[0]]).complete, "every symbol does not make up for a missing strip");
ok(p([...parts, A.shares[0], A.shares[1]]).complete, "every symbol and enough strips are complete");

// KMPART1 parts carry i/n too.
const v1 = m.encodePaperParts(A.container, 800);
ok(!p(v1.slice(1)).complete && p(v1).complete, "KMPART1 parts are counted the same way");

// A whole backup in one code needs nothing else, and a KMSHARE1 strip counts.
ok(p([m.armorKeym2(A.container)]).complete, "a whole backup in one code is complete on its own");
const salt = new Uint8Array(32).fill(7);
const id1 = await m.shareSetId(salt);
const k1 = await Promise.all([1, 2].map((index) => m.encodeShare({ setId: id1, threshold: 2, index, value: new Uint8Array(32).fill(index) })));
ok(!p([k1[0]]).complete && p(k1).complete, "KMSHARE1 strips are counted by their own threshold");

ok(!p(["https://example.com/"]).complete, "a stranger's QR is not progress");

console.log(failed ? `\n${failed} failed` : "\nAll camera-progress checks passed.");
process.exit(failed ? 1 : 0);
