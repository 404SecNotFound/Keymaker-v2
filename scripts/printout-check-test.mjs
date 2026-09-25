#!/usr/bin/env node
/**
 * "Check this printout" (src/lib/printout-check.ts): each printed code reads
 * back, and is from this backup or is said not to be.
 *
 * Two real containers, A and B, each with its own share set, written by the
 * shipping encryptor. Every code A's paper would carry is checked against A
 * (belongs), against B (does not), against A's header alone (strips yes, parts
 * unknown, since a part needs the whole container), and against nothing
 * (unknown). Then the codes that must not pass: a damaged strip, a damaged
 * part, and a strip whose set id matches A's only in its first four bytes,
 * which only a full sixteen-byte comparison refuses (§6).
 *
 * Controls, each shown to fail this suite: comparing four bytes of a KMSHARE2
 * set id; skipping the part checksum; treating a header as a whole container.
 */
import esbuild from "esbuild";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
const LIB = join(HERE, "..", "src", "lib");
const dir = mkdtempSync(join(tmpdir(), "km-printout-"));
const entry = join(dir, "entry.ts");
writeFileSync(
  entry,
  [
    `export * from ${JSON.stringify(join(LIB, "printout-check.ts"))};`,
    `export { encryptKeym2, addShamirSlotKeym2, armorKeym2, KEYM2_HEADER_PEEK_BYTES } from ${JSON.stringify(join(LIB, "keym-v2.ts"))};`,
    `export { encodePaperParts, encodePaperPartsV2 } from ${JSON.stringify(join(LIB, "keym-v2-paper.ts"))};`,
    `export { decodeShareV2, encodeShareV2 } from ${JSON.stringify(join(LIB, "keym-v2-shamir.ts"))};`,
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

const PASSWORD = "printout check password 7731";
const opts = { kdf: { kdf: m.KdfId.PBKDF2, params: { iterations: 600_000 } }, cipher: m.CipherId.AES_256_GCM };
async function backupWithShares(tag) {
  const base = await m.encryptKeym2(new TextEncoder().encode(`backup ${tag} `.repeat(200)), PASSWORD, null, opts);
  return m.addShamirSlotKeym2(base, { password: PASSWORD }, 2, 3);
}
const A = await backupWithShares("A");
const B = await backupWithShares("B");
const plain = await m.encryptKeym2(new TextEncoder().encode("no shares here"), PASSWORD, null, opts);

// Small parts so a backup spans several symbols, as a printed one does.
const partsA = await m.encodePaperPartsV2(A.container, 400);
const partsB = await m.encodePaperPartsV2(B.container, 400);
ok(partsA.length > 1, `A prints as several parts (${partsA.length})`);

const full = (c) => ({ container: c, header: c.subarray(0, m.KEYM2_HEADER_PEEK_BYTES) });
const headerOnly = (c) => ({ container: null, header: c.subarray(0, m.KEYM2_HEADER_PEEK_BYTES) });
const nothing = { container: null, header: null };
const check = (text, backup) => m.checkPrintoutCode(text, backup);

// --- strips ---------------------------------------------------------------
for (const [i, strip] of A.shares.entries()) {
  const f = await check(strip, full(A.container));
  ok(f.kind === "strip" && f.belongs === "yes" && f.index === i + 1 && f.threshold === 2,
    `A's strip ${i + 1} belongs to A`, JSON.stringify(f));
}
ok((await check(A.shares[0], full(B.container))).belongs === "no", "A's strip does not belong to B");
ok((await check(A.shares[0], headerOnly(A.container))).belongs === "yes",
  "a strip is matched against the header alone, as for a file written straight to disk");
ok((await check(A.shares[0], nothing)).belongs === "unknown", "with no backup, a strip reads but is not matched");
ok((await check(A.shares[0], full(plain))).belongs === "no", "a backup with no share slot owns no strip");
ok((await check(A.shares[0].toLowerCase().replace(/-/g, " "), full(A.container))).belongs === "yes",
  "a strip copied by hand, lower case with spaces, still matches");
{
  const f = await check(A.shares[0], full(A.container));
  ok(f.setCode !== null && A.shares[0].startsWith(`KMSHARE2:${f.setCode}-`), "the finding carries the strip's set code");
}

// A set id that agrees with A's in its first four bytes only. The strip's own
// checksum is valid, so only the full comparison can refuse it.
{
  const s = await m.decodeShareV2(A.shares[0]);
  const near = s.setId.slice();
  for (let i = 4; i < near.length; i++) near[i] ^= 0xff;
  const nearText = await m.encodeShareV2({ ...s, setId: near });
  ok((await check(nearText, full(A.container))).belongs === "no",
    "a strip whose set id matches only its first four bytes is not A's");
}

// A strip with one character changed fails its checksum.
{
  const body = A.shares[1];
  const at = body.length - 3;
  const damaged = body.slice(0, at) + (body[at] === "0" ? "1" : "0") + body.slice(at + 1);
  ok((await check(damaged, full(A.container))).kind === "strip-damaged", "a damaged strip is named as damaged");
}

// --- container symbols ------------------------------------------------------
for (const part of partsA) {
  const f = await check(part, full(A.container));
  ok(f.kind === "part" && f.belongs === "yes", `A's ${f.index}/${f.total} belongs to A`, JSON.stringify(f));
}
ok((await check(partsB[0], full(A.container))).belongs === "no", "B's symbol does not belong to A");
ok((await check(partsA[0], headerOnly(A.container))).belongs === "unknown",
  "a symbol is not matched against a header: its fingerprint covers the whole container");
{
  // A slice character changed, the checksum left alone: still well-formed.
  const fields = partsA[1].split(":");
  const slice = fields[4];
  fields[4] = (slice[0] === "A" ? "B" : "A") + slice.slice(1);
  const f = await check(fields.join(":"), full(A.container));
  ok(f.kind === "part-damaged" && f.index === 2, "a symbol that did not read back intact is named", JSON.stringify(f));
}
{
  const v1 = m.encodePaperParts(A.container, 400);
  const f = await check(v1[0], full(A.container));
  ok(f.kind === "part-v1", "a KMPART1 part reads, and is said to carry no fingerprint", JSON.stringify(f));
}

// --- the whole backup in one code, and anything else --------------------------
ok((await check(m.armorKeym2(A.container), full(A.container))).belongs === "yes", "A's armor is A");
ok((await check(m.armorKeym2(B.container), full(A.container))).belongs === "no", "B's armor is not A");
ok((await check("https://example.com/", full(A.container))).kind === "other", "a stranger's QR is not a Keymaker code");

// --- what is said -------------------------------------------------------------
{
  const yes = m.describePrintoutFinding(await check(A.shares[0], full(A.container)));
  const no = m.describePrintoutFinding(await check(partsB[0], full(A.container)));
  ok(/belongs to this backup/.test(yes) && !m.printoutFindingIsProblem(await check(A.shares[0], full(A.container))),
    "a match is said plainly, and is not a problem", yes);
  ok(/different backup/.test(no) && m.printoutFindingIsProblem(await check(partsB[0], full(A.container))),
    "a mismatch is said plainly, and is a problem", no);
}

console.log(failed ? `\n${failed} failed` : "\nAll printout checks passed.");
process.exit(failed ? 1 : 0);
