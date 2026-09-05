#!/usr/bin/env node
/**
 * The advisory password floor, tested directly.
 *
 * `src/lib/password-policy.ts` is UI-only, but "UI-only" is not "untested": the
 * whole point of KM-02c was that the *previous* rule passed predictable
 * passwords and failed strong lowercase ones. This asserts the new rule does the
 * opposite, with both halves present so the suite fails whether the function
 * collapses to always-true (the reject cases fail) or always-false (the accept
 * cases fail). Node cannot run the TS directly, so it is esbuild-bundled first,
 * the same way the rest of the project reaches its `.ts`.
 */
import esbuild from "esbuild";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
const src = join(HERE, "..", "src", "lib", "password-policy.ts");
const out = join(mkdtempSync(join(tmpdir(), "pwpol-")), "password-policy.mjs");
await esbuild.build({ entryPoints: [src], bundle: true, format: "esm", platform: "node", outfile: out });
const { meetsPasswordPolicy, MIN_TYPED_LENGTH } = await import(pathToFileURL(out).href);

let failed = 0;
const ok = (cond, msg) => {
  if (!cond) {
    console.error("FAIL:", msg);
    failed++;
  } else {
    console.log("ok   ", msg);
  }
};

// A generated secret is trusted on provenance, whatever it looks like.
ok(meetsPasswordPolicy("short", true), "a generated secret short-circuits to accepted");

// Accepts: the case the old composition rule wrongly refused.
ok(meetsPasswordPolicy("togetherweraisethelanternhigh"), "accepts a strong lowercase-only secret (no character-mix rule)");
ok(meetsPasswordPolicy("river maple copper lantern"), "accepts a plain multi-word phrase of sufficient length");
ok(meetsPasswordPolicy("x".repeat(MIN_TYPED_LENGTH - 1) + "yzab"), "accepts exactly at the length floor with enough variety");

// Rejects: short, low-variety, and known-weak.
ok(!meetsPasswordPolicy(""), "rejects an empty secret");
ok(!meetsPasswordPolicy("short-one"), "rejects a secret below the length floor");
ok(!meetsPasswordPolicy("a".repeat(20)), "rejects low-variety padding however long");
ok(!meetsPasswordPolicy("Passw0rd!"), "rejects a short composed password the old rule shape allowed");

// Rejects: the blocklist, and its capitalised / spaced / suffixed variants.
ok(!meetsPasswordPolicy("correct horse battery staple"), "rejects the famous passphrase");
ok(!meetsPasswordPolicy("Correct-Horse-Battery-Staple1!"), "rejects a capitalised, hyphenated, suffixed variant of it");
ok(!meetsPasswordPolicy("correcthorsebatterystaple"), "rejects the run-together form of it");
ok(!meetsPasswordPolicy("Encrypt Everything Trust Nothing"), "rejects Keymaker's own hero line");

console.log(failed === 0 ? "\nAll password-policy checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
