#!/usr/bin/env node
/**
 * README claims that can be checked against the repository are checked.
 *
 * 1. Every `test:` script in package.json is mentioned in the README.
 *
 *    The "Run it locally" block once listed ten of sixteen. By the time this
 *    gate was re-landed it listed eleven of thirty-eight. Nothing in the listed
 *    ones was wrong; the rest had been added since anyone last read the section,
 *    which is how every documentation defect in this project has happened.
 *    RECOVERY.md claimed the app wrote v2 for as long as v3 had been the
 *    default, and the fix there was a gate rather than a proofread.
 *
 *    Deliberately one-directional. It does not require the README to mention
 *    *only* real scripts. Prose refers to commands in passing, and a check that
 *    policed that would be a check people route around.
 *
 * 2. The README's audit-scope disclaimer agrees with SECURITY-AUDIT.md, in both
 *    directions. See the section below.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
const readme = readFileSync(join(ROOT, "README.md"), "utf8");

const scripts = Object.keys(pkg.scripts).filter((k) => k.startsWith("test:"));
// A word boundary, so `test:secret-erase` is not satisfied by the line that
// documents `test:secret-erase-core`.
const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const missing = scripts.filter(
  (s) => !new RegExp(`npm run ${escape(s)}(?![\\w-])`).test(readme)
);

for (const s of scripts) {
  console.log(`  ${missing.includes(s) ? "FAIL" : "ok  "} README documents ${s}`);
}

// ---------------------------------------------------------------------------
// The audit-scope disclaimer stays true
// ---------------------------------------------------------------------------
//
// README tells the reader that SECURITY-AUDIT.md does not cover the format the
// app writes: v2 onward, the slot table, Shamir, passkey slots, v4 padding.
// That is true today. The document's scope line names the v1 container and the
// app shell, and it never discusses any of those subjects.
//
// It is the kind of claim that goes quietly false in the good case. The day an
// audit of the format is written up, the README would still be telling people
// it does not exist, under-claiming to the people deciding whether to trust the
// thing. So if SECURITY-AUDIT.md starts discussing the current format, this
// fails and asks for the README to be re-read.
//
// Bound in both directions. The first version only caught the audit widening,
// which meant the disclaimer could simply be deleted and nothing would
// complain, and a deleted disclaimer reads to a visitor as "audited". Its own
// negative control is what showed that.
//
// "KEYM v2" is not in the list on purpose. SECURITY-AUDIT.md names it, but only
// under "Remaining work", as the format that closed KM-05, not as something the
// review covered.
const audit = readFileSync(join(ROOT, "SECURITY-AUDIT.md"), "utf8");
const formatSubjects = ["KEYM v3", "KEYM v4", "slot_table_mac", "Shamir", "passkey"];
const nowCovered = formatSubjects.filter((t) => audit.includes(t));
const disclaims = readme.includes("not in that scope");

const shouldDisclaim = nowCovered.length === 0;
const scopeOk = shouldDisclaim === disclaims;

console.log(
  `  ${scopeOk ? "ok  " : "FAIL"} README's audit-scope disclaimer matches SECURITY-AUDIT.md`
);

let failed = false;
if (!scopeOk) {
  failed = true;
  console.error(
    shouldDisclaim
      ? `\nSECURITY-AUDIT.md still covers only the v1 core (it mentions none of ` +
          `${formatSubjects.join(", ")}), but README no longer says the format is ` +
          `"not in that scope".\nSilence there reads as "audited" to someone deciding ` +
          `whether to trust a seed phrase to this.`
      : `\nSECURITY-AUDIT.md now discusses ${nowCovered.join(", ")}, but README still ` +
          `says the format is "not in that scope".\nIf the audit was widened, say so. ` +
          `The disclaimer is now under-claiming to exactly the people it was written for.`
  );
}

if (missing.length) {
  failed = true;
  console.error(
    `\n${missing.length} of ${scripts.length} test scripts are missing from README.md: ` +
      `${missing.join(", ")}.\nAdd them to "Run it locally". A reader deciding whether ` +
      `to trust this project runs that list.`
  );
}

if (failed) process.exit(1);
console.log(`\nAll ${scripts.length} test scripts are documented, and the audit scope matches.`);
