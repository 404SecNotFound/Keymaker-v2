#!/usr/bin/env node
/**
 * Every `test:` script in package.json is mentioned in the README.
 *
 * The README's "Run it locally" block listed ten of sixteen. Nothing was wrong
 * with the ten; the other six had simply been added since somebody last read
 * the section, which is how every documentation defect in this project has
 * happened — RECOVERY.md claimed the app wrote v2 for as long as v3 had been
 * the default, and the fix there was a gate rather than a proofread.
 *
 * A list of commands nobody re-checks is a list that quietly stops being true,
 * and the reader who suffers for it is the one running the commands to decide
 * whether to trust the thing.
 *
 * Deliberately one-directional: it does not require the README to mention *only*
 * real scripts. Prose naturally refers to commands in passing, and a check that
 * policed that would be a check people route around.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
const readme = readFileSync(join(ROOT, "README.md"), "utf8");

const scripts = Object.keys(pkg.scripts).filter((k) => k.startsWith("test:"));
const missing = scripts.filter((s) => !readme.includes(`npm run ${s}`));

for (const s of scripts) {
  console.log(`  ${missing.includes(s) ? "FAIL" : "ok  "} README documents ${s}`);
}

// ---------------------------------------------------------------------------
// The audit-scope disclaimer stays true
// ---------------------------------------------------------------------------
//
// README tells the reader that SECURITY-AUDIT.md does not cover the format the
// app writes — v2, v3, the slot table, Shamir, passkey. That is true today: the
// document's scope line names the v1 container and the app shell, and it
// mentions none of those subjects.
//
// It is exactly the kind of claim that goes quietly false in the good case. The
// day someone commissions an audit of the format and writes it up, the README
// will still be telling people it does not exist — under-claiming to the people
// deciding whether to trust the thing, which is the same failure as
// over-claiming, pointed the other way.
//
// So: if SECURITY-AUDIT.md starts discussing the current format, this fails and
// asks for the README to be re-read.
const audit = readFileSync(join(ROOT, "SECURITY-AUDIT.md"), "utf8");
const formatSubjects = ["KEYM v3", "slot_table_mac", "Shamir", "passkey"];
const nowCovered = formatSubjects.filter((t) => audit.includes(t));
const disclaims = readme.includes("not in that scope");

// Bound in both directions. The first version only caught the audit widening,
// which meant the disclaimer could simply be deleted and nothing would complain
// — and a deleted disclaimer reads to a visitor as "audited". Its own negative
// control is what showed that.
const shouldDisclaim = nowCovered.length === 0;
const scopeOk = shouldDisclaim === disclaims;

console.log(
  `  ${scopeOk ? "ok  " : "FAIL"} README's audit-scope disclaimer matches SECURITY-AUDIT.md`
);
if (!scopeOk) {
  console.error(
    shouldDisclaim
      ? `\nSECURITY-AUDIT.md still covers only the v1 core — it mentions none of ` +
          `${formatSubjects.join(", ")} — but README no longer says the format is ` +
          `"not in that scope".\nSilence there reads as "audited" to someone deciding ` +
          `whether to trust a seed phrase to this.`
      : `\nSECURITY-AUDIT.md now discusses ${nowCovered.join(", ")}, but README still ` +
          `says the format is "not in that scope".\nIf the audit was widened, say so — ` +
          `the disclaimer is now under-claiming to exactly the people it was written for.`
  );
  process.exit(1);
}

if (missing.length) {
  console.error(
    `\n${missing.length} of ${scripts.length} test scripts are missing from README.md: ` +
      `${missing.join(", ")}.\nAdd them to "Run it locally" — a reader deciding whether to ` +
      `trust this project runs that list.`
  );
  process.exit(1);
}
console.log(`\nAll ${scripts.length} test scripts are documented.`);
