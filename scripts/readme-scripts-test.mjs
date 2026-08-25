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

if (missing.length) {
  console.error(
    `\n${missing.length} of ${scripts.length} test scripts are missing from README.md: ` +
      `${missing.join(", ")}.\nAdd them to "Run it locally" — a reader deciding whether to ` +
      `trust this project runs that list.`
  );
  process.exit(1);
}
console.log(`\nAll ${scripts.length} test scripts are documented.`);
