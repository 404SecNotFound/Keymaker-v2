// The publish gate (R01), made executable.
//
// deploy.yml and release.yml build, sign and publish. The suites that decide
// whether those bytes are fit to publish live in four other workflows. Nothing
// in YAML makes "deploy" wait for "tests" unless a `needs` edge says so, and
// the failure mode of a missing edge is invisible: the deploy still turns
// green, having tested nothing. A signature over untested bytes proves only
// that CI built them.
//
// So this asserts the edges exist. On both publishing channels the terminal
// job (deploy / publish) must transitively depend on every verification
// workflow, and each of those must be reachable through a `workflow_call` so it
// runs on this run's commit rather than beside it. Remove any `needs` entry, or
// the `workflow_call` trigger from a suite, and this fails naming the gap.
//
// Deliberately not a YAML library: every other workflow gate in this repo
// (deploy-base-path.cjs, verifying-doc.cjs) hand-reads the file for the same
// reason — no dependency in the toolchain that inspects the supply chain.
//
// To watch the control bite: delete "verify-browser" from build.needs in
// deploy.yml and re-run; this reports that deploy no longer waits for the
// browser suite. Restore it and it passes.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const WF = join(ROOT, ".github", "workflows");

let failures = 0;
const ok = (msg) => console.log(`  ok   ${msg}`);
const bad = (msg) => {
  console.log(`  FAIL ${msg}`);
  failures++;
};

// The four suites a publish must pass, and the file each lives in.
const SUITES = {
  "verify-crypto": "crypto-regression.yml",
  "verify-ci": "ci.yml",
  "verify-conformance": "conformance.yml",
  "verify-browser": "browser.yml",
};

/**
 * The block of text belonging to one top-level job.
 *
 * Jobs sit at two-space indent under `jobs:`; a job's own keys are indented
 * deeper. The block runs from the job header to the next two-space `name:` line
 * (the next job) or end of file.
 */
function jobBlock(src, job) {
  const lines = src.split("\n");
  const start = lines.findIndex((l) => new RegExp(`^  ${job}:\\s*$`).test(l));
  if (start === -1) return null;
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    if (/^  \S/.test(lines[i])) {
      end = i;
      break;
    }
  }
  return lines.slice(start, end).join("\n");
}

/** The job names in a `needs:`, whether written as `[a, b]` or a block list. */
function needsOf(block) {
  if (!block) return [];
  const inline = block.match(/^\s*needs:\s*\[([^\]]*)\]\s*$/m);
  if (inline) {
    return inline[1]
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  }
  const scalar = block.match(/^\s*needs:\s*([A-Za-z0-9_-]+)\s*$/m);
  if (scalar) return [scalar[1]];
  const listHead = block.match(/^(\s*)needs:\s*$/m);
  if (listHead) {
    const after = block.slice(block.indexOf(listHead[0]) + listHead[0].length);
    const out = [];
    for (const line of after.split("\n").slice(1)) {
      const m = line.match(/^\s*-\s*([A-Za-z0-9_-]+)\s*$/);
      if (m) out.push(m[1]);
      else if (line.trim() !== "") break;
    }
    return out;
  }
  return [];
}

/** Every job the terminal job depends on, walked transitively. */
function ancestors(src, job, seen = new Set()) {
  for (const dep of needsOf(jobBlock(src, job))) {
    if (!seen.has(dep)) {
      seen.add(dep);
      ancestors(src, dep, seen);
    }
  }
  return seen;
}

// ---------------------------------------------------------------- the suites
//
// Each must be callable, or deploy/release cannot make it a prerequisite.
for (const [verifyJob, file] of Object.entries(SUITES)) {
  const src = readFileSync(join(WF, file), "utf8");
  if (/^\s{2}workflow_call:\s*$/m.test(src)) ok(`${file} is callable (workflow_call)`);
  else bad(`${file} has no workflow_call trigger, so it cannot gate a publish`);
}

// ---------------------------------------------------------------- deploy.yml
{
  const src = readFileSync(join(WF, "deploy.yml"), "utf8");

  // Each verify job calls the workflow it claims to.
  for (const [verifyJob, file] of Object.entries(SUITES)) {
    const block = jobBlock(src, verifyJob);
    if (block && new RegExp(`uses:\\s*\\./\\.github/workflows/${file.replace(".", "\\.")}`).test(block))
      ok(`deploy.yml ${verifyJob} calls ${file}`);
    else bad(`deploy.yml ${verifyJob} does not call ./.github/workflows/${file}`);
  }

  // The published job is `deploy`; it must reach every suite through needs.
  const chain = ancestors(src, "deploy");
  for (const verifyJob of Object.keys(SUITES)) {
    if (chain.has(verifyJob)) ok(`deploy waits for ${verifyJob}`);
    else bad(`deploy does not depend on ${verifyJob}; it could publish untested bytes`);
  }
  if (chain.has("build")) ok("deploy waits for build");
  else bad("deploy does not depend on build");
}

// ---------------------------------------------------------------- release.yml
{
  const src = readFileSync(join(WF, "release.yml"), "utf8");

  for (const [verifyJob, file] of Object.entries(SUITES)) {
    const block = jobBlock(src, verifyJob);
    if (block && new RegExp(`uses:\\s*\\./\\.github/workflows/${file.replace(".", "\\.")}`).test(block))
      ok(`release.yml ${verifyJob} calls ${file}`);
    else bad(`release.yml ${verifyJob} does not call ./.github/workflows/${file}`);
  }

  // The published job is `publish`; it must reach every suite through needs.
  const chain = ancestors(src, "publish");
  for (const verifyJob of Object.keys(SUITES)) {
    if (chain.has(verifyJob)) ok(`publish waits for ${verifyJob}`);
    else bad(`publish does not depend on ${verifyJob}; it could publish untested bytes`);
  }

  // preflight must gate the suites, so a lightweight tag or a changelog that
  // will not compose fails fast rather than after the matrix.
  const verifyNeedsPreflight = Object.keys(SUITES).every((j) =>
    needsOf(jobBlock(src, j)).includes("preflight")
  );
  if (verifyNeedsPreflight) ok("release verification runs after preflight (fast-fail preserved)");
  else bad("a release verify job does not need preflight; the fast-fail checks no longer run first");
}

if (failures > 0) {
  console.log(`\n${failures} check(s) failed: a publish path is not gated on its tests.`);
  process.exit(1);
}
console.log("\nAll checks passed: deployment and release both wait for every suite.");
