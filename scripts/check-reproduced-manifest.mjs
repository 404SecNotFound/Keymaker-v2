#!/usr/bin/env node
/**
 * Refuse to sign a manifest that no independent runner reproduced.
 *
 * deploy.yml and release.yml build the site once, in their own `build` job,
 * and sign that job's out/SHA256SUMS. The suites they wait on never see those
 * bytes: they build their own copy of the same commit. "Publish the tested
 * artifact" therefore rests on a claim, that every build of this commit is
 * byte-identical, and until this script nothing checked the claim against the
 * bytes actually being signed. A nondeterminism that only showed up on the
 * publishing runner would have been signed, deployed and published, with
 * every suite green.
 *
 * ci.yml's `reproducible-elsewhere` legs each build the same commit on a
 * separate runner and upload their SHA256SUMS as `sums-<leg>`. They run in the
 * same workflow run as the publisher (it calls ci.yml through `workflow_call`),
 * so the sign job can download them. This compares each one, byte for byte,
 * against the manifest about to be signed, and fails naming the files that
 * differ. SHA256SUMS covers every served file, so equal manifests mean equal
 * artifacts.
 *
 * Usage:
 *   node scripts/check-reproduced-manifest.mjs <build SHA256SUMS> <dir>
 *
 * where <dir> holds one subdirectory per downloaded artifact, each containing
 * a SHA256SUMS (the layout actions/download-artifact produces for a pattern).
 *
 * No dependencies: the sign job installs with --ignore-scripts and holds an
 * OIDC token, so this reads files and compares them and does nothing else.
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Fewer than this is a comparison that proves too little to sign on. Two is
 * also what ci.yml's own cross-runner comparison requires, so a publish run
 * that got this far always has at least that many.
 */
const MIN_REPRODUCTIONS = 2;

function fail(message) {
  console.error(`reproduced: FAILED - ${message}`);
  process.exit(1);
}

/** path -> digest, for naming what differs rather than only that something does. */
function entries(bytes) {
  const map = new Map();
  for (const line of bytes.toString('utf8').split('\n')) {
    if (!line) continue;
    const m = /^([a-f0-9]{64}) {2}(.+)$/.exec(line);
    map.set(m ? m[2] : `<unparseable line> ${line.slice(0, 80)}`, m ? m[1] : '');
  }
  return map;
}

const [buildPath, dir] = process.argv.slice(2);
if (!buildPath || !dir) {
  fail('usage: check-reproduced-manifest.mjs <build SHA256SUMS> <dir of downloaded manifests>');
}

let built;
try {
  built = readFileSync(buildPath);
} catch {
  fail(`${buildPath} not found. There is no build manifest to compare.`);
}
if (built.length === 0) fail(`${buildPath} is empty.`);

let legs = [];
try {
  legs = readdirSync(dir)
    .sort()
    .map((name) => join(dir, name))
    .filter((p) => statSync(p).isDirectory() && existsSync(join(p, 'SHA256SUMS')));
} catch {
  // A missing directory is the zero-reproductions case below.
}

if (legs.length < MIN_REPRODUCTIONS) {
  fail(
    `found ${legs.length} reproduced manifest(s) in ${dir}, need at least ${MIN_REPRODUCTIONS}. ` +
      'Comparing against nothing would pass while proving nothing, so this refuses to sign.'
  );
}

const reference = entries(built);
let differing = 0;
for (const leg of legs) {
  const theirs = readFileSync(join(leg, 'SHA256SUMS'));
  if (theirs.equals(built)) {
    console.log(`reproduced: ok   ${leg} is byte-identical (${reference.size} files)`);
    continue;
  }
  differing++;
  const other = entries(theirs);
  console.error(`reproduced: FAIL ${leg} differs from ${buildPath}:`);
  for (const [path, digest] of reference) {
    if (!other.has(path)) console.error(`  only in the signed build: ${path}`);
    else if (other.get(path) !== digest) console.error(`  differs:                  ${path}`);
  }
  for (const path of other.keys()) {
    if (!reference.has(path)) console.error(`  only in ${leg}: ${path}`);
  }
}

if (differing > 0) {
  fail(
    `${differing} of ${legs.length} independent build(s) disagree with the manifest about to be ` +
      'signed. The publishing runner produced bytes the verified builds did not, so signing ' +
      'them would certify an artifact nobody tested or reproduced. Find the nondeterminism ' +
      'rather than relaxing this.'
  );
}
console.log(
  `reproduced: the signed manifest matches ${legs.length} independent build(s) byte for byte`
);
