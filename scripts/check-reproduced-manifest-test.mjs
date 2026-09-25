#!/usr/bin/env node
/**
 * The sign jobs refuse a manifest that the independent builds did not
 * reproduce.
 *
 * scripts/check-reproduced-manifest.mjs is the step in deploy.yml and
 * release.yml that stands between "the publishing runner built something" and
 * "sign it". It only ever runs on GitHub, inside a publish, so this drives it
 * as a subprocess against manifests laid out the way actions/download-artifact
 * lays them out, and asserts it refuses every case that should stop a
 * signature and accepts the one that should not.
 *
 * Control shown to bite: make the comparison always succeed (replace
 * `theirs.equals(built)` with `true`) and the differing, extra-file and
 * missing-file cases below pass the checker, so their assertions fail. Drop
 * MIN_REPRODUCTIONS to 0 and the no-manifest and one-manifest cases do.
 */
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const CHECKER = join(dirname(fileURLToPath(import.meta.url)), 'check-reproduced-manifest.mjs');

let failed = 0;
const ok = (cond, msg, detail = '') => {
  if (!cond) {
    console.error(`FAIL: ${msg}${detail ? `\n${detail}` : ''}`);
    failed++;
  } else console.log(`ok    ${msg}`);
};

const hex = (c) => c.repeat(64);
const manifest = (rows) => rows.map(([digest, path]) => `${digest}  ${path}\n`).join('');
const BASE = [
  [hex('a'), '_next/static/chunks/app.js'],
  [hex('b'), 'index.html'],
  [hex('c'), 'sw.js'],
];

const root = mkdtempSync(join(tmpdir(), 'keymaker-reproduced-'));
let caseNo = 0;

/**
 * Lay out one case: the build's manifest, and a directory of legs, each a
 * subdirectory holding SHA256SUMS. Returns the checker's exit status and
 * combined output.
 */
function run(buildRows, legRows, { build = true, legsDir = true } = {}) {
  const dir = join(root, `case-${++caseNo}`);
  mkdirSync(dir, { recursive: true });
  const buildPath = join(dir, 'out', 'SHA256SUMS');
  if (build) {
    mkdirSync(dirname(buildPath), { recursive: true });
    writeFileSync(buildPath, buildRows === null ? '' : manifest(buildRows));
  }
  const reproduced = join(dir, 'reproduced');
  if (legsDir) {
    mkdirSync(reproduced);
    legRows.forEach((rows, i) => {
      mkdirSync(join(reproduced, `sums-leg${i}`));
      writeFileSync(join(reproduced, `sums-leg${i}`, 'SHA256SUMS'), manifest(rows));
    });
  }
  const r = spawnSync(process.execPath, [CHECKER, buildPath, reproduced], { encoding: 'utf8' });
  return { status: r.status, out: `${r.stdout}${r.stderr}` };
}

// Positive: every leg agrees, so the manifest may be signed.
{
  const r = run(BASE, [BASE, BASE, BASE]);
  ok(r.status === 0, 'three identical reproductions pass', r.out);
}

// A digest differs on one leg: the publishing runner built different bytes.
{
  const changed = BASE.map(([d, p]) => (p === 'sw.js' ? [hex('d'), p] : [d, p]));
  const r = run(BASE, [BASE, changed, BASE]);
  ok(r.status === 1, 'one leg with a different digest refuses to sign', r.out);
  ok(/differs:\s+sw\.js/.test(r.out), 'the refusal names the differing file', r.out);
}

// The signed build carries a file no verified build produced.
{
  const extra = [...BASE, [hex('e'), 'injected.js']];
  const r = run(extra, [BASE, BASE]);
  ok(r.status === 1, 'a file only the publishing runner produced refuses to sign', r.out);
  ok(/only in the signed build: injected\.js/.test(r.out), 'the refusal names the extra file', r.out);
}

// The verified builds have a file the signed build dropped.
{
  const r = run(BASE.slice(0, 2), [BASE, BASE]);
  ok(r.status === 1, 'a file the publishing runner dropped refuses to sign', r.out);
  ok(/only in .*sums-leg0: sw\.js/.test(r.out), 'the refusal names the missing file', r.out);
}

// Same entries, different bytes (a reordered manifest is a different manifest,
// and so a different signature).
{
  const r = run(BASE, [[...BASE].reverse(), BASE]);
  ok(r.status === 1, 'a manifest that differs only in order refuses to sign', r.out);
}

// Nothing to compare against must never read as agreement.
{
  const r = run(BASE, [], { legsDir: false });
  ok(r.status === 1, 'no downloaded manifests at all refuses to sign', r.out);
  const empty = run(BASE, []);
  ok(empty.status === 1, 'an empty download directory refuses to sign', empty.out);
  const one = run(BASE, [BASE]);
  ok(one.status === 1, 'a single reproduction is below the minimum and refuses to sign', one.out);
}

// No build manifest, or an empty one, is not something to sign either.
{
  const r = run(BASE, [BASE, BASE], { build: false });
  ok(r.status === 1, 'a missing build manifest refuses to sign', r.out);
  const empty = run(null, [BASE, BASE]);
  ok(empty.status === 1, 'an empty build manifest refuses to sign', empty.out);
}

rmSync(root, { recursive: true, force: true });
console.log(failed === 0 ? '\nAll reproduced-manifest checks passed.' : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
