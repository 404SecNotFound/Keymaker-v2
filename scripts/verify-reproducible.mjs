#!/usr/bin/env node
/**
 * Build twice and prove the output is identical.
 *
 * The signed manifest makes a promise on the project's behalf: check out this
 * commit, rebuild, and you get the same bytes that were deployed. That promise
 * is worth exactly as much as the guard behind it, and reproducibility is
 * unusually easy to lose by accident — one timestamp, one random id, one
 * `Date.now()` baked into a bundle, and it is gone. Nothing else in the build
 * would fail; the artifact would simply stop being verifiable, quietly.
 *
 * It happened here already: Next generates a random build id per build, which
 * appeared both in `_next/static/<buildId>/` paths and in the emitted HTML, and
 * was the sole reason two builds of the same commit differed. See
 * next.config.js.
 *
 * So this runs the real build twice, into two directories, and compares every
 * file. It is slow — two full builds — and it belongs in CI rather than in the
 * inner loop, which is why it is a separate script rather than part of `build`.
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { cpSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative, sep } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = join(ROOT, 'out');

function walk(dir) {
  const found = [];
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) found.push(...walk(p));
    else found.push(p);
  }
  return found;
}

function digestTree(dir) {
  const map = new Map();
  for (const abs of walk(dir)) {
    const rel = relative(dir, abs).split(sep).join('/');
    map.set(rel, createHash('sha256').update(readFileSync(abs)).digest('hex'));
  }
  return map;
}

function build(label) {
  console.log(`reproducible: building (${label})...`);
  rmSync(OUT, { recursive: true, force: true });
  rmSync(join(ROOT, '.next'), { recursive: true, force: true });
  execFileSync('npm', ['run', 'build'], {
    cwd: ROOT,
    stdio: ['ignore', 'ignore', 'inherit'],
    // Pin the build id explicitly. In CI the checkout may be a detached HEAD or
    // a merge commit that does not exist upstream, and letting the two runs
    // resolve it independently would be testing git rather than the build.
    env: { ...process.env, KEYMAKER_BUILD_ID: process.env.KEYMAKER_BUILD_ID || 'reproducibility-check' },
  });
  const snapshot = mkdtempSync(join(tmpdir(), `keymaker-repro-${label}-`));
  cpSync(OUT, snapshot, { recursive: true });
  return snapshot;
}

const first = build('1 of 2');
const second = build('2 of 2');

try {
  const a = digestTree(first);
  const b = digestTree(second);

  const onlyInA = [...a.keys()].filter((k) => !b.has(k));
  const onlyInB = [...b.keys()].filter((k) => !a.has(k));
  const differing = [...a.keys()].filter((k) => b.has(k) && a.get(k) !== b.get(k));

  for (const f of onlyInA) console.error(`  only in build 1: ${f}`);
  for (const f of onlyInB) console.error(`  only in build 2: ${f}`);
  for (const f of differing) console.error(`  differs: ${f}`);

  const problems = onlyInA.length + onlyInB.length + differing.length;
  if (problems > 0) {
    console.error(
      `\nreproducible: FAILED — ${problems} difference(s) across ${a.size} files.\n` +
        'Two builds of the same source produced different bytes, so the signed\n' +
        'manifest can no longer be reproduced from source and only proves that\n' +
        'CI built something. Find the nondeterminism (a timestamp, a random id,\n' +
        'an environment value baked into a bundle) rather than relaxing this.'
    );
    process.exit(1);
  }

  console.log(`\nreproducible: OK — ${a.size} files identical across two clean builds.`);
} finally {
  rmSync(first, { recursive: true, force: true });
  rmSync(second, { recursive: true, force: true });
}
