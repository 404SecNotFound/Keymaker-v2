#!/usr/bin/env node
/**
 * Build twice, under two deliberately different environments, and prove the
 * output is identical.
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
 * ## What this proves, and what it does not
 *
 * Two builds on one runner answer "is the build a function of its source" —
 * they catch the `Date.now()` class immediately and cheaply. They do **not**
 * answer the question a verifier actually asks, which is "does *my* machine
 * produce the bytes you published". Same OS, same CPU, same Node, same paths:
 * every variable a stranger's machine would change is held fixed.
 *
 * So the second build is run under a different clock, a different locale and a
 * different HOME, which closes the cheapest part of that gap here. The rest —
 * a different machine, a different checkout path, a different Node major — is
 * not something a single process can vary honestly, and is enforced instead by
 * the `reproducible-elsewhere` matrix in .github/workflows/ci.yml, where each
 * leg is a separate runner. Neither covers a different OS or CPU architecture;
 * docs/VERIFYING.md says so rather than implying otherwise.
 *
 * It is slow — two full builds — and it belongs in CI rather than in the inner
 * loop, which is why it is a separate script rather than part of `build`.
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

/**
 * The environment the second build runs under.
 *
 * Every one of these is something a stranger's machine would differ in, and
 * something that has broken reproducibility in other projects: a timezone that
 * reaches a date formatter, a locale that reaches a sort, a HOME that moves a
 * tool cache. Kiritimati is UTC+14, the furthest offset there is, so for
 * fourteen hours out of every twenty-four a date rendered under it falls on a
 * different calendar day from the same instant rendered under UTC — which is
 * what makes it a better probe than an offset that only shifts the hour.
 *
 * `LC_ALL: 'C'` rather than a named language, because a locale that is not
 * installed is silently ignored — the variable is set, nothing changes, and the
 * run reports success having varied nothing. `C` is guaranteed to exist.
 */
function alternateEnvironment() {
  return {
    TZ: 'Pacific/Kiritimati',
    LC_ALL: 'C',
    LANG: 'C',
    HOME: mkdtempSync(join(tmpdir(), 'keymaker-repro-home-')),
  };
}

function build(label, overrides = {}) {
  const varied = Object.keys(overrides);
  console.log(
    `reproducible: building (${label})${varied.length ? ` with ${varied.join(', ')} changed` : ''}...`
  );
  rmSync(OUT, { recursive: true, force: true });
  rmSync(join(ROOT, '.next'), { recursive: true, force: true });
  execFileSync('npm', ['run', 'build'], {
    cwd: ROOT,
    stdio: ['ignore', 'ignore', 'inherit'],
    env: {
      ...process.env,
      // Pin the build id explicitly. In CI the checkout may be a detached HEAD
      // or a merge commit that does not exist upstream, and letting the two
      // runs resolve it independently would be testing git rather than the
      // build.
      KEYMAKER_BUILD_ID: process.env.KEYMAKER_BUILD_ID || 'reproducibility-check',
      ...overrides,
    },
  });
  const snapshot = mkdtempSync(join(tmpdir(), `keymaker-repro-${label}-`));
  cpSync(OUT, snapshot, { recursive: true });
  return snapshot;
}

const alternate = alternateEnvironment();
const first = build('1 of 2');
const second = build('2 of 2', alternate);

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

  console.log(
    `\nreproducible: OK — ${a.size} files identical across two clean builds, the second ` +
      `under TZ=${alternate.TZ}, LC_ALL=${alternate.LC_ALL} and a different HOME.\n` +
      'This is same-machine determinism. Whether a *different* machine reproduces these\n' +
      'bytes is the reproducible-elsewhere matrix in ci.yml, not this script.'
  );
} finally {
  rmSync(first, { recursive: true, force: true });
  rmSync(second, { recursive: true, force: true });
  rmSync(alternate.HOME, { recursive: true, force: true });
}
