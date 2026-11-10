#!/usr/bin/env node
/**
 * The README's "downloaded and verified" recipe serves the app, not a listing.
 *
 * release.yml packs the site as `keymaker-<tag>/...` inside the tarball. The
 * README told the reader to extract that into `keymaker-local/Keymaker-v2`
 * without stripping the top directory, so the app landed one level too deep
 * and `http://localhost:8000/Keymaker-v2/` showed a directory listing.
 *
 * This gate packs a stand-in site the way release.yml's Package step does,
 * runs the README's own extraction lines against it, and requires
 * `index.html` at the path the README then tells the reader to open. It also
 * requires the Package step to still use the layout the stand-in copies, so a
 * change to the archive cannot leave this gate testing a layout nobody ships.
 */
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const TAG = 'v0.0.0-gate';

let failures = 0;
function check(name, ok, detail) {
  if (ok) console.log(`  ok   ${name}`);
  else {
    failures++;
    console.error(`  FAIL ${name}${detail ? `\n       ${detail}` : ''}`);
  }
}

// ---- 1. The archive layout this gate copies is still the shipped one ----

const workflow = readFileSync(join(ROOT, '.github', 'workflows', 'release.yml'), 'utf8');
check(
  'release.yml still packs the site under keymaker-<tag>/',
  workflow.includes('cp -r out "keymaker-$TAG"') &&
    /-cf - "keymaker-\$TAG" \| gzip -n -9 > "keymaker-\$TAG\.tar\.gz"/.test(workflow),
  'the Package step changed; update the stand-in archive below to match it'
);

// ---- 2. The README block, run as written ----

const readme = readFileSync(join(ROOT, 'README.md'), 'utf8');
const blocks = [...readme.matchAll(/```bash\n([\s\S]*?)```/g)]
  .map((m) => m[1])
  .filter((b) => b.includes('keymaker-<tag>.tar.gz'));
check('README.md has exactly one local-serving recipe', blocks.length === 1, `found ${blocks.length}`);

if (blocks.length === 1) {
  const lines = blocks[0].split('\n').filter((l) => l.trim() && !l.trim().startsWith('#'));
  const serve = lines.filter((l) => l.includes('http.server'));
  const steps = lines.filter((l) => !l.includes('http.server'));
  check('the recipe ends by serving keymaker-local', serve.length === 1 && /^cd keymaker-local && /.test(serve[0]), serve.join(' | '));

  const url = /http:\/\/localhost:\d+(\/\S*)/.exec(blocks[0]);
  check('the recipe names the URL to open', url !== null);

  const work = mkdtempSync(join(tmpdir(), 'keymaker-readme-'));
  try {
    mkdirSync(join(work, `keymaker-${TAG}`, '_next'), { recursive: true });
    writeFileSync(join(work, `keymaker-${TAG}`, 'index.html'), '<!doctype html><title>Keymaker</title>');
    writeFileSync(join(work, `keymaker-${TAG}`, '_next', 'chunk.js'), '');
    execFileSync('tar', ['-czf', `keymaker-${TAG}.tar.gz`, `keymaker-${TAG}`], { cwd: work });
    rmSync(join(work, `keymaker-${TAG}`), { recursive: true });

    let ran = true;
    try {
      execFileSync('bash', ['-euo', 'pipefail', '-c', steps.join('\n').replaceAll('<tag>', TAG)], { cwd: work, stdio: 'pipe' });
    } catch (e) {
      ran = false;
      check('the extraction lines run', false, String(e.stderr || e.message));
    }
    if (ran && url) {
      const served = join(work, 'keymaker-local', url[1]);
      check(
        `index.html is at the path the recipe opens (${url[1]})`,
        existsSync(join(served, 'index.html')),
        'the app is not where the URL points, so the reader sees a directory listing'
      );
      check('the assets sit beside it', existsSync(join(served, '_next', 'chunk.js')));
    }
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

console.log();
if (failures > 0) {
  console.error(`${failures} check(s) failed.`);
  process.exit(1);
}
console.log('All checks passed: the README local-serving recipe serves the app.');
