#!/usr/bin/env node
/**
 * Copy the recovery kit into the static export.
 *
 * ## Why this exists
 *
 * `docs/RECOVERY.md` and `reference/keym.py` are the answer to the question the
 * whole project is built around: *what happens when this website is gone?* A
 * `.keym` file is decryptable with 577 lines of Python and no browser, and that
 * is the property that makes it reasonable to store a seed phrase in one.
 *
 * Today that answer lives in a GitHub repository. Someone who bookmarked the
 * app, uses it for years, and comes back to a dead domain has the container and
 * no idea the reference implementation exists. Shipping both files *with the
 * app* means the recovery path is in the same cache as the tool — it survives
 * the network, and it is there to be saved alongside the backup.
 *
 * ## Why copy rather than symlink or import
 *
 * They are copied into `public/` before `next build` so the export picks them
 * up like any other static asset, and `public/recovery/` is gitignored for the
 * same reason `public/crypto-worker.js` is: a generated file that drifts from
 * its source is worse than no file. The originals stay canonical.
 *
 * The service worker precaches them via APP_SHELL, so they are available
 * offline — which is the case that matters. A recovery document you can only
 * read when the site is up is not a recovery document.
 */
import { copyFileSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const DEST = join(ROOT, 'public', 'recovery');

/**
 * Each entry carries a floor on its size and a string it must contain.
 *
 * Both checks are here because the failure this guards against is silent: an
 * empty or truncated copy still builds, still deploys, and is only discovered
 * by the one person who ever needs it, at the worst possible moment.
 */
const KIT = [
  {
    from: join(ROOT, 'docs', 'RECOVERY.md'),
    to: 'RECOVERY.md',
    minBytes: 2_000,
    mustContain: 'keym2.py',
  },
  {
    from: join(ROOT, 'reference', 'keym.py'),
    to: 'keym.py',
    minBytes: 5_000,
    mustContain: 'def decrypt',
  },
  // Both decryptors ship, and both have to. The app writes v2 now, but every
  // container written before Phase 3 is v1 and v1 is readable forever — a kit
  // carrying only the current script would strand exactly the oldest backups,
  // which are the ones most likely to need it.
  {
    from: join(ROOT, 'reference', 'keym2.py'),
    to: 'keym2.py',
    minBytes: 5_000,
    mustContain: 'def decrypt',
  },
  // The two library versions these scripts were actually tested against.
  //
  // Without it the kit says "pip install cryptography argon2-cffi" and leaves
  // the version to whatever the index serves that day, which for a document
  // whose whole point is working in ten years is the wrong end to leave open.
  // This does not make the kit offline-complete — the wheels themselves are
  // not here, and docs/RECOVERY.md no longer claims otherwise — but it does
  // mean someone assembling an offline bundle knows exactly what to fetch.
  {
    from: join(ROOT, 'reference', 'requirements.txt'),
    to: 'requirements.txt',
    minBytes: 200,
    mustContain: 'cryptography==',
  },
];

rmSync(DEST, { recursive: true, force: true });
mkdirSync(DEST, { recursive: true });

let total = 0;
for (const item of KIT) {
  let source;
  try {
    source = readFileSync(item.from);
  } catch {
    console.error(
      `recovery-kit: ERROR — ${item.from} is missing. The app would ship a ` +
        'footer link to a recovery kit that does not exist.'
    );
    process.exit(1);
  }

  if (source.length < item.minBytes) {
    console.error(
      `recovery-kit: ERROR — ${item.to} is ${source.length} bytes, below the ` +
        `${item.minBytes}-byte floor. Refusing to ship a truncated recovery kit.`
    );
    process.exit(1);
  }

  if (!source.toString('utf8').includes(item.mustContain)) {
    console.error(
      `recovery-kit: ERROR — ${item.to} does not contain ${JSON.stringify(item.mustContain)}. ` +
        'Either the file moved or it is not what this script thinks it is.'
    );
    process.exit(1);
  }

  copyFileSync(item.from, join(DEST, item.to));
  total += source.length;
}

console.log(
  `recovery-kit: copied ${KIT.length} file(s), ${(total / 1024).toFixed(0)} KB to public/recovery/`
);
