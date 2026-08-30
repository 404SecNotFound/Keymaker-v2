#!/usr/bin/env node
/**
 * Compose release notes, with the verification commands taken from
 * docs/VERIFYING.md rather than retyped.
 *
 *     node scripts/release-notes.mjs <tag> <workflow-ref> > NOTES.md
 *
 * Roadmap 6.2. The gate on that item is that the `cosign verify-blob`
 * invocation in the notes is *copied* from the document, because a verification
 * command that does not work is worse than none — it costs a careful reader
 * their time and then their trust, in that order.
 *
 * ## Why this extracts rather than duplicating
 *
 * The flags are load-bearing. `--certificate-identity` in particular is the
 * whole argument (VERIFYING.md: "the certificate identity is the load-bearing
 * argument, so pass it explicitly"), and a second hand-maintained copy of that
 * command would be free to lose a flag on the first edit that touched only one
 * of the two. `cosign verify-blob` without that flag accepts a signature from
 * anybody, and it does so silently, printing "Verified OK".
 *
 * ## Why the identity is substituted rather than copied verbatim
 *
 * The document's command verifies the *deployed site*, signed by deploy.yml on
 * refs/heads/main. A release is signed by release.yml on a tag ref, so the
 * identity genuinely differs — copying that line unchanged would produce a
 * command that fails against the artifact it is printed beside, which is the
 * exact failure this script exists to prevent.
 *
 * So: structure and flags come from the document, the identity is computed from
 * the ref actually doing the signing. `scripts/release-notes-test.mjs` asserts
 * that the two commands are identical apart from that one value.
 *
 * The composition is a pure function so the test can feed it a mangled document
 * and check that it refuses, rather than only checking that it works.
 */
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
// Shared with next.config.js, which injects the same commands into the in-app
// verify page (roadmap 6.3). One extractor, three consumers, one hand-written
// copy of each command — in docs/VERIFYING.md.
import verifyingDoc from './verifying-doc.cjs';

const { extractBlock } = verifyingDoc;

const HERE = dirname(fileURLToPath(import.meta.url));
export const ROOT = join(HERE, '..');

/**
 * Compose the notes.
 *
 * @param {object} opts
 * @param {string} opts.doc          contents of docs/VERIFYING.md
 * @param {string} opts.version      the `version` field of package.json
 * @param {string} opts.tag          the git tag being released, e.g. "v2.0.0"
 * @param {string} opts.workflowRef  the certificate identity that will sign it
 * @param {string} [opts.changelog]  the annotated tag's message, if it has one
 */
export function composeNotes({ doc, version, tag, workflowRef, changelog = '', formatVersion }) {
  // Roadmap 6.1 decided the footer and package.json must not carry different
  // application versions. A tag is a third place the number appears, and the
  // one users cite. Catch the disagreement here, where it costs a failed
  // workflow run, rather than after a release is public and immutable.
  if (tag !== `v${version}`) {
    throw new Error(
      `tag ${tag} does not match package.json version ${version} (expected tag v${version}). ` +
        'Bump the version or fix the tag; do not publish a release whose number disagrees with the build inside it.'
    );
  }

  // Release bodies are not rendered inside the repository tree, so a relative
  // link out of one does not resolve — it 404s. Build absolute URLs, pinned at
  // the tag rather than at main, so a reader following them from a two-year-old
  // release gets the documents that shipped with it rather than whatever the
  // format doc says today.
  const repo = /^(https:\/\/[^/]+\/[^/]+\/[^/]+)\/\.github\/workflows\//.exec(workflowRef);
  if (!repo) {
    throw new Error(
      `could not derive the repository URL from workflow ref ${JSON.stringify(workflowRef)}; ` +
        'expected https://<host>/<owner>/<repo>/.github/workflows/<file>@<ref>'
    );
  }
  const link = (path) => `${repo[1]}/blob/${tag}/${path}`;

  const cosignBlock = extractBlock(doc, 'cosign verify-blob');

  // The document's identity is deploy.yml on main; a release is signed by
  // whichever workflow ref actually produced it.
  const cosign = cosignBlock.replace(
    /--certificate-identity '[^']*'/,
    `--certificate-identity '${workflowRef}'`
  );
  if (cosign === cosignBlock) {
    throw new Error(
      'could not substitute --certificate-identity in the extracted cosign command; ' +
        'the flag format in docs/VERIFYING.md changed and this script did not follow it. ' +
        'Emitting the deployment identity beside a release artifact would print a command that fails.'
    );
  }

  // Only the manifest check itself transfers to a tarball — the rest of that
  // block is about mirroring the live site, which is not what is being
  // unpacked here. Take the command lines and leave the surrounding steps.
  const sumsBlock = extractBlock(doc, 'sha256sum -c SHA256SUMS');
  const sums = sumsBlock.split('\n').filter((line) => line.startsWith('sha256sum '));
  if (sums.length !== 1) {
    throw new Error(
      `expected exactly one sha256sum command line in that block, found ${sums.length}`
    );
  }

  // No default. A default here is what the literal "v2" was: a value that keeps
  // composing after it stops being true, in the one document a reader consults
  // precisely because their file will not open.
  if (!Number.isInteger(formatVersion)) {
    throw new Error(
      'composeNotes needs formatVersion — the container version this build writes. ' +
        'It comes from readSources(); do not restate it here.'
    );
  }
  const keym = `KEYM v${formatVersion}`;
  const specPath = `docs/FORMAT-V${formatVersion}-DESIGN.md`;

  // Written by whoever cut the tag. Omitted rather than filled with a
  // placeholder when the tag carries no message: an empty "What changed" is a
  // worse answer than no heading, because it reads as "nothing changed".
  const changed = changelog.trim() ? `## What changed\n\n${changelog.trim()}\n\n` : '';

  return `Keymaker **${tag}**, writing **${keym}** containers. Those are two
different version numbers and they move independently — see the bottom of these
notes if a file will not open.

${changed}## Verifying this release

Two checks, and they answer different questions. Neither of them asks you to
trust this project's own tooling.

**1. The files are the ones this tag produced.**

\`\`\`bash
tar -xzf keymaker-${tag}.tar.gz && cd keymaker-${tag}
${sums[0]}
\`\`\`

\`sha256sum\` is on every Unix machine and has nothing to do with this project,
which is the point.

**2. This repository's release workflow is what signed that manifest.**

\`\`\`bash
${cosign}
\`\`\`

Keyless signing: there is no published key to obtain and therefore no key
distribution to get wrong. The check is not "signed by a key we told you about"
— it is "signed by *this workflow*, in *this repository*", and
\`--certificate-identity\` is the flag that makes it so. Without it,
\`cosign verify-blob\` accepts a signature from anybody and says "Verified OK".

Note that the identity above ends in \`release.yml@refs/tags/${tag}\`, while
[docs/VERIFYING.md](${link('docs/VERIFYING.md')}) gives \`deploy.yml@refs/heads/main\` for
the live site. Different workflows sign the two things, so they are different
identities and neither will verify the other. That document is where these
commands come from — they are generated from it, not maintained beside it.

## What this artifact is

The site as built from this tag, with the Pages base path, so it is directly
comparable to a deployment of the same commit.

Not byte-identical to whatever the live site is serving right now, and it would
be dishonest to imply otherwise: the live site tracks \`main\`, so unless the
deployment is of this exact tag it is a different commit. The two are also
labelled differently on purpose — a build from this workflow says
\`v${version}\`, a rolling deployment says \`v${version}-dev\` — so that a
version number never names an artifact you are not running. Each is verified
against its own signing identity; neither is offered as a proxy for the other.

It is built with the Pages base path, so it expects to be served from
\`/Keymaker-v2/\`. That makes it a verification artifact rather than a drop-in
for hosting elsewhere; to host it at another path, build from source, which
\`docs/VERIFYING.md\` also covers.

## Container format

This release writes **${keym}** containers. The format is specified in
[${specPath}](${link(specPath)}) and implemented
independently in [reference/keym2.py](${link('reference/keym2.py')}), which decrypts your
files without this application, this website, or a browser. If this project
disappears, that file and the printed procedure in
[docs/RECOVERY.md](${link('docs/RECOVERY.md')}) are enough.

**${tag} is the application version. ${keym} is the format version.** They are
separate numbers on purpose, because they answer different questions: which app
you are running, and which file you are holding. A file that will not open is
almost always a question about the second.
`;
}

/**
 * Which container version this build writes, read from the implementation.
 *
 * This was the string "KEYM v2", three times, as prose. When the writer moved
 * to v3 nothing made the notes follow, and v2.1.0 shipped notes whose first
 * line said the release writes v2 while the tag message two paragraphs below
 * said v3 — sending a reader whose file will not open to the wrong
 * specification, from the document that exists to answer exactly that.
 *
 * A regex over a source file is blunt, and is the deliberate choice: the
 * publish job runs with no `npm ci` at all (see release.yml, which says why),
 * so this script cannot import the module, and a second hand-kept copy of the
 * number is the thing that just failed. It refuses rather than guessing if the
 * declaration moves, because a wrong version here is worse than no notes.
 */
export function writtenFormatVersion(source) {
  const match = /^export const KEYM2_VERSION\s*=\s*KEYM2_VERSION_V(\d+)\s*;/m.exec(source);
  if (!match) {
    throw new Error(
      'could not read KEYM2_VERSION from src/lib/keym-v2.ts, so the notes cannot say ' +
        'which container version this release writes. Update the pattern here rather ' +
        'than writing the version back into the notes by hand.'
    );
  }
  return Number(match[1]);
}

/** Read the inputs from the working tree. Split out so tests need no I/O. */
export function readSources() {
  const formatVersion = writtenFormatVersion(
    readFileSync(join(ROOT, 'src', 'lib', 'keym-v2.ts'), 'utf8')
  );
  // The notes link this file by name. Deriving the name means a version with no
  // document would link a 404 from the paragraph telling a reader where their
  // format is written down, so the file is required to exist.
  const spec = `docs/FORMAT-V${formatVersion}-DESIGN.md`;
  if (!existsSync(join(ROOT, spec))) {
    throw new Error(
      `this build writes KEYM v${formatVersion}, but ${spec} does not exist — the notes ` +
        'would link it from the section that tells a reader where the format is specified.'
    );
  }
  return {
    doc: readFileSync(join(ROOT, 'docs', 'VERIFYING.md'), 'utf8'),
    version: JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).version,
    formatVersion,
  };
}

// Only when run directly, so the test can import composeNotes without the CLI
// firing and exiting the process.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [, , tag, workflowRef, changelogPath] = process.argv;
  if (!tag || !workflowRef) {
    console.error('usage: release-notes.mjs <tag> <workflow-ref> [changelog-file]');
    console.error(
      "  e.g. release-notes.mjs v2.0.0 'https://github.com/o/r/.github/workflows/release.yml@refs/tags/v2.0.0'"
    );
    process.exit(2);
  }
  // Absent or empty is normal — a lightweight tag has no message. Unreadable is
  // treated the same way rather than fatally: a missing changelog should not
  // block a release whose verification section is intact.
  let changelog = '';
  if (changelogPath) {
    try {
      changelog = readFileSync(changelogPath, 'utf8');
    } catch {
      console.error(`release-notes: no changelog at ${changelogPath}; omitting that section`);
    }
  }
  process.stdout.write(composeNotes({ ...readSources(), tag, workflowRef, changelog }));
}
