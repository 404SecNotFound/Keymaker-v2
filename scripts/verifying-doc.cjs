/**
 * Read the verification commands out of docs/VERIFYING.md.
 *
 * That document is the single source for every `cosign verify-blob` and
 * `sha256sum -c` invocation this project publishes. Three places now print
 * them — the document itself, a release's notes (scripts/release-notes.mjs),
 * and the in-app verify page (roadmap 6.3) — and only the first is written by
 * hand.
 *
 * The reasoning is the 6.2 gate, and it applies with more force to the page
 * than to the notes: **a verification command that does not work is worse than
 * none.** It costs a careful reader their time and then their trust, in that
 * order, and the flags are where that goes wrong silently — `cosign
 * verify-blob` without `--certificate-identity` accepts a signature from
 * anybody and prints "Verified OK".
 *
 * ## Why CommonJS
 *
 * next.config.js is CommonJS and injects these strings into the client bundle
 * at build time; scripts/release-notes.mjs is ESM and imports the same
 * function. CJS is the format both can consume, so there is one implementation
 * rather than one per module system — which is the whole point.
 */
const { readFileSync } = require('node:fs');
const { join } = require('node:path');

const ROOT = join(__dirname, '..');
const VERIFYING = join(ROOT, 'docs', 'VERIFYING.md');

/**
 * The one fenced bash block in `doc` containing `needle`, trailing blank lines
 * trimmed.
 *
 * Fails loudly rather than returning something empty. A page or a release that
 * silently lost its verification section is the outcome worth preventing:
 * nobody notices a missing instruction until they need it, which is the worst
 * possible moment to find out.
 *
 * Requiring *exactly* one match is deliberate. Two blocks would mean the
 * document grew a second copy of the command, and picking one arbitrarily
 * would be this code guessing which copy is current.
 */
function extractBlock(doc, needle) {
  const blocks = [...doc.matchAll(/```bash\n([\s\S]*?)```/g)].map((m) => m[1].trimEnd());
  const found = blocks.filter((b) => b.includes(needle));
  if (found.length !== 1) {
    throw new Error(
      `expected exactly one bash block in docs/VERIFYING.md containing ${JSON.stringify(needle)}, found ${found.length}. ` +
        'The notes generator and the in-app verify page both read that document; if the command moved or was duplicated, they need to follow it.'
    );
  }
  return found[0];
}

/** docs/VERIFYING.md as text. */
function readVerifyingDoc() {
  return readFileSync(VERIFYING, 'utf8');
}

/**
 * The two commands, as the deployed site should present them.
 *
 * No substitution here, unlike the release notes: the running site *is* the
 * deployment, so the document's identity — deploy.yml on refs/heads/main — is
 * already the correct one. The page prints them verbatim.
 */
function deploymentCommands(doc = readVerifyingDoc()) {
  return {
    cosign: extractBlock(doc, 'cosign verify-blob'),
    sums: extractBlock(doc, 'sha256sum -c SHA256SUMS'),
  };
}

module.exports = { extractBlock, readVerifyingDoc, deploymentCommands, VERIFYING };
