#!/usr/bin/env node
/**
 * The release rebuild recipe in docs/VERIFYING.md sets what release.yml sets.
 *
 * A release is not the deployment with a different signature. next.config.js
 * reads KEYMAKER_RELEASE_TAG and compiles the answer into a content-hashed
 * chunk, so a build with the tag set and one without differ in that chunk,
 * in every file that names it, and in the service worker's precache list:
 * six manifest entries, measured. The document said a release was "directly
 * comparable to the deployment" and told the reader to rebuild it with the
 * deployment's command, which does not set the tag. A verifier following
 * that got a diff and was told, by the same document, to treat a diff as
 * "the published source is not what was deployed".
 *
 * So the recipe is bound to the workflow here, the way release-notes-test.mjs
 * binds the notes to the same document: every KEYMAKER_* variable the
 * workflow's build step sets appears on the recipe's build line with the same
 * value, and nothing else does. Static, seconds, on every PR, because a release
 * runs on a tag, which is too late to learn the document drifted.
 *
 * ## What "the same value" means for the tag
 *
 * The workflow sets `${{ github.ref_name }}`, the tag being built; the
 * document cannot know a tag in advance and writes `<tag>`. Those are the same
 * instruction. Anything else on either side, a literal version or a different
 * expression, is a drift.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

let failures = 0;
function check(name, ok, detail) {
  if (ok) {
    console.log(`  ok   ${name}`);
  } else {
    failures++;
    console.error(`  FAIL ${name}${detail ? `\n       ${detail}` : ''}`);
  }
}

/** The `env:` block of the one build step in a workflow, as name → value. */
function buildStepEnv(workflowPath) {
  const text = readFileSync(join(ROOT, '.github', 'workflows', workflowPath), 'utf8');
  // The step whose `run:` is the build, then its env block: lines indented
  // deeper than `env:` until the indentation comes back out.
  const steps = [...text.matchAll(/^(\s*)- run: npm run build\s*\n((?:\1  .*\n)*)/gm)];
  if (steps.length !== 1) {
    throw new Error(
      `${workflowPath}: expected exactly one \`- run: npm run build\` step, found ${steps.length}. ` +
        'This gate reads that step\'s env: block; with two it would be guessing which one publishes.'
    );
  }
  const body = steps[0][2];
  const env = {};
  const envBlock = body.match(/^\s*env:\s*\n((?:\s+[A-Z_]+:.*\n)*)/m);
  for (const line of (envBlock?.[1] ?? '').split('\n')) {
    const m = /^\s*([A-Z_]+):\s*(.*?)\s*$/.exec(line);
    if (m) env[m[1]] = m[2].replace(/^['"]|['"]$/g, '');
  }
  return env;
}

/** The `VAR=value ... npm run build` line of a bash block, as name → value. */
function recipeEnv(block) {
  const lines = block.split('\n').filter((l) => /npm run build\s*$/.test(l));
  if (lines.length !== 1) {
    throw new Error(`expected exactly one \`npm run build\` line in the recipe, found ${lines.length}`);
  }
  const env = {};
  for (const m of lines[0].matchAll(/([A-Z_]+)=(\S+)/g)) env[m[1]] = m[2];
  return env;
}

const doc = readFileSync(join(ROOT, 'docs', 'VERIFYING.md'), 'utf8');
const blocks = [...doc.matchAll(/```bash\n([\s\S]*?)```/g)].map((m) => m[1]);

// ---- 1. The variable is still the one the build reads ----

const nextConfig = readFileSync(join(ROOT, 'next.config.js'), 'utf8');
check(
  'next.config.js still reads KEYMAKER_RELEASE_TAG',
  nextConfig.includes('process.env.KEYMAKER_RELEASE_TAG'),
  'the label moved to another variable; this gate and the document both name the old one'
);

// ---- 2. The release recipe sets what release.yml sets ----

const releaseBlocks = blocks.filter((b) => b.includes('KEYMAKER_RELEASE_TAG='));
check(
  'docs/VERIFYING.md has exactly one release rebuild recipe',
  releaseBlocks.length === 1,
  `found ${releaseBlocks.length} bash blocks setting KEYMAKER_RELEASE_TAG`
);

if (releaseBlocks.length === 1) {
  const workflow = buildStepEnv('release.yml');
  const recipe = recipeEnv(releaseBlocks[0]);
  const workflowVars = Object.keys(workflow).filter((k) => k.startsWith('KEYMAKER_')).sort();
  const recipeVars = Object.keys(recipe).sort();

  check(
    'the recipe sets every KEYMAKER_* variable release.yml sets, and no other',
    JSON.stringify(workflowVars) === JSON.stringify(recipeVars),
    `release.yml: ${workflowVars.join(', ') || 'none'}; recipe: ${recipeVars.join(', ') || 'none'}`
  );
  check(
    'release.yml sets the tag it is building',
    workflow.KEYMAKER_RELEASE_TAG === '${{ github.ref_name }}',
    `found ${JSON.stringify(workflow.KEYMAKER_RELEASE_TAG)}`
  );
  check(
    'the recipe substitutes the tag rather than naming one',
    recipe.KEYMAKER_RELEASE_TAG === '<tag>',
    `found ${JSON.stringify(recipe.KEYMAKER_RELEASE_TAG)}`
  );
  check(
    'the recipe builds with the base path release.yml builds with',
    recipe.KEYMAKER_BASE_PATH !== undefined && recipe.KEYMAKER_BASE_PATH === workflow.KEYMAKER_BASE_PATH,
    `release.yml: ${JSON.stringify(workflow.KEYMAKER_BASE_PATH)}; recipe: ${JSON.stringify(recipe.KEYMAKER_BASE_PATH)}`
  );
  check(
    'the recipe checks out the tag before building',
    /^git checkout <tag>\s*$/m.test(releaseBlocks[0]),
    'a release rebuilt from another commit is not a check of the release'
  );
}

// ---- 3. The deployment recipe does not set it ----
//
// deploy.yml builds without the tag, so a rolling deployment says `-dev`. A
// deployment recipe that set it would produce the release's bytes and fail
// against the live site for the mirror-image reason.

const deploy = buildStepEnv('deploy.yml');
check(
  'deploy.yml does not label its build as the release',
  !('KEYMAKER_RELEASE_TAG' in deploy),
  'if the deployment is now labelled, the deployment recipe and this gate both need to follow'
);
const deploymentBlocks = blocks.filter(
  (b) => /npm run build\s*$/m.test(b) && !b.includes('KEYMAKER_RELEASE_TAG=')
);
check(
  'the deployment rebuild recipes exist and build without the tag',
  deploymentBlocks.length >= 1 &&
    deploymentBlocks.every((b) => recipeEnv(b).KEYMAKER_BASE_PATH === deploy.KEYMAKER_BASE_PATH),
  `found ${deploymentBlocks.length} deployment recipe(s); deploy.yml base path ${JSON.stringify(deploy.KEYMAKER_BASE_PATH)}`
);

console.log();
if (failures > 0) {
  console.error(`${failures} check(s) failed.`);
  console.error('docs/VERIFYING.md and the release workflow disagree about how a release is built.');
  process.exit(1);
}
console.log('All checks passed: the release rebuild recipe matches release.yml.');
