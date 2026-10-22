export const meta = {
  name: 'keymaker-issues-and-10x',
  description: 'Find verified issues across ten dimensions and build a judged 10x plan, then write a report for the coder',
  phases: [
    { title: 'Find', detail: 'ten finders, one dimension each' },
    { title: 'Verify', detail: 'three lenses per finding, majority keeps' },
    { title: 'Strategy', detail: 'five angles propose, three judges score' },
    { title: 'Report', detail: 'synthesize for the coder' },
  ],
}

const REPO = args.repo
const TODAY = args.today
const HEAD = args.headSha

const COMMON = `Repository: ${REPO} (branch main at ${HEAD}, ${TODAY}). It is Keymaker, a client-side browser encryption PWA (Next.js static export on GitHub Pages) with a specified container format (KEYM v1..v4), Shamir shares, passkey PRF slots, paper vault, self-extracting HTML decryptor, audio carrier, and an independent Python reference (reference/keym2.py, keym.py) held to byte parity by conformance suites. Three self-review security passes have just landed (see git log, SECURITY-AUDIT.md, docs/ROADMAP.md Phase 9 and the PR #267 description in git log -1 --format=%B). Zero open GitHub issues. Every roadmap phase is marked shipped except owner-only items.

You are READ-ONLY: do not edit, commit, build (no npm run build) or run Playwright. You may read any file, grep, run node scripts (scripts/*.mjs, npm run typecheck, npm run test:<name> for the node suites), python3 reference/*.py selftest, and write scratch scripts under /tmp/claude-0/-home-user-Keymaker-v2/b80cba88-e1fd-58b1-8477-ce4d198ec25e/scratchpad/ (esbuild is available; reference/bridge.mjs shows how the project bundles TS). Prefer confirming a claim by running something over reasoning alone, and say which you did.

Be brutally honest and specific. Every finding needs a file path (repo-relative) and, where it is code, a line number. No padding: if a dimension is in good shape, return fewer findings and say so in the summary. Severity: P0 = data loss, secret exposure or a user locked out of their backup; P1 = a real bug or a trust claim that is wrong; P2 = a gap that costs users or the maintainer real time; P3 = polish. Effort: S (< 2 h), M (a day), L (several days). Do not re-report what PR #267 just fixed (read its description first).`

const FINDINGS_SCHEMA = {
  type: 'object',
  properties: {
    summary: { type: 'string', description: 'Two or three sentences on the state of this dimension.' },
    findings: {
      type: 'array',
      maxItems: 12,
      items: {
        type: 'object',
        properties: {
          title: { type: 'string' },
          severity: { type: 'string', enum: ['P0', 'P1', 'P2', 'P3'] },
          area: { type: 'string' },
          file: { type: 'string' },
          line: { type: 'number' },
          what: { type: 'string', description: 'What the code or doc does today' },
          scenario: { type: 'string', description: 'Concrete input or user path to the failure or cost' },
          evidence: { type: 'string', description: 'What you ran or read to confirm it; say "reasoning only" if not confirmed' },
          fix: { type: 'string', description: 'Minimal fix, concrete' },
          effort: { type: 'string', enum: ['S', 'M', 'L'] },
          test: { type: 'string', description: 'The negative-control test that would pin it' },
        },
        required: ['title', 'severity', 'area', 'file', 'what', 'scenario', 'evidence', 'fix', 'effort'],
      },
    },
  },
  required: ['summary', 'findings'],
}

const DIMENSIONS = [
  {
    key: 'crypto-core',
    prompt: `Dimension: correctness of the crypto core and format readers, with fresh eyes. Files: src/lib/keym-v2.ts, src/lib/keymaker-crypto.ts, src/lib/crypto.ts, src/lib/keym-v2-shamir.ts, src/lib/keym-v2-paper.ts, src/lib/webauthn-prf.ts, src/lib/kdf-calibration.ts, against docs/FORMAT-V2-DESIGN.md, FORMAT-V3-DESIGN.md, FORMAT-V4-DESIGN.md. The last pass already checked allocation bounds, AAD coverage, nonces, constant-time compares and truncation; do not repeat those. Hunt instead for: error-path bugs (what happens on the second failure, on retry, on cancel mid-derivation), state carried between calls (module-level caches, lazy-import promises that memoise a rejection), version-dispatch edge cases (v1 vs v2/v3/v4 detection on short or ambiguous inputs, IttyBitz legacy path), key-file edge cases (empty, huge, binary vs text), Unicode/NFC handling of passwords across the three readers, calibration under throttled or hidden tabs, and anything where the TypeScript and the Python reference could legally disagree because the spec is silent. Use the fuzzers (scripts/keym2-fuzz.mts, keym3-fuzz.mts, keymaker-fuzz.mts) to see what is covered and probe what is not.`,
  },
  {
    key: 'state-hook',
    prompt: `Dimension: the React state machine. Files: src/components/encryptor/use-encryptor-state.ts (3,610 lines), src/components/encryptor/secret-form.tsx, src/components/encryptor/shared.ts, src/components/encryptor/*.tsx, src/lib/crypto-client.ts. Hunt for: stale closures in useCallback/useEffect deps, races between the opSeq/isStale guard and setState after unmount, effects without cleanup, re-entrancy (double-click Encrypt, Stop during each phase), toast/announcement duplication, error paths that leave the UI in a state the user cannot leave (spinner stuck, button disabled, mode switch mid-operation), the auto-lock and visibility handlers interacting with modals and file inputs, and any state that is derived twice and can disagree. Trace at least three complete user paths through processData (encrypt file with shares, decrypt paste with key file, verify) and say where each can go wrong. Confirm with code reading at exact lines; where a node-level repro is feasible via crypto-client.ts, run it.`,
  },
  {
    key: 'ux-product',
    prompt: `Dimension: product and UX gaps. Read docs/WALKTHROUGH.md, docs/reports/USABILITY-2026-09-29.md, docs/reports/UAT-2026-08-14.md, docs/HOW-IT-WORKS.md and the component tree under src/components. Walk the flows as (a) a first-time user who wants to back up a seed phrase, (b) an heir holding a printed vault and a USB stick ten years later, (c) a power user with a 100 MB file. Identify friction, dead ends, copy that misleads, missing affordances (undo, progress, estimates, what-happens-next), inconsistent terminology across app, docs and Python CLI, and places where the app asks for a decision the user cannot make. Check the disclaimer strip, the inheritance wizard, the printout check, the verify page and the docs tab. Also assess mobile: what in the layout or interaction model will break on a 390px phone with a software keyboard (roadmap 6.5 says no one has opened it on a phone). Rate each by how many users it costs, not by how annoying it is.`,
  },
  {
    key: 'tests-ci',
    prompt: `Dimension: test suite and CI health. Read package.json scripts, .github/workflows/*.yml, playwright.config.ts, tests/browser/*.spec.ts (list them, read the largest and the flaky ones named in CLAUDE.md), scripts/*-test.mjs, reference/crosstest2.py, reference/recovery_test.py. Measure what you can: count tests per engine, find duplicated helpers across specs, find tests that assert nothing (no expect) or that would pass with the feature removed, find timing-based waits (waitForTimeout), find the two documented flakes and say whether they can be made deterministic. Assess CI: wall-clock per workflow from the last main runs if visible in logs or comments, what runs on every PR that could run nightly, what is not covered at all (self-extract on Firefox/WebKit, worker fallback in a real browser, base-path deploy layout, Windows Python), and whether the fixture corpus counts are still asserted in both languages. Propose concrete restructurings with their time savings.`,
  },
  {
    key: 'code-health',
    prompt: `Dimension: maintainability and architecture. The three largest files are src/components/encryptor/use-encryptor-state.ts (3,610 lines), src/lib/keym-v2.ts (2,828) and src/components/encryptor/secret-form.tsx (1,889); reference/keym2.py is also very large. Assess: module boundaries and what a split would look like (name the seams by function groups and line ranges), duplicated constants restated across files (keymaker-crypto.ts restates format constants from keym-v2.ts and keym2-dispatch asserts them; list every such pair), dead code and unused exports (run a quick check with grep or a small script), TypeScript strictness settings and any-escapes, lint configuration, the dependency surface (package.json: what is unused, what is pinned, Next.js/React as the largest risk per ROADMAP), bundle composition (hash-wasm inlined as base64 in both the worker and a page chunk), and the esbuild bridge pattern that every test re-implements. Produce a refactor plan a solo developer could execute in increments without a flag day, with the first three steps and the test that guards each.`,
  },
  {
    key: 'docs-heir',
    prompt: `Dimension: documentation accuracy and the heir path. Read README.md, docs/RECOVERY.md, docs/WALKTHROUGH.md, docs/VERIFYING.md, docs/HOW-IT-WORKS.md, SECURITY-AUDIT.md, SECURITY.md if present, docs/FORMAT.md, reference/README.md, public/recovery/*, CHANGELOG.md if present. Check every claim against the code at this commit: version numbers, command lines, file names, counts ("two mainstream libraries", test counts), the KDF floors, what is and is not audited, the self-review wording landing in PR #268, the verify commands, Python version floor. Then take the heir's view: someone with the recovery kit and no author. What is missing, out of order, or assumes knowledge? Is pip install hash-pinned? Does the kit say what to do on Windows? Is there a single printable one-page "if you are reading this, do these five things"? Report drift as P1 where the doc is wrong and P2 where it is merely incomplete.`,
  },
  {
    key: 'performance',
    prompt: `Dimension: performance and resource use. Files: src/lib/crypto-worker.ts, src/lib/crypto-client.ts, src/lib/kdf-calibration.ts, src/lib/keym-v2.ts chunking, src/lib/keymaker-crypto.ts, public/sw.js, scripts/build-crypto-worker.mjs, scripts/apply-build-id.mjs, next.config.*, the paper vault renderer (src/components/paper-vault.tsx, src/lib/keym-v2-paper.ts) and QR decode (src/lib/qr-decode.ts). Measure what you can in node: time to bundle, size of public/crypto-worker.js (is it in git? check .gitignore) and how much is the inlined Argon2 wasm base64, chunk sizes vs memory at the 100 MB cap (peak allocations through encrypt and decrypt, counting copies), Argon2 calibration bounds and what a slow phone gets, service-worker precache size and first-load cost, and the cost of printing a many-part paper vault. Identify the three biggest wins for first paint, first encrypt and the 100 MB path, each with an estimate and a way to measure it in CI so it cannot regress.`,
  },
  {
    key: 'security-residual',
    prompt: `Dimension: what a professional auditor would still flag. Read SECURITY-AUDIT.md, docs/AUDIT-BRIEF.md, the PR #267 description (git log -1 --format=%B dd5b350) and its "Found and deliberately not changed" list, scripts/shamir-adversarial.mts, .github/workflows/*.yml (action pinning by SHA, permissions blocks, pull_request_target use, artifact flow between build and sign), .github/dependabot.yml, scripts/sign-manifest.mjs, verify-manifest.mjs, release-gate-test.mjs, public/recovery/requirements.txt. Do not repeat fixed items. Hunt for: supply-chain gaps (any action not SHA-pinned, any workflow with write permissions it does not need, token scopes), the forged-low-index-share problem and whether a safe fix exists (try other k-subsets on unwrap failure: cost and leakage analysis), hash-pinning of the recovery kit's pip install, the threat-model document's honesty gaps (what is claimed vs what the shared github.io origin allows), and the residual risk register a reader of SECURITY-AUDIT.md would want. Also assess the three self-review passes themselves: what kind of defect would they systematically miss, and what independent check (fuzzing campaign, property tests, formal spec of the slot walk, external audit scope) would close that.`,
  },
  {
    key: 'accessibility',
    prompt: `Dimension: accessibility. Read tests/browser/a11y.spec.ts, uat-a11y.spec.ts, docs/ROADMAP.md 2.7 and 5.3, src/app/globals.css (the Signal Blue tokens), docs/design/*, and the components. Check: keyboard-only completion of encrypt, decrypt, shares modal, paper vault print, camera scan, command menu and the wipe; focus management when modals open and close and when the auto-lock clears the form; live-region announcements (toasts, status, the clipboard countdown, the disclaimer strip role=note); contrast of every token pair in both themes (compute it from the hex values in globals.css); touch target sizes; reduced-motion handling; screen-reader labels on icon-only buttons; the printed vault and the self-extracting page as documents. Say which checks axe already covers in CI and which it cannot (keyboard paths, focus order, announcements). Each finding needs the component and line.`,
  },
  {
    key: 'python-reference',
    prompt: `Dimension: the Python reference and conformance. Files: reference/keym2.py, reference/keym.py, reference/crosstest.py, crosstest2.py, recovery_test.py, bridge.mts, scripts/pin-conformance-deps.py, reference/README.md, docs/RECOVERY.md. Run the selftests and read the conformance harness. Assess: CLI usability for an heir (help text, error messages, exit codes, prompts), Windows and macOS gaps (O_NOFOLLOW, fcntl, mkfifo, getpass), packaging (no pyproject, no pip install, no checksummed single-file release of keym2.py itself: how does an heir know their copy of keym2.py is genuine?), the size and structure of keym2.py (6,000+ lines in one file: is that the right call for a durable artefact, and what would a reader in 2036 need), what conformance covers and does not (list the subcommands and flags exercised by crosstest2.py vs those that exist), fuzzing of the Python side, and version/feature parity with the TypeScript (v4 padded, audio carrier, self-extract, paper parts, passkey PRF via --prf-output). Propose the three changes that most raise the heir's odds.`,
  },
]

phase('Find')
log(`Running ${DIMENSIONS.length} finders`)
const found = await parallel(
  DIMENSIONS.map((d) => () =>
    agent(`${COMMON}\n\n${d.prompt}\n\nReturn at most 12 findings, most severe first, plus a summary.`, {
      label: `find:${d.key}`,
      phase: 'Find',
      schema: FINDINGS_SCHEMA,
    }).then((r) => (r ? { key: d.key, ...r } : null))
  )
)
const finders = found.filter(Boolean)
const missing = DIMENSIONS.filter((d) => !finders.some((f) => f.key === d.key)).map((d) => d.key)
if (missing.length) log(`Finders that returned nothing: ${missing.join(', ')}`)

// Dedup across finders by file + line + title stem. Different titles on the same
// line survive; the report synthesizer merges those.
const seen = new Map()
for (const f of finders) {
  for (const x of f.findings) {
    const key = `${x.file}:${x.line ?? ''}:${x.title.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim().slice(0, 48)}`
    if (!seen.has(key)) seen.set(key, { ...x, dimension: f.key })
  }
}
const candidates = [...seen.values()]
log(`${candidates.length} candidate findings after dedup (${finders.reduce((n, f) => n + f.findings.length, 0)} raw)`)

const VERDICT_SCHEMA = {
  type: 'object',
  properties: {
    real: { type: 'boolean', description: 'true only if you could not refute it' },
    severity: { type: 'string', enum: ['P0', 'P1', 'P2', 'P3'], description: 'Your own severity, after checking' },
    reasoning: { type: 'string' },
    checked: { type: 'string', description: 'What you ran or read' },
  },
  required: ['real', 'severity', 'reasoning', 'checked'],
}

const LENSES = [
  { name: 'refute', prompt: 'Your job is to REFUTE this finding. Read the exact file and line, trace the real callers and inputs, and look for the guard, test or design note that already handles it. If you cannot find a concrete, reachable failure, set real=false. Default to refuted when uncertain.' },
  { name: 'reproduce', prompt: 'Your job is to REPRODUCE this finding. Where a node or python repro is feasible (the esbuild bridge, scripts/*, reference/*.py), write one in the scratchpad and run it; where it is a UI path, trace the exact component code and say which line produces the described behaviour. real=true only if the repro or the trace holds.' },
  { name: 'worth', prompt: 'Your job is to judge whether this is WORTH FIXING as described. Assume it is technically accurate; ask whether a real user or the maintainer is hurt, whether the proposed fix is proportionate, and whether it conflicts with a deliberate design decision recorded in docs/ROADMAP.md (the Cut table and Honest framing), CLAUDE.md, SECURITY-AUDIT.md or a code comment. real=false if it is already handled, by design, or not worth its code.' },
]

phase('Verify')
const verifyOne = async (finding) => {
  const lenses = finding.severity === 'P3' ? [LENSES[0]] : LENSES
  const votes = (
    await parallel(
      lenses.map((lens) => () =>
        agent(
          `${COMMON}\n\nA finder reported this (dimension ${finding.dimension}):\n${JSON.stringify(finding, null, 2)}\n\nLens: ${lens.name}. ${lens.prompt}`,
          { label: `verify:${lens.name}:${finding.file.split('/').pop()}`, phase: 'Verify', schema: VERDICT_SCHEMA }
        )
      )
    )
  ).filter(Boolean)
  const real = votes.length > 0 && votes.filter((v) => v.real).length * 2 > votes.length
  // Severity settles to the most common verdict, falling back to the finder's.
  const sev = votes.map((v) => v.severity).sort()[Math.floor(votes.length / 2)] ?? finding.severity
  return { ...finding, verified: real, votes, settledSeverity: sev }
}

const PROPOSALS_SCHEMA = {
  type: 'object',
  properties: {
    proposals: {
      type: 'array',
      maxItems: 8,
      items: {
        type: 'object',
        properties: {
          title: { type: 'string' },
          what: { type: 'string', description: 'Concrete, two to four sentences' },
          why_10x: { type: 'string', description: 'The mechanism by which this multiplies value, not adjectives' },
          who_benefits: { type: 'string' },
          effort: { type: 'string', enum: ['S', 'M', 'L', 'XL'] },
          risk: { type: 'string', description: 'What it could cost in trust, scope or maintenance' },
          dependencies: { type: 'string' },
          first_step: { type: 'string', description: 'What the coder does in the first two hours' },
          measure: { type: 'string', description: 'How you would know it worked' },
        },
        required: ['title', 'what', 'why_10x', 'who_benefits', 'effort', 'risk', 'first_step', 'measure'],
      },
    },
  },
  required: ['proposals'],
}

const ANGLES = [
  { key: 'adoption', prompt: 'Angle: adoption and distribution. Who is the user today and who could be, what stops a stranger from trying it, what would make ten times more people use it and keep using it. Consider the GitHub presence, the live site, the hosted-instance trust posture in docs/HOW-IT-WORKS.md, mobile, install as PWA, the docs tab, and the outreach drafts in docs/OUTREACH.md. Be concrete about channels and about what the product must be able to show in the first thirty seconds.' },
  { key: 'assurance', prompt: 'Angle: trust and assurance. What would make a sceptical security professional trust this ten times more than they do today. Consider: an external audit and its scope, a public fuzzing corpus and continuous fuzzing, property-based tests against the spec, a machine-checkable spec of the slot walk, a bug bounty or disclosure policy, SLSA level, reproducibility verified by third parties, a test vector suite other implementations could run, and what the three self-review passes structurally cannot find. Say what is cheap and what is not.' },
  { key: 'engineering', prompt: 'Angle: engineering leverage. What architecture or tooling changes would let one developer ship ten times faster without breaking the parity moat. Consider: splitting the 3,610-line state hook and the 2,828-line format module, a typed page-to-worker protocol, a shared esbuild test harness, CI that runs the slow suites nightly, deterministic replacements for the timing flakes, a design-token pipeline, and making the Python reference importable as a package. Name the seams.' },
  { key: 'ecosystem', prompt: 'Angle: ecosystem and interop. What would make Keymaker containers and shares useful outside this app: a documented stable library API (npm package of the format core with no React), a CLI, a reference in a second language (Go or Rust) to prove the spec, integration points for hardware or software wallets and password managers, a browser extension, interop with age or OpenPGP for the payload only, and a format registration (magic bytes, MIME type). Respect the ROADMAP Cut table: do not propose what it cut unless you argue why the reason no longer holds.' },
  { key: 'focus', prompt: 'Angle: the contrarian. Argue what to STOP doing and what to cut further so the remaining effort compounds: features that dilute the thesis "verifiable, zero-server encryption whose files outlive the tool", documentation that no one reads, tests that cost more than they protect, and ambitions in the other angles that would damage the trust claims. Then say which two or three bets you would actually make, and why those compound.' },
]

const SCORES_SCHEMA = {
  type: 'object',
  properties: {
    scores: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          title: { type: 'string', description: 'Exact proposal title' },
          impact: { type: 'number', description: '1-5, on the thesis and on users' },
          feasibility: { type: 'number', description: '1-5, for one developer in the next quarter' },
          trust: { type: 'number', description: '1-5, 5 = strengthens the trust claims, 1 = endangers them' },
          note: { type: 'string', description: 'One sentence, the decisive consideration' },
        },
        required: ['title', 'impact', 'feasibility', 'trust', 'note'],
      },
    },
    best_three: { type: 'array', items: { type: 'string' }, description: 'Titles of the three you would fund first' },
  },
  required: ['scores', 'best_three'],
}

const strategy = async () => {
  phase('Strategy')
  const panels = (
    await parallel(
      ANGLES.map((a) => () =>
        agent(
          `${COMMON}\n\nYou are one of five strategists asked how to take this project ten times further from here. Read docs/ROADMAP.md (especially the Cut table, Honest framing and Sequencing), README.md, docs/HOW-IT-WORKS.md, docs/OUTREACH.md, SECURITY-AUDIT.md and enough code to be concrete. ${a.prompt}\n\nReturn five to eight proposals. Each must name a mechanism, not a wish.`,
          { label: `strategy:${a.key}`, phase: 'Strategy', schema: PROPOSALS_SCHEMA }
        ).then((r) => (r ? { angle: a.key, ...r } : null))
      )
    )
  ).filter(Boolean)
  const all = panels.flatMap((p) => p.proposals.map((x) => ({ ...x, angle: p.angle })))
  log(`${all.length} proposals from ${panels.length} angles; scoring`)
  const judges = (
    await parallel(
      ['a security engineer who has audited browser crypto', 'a solo maintainer of a widely used open-source tool', 'a product lead who has launched privacy tools'].map((who, i) => () =>
        agent(
          `${COMMON}\n\nYou are ${who}. Score every proposal below on impact (1-5), feasibility for one developer in a quarter (1-5) and effect on the trust claims (1-5, 5 strengthens). Read docs/ROADMAP.md's Cut table and Honest framing first and penalise anything that contradicts them without a new argument. Be harsh on proposals that are adjectives. Then name the three you would fund first.\n\nProposals:\n${JSON.stringify(all, null, 2)}`,
          { label: `judge:${i + 1}`, phase: 'Strategy', schema: SCORES_SCHEMA }
        )
      )
    )
  ).filter(Boolean)
  return { all, judges }
}

// Verification and strategy are independent; run them side by side.
const [verified, strat] = await parallel([
  () => parallel(candidates.map((c) => () => verifyOne(c))),
  strategy,
])
const results = (verified ?? []).filter(Boolean)
const kept = results.filter((r) => r.verified)
const dropped = results.filter((r) => !r.verified)
log(`${kept.length} findings survived verification, ${dropped.length} refuted`)

// Aggregate judge scores per proposal title.
const tally = new Map()
for (const j of (strat?.judges ?? [])) {
  for (const s of j.scores) {
    const t = tally.get(s.title) ?? { title: s.title, n: 0, impact: 0, feasibility: 0, trust: 0, notes: [], funded: 0 }
    t.n++; t.impact += s.impact; t.feasibility += s.feasibility; t.trust += s.trust; t.notes.push(s.note)
    tally.set(s.title, t)
  }
  for (const b of j.best_three ?? []) {
    const t = tally.get(b); if (t) t.funded++
  }
}
const ranked = [...tally.values()]
  .map((t) => ({ ...t, impact: t.impact / t.n, feasibility: t.feasibility / t.n, trust: t.trust / t.n, score: (t.impact + t.feasibility + t.trust) / t.n }))
  .sort((a, b) => b.score - a.score || b.funded - a.funded)
const proposals = (strat?.all ?? []).map((p) => ({ ...p, judged: ranked.find((r) => r.title === p.title) ?? null }))

phase('Report')
const report = await agent(
  `${COMMON}\n\nYou are writing the report for the coder who will act on it. Inputs: (1) the verified findings with their votes, (2) the refuted findings (list them briefly in an appendix so the coder knows they were checked and why they were dropped), (3) the finders' dimension summaries, (4) the 10x proposals with the judges' aggregated scores and notes.\n\nWrite in Markdown. Structure:\n# Keymaker review, ${TODAY}\nOne paragraph: state of the project at ${HEAD} and the headline.\n## 1. Fix first (P0 and P1)\nEach as a numbered item: title; file and line; what happens today; the scenario; the fix; the test that pins it; effort. Merge duplicates that describe the same defect from different finders.\n## 2. Worth a day each (P2)\nSame shape, shorter.\n## 3. Polish (P3)\nOne line each.\n## 4. Quick wins\nThe items from above a coder can land in a single afternoon, as a checklist.\n## 5. The 10x plan\nRank the proposals by the judges' scores, group into: Bets (fund now), Enablers (do first because the bets need them), Later, and Rejected (with the judge's decisive note). For each Bet give the mechanism, the first two hours, the measure, and the risk. Then a sequenced 90-day plan in three 30-day blocks, naming what ships at the end of each block and which findings from sections 1 and 2 it absorbs.\n## 6. What not to do\nFrom the contrarian angle and the ROADMAP Cut table.\n## 7. Open decisions for the owner\nThings only the owner can decide, with the question and the trade-off.\n## Appendix A. Refuted findings\n## Appendix B. Dimension summaries\n\nStyle rules, mandatory: plain direct English; no em-dashes anywhere (use a comma, a full stop or parentheses); never use a colon in the middle of a sentence, restructure instead (a colon is allowed only inside a verbatim file, command or rule name, and in Markdown table cells and after a heading-style label at the very start of a line such as "Fix." is fine but "Fix:" is not); do not use any of these words: hurdles, bustling, harnessing, unveiling, realm, depicted, demystify, insurmountable, new era, poised, unravel, entanglement, unprecedented, eerie, unliving, beacon, unleash, delve, enrich, multifaceted, elevate, discover, supercharge, unlock, tailored, elegant, dive, ever-evolving, pride, meticulously, grappling, weighing, picture, architect, adventure, journey, embark, navigate, navigation, dazzle. Label anything not confirmed by a run or a code trace with [Unverified] at the start of the sentence. Keep file paths repo-relative. Be specific and brutally honest; the reader is an experienced engineer.\n\nVerified findings:\n${JSON.stringify(kept.map(({ votes, ...k }) => ({ ...k, votes: votes.map((v) => ({ lens: v.checked?.slice(0, 160), real: v.real, severity: v.severity, reasoning: v.reasoning })) })), null, 1)}\n\nRefuted findings:\n${JSON.stringify(dropped.map((d) => ({ title: d.title, file: d.file, line: d.line, dimension: d.dimension, why: d.votes.filter((v) => !v.real).map((v) => v.reasoning).join(' | ').slice(0, 600) })), null, 1)}\n\nDimension summaries:\n${JSON.stringify(finders.map((f) => ({ dimension: f.key, summary: f.summary })), null, 1)}\n\nProposals with judge scores:\n${JSON.stringify(proposals, null, 1)}\n\nReturn only the Markdown document.`,
  { label: 'report', phase: 'Report', effort: 'high' }
)

return { report, kept: kept.length, dropped: dropped.length, candidates: candidates.length, missing, proposals: proposals.length, ranked: ranked.slice(0, 10) }