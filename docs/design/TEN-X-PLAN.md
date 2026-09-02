# The 10× plan — five bets, five PRs

The execution plan for the UX/IX bets that followed `UI-REVIEW.md`. That review
asked whether the interface should be replaced; the answer was no, and its four
items shipped (PRs #131–#133). This file is what comes next: the step-changes
that live in flows, inputs and moments of truth rather than in polish. Every
bet here lands inside the existing gates except the last, which names the one
rule it amends.

The organising fact: Keymaker *displays* QR codes everywhere and cannot *read*
one. The paper vault prints symbols the app cannot scan back. The heir — the
person the product exists for — types. The bets follow from taking that person
seriously, even though the bet that fixes it directly (Heir Mode) is on hold.

## Decisions already made

- **Bet 1 — Heir Mode (in-app camera scanning) is ON HOLD.** It adds a camera
  permission surface and, because `BarcodeDetector` is not available in every
  engine, almost certainly a QR-decoding dependency. That is a supply-chain
  decision the owner has not taken. Do not start it; do not add a decoder.
- **Bet 6's motion amendment is approved** by the instruction to execute every
  bet except Bet 1. The house order still applies: amend
  `DESIGN-SYSTEM.md § Motion` *first*, in the same PR, then write the code.
- **Five PRs, strictly in this order:** Bet 3 → Bet 4 → Bet 2 → Bet 5 → Bet 6.
  Each restarts the designated branch from `main` (the previous PR is merged
  by then), ships with its own spec and negative control, joins the gates, and
  is merged on green with a merge commit. One PR at a time; never stack.

## The pipeline every PR runs

The same pipeline the last four PRs ran. Do not skip steps to save time — each
one has caught something in this repository.

1. `git fetch origin main && git checkout -B claude/ui-design-review-sq9lke origin/main`
   (a merged branch is never reused; the push is a fast-forward from the merge
   commit, so no force is needed). Fresh container: `npm ci` first.
2. Implement. New surfaces use tokens only, icons at 14/16/20px, text ≥ 12px,
   no shadows, no accent, no cool grey. Sparks only in data-viz marks.
3. `npm run typecheck`, then `npm run build` (plain — never with a base path
   before Playwright).
4. The PR's own spec plus any spec it touches:
   `npx playwright test <files> --project=chromium --workers=2 > /tmp/pw.log 2>&1; echo EXIT=$?`
   — capture the exit code; never pipe through `tail`.
5. **Negative control, for real:** sabotage the feature in source, confirm the
   sabotaged build *compiles*, confirm the spec *fails* naming the defect,
   restore, rebuild. Record what was sabotaged and what bit in `STATUS.md`.
6. Add the new surface as a view in `scripts/palette-audit.mjs` (and
   `scripts/icon-audit.mjs` if it carries icons) so the sample counts rise —
   the count movement is the evidence the view is scanned. Run
   `npm run test:palette` and `npm run test:icons`.
7. Full suite: `npx playwright test --project=chromium --workers=2` (about
   5 minutes; 193 tests at the time of writing). Then
   `node scripts/capture-screenshots.mjs` against a static server on `out/`
   and `npm run test:screenshots` if anything visible changed.
8. A `STATUS.md` entry under "Done since this file was written", in the house
   voice: what changed, why, what was measured, what was sabotaged.
9. Commit as the repository author identity (see the house rules), message
   via `-F` file. Push. Open the PR against `main` with a body that states the
   verification. Subscribe to it, merge on green with a merge commit, then
   verify `main`'s **tree** carries the change — not the merge status.

## PR 1 — Bet 3: intent doors, and a real Seed Phrase mode

**Insight.** The first decision the page asks is the system's ("Encrypt /
Decrypt / Tools"), not the user's. A seed phrase is typed into a generic
textarea and *detected* afterwards with a tinted border. The defaults for a
passport scan and a 24-word seed are identical, and they should not be.

**Scope.**
- Three doors under the hero: *Back up a seed phrase* · *Encrypt a file* ·
  *Open a backup*. Tabs stay for power users; a door sets mode, input type and
  defaults (seed → text input in seed mode, shares suggested on, paper vault
  offered after seal). The anticipation rule applies: a door configures, it
  does not pre-render forms.
- **Seed mode** for the text input: a 12/24-word grid, per-word validation
  against `src/lib/bip39.ts` as you type, autocomplete from the list after a
  few letters, the checksum reported honestly in words ("word 7 is not on the
  list — did you mean *absorb*?"), never only as a colour. Repeated words are
  not an error (they are legal in a phrase). The existing seed-shaped
  detection and its tests keep working for the plain textarea.
- Nothing about the password policy, the generators or the crypto path
  changes. This is input design.

**Files.** `src/components/encryptor-tool.tsx` (hero, tabs, `renderContent`,
`handleModeChange`, `handleInputTypeChange`, the text-secret handlers and
`textSecretSeedStatus`), `src/lib/bip39.ts` (already lazy-loaded via
`loadBip39()`), `src/components/ui/*` for controls.

**Spec.** `tests/browser/seed-mode.spec.ts`: a door switches mode and defaults;
the grid accepts a valid 12-word phrase and reports the checksum; a misspelled
word is named by position with the suggestion; autocomplete completes a word
from its prefix; a phrase entered in the grid encrypts and decrypts to the same
words (byte authority — round-trip, not appearance). Negative control: break
the per-word validation and watch the misspelling test fail by name.

**Gates.** New palette/icon view: the seed grid with one flagged word. Word
cells are mono ≥ 12px; the flag is the semantic `danger` token used as text on
its own wash, never a new colour.

## PR 2 — Bet 4: the paper vault as a procedure

**Insight.** The sheet is already principled (level-M symbols, the procedure
on the page, a paper-only hint line — see the header comment in
`src/components/paper-vault.tsx`). But it is one document: shares that should
go to three different people are on one sheet; there is no "held by", no cut
lines, no place to record a rehearsal.

**Scope.**
- A cover block in plain language, three cells: *What this is* · *What you
  need* · *Do this* — written for someone who did not choose this tool.
- Per-share strips with cut lines and a "held by ________" label, one strip
  per envelope; the container symbols on the owner's copy.
- The byte map printed under the symbols (reuse `byteMapSpans` from
  `container-inspector.tsx` — export it; same widths, print-safe fills).
- A rehearsal box: "☐ Rehearsed on ____ with strips __ and __ · rehearse
  again by ____". PR 3 fills it in.
- The recovery-kit line stays and still names `keym2.py` and
  `docs/RECOVERY.md`. Nothing secret is printed automatically — that rule
  stands.

**Files.** `src/components/paper-vault.tsx`; its print styles (search
`paper-vault` / `pv-` in `src/app/globals.css`); `encryptor-tool.tsx` where
`paperVault` state and the print effect live.

**Spec.** Extend `tests/browser/paper-vault.spec.ts`: the printed DOM carries
the three cover cells, one strip per share with a "held by" label, the byte
map with one segment per share slot, and the rehearsal box. Negative
control: drop the strips and watch the per-share count fail.

**Gates.** Print CSS is outside the palette gate; hold it to the same standard
by eye and keep it monochrome on white except the byte map's two spark cuts.
`test:recovery` executes `docs/RECOVERY.md` and `docs/WALKTHROUGH.md` — if
the sheet's wording changes what those documents say, update them in the
same PR (`scripts/release-notes-test.mjs` binds the release notes to
`docs/VERIFYING.md`; leave that alone).

## PR 3 — Bet 2: rehearsal — test the backup before you trust it

**Insight.** Shares are shown once with a strong warning, then gone. The first
time anyone learns whether they work is the day they are needed. There is a
verify-only unlock (see `verifyOnly` in `encryptor-tool.tsx`), but nothing
walks the owner through the *heir's* path.

**Scope.**
- "Rehearse now" on the issued-shares dialog: choose any K of the N shares
  just issued, enter them as an heir would (paste; scanning is Bet 1 and on
  hold), run the identical decryption via the verify-only path, and report
  "opened in N s — contents kept hidden". A wrong share fails loudly.
- On success, the next print carries the rehearsal stamp filled in
  (date, which strips). The app stores nothing: the stamp is ink on paper and
  state is discarded with everything else in `clearSensitiveState`.
- Rehearsal never renders plaintext, never touches the clipboard, and never
  persists. It must fit inside the auto-lock and the `LockWarning` behaviour
  the dialog already has.

**Files.** `encryptor-tool.tsx` (the `issuedShares` dialog, `verifyOnly`, the
share-input path, `paperVault` state); `paper-vault.tsx` (the stamp fields).

**Spec.** `tests/browser/rehearsal.spec.ts`: after sealing with 2-of-3, the
rehearsal opens with two shares and reports success without ever rendering
the plaintext (assert the secret text is absent from the DOM); a wrong share
fails with a named error; the following print carries the filled stamp.
Negative control: make the rehearsal skip verification and watch the
wrong-share test pass-when-it-should-fail — i.e. assert it *fails* honestly.

**Gates.** New palette view: the rehearsal state of the shares dialog.

## PR 4 — Bet 5: trust you can test, not read

**Insight.** `connect-src 'none'` forbids every network request and the build
is reproducible with a signed manifest — and both live in a footer link and a
document. Every competitor *says* client-side; the user cannot tell the
difference.

**Scope.**
- A "Sealed" status in the inspector footer (it already says "runs in this
  tab · nothing is uploaded") that expands to plain language: this page is
  forbidden by policy from contacting any server — and shows the line that
  forbids it, read from the page's own CSP meta tag, not typed.
- "Try it": a calm offline notice — the app notices `navigator.onLine` is
  false and says encryption still works, because it does.
- "Verify this build" in place: compare the running bundle's chunk hashes to
  the signed manifest the build already ships (see `scripts/build-manifest.mjs`,
  `scripts/verify-manifest.mjs` and the verify page in `src/app/verify/`) and
  show the match — the verify page's logic brought to the moment of use.
- Every row must be a **structural fact the page can prove locally**, never
  live telemetry. A status light that could be wrong is worse than none; the
  inspector footer comment already records this rule.

**Files.** `container-inspector.tsx` (footer), `src/app/verify/page.tsx` and
whatever it imports to check hashes, `scripts/apply-csp-hashes.mjs` (to see
how the CSP is emitted — do **not** relax `connect-src`; the build fails on
purpose if it is not `'none'`).

**Spec.** `tests/browser/sealed-status.spec.ts`: the status expands and quotes
the actual `connect-src 'none'` directive from the served page; the in-place
verification reports a match against the shipped manifest; with the manifest
altered in the test fixture the verification reports a mismatch (the negative
control is built in — a verifier that cannot fail verifies nothing).

**Gates.** New palette view: the expanded status. Semantic `success` for the
checkmarks — data, not decoration.

## PR 5 — Bet 6: the seal as a ceremony, and a receipt instead of a toast

**Insight.** Press Encrypt → spinner → toast → the output appears. Correct,
and forgettable. The next steps (download, print, issue shares, rehearse) are
scattered across the form and the footer. The moment of completion is the one
moment the owner is certain to be paying attention.

**Scope — the rule first.** Amend `DESIGN-SYSTEM.md § Motion` before any code:
keep 150–250ms for everything, and add a scoped allowance — *moments of
completion* (a seal, a wipe) may run 400–600ms, still opacity/transform only,
still flattened by `prefers-reduced-motion`. Write it as a rule with the
reason, in the file's voice.

**Scope — the code.**
- While sealing, the inspector's byte map fills left to right as the bytes
  are written — stamp, fields, then slots — replacing the spinner as the
  progress indicator. Motion with meaning, inside the amended allowance.
- A receipt state replaces the success toast: what was written (name →
  name.keym), how it is protected (KDF · cipher), the ways in, "left this
  device: nothing", and three real buttons — *Print the paper vault*,
  *Rehearse recovery* (PR 3), *Download .keym*. The receipt is the entrance
  for PRs 2 and 3, which is why this PR is last.
- The wipe gets the same treatment: a deliberate act, a deliberate
  acknowledgment, no longer a toast that disappears.

**Files.** `encryptor-tool.tsx` (the encrypt completion path, `toast` calls,
`paperVault`, download handlers), `container-inspector.tsx` (a progress prop
for the byte map), `DESIGN-SYSTEM.md § Motion`, `STATUS.md`.

**Spec.** `tests/browser/receipt.spec.ts`: after sealing, the receipt lists
the output name, KDF and cipher exactly as the inspector does (same
authority); its buttons print, rehearse and download; with reduced motion
the byte-map fill is instant and the receipt still appears. Negative
control: break the receipt's KDF label and watch the authority assertion
fail.

**Gates.** No new colour. The amended motion rule is the only spec change in
the whole plan; say so in the PR body.

## What not to touch, in any PR

- The honesty register: no strength meter for typed passwords, ever. The app
  only states entropy it can prove.
- The gates: palette, icons, contrast, screenshots, the 12px floor. New
  surfaces become new views.
- No accent, no shadow, warm only. Sparks stay in data-viz marks.
- Secrets never persist. Rehearsal stamps live on paper; nothing new is
  stored anywhere; nothing new touches the clipboard.
- `connect-src 'none'`. The build fails on purpose if it changes.

## Bet 1, for when it is un-held

Heir Mode: in-app scanning of paper parts and shares inside Decrypt, a
viewfinder that requests the camera only on tap, "2 of 3 shares scanned"
progress, arrival detection when someone lands from the printed URL, and
zero-jargon copy. The decision it needs is the decoder dependency
(`BarcodeDetector` where present; a small, licence-vetted fallback where not).
Everything else in this plan is designed so that Heir Mode drops into flows
that already speak the heir's language.
