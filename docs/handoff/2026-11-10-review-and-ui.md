# Session refresh: full Keymaker-v2 review, fixes, and UI/UX exploration

Continuing work in the `404SecNotFound/Keymaker-v2` repository (branch `main`, at or after `4501cc0`). Goal of this session: finish the full codebase review, fix what it finds, say how to make the system better overall, and explore UI/UX design directions using the Refero MCP and the `refero-design` skill.

## Where things stand

- **Merged to `main` since the 22 October review.**
  - E3: `keym2.py` reads the audio carrier (#274).
  - Bet 4: the language-neutral vector pack, 94 vectors (#276).
  - Bet 5: duplicate shares count once, plus property tests (#275).
  - E4: `npm run typecheck` now covers `scripts/*.mts` and `reference/bridge.mts` (#278).
  - Two CI fixes: the command button's accessible name and the race-free pipe test (#277).
  - Dependabot bumps #269 to #272 and #280, and a later npm group bump (#286).
  - A Dependabot ignore rule for pycparser 3.12 and later, because the recovery kit's floor is Python 3.10 (#281).
  - The graphify code map under `graphify-out/` (#287).
- **Full review was started on 10 November and not finished.** Five parallel read-only reviewers were launched (TypeScript crypto core, Python recovery kit, app and UI, CI and supply chain, tests and docs truth). Their results were not collected and do not survive into this session. Run the review again.
- **Owner decisions still open.**
  1. Paper-part prefix: should a reader refuse an ignorable character inside `KMPART2:`? Recommendation was to keep accepting and write that into §7.
  2. Bet 1: the live site serves the release bytes, not `main`. Needs an identity change and the Pages environment policy.
  3. Bet 2: PBKDF2 page profile as the default for generated passphrases.
  4. Bet 3: public issues and an outside reader.
- **Known loose ends.**
  - Local `npm run build` sometimes stops with a Next.js `SecurityFatalError` notice and passes on retry. Next.js is now 16.4.3 or later. Whether the advisory is cleared is unverified. Run `npm audit`.
  - Over 150 stale remote branches. This session type gets HTTP 403 on branch deletion, so the owner deletes branches from their Mac or the GitHub UI.
  - `handoff/2026-10-22-review` is still to be deleted when the Bets are done.
  - The GitHub comment tool mangles `@dependabot` commands. Use "Update branch" instead, or the owner comments.

## Rules that are not in CLAUDE.md

- The owner merges. Merge only when they say "merge it" or "merge them all". Never force-push.
- Every fix ships with a test shown to fail with the fix removed, and the control must compile or build.
- Writing rules for PR text, commit messages and documents: no em-dashes, no colon mid-sentence, brief, label unverified claims as [Unverified] or [Inference]. Banned words include delve, unlock, elevate, navigate, journey, tailored, elegant, dive.
- Decided, do not reopen: the seed-phrase default output stays "File". The one-owner CODEOWNERS setup is intentional. `connect-src 'none'` is never relaxed. Never run `npx playwright install`.
- Branch protection requires a PR to be up to date with `main` before it merges.

## Next steps

1. Re-run the full review with parallel read-only reviewers on the five areas above. Each reviewer checks which October findings are fixed, verifies findings by trace or run, and proves weak tests by mutation. Keep machine load low: one suite at a time, no full Playwright runs in parallel.
2. Verify the serious findings yourself, then fix the safe ones as separate PRs with negative controls. Put anything needing an owner decision on a list.
3. Write `docs/reports/REVIEW-<date>.md`: ranked fixes, what was fixed since October, and the changes that would most improve the system.
4. UI/UX exploration. Load the `refero-design` skill first and follow its research-first method. Use the Refero MCP to find the best references for a security tool of this kind: encrypt and decrypt flows, recovery and inheritance wizards, key and secret handling, trust and verification screens, empty and error states, command menus. Produce two or three distinct design directions with the references behind each, and what each would change in the current app. Ask the owner which direction to prototype before changing any shipped UI.
5. Report in plain, brief language, with open decisions listed at the end.

## Files to open (read these, don't re-derive)

- `docs/reports/REVIEW-2026-10-22.md`: the previous full review, with P1 to P3 findings, the Bets, refuted findings and open decisions. The new review builds on it.
- `docs/reports/USABILITY-2026-09-29.md` and `docs/reports/UAT-2026-08-14.md`: earlier usability and UAT findings, the starting point for the UI/UX work.
- `docs/ROADMAP.md`: what is left and why.
- `graphify-out/GRAPH_REPORT.md`: generated map of the codebase, useful for orienting reviewers.
- `src/components/` and `src/app/`: the current UI that the design directions must be judged against.
- `docs/vectors/README.md`: the vector pack's rules, including append-only and erratum.
