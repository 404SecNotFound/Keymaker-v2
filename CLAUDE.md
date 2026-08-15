# Working in this repository

Notes for anyone — human or agent — picking this project up cold. Everything
here cost real time to learn at least once. It is deliberately short: this file
records what is *surprising*, not what is discoverable by reading the code.

The two documents that actually explain the project are
[`docs/ROADMAP.md`](docs/ROADMAP.md) (what is left and why) and
[`docs/FORMAT-V2-DESIGN.md`](docs/FORMAT-V2-DESIGN.md) (the normative KEYM v2
spec). Read the roadmap first.

---

## The order a format change happens in

**Design document → Python reference → TypeScript → fixtures.** Not negotiable,
and it is the reason the two implementations have never diverged.

1. Write the section in `docs/FORMAT-V2-DESIGN.md` first.
2. Implement it in `reference/keym2.py` **from that section alone**. This is the
   only thing in the project that tests the *prose* rather than the code, and it
   is what produced KM-14 and findings F5–F8.
3. Then the TypeScript.
4. Then fixtures, and then the parity gate.

**The parity gate must compare the emitted bytes, not just the round-trip.**
Two implementations decode each other's output happily while disagreeing about
how to *write* it. §4.6 had to compare share **strings**, §7.1 had to compare
part **strings**, and §7.2 had to compare the sentinel **block** — in each case a
container-only comparison passed on a real defect.

**Fixtures are append-only.** A fixture is a promise that a container written on
a particular day still opens. `scripts/keymaker-generate-fixtures.mts` skips any
fixture whose file already exists, so running it twice is a no-op — the guarantee
is structural rather than a matter of remembering.

> **Adding a fixture means updating two counts, in two languages.**
> `reference/crosstest2.py` and `scripts/keymaker-regression.mts` both assert the
> corpus size, deliberately, so a fixture that silently stopped being listed
> would stop being tested. Miss the second one and `npm run test:keymaker` fails
> with an off-by-one that looks like a corrupted corpus.

---

## Build and test traps

- **Never leave `out/` built with a base path before running Playwright.**
  `KEYMAKER_BASE_PATH=/Keymaker-v2 npm run build` makes every asset 404 under the
  test server, React never hydrates, and the failures present as *"element
  intercepts pointer events"* and two-minute timeouts that look like real UI
  bugs. Plain `npm run build` before browser tests. This cost ~40 minutes and a
  wrong diagnosis once already.

- **Never pipe Playwright through `| tail`.** You read `tail`'s exit code, which
  is always 0, so a failing suite reports success. Capture the real status:

  ```bash
  npx playwright test ... > /tmp/pw.log 2>&1; echo "EXIT=$?"
  ```

  The same trap applies to any `cmd | head`/`| tail` where you care about the
  result.

- **Use `--workers=2` locally** — CI's setting. At the default 4 the Argon2id
  calibration test times out on CPU contention; it passes alone in 1.3s.

- **Two known timing flakes**, both pre-existing: WebKit `paste-size.spec.ts`
  ("a 1 MiB single-line paste…") and Chromium `async-guard.spec.ts` ("switching
  tabs mid-derivation…"). On a lone timing failure, re-run the job and check
  whether `main` is red on the same test before treating it as real.

- **A fresh container may only have Chromium.** Firefox and WebKit binaries are
  often absent, and every test in those projects then fails with
  *"Executable doesn't exist"* — an environment fact, not a regression. Run
  `--project=chromium` locally and let CI cover the other two. Do **not** run
  `npx playwright install`.

- **`scripts/apply-csp-hashes.mjs` fails the build if `connect-src` is not
  `'none'`.** That is deliberate (KM-07). Design around it; do not relax it.

- **Node cannot run the TypeScript directly.** `--experimental-strip-types` is
  strip-only and `enum KdfId` is emitted code, and the crypto core lazy-imports
  `hash-wasm` and `@noble/ciphers`. Everything goes through
  `reference/bridge.mjs`, which esbuild-bundles `bridge.mts` first. A new
  capability that conformance needs to drive gets a new bridge subcommand.

---

## House rules

- **Commit as** `404SecNotFound <46477113+404SecNotFound@users.noreply.github.com>`.
  Never a personal address — history has been rewritten twice to remove one.
- **No assistant references** in commits, PR bodies or code comments, and never
  a model identifier in anything pushed.
- **Branch, push, open a PR. The owner merges.** Do not merge, and do not
  force-push without asking.
- **Watch out for backticks in `git commit -m "…"`.** A double-quoted message
  containing `` `var status = …` `` is command-substituted by the shell and the
  text silently disappears. Use `-F` with a file, or a quoted heredoc.
- **Verify a merge against `main`'s tree, not the merge status.** PR #23 was
  merged into an already-merged branch and silently landed nothing.
- **Stack PRs when items touch the same files.** 4.2 → 4.3 → 4.5 each based on
  the one below, so each PR shows only its own diff; GitHub retargets to `main`
  as they merge in order. The repo uses merge commits, so this is safe.

---

## Negative controls are the house rule

Every test must be **shown to fail** when the thing it tests is removed. Two
corollaries, both learned the hard way:

- **A control that does not build proves nothing.** Always confirm the patched
  source compiles (and, for browser tests, *builds*) before reading its result.
  A control that silently failed to apply looks exactly like a passing one.

- **A control that does not bite usually means the test is weak, not that the
  code is fine.** Three times in one session this was the cause rather than a
  false alarm: a conformance suite that never handed its extractor a page it
  should refuse; a key-file exclusion never checked against the TypeScript at
  all; and a threshold-clamp test that filled the threshold *before* shrinking
  the count, so the other input's bound did the work. Each looked like a
  redundant check and was actually a hole.

- **An unguarded call can hide a control's bite.** If a disagreement makes a
  helper *raise* rather than return a wrong answer, the suite crashes with a
  traceback instead of printing the one line naming the disagreement — and the
  control appears not to have worked. `bridge()`'s docstring records this;
  guard the calls that a real divergence would blow up.

---

## Executable documentation

Doc commitments have gates. Changing a CLI flag or a documented command breaks
the build **on purpose**:

- `reference/recovery_test.py` extracts every `bash` block from
  `docs/RECOVERY.md` **and** `docs/WALKTHROUGH.md` and runs it against a
  container the *shipping* encryptor produced. Assert the recovered bytes, not
  just the exit code — a decrypt that writes the wrong bytes still exits 0.
- `scripts/release-notes-test.mjs` binds the release notes to
  `docs/VERIFYING.md`, so editing either side alone fails.
- `docs/WALKTHROUGH.md`'s screenshots are generated by
  `scripts/capture-screenshots.mjs` from the production build, and every embedded
  image is checked to exist.

---

## Browser-page code (the self-extracting decryptor)

`src/lib/keym-v2-selfextract.ts` embeds a decryptor as source text, so it is
outside TypeScript's reach entirely — `tsc` will not look at it and the
conformance suite cannot run it. It is only checked by
`tests/browser/self-extract.spec.ts`.

One trap already paid for: **`var status = document.getElementById(…)` at global
scope does not create a variable.** `window.status` is a legacy string property,
so the element is coerced and every later use fails on a string. Suffix element
handles (`statusEl`), and assume anything in that file is only as correct as the
last time a browser ran it.

---

## Test commands

```bash
npm run typecheck          # tsc --noEmit
npm run test:crypto        # v1 crypto regression
npm run test:keymaker      # KEYM regression + the frozen corpus
npm run test:conformance   # v1 Python ↔ TypeScript parity
npm run test:keym2         # keym2.py self-test
npm run test:conformance2  # v2 Python ↔ TypeScript parity — the moat
npm run test:recovery      # executes RECOVERY.md and WALKTHROUGH.md
npm run test:wordlist
npm run test:release-notes

npm run build                                        # never with a base path first
npx playwright test --project=chromium --workers=2   # capture EXIT, do not pipe
```
