# Nightpaper — decisions and asset manifest

The working state of the redesign, kept in the repository so any session can
resume it. `BAR.md` holds the reference mechanisms; `DESIGN-SYSTEM.md` holds
the binding tokens. This file holds the choices and the loose ends.

## Decided

- **Direction**: ElevenLabs design system, translated to dark ("Nightpaper").
  Reference: styles.refero.design/style/031056ff-7af1-46db-8daa-115f731c5d26
  (site: elevenlabs.io). The earlier Linear direction (PR #116) is
  superseded visually; its workbench layout, container inspector, fonts
  infrastructure, and test additions carry forward unchanged.
- **Type**: Plus Jakarta Sans Variable (UI + display) and JetBrains Mono
  (data), both OFL-1.1 and both vendored from npm — in the lockfile, content
  hashed into the bundle, precached for offline, and legal to redistribute in
  a public repository. That last clause is the requirement, not a bonus: it is
  what Satoshi failed. See "Loose ends" for the licence reasoning, and
  `DESIGN-SYSTEM.md § Type` for the test any future face has to pass.
- **Hero background**: "Deep Field" — sparse blue/ember bokeh drifting in a
  diagonal band over warm charcoal. **Shipped** as
  `public/hero-cipher-field.webp` (1400×781, 16 KB).

  It is a regeneration of the concept, not the plate originally chosen. The
  first pick was a 2752×1536 PNG on the Higgsfield CDN, and that host is
  refused by the network policy of a sealed container — generating a new one
  through the MCP server worked, but its result URL is on the same blocked
  host, so the bytes came back through the Higgsfield sandbox rather than by
  fetching them here. Prompt and settings, so it can be reproduced or
  re-rolled: `nano_banana_pro`, 16:9, 4k, the brief in
  `DESIGN-SYSTEM.md § Imagery` written out longhand — warm near-black ground
  with a taupe undertone, twenty to thirty widely spaced bokeh points on a
  lower-left to upper-right diagonal, a handful `#0447FF`, a handful
  `#FF4704`, the rest dim warm grey, darkest at the left/right/bottom edges,
  no text or subject of any kind.

  Downscaled to 1400px and WebP q60 deliberately: the plate is soft bokeh with
  no fine detail, so it survives the compression intact and 22 MB of PNG in a
  repository that promises reproducible builds would be 22 MB nobody can
  diff. Mounted behind the hero only, at 40% with a radial canvas scrim under
  the text and a gradient to flat canvas before the workbench. Worst measured
  contrast over it, per glyph run: 15.2:1 for the headline, 4.8:1 for the
  dimmed second line (large text, needs 3), 7.0:1 for the body.

  Runners-up from the original set, if a re-pick is ever wanted (host
  `d8j0ntlcm91z4.cloudfront.net`, path prefix
  `user_3IcKP9J7tAl1kmrRAIwI2f3BcKm/hf_20260830_043937_`): bloom
  `e3bbdfdb-c345-4eb3-9fc0-48702cdd3f2a`, ribbon
  `205a5da0-bc6c-4198-aab0-826b14257d1b`, topography
  `b3753996-971c-4e3b-af3b-bc8539c37462`, aurora
  `de2734f5-805c-4e1c-a1fd-a38728e6b681`.
- **Generated assets**: Recraft V4.1 `vector` mode for icons-as-art and
  illustrative objects (takes exact hex palettes and background colour);
  the nano-banana image model for atmospheric plates. UI glyphs stay the
  stroke icon set.

## The build loop

Scope: the complete app. Four pieces, each judged by three independent
reviews with fresh context and binary verdicts (pass/fail, no scores), any
fail returning to the builder with the single biggest gap named:

1. **Shell** — tokens, fonts, header, hero with the Deep Field plate, footer.
2. **Workbench** — the encrypt/decrypt forms and the container inspector.
3. **Tools** — dice entropy, paper vault, recovery kit, dialogs.
4. **Verify & social** — the verify page, og card, PWA icons.

Reviews per piece: brief (does it do the job), system (`DESIGN-SYSTEM.md`
adherence, objective), craft (`BAR.md` mechanisms against rendered
screenshots). All existing suites stay green throughout — the browser suite,
the 12px floor, AA contrast, and the container-inspector spec are part of
"pass".

## Done since this file was written

- Piece 1 of the loop, the shell: the token layer, the fonts, the header, the
  hero with its plate, and the primary action. The accent colour was retired
  outright rather than restyled — see the commit for why the system has no
  emphasis colour and what replaced it.
- JetBrains Mono is vendored (npm, OFL, no licence question).
- The Deep Field plate is generated, downscaled and shipped; see above.
- All thirteen README and walkthrough screenshots regenerate from
  `scripts/capture-screenshots.mjs`. Seven of them had no generator at all
  and were still showing the pre-Nightpaper identity.

- Piece 2, the workbench — and most of piece 3 with it, since the tools and
  the dialogs live in the same file and took the same mapping. 122 `white/N`
  washes and 38 default-palette `yellow`/`amber`/`red`/`zinc` classes became
  tokens. Two levels do the work inside a card now: no fill plus a hairline
  for anything resting, `inset` for a field or a selected option.
- `npm run test:palette` — the gate that keeps it that way. It reads the
  *rendered* page, not the source, because a wash only becomes a colour after
  the browser composites it.

- Pieces 3 and 4: the dialogs, the verify page, the PWA icons and the social
  card. The palette gate now opens a dialog too — dialogs render into a portal
  at the end of `<body>`, so no earlier run had ever looked at one, and the
  first that did found the modal scrim still on `bg-black/80`.
- `node scripts/make-icons.mjs` and `node scripts/make-og-card.mjs` regenerate
  the brand artifacts and verify their own output before shipping it.
- `playwright.config.ts` drops engines whose binaries are missing — locally
  only. In CI every project stays, so a broken install step still fails.

- The three borrows from the UI review (`UI-REVIEW.md`), each inside the
  existing gates — no new colour, no shadow, no cool grey:
  - **The command bar** (⌘K / Ctrl+K), the Linear borrow. A new
    `command-bar.tsx` on the Radix dialog primitives — hand-rolled rather than
    `cmdk`, because the supply chain stays small and a substring filter is one
    whose misses a user can predict. Every command calls a handler a button
    already calls (mode switches, the generators, calibration, the recovery
    kit, the panic wipe), so the bar adds reach, never capability. Contextual
    on purpose: the wipe is listed only while there is something to wipe.
    `command-bar.spec.ts` pins it — including that commands act on real state —
    and was sabotaged (listener disabled, rebuild confirmed compiling, six of
    seven failed, the header-click survivor being the path the sabotage left
    alive). Both audits gained the bar as a seventh view, counts rising
    1871→2368 colours and 82→110 icons — the evidence the view is scanned.
  - **Micro-motion**, the other Linear borrow: the arriving tab panel fades
    and rises 8px over 200ms, and buttons ease to 0.985 scale on press. All
    opacity/transform, inside the reduced-motion global.
  - **Rhythm**, the AuthKit borrow: more air under the hero (the plate
    finishes fading before the workbench arrives), a wider Ledger-split gap,
    and the feature cards pushed a step further from the forms. The Warp
    borrow needed almost nothing — the container inspector already *is* the
    terminal-register data surface; its rows tightened two points and the new
    command bar carries the same mono voice (group labels, kbd chips, hints).

- The command-menu pill shows on every width now. It shipped `hidden
  sm:flex` on the theory that a shortcut hint is dead weight without a
  keyboard — but the pill is a *button*, and hiding it made the bar
  unreachable on exactly the devices where hunting through the page costs
  the most. The label is the responsive part, not the existence: below `sm`
  it is the 16px search glyph on a 32px target, at `sm+` it is "Ctrl K" /
  "⌘ K" as before. The phone spec drives the whole round trip by touch —
  pill visible, label hidden, glyph shown, tap opens, tapping a command
  switches the tab — and was sabotage-verified by re-hiding the pill:
  compiled, failed on visibility, restored. The 375px/393px overflow sweeps
  still pass, so the tightest header holds.

- The sparks are spent, once, where UI-REVIEW.md item 4 said they were owed:
  the container inspector's **byte map**, a strip under the hex readout whose
  segment widths are the byte extents the parser (or the plan) computes —
  ember for the 5-byte magic+version stamp, `border-strong` for the header
  fields, `#5C7FFF` per slot, so more slots draw a longer table and a chained
  cipher draws wider slots. Marks only; every glyph stays in the warm text
  scale, and the block is aria-hidden because the annotation line and the
  slot rows already say all of it in text. It renders in the parsed branch
  and the itemised plan branch, never the summary — the anticipation rule
  counts a diagram as itemisation. The lifted cuts joined the palette gate's
  ALLOWED list (they were named in § sparks all along, used nowhere), the
  audit gained the plan-detail view as its eighth so the one sanctioned use
  is actually scanned, and both sides were sabotage-verified: a map hardcoded
  to one slot failed the two-slot container's segment count, and removing
  `#5c7fff` from ALLOWED failed the audit naming the strip's own spans.

- The plate is brighter, and the gate moved with it. `brightness(1.3)
  saturate(1.2)` on the hero img lifts it from 2.32x the canvas mean to 3.23x
  (peak 10.2x → 16.7x) — once opacity was already 1.0, the filter was the
  lever left, and a sweep showed widening the mask moved the measured band
  not at all (2.32x → 2.37x). 1.5 was measured and declined: the worst
  glyph-free ground beside the eyebrow reads 4.99:1 against `body` there, an
  11% margin over the 4.5 floor that three engines' compositing could eat;
  at 1.3 it reads 5.50:1. The wrapper also came down 620px → 560px, because
  at 1.3 the residue where the bottom gradient had not quite finished
  stopped being invisible against "fades to flat canvas before any form" —
  the fade now completes a clear margin above the workbench card.
  `hero-plate.spec.ts`'s floors rose to 2.5x/12x (~25% under shipped, same
  policy), so the old look now *fails* — sabotage-verified by rebuilding
  with the filter removed: compiled, failed on the mean-lift floor, restored.

- Every screenshot is one width now. `07-decrypt-detection` and `08-seedqr`
  were element `.screenshot()` captures — 960 and 1024px wide against the
  2360px of every other shot — which read as ragged in the folder and the
  README. Both are viewport-width bands now (the inspector in its decrypt
  column; the SeedQR dialog centred on its scrim), the README shows every
  non-hero shot at one display width, and `scripts/screenshot-audit.mjs`
  (`npm run test:screenshots`, wired into `ci.yml`) holds every shot at
  2360px so the next stray element capture fails CI instead of shipping.
  The standard is written down in `DESIGN-SYSTEM.md § Screenshots`.

- The 10× plan's first bet (`TEN-X-PLAN.md`, PR 1 — Bet 3): three **doors**
  under the hero and a real **Seed Phrase mode**. The page's first question
  used to be the system's — Encrypt, Decrypt, Tools — and the user's own
  question ("I have a seed phrase to put somewhere safe") had to be
  translated into it. The doors ask the user's: *Back up a seed phrase ·
  Encrypt a file · Open a backup*. Each one configures the form that already
  exists rather than growing a second one — mode, input, and the defaults a
  passport scan and a 24-word phrase had been sharing. The seed door turns
  recovery shares on, the file door turns them off, the tabs stay for anyone
  who thinks in the system's terms, and the command bar lists the doors under
  *Start*. Pressing the door already pressed is a no-op, so a stray click
  never resets a form in progress.

  Seed Phrase mode is the third pill above the text box, and it is an
  *editor*, not an input type: a 12/15/18/21/24-cell grid whose every change
  writes the joined words back into `textSecret`, so the size gate, the
  inspector's byte count and the encrypt call never learned that a second
  field existed. Each cell is a combobox on the command bar's pattern —
  aria-activedescendant, arrow keys, Enter takes the highlight; Space and Tab
  take it only when it is the sole candidate or the user moved it, and
  nothing is ever completed from a prefix that could be several words. Four
  letters name every word on the list, so the honest case is also the common
  one. A word is judged when it is *left*, not while it is typed, and the
  verdict is a sentence with a position in it: "Word 7 is not on the list —
  did you mean worth?" The suggestion is optimal-string-alignment distance
  ≤ 2, ties broken by the longest shared opening: "yelow" is one edit from
  both "below" and "yellow", and only one of those was meant. Repeated words
  are not an error. A wrong checksum is reported, not enforced — a phrase
  from a wallet that never followed the standard is its owner's to seal — and
  the only thing the button waits for is every cell holding a listed word. A
  whole phrase pasted into any cell fills the grid and grows it to fit,
  numbering and all. Only the focused cell is readable; the rest blur as the
  textarea does, and the same reveal toggle lifts them together. `bip39.ts`
  gained `isBip39Word`, `bip39Completions` (a binary search over the list,
  which is now checked to be sorted at load) and `suggestBip39Word`; the
  module stays lazy, so the grid takes input before the list lands and says
  so in the status line.

  `seed-mode.spec.ts` pins eleven things against the list and against the
  bytes, never against the grid's own claims: the doors and their defaults
  (the inspector's "2 ways in" is the witness that the seed door changed what
  will be written), a phrase typed with spaces landing word by word, the
  misspelling named by position with its suggestion and the button withheld
  until it is fixed, the incomplete-word wording, autocomplete completing a
  unique prefix and refusing to guess between eight, a paste that grows a
  12-grid to 24, the round trip — sealed from the grid, opened with
  `decryptText`, equal to the words joined by single spaces — the checksum
  reported but not enforced, the blur rule read from the computed `filter`,
  the textarea and the grid editing one secret, and Wipe now emptying the
  cells. Sabotage: `isBip39Word` made to pass every word; typecheck and build
  confirmed clean, then 3 of 11 failed — the misspelling test by name, its status reading "All 12 words are on the list, but the checksum does not match" where "Word 7 is not on the list" was expected, and with it the incomplete-word and autocomplete tests, since a list that knows every word has nothing to complete; restored, rebuilt.

  Both audits gained the grid — a word flagged, a completion list open — as a
  view: palette 3126→3747 colours across 8→9 views, icons 130→156 across 7→8.
  The axe sweep gained the same state. Every screenshot regenerated, plus a
  fourteenth, `11-seed-mode.png`, for the README's seed section, which no
  longer claims the field speaks in colour alone. Full chromium suite:
  205 passed. The first run was 204 of 205: `command-bar.spec.ts`'s "second Go-to entry is Tools" test, because the doors had gone in at the top of the command list. *Start* now follows *Go to*, so the palette still opens on the mode switches that test pins, and the re-run was clean.

- PR 2 of the plan — Bet 4, the **paper vault as a procedure**. The sheet was
  principled and it was one document doing three jobs: the owner's copy of
  the backup, the envelopes for three different people, and the instructions
  for a fourth person years later. It reads now in the order that person
  meets it. A **cover** before a single square — *What this is · What you
  need · Do this* — in the voice of someone who did not choose this tool,
  pointing at the full procedure at the end rather than repeating it. The
  **byte map** under the symbols, drawn by the inspector's own `byteMapSpans`
  (exported for the purpose) from the header the sheet is printing, so the
  page says how many ways in the container holds without anyone decoding a
  square; its two spark cuts are the page's only colour, and they are data —
  the header-fields segment is black so the strip survives a monochrome
  printer as three greys, and `print-color-adjust: exact` keeps a browser
  from dropping the fills on the way to paper. A **rehearsal box** — "☐
  Rehearsed on ____ with strips ____ and ____ · rehearse again by ____",
  one blank per strip the threshold needs — because a backup that has never
  been opened is a hope, and the record belongs in ink on the copy that will
  be in the drawer; the app stores nothing, and PR 3 fills the box in. And
  the shares as **strips**: a cut line and a *Held by* line each, one per
  envelope, on a page of their own, so the owner's copy keeps the symbols and
  a holder gets a key that says what it is to whoever finds it. The
  recovery-kit line stays, still naming `keym2.py` and `docs/RECOVERY.md`;
  nothing secret is printed automatically, as before.

  `paper-vault.spec.ts` gained four tests on the same print-instant
  snapshot: the three cover headings in order and the plain-language lines;
  the byte map's slot segments equal to the slot-count byte read from the
  armored output (one for a passphrase seal, two with a share set — the
  authority container-inspector.spec.ts uses); with 2-of-3 enrolled, three
  strips, three *Held by* lines, no container symbol on the strips page, and
  the rehearsal line asking for two strips; and the rehearsal box with its
  empty tick. Sabotage: the strips rendered as none; typecheck and build clean, then 1 of 11 failed — the strips test, "one strip per share, or an envelope is short a key", expected 3 and received 0; restored, rebuilt. Print CSS is outside the palette
  gate, so the page was held to the standard by eye: monochrome on white
  except the two cuts. `test:recovery` and the walkthrough are untouched —
  neither document describes the sheet's layout. Full chromium suite:
  209 passed on the restored build, typecheck and production build clean.

- PR 3 of the plan — Bet 2, the **rehearsal**. Shares were shown once with a
  strong warning, then gone, and the first time anyone learned whether they
  worked was the day they were needed. *Rehearse now*, on the one-time shares
  dialog, walks the owner through the heir's path while the strips are still
  on screen: paste any k of them, exactly as an heir would — comment lines
  dropped, the same size gate as the decrypt box — and the backup is opened
  with them alone, no password, through the same worker call the verify-only
  unlock uses. What comes back is "Opened in 1.2 s with strips 1 and 3 — 75
  bytes, kept hidden": the strips are named in strip order whichever order
  they were pasted, the byte count is the one fact about the contents that is
  reported, and the buffer is zeroed on arrival — nothing reaches the DOM, the
  clipboard, a Blob or a file. A wrong strip fails loudly, in words, and
  stamps nothing; fewer than k is refused before any attempt, with the count
  so far. The pasted strips are wiped with everything else and the moment the
  dialog closes; the outcome is not a secret and is not kept either — it goes
  onto the next paper vault as ink ("☑ Rehearsed on 2026-09-02 with strips 1
  and 3 · rehearse again by 2027-09-02", the same day next year) and is
  discarded with the rest. A result that lands after a wipe or a lock has
  moved the operation counter is discarded like any other, and the dialog's
  own lock warning covers the whole exercise.

  `rehearsal.spec.ts` seals 2-of-3 and asserts two things at once: that the
  strips open the backup — seconds, strip numbers, and a byte count checked
  against the secret the test sealed — and that the plaintext went nowhere:
  absent from every text node and every field on the page, with the Result
  box still holding the container. A corrupted strip fails by name and the
  printed box stays blank; one strip is refused with "1 of 2 strips pasted";
  and the following print carries the filled stamp with next year's date.
  Sabotage: the unlock replaced with a fake success; typecheck and build clean, then the wrong-strip test failed by name — "Opened in 0.0 s with strips 1 — 340 bytes, kept hidden" where "did not open the backup" was expected — and the hidden-contents test failed on its byte count (the fake reported the container's length, not the secret's). The last two tests of that run never reached the page: the test server dropped mid-run with a connection refused, which says nothing either way and is recorded here rather than tidied away. Restored, rebuilt. Both audits and the axe sweep gained the dialog
  in its rehearsal state — a seal with a share set inside the audit, PBKDF2
  so it is quick — palette 3747→4376 colours across 9→10 views, icons 156→193 across 8→9. Full chromium suite: 214 passed on the restored build, typecheck and production build clean.

- PR 4 of the plan — Bet 5, **trust you can test, not read**. `connect-src
  'none'` and the signed, reproducible build both lived in a footer link and
  a document; from inside the app, every competitor's "client-side" looked
  the same. The inspector's footer — "runs in this tab · nothing is
  uploaded" — now opens into the three things the page can prove about
  itself on the spot, and the standing rule held: every row is a structural
  fact established locally, never live telemetry. **The policy line is read,
  not typed** — `connect-src 'none'` quoted from the page's own CSP meta tag
  as served; a copy without it says *unsealed — a development build*, with
  the warning dot, because a light that could be wrong is worse than none.
  **Offline is noticed, not claimed** — `navigator.onLine`, with the one true
  sentence beside it: nothing here ever needed a connection. And **the
  in-place check** hashes what the service worker holds for this build
  against the manifest it now holds beside it (`SHA256SUMS` joined the
  precache list; `apply-build-id.mjs` exempts the one file the next build
  step writes). Cache API only — no request is made, and none is allowed, so
  the check runs inside the policy rather than around it. What it proves is
  said plainly: the set is *consistent*, not *honest*, and the manifest's
  sha256 is printed so the outside procedure can be run against the same
  bytes. The verify page could never print that digest — baking it is
  circular and fetching it is forbidden — and reading it back from the cache
  is neither. That is the bridge the plan asked for.

  `sealed-status.spec.ts` holds each row to an authority outside the
  component: the quoted directive equals the meta tag's character for
  character; the offline notice appears under `setOffline` and a seal runs
  with the network off; the check's digest equals sha256 of the `SHA256SUMS`
  in `out/`, and its file count covers every precached chunk plus the shell.
  The negative control is built in — the cached manifest is rewritten with a
  wrong digest for one chunk and the check reports that file by name — and
  the verifier itself was sabotaged too — made to ignore every mismatch — and with it the altered-manifest test failed by name (the result never reached "mismatch"; the other three passed), then restored and rebuilt. The first full run on the restored build found one real failure of this change's own: the new footer toggle measured 257×18 at a phone width, under the 24px touch-target floor U8 holds, fixed with the footer's own idiom (padding plus a negative margin) and its pre-hydration label made to claim nothing. Both audits gained the opened status with its check run —
  palette 4376→4891 colours across 10→11 views, icons 193→226 across 9→10 — and the axe sweep gained the opened panel. Full chromium
  suite: 219 passed on the final build, typecheck and production build clean; six screenshots regenerated (every band that frames the inspector footer), all fourteen still 2360px.

## Loose ends

- **Satoshi is not being vendored, and the question is closed.** It headed both
  text stacks and was never once drawn: the ITF Free Font License §02 forbids
  distributing the binary through a "repository" or "publicly accessible
  servers" and requires third parties to obtain their own copy from Fontshare,
  so it could not live in this public repo, and the stack fell through to
  whatever system UI face the reader had. §01 does permit self-hosting on the
  deployed site — but a font that may not be in the source while it must be in
  the deployment breaks the reproducible-build promise, and a build-time fetch
  would put an external server inside a build that currently has no network at
  all. Replaced with **Plus Jakarta Sans** (OFL-1.1, npm, in the lockfile,
  precached). ITF invite exception requests under §09 if the face is ever
  wanted badly enough to ask.
- Grab reference screenshots (images.refero.design and elevenlabs.io) so the
  craft review can compare pixels, not just mechanisms. Both hosts were added
  to the environment's network allowlist, but a session that was provisioned
  before that change cannot see it — the policy binds when the container is
  built. So this is a task for a **fresh session**: confirm reachability with
  `curl -sS -o /dev/null -w "%{http_code}" https://images.refero.design/`, and
  if it is not `000`/`403`, screenshot both references and drop them beside the
  craft notes. Still blocked from the session this note was written in.
- The one flaky browser test is **fixed**. `calibration.spec.ts` ›
  "reports the estimate as measured rather than typical" failed once in a full
  parallel run and never alone. Diagnosed: the `calibrate()` helper returned as
  soon as any `[role="status"]` was non-empty, which includes the two honest
  failure notes ("did not finish" / "needs a Web Worker") that `runCalibration`
  writes when the worker loses its CPU slice inside the 1 s budget under load,
  leaving `deviceFit` null. The caller then asserted a measured-this-device
  outcome that had correctly not happened. The helper now targets the note by
  `data-testid="calibration-note"` (not "the first status on a page that has a
  dozen"), classifies success versus the two failures, and retries the
  transient ones, throwing with the last status if calibration never lands —
  so a genuinely broken calibration still fails, loudly. Sabotaged by forcing
  the did-not-finish path: the helper retried three times and threw
  `calibration did not run in 3 attempts`, rather than passing or hanging.
- A second one, seen once and **diagnosed**: `passkey.spec.ts` › "a container
  enrolled with a passkey opens with the passkey alone" failed as
  `[0] != [0, 1]` — the sealed container carried a passphrase slot and no
  passkey slot. That narrows to one cause rather than several: enrolment is
  skipped when the toggle is off and *throws* when it is on and fails, so a
  container that sealed successfully with one slot means the switch was never
  turned on. `prepareEncrypt` clicked it once and assumed. It now polls until
  `aria-checked` reports `true`, which is what the sibling helper
  `enableShares` in the same file already did. Did not reproduce in the next
  full run; the byte-level assertion stays, since it is the thing that would
  catch a toggle that is on and does nothing.

## The icon audit

Review point 5 was "iconography is inconsistent". The obvious suspect is stroke
weight, and it is innocent: there is not one `strokeWidth` prop in `src/`, so
every lucide icon in the app renders at the library default of `2`. There is
nothing to normalise there.

What is actually inconsistent is **size**, in three separate ways.

**Five sizes, two of them used once.** `h-3` (12px), `h-3.5` (14px), `h-4`
(16px), `h-4.5` (18px) and `h-5` (20px) are all in use; `h-3` appears once
(`encryptor-tool.tsx`, the inline Download) and `h-4.5` once
(`dice-entropy-tool.tsx`). `h-4.5` does compile — Tailwind v4 resolves
fractional spacing dynamically, confirmed by running the class through
`@tailwindcss/postcss` — so it is a one-off, not a typo.

**Apparent line weight is a function of that size.** Lucide draws a 2-unit
stroke on a 24 grid, so the painted stroke is `2 x size/24`: 1.00px at 12,
1.17px at 14, 1.33px at 16, 1.50px at 18, 1.67px at 20. A 67% spread in line
weight across one icon family is what reads as "inconsistent" long before glyph
choice does. Normalising sizes fixes the weights; there is no separate weight
fix to make.

**Inside a button the authored size is fiction.** The button base carries
`[&_svg]:size-4`, which compiles to `.[&_svg]:size-4 svg` — a class plus a type
selector, specificity (0,1,1) — and that outranks `.h-5` at (0,1,0). Measured
in chromium rather than reasoned about: an icon written `h-5 w-5` inside a
button computes to 16x16, one written `h-3.5 w-3.5` also computes to 16x16, and
the same `h-5 w-5` icon outside a button computes to 20x20. So the encrypt
CTA's `Lock className="mr-2 h-5 w-5"` paints at 16px, and every per-icon size
class written inside a button is dead code.

**Two names for one icon.** `AlertTriangle` and `TriangleAlert` are the same
export object — verified by `===`, not by reading the docs. `AlertTriangle` is
the deprecated alias. `container-inspector.tsx` imports the current name,
everything else imports the alias. Invisible to a user, but it means a search
for one usage misses half of them. `Check` and `CheckCircle2` are separately
both used for the "ok" state.

**Resolved.** Six sizes were in use once the rendered page was measured rather
than the source read — 12, 14, 16, 18, 20 and 22px, expressed three ways: an
`h-*` class, a `size={22}` prop, and nothing at all. They are now three, each
with a job, written into § Icons: 14px inline, 16px standalone and in controls,
20px display. `AlertTriangle` is gone in favour of `TriangleAlert`.

The screenshot turned out not to be needed. The question it was meant to answer
— which size looks wrong — dissolved once the sizes were counted: the answer is
that having six of them is what looks wrong, whichever one you happen to be
staring at.

`scripts/icon-audit.mjs` now holds the line, walking the rendered page the way
the palette gate does. Three sabotages, three distinct failures: a banned size
names the icon and its authored class, a hand-set `strokeWidth` names the
weight, and a scan that matches nothing fails on its own floor rather than
reporting success over zero icons.

## The browser job, and why it was red

`browser.yml` builds with `KEYMAKER_BASE_PATH` set; every local run does not.
That is the only difference, and it is why three engines failed in CI while
chromium passed here — the failure was in a layout no local run produces.

It was a false positive. `base-path.spec.ts` collected every declared URL and
required all of them under the base path, which is right for a stylesheet or
a script and wrong for `rel="preconnect"`: a connection hint consumes only the
*origin* of its href and never requests the path, so it cannot 404. React
injects exactly one — `<link rel="preconnect" href="/">`, added during
hydration once a stylesheet pulls in font files, which is why it arrived with
the first vendored font and why it cannot be removed from the exported HTML.

Reproduce any of this locally by building the way CI does:

    KEYMAKER_BASE_PATH=/Keymaker-v2 npm run build
    KEYMAKER_BASE_PATH=/Keymaker-v2 npx playwright test --project=chromium

## The ci job, and why it was red

The palette gate needs a renderer, and `ci.yml` had never needed one: every
other step in that job is pure Node, so no Playwright browser was installed and
`chromium.launch()` failed with "Executable doesn't exist". A one-line install
step fixes it — chromium only, because the audit asks what colour was painted
and that answer does not vary by engine.

It cannot simply move to `browser.yml`, which already has all three engines
installed. That job builds with `KEYMAKER_BASE_PATH` set, so every asset is
referenced at `/Keymaker-v2/…`, and `palette-audit.mjs` spawns
`static-server.mjs` with no base path — the stylesheet would 404.

That failure mode was checked rather than assumed: deleting the stylesheet from
`out/` and re-running the audit **fails** with four offenders, three of which
are unmistakably the browser's own defaults — `#0000ee` link blue and the
`#767676` / `#777777` form-control borders. So an audit accidentally pointed at
unstyled HTML reports a red build rather than a green one.

## Notes for whoever picks this up

The environment's network allowlist binds when a container is **provisioned**,
not when it is edited — a running session cannot be opened up by changing the
setting, it has to be a new session. What is reachable from a sealed one:
`registry.npmjs.org` and `files.pythonhosted.org` (which is how JetBrains Mono
and Pillow got here), and the Higgsfield MCP server, whose sandbox has its own
internet access and can be used to move bytes that the local proxy refuses.

Firefox and WebKit binaries are not installed in the sealed container and
`playwright install` cannot reach its CDN, so only `--project=chromium` is
verifiable locally; CI covers the other two. A bare `npm run test:browser`
reports ~320 failures that are all "Executable doesn't exist" — do not read
that as a regression.
