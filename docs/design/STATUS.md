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
- **Hero background**: "Deep Field" — a sparse field of fine luminous line
  runs, like rows of a cipher block, stacked along a lower-left to upper-right
  diagonal over warm charcoal, with blue and ember nodes. **Shipped** as
  `public/hero-deep-field.webp` (1400×781, 9.0 KB).

  It replaces the bokeh plate that held this slot, and states the concept as a
  key schedule rather than as drifting points. Reaching it took two passes: the
  first read as formless and let a haze bloom off the right edge, and the
  correction for that overshot into crisp corner-to-corner geometry. The
  shipped plate is the second pass. Prompt and settings, so it can be
  reproduced or re-rolled: `nano_banana_pro`, 16:9, 4k, the brief in
  `DESIGN-SYSTEM.md § Imagery` written out longhand — warm near-black ground
  with a taupe undertone, fine horizontal runs of varying length stacked on a
  lower-left to upper-right diagonal band, a handful of nodes `#0447FF`, a
  handful `#FF4704`, the rest dim cool-neutral grey, darkest at the
  left/right/bottom edges, no text or subject of any kind.

  The Higgsfield CDN host (`d8j0ntlcm91z4.cloudfront.net`) is still refused by
  the network policy of a sealed container, so the bytes cannot be fetched from
  a session; they arrived as a chat attachment and were converted here.
  `.claude/settings.json` allowlists the host for the sandbox, which does not
  by itself lift the egress policy above it.

  Downscaled to 1400px and WebP q60 deliberately: 22 MB of PNG in a repository
  that promises reproducible builds would be 22 MB nobody can diff. Mounted
  behind the hero only, at **20%** with a radial canvas scrim under the text
  and a gradient to flat canvas before the workbench.

  The opacity is not the 40% the bokeh plate ran at, and the reason is the
  reason this plate is different: crisp lines peak far brighter than soft
  bokeh. In the headline zone this plate is fractionally *darker* on average
  (mean L 0.179 against 0.194) but its peak is nearly double (0.857 against
  0.480), and contrast is set by the brightest pixel behind a glyph, not the
  mean. Composited at 40% over canvas the worst case fell to 5.67:1 headline,
  1.84:1 dimmed second line, 2.48:1 body — the second line under the 3:1 that
  large text requires. At 20% every run is back at or above where the bokeh
  plate sat: 10.82:1, 3.52:1, 4.75:1 against its 9.86 / 3.20 / 4.32. Those
  figures are the conservative bound — text over plate-over-canvas with the
  scrim discounted entirely — so the on-page numbers are better. Re-measure
  before raising the opacity; the mean is not the number that matters.

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
  craft review can compare pixels, not just mechanisms. Still blocked in a
  sealed container; both hosts are refused at the proxy.
- One flaky browser test, seen once and not reproduced: `calibration.spec.ts`
  › "reports the estimate as measured rather than typical" failed in a full
  run and passed alone and in the next two full runs. It measures real device
  timing, so it is load-sensitive by construction. Not diagnosed, not
  "fixed" — recorded so the next person who sees it knows it is not new.
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
- **Iconography is inconsistent, and it is not the stroke weight.** Measured,
  not guessed — see "The icon audit" below. Waiting on a screenshot to say
  which of the five sizes looks wrong before anything is changed.

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

Nothing here has been changed. The diagnosis does not need the screenshot; the
decision about which sizes survive does.

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
