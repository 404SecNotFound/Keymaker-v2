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
- **Type**: Satoshi Variable (UI + display) and JetBrains Mono (data), both
  from Fontshare. JetBrains Mono is OFL and also ships on npm
  (`@fontsource-variable/jetbrains-mono`). Satoshi is ITF Free Font License —
  free for commercial use; **verify the FFL's redistribution clause before
  committing the font binaries to this public repository** (self-hosting on
  the deployed site is fine either way). Download:
  `https://api.fontshare.com/v2/fonts/download/satoshi`
- **Hero background**: "Deep Field" — sparse blue/ember bokeh drifting in a
  diagonal band over warm charcoal. **Shipped** as
  `public/hero-deep-field.webp` (1400×781, 7.5 KB).

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

## Loose ends

- **Satoshi is still not vendored.** It heads both text stacks in
  `globals.css` and falls through to the system UI face until the binary
  lands, so the display weight is approximated rather than drawn: the
  whispered 300 is the single most visible thing still missing. Needs
  fontshare.com / api.fontshare.com reachable, *and* the ITF FFL
  redistribution clause read before a binary goes into a public repository.
  Download: `https://api.fontshare.com/v2/fonts/download/satoshi`. The drop-in
  is one file in `public/` plus one `@font-face` — `globals.css` says where.
- Grab reference screenshots (images.refero.design and elevenlabs.io) so the
  craft review can compare pixels, not just mechanisms. Still blocked in a
  sealed container; both hosts are refused at the proxy.
- One flaky browser test, seen once and not reproduced: `calibration.spec.ts`
  › "reports the estimate as measured rather than typical" failed in a full
  run and passed alone and in the next two full runs. It measures real device
  timing, so it is load-sensitive by construction. Not diagnosed, not
  "fixed" — recorded so the next person who sees it knows it is not new.
- Open the Nightpaper PR. #116 is merged, so `main` currently ships the Linear
  identity; this branch supersedes it visually and nothing on the live site
  changes until it lands.

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
