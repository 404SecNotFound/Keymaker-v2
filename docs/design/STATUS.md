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
- **Hero background**: concept 4, "Deep Field" — sparse blue/ember bokeh
  drifting in a diagonal band over warm charcoal. 2752×1536 PNG:
  `https://d8j0ntlcm91z4.cloudfront.net/user_3IcKP9J7tAl1kmrRAIwI2f3BcKm/hf_20260830_043937_4363414e-1dd6-4027-aacc-8e3345744aec.png`
  Runners-up, if a re-pick is ever wanted (same host, same prefix
  `hf_20260830_043937_`): bloom `e3bbdfdb-c345-4eb3-9fc0-48702cdd3f2a`,
  ribbon `205a5da0-bc6c-4198-aab0-826b14257d1b`, topography
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

## Loose ends

- Fetch Satoshi and the Deep Field plate once the environment's network
  allowlist applies (fontshare.com, api/cdn.fontshare.com,
  styles.refero.design, images.refero.design, the cloudfront host above,
  cdn.jsdelivr.net, elevenlabs.io).
- Read the ITF FFL text and record the vendoring decision here.
- Grab reference screenshots (images.refero.design and elevenlabs.io) so the
  craft review can compare pixels, not just mechanisms.
- Decide the fate of PR #116: supersede with one Nightpaper PR from this
  branch, or land #116 first and diff the restyle on top.
