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
- **Hero background**: "Deep Field II" — layered blue/ember bokeh receding
  into haze along a lower-left to upper-right diagonal band over warm charcoal.
  **Shipped** as `public/hero-cipher-field.webp` (1400x781, 19 KB). The
  filename is unchanged on purpose: it is referenced by the component, the
  screenshot generator and the walkthrough, and none of those get churn for a
  rename.

  It replaces the first Deep Field plate, which was generated to a brief asking
  for "twenty to thirty widely spaced bokeh points". That brief was the
  problem. Rendered at the hero's size the points read as faint diagonal
  scratches, and the plate had almost nothing to say — the model was never the
  limit, and re-running the same brief on the same model would have produced
  the same thing again. The replacement keeps the concept and rewrites the
  brief: many more points, across five or six depth layers, with real
  atmospheric perspective instead of a scatter on a flat ground.

  Prompt and settings, so it can be reproduced or re-rolled: `nano_banana_pro`,
  16:9, `resolution: 4k`, source 5504x3072 — a deep field of drifting light
  particles receding into fog along a lower-left to upper-right diagonal, five
  or six depth layers, sharp bright points nearest and progressively softer
  dimmer bokeh behind, warm amber-taupe haze, a handful of particles at
  `#0447FF` and a handful at `#FF4704` among dim warm grey, vignetted to
  near-black at all four edges, and an explicit negative list: no horizon, no
  ground plane, no terrain, no subject, no text.

  **The submitted model id and the reported one differ.** Every job was
  submitted as `nano_banana_pro` and came back reporting `model:
  nano_banana_2`. Recorded rather than explained; if a future re-roll looks
  unlike this plate, that discrepancy is the first thing to check.

  **Known defect, accepted knowingly.** The haze in the upper right renders as
  a pale *neutral grey* rather than the warm amber the brief asked for — the §
  Surfaces drift arriving through the imagery door, and the same fault that
  sent two other candidates back. It was accepted on this plate because the
  plate was chosen on its merits and the exception stops at the imagery layer.
  First thing to fix on a re-roll; not a precedent.

  WebP q80 rather than the q60 the previous plate used, and the reason is a
  property of the image rather than a preference: q60 was justified in this
  file by the plate being "soft bokeh with no fine detail, so it survives the
  compression intact". This plate carries fine particle detail against haze, so
  that justification does not transfer. 19 KB against the old 16 KB.

  **Brightness 0.60** (`sharp().modulate({brightness: 0.60})`), and this is not
  a preference either — as generated the plate **failed** `hero-plate.spec.ts`,
  putting the headline at 4.08:1 against a 4.5 floor, because the bright haze
  falls exactly where the words sit. Visibility had enormous surplus to pay
  with. The measured sweep:

  | brightness | meanLift (≥1.85) | peakLift (≥6.5) | headline (≥4.5) |
  | --- | --- | --- | --- |
  | 1.00 | 12.30 | 39.82 | **4.08:1 FAIL** |
  | 0.75 | 7.41 | 21.86 | 5.03:1 |
  | **0.60 (shipped)** | **5.26** | **14.14** | **6.08:1** |
  | 0.50 | 4.10 | 10.30 | 6.82:1 |
  | 0.42 | 3.33 | 7.77 | 7.43:1 |

  0.60 is the balance point rather than the calmest row: it leaves 1.6 of
  headline headroom while keeping the visibility half at 2.2x its floor. 0.42
  reads quieter but leaves that half only 1.3 above failing, which is the wrong
  side to run thin on given the plate exists to be seen.

  This is not the `opacity-40` mistake returning. That was three CSS
  suppressors stacked on an already-quiet image, taking it to a lift of two
  values out of 255. This is one adjustment baked into the art, chosen against
  measurements, on an image that started at five times the meanLift the
  previous plate shipped at and failed a gate at full strength.

  Rejected, with reasons, so they are not re-tried: a geometric lattice (read
  as a stock tech terrain floor); a filament/light-trail plate (shipped briefly
  and measured well at 0.65 brightness, but the bokeh field was preferred); a
  cyan/indigo neon plate (breaks the warm-monochrome rule and the spark
  quarantine outright).
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
- Grab reference screenshots so the craft review can compare pixels, not just
  mechanisms. **No longer blocked**: `styles.refero.design` and `elevenlabs.io`
  both answer 200 from a session provisioned after the allowlist widened
  (`images.refero.design` still returns 403 and was not disambiguated). Not
  done yet — the hosts are open, the screenshots have not been taken.
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
setting, it has to be a new session. A session started after the allowlist was
widened measured the following, and the results are worth stating precisely
because two of them contradict what this file used to say:

| host | result |
| --- | --- |
| `registry.npmjs.org`, `files.pythonhosted.org` | reachable |
| `d8j0ntlcm91z4.cloudfront.net` (Higgsfield results) | **reachable** — generated bytes can now be pulled straight down with `curl`, no sandbox relay |
| `styles.refero.design`, `elevenlabs.io` | **reachable** — the reference-screenshot loose end is open |
| `playwright.download.prss.microsoft.com` | reachable, but see below |
| `cdn.playwright.dev`, `ppa.launchpadcontent.net` | refused at CONNECT |

**Reachable is not the same as downloadable, and a bare status code will not
tell you which you have.** A policy denial is the gateway answering `403` *to
the CONNECT*, with no tunnel and no TLS. A CDN answering `403` or `404` to a
pathless `GET` has already completed CONNECT and a TLS handshake, and is
reachable. Both print the same three digits from `curl -o /dev/null -w
'%{http_code}'`. Read `curl -v` for `CONNECT tunnel established`, or the
proxy's own `recentRelayFailures` at `$HTTPS_PROXY/__agentproxy/status`, which
names the host and the reason.

So `playwright install --with-deps firefox webkit` still fails here, but one
step later than it used to: the Microsoft CDN is reachable and the transfer
then dies mid-stream ("server closed connection" on the Firefox zip), while
`cdn.playwright.dev` and the apt PPA are refused outright. Only
`--project=chromium` is verifiable locally; CI covers the other two. A bare
`npm run test:browser` reports ~320 failures that are all "Executable doesn't
exist" — do not read that as a regression.

Chromium also cannot reach the network *through* the relay even where `curl`
can: its TLS handshake gets ~39 bytes back and the tunnel closes
(`ws_closed_mid_exchange`). To screenshot a live URL, intercept with
`page.route` and fulfil each request from a `curl` subprocess. That renders
the real deployed bytes and is how the live hero shot was taken.
