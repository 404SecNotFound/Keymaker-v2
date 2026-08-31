# Nightpaper — the Keymaker design system

The ElevenLabs system (see `BAR.md`), printed on warm black paper. This file
is the objective source of truth a reviewer can hold a rendered screen to:
every value here is checkable by looking, and any screen that disagrees with
this file is wrong — the file only changes by editing it first.

## Surfaces

All grounds share one warm hue family (taupe, hue ≈ 40–75°). Cool or neutral
greys do not appear anywhere.

| token          | value     | use                                            |
| -------------- | --------- | ---------------------------------------------- |
| `canvas`       | `#0E0D0B` | the page                                       |
| `card`         | `#171512` | panels, the workbench cards                    |
| `inset`        | `#1D1A17` | fields, wells, segmented tracks                |
| `raised`       | `#262320` | hover/active on an `inset` surface             |
| `line`         | `#292521` | hairline borders (1px, everywhere)             |
| `line-strong`  | `#3A342E` | hover borders, active hairlines                |

`raised` exists because a control already filled with `inset` has nowhere to
go on hover: the three grounds are absolute, so lightening one by a fraction
of white is exactly the drift this palette forbids. One more named step is
the honest fix. It is the only surface above `inset`, and nothing idle uses
it — a `raised` fill on a resting control means the state is wrong.

Two levels do all the work inside a card. A resting container or an
unselected option carries **no fill at all** and is drawn by its hairline
alone; a field, a well, a segmented track, or a selected option carries
`inset`. That is the reference's "flat or barely elevated" rule stated as a
choice between two values rather than a gradient of washes.

Elevation is fill difference plus a 1px hairline — **no drop shadows,
anywhere**. Cards: 20px radius, 32px padding (24px under 480px). Inputs and
small controls: 12px radius. Buttons: 9999px pills, always with a 1px border,
including the filled primary.

## Text

| token     | value     | canvas | card | inset | raised | use                                              |
| --------- | --------- | ------ | ---- | ----- | ------ | ------------------------------------------------ |
| `ink`     | `#F5F3F1` | 17.6:1 | 16.5 | 15.7  | 14.1   | headlines, primary labels — never pure `#FFFFFF` |
| `body`    | `#A9A29A` | 7.7:1  | 7.2  | 6.9   | 6.2    | body copy, secondary labels                      |
| `muted`   | `#918A83` | 5.7:1  | 5.4  | 5.1   | 4.6    | captions, hints — 12px minimum, nothing smaller  |

Every ground is listed because the floor applies to the **pair**, not to the
token. A single "on canvas" column is what let `muted` sit under AA on `inset`
through two separate fixes of the same value.

These three are the whole text scale. Opacity modifiers on top of them
(`text-body/60` and the like) are not part of it: they were how the old
palette drifted under the contrast floor without anyone deciding to, so a
tone that needs to be quieter uses the next token down, not a fraction of the
one above.

`muted` has now been lifted twice, and the second time is the instructive one.
It was `#7E776F` when this file was first written, 4.40:1 on `canvas`, under
the 4.5:1 AA floor; the floor overrides the palette, so the value rose two
lightness points to `#878078` rather than the floor bending.

That fix measured `canvas`, because `canvas` was the only column this table
had. But `muted` is captions and hints, and those live in fields, wells and
segmented tracks — `inset`. On `inset` the lifted value read **4.45:1**, still
under the floor it had just been raised to clear, and on `raised`, the hover
state of those same controls, **4.01:1**. A token does not have a contrast
ratio. A pair does, and the table now says so in four columns.

`scripts/palette-audit.mjs` checks every pair in that table before it opens a
browser. What it does not check is which pairs the app actually composes: it
proves the palette cannot fail, not that no element picked an unlisted ground.
The membership half of the same gate is what keeps grounds on the list.

## Actions

The primary action is the highest-contrast **neutral**: `#F5F3F1` fill,
`#14120F` text, pill, and — because every button in this system carries one —
a 1px border in `#FDFCFC`, the same tone its hover lifts the fill to. That
border was `rgba(255,255,255,0.18)` when this file was first written, which
is a translucent white wash: the exact thing the palette forbids everywhere
else, written into the spec by hand. An opaque named tone keeps the
silhouette rule without keeping the exception, and on an eggshell fill the
two read the same. Secondary buttons: transparent or `inset` fill, `line`
border, `body` text. Focus ring: 2px `#F5F3F1`, offset 2px — the ring is
never a spark colour. Destructive confirmation buttons may use the semantic
danger fill; nothing else is a coloured button.

## Disabled

A disabled control is a **named state built from the tokens**, never a fraction
of the enabled one. `disabled:opacity-50` is the same defect as `text-body/60`,
one level up: it dims the whole element rather than choosing a tone, so nobody
decides what the result looks like and nobody can name it.

On the filled primary it is actively misleading. `#F5F3F1` at 40% over `canvas`
composites to a mid grey pill — which reads as *an ordinary button*, not as an
unavailable one. The single most important control in the app was announcing
itself in the one treatment reserved for nothing at all.

So a disabled control **stops being filled**: no background, `line` border,
`muted` label, `not-allowed` cursor. The filled eggshell pill then means one
thing only — this action is available now. Enabled and disabled differ in fill,
border and text tone together, so the distinction survives greyscale, low
contrast displays, and a glance.

Disabled text is exempt from the AA floor (WCAG 1.4.3), and `muted` clears it
anyway at 5.7:1 on `canvas`. The exemption is not the reason for the choice.

## Anticipation

A panel that describes something the user has not made yet shows a **summary,
not the full record**. The itemised form is available on request and arrives on
its own once the thing is real.

The container inspector was the case that produced this rule. On first load,
before a single character is typed, it painted a header hex row, a slot table,
and three green ticks — a complete description of a file that does not exist.
Everything in it was true and none of it was answering a question anyone had
yet, so the pane read as a wall and the one line worth reading, *which format
this writes*, was buried in it.

Volume is the failure, not detail. The fix is never to delete what the panel
knows or to soften it into vagueness: the summary states the same facts in one
line, the disclosure is labelled with what it will reveal rather than "more",
and the moment there is real input the detail opens by itself — the user should
not have to ask twice for a description of something they have now made.

Applies to any surface that speaks in the future tense. A panel describing
bytes that exist is not anticipating anything, and this rule has nothing to say
about it.

## Icons

One family — lucide — at **three sizes, each with a job**:

| class | paints | for |
| --- | --- | --- |
| `h-3.5 w-3.5` | 14px | inline, sitting in a run of text |
| `h-4 w-4` | 16px | standalone, and inside any control |
| `h-5 w-5` | 20px | display: empty states, and nothing else |

Stroke weight is never set. Lucide draws a 2-unit stroke on a 24 grid, so the
painted line follows the size — 1.17px, 1.33px, 1.67px. That is the whole
reason the sizes are rationed: the apparent weight of an icon is a function of
its height, so five sizes is five line weights in one family, and *that* is
what reads as inconsistent long before anyone notices a glyph. The audit that
produced this rule found no `strokeWidth` prop anywhere. There was never a
stroke problem to fix.

Before this, six sizes were in use — 12, 14, 16, 18, 20 and 22px — expressed
three different ways: a `h-*` class, a `size={22}` prop, and nothing at all.

**Inside a control the size class is decoration.** The button base carries
`[&_svg]:size-4`, a class-plus-type selector, which outranks the `.h-5` on the
icon itself. Measured, not assumed: an icon written `h-5 w-5` in a button
computes to 16×16, one written `h-3.5 w-3.5` in a button also computes to
16×16, and the same `h-5 w-5` icon outside a button computes to 20×20. So the
encrypt button's `Lock` was authored at 20 and had been painting 16 since the
button was written. Author `h-4 w-4` on icons in controls — matching what the
control will paint anyway — rather than a number the cascade discards.

**One name per icon.** `AlertTriangle` and `TriangleAlert` are the same export
object; the first is lucide's deprecated alias. Two names for one glyph means a
search for one usage silently misses the other half, so only the current name
is used.

`scripts/icon-audit.mjs` enforces the sizes against the rendered page, the same
way the palette gate does, because the override above is exactly the kind of
thing that is invisible in the source and obvious in the pixels. The logo is
not a lucide icon and is not covered — it is a fill-based mark on its own grid.

## The sparks — quarantined

`#0447FF` (electric blue) and `#FF4704` (ember) exist **only** inside
product visuals: the generated background art, data visualisation, and
illustrative objects. Never on buttons, links, borders, focus, icons-as-
chrome, or text. Strip the imagery from any screen and what remains is
entirely warm monochrome. For data-viz strokes on dark grounds the lifted
cuts `#5C7FFF` / `#FF7A47` are permitted, in viz only.

## Overlays

A modal scrim is the one surface that must be translucent — it dims whatever
happens to be behind it, which no opaque token can do. It is `canvas` at
**80%**, not black: a pure-black scrim is the same cool-neutral drift as a
white wash, just in the other direction, and against a warm ground it reads
grey. `rgba(14, 13, 11, 0.8)`.

## Semantic status (data, not decoration)

Warm-shifted, used as text on their own `/10` washes and required to pass
AA there: success `#53B37E`, warning `#D9A23F`, danger `#E5624E`. Status
dots may use the same values.

## Type

- **Plus Jakarta Sans Variable** for everything textual.
  - Display: weight **300**, sizes 36/44/56px, tracking −0.02em,
    line-height ≤ 1.1. A display headline at ≥600 weight is a defect.
  - UI and body: 400 and 500 only, 13–16px.
  - At most three type sizes visible on one screen.
- **JetBrains Mono** 400/500 for data surfaces: hex bytes, armored text,
  share strings, KDF parameters, the container inspector's readouts.
  Mono text renders in `body`/`muted` tones; a byte in a spark colour is a
  defect (emphasis uses `ink`).
- Floors from the browser suite override everything: 12px minimum
  rendered size, WCAG AA contrast, visible focus.

This said **Satoshi Variable** until the licence was read. Satoshi is under the
ITF Free Font License, whose §02 forbids distributing the font "through
another font website, font library, marketplace, repository, download service"
or via "publicly accessible servers", and requires any third party to obtain
their own copy from Fontshare. This repository is public, so the binary can
never live in it. Self-hosting on the deployed site is permitted (§01) — but a
font that may not be in the source while it must be in the deployment breaks
the promise that the build is reproducible from what you can read, and that
promise is worth more than a typeface.

So the display face was never actually drawn: the stack fell through to
whatever system UI face the reader had, which is why the interface read as
characterless rather than quiet. Plus Jakarta Sans is OFL-1.1, ships on npm as
`@fontsource-variable/plus-jakarta-sans`, and is therefore vendored,
precached, and offline like JetBrains Mono. Its 200–800 axis covers the 300
display weight this system is built on.

Any future replacement is subject to the same test, in this order: the licence
must permit redistribution in a public repository, then it must self-host from
the lockfile, then it must carry a light weight. A face that fails the first
is not a candidate however well it reads.

## Imagery

- **Hero background**: the "Deep Field" plate (see `STATUS.md` for source) —
  layered blue/ember bokeh receding into warm haze along a lower-left to
  upper-right diagonal band, with the upper left dark and the band passing
  below and around the headline. It sits behind the hero only, fades to flat
  `canvas` before any form or text panel, and carries its sparks at full
  strength, because imagery is the one place they are allowed.

  The composition is load-bearing rather than a matter of taste, and the two
  regions that matter are not the ones intuition suggests. `hero-plate.spec.ts`
  samples a band at `y 40–150` for visibility — that is *above* the headline,
  and it lands on the middle of the plate once the wrapper's `-165px` offset is
  applied — while the contrast half samples the headline's own bounding box
  below it. So a plate has to be **bright where it is sampled for visibility
  and quiet where the words actually sit**. A plate briefed the obvious way
  round — dark through the middle to protect the headline — fails the
  visibility half outright, measured at `peakLift 4.92` against a floor of 6.5
  on a candidate that was otherwise fine.

  Neither "looks good" nor "safely dim" is the standard, because both halves
  are asserted.

  **Haze is warm** — amber or taupe tinted. A neutral grey or white smoke
  plume is the § Surfaces drift arriving through the one door this system
  leaves open, and it is the fault that sent two candidate generations back.

  **The shipped plate breaks that rule, and the exception is recorded rather
  than hidden.** Its haze in the upper right renders pale neutral grey, not the
  warm amber the paragraph above requires. It was accepted knowingly, on a
  plate chosen for its other qualities, and it is the first thing to fix on any
  re-roll. The rule is not retired by it: § Surfaces still binds every ground,
  border and text tone without exception, and this one reaches no further than
  the imagery layer — the single place the system already tolerates colour it
  forbids everywhere else. It is a debt, not a precedent.

  **Dimming is done in the art, never on mount.** The `opacity-40` and the
  canvas scrim that once guarded the headline are gone — three suppressors
  stacked cost a third of the image's visibility to buy 0.3:1 on a floor of
  4.5, and what they guarded is measured in `hero-plate.spec.ts` instead. A
  plate that is too bright for the headline is therefore corrected *before* it
  ships, by baking the reduction into the file (the current one at
  `brightness: 0.60`, see `STATUS.md`), so what the repository holds is what
  the browser paints. Re-adding a CSS opacity or a scrim over the plate is the
  mistake this rule exists to prevent.
- **Illustrative objects and icons-as-art** (empty states, tool cards,
  social imagery): generated in the spark palette on `canvas` grounds,
  vector-style, no text baked in.
- **UI glyphs** (buttons, rows, nav): remain the stroke icon set, coloured
  by the text tokens like any other glyph — never spark-coloured.

## Motion

150–250ms, ease-out, opacity/transform only. The existing
`prefers-reduced-motion` global applies unchanged.

## Voice

Headlines whisper (light weight, tight tracking, short sentences). Body is
calm and factual. The interface states what it does and what it will not do
in the same tone — the honesty register the app already uses.
