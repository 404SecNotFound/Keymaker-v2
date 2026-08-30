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
  sparse blue/ember bokeh over warm charcoal. It sits behind the hero only,
  fades to flat `canvas` before any form or text panel, and text over it
  always has ≥ AA contrast against the darkest local region or sits on a
  `canvas` scrim.
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
