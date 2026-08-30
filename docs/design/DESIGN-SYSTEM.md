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

| token     | value     | on canvas | use                                              |
| --------- | --------- | --------- | ------------------------------------------------ |
| `ink`     | `#F5F3F1` | 17.4:1    | headlines, primary labels — never pure `#FFFFFF` |
| `body`    | `#A9A29A` | 7.7:1     | body copy, secondary labels                      |
| `muted`   | `#878078` | 5.0:1     | captions, hints — 12px minimum, nothing smaller  |

These three are the whole text scale. Opacity modifiers on top of them
(`text-body/60` and the like) are not part of it: they were how the old
palette drifted under the contrast floor without anyone deciding to, so a
tone that needs to be quieter uses the next token down, not a fraction of the
one above.

`muted` was `#7E776F` when this file was first written, which measures 4.40:1
on `canvas` — under the 4.5:1 AA floor. The floor overrides the palette, so
the value lifted two lightness points rather than the floor bending.

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

## The sparks — quarantined

`#0447FF` (electric blue) and `#FF4704` (ember) exist **only** inside
product visuals: the generated background art, data visualisation, and
illustrative objects. Never on buttons, links, borders, focus, icons-as-
chrome, or text. Strip the imagery from any screen and what remains is
entirely warm monochrome. For data-viz strokes on dark grounds the lifted
cuts `#5C7FFF` / `#FF7A47` are permitted, in viz only.

## Semantic status (data, not decoration)

Warm-shifted, used as text on their own `/10` washes and required to pass
AA there: success `#53B37E`, warning `#D9A23F`, danger `#E5624E`. Status
dots may use the same values.

## Type

- **Satoshi Variable** for everything textual.
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
