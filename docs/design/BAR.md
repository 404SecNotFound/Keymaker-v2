# bar.md — ElevenLabs design system, adapted to dark

Reference: Refero Styles, "ElevenLabs design system"
(styles.refero.design/style/031056ff-7af1-46db-8daa-115f731c5d26, extracted 2026-08-30).
Reference north star, verbatim: *"Warm cream editorial with whispered headlines.
A Bauhaus studio notebook — eggshell paper, black ink, a single violet and
orange spark for product moments."*

Our translation: **the same notebook, printed on warm black paper.** The hue
family, hierarchy, and restraint carry over unchanged; only lightness inverts.
Every mechanism below is checkable by looking at a rendered screen.

## Mechanisms

1. **Two warm surface layers, hairline-separated, zero shadows.**
   Canvas and card are both warm-hued near-blacks (taupe family, hue ≈ 75°)
   no more than 4–5 L points apart (light ref: #fdfcfc canvas / #f5f3f1 card
   → dark: #0e0d0b canvas / #171512 card). Elevation is a 1px hairline border
   (#2a2724-family) plus the fill difference — a drop shadow anywhere is a
   fail. Cards: 20px radius, ≥32px horizontal padding.

2. **Whispered display type.** Headlines are LIGHT weight (≤340) at large
   sizes (≥36px), tracking ≈ −0.02em, line-height ≤ 1.1. The whisper is the
   voice: a bold (≥600) display headline is a fail. At most three type sizes
   visible per screen.

3. **Everything else is calm and regular.** Body/UI text at 400/500 only.
   Body copy is muted warm grey (light ref #777169 → dark: stone ≈ #a59f97),
   never full-contrast; captions one step further. Primary text is warm
   off-white (#f5f3f1 family), never pure #ffffff.

4. **Buttons are full pills.** 9999px radius, always a 1px border — even on
   the filled primary. The primary action is the highest-contrast NEUTRAL
   (light ref: black fill → dark: eggshell #f5f3f1 fill, near-black text).
   A square or 6px button is a fail; a colored button is a fail.

5. **The two sparks never touch the chrome.** Electric blue #0447ff and
   ember orange #ff4704 appear ONLY inside product visuals: the background
   art, data visualization, the sphere/bloom motif, illustrative icons.
   Never on buttons, links, borders, focus chrome, or text. One glance test:
   strip the imagery and the UI is entirely warm monochrome.

6. **The signature visual is a soft bloom.** Gradients that blend blue →
   orange (→ pink haze) radially with no hard edge, dissolving into the
   canvas color at their boundary — the audio-sphere language. Generated
   background art must reach flat canvas color (#0e0d0b) before any frame
   edge or UI panel, so image and interface meet with no visible seam.

7. **Data is mono and quiet.** Byte views, armor, share strings render in
   the mono face at 400/500, in the muted stone tones — mono text never
   takes the spark colors (a hex byte in blue/orange is a fail; the version
   byte annotation may use the warm off-white for emphasis instead).

## Our concrete deviations from the reference (deliberate, not drift)

- Waldenburg → **Satoshi** (display 300, UI 400/500); Inter's role is
  absorbed by Satoshi. Geist Mono's role → **JetBrains Mono**.
- The reference is a marketing site; ours is an instrument. Density may be
  one notch higher in the workbench pane, but every mechanism above still
  binds — including the shadow ban and the accent quarantine.
- Accessibility floors from the existing test suite override anything here:
  12px minimum text, WCAG AA contrast, visible focus (focus ring uses the
  warm off-white, not a spark color — mechanism 5 applies to focus too).
