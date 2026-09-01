# UI review — is Nightpaper the best?

A design review triggered by a simple question: *is the UI the best, and are there
better styles to copy?* The short answer is that the UI is already near the ceiling
for what a client-side security tool needs, and "copy another style" is the wrong
frame — the right move is three surgical borrows that each land **inside** the
existing gates. This file records the reasoning so the next session does not
re-open a settled question.

A visual version of this review (the palette rendered, the shortlist with fit
meters) was produced as a Claude artifact; this file is the durable copy.

## The verdict

**Keep Nightpaper. Extend it; do not repaint it.**

The rare thing about this system is not the look — it is the *enforcement*. Most
design systems are a document nobody re-opens. This one fails the build when a
screen drifts from `DESIGN-SYSTEM.md`:

- `palette-audit`, `icon-audit` and `screenshot-audit` read the **rendered** page,
  not the source, because a wash only becomes a colour after the browser
  composites it.
- AA contrast is proven on every text × ground **pair**, not per token — the
  four-column table exists because `muted` sat under the floor on `inset` and
  `raised` through two separate fixes that only ever measured `canvas`.
- Elevation is a fill difference plus a 1px hairline. No drop shadows anywhere;
  the old `glass-card` (blur + white wash + 40px shadow) is gone, name and all.
- There is **no accent colour**. The primary action is the highest-contrast
  neutral, and the blue/ember "sparks" are quarantined to imagery — strip the art
  and every screen is warm monochrome.
- The type is licence-vetted and offline-vendored (Satoshi was rejected on its
  licence, not its looks).

A system this constrained does not get "better" by importing someone else's skin.
It gets better by closing the few gaps the constraints leave open.

## The reference the question linked

The link in the request — `styles.refero.design/style/d4c51049-…` — is the **Warp**
style (warp.dev), a terminal-native obsidian aesthetic. It is the closest thing on
refero to what Keymaker already is: flat hairline surfaces, pills, monospace-forward
density, warm-ish near-black ground. It is a good instinct, and it also isolates the
one thing to leave behind — Warp carries a single phosphor-violet accent
(`#CBB0F7`), which is exactly what Nightpaper deliberately removed.

## The gaps worth closing

None of these needs a colour, a shadow, or a cool grey.

1. **No keyboard / command layer.** Wayfinding rests entirely on neutral contrast.
   A command surface adds capability and speed with no new hue. Highest value.
2. **Expressive range is deliberately narrow.** Three text tones, three icon sizes.
   Correct for consistency, but a data-dense screen (the container inspector) can
   read flat. The lever is density and rhythm, not colour.
3. **Motion is minimal.** 150–250ms opacity/transform. Micro-interactions raise
   perceived quality and still satisfy `prefers-reduced-motion`.
4. **The mono voice could carry more of the data.** JetBrains Mono is reserved for
   readouts; a more terminal-native treatment of the data surfaces is available
   without turning the app into a document.

## The shortlist (from the refero gallery of ~20 styles)

Chosen for a client-side, offline-first security tool. Rated by *how much is worth
borrowing for Keymaker*, not by how good the site is.

### 1. Warp — the linked style · borrow value: high

- **Borrow:** monospace-forward density (its 24px padding / 10px gaps map straight
  onto the inspector and share tables); flat hairline surfaces and pills (which
  Nightpaper already does — Warp validates the direction); a terminal identity that
  ties the web app to the Python/CLI core.
- **Leave:** the phosphor-violet accent (fails the palette gate); the pure `#000`
  canvas (the warm `#0E0D0B` is the more considered ground).

### 2. Linear — craft benchmark · borrow value: craft only

- **Borrow:** the command palette and keyboard model (closes gap #1 with no new
  hue); micro-interaction timing (the feel of quality, inside the reduced-motion
  rule).
- **Leave:** the visual skin — a Linear direction was already run (PR #116) and
  superseded by Nightpaper, so do not re-tread it; its indigo accent, cool greys
  and subtle gradients each break a Nightpaper rule.

### 3. AuthKit (WorkOS) — domain analog · borrow value: thematic

- **Borrow:** how a security/auth product signals trust through calm and generous
  negative space; step/flow composition for the encrypt → shares → paper-vault
  sequence.
- **Leave:** the literal frosted glass (blur + translucency is exactly what
  Nightpaper removed — take the composition, not the material); the cool navy-black
  ground.

Honourable mentions from the same gallery, if a re-pick is ever wanted: **Mercury**
(fintech trust, cool blue-hour dark) and **Origin Financial** ("midnight gallery of
quiet wealth"). Both trade on premium restraint; neither is a closer match than the
three above.

## What I'd do next, in priority order

1. A keyboard command layer (from Linear).
2. Lean the container inspector monospace-forward (from Warp).
3. Compose the encrypt/shares/vault flows for trust (from AuthKit) — more rhythm
   and negative space, not more chrome.
4. Spend the sparks, once, in the inspector — the blue/ember pair is already
   sanctioned for data-viz, and a single restrained readout is the one place colour
   is allowed to earn its keep.

Each of these is a separate, scoped change. None of them touches the palette
tokens, the shadow rule, or the warm-only discipline — which is the point. The
system is worth protecting; the work is behaviour, not repaint.

## Method and caveats

Grounded in `DESIGN-SYSTEM.md`, `STATUS.md` and the rendered implementation, which
is where this system's rigor actually lives. This review did not capture fresh
screenshots (the palette and craft are legible from the spec and the code). Warp's
hex values are exact, from the linked style page; the Linear and AuthKit swatches
in the visual version are representative of the published styles, chosen to show
direction rather than transcribe a spec.
