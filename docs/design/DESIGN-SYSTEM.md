# Graphite — the Keymaker workspace design system

Approved 7 September 2026. Linear-inspired component styling and the approved
Keymaker layout. Neutral black and graphite replace the earlier brown/taupe
Nightpaper palette at the user's request. See [BAR.md](BAR.md) for the reference.

## Surfaces

| Token | Value | Use |
| --- | --- | --- |
| Canvas | #090A0C | Page and navigation |
| Card | #111316 | Content, protection, and inspector panels |
| Inset | #191C20 | Fields and segmented tracks |
| Raised | #23272E | Hovered inset controls |
| Line | #2A2E35 | Section dividers and quiet panel edges |
| Line strong | #454B55 | Active borders and field edges |
| Selection | #102A32 | Active navigation and selected options only |
| Selection line | #428795 | Selected option borders, never body text |

No brown undertones, glass, background gradients or drop shadows. Surfaces
separate sections through neutral lightness and crisp 1px edges.

## Typography and contrast

Spline Sans Variable, pinned to @fontsource-variable/spline-sans 5.3.0
(OFL-1.1), for interface text and headings. JetBrains Mono, likewise
self-hosted, for bytes, codes, shares and cryptographic settings. Never use a
remote font. Both Latin subsets are precached; the Spline Sans licence ships
at /licenses/spline-sans-OFL.txt. Body copy uses natural tracking (0).

| Text | Value | Canvas | Card | Inset | Raised |
| --- | --- | --- | --- | --- | --- |
| ink | #F0F2F5 | 17.66:1 | 16.59:1 | 15.24:1 | 13.36:1 |
| body | #B1B7C1 | 9.82:1 | 9.23:1 | 8.48:1 | 7.43:1 |
| muted | #949CA9 | 7.16:1 | 6.72:1 | 6.18:1 | 5.42:1 |
| heading | #F7F9FC | 18.78:1 | 17.64:1 | 16.21:1 | 14.21:1 |

Titles 28–32px/400, section headings 15px/500, body 13–14px/400,
captions/data at least 12px. No opacity modifiers on body or caption text.
Contrast must remain at least 4.5:1 for ordinary text; accessibility floors
override the visual reference.

## Geometry and controls

- Panels: 12px radius, 22–24px padding, 16px padding on phones.
- Inputs and buttons: 8px radius; compact navigation 6px. Switches and dots
  remain round. Primary buttons are not pills.
- Primary: action blue #84B9FF fill, #111316 text, #ACD0FF hover.
- Outline actions: transparent or inset fill, line border, action-blue text.
- Utility controls (copy, clear, reveal): neutral until focused or hovered.
- Disabled: transparent fill, line border, muted label; not reduced opacity.
- Focus: a visible 2px action-blue ring, offset from the control.
- Motion: restrained 150–200ms color/opacity changes, no scale on press.
  Existing reduced-motion handling remains. Completion may use 400–600ms.

## Accent and status

Container diagrams keep blue #5C7FFF and ember #FF7A47. These marks are the
visual focal point against the neutral shell, not decorative glows behind forms.
Do not use diagram colors for form text or fill entire panels with them.

Section numbers and panel headings use ice blue #9EC5FF. The marker-only
version was too subtle in review: 15px panel titles now carry the accent too.
Page titles remain crisp off-white #F7F9FC. Body text and descriptions remain
neutral silver. Ice blue marks structure, not a successful outcome.

Action blue #84B9FF identifies links, task titles, upload prompts and actions
such as Random, Passphrase and recovery verification. Hover is #ACD0FF.
Selected options and the active destination use cyan #6EE7F2 over #102A32,
with #428795 borders. Selection is also expressed by a filled shape, border,
and aria-pressed/aria-selected; it never relies on hue alone. Switch tracks
use cyan for enabled settings, not mint: configuration is not validation.
Within a selected card, the option title is cyan but its description stays
silver. Filenames and entered text stay off-white, with cyan file icons.

Blue and cyan clear 7.40:1 and 10.26:1 respectively on raised surfaces.
Muted text clears 5.42:1 on selection fill; selection borders clear 3.66:1
against raised surfaces. Dark primary-button text clears 9.18:1 on blue.

Semantic status uses brighter mint #69DBAA, warning #D9A23F and danger #E5624E.
Ice blue and mint clear 8.48:1 and 8.79:1 respectively on the raised surface.
Use status colors only for real outcomes or warnings, with a textual explanation.
For a typed password, mint means only "Minimum policy met"; retain the explicit
disclaimer that this is not a strength rating. Empty inputs carry no success state.
Primary and destructive fills use dark text, not white where contrast fails.

## Layout and navigation

Persistent workspace navigation on desktop; a contained horizontal tab strip
on mobile. Keyboard direction matches the navigation orientation. One controlled
form, not parallel desktop/mobile secret fields. Sections: Content and Protection.
The inspector sits alongside at desktop widths, below on narrower screens.

Workspace, Encrypt, Decrypt, Recovery, Audio and Tools are distinct views.
No marketing hero, fabricated activity feed, accounts, cloud storage or scorecards.
Keep advanced cryptographic options, cancellation, auto-lock and offline tools.

## Container preview and recovery honesty

The preview is a plan until real bytes exist. Its diagram is a header schematic
derived from real format dimensions. Each cell's byte extent is stated; it is not
random ciphertext or an entropy meter. Parsed metadata is not successful verification.

A downloaded file is only a download request; the user must confirm their saved
copy. Recovery shares configured is not the same as shares issued. Verification
states which method was tested and never renders or downloads plaintext.

## Icons and screenshots

Lucide only, default stroke 2: 14px inline, 16px controls/navigation, 20px empty
states. Preserve the Keymaker keyhole mark. Rendered icon and palette audits
remain required, including neutral text/ground contrast.

README captures remain 1180 CSS pixels at DPR 2 (2360px intrinsic), produced by
`scripts/capture-screenshots.mjs`. Capture viewport-width bands with padding,
not tight element crops. Presentation previews may also include mobile captures.
