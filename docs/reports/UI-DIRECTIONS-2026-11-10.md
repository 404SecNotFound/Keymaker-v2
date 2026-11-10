# Keymaker UI/UX directions

**Date.** 2026-11-10 · **Status.** Proposal. Nothing in the shipped UI was changed.

**Method and limits.**

- References come from the Refero MCP (searches of flows and screens, web platform).
- The `refero-design` skill is not installed in this session type, so its research method was not loaded. Installing it needs the owner's approval.
- I read Refero's written descriptions of each reference. I did not open the reference images. Claims about a reference are [Unverified] beyond that description.
- The current UI was judged from `docs/screenshots/01-landing.png`, the two earlier reports and the 10 November UI review.
- Refero has little for "verify a build signature". The one near match is a marketing page. Trust and verification screens below are [Inference], not reference-led.

## What the current UI gets right

Keep these in every direction.

- The six-step list never runs ahead of the evidence (USABILITY-2026-09-29, "What held").
- The author-reviewed banner and "What it does not protect against" link sit above the fold.
- The container preview shows what will be written before it is written.
- "sealed · no connections" status is on screen all the time.

## What the review says is failing

These are the problems a direction has to solve. Numbers refer to REVIEW-2026-11-10.md.

1. A generated password can seal a backup without the owner ever seeing it.
2. A finished backup is easy to lose. Causes are a reload from another tab, a click on the active pill, and a single auto-download.
3. Three unlock paths (password, shares, passkey) are chosen in different places and can contradict each other.
4. Read failures are reported as a wrong password.
5. Text fields show no focus indicator.

## Direction A. Guided custody

One task on screen at a time. The six-step list becomes the page's spine, and two steps become gates.

**References.**

| Reference | What it shows | Link |
|---|---|---|
| Wealthsimple, authenticator setup | Eight steps that end on "Save your recovery code" | https://refero.design/flows/8515 |
| Zapier, 2FA setup | Left step list beside one form, with an optional emergency step | https://refero.design/pages/97b9b17e-f7b5-4b3e-82f6-3cf702a9c604 |
| Mercury, check upload | Sidebar stepper, drop zone, progress rows, Review and Back | https://refero.design/pages/bade88f7-e28a-4fb5-a40d-1096fff2b9a1 |
| n8n, recovery codes | "Download your recovery codes [2/2]" with a separate "I have saved them" action | https://refero.design/pages/29085c97-a7e6-4d5a-8b8e-ca58176f920f |
| 1Password, secret key | One key, one "Save PDF" button, one note that it cannot be recovered | https://refero.design/pages/b09e02d6-414d-4df3-a35f-8d1698256ef4 |
| Family, new recovery code | One-time display, copy control, warning it will not be shown again | https://refero.design/flows/6203 |

**What changes.**

- Content, Access rule and Review each get the main column to themselves. Back and Next replace scrolling.
- A generated password is shown when made. Next stays disabled until it is copied, revealed or retyped.
- "Saved copy" becomes a screen with a Download button that works again until wipe. The text says "download requested" until the owner confirms.
- "Recovery test" is the last screen and uses the saved file, not the copy in memory.
- The container preview moves to the Review step.

**Cost.** Largest change. `secret-form.tsx` (1,889 lines) splits by step. Experts lose the single-page view unless a toggle keeps it.

**Best for.** A first-time owner backing up a seed phrase.

## Direction B. Workbench, tightened

Keep the single-page layout. Fix custody and errors inside it, and make the command palette the fast path.

**References.**

| Reference | What it shows | Link |
|---|---|---|
| Linear, shortcuts panel | Searchable shortcuts in a side sheet over the workspace | https://refero.design/pages/84407ff1-9cae-4ace-92db-5027844e3437 |
| fal, command palette | Centred palette with suggested destinations and an Esc hint | https://refero.design/pages/43640d5d-fc7d-4c13-a2e0-9b40376b835f |
| Excalidraw, palette empty state | "No matching commands" with key hints | https://refero.design/pages/90a2b441-419f-4b7d-be25-a0ec0b55c3bd |
| Family, invalid password | Error under the field inside the prompt, Cancel and Continue kept | https://refero.design/pages/19f4a541-cf62-4573-9864-2da0f1a523ad |
| Workflow, incorrect password | Field outlined in error state with the message directly beneath | https://refero.design/pages/eef37ed2-4c8c-4647-b922-776ad042f9fc |

**What changes.**

- One "Opens with" selector (password, shares, passkey) replaces the scattered toggles, on Encrypt and Decrypt.
- Errors appear under the field that caused them. "This file could not be read" and "wrong password or shares" become separate messages.
- The palette lists only commands that are safe in the current state. It is closed while one-time shares are shown (fixed in this session).
- Generated passwords reveal on creation. The receipt keeps a re-download button.
- Focus rings return on every text field.

**Cost.** Smallest change. Mostly `secret-form.tsx`, `shared-ui.tsx` and `command-bar.tsx`. Each item can ship as its own PR with a browser test.

**Best for.** The current audience, people who read the format detail.

## Direction C. Emergency kit first

Organise the app around the thing the heir receives, not the act of encrypting.

**References.**

| Reference | What it shows | Link |
|---|---|---|
| 1Password, Emergency Kit | A named, downloadable kit with the secret and an explanation | https://refero.design/pages/0403bbb8-4b27-443e-afa9-388c414bf51a |
| Skiff, recovery key | Blurred key, QR and copy icons, one "Download key" button | https://refero.design/pages/f8260bab-bca7-4a14-a2b2-2d26b71a3582 |
| Skiff, recovery with key | The receiving side, where a recovery key file restores access | https://refero.design/flows/1885 |
| Family, export secret keys | Password prompt, warning banner, blurred phrase that reveals on hover | https://refero.design/flows/6197 |
| Chargetrip, store recovery codes | Monospaced list, copy icon, short text on why to store them | https://refero.design/pages/6b52e93c-e3da-4e2e-a463-3a763dfdb7ad |

**What changes.**

- The home screen offers two doors. "Make a kit" and "Open a kit someone left me".
- "Make a kit" ends on a kit page. It lists the backup file, the paper vault, the shares and the recovery instructions, each with a saved or not-saved state.
- The Recovery tab and the inheritance plan merge into that kit page.
- "Open a kit" is written for a person who has never seen the app. It asks what they are holding (a file, paper, strips, a WAV) and routes from there.
- Encrypt and Decrypt remain as the expert path behind the doors.

**Cost.** Medium. New home and kit pages. `inheritance-plan.tsx`, `recovery-tab.tsx` and `paper-vault.tsx` are regrouped. The crypto and the form stay as they are.

**Best for.** The inheritance case, which is the reason the shares and the paper vault exist.

## Recommendation

[Inference] Start with B, then build C on top of it.

- B fixes four of the five failures with the least risk, and every item is testable on its own.
- C is the direction that makes the product different, and it does not need the form rewritten.
- A solves the first-time case best but costs the most and removes the layout current users know.

## Decision needed

Which direction should be prototyped. A, B, C, or B followed by C. No shipped UI changes until that is answered.
