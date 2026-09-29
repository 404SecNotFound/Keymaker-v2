# Keymaker Section 06 usability notes

**Date:** 2026-09-29 · **Build:** the production export of the Section 06 branch
(parts a to f) · **Method:** `scripts/capture-screenshots.mjs` drives the built
page in headless Chromium at 1180 CSS wide, device scale 2, dark scheme, reduced
motion, and one reviewer read every captured screen along that scripted path.
This is an inspection of the screens, not a study with users: nothing here says
how a first-time owner actually behaves, only what the page shows them.

---

## What the screens show

| Shot | Where it is used | What it shows |
|---|---|---|
| `01-landing.png` | README | The Encrypt tab on first visit. The six steps sit above the container preview, content is **Next**, the rest **To do**. Format detail is off. |
| `walkthrough-3-container.png` | WALKTHROUGH, step 4 | The receipt after sealing: "Protected by Argon2id · AES-256-GCM + ChaCha20-Poly1305", names without parameters. |
| `walkthrough-4-verified.png` | WALKTHROUGH, Part 2 | The verify result, with the format line trimmed to "KEYM v3 · Argon2id · …". |
| `walkthrough-5-steps.png` | WALKTHROUGH, Part 2 (new) | Back on Encrypt after that verify: **Prepare recovery** done, **Check saved copy** next, because nothing was saved. |
| `07-decrypt-detection.png` | README | The container pane on the Decrypt tab **with Format detail on**, since the README text promises the parameters read back from the header. Every other shot has it off. |
| `13-recovery-tested.png` | this report | The Recovery tab after the walkthrough's verify: the backup is still there, and the recovery test reads "Verified with the password at …". |
| `14-verify-stale.png` | this report | A password typed after a verify: the green result has given way to "Changed since: credentials". |

The other eleven shots were recaptured from the same build but not read closely,
since Section 06 does not touch the panels they frame. All 18 are 2360px wide,
which `npm run test:screenshots` checks.

---

## Findings

| # | Finding | State | Recommendation |
|---|---|---|---|
| S1 | **The Recovery tab reported a change nobody made.** After testing the backup on the Decrypt tab, the Recovery tab said "The form on the Encrypt tab has changed since this backup was made (content)". The input type, the text box and the chosen file are shared by the two tabs, so the Decrypt side's input was read as the Encrypt form's. A File-mode test would also have said "input type". | **Fixed in this part.** Content and input type are compared only while the form is on the Encrypt tab; returning there restores both. `recovery-test-keeps.spec.ts` checks the Recovery tab after a text-mode and a file-mode test, and disabling the fix fails both checks. | None. |
| S2 | **The container pane's first-visit copy promises what it no longer shows.** It says it "itemises the container it will write, header byte by header byte", and its button reads "Show the header it will write". With Format detail off, which is the default since part c, the itemisation shows the ways in and the layout but no header bytes. | **Fixed.** The copy and the button now follow the switch: off, they name the version, the ways in and the layout; on, they keep "header byte by header byte". Checked in `workflow-expert-view.spec.ts`. | Reword to what is shown ("…itemises the container it will write: its version, its ways in and its layout"), or turn Format detail on when the button is pressed. The first is smaller and keeps one switch in charge. |
| S3 | **The step grid's rows do not line up.** "Check saved copy" and "Prepare recovery" wrap to two lines at this width, so in the second row "Create" sits higher than its neighbours and the three state words sit at two heights. | **Fixed.** Both: the labels are "Saved copy" and "Recovery test", and each step is two rows with the state at the bottom, so a row's labels share a top and its states share a line even where a label still wraps. Checked by measuring the rows in `workflow-steps.spec.ts`. | Shorter labels ("Saved copy", "Recovery"), or a grid that aligns the state words on a common row. |
| S4 | **"Check saved copy" names only half of what completes it.** Its sentence says "Download it or print the paper vault, then check the copy", but not how to check. The two ways are loading the saved file on the Decrypt tab and verifying it, or photographing every printed symbol on the Recovery tab. The walkthrough now says so; the page does not. | **Fixed.** The step's sentence names both ways, before and after a download or print has started. Checked in `test:backup-workflow`. | Name both ways in the sentence, or link to the Recovery tab's printout check. |
| S5 | **"credentials" is the page's word, not the owner's.** The stale-verify notice says "Changed since: credentials" for a newly typed password. | **Fixed.** The notice now says "password or recovery shares". Checked in `test:backup-workflow` and `verify-evidence.spec.ts`. | "password or recovery shares". |
| S6 | **Long sentences set in monospace.** The Recovery tab's "Saved copy" and "Recovery test" values are full sentences in the monospace data face, which reads slowly at this length. Predates Section 06. | **Fixed.** "Saved copy" and "Recovery test" are in the body face; "Recovery shares" keeps monospace. Checked by computed font in `recovery-test-keeps.spec.ts`. | Body face for sentences; keep monospace for values such as byte counts. |
| S7 | **The Format detail label wraps.** "Format detail (header bytes, offsets, KDF parameters)" takes two lines in the pane header at 1180 wide. | **Fixed.** The label is "Format detail"; the list is in a tooltip beside it and in the switch's accessible description. Checked in `workflow-expert-view.spec.ts`. | Keep "Format detail" as the label and move the list into a tooltip or the pane's help text. |

S1 was a defect in behaviour and is fixed in the same change as this report.
S2 to S7 are copy and layout, and each was fixed in a pull request of its own
after the report was written; the rows above record how each was checked.

---

## What held

- The steps never ran ahead of the evidence in any captured state: after a
  verify of the page's own copy, recovery was done and the saved copy was not.
- With Format detail off, the KDF and cipher names, the version and the checks
  were still on screen in each of the shots read for this report.
- The receipt, the steps and the recovery test survived the round trip through
  the Decrypt and Recovery tabs, which is what part e set out to do.
