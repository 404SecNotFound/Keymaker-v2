# Keymaker roadmap

Derived from two inputs — a four-agent security audit and a competitive feature
blueprint — reconciled against the code at `d48019f` and cut down hard.

The blueprint proposes 25 features. **Nine survive.** The rest are cut or
deferred below, with reasons, because a tool whose entire moat is trust
engineering cannot afford to ship sixteen half-features.

**Selection rule.** A candidate survives only if it does one of three things:

1. fixes something that is wrong in the shipped product,
2. strengthens the trust moat (verifiability, recoverability, honesty), or
3. is a differentiator nobody else has **and** works with zero servers.

"Would be cool" is not one of them.

---

## Corrections to the input documents

Verified against `d48019f`, not assumed.

| Claim | Reality |
|---|---|
| Audit: `scripts/fixtures/keymaker/` "absent from the audited checkout — confirm whether git-ignored or a broken regression gate" | **Present and tracked**, 7 files, not gitignored. The audit's sandbox `npm ci` failed; the gate is intact. |
| Audit Wave 2 #7: "Precache manifest for true offline completeness" | **Already shipped** as KM-26. Coverage went 3/17 → 17/17 chunks, with a browser test that counts what the worker holds. |
| Audit C-I3: "CSP `script-src` keeps `'unsafe-inline'`" | True in source; the build replaces it with per-file sha256 hashes and fails closed. The residual item is moving the inline script to a static file — cosmetic, not a hole. |
| Audit C-I1: unseparated `password‖keyfile` | Already designed out in `FORMAT-V2-DESIGN.md` §4.1. |
| Blueprint #1: passkey PRF as a security upgrade | **Reframed.** See "Honest framing" below — with a mandatory passphrase fallback it is a convenience and phishing-resistance win, not added strength. |

---

## Phase 1 — Fix what is broken

**Nothing else starts until this lands.** These are defects in the product
people are using today, and three of them make a backup tool lie to its user
about *why* their file did not open. In a category where the failure mode is
"I cannot get my money back", a misleading error message is not a papercut.

| Item | Sev | What |
|---|---|---|
| B1 | **High** | No async-operation guard. Switching tab or input type mid-KDF lets the stale operation fire "Success!" on the wrong tab and — via the unconditional `setPassword('')` in its `finally` — **wipe a password the user has since typed**. Fix: op-sequence ref, bail out of every post-`await` `setState`/toast when stale. |
| B8 | Low | `processData` has no `isLoading` early-return; reentrancy is guarded only in render. Same root cause as B1, fix together. |
| B3, B4 | Med | `knownSafeMessages` is an **exact-match** list, so "Encrypted data is too large…" and "KDF parameter out of range: …" (interpolated, can never match) both surface as *"the password may be incorrect"*. Tampered and oversized files are misreported as wrong-password. Fix: typed error codes, not string matching. |
| B5 | Med | Legacy IBTZ path skips NFC normalization — only `keymaker-crypto.ts` normalizes. A legacy file encrypted with an NFC password rejects the canonically-equivalent NFD string. Fix: retry NFC/NFD variants on legacy auth failure. |
| B6 | Low | `parseKeym` reads Argon2 params via `DataView` at offset 7+ after only a `length < 8` check; `minLen` is validated at line 607, too late. 8–13-byte inputs throw `RangeError`, re-wrapped as wrong-password. |
| B2 | Med | "Imported from IttyBitz" re-encryption nudge is dead code — `TOAST_LIMIT = 1` means the unconditional "Success!" replaces it instantly. |
| B7 | Low-Med | Dice tool silently coerces invalid `sides` to 6, so a cleared field showing "256 bits" describes a d6 nobody rolled. Inflated entropy is the exact failure class the tool's own comments warn about. |
| B9 | Low | `uint8ArrayToBase64` string-concatenates ~3,200 chunks at 100 MB. `chunks.join("")`. |
| W-L1 | Low | `base-uri 'self'` → `'none'`. The app has no `<base>`. |
| C-L3 | Low | KEYM inputs under 5 bytes fall through to the legacy v0 path and burn 1M PBKDF2 iterations before failing. Special-case prefixes of `KEYM`. |

**Tests, same phase** — these bugs shipped because the gaps existed:
`bip39.ts` has zero tests, NFC round-trip is untested (would have caught B5),
dice math untested (B7), UI logic untested (B1–B3).

**Gate:** every item above has a test that fails without the fix.

---

## Phase 2 — Unfreeze and prove

Everything here is **independent of the wire format**, so it can proceed in
parallel with Phase 3's design work and ship without a migration.

### 2.1 Crypto in a Web Worker — **shipped**

Argon2id freezes the tab for 1–3 s today. A Worker buys four things at once:
a responsive UI, real cancel/progress, transferable `ArrayBuffer`s that kill
the double copies, and — the part that matters most — **a separate heap** for
key material, away from React state and DOM strings. `worker-src 'self'` is
already in the CSP. This also unblocks 2.2 and 2.5.

### 2.2 Signed build provenance — **shipped**

The README concedes that "whoever serves the bundle is the trust anchor". Emit
`SHA256SUMS` of `out/`, sign with **Sigstore keyless** (the deploy job already
has OIDC), publish as a release asset, document `cosign verify-blob`. This
converts the project's central honesty admission into something a user can
check. For a zero-server tool this is the highest-value trust item that exists.

### 2.3 Verify-only mode — **shipped**

"Prove this backup still opens with this password" — decrypt, authenticate,
discard the plaintext, never render it. Tiny to build, and it makes backup
hygiene a first-class flow. Nobody ships this.

Worth stating precisely, because the honest version is narrower than the pitch:
authenticating an AEAD ciphertext *requires producing the plaintext*. Neither
AES-GCM nor ChaCha20-Poly1305 has a verify-the-tag-only operation and WebCrypto
exposes no such API, so the plaintext exists in the worker heap for the length
of one call. What verify-only removes is the part under the user's control — it
never reaches the DOM, a Blob, the clipboard, or a file. The result reports the
byte count as well as a tick, because "it opens" alone does not catch the right
password on the wrong backup.

### 2.4 In-app recovery kit — **shipped**

Footer link → the bundled `RECOVERY.md` and `keym.py`. Near-zero cost, and it
means the recovery path travels with the container instead of living in a repo
the user may never find.

Both are copied into the export at build time (`scripts/build-recovery-kit.mjs`,
fail-closed on a missing or truncated source) and precached via the service
worker's `APP_SHELL`. The precaching is the point: the moment someone needs
these is the moment the website is unreachable, so a recovery document that
requires the site to be up is not a recovery document.

### 2.5 KDF auto-calibration — **shipped**

Benchmark ~300 ms in the Worker, pick the strongest Argon2id parameters that
fit a chosen unlock-time budget. KeePass does this; no browser tool does.

Three things were less obvious than "time it and scale":

**A one-point model always under-provisions.** The first Argon2id call in a
worker pays for instantiating the wasm module, and there is a fixed per-call
cost besides. A single measurement cannot separate that from the per-byte cost,
so it attributes the overhead to memory and concludes the device is roughly
three times slower than it is. Two points at different memory sizes separate
the intercept from the slope; a discarded warm-up keeps wasm instantiation out
of both.

**The ceiling is a portability decision, not a cryptographic one.** §6 permits
256 MiB and calibration stops at 128, because *the device you encrypt on is not
the device you recover on*. A container calibrated to a desktop can be painful
to open on the phone someone reaches for in ten years.

**"8 MiB" means two different things.** It is a different answer when it is the
floor a slow device could not beat than when it is what the budget bought, so
the result carries which constraint bound it and the UI says so rather than
printing a number. A device that cannot reach the target is told it will be
slower, not shown the target it missed.

The solver is pure and takes measurements as data, which is what lets it be
tested against devices that do not exist — one fast enough to exhaust the
ceiling, one too slow to reach the floor, one whose samples are incoherent.
Every result is pushed through `validateKdfParams` rather than compared against
a second copy of §6's numbers.

### 2.6 Session auto-lock and clipboard hardening — **shipped**

Inactivity timer clearing password/plaintext state, a "Wipe now" button, and an
unconditional clipboard overwrite with a visible countdown (drop the failing
`readText` comparison). Small, and they close the gap between what the threat
model claims and what the UI actually does.

The `readText` comparison was worse than useless: it needs permission and
document focus, Firefox does not offer it to page script at all, and it sat
inside a bare `catch {}` — so the read threw, the overwrite never ran, and the
toast said the clipboard would be cleared while the seed phrase stayed in it.
The overwrite is now unconditional, which has a real cost — anything copied in
the meantime is cleared too — so the countdown is on screen with a **Clear now**
control rather than the behaviour being a surprise.

Auto-lock fires after five minutes idle and spends the last 30 seconds visibly
counting down with **Keep open**, because someone transcribing a 24-word phrase
onto paper is doing exactly the thing a silent wipe would ruin. A wipe is
deliberately not a reset: cipher, KDF and input-type choices survive it.

### 2.7 Accessibility — **shipped**

Non-colour cue for BIP-39 validity (it is colour-only today, invisible to
colour-blind users), aria states, `axe-core` in CI.

**Gate:** Worker landed with cancel working; `cosign verify-blob` documented
and demonstrated against a real release. **Both met** — the signing job ran
against a real OIDC token on the first deploy after 2.2 merged, and verifies its
own signature before publishing it.

**Remaining in this phase:** nothing. 2.5 was the last item.

### What 2.7 actually found

Two defects, and the more serious one is the one no tool reports.

**axe found three unnamed buttons.** The ⓘ controls explaining the key file,
the password policy and filename privacy were icon-only `<button>`s with no
accessible name, so a screen reader announced three anonymous "button"s among
the security settings. They also carried `focus:outline-hidden` with nothing
put back, so a keyboard user lost their place entirely (WCAG 2.4.7) — a defect
invisible to anyone driving the page with a mouse, which is why it survived.
All three are now one `InfoTip` component with a name and a 2px accent ring.

**axe did not find the colour-only recovery-phrase check, and could not.** The
encrypt-side BIP-39 validator spoke in border tint alone: green for a valid
phrase, red for one with a word the list does not contain. That red border is
the last warning before a mistyped phrase is sealed into a backup nobody may
open for a decade, and roughly one man in twelve cannot tell it from the green
one. Every screen reader got nothing. **axe reports zero violations for a red
border** — measured, by reverting the fix and watching all six scans stay
green.

It was colour-only deliberately: the original note reasoned that a text badge
would tell a shoulder-surfer the blurred field holds a seed phrase. That
concern is real but does not bite, because the indicator only appears for
phrase-shaped input — an icon leaks precisely what the coloured border already
leaked. The wording is kept generic for the same reason: "a word isn't
recognised" is a spellcheck result, not an announcement about a wallet.

---

## Phase 3 — KEYM v2

The design already exists in [FORMAT-V2-DESIGN.md](FORMAT-V2-DESIGN.md). Two
changes to it, both from the blueprint:

- **Add a multi-slot envelope key.** One random master key per container,
  wrapped independently by passphrase / keyfile / passkey-PRF / Shamir-share
  slots. This is the architectural unlock for three separate Phase 4 features,
  and adding it later would mean a *second* format migration. It also gives
  cheap re-passwording without re-encrypting the payload.
- Keep everything else as specified: chunked STREAM AEAD, domain-separated
  length-prefixed key material, bounds normative from the start, `keym2:` armor.

**Process is non-negotiable and is the reason v1 is trustworthy:**

1. Write `reference/keym2.py` **from the document alone**, before any
   TypeScript. That is what produced KM-14 — the only finding in this project's
   history that came from testing the specification rather than the code.
2. FORMAT.md, the reference, and the fixture corpus update in the same PR.
3. v1 decrypt stays frozen forever; the v1 fixture corpus stays append-only.

**Gate:** Python and TypeScript agree bit-for-bit on every KDF × cipher combo;
the whole v1 corpus still decrypts; truncation, reordering, duplication and
cross-container splicing all fail authentication.

---

## Phase 4 — What v2 unlocks

Only after Phase 3 ships. Ordered by value.

| # | Feature | Why it survives |
|---|---|---|
| 1 | **Shamir k-of-n key splitting** — **shipped**, §4.1 below | Slots made this as clean as predicted: a share set is a slot and the slot record did not change shape. ~150 lines of GF(256), as estimated. |
| 2 | **Paper vault print kit** — **shipped**, §4.2 below | Ciphertext as QR grid, condensed recovery procedure, Shamir share slots, password *hint* field. Safe-deposit-box ready. Composes directly with 4.1, and there is now a concrete debt to pay: the share modal's Print button is `window.print()` against a screen layout, which is the weakest part of what 4.1 shipped. A share set printed from a dark-themed dialog is not a paper backup. |
| 3 | **Self-extracting HTML decryptor** — **shipped**, §4.3 below | One `.html` = ciphertext + a minimal WebCrypto-only decryptor. The "openable by a non-technical heir in 2040" story, with `keym2.py` as the second line. PBKDF2/AES-GCM only — no WASM — and §7.2 now says so normatively rather than as advice. |
| 4 | **Passkey / WebAuthn PRF slot** | Phishing-proof daily unlock. Read the honest framing below before selling it as strength. |
| 5 | **Inheritance wizard** — **shipped**, §4.5 below | Pure composition of 1–3 plus the existing recovery doc. Cheap once they exist; incoherent before — and the composition turned out to have one real decision in it, which is the section below. |

**Gate for each:** fixture-corpus entries and Python-reference parity, per the
append-only rule. No exceptions — that rule is the moat.

### 4.1 Shamir — what shipped, and what has not

**Shipped, in that order:** `FORMAT-V2-DESIGN` §4.6 written first, the Python
reference derived from it, then the TypeScript, then byte equality on the
container *and* all five share strings. Three fixtures added, one per cipher,
each carrying its shares; the twelve existing entries untouched. Reference
self-test 109 → 189 checks, v2 conformance 61 → 74.

**The UI shipped separately, and item 1 is now complete.** Enrolment is a write
option beside the cipher and KDF, because a slot has to be added while a secret
that opens the container is in hand and that moment is the encrypt itself. On
the other side, "Use recovery shares" replaces the password field outright — an
heir has no password, so the way in has to be reachable without one.

Three things that shaped it:

- **One worker op, not two.** Enrolling needs a secret that already opens the
  container. Splitting it would mean either holding the password in the page
  past the encrypt that should have cleared it (U13), or asking for it twice.
- **The shares exist once.** §4.6 discards the share secret when the slot is
  wrapped, so nothing can reissue them. They go straight to a modal that says
  so, rather than being left somewhere to be noticed.
- **A share pasted into the container field is named as a share.** That is §7's
  wrong-box paste with a second encoding to be wrong about for the first time,
  aimed at the person least equipped to work it out.

**Two things the exercise turned up**, both recorded in the design document:

- **F8**, the first finding in this project that is not about the format.
  Re-passwording writes a *passphrase* slot, so aiming it at a share-set slot
  converts one and turns `n` printed papers into scrap, silently. `rewrap_slot`
  now refuses without an explicit flag.
- The conformance test had to compare **shares**, not only containers.
  Transposing the coefficient layout in one implementation leaves the container
  byte-identical and changes only the printed strings — so a container-only
  comparison would have passed while the two sides issued mutually-unusable
  share sets.

**Before the UI lands, re-read *Honest framing to preserve*.** Any `k` shares
open the container without the password, which makes each share as sensitive as
the password itself. That belongs on the screen and on the paper, not only here.

### 4.2 Paper vault — what shipped

**Format first, as always.** §7.1 specifies `KMPART1:<i>/<n>:<base64url>`, a
paper transport encoding, because a container of any interesting size does not
fit in one QR. The prefix continues §7's disjointness rule rather than bending
it: `KM` is now a family, `KMS` a share and `KMP` a part, separated at byte 2. A
prefix inside the `ke` family — `keym2p:` — was the obvious choice and was
rejected for leaving armor and a *fragment* of armor distinguishable only at
byte 6.

Then Python, then TypeScript, then the parity gate. `keym2.py` gained `split`
and `join`; the conformance suite compares the **emitted strings**, not just the
reassembled container, for the same reason §4.6 had to compare shares —
transposing a slice boundary leaves both sides reassembling correctly while
their printed pages are mutually unusable. Reference self-test 189 → 203, v2
conformance 74 → 87.

**The debt is paid.** The share modal's Print was `window.print()` against a dark
dialog, which produced a screenshot of a modal. It now renders a real sheet:
the container as scannable symbols, a ruled reminder line, share slips with cut
lines and a holder field, and the procedure to open it all with `keym2.py`.

Four decisions worth recording:

- **Error-correction level M, not L.** The screen QR uses L, right for a phone
  two feet away. Paper gets folded, stained and photocopied; 15% recovery for a
  third fewer bytes is the trade that matches the medium.
- **The hint is a ruled line, not a container field.** The roadmap asked for a
  "password hint field". A hint stored in the ciphertext is a hint handed to
  whoever steals the ciphertext, and it travels everywhere the file goes. On
  paper it is exactly as exposed as the paper.
- **No checksum on a part.** The AEAD already covers the container. A second
  integrity mechanism only creates a case where the two disagree.
- **A single-part backup is still `1/1`.** Special-casing it buys an untested
  branch and a drawer search for pages that were never printed.

**Found by a negative control.** The first version of the browser gate asserted
the sheet's own colours under print media and passed happily with the
`body * { visibility: hidden }` rule deleted — i.e. with the whole dark app
printing around it, which is the entire bug 4.2 exists to fix. The test now
asserts the app's own `main` and `h1` are hidden, and the control bites.

### 4.3 Self-extracting page — what shipped

**Format first.** §7.2 defines a *profile* rather than an encoding: the subset
of KEYM v2 a reader can implement with `crypto.subtle` alone — cipher `0x00`,
`slot_type 0x00`, `slot_kdf_id 0x00`, no key file. The subset is **forced, not
chosen**: WebCrypto has PBKDF2, HKDF, SHA-256 and AES-GCM, has never had
Argon2id or ChaCha20-Poly1305, and no proposal adds either.

Then Python, then TypeScript, then the parity gate. Reference self-test
203 → 225, v2 conformance 87 → 107.

**The container inside a page is an ordinary container**, so `keym2.py`, the app
and the page are three independent readers of one file. A bespoke "simplified"
container for the artefact would have thrown that away for nothing.

Four decisions worth recording:

- **The page carries its own container, not a second slot on the user's.** The
  envelope makes the other option look free — add a PBKDF2 slot beside the
  Argon2id one and the page opens the same file — and it is wrong, for a reason
  that generalises past this feature: **a container is only as strong as its
  weakest slot.** Anyone holding those bytes would attack the PBKDF2 slot and
  ignore the other, so enabling the convenience would silently downgrade the
  real backup. Slots are an unlock-path mechanism, not a strength mechanism.
- **Key files are refused rather than supported.** Embedding one puts both
  factors in a single file, which is the property a key file exists to deny;
  dropping it writes a weaker container than the user believes they have.
  Refusing is the only honest third option.
- **Shamir is excluded for a smaller reason, and it is named** because GF(256)
  is forty lines and the exclusion looks over-cautious beside two that are
  forced. §4.6's share *text* is a second encoding, and every line of it in the
  page has to still be right in 2040 with nobody to fix it.
- **Sentinel comments, not "find the `keym2:` in the file".** The page's own
  prose contains that string — it tells the reader to run `keym2.py` — so a
  scanner finds a sentence before it finds the backup. Comments rather than a
  `<script>` or a data attribute keep the armor as *visible text*, which is the
  case the artefact exists for: if the JavaScript will not run, the container is
  still there in a text editor. A browser test reads it back with JavaScript
  disabled entirely.

**The UI names its own refusal.** Argon2id is the recommended default, so most
containers cannot become a page — and the export does not disappear for them, it
says which change would allow one and states the trade in both directions.
Hiding it would make the feature invisible to the majority.

**Found by running it rather than reading it.** The decryptor's element handles
were `var status = …`, and `window.status` is a legacy *string* property, so the
element was coerced and every later use failed on a string. Invisible to review,
to `tsc` and to the conformance suite; a browser found it on the first click.

**Two conformance gaps found by controls that failed to bite.** The suite never
checked the key-file exclusion against the TypeScript, and never handed its
extractor a page it was supposed to refuse — so removing either check changed
nothing. Both are covered now. A third control appeared not to bite because a
sentinel mismatch *crashed* the suite instead of naming the disagreement, which
is the lesson `bridge()` already records, now applied to the section that needed
it.

**And one redundancy the controls exposed as untestable.** `extract` stripped
whitespace across the whole armor body, which `dearmor` then did again — so
deleting the first copy was unobservable and no control could be written for it.
It now strips only the ends, which is the part with an actual job: letting the
prefix check see the prefix.

**A 4.2 gap closed on the way past.** §7.1 requires a paper part pasted into the
container field to be reported as *part i of n*; the encoding and
`looksLikePaperPart` shipped, and nothing ever called them. The rule was
unimplemented in the shipping UI. It is wired now, beside §7.2's own wrong-box
paste — which extracts and proceeds rather than reporting, because unlike a
share, a page in that box *can* be used.

### 4.5 Inheritance wizard — what shipped

**No format, no crypto, no new artefact.** Every piece already existed, already
had a Python counterpart and already had a gate. This item is the orchestration,
and it earns its place because the composition turned out not to be neutral.

**The three artefacts disagree about the container, and something had to
decide.** The backup file and the paper vault want the strongest settings the
device can carry. §7.2's page cannot have them — WebCrypto has never had
Argon2id. Left unresolved, a user picks Argon2id (the recommended default),
reaches the page export, and is refused; or worse, is quietly given something
weaker than they chose.

The resolution: **a package holds two containers of the same plaintext**, the
primary under the user's settings and the page's under PBKDF2/AES. Not one
container with two slots, which is the tempting version and is the same mistake
§7.2 already refuses — a container is only as strong as its weakest slot, so a
PBKDF2 slot beside an Argon2id one downgrades the backup outright. Two
containers keep the weakness inside the artefact that needs it, and **declining
the page leaves nothing weak in the package at all**. That is a real choice with
a real cost, so it is on the screen where the choice is made.

Three smaller decisions:

- **The page gets no share set.** It is the copy most likely to be stored
  casually — emailed to an executor, left on a drive — and enrolling shares on it
  would mean the same *k* slips also open a PBKDF2 container. Strictly worse than
  the trade the page already makes. The heirs' route is the primary container.
- **One password, taken once.** A package whose two halves take different
  passwords half-works at the worst possible moment, and asking twice is what
  U13 already refused to do. Both encryptions happen in one operation.
- **The letter is plain text and does not soften the share warning.** "Honest
  framing to preserve" says any *k* shares decrypt without the password, which
  makes each share as sensitive as the password itself — and the person who needs
  that sentence is whoever is about to put three slips in one envelope.

**The orchestration is a library function, not logic inside the dialog**, so
`crosstest2.py` drives the same function the wizard drives. A separate assembly
path in the test would be a second implementation of the package and the first
thing to drift. The gate opens a package **three ways** — password, two of three
shares, and through the page — because the package's whole value is that they
are alternatives, and one that works two ways out of three fails precisely the
heir who was handed the third. v2 conformance 107 → 121.

**One control bit harder than its test.** Making the page reuse the primary
container does not produce a wrong package — it produces *no* package, because
§7.2's policy check refuses to embed a chained/Argon2id container. The guard is
structural rather than test-enforced, which is the stronger outcome.

**And one more test found to be weaker than it looked.** The threshold-clamp
check filled the threshold before shrinking the count, so the threshold input's
own bound did the work and the assertion passed with the count's clamp deleted.
Raising the count, raising the threshold into the new room, then shrinking the
count is the only sequence that constructs an impossible pair — third time this
session that a control which failed to bite found a real gap in a test rather
than a defect in the feature.

---

## Phase 5 — UAT remediation — **26 of 28 closed**

Source: [reports/UAT-2026-08-14.md](reports/UAT-2026-08-14.md) — five agents
driving the production build in headless Chromium, ~150 automated checks plus
manual inspection, 28 findings.

**Two remain, both by decision rather than backlog.** U14 is refused — v2 has no
filename field and should not grow one. U27 is parked until the non-ASCII
download filename is confirmed in a real browser; the unpark condition is in
§5.4 and has not been met.

**A counting correction, recorded because the process failed, not just the
count.** This was reported as 26 of 28 twice while it was actually 24. U2b and
U24 were both enumerated correctly in the triage and then not carried into
either PR — worse than overlooking them, because the list was right and stopped
being consulted. An external review caught U2b by name; re-counting against the
report found U24.

The lesson is mechanical: **a triage list is worth only what the final count is
checked against.** Stating a total from memory instead of recomputing it from
the source document is how two open findings became closed ones on paper.

**The headline is the part worth keeping.** With every network request aborted
at the browser level, a full Argon2id text round-trip completed with **zero
requests attempted**. The service worker controls the page on first load,
offline reload works, the served CSP has hashed scripts and `connect-src
'none'`, a DOM-injected inline script was blocked, and the heap stayed flat
across ten encrypt/decrypt cycles. The central claim of the product was tested
adversarially and held.

### Corrections to the report

Verified against the working tree, not assumed — the same rule as the
corrections at the top of this document. **Ten of the 28 findings, including
five of the ten Priority 1 items, are already fixed.** The report was run
against a build predating Phases 1 and 2.

| Finding | Reality |
|---|---|
| U1 — UI freezes during KDF, "found independently by 3 agents" | **Shipped** as 2.1. Crypto runs in a Worker, with a cancel that actually stops the derivation. |
| U3 / B1 — stale-op toast and silent data loss | **Shipped** in Phase 1. Op-sequence guard; the `finally` that wiped the password now sits behind `isStale()`. |
| U11 / B2 — dead IttyBitz toast | **Shipped** in Phase 1. |
| U12 / B4 — arbitrary error whitelist | **Shipped** in Phase 1 as typed error codes. |
| U19 — derivation estimate 4–7× off ("≈3s" measured 0.43s) | **Shipped** as 2.5, and the fix is exactly what the report proposed: calibrate from a one-time Argon2 benchmark. Every slider position is now priced against the measured device. |
| U6, U10 — icon-only buttons with no name, tooltip focus ring removed | **Shipped** as 2.7, as one `InfoTip` component with a name and a 2px accent ring. |
| U7 — colour-only BIP-39 signalling | **Shipped** as 2.7. This is the finding 2.7 records as the one **axe could not see**: a red border produces zero violations. |
| U2, first half — tab round-trip wipes in-progress work | **Already fixed.** `handleModeChange` skips `resetState()` for the Tools tab, with a comment saying why. |
| B7 — dice invalid-sides entropy | **Shipped.** |
| U9 — 320px header overflow, "Tools" clipped off-screen | **Shipped**, and now measured rather than assumed: `platform.spec.ts` asserts no horizontal overflow at 320, 360, 375, 393 and 430px, and all five pass. |
| "Add axe-core to the Playwright suite" | **Shipped** as 2.7, across six scans in CI. |

One is still open but is not the finding it is filed under:

- **U2, second half** — the dice roll log dying on a tab switch. Confirmed
  still true (`TabsContent` carries no `forceMount`, so Radix unmounts it), but
  a different defect from the one U2 leads with. Queued as U2b in 5.2.

### 5.1 The crash, first — **shipped**

**What it actually was.** The report filed this as a renderer OOM at ~140 MB.
Measuring it found something smaller, more ordinary, and reachable on the
*normal* path. Worst main-thread block, production build, headless Chromium:

| pasted | as one line | wrapped at 76 cols |
|---|---|---|
| 64 KiB | 833 ms | — |
| 256 KiB | 3 245 ms | — |
| 1 MiB | **12 434 ms** | 407 ms |

Three findings, each of which changed the fix:

1. **The cost is not in the handler.** `onChange` returns in 3–7 ms at every
   size; the block is afterwards, in the browser laying out the field. A check
   inside `processData` could never have helped.
2. **It is not the BIP-39 check** — encrypt and decrypt block identically, and
   that check only runs on encrypt.
3. **It is line length, not total size.** 30× between the same megabyte as one
   line and as wrapped lines.

(3) is the part worth keeping: **Keymaker's own armored output is a single
unbroken line**, so a user copying a backup out and pasting it back into Decrypt
walks into this on the ordinary recovery path. 100 MB was never a real limit for
this field — it was a number nobody had tested.

Fixed by gating the input layer, refusing rather than truncating (silently
keeping a prefix of someone's secret and encrypting *that* is the worse
outcome), with asymmetric caps — 32 KiB of plaintext, 64 KiB of armored text —
because armor expands by 4/3 and a symmetric pair would let the app produce text
it then refuses to take back. `tests/browser/paste-size.spec.ts`; the negative
control reproduces 12 569 ms.

**Still open, and a decision rather than a bug:** the app emits armor as one
line. Wrapping it would remove the self-inflicted case entirely, and both the
parser and `RECOVERY.md` already accept wrapped text — but it changes what the
app writes, so it is not folded into a crash fix.

### The original triage entry

**U4 — a large paste hard-crashes the renderer (OOM) before any validation
runs.** The size check fires only on submit; the textarea's `onChange` has no
gate at all.

This does not queue behind Phase 4. It is a Phase-1-class defect that arrived
late, and this document's own selection rule puts a defect in the shipped
product above any feature. A tab that dies taking the user's typed secret with
it is worse than anything Phase 4 adds.

Gate the input layer independently of the submit path, and put the size message
in the error whitelist so it is reported as a size limit rather than as a
possible wrong password.

### 5.2 Correctness and honesty

| # | Issue | Note |
|---|---|---|
| U13 | The password is cleared after **every** attempt, failures included — a typo means retyping all of it | The clear lives in `finally`. Moving it to the success path is small, but read why it is there first: it was part of the B1 fix. |
| U2b | Dice roll log destroyed on tab switch | `forceMount`, or lift the state out. |
| U15 | The password policy silently disables Encrypt with no explanation at the button — **and the code comment calls the policy "advisory and UI-only" while the code hard-blocks** | The comment that lies is the worse half. |
| U16 | Footer "GitHub" points at `seQRets/ittybitz`, in three places | Someone looking for the source of *this* product lands on a different one. |
| U14 | Obscured-filename decrypt loses the extension, silently | The report suggests storing the name in the v2 header. **v2 has no field for it and should not grow one** — §8 deferred metadata deliberately, and container length already leaks plaintext size. If it happens at all it belongs inside the plaintext. A design note, not a bug fix. |
| U20 | `'wasm-unsafe-eval'` also permits `eval()` in Chromium | Not exploitable — no inline injection is possible — but it belongs in SECURITY.md rather than being rediscovered. |

### 5.3 Accessibility, second pass

2.7 was a real pass and it closed what axe can see. These are what it cannot,
which is the lesson 2.7 already recorded about itself.

| # | Issue |
|---|---|
| U5 | **The collapsed Advanced panel keeps 12 controls in the tab order.** Confirmed: it collapses via `grid-template-rows: 0fr` with `overflow-hidden`, so the content is clipped but still focusable. A keyboard user tabs through twelve controls they cannot see. Needs `inert`, or unmounting. |
| U8 | Touch targets under the minimum at every viewport — sliders 16px tall, info buttons 14×14, footer links 16–17px |
| U18 | Dropzone `role="button"` handles Enter but not Space; a dead tab stop on the Radix tab panel; heading hierarchy skips h1→h3 |
| U17 | `prefers-reduced-motion` ignored entirely — 25 animated elements, no media query anywhere in the stylesheet |

### 5.4 Polish

U21–U28: dice pluralisation ("1 more rolls"), non-file drops ignored without
feedback, Enter doing nothing in the password field, the undisclosed
1024-character password limit, Show/Hide reading "Hide" on an emptied field and
exposing no `aria-pressed`, the 11px typography floor, and the SeedQR modal
offering no "copy digits" path.

**U27 is deliberately not actionable yet.** Non-ASCII download filenames
collapsing to "download" is suspected to be a harness artifact, and the report
says to confirm it in a real browser first. Worth honouring — a fix aimed at a
test-harness bug is worse than no fix.

**Gate:** every item in 5.1 and 5.2 ships with a Playwright regression test that
has been *seen to fail* without the fix. The UAT produced reproducible scripts
per finding; ask for those rather than reconstructing the repro from prose.

---

## Phase 6 — Make the trust claims checkable by a stranger

Source: an external review of the public repo, 2026-08-15. Its central point is
correct and uncomfortable: **the engineering is ahead of the packaging.** Every
expensive trust property this project has already built — reproducible builds,
Sigstore signatures, an independent reference implementation — is currently
invisible to someone who arrives at the repo and has to decide whether to trust
it in the next ninety seconds.

This phase adds no cryptography. It is the phase that makes the existing
cryptography *legible*, and by the selection rule at the top of this document it
survives under criterion 2: it strengthens the trust moat, because a
verifiability property nobody can find is not a verifiability property.

**Sequenced first among what remains**, ahead of Phase 4's features, and that is
a deliberate reversal of the usual order. Phase 4 makes the tool do more for
people already using it; Phase 6 is what lets anyone establish that it is worth
using at all. With zero stars, zero forks and no release, the second is the
binding constraint.

### 6.1 Version coherence — do this before anything with a version number in it

`package.json` says `1.0.0`, the footer says `Keymaker v1`, the container format
is KEYM v2, and there are **zero git tags**. Three different numbers and no
release to pin any of them to.

The fix is a decision, not a rename: **the application version and the container
format version are separate things and must stay separate.** Conflating them is
its own confusion — a user reading "v2" needs to know whether that describes the
app they are running or the file they are holding, and those diverge the moment
the app gains a feature that does not change the format.

- Application version in `package.json` and the footer, moving on app releases.
- Format version stated as "KEYM v2" wherever a container is described, moving
  only on a format change — which §9 of `FORMAT-V2-DESIGN.md` says is now frozen.
- The footer says both, because the footer is where someone looks when a file
  will not open.

**Gate:** a test asserting the footer's app version matches `package.json`. A
version string maintained in two places drifts, and the one place it must not
drift is the line a user quotes in a bug report.

**Shipped.** `next.config.js` injects `KEYMAKER_APP_VERSION` from `package.json`;
the footer reads `Keymaker v2.0.0 · writes KEYM v2`. The fallback is the literal
`unknown` rather than a plausible number, so a broken injection looks broken.
Version went to 2.0.0 — the app no longer *writes* KEYM v1, which is breaking
for anything consuming its output; existing v1 containers still decrypt.
`tests/browser/version.spec.ts` is the gate, and restoring a hardcoded
`Keymaker v1.0.0` fails it.

One thing the item did not anticipate, found while merging: the decrypt info
line labelled containers `Keymaker v1` / `Keymaker v2`, which collided with the
application version the moment it reached 2.0.0. Those are now `KEYM v1` /
`KEYM v2` per the rule above, gated in `crypto.spec.ts` — which asserts both the
new label and that no container is named after the application. That line is
where someone looks when a file will not open, so it is the worst place for the
ambiguity this item exists to remove.

### 6.2 A tagged release, with the verification path attached

No release exists, which makes `SHA256SUMS` and the Sigstore signature
unreachable in practice: there is nothing to download and verify *against*.

Release notes should say what the container format is, what changed, and how to
check the artefact — in that order, because the third is the differentiator and
it currently reads as an implementation detail buried in `docs/VERIFYING.md`.

**Gate:** the release workflow attaches `SHA256SUMS` and its signature, and the
`cosign verify-blob` line in the notes is copied from `docs/VERIFYING.md` rather
than retyped. A verification command that does not work is worse than none.

**Shipped, except the tag itself.** `.github/workflows/release.yml` fires on a
`v*` tag with `deploy.yml`'s three-way token split: `build` runs `npm ci` holding
only `contents: read`, `sign` holds `id-token: write` and installs with
`--ignore-scripts`, `publish` holds `contents: write` and installs nothing.
Before publishing it verifies the signature against *this* workflow's identity on
the tag — not `deploy.yml@refs/heads/main`, which would pass in CI and fail for
every reader — then unpacks the tarball and runs `sha256sum -c` inside it.

`scripts/release-notes.mjs` extracts the command from `docs/VERIFYING.md` and
substitutes only `--certificate-identity`, the one value that genuinely differs.
`scripts/release-notes-test.mjs` masks that value and demands the two commands
match byte for byte, so editing either side alone fails; it runs on every PR
rather than at release time, because a PR is when the document gets edited.

Two things the item did not anticipate, both found by testing rather than
reading: release bodies do not resolve repo-relative links, so the notes carry
absolute URLs pinned at the tag; and a *lightweight* tag's `%(contents:subject)`
falls through to the commit, which would have made a release announce "Merge
pull request #29" as its changelog.

**No tag is pushed.** A public release cannot be withdrawn, so cutting one is an
owner action: `git tag -a v2.0.0` — annotated, because the message becomes the
"What changed" section — and push it. That remains open in the register below.

### 6.3 "Verify this build" — in the app, not only in a doc

The review's strongest suggestion. The infrastructure is complete and nothing
walks a user through using it.

An in-app page that states the running build's commit and manifest hash, and
gives the exact `cosign verify-blob` and `sha256sum` invocations for it. Not a
button that claims "verified" — the page cannot verify itself, and one that
pretended to would be the precise class of overstatement KM-02 was about. It
hands the user the commands and gets out of the way.

**Gate:** a browser test that reads the hash off the page and checks it against
the built `SHA256SUMS`. Otherwise the page becomes wrong on the first build that
changes it, silently, and a stale hash is worse than no hash.

**Shipped, with one deliberate change to the spec above.** `/verify.html` states
the commit, the app version and the format version, prints the two commands, and
spends its last section on what none of it proves. Reachable from the footer.

**The manifest hash is not on the page, and could not honestly be.** Three
independent reasons, found while building it:

1. *Baking it is circular.* `SHA256SUMS` covers the page, so writing the digest
   into the page changes the page, which changes the manifest, which changes the
   digest. There is no fixed point.
2. *Fetching it needs `connect-src 'self'`.* The policy is `connect-src 'none'`,
   which KM-07 was raised to obtain. This is not merely a test: `apply-csp-hashes.mjs`
   **fails the build** if the directive is anything else, and says to update the
   claim in README.md at the same time. Confirmed by trying it.
3. *It would prove nothing.* A digest served by the same host as the bundle it
   describes is a number that host chose.

So the gate checks the value the page does carry — the commit — against the build
id Next embedded in the landing page's router payload. Two independent paths out
of one `resolveBuildId()`, which is the staleness the gate was written for. Three
further checks came with it: the commands must match `docs/VERIFYING.md`
byte-for-byte, the page must not claim to have verified anything, and the CSP on
that route must still be `connect-src 'none'`.

Controls all confirmed: a hardcoded commit, a retyped cosign command, a "this
build is verified" banner, and a removed footer link each fail exactly one test;
relaxing the CSP fails the build outright.

The commands come from `docs/VERIFYING.md` via `scripts/verifying-doc.cjs`, now
shared with the release-notes generator — one extractor, three consumers, one
hand-written copy of each command.

### 6.4 README top matter

Live-demo link, CI / licence / reproducible-build badges, and a short **"Why
Keymaker?"** against `age`, GPG, Cryptomator and the browser-only tools. Nine
screenshot references already exist; badges and the comparison are the gap.

The comparison must be honest about where the alternatives win — `age` and GPG
are not browser tools and do not carry this project's threat model, and saying
so is what makes the rest of the table credible.

**Shipped.** Five badges (CI, browser tests across three engines, format
conformance, reproducible build, GPL-3.0), the demo link already present, and a
link to the verify page beside it. The comparison runs Keymaker against `age`,
GPG, Cryptomator and typical browser tools over eleven rows, then spends three
paragraphs on where each of the others is the better answer, on the honest
weakness — *a web app has the weakest trust anchor of the four* — and on the
narrow case Keymaker is actually built for.

Two rows were deliberately weakened while writing it. Claims about whether other
projects ship reproducible builds, and how many independent implementations read
their formats, are not this repository's to make; a dash now means "not claimed
here" and the table says so. A table that overstates a competitor's weakness is
worth less than no table, which is the same reasoning as the item above it.

### 6.5 Mobile and PWA polish

Install prompt, offline behaviour after install, and touch targets on a real
handset. U8 fixed the measurable part at 390px in a headless browser; **nothing
in this project has ever been opened on a phone.** That is an owner-only task
and it is in the register below.

---

## Phase 7 — Documentation that survives the author

The recovery-first philosophy is already the best thing in the docs. These
extend it in the two directions it does not currently reach.

### 7.1 An illustrated end-to-end walkthrough

First encryption through to recovery with `keym.py` and no website. Written and
illustrated, in the repo, tested by `recovery_test.py` the way `RECOVERY.md`
already is.

**A video is cut.** It cannot be version-controlled, cannot be tested against
the code, and goes stale silently the first time the UI moves — which, on this
project's recent rate of change, is days. The written walkthrough is executable
by a test; a video is a screenshot with a play button.

**Shipped.** `docs/WALKTHROUGH.md` — scenario, four illustrated steps, verify
before you rely on it, what to keep and where, then recovery with `keym2.py` and
no website. Linked from the README and from `RECOVERY.md`, which it defers to as
the printable emergency card rather than duplicating.

Both halves are executed, which is the part that matters:

- **The commands.** `recovery_test.py` reads the page, extracts every `bash`
  block and runs it against a container the *shipping* encryptor produced, then
  checks the recovered bytes are byte-identical. Extracted rather than re-typed,
  for the reason 6.2 gave: a second copy of a command drifts, and the copy that
  drifts is the one nobody runs. `pip install` is skipped and *reported as
  skipped*, because a suite that quietly stops covering a step reads exactly
  like one that covers it.
- **The UI.** `tests/browser/walkthrough.spec.ts` walks the documented path and
  asserts the claims the prose makes by name — that the secret field blurs, that
  Argon2id is still the recommended default, that the policy line still refuses
  to score a password it did not generate, that verify-only reports a size and
  withholds the plaintext.
- **The pictures.** Generated by `scripts/capture-screenshots.mjs` from the
  production build, and every embedded image is checked to exist.

Controls: a renamed flag in the doc, a missing illustration, and removing the
commands each fail their own check; un-blurring the secret field, regressing the
policy line to a strength score, and breaking the links each fail exactly one
browser test.

**Found by writing it.** The capture script had been broken since U25 gave the
reveal toggle an `aria-label` — it was still matching `/^Show$/`, and nothing
ran it, so nothing said so. Two of the nine existing screenshots were the only
ones it still produced.

### 7.2 The hosted instance is a different trust model, and should say so

Using `404secnotfound.github.io` means trusting whoever serves the bundle, on
every visit. Downloading a signed release and opening it locally does not. The
README concedes the first point in passing; it deserves its own section with
the three postures spelled out — hosted, downloaded-and-verified, and
built-from-source — and what each one actually costs.

**Shipped** as "Three ways to run this, and what each one costs" — a table of
what you trust and what it costs, then a paragraph each. Hosted is named as the
weakest *and* the default, because a tool nobody can open protects nothing, with
the consequence spelled out: the bundle is fetched fresh every visit, so
verifying today says nothing about tomorrow. A fourth posture fell out of
writing it — build from source, compare your manifest to the deployment's, and
keep using the hosted copy having **checked** it rather than adopted it.

### 7.3 Expand "what this does not protect against"

Currently honest but thin. Should name, plainly: a compromised device or
browser, a malicious extension, the clipboard, shoulder-surfing, and the fact
that **container length reveals plaintext length to within a chunk** (§8 of the
format design). The last one is documented in the spec and nowhere a user will
look.

**Shipped**, in both places a reader might look: the README's security model
gained a named list — device compromise, extensions (which run inside the
origin, where the CSP does not reach), the clipboard, shoulder-surfing, the
length leak, weak passwords, and *forgetting the password*, which is the failure
that actually happens. `SECURITY.md` gained the same three additions in its
scope notes.

**Three pieces of drift fell out of this pass** and are fixed here. The README
told a v2 user to run `keym.py`, the v1 script, on a backup the app had just
written — the one that refuses is how you tell them apart, so the snippet would
have failed for everybody. The documentation table still described
`FORMAT-V2-DESIGN.md` as "design only, nothing implemented". And `SECURITY.md`'s
scope listed formats only up to KEYM v1.

---

## Phase 8 — Outreach, and only after 6

Gated deliberately. The first thing a security-minded visitor does is look for a
release to check against `SHA256SUMS` — so posting to r/privacy, r/crypto or
Show HN before Phase 6 spends the one arrival that matters on a repo that cannot
yet substantiate its own claims.

Order: Phase 6 lands → tagged release → then posts, leading with the offline
guarantee and the recovery path rather than the cipher list. The demonstration
that lands is "every network request blocked, full round trip still works",
which the UAT already measured.

**One recommendation is reframed rather than adopted.** The review suggests
seeking independent audits *for publicity*. Commission an audit for findings;
publicity is the wrong reason and selects for the wrong auditor — one who
produces quotable conclusions rather than uncomfortable ones. The publicity
asset this project should lead with already exists and is stronger: reproducible
builds, signed manifests, and a Python reference that lets a stranger verify the
format without trusting the app or its author.

---

## Ongoing — not a phase, a standing obligation

- **Dependency surface.** `@noble/ciphers` and `hash-wasm` are good choices and
  the risk is Next.js and React, which move fastest and are the largest surface.
- **The Python reference stays first-class.** Bit-for-bit conformance on every
  format change, no exceptions. It is the moat.
- **`wasm-unsafe-eval` is answered, not open.** The review asks whether it can be
  hardened further; that evaluation is done and written up in `SECURITY.md` as
  U20. Removing the token means either a JavaScript Argon2id or PBKDF2-only, and
  both trade real key-derivation strength for a hypothetical injection gain. It
  is revisited only if the CSP spec or Chromium's behaviour changes.

---

## Owner-only register

Not blocked on work, blocked on access. Listed because they have been
outstanding across every session and each one costs minutes.

| # | What | Why it matters |
|---|---|---|
| O1 | **About panel and topics are empty** on a public repo | The one-line description is the entire first impression, and topics are how anyone finds this at all |
| O2 | **Two stale `claude/*` branches** on the old repo | Force-push was permission-denied |
| O3 | **The live site has never been opened on a phone** | Several rounds of UI change have shipped; this container is egress-blocked from the deployed site, so it cannot be checked here. It is also 6.5's gate |
| O4 | **U27 unpark** — confirm the non-ASCII download filename in a real browser | Suspected harness artifact; a fix aimed at one would be worse than none |
| O5 | **Cut the `v2.0.0` tag** — `git tag -a v2.0.0 && git push origin v2.0.0` | 6.2 built and tested the whole release path but deliberately stops here: a public release cannot be withdrawn, so pushing the tag is a decision rather than a step. Annotated, because the message becomes the "What changed" section |

---

## Cut

Not "later". Cut, with reasons.

| Feature | Why |
|---|---|
| **Plausible-deniability container** and **duress/decoy password** | The blueprint concedes it: "deniability fails if the UI announces it." This is open-source software with a public spec — an adversary who knows Keymaker exists knows the decoy mode exists, and the presence of the feature is itself evidence. Shipping it invites users to bet their physical safety on a property the design cannot deliver. Worse than absent. |
| **PAKE / croc-style transfer** | Needs a rendezvous server. The zero-server property is the product. |
| **Steganography (KEYM-in-PNG)** | The blueprint frames it honestly as "obscurity, not security" — which is the argument for not shipping it. |
| **TOTP vault** | Scope creep into password-manager territory, against incumbents with sync. Dilutes focus for no differentiation. |
| **OPFS vault / File System Access workspace** | Chromium-only, large surface, and it puts plaintext-adjacent state into durable storage — directly against "nothing is stored", which is the claim people choose this tool for. |
| **Importers (Hat.sh, age, OpenPGP)** | Low value, ongoing maintenance, and OpenPGP is a key-model mismatch with a huge dependency tree. |
| **Reed-Solomon error correction** | Genuinely interesting, but AEAD already rejects any corrupted container, so parity has to wrap the whole thing as an outer layer with its own spec and reference parity. Real cost is well above the blueprint's "M". Revisit only if bit-rot is an observed complaint. |
| **Video walkthrough** (Phase 7 alternative) | Cannot be version-controlled, cannot be tested against the code, and goes stale silently the first time the UI moves. The written walkthrough in 7.1 is executed by `recovery_test.py`; a video is a screenshot with a play button. |
| **Auto-copying a generated password to the clipboard** (UAT U24) | The clipboard is readable by other applications and syncs across devices on some platforms. Putting a secret there without being asked is the wrong default for a tool whose thesis is minimising exposure. Generate already fills the field; Copy sits beside it and carries 2.6's countdown and unconditional clear. |
| **Auditing for publicity** (external review, 2026-08-15) | Commission an audit for findings. Publicity is the wrong reason and selects for the wrong auditor. The asset to lead with already exists: reproducible builds, signed manifests, and a reference implementation that removes the need to trust the author. |
| **Post-quantum hybrid / encrypt-to-recipient** | Changes the model from password-based to keypair-based — effectively a different product. Revisit when WebCrypto ships ML-KEM natively and `SubtleCrypto.supports()` can gate it. |
| **Wipe-on-N-attempts, self-destruct, time-lock, breach checks** | Impossible without a server. The blueprint already lists these as impossibilities; keeping them documented as impossible **is** the feature. |

---

## Honest framing to preserve

Two places where the blueprint's pitch outruns what the crypto delivers. Both
must be stated plainly in the UI, not just here.

**Passkey PRF is convenience, not strength.** With a mandatory passphrase
fallback — and there must be one, or a lost key is lost data — the container's
security is still bounded by the passphrase. The passkey removes phishing and
typing, not brute-force exposure. Advertising it as "hardware-grade security"
while a 12-character password unlocks the same file would be exactly the class
of overstatement KM-02 was about.

**Shamir shares are password-equivalent.** Any *k* shares decrypt without the
password. That makes each share as sensitive as the password itself, and it
changes the threat model from "one secret I know" to "k secrets other people
hold". The print kit must say so on the paper.

---

## Sequencing at a glance

```
Phase 1  Fix what is broken            ─ done ─  blocked everything
Phase 2  Unfreeze and prove            ─ done ─  format-independent
         └ Worker · provenance · verify-only · recovery kit · calibration · auto-lock · a11y
Phase 3  KEYM v2                       ─ done ─  Python reference first, then TS
         └ chunked STREAM + envelope slots · the app writes v2
Phase 5.1 The OOM crash (U4)           ─ done ─  jumped the queue, see below
Phase 5  UAT remediation               ─ done ─  26 of 28; U14 refused, U27 parked
         └ correctness · a11y second pass · polish
Phase 4.1 Shamir k-of-n                ─ done ─  format · reference · parity · UI
Phase 6  Make the claims checkable     ─ done ─  version · release · verify page · README · (6.5 owner)
Phase 7  Documentation                 ─ done ─  walkthrough · trust postures · limitations
Phase 4.2 Paper vault print kit        ─ done ─  §7.1 parts · the sheet · the debt paid
Phase 4.3 Self-extracting page         ─ done ─  §7.2 subset · the page · three readers, one file
Phase 4.5 Inheritance wizard           ─ done ─  composition of 4.1–4.3 · three ways in · the letter
Phase 4.4 Passkey / WebAuthn PRF       ──────    the only feature item left; see below
Phase 8  Outreach                      ──────    gated on 6, and on a tag existing
```

**4.4 is deliberately last, and 4.5 did not wait for it.** The wizard composes
4.1–4.3 and a passkey slot would add a fourth unlock path to a package that
already has two; nothing in 4.5 assumes 4.4 exists. Keeping the order as written
would have meant blocking a finished composition on the one item the roadmap
itself reframes as convenience rather than strength.

**Phase 6 goes before the rest of Phase 4, and that reverses the usual order.**
Phase 4 makes the tool do more for people already using it. Phase 6 is what lets
anyone decide it is worth using. At zero stars, zero forks and no tagged
release, the second is the binding constraint — and every trust property that
would answer a sceptical visitor is already built and simply cannot be found.

The one exception inside Phase 4 is the **paper vault print kit**, which is the
natural next feature regardless: it composes directly with the share sets that
just shipped, and the share modal's Print button is currently `window.print()`
against a screen layout, which is the weakest thing in that feature.

The order is not negotiable in two respects now.

**Phase 1 came before anything**, because a tool that tells you your password is
wrong when the file is actually truncated has no business gaining features.

**5.1 comes before Phase 4** for the same reason, arriving late. It is numbered
5.1 because that is where the report put it, not because it waits for Phase 4 —
a paste that kills the tab and takes the user's typed secret with it is the same
class of defect Phase 1 existed to clear, and it outranks every feature below
it. The rest of Phase 5 does sit after Phase 4.
