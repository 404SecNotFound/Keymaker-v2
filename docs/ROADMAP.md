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
| 2 | **Paper vault print kit** | Ciphertext as QR grid, condensed recovery procedure, Shamir share slots, password *hint* field. Safe-deposit-box ready. Small, and it composes with everything else. |
| 3 | **Self-extracting HTML decryptor** | One `.html` = ciphertext + a minimal WebCrypto-only decryptor. The "openable by a non-technical heir in 2040" story, with `keym.py` as the second line. Must be PBKDF2/AES-GCM only — no WASM — or it does not survive the decade. |
| 4 | **Passkey / WebAuthn PRF slot** | Phishing-proof daily unlock. Read the honest framing below before selling it as strength. |
| 5 | **Inheritance wizard** | Pure composition of 1–3 plus the existing recovery doc. Cheap once they exist; incoherent before. |

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

---

## Phase 5 — UAT remediation

Source: [reports/UAT-2026-08-14.md](reports/UAT-2026-08-14.md) — five agents
driving the production build in headless Chromium, ~150 automated checks plus
manual inspection, 28 findings.

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
Phase 5.1 The OOM crash (U4)           ──────    jumps the queue, see below
Phase 4  What v2 unlocks               ──────    Shamir · print kit · self-extracting HTML · passkey · inheritance
Phase 5  UAT remediation (rest)        ──────    correctness · a11y second pass · polish
```

The order is not negotiable in two respects now.

**Phase 1 came before anything**, because a tool that tells you your password is
wrong when the file is actually truncated has no business gaining features.

**5.1 comes before Phase 4** for the same reason, arriving late. It is numbered
5.1 because that is where the report put it, not because it waits for Phase 4 —
a paste that kills the tab and takes the user's typed secret with it is the same
class of defect Phase 1 existed to clear, and it outranks every feature below
it. The rest of Phase 5 does sit after Phase 4.
