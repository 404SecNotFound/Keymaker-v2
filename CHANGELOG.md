# Changelog

## Unreleased

### Added
- **Diceware passphrase generator.** Seven words drawn uniformly from the EFF
  Long Wordlist with rejection sampling — 90 bits, stated exactly. The wordlist
  is fetched from three independent redistributions that must agree on the full
  ordered sequence, and `npm run test:wordlist` re-derives EFF's own file
  checksum from the shipped array, offline, in CI. Closes the enhancement left
  open under KM-02.
- **`docs/FORMAT-V2-DESIGN.md`** — the proposed KEYM v2 container. Design only:
  no code reads or writes it, and KEYM v1 is unchanged and stays readable.

### Changed
- **Service-worker updates now wait for the user.** A new version installs and
  stops; the page offers a reload and only the user's click promotes it.
  Previously `skipWaiting()` plus `clients.claim()` replaced the running
  version underneath an open tab and evicted its cache, which could break a
  lazily imported crypto chunk part-way through an encryption (KM-25).
- The password policy gate now accepts a secret on provenance when Keymaker
  generated it, instead of re-judging it on morphology. Without this, a uniform
  seven-word draw that happened to repeat a word — about one in 370 — would
  have been certified at 90 bits in the UI and then refused by the Encrypt
  button.
- The update banner is a `<button>` rather than a `<div>` with a click handler,
  so the update path is reachable from the keyboard.

### Fixed
- `resetState()` did not clear the "this password came from the CSPRNG" flag.

## Keymaker v1.0.0

First Keymaker release, forked from IttyBitz v2.8.0 (the previous
RELEASE-NOTES-*.md history is consolidated into this file).

### Rebrand
- Renamed to **Keymaker** (app title, PWA manifest, package name, docs).
- New visual identity: deep amber/bronze key motif; `.keym` file extension;
  `KEYM1:` prefix for encrypted text blobs.

### New crypto core (KEYM v1)
- Self-describing, AAD-authenticated container header (KDF id, cipher id,
  KDF params, key-file flag) — decryption needs no options.
- Argon2id KDF (via hash-wasm) alongside PBKDF2-HMAC-SHA-256 (1M iters).
- ChaCha20-Poly1305 (via @noble/ciphers) alongside AES-256-GCM, plus chained
  AES-256-GCM → ChaCha20-Poly1305 with HKDF-derived independent subkeys.
- Transparent legacy support: IttyBitz IBTZ v1 and headerless v0 payloads
  (files and bare base64 blobs) decrypt as before, with an import notice.

### UI/UX
- Collapsible **Advanced** section on the Encrypt tab: KDF choice with
  Argon2id parameter sliders, cipher choice with explanations, key-file
  toggle, filename obscuring, and an effective-configuration summary.
- New **Tools** tab with a dice entropy calculator (ported from Morpheus):
  bits per roll, rolls needed for the 128-bit floor / 256-bit target,
  progress bar, verdict, and educational context.
- Encrypt-side secret field now defaults to blurred (matching decrypt side).
- Entropy-aware password strength: 4+ word passphrases count as strong even
  without symbol/uppercase classes.
- Post-decryption info line shows the detected container format and
  parameters.
