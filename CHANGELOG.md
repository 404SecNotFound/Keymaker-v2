# Changelog

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
