# Security Policy

## Reporting a Vulnerability

**Please do not open public issues for security vulnerabilities.**

Report vulnerabilities privately via **GitHub private security advisories**:
go to the repository's *Security* tab → *Advisories* → *Report a
vulnerability*.

Please include:

- A description of the vulnerability and its impact.
- Steps to reproduce or a proof of concept.
- Affected versions, if known.
- Any suggested mitigation (optional).

We aim to acknowledge reports within 72 hours and to provide an initial
assessment within 7 days. We will coordinate disclosure with the reporter;
credit will be given in the release notes unless you prefer to remain
anonymous.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes — security fixes |
| Older releases | No — please upgrade |

Security fixes are shipped in new releases; only the latest release line
receives patches.

## Scope Notes

Keymaker is a **client-side** browser encryption PWA. In scope:

- The cryptographic core (`src/lib/crypto.ts` — frozen legacy format;
  `src/lib/keymaker-crypto.ts` — KEYM v1) and its wire formats (IBTZ v0/v1,
  KEYM v1). See `docs/FORMAT.md`.
- Key derivation, nonce/salt generation, memory handling (`secureErase`),
  and authentication of ciphertext and header metadata (AAD).
- The static export's content security policy and supply-chain (dependency)
  integrity.

Out of scope / known limitations:

- **Endpoint compromise.** All cryptography runs in the user's browser. If
  the device is compromised (malware, malicious extensions, keyloggers), no
  web app can protect the plaintext or password.
- **JavaScript memory hygiene is best-effort.** `secureErase` zero-fills
  buffers, but the JS engine/GC may retain copies of secrets. WebCrypto keys
  are non-extractable where the API allows.
- **Deniability / traffic analysis.** File sizes are not padded; ciphertext
  length leaks plaintext length (plus a small constant).
- **Password strength.** Weak passwords undermine any KDF. Argon2id
  (memory-hard) is the default recommendation, but cannot fix a weak
  password.
- Vulnerabilities in third-party dependencies should be reported upstream
  as well; do report them here if they affect Keymaker's shipped bundle.

## Cryptographic Inventory

| Primitive | Implementation |
|-----------|----------------|
| AES-256-GCM | WebCrypto (`crypto.subtle`) |
| ChaCha20-Poly1305 | `@noble/ciphers` (audited, pure JS) |
| Argon2id | `hash-wasm` (WASM inlined as base64, offline-capable) |
| PBKDF2-HMAC-SHA-256 | WebCrypto |
| HKDF-SHA-256 | WebCrypto |
| CSPRNG | `crypto.getRandomValues` |

Format details and AAD rules: see `docs/FORMAT.md`.
Historical audit notes: see `SECURITY-AUDIT.md`.

## Known CSP trade-off: `wasm-unsafe-eval`

The Content-Security-Policy `script-src` includes `'wasm-unsafe-eval'`. It is
there because Argon2id is WebAssembly and the browser will not instantiate a
module without it.

**In Chromium, `'wasm-unsafe-eval'` also permits `eval()`.** That is a quirk of
the implementation rather than of the specification, which scopes the token to
WebAssembly compilation. So on Chromium the policy is broader than it reads.

Documented rather than fixed, because there is nothing worth fixing on either
side of the trade:

- It is **not currently exploitable.** Reaching `eval()` needs script injection,
  and the rest of the policy is what prevents that: `default-src 'none'`, no
  `unsafe-inline` (every inline script carries a build-time sha256 hash and the
  build fails closed if one is missing), and `connect-src 'none'`. A
  dynamically injected inline script is blocked, and the browser suite asserts
  that rather than assuming it.
- It **weakens defence in depth**, which is the honest cost. If an injection
  ever did become possible, this token means the attacker also gets `eval()`
  rather than being confined to what the hashed scripts already do.

The alternative is worse. Removing the token means either a JavaScript Argon2id
— orders of magnitude slower, so in practice users would choose weaker
parameters — or PBKDF2 as the only KDF. Both trade a real reduction in
key-derivation strength for a hypothetical one in injection resistance.

Recorded here so it is not rediscovered as a finding by every subsequent audit.
It has been found once already, as U20 in `docs/reports/UAT-2026-08-14.md`.
