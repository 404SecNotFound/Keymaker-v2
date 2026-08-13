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
