# Keymaker Security Audit

**Scope:** Keymaker v2 — the KEYM v1 container, `src/lib/keymaker-crypto.ts`,
the encryptor UI, the dice entropy tool, the CSP build pipeline, and CI.
**Baseline reviewed:** `ddedfaf`
**Predecessor:** [SECURITY-AUDIT-ITTYBITZ-2026-04.md](SECURITY-AUDIT-ITTYBITZ-2026-04.md),
which covers only the frozen legacy core and does **not** cover anything below.

External review found no Critical or High severity vulnerabilities. It found
three Medium issues, several Low, and a set of informational items. Each is
listed below with its disposition and, where fixed, the test that holds it
fixed.

---

## Findings and disposition

| ID | Severity | Finding | Status |
|---|---|---|---|
| KM-01 | Medium | Unbounded KDF parameters executed before authentication | **Fixed** |
| KM-02 | Medium | Password gate accepted trivially guessable phrases | **Fixed** |
| KM-03 | Medium | Dice calculator counted impossible rolls as entropy | **Fixed** |
| KM-04 | Low | No ciphertext size ceiling on the decrypt path | **Fixed** |
| KM-05 | Low | Password + key file concatenation is ambiguous | **Deferred to KEYM v2** |
| KM-06 | Low | PBKDF2 is the effective default despite Argon2id being recommended | **Open** |
| KM-07 | Low | `connect-src 'self'` did not enforce the zero-egress claim | **Fixed** |
| KM-08 | Low | Service worker caching scope broader than necessary | **Open** |
| KM-09 | Low | Prior audit was stale and could be misread as covering KEYM | **Fixed** |
| KM-10 | Info | Encryption did not validate caller-supplied KDF parameters | **Fixed** |
| KM-11 | Info | CSP postprocessor skipped HTML with no CSP meta tag | **Fixed** |
| KM-12 | Info | CI, legacy test, and deploy used three Node majors | **Fixed** |
| KM-13 | Info | Chained-cipher wording claimed more than was established | **Fixed** |

---

## KM-01 — KDF parameters executed before authentication

**The issue.** A KEYM header states how to derive the key, so it must be read
before the key exists — and the AEAD tag that authenticates it cannot be
checked until after derivation. `parseKeym()` read a `uint32` iteration count
and `uint16`/`uint32`/`uint8` Argon2id parameters and passed them straight to
the KDF with no bounds.

AAD prevents a tampered header from yielding valid plaintext. It does not
prevent attacker-chosen parameters from being *executed* on the way to
discovering the tamper. A 200-byte hostile file could request 4,294,967,295
PBKDF2 iterations or 4 TiB of Argon2id memory and hang or OOM the tab.

**Fix.** `validateKdfParams()` runs inside `parseKeym()`, before any derivation,
and again in `encryptData()` on caller-supplied options.

| Parameter | Accepted on decrypt | Accepted on encrypt |
|---|---|---|
| PBKDF2 iterations | 1 .. 10,000,000 | 600,000 .. 10,000,000 |
| Argon2id timeCost | 1 .. 10 | 1 .. 10 |
| Argon2id memoryKiB | 1 .. 262,144 | 8,192 .. 262,144 |
| Argon2id parallelism | 1 .. 8 | 1 .. 8 |

Ceilings are the security control and apply everywhere. Floors are policy for
new encryptions only — decryption stays permissive so that files created with
older or lower settings still open. The encrypt floor follows OWASP's current
PBKDF2-HMAC-SHA-256 recommendation.

**Tests.** Five hostile headers requesting maximal costs, each asserted to be
refused in under a second — a timing assertion, because an unbounded
implementation would grind rather than return. Observed: 0.0–0.2 ms. Plus two
encrypt-side rejections and one test confirming policy-floor containers still
decrypt.

**Note on how this was hiding.** The AAD sweep flips every header byte and
attempts decryption. On the Argon2id test container, byte 7 is the high byte of
`timeCost` — flipping it turned 2 passes into 16,386, and byte 10 turned memory
into roughly 4 GiB. The suite was executing hostile parameters on every run,
and took 3m33s. With bounds enforced it takes 11.8s, while running *more* tests
and a slower PBKDF2 setting. The test suite had been demonstrating the finding
for its whole existence.

## KM-02 — Password gate certified guessable phrases

**The issue.** `isPasswordStrong()` returned true for any input of six or more
whitespace-separated tokens, justified in a comment as "6 diceware words ≈ 77
bits". That inference holds only for words drawn independently and uniformly
from a list. For typed text it is false, and it accepted `a a a a a a`,
`password password password password`, and `one one one one one one`.

**Fix.** Word count is not treated as entropy. The passphrase path now counts
*distinct* words of at least three characters and applies a length floor, which
removes the degenerate repetition cases without rejecting real passphrases.
A genuine phrase containing a repeated word still passes on length.

This gate is advisory and lives only in the UI. `encryptData()` has never
consulted it, and still does not — cryptographic behaviour must not depend on
a heuristic.

**Not done:** a built-in Diceware generator. That is the only way to state a
passphrase's entropy honestly, since it requires controlling the sampling. The
existing generator produces rejection-sampled random passwords, which is a
sound alternative; a word-list generator remains a reasonable enhancement.

## KM-03 — Dice calculator counted impossible rolls

**The issue.** Any token the parser could not interpret fell through to
`rolls += 1`. A 9 on a d6, a 25 on a d20, `0`, and `hello` each contributed a
full roll of entropy. For a tool whose only output is an entropy estimate,
this inflated the number the user was relying on.

**Fix.** Every entry must be an integer in `1..sides`. Run-together digits
(`46231` on a d6) still expand to individual rolls, but only when every digit
is a valid face and the die has single-digit faces. `sides` is validated as an
integer in 2..1000 in code, not left to HTML `min`/`max`. Rejected entries are
counted and displayed rather than silently dropped — silent rejection would
trade one wrong number for another.

## KM-04 / KM-10 — Missing limits at API boundaries

The 100 MB cap applied only to encryption, so a large pasted base64 blob
reached `decryptData()` and its KDF without one; and `encryptData()` trusted
whatever options a caller supplied. Both now validate independently of the UI,
so a CLI, a test, or a future refactor cannot bypass them.

## KM-07 — Zero-egress is now structurally enforced

The policy was `connect-src 'self'`, which permits same-origin `fetch`, XHR,
and WebSocket. The zero-egress property was therefore a property of the code,
not of the policy.

Tested and tightened to `connect-src 'none'`. Verified in Chromium: PBKDF2 and
Argon2id round-trips, service-worker registration, and a reload all succeed
with no CSP violations — the page needs no connections at all. The build now
fails if `connect-src` is anything other than `'none'`.

## KM-05 — Deferred to KEYM v2

Key material is `password_bytes || keyfile_bytes` with no length prefix or
domain separation, so `("ab","c")` and `("a","bc")` produce identical KDF
input. This is not a practical key-recovery path, but it is not how a format
should combine two secrets. Fixing it changes derivation and therefore the wire
format, so it belongs in v2 alongside length-prefixed, domain-separated inputs
and pre-hashing of key files. **KEYM v1 must remain readable exactly as-is.**

## KM-06 / KM-08 — Open

**KM-06:** the UI still initialises to PBKDF2 while labelling Argon2id
recommended, so the least technical user gets the weaker KDF. Changing the
default needs a WASM capability probe and a visible fallback, given that
Argon2id is unavailable where WebAssembly is blocked. Deliberately left as a
product decision rather than changed unilaterally.

**KM-08:** the service worker caches any same-origin GET. Correct for the
current static bundle, but broad enough that future same-origin resources would
be persisted without anyone deciding they should be.

---

## Recommended next steps

Roughly in order of value:

1. **Independent reference implementation.** The KEYM fixtures were generated
   by the implementation they test, so a specification bug could be frozen into
   both. A small Rust or Python implementation written only from `FORMAT.md`,
   cross-tested in both directions across all six KDF/cipher combinations,
   would turn the fixtures into a real conformance suite.
2. **Browser-based CI.** The Argon2id/CSP failure was invisible to a green Node
   suite because Node has no CSP. Playwright against the production export, in
   Chromium/Firefox/WebKit, online and offline, closes that whole class.
3. **Parser fuzzing.** `parseKeym()` consumes attacker-controlled binary.
   Fuzz version, IDs, integer boundaries, flags, and truncation at every byte,
   asserting no crash, no uncontrolled allocation, no KDF invocation, and
   deterministic rejection.
4. **KEYM v2** with streaming/chunked encryption, addressing KM-05 and the
   whole-file memory cost that makes the 100 MB cap necessary.

---

## What holds up well

Primitives are well chosen and correctly assembled: AES-256-GCM via WebCrypto
with non-extractable keys, ChaCha20-Poly1305 via `@noble/ciphers`, Argon2id via
`hash-wasm` at RFC 9106's second recommended profile (64 MiB, t=3, p=4), HKDF
with distinct `keymaker-aes` / `keymaker-chacha` labels giving proper domain
separation between the two chained keys. Fresh salt and nonces per message from
`crypto.getRandomValues`, so every file gets a distinct derived key.

The AAD rule is right, and the byte-flip sweep across the whole header proves
it rather than asserting it. BIP-39 validation checks the actual checksum, not
just word membership. Decryption failures are generic, avoiding an oracle.

The CI split is unusually good: the job guarding legacy decryption runs with no
`npm ci` at all, so no dependency install script can execute in the job that
protects users' existing files. Actions are SHA-pinned with minimal permissions.
