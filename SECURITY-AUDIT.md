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
| KM-06 | Low | PBKDF2 is the effective default despite Argon2id being recommended | **Fixed** |
| KM-07 | Low | `connect-src 'self'` did not enforce the zero-egress claim | **Fixed** |
| KM-08 | Low | Service worker caching scope broader than necessary | **Fixed** |
| KM-14 | Medium | *(new)* Specification omitted the KDF parameter bounds | **Fixed** |

### Second follow-up review (baseline `cb0a0c8`)

| ID | Severity | Finding | Status |
|---|---|---|---|
| KM-02b | Medium | Password gate still certified common dictionary words as "strong" | **Fixed** |
| KM-15 | Medium | Offline guarantee untested for first-use of most cipher paths | **Fixed** |
| KM-16 | Low | Pasted base64 allocated before any size check | **Fixed** |
| KM-17 | Low | One size limit for both directions rejected a max-size container | **Fixed** |
| KM-18 | Low | QR capacity measured in UTF-16 units, not UTF-8 bytes | **Fixed** |
| KM-19 | Low | Secret inputs inherited spellcheck/autocorrect/autofill | **Fixed** |
| KM-20 | Low | Service-worker cache name hand-maintained and stale | **Fixed** |
| KM-21 | Low | Browser CI executed an unpinned downloaded package | **Fixed** |
| KM-22 | Low | Reference implementation dependencies floated | **Fixed** |
| KM-23 | Low | `encryptData` silently defaulted to PBKDF2 | **Fixed** |
| KM-24 | Low | Dice tool collected roll outcomes it has no use for | **Fixed** |

### Found in-house while closing the open items

| ID | Severity | Finding | Status |
|---|---|---|---|
| KM-25 | Low | Service-worker update could swap versions mid-encryption | **Fixed** |
| KM-26 | Medium | Offline support rested on the browser's HTTP cache, not the service worker (3 of 17 chunks cached) | **Fixed** |

**KM-02b — the same mistake, twice removed.** The first version accepted
`a a a a a a`. Tightened to distinct, substantial words, it still accepted
`password qwerty letmein monkey dragon football`. No morphology check fixes
this: entropy is a property of *how* a password was chosen, and a string
carries no evidence of its own provenance. The gate no longer claims to
identify strong passwords — it enforces a floor and says so. The only entropy
figure stated anywhere is for passwords Keymaker generated itself, where it
controls the sampling and the arithmetic is exact.

**KM-15 — the finding did not reproduce, but the concern was right.** First-use
ChaCha *did* work offline, because Turbopack duplicates `@noble/ciphers` into
the eagerly-loaded bundle. That is a bundler chunking decision, not a
guarantee, and it can change on any toolchain bump. Dependencies are now warmed
explicitly at mount, and the offline suite covers all six KDF/cipher
combinations, each in a fresh context that goes offline *before* selecting its
algorithms. The harness was validated by disabling static-asset caching and
confirming the tests fail.

**KM-20** replaced a hand-bumped `keymaker-v1.0.0` — which had gone stale across
several shipped changes to the service worker itself — with a hash of the build
output. It gates more than freshness: the activate handler detects an upgrade
by finding a cache under a different name, so a constant name disabled that
check entirely.
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

**Now done:** a built-in Diceware generator. Controlling the sampling is the
only way to state a passphrase's entropy honestly, so the generator draws seven
words uniformly from the EFF Long Wordlist with the same rejection sampling the
password generator uses — 90 bits, exactly.

The wordlist is the part that needed care, because its size is the denominator
of every figure the UI prints: one duplicate entry and the claim is an
overstatement, which is the KM-02/KM-03 failure class again. So it is fetched
rather than transcribed. `scripts/generate-wordlist.mjs` pulls it from three
independent redistributions across two package registries, pinned by version
and archive hash, and refuses to emit anything unless all three agree on the
full ordered 7,776-word sequence; two of the three carry EFF's file
byte-for-byte, so the recorded SHA-256 is the upstream artifact's.
`npm run test:wordlist` re-derives that hash offline in CI by rebuilding EFF's
exact file layout from the shipped array, which checks content, order and
completeness in one comparison. It earned its place immediately: it caught the
generated module splitting on a single space, which fused the word pair
straddling each line break and silently shortened the list to 7,047 entries.

`meetsPasswordPolicy()` now takes provenance, which fixes a defect the
generator would otherwise have introduced. A uniform seven-word draw repeats a
word about once in 370; repetition costs nothing when the draw is uniform, but
the distinct-word rule reads it as padding — so roughly one generated
passphrase in 370 would have been certified at 90 bits in the UI and then
refused by the Encrypt button. Provenance is the correct basis anyway: it is
KM-02b pointed where it helps, since a typed string can only be judged on
morphology *because* its provenance is unknown, and here it is known.

## KM-25 — Service-worker updates could swap versions mid-encryption *(new)*

Not in either external review. Found while closing out the open items above.

The worker called `skipWaiting()` on install and `clients.claim()` on activate,
so a deployment replaced the running version underneath any open tab, and the
activate handler evicted the old cache on its way in.

That combination is a mid-encryption version swap. The crypto libraries are
lazily imported — the reason `warmCryptoDependencies` exists at all — so a tab
part-way through an Argon2id derivation can still fetch a content-hashed chunk,
and the new build does not contain the old build's chunk URLs. Online that is a
re-fetch of the wrong version's asset; offline, which is the supported way to
use this tool, the import simply fails while the user is encrypting a seed
phrase.

**Fix.** The replacement installs and stops. The page detects it waiting, offers
a reload, and only the user's click promotes it. Until then nothing about the
running version changes — in particular its cache is not evicted, so every lazy
import still resolves. `clients.claim()` stays, because activation is now
reachable only on a first install (nothing to displace, and claiming is what
makes the app work offline without a reload) or on an accepted update (the page
is reloading anyway).

**Tests.** A real update cycle against a private copy of the export on its own
port: both caches coexist while the update waits, the waiting worker has not
taken control, and the old cache is evicted only after the click. Validated by
reinstating `skipWaiting()` and confirming the tests fail. Two things had to be
worked around: Playwright's request interception never sees the browser's
service-worker script fetch, and a `waitForFunction` predicate that returns a
Promise reads as truthy — so the first version of the test passed while
asserting nothing.

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

## KM-06 — Argon2id is now the default

The UI initialises to Argon2id, so the user who never opens Advanced gets the
memory-hard KDF. Because Argon2id needs WebAssembly — and the CSP bug proved
that assumption can fail silently — availability is *probed* rather than
assumed: `isArgon2idAvailable()` compiles an empty WASM module and loads the
library. If either step fails, the UI falls back to PBKDF2, disables the
Argon2id option, and says why. Asserted by a browser test.

## KM-08 — Service worker caching is now an allowlist

Runtime caching was "cache-first for everything else", correct for the current
bundle but open-ended. It is now restricted to content-hashed `/_next/static/*`
and the enumerated app shell. Anything else falls through to the network. For a
tool whose users may be handling seed phrases, what reaches durable storage
should be a decision, not a default.

## KM-14 — The specification omitted the parameter bounds *(new finding)*

Not in the original review. Found by writing the reference implementation.

`FORMAT.md` documented the KDF cost parameters but said nothing about bounding
them. The TypeScript enforced bounds after KM-01; the specification did not, so
the Python reference — written faithfully from the prose — reproduced the
original vulnerability. Cross-testing surfaced it immediately: flipping a
container's `kdf_id` byte makes PBKDF2's iteration bytes be re-read as Argon2id
parameters, and the reference attempted a ~2.5 GiB allocation.

The TypeScript was already immune. Any *new* implementation built from the
document would not have been. Bounds are now normative in `FORMAT.md` §3.1,
with the reading/writing distinction spelled out, and enforced in both
implementations.

This is the finding that justifies keeping the reference: it is the only thing
in the project that tests the specification rather than the code.

---

## Verification now in CI

| Suite | What it covers | Where it runs |
|---|---|---|
| `test:crypto` | 45 frozen-core checks, legacy IBTZ decryption | no dependencies installed |
| `test:keymaker` | 78 KEYM v1 checks, incl. hostile-parameter timing | Node |
| `test:fuzz` | 2,059 assertions over malformed containers | Node |
| `test:wordlist` | EFF wordlist integrity against the upstream checksum | Node, no network |
| `test:browser` | 27 tests on the production export | Chromium, Firefox, WebKit |
| `test:conformance` | 44 cross-implementation checks | Node + Python |
| `test:recovery` | 22 checks executing docs/RECOVERY.md as written | Python |

The browser suite was validated against the bug it exists for: stripping
`'wasm-unsafe-eval'` from the built output fails four tests, two of them
naming the cause directly.

## KM-26 — The offline guarantee was resting on the browser's HTTP cache

Found by counting rather than by reading. Removing `skipWaiting()` (KM-25) was
correct, but it also removed the thing that had been making runtime caching
appear to work: a worker that seizes control on install sees the page's chunk
requests, and one that politely waits does not. Chunks fetched before the
worker controls the page never reach the fetch handler, so they never enter the
cache.

The offline matrix did not notice, and could not. Measured on a first visit,
**3 of 17 shipped chunks** were in Cache Storage — and all six offline cases
still passed, because Playwright's offline emulation leaves Chromium's HTTP
disk cache able to answer, and that cache was warm from the load a moment
earlier. The suite was testing the wrong cache.

The distinction is the whole offline claim. The HTTP cache is evictable and
heuristic; a Cache Storage entry is not. Load the page, close the tab, come
back next week on a plane, and only what the *worker* kept is still there.

The build now emits a precache manifest of every content-hashed chunk and the
worker installs all of them, taking coverage to 17 of 17. Chunks are immutable
by construction, so precaching them wholesale is safe rather than a staleness
risk. A new browser test counts what the worker holds and fails on any chunk
that is missing — the offline matrix stays, but it is no longer the only thing
standing behind the word "offline".

---

## Remaining work

**KEYM v2.** The one substantial item left. Still no code, deliberately — a
wire format needs design review before implementation, not after — but the
design is now written up in
[docs/FORMAT-V2-DESIGN.md](docs/FORMAT-V2-DESIGN.md) rather than living as a
bullet list. It carries:

- length-prefixed, domain-separated key material, closing KM-05
- key files hashed to a fixed size before derivation, so a 100 MB key file is
  not a 100 MB KDF input
- chunked AEAD with counter nonces and a final-chunk flag, removing the
  whole-file memory cost that makes the current 100 MB cap necessary
- the §3.1 bounds as part of the format from the start

Three things the write-up added that the bullet list did not imply: truncation
of a chunked payload is undetectable without an explicit final-chunk marker; a
prefix of verified chunks is not a verified prefix of a file, so streaming
output must not be committed until the last chunk authenticates; and the format
change alone does not lift the size cap, because a browser assembling a Blob to
download still holds the whole ciphertext. The document ends with a review
checklist rather than a conclusion.

KEYM v1 should be frozen as it now stands once v2 exists.

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
