# Review brief for the current format

What an external reviewer of the current container format needs in order to
start, in one place. It is a brief, not a review, and nothing here should be
read as saying the current format has been reviewed.

**Status.** No review scoped to the current format has been engaged. Engaging
one is an owner decision (roadmap, Owner-only register). The review on record
is [SECURITY-AUDIT.md](../SECURITY-AUDIT.md), and its scope line is the KEYM v1
container and the application around it, not what the app writes today.

**Who reviewed is described two ways, and only the owner can settle it.**
SECURITY-AUDIT.md calls its findings the result of external review, and one of
its sections a third-party audit by a four-agent swarm. [OUTREACH.md](OUTREACH.md)
says the project is not audited and has a self-audit, and the README says parts
of the current format have been through external review passes. A reviewer
should read those findings as recorded and fixed, and should not treat any of
them as independent assurance until the owner states who performed them.

**Baseline.** Written against `main` at `40c521b`, the tree released as
v2.3.0 plus the three maintenance PRs merged after it. A reviewer should pin
the exact commit they review and record it here and in the finding write-up;
evidence gathered on one tree does not carry to another without a reason.

---

## 1. What is in scope

The format the app writes by default is KEYM v3; KEYM v4 is written only when
the owner turns on "Hide the size of what is inside". Both readers also open
KEYM v2. Each item points at the normative text, which is the thing to review;
the two implementations are how to check it.

| Area | Normative text | Implementations |
|---|---|---|
| Header, flags, KDF parameter block | FORMAT-V2-DESIGN §3, FORMAT-V3-DESIGN §3, FORMAT-V4-DESIGN §3 | `src/lib/keym-v2.ts`, `reference/keym2.py` |
| KDF choice and bounds, enforced before any derivation | FORMAT-V2-DESIGN §3.2 and §6 | `KDF_LIMITS` in `src/lib/keymaker-crypto.ts` |
| Passphrase and key-file input encoding | FORMAT-V2-DESIGN §4.1, §4.2 | as above |
| Master key, slot keys, the wrap | FORMAT-V2-DESIGN §4.3 | as above |
| Slot record and slot types: passphrase `0x00`, passkey `0x01`, Shamir `0x02`, passphrase-and-shares `0x03` | FORMAT-V2-DESIGN §4.4, §4.6, §4.7, §4.8 | as above, and `src/lib/keym-v2-shamir.ts` |
| Which slots may coexist (OR across slots; AND only inside a `0x03` slot) | FORMAT-V2-DESIGN §4.4 and §4.8 | worker request in `src/lib/crypto-worker.ts` |
| Freshness | FORMAT-V2-DESIGN §4.5 | as above |
| Chunked AEAD, nonces, final-chunk flag, truncation | FORMAT-V2-DESIGN §5 | as above |
| `container_id` and `slot_table_mac`: reported, not refused | FORMAT-V3-DESIGN §4, §5 | as above |
| Padded payload and what it hides | FORMAT-V4-DESIGN §4, §5 | as above |
| Text armor, ignorable characters, paper parts | FORMAT-V2-DESIGN §7 | `src/lib/keym-text.ts`, `src/lib/keym-v2-paper.ts`, `reference/keym2.py` |
| Passkey context: WebAuthn PRF salt derivation and relying party | FORMAT-V2-DESIGN §4.7 | `src/lib/webauthn-prf.ts` |
| Release trust: signed manifest, build attestation, reproducible builds | [VERIFYING.md](VERIFYING.md) | `.github/workflows/release.yml`, `deploy.yml` |

The spec already carries a review checklist (FORMAT-V2-DESIGN §10). Its ticked
rows are executed by `reference/keym2.py selftest` rather than argued; a
reviewer should treat them as claims with a test attached, not as settled.

## 2. What is not in scope

- **KEYM v1 and the legacy IttyBitz formats.** Read-only in this app, frozen,
  and covered by SECURITY-AUDIT.md and its predecessor.
- **The audio carrier** (`docs/FORMAT-AUDIO-STEGO.md`). A transport for a
  container that claims no confidentiality of its own. In scope only if the
  reviewer wants the parser surface; the container inside it is covered above.
- **The internals of the primitives' libraries** (`@noble/ciphers`,
  `hash-wasm`, WebCrypto). Their *use* is in scope; their correctness is
  assumed.
- **The browser, the operating system and the host.** A compromised device or
  browser sees the plaintext as it is typed (README, "What this does not
  protect against").
- **Physical authenticators.** Nothing in the project has tested a real
  passkey; the browser suite uses a virtual authenticator.

## 3. Adversaries

Each row states the project's documented position and where it is written.
Where there is no documented position, the row is a question, not a claim.

| Adversary | Documented position |
|---|---|
| Someone holding the ciphertext only | Addressed: KDF and AEAD. FORMAT-V2-DESIGN §4, §5. |
| Someone crafting a hostile container | Addressed for resource use: bounds are checked before any KDF (FORMAT-V2-DESIGN §6, KM-01). Parser behaviour is fuzzed (`test:fuzz2`, `test:fuzz3`). |
| Someone editing the slot table of a copy | v3 onward: detected and reported, not refused (FORMAT-V3-DESIGN §5.2). v2: not detected (FORMAT-V3-DESIGN §7). |
| A holder of fewer than k shares | Addressed: k−1 shares reveal nothing (FORMAT-V2-DESIGN §4.6, enumerated in the selftest). |
| A dishonest share holder supplying a wrong share | **Question.** The share checksum catches transcription damage (FORMAT-V2-DESIGN §4.6); whether it resists a deliberately altered share is not stated. |
| Someone holding an older copy after a slot was removed | **No documented position.** A copy made before the removal still carries the slot, and no file format can change a copy it does not hold. The documents that offer slot removal should say so. |
| A compromised delivery of the app | Out of the app's reach at run time. Mitigated by the verification procedure in VERIFYING.md, which depends on the reader obtaining the signer identity from somewhere other than the app. |
| A compromised device | Out of scope (README, "What this does not protect against"). |

## 4. Evidence available

Counts from the assurance baseline (roadmap 9.0, added in PR #223), all passing at `40c521b`:

| Suite | What it holds |
|---|---|
| `npm run test:keymaker` | 297 container checks, including the frozen fixture corpus |
| `npm run test:keym2-dispatch` | 76 version-routing checks |
| `npm run test:fuzz2`, `test:fuzz3` | 6,023 and 4,853 mutation assertions on v2 and v3 surfaces |
| `npm run test:shamir` | 19 adversarial assertions on the Shamir core |
| `python reference/keym2.py selftest` | 680 checks, including the spec's §10 rows |
| `python reference/crosstest2.py` | 445 checks: the two implementations agree byte for byte on v2, v3 and v4, including share strings and paper parts |
| `python reference/recovery_test.py` | 185 checks: RECOVERY.md and WALKTHROUGH.md executed against the shipping writer's output |
| Browser suite | Chromium, Firefox and WebKit in CI |

The fixture corpus under `scripts/fixtures/keymaker/` is append-only: a fixture
is a promise that a container written on that day still opens.

## 5. Known findings, open

| # | Finding | Where |
|---|---|---|
| 9.1 | The inheritance plan contradicted the AND setting | roadmap 9.1; fixed in PR #224, merged |
| 9.2 | Verify-only and rehearsal brought the plaintext into the page, which zeroed it without rendering it | roadmap 9.2; fixed by the worker's `verify` operation, not yet merged |
| 9.3 | Creating a backup with extra ways in derives the password once per way in | roadmap 9.3 |
| 9.4 | Shamir polynomial coefficients are not erased after the split | roadmap 9.4 |
| §10 | Whether 1 MiB chunks and a cap of eight slots are the right constants | FORMAT-V2-DESIGN §10, open rows |
| — | The 100 MB user-visible size cap, which the format did not lift | SECURITY-AUDIT.md, "Remaining work" |

## 6. Questions for the reviewer

1. Does the §4.8 slot compose the password and the shares so that neither half
   alone yields the slot key, under the KDF and HKDF steps as specified?
2. Does anything in the wrap or the slot table allow a slot from one container
   to open another (key commitment, domain separation across slot types)?
3. Is reporting rather than refusing a failed `slot_table_mac` the right choice
   for a backup format, given the reasoning in FORMAT-V3-DESIGN §5.2?
4. Do the error paths distinguish failures in a way that forms an oracle?
5. Does the share checksum give any resistance to a deliberately altered share,
   or only to transcription errors?
6. Is the passkey slot's PRF salt derivation bound tightly enough to the
   container and slot that a PRF output cannot be replayed across them?
7. Does v4's padding hide what FORMAT-V4-DESIGN §5 says it hides, and nothing
   less?

---

## Claim register

Every security claim the project makes about the current format, with the
evidence behind it and the assumption it rests on. A claim whose evidence is
only a design argument says so.

| Claim | Stated in | Evidence | Rests on |
|---|---|---|---|
| The page is blocked from opening connections | the app's sealed status (`SEALED_CLAIM` in `src/lib/seal-verdict.ts`) | `test:csp-egress`, `test:seal-verdict`: the build refuses, and the status withholds the claim from, a policy without `default-src`, `connect-src` and `form-action` all `'none'` | The browser enforcing CSP. It says nothing about the backup, which the status does not examine |
| KDF cost parameters are checked before any derivation runs | FORMAT-V2-DESIGN §6; SECURITY-AUDIT KM-01 for v1 | `test:fuzz2` (hostile headers under a time budget); selftest §10, "Does every rejection path run before the KDF?" | Bounds being checked on every read path, including the Python reference |
| A modified or truncated payload is refused | FORMAT-V2-DESIGN §5 | `test:fuzz2`; selftest §10 truncation rows | AES-GCM and ChaCha20-Poly1305 integrity |
| An edited slot table is reported (v3 onward) | FORMAT-V3-DESIGN §5 | `test:fuzz3` | The MAC key being derived from the master key (FORMAT-V3-DESIGN §5.1), which only an opened slot yields |
| Fewer than k shares reveal nothing | FORMAT-V2-DESIGN §4.6 | selftest enumeration; `test:shamir` | Coefficients drawn independently per byte position |
| Two independent implementations agree | FORMAT-V2-DESIGN §10 | `crosstest2.py`, comparing emitted bytes | The Python having been written from the spec, not from the TypeScript |
| A backup can be recovered without the app | RECOVERY.md | `recovery_test.py`; roadmap 9.5 (cold, offline, with pre-downloaded wheels) | The reader having Python and the two pinned libraries, or their wheels saved in advance |
| Verify-only and the rehearsal keep the plaintext in the worker | roadmap 2.3 and 9.2; the app | `test:verify-transport` (every message the worker posts back, for every format); `tests/browser/verify-confinement.spec.ts` (what reaches the page); `tests/browser/verify-recovery-lock.spec.ts` (the rendered page) | A browser with a working worker. Without one the check runs in the page and says so. The password and a passkey's PRF output are still handled in the page |
| Secrets are erased after use | the app's code; SECURITY.md | `test:secret-erase`, `test:secret-erase-core`, `test:encrypt-input-erase` | Best effort only: JavaScript gives no guarantee that a copy was not made elsewhere, and 9.4 is a known gap |
| The published build is the one the source produces | VERIFYING.md | `reproducible` and `reproducible-elsewhere` CI jobs; `test:reproduced-manifest` | The builders being GitHub runners under one administrator, which is not independent reproduction |
| A release was signed by this repository's release workflow | VERIFYING.md; release notes | Sigstore signature and GitHub build attestation on each release | The reader checking the signer identity against a value obtained outside the app |
| v4 hides a small payload's exact length | FORMAT-V4-DESIGN §5 | `crosstest2.py` v4 vectors | Length only; the header, slot count, filename and receipt are separate metadata |
