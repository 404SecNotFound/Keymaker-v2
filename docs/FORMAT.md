# KEYM v1 — Keymaker Container Format Specification

This document is the normative specification of the **KEYM v1** encrypted
container format implemented in `src/lib/keymaker-crypto.ts`. KEYM is a
self-describing, tamper-authenticated file format modeled on the Morpheus
project's format. It supersedes (but can read) the legacy IttyBitz formats
IBTZ v1 and headerless v0.

> For the reasoning behind these choices — the pipeline, the AAD rule, the
> chained-cipher construction, and the attacks they close — see
> [HOW-IT-WORKS.md](HOW-IT-WORKS.md), which covers the same ground with
> diagrams. This document is the contract; that one is the explanation.

All multi-byte integers are **big-endian**. All byte offsets below are
absolute, counted from the first byte of the file.

## 1. Byte layout

```
+--------+-------+-------------------------------------------+
| Offset | Size  | Field                                     |
+--------+-------+-------------------------------------------+
| 0      | 4     | magic: ASCII "KEYM" (4B 45 59 4D)         |
| 4      | 1     | version: 0x01                             |
| 5      | 1     | kdf_id                                    |
| 6      | 1     | cipher_id                                 |
| 7      | 4/7   | kdf params (see §3)                       |
| 11/14  | 1     | flags (see §4)                            |
| 12/15  | 16/32 | salt (16 B for PBKDF2, 32 B for Argon2id) |
| 28/47  | 12/24 | nonce(s) (see §5)                         |
| 40/71  | n     | ciphertext || AEAD tag(s)                 |
+--------+-------+-------------------------------------------+
```

Two header sizes exist depending on kdf_id:

| kdf_id | KDF params | flags at | salt at (len) | nonce(s) at | ciphertext at | settings block len |
|--------|-----------|----------|---------------|-------------|---------------|--------------------|
| 0 (PBKDF2)   | bytes 7–10 | 11 | 12 (16) | 28 (12 or 24) | 40 or 52 | 40 (single) / 52 (chained) |
| 1 (Argon2id) | bytes 7–13 | 14 | 15 (32) | 47 (12 or 24) | 59 or 71 | 59 (single) / 71 (chained) |

## 2. Algorithm identifiers

**kdf_id** (offset 5):

| Value | KDF |
|-------|-----|
| 0x00  | PBKDF2-HMAC-SHA-256 (WebCrypto) |
| 0x01  | Argon2id (hash-wasm, RFC 9106) |

**cipher_id** (offset 6):

| Value | Cipher |
|-------|--------|
| 0x00  | AES-256-GCM (WebCrypto) |
| 0x01  | ChaCha20-Poly1305 (RFC 8439, @noble/ciphers) |
| 0x02  | Chained: AES-256-GCM (inner) then ChaCha20-Poly1305 (outer) |

## 3. KDF parameters

**kdf_id = 0 (PBKDF2-HMAC-SHA-256)** — 4 bytes:

| Offset | Size | Field |
|--------|------|-------|
| 7  | 4 | iterations, uint32 big-endian |

Default at encryption time: 1,000,000. Hash is always SHA-256. Salt length
16 bytes. Output 32 bytes.

**kdf_id = 1 (Argon2id)** — 7 bytes:

| Offset | Size | Field |
|--------|------|-------|
| 7  | 2 | time_cost, uint16 big-endian |
| 9  | 4 | memory_kib, uint32 big-endian |
| 13 | 1 | parallelism, uint8 |

Defaults at encryption time: time_cost 3, memory_kib 65536 (64 MiB),
parallelism 4. Salt length 32 bytes. Output (hashLength) 32 bytes.
Version is always Argon2 v1.3 (0x13), the only version hash-wasm emits.

## 3.1 Parameter bounds (NORMATIVE)

An implementation **MUST** bound the cost parameters in §3 *before* invoking
any key derivation.

This requirement is not an optimisation. It follows from the format's own
structure: the header states how to derive the key, so it must be read before
a key exists, and the AEAD tag that authenticates it (§7) cannot be verified
until after derivation. Every byte of the header is therefore attacker-
controlled at the moment it is used. AAD prevents a tampered header from
yielding valid plaintext; it does **not** prevent attacker-chosen parameters
from being *executed* on the way to discovering the tamper.

Without bounds, a 200-byte file can request 4,294,967,295 PBKDF2 iterations or
4 TiB of Argon2id memory and the reader will attempt it. Note this needs no
crafted file at all: flipping the single `kdf_id` byte of a valid PBKDF2
container makes its iteration bytes be re-read as Argon2id parameters, which
in practice lands on a multi-gigabyte allocation.

| Parameter | Reading (MUST reject outside) | Writing (SHOULD also enforce) |
|---|---|---|
| PBKDF2 `iterations` | 1 .. 10,000,000 | ≥ 600,000 |
| Argon2id `time_cost` | 1 .. 10 | 1 .. 10 |
| Argon2id `memory_kib` | 1 .. 262,144 | ≥ 8,192 |
| Argon2id `parallelism` | 1 .. 8 | 1 .. 8 |

The **upper** bounds are the security control and MUST be enforced when
reading. The **lower** bounds are policy for newly written containers: a
reader MUST remain permissive about weak historical parameters, because
refusing them would strand files that were legitimately created with older or
lower settings.

Rejection MUST happen without invoking the KDF, and MUST be reported as an
ordinary decryption failure.

Bounding parameters does not make a hostile container free to process — it
caps the cost at what the most expensive *legitimate* setting would have cost.
That residual is accepted and bounded; unbounded execution is not.

## 4. Flags (1 byte)

| Bit | Meaning |
|-----|---------|
| 0 | A key file was used at encryption time (**UX hint only** — a UI may prompt for the key file; the bit is authenticated via AAD but is not required for decryption) |
| 1–7 | Reserved; MUST be 0 when writing, MUST be ignored when reading |

## 5. Nonces

- cipher_id 0 or 1: **one** 12-byte nonce (96-bit, as required for GCM and
  used by RFC 8439 ChaCha20-Poly1305).
- cipher_id 2 (chained): **two** 12-byte nonces — first the AES-GCM nonce,
  then the ChaCha20-Poly1305 nonce.

Nonces are generated with a CSPRNG (`crypto.getRandomValues`) per message;
random 96-bit nonces are safe for realistic message counts per key, and keys
are per-file anyway (fresh salt → fresh key).

## 6. Key derivation

1. Password is **NFC-normalized** (`String.prototype.normalize("NFC")`) and
   UTF-8 encoded. This fixes a known IttyBitz gap where visually identical
   passwords with different Unicode normalization produced different keys.
2. If a key file is used, its raw bytes are **appended after** the password
   bytes: `material = password_bytes || keyfile_bytes` (same convention as
   the legacy IttyBitz format).
3. `master_key (32 B) = KDF(material, salt, params)`.
4. Cipher key selection:
   - cipher 0/1: the master key is used directly as the AEAD key.
   - cipher 2 (chained): the master key is expanded with **HKDF-SHA-256**
     (WebCrypto, zero salt) into two independent 32-byte subkeys:
     - AES subkey:     `HKDF(master, info="keymaker-aes")`
     - ChaCha subkey:  `HKDF(master, info="keymaker-chacha")`

## 7. AAD rules (tamper authentication)

The **settings block** — every byte from the magic (offset 0) through the
last nonce byte, i.e. the entire header — is passed as **additional
authenticated data (AAD)** to every AEAD layer:

- cipher 0: AES-256-GCM `additionalData = settings_block`
- cipher 1: ChaCha20-Poly1305 `aad = settings_block`
- cipher 2: inner AES-256-GCM `additionalData = settings_block`; outer
  ChaCha20-Poly1305 `aad = settings_block`

Consequences:

- Flipping any header byte (kdf_id, cipher_id, KDF params, flags, salt,
  nonce) causes authentication failure — the header cannot be rewritten to
  downgrade algorithms or weaken KDF parameters.
- The flags byte is authenticated, so the "key file was used" hint cannot
  be forged.

## 8. Encryption procedure (cipher 2, chained)

1. `inner = AES-256-GCM-Encrypt(aes_subkey, aes_nonce, plaintext, aad=settings)`
   — output includes the 16-byte GCM tag.
2. `ciphertext = ChaCha20-Poly1305-Encrypt(chacha_subkey, chacha_nonce, inner, aad=settings)`
   — appends the 16-byte Poly1305 tag.

Decryption reverses the order: verify+decrypt ChaCha first, then AES-GCM.
Overhead vs. plaintext is 32 bytes of tags (16 for single-cipher modes).

## 9. Backward compatibility

`decryptData()` sniffs the first four bytes:

- `"KEYM"` → this format (version byte 0x01 required).
- `"IBTZ"` → legacy IttyBitz v1, delegated to the frozen `src/lib/crypto.ts`.
- anything else → legacy headerless v0 (`salt(16) || IV(12) || ciphertext`),
  delegated to the frozen `src/lib/crypto.ts`.

The detected format is returned so the UI can show "Imported from IttyBitz"
messaging. Legacy KDF details: PBKDF2-HMAC-SHA-256 at 1,000,000 iterations,
AES-256-GCM, **no** AAD and **no** NFC normalization — see
`scripts/crypto-regression.mts` for the frozen behavior contract.

## 10. Security notes

- **Algorithms:** AES-256-GCM (WebCrypto, constant-time in browsers),
  ChaCha20-Poly1305 (audited @noble/ciphers, pure JS), Argon2id per
  RFC 9106 (hash-wasm, WASM with inlined base64 — fully offline), HKDF and
  PBKDF2 per RFC 5869 / RFC 8018.
- **Chained mode** provides algorithmic defense in depth using independently
  derived keys: recovering the plaintext requires defeating both AEAD layers,
  and neither subkey is derivable from the other. This is a design property,
  not a formally proven combiner-security result — treat it as reducing
  reliance on any single construction, not as a quantified guarantee.
- **Argon2id** is the recommended KDF for new data (memory-hard; resistant
  to GPU/ASIC cracking). PBKDF2 at 1M iterations remains for WebCrypto-only
  environments and legacy parity.
- **AAD on the header** prevents parameter-downgrade and metadata-tampering
  attacks.
- **Memory hygiene:** intermediate key material buffers are zero-filled
  (`secureErase`) after use. This is best-effort — JavaScript's GC may
  retain copies; WebCrypto keys are imported non-extractable where the API
  allows.
- **Error messages** are generic on decryption failure to avoid oracle
  leakage (wrong password vs. corruption are indistinguishable).
- Non-extractable CryptoKeys are used for all AES keys; ChaCha keys exist
  as raw bytes only for the lifetime of the operation and are zeroed.

## 11. Test vectors

Frozen ciphertext vectors live in `scripts/fixtures/keymaker/` — one per
KDF/cipher combo (6 total), described by `fixtures.json`:

| File | KDF | Cipher | Key file |
|------|-----|--------|----------|
| pbkdf2-aes256gcm.keym | PBKDF2 (100k) | AES-256-GCM | no |
| pbkdf2-chacha20poly1305.keym | PBKDF2 (100k) | ChaCha20-Poly1305 | yes |
| pbkdf2-chained.keym | PBKDF2 (100k) | chained | no |
| argon2id-aes256gcm.keym | Argon2id (t=2, m=16384, p=2) | AES-256-GCM | no |
| argon2id-chacha20poly1305.keym | Argon2id (t=2, m=16384, p=2) | ChaCha20-Poly1305 | yes |
| argon2id-chained.keym | Argon2id (t=2, m=16384, p=2) | chained | no |

The corpus is **append-only**: never modify or delete an existing fixture.
Run `npm run test:keymaker` to verify decryption of all vectors plus live
round-trips, tamper rejection and legacy-format compatibility. The fixture
password/key file are published test credentials — never use them for real
data.
