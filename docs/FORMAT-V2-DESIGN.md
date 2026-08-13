# KEYM v2 — Design Proposal

**Status: proposal. Not implemented, not normative, no code written against it.**
Nothing in `src/` reads or writes this format. It exists to be argued with on
paper first, because a wire format is the one part of this project that cannot
be revised after users have files in it.

[FORMAT.md](FORMAT.md) is the normative specification of KEYM v1 and stays
that way. **KEYM v1 must remain readable exactly as it is today**, and the
frozen fixture corpus in `scripts/fixtures/keymaker/` is append-only, so no
change proposed here may alter how a v1 container is parsed or decrypted.

## 1. Why a new version at all

Four items, three of them carried over from
[SECURITY-AUDIT.md](../SECURITY-AUDIT.md#remaining-work).

| # | Problem | Source |
|---|---|---|
| 1 | `password_bytes \|\| keyfile_bytes` is an ambiguous encoding of two secrets | KM-05 (Low, deferred) |
| 2 | A 100 MB key file becomes a 100 MB KDF input | KM-05 follow-on |
| 3 | Encryption holds the whole plaintext, whole ciphertext and both in memory at once, which is what forces the 100 MB cap | audit remaining-work |
| 4 | Parameter bounds arrived as an amendment (§3.1) after an implementation had already reproduced the vulnerability from the prose | KM-14 |

Only the first is a soundness complaint, and even that one is not a practical
key-recovery path. The honest summary is that v1 is *correct but awkward*, and
the awkwardness is in exactly the places a second implementer would trip over.
That is the argument for v2 — not that v1 is broken.

**It is also the argument against rushing.** A format change costs every user a
migration and costs the project a second decryption path it must support
forever. If items 1–4 were the only motivation, deferring indefinitely would be
defensible. Item 3 is what tips it: the 100 MB cap is a user-visible limit that
exists purely because of how the code holds data, and no amount of tuning
removes it without changing the container.

## 2. What does not change

Stated first, because the temptation with a version bump is to redesign things
that are working.

- **Primitives.** AES-256-GCM (WebCrypto), ChaCha20-Poly1305 (`@noble/ciphers`),
  Argon2id (`hash-wasm`, RFC 9106), PBKDF2-HMAC-SHA-256, HKDF-SHA-256. No new
  algorithm is introduced and none is retired.
- **The AAD rule.** The entire header authenticates every AEAD invocation. This
  is the property the byte-flip sweep proves rather than asserts, and it is
  carried forward unchanged in principle.
- **Per-file salt, per-file key.** Fresh CSPRNG salt per container.
- **NFC normalization** of the password before UTF-8 encoding.
- **Generic decryption errors.** Wrong password and corruption stay
  indistinguishable.
- **Chained mode** as algorithmic defence in depth with HKDF-separated subkeys,
  with the same caveat as v1 §10: a design property, not a proven combiner
  result.
- **Non-extractable keys and best-effort zeroing.**

## 3. Header

Fixed 48 bytes. All multi-byte integers big-endian.

```
+--------+------+--------------------------------------+
| Offset | Size | Field                                |
+--------+------+--------------------------------------+
| 0      | 4    | magic: ASCII "KEYM" (4B 45 59 4D)    |
| 4      | 1    | version: 0x02                        |
| 5      | 1    | kdf_id                               |
| 6      | 1    | cipher_id                            |
| 7      | 1    | flags                                |
| 8      | 32   | salt (always 32 bytes)               |
| 40     | 8    | kdf params (§3.2, fixed width)       |
+--------+------+--------------------------------------+
| 48     | ...  | payload: chunk sequence (§5)         |
+--------+------+--------------------------------------+
```

`kdf_id` and `cipher_id` keep their v1 meanings (FORMAT.md §2). Version 0x02 is
what selects this layout; a reader dispatches on bytes 0–4 exactly as v1's
`decryptData()` already does, so v1 containers are unaffected.

### 3.1 Three deliberate removals

**No variable header size.** v1 has two header layouts and two sets of offsets
depending on `kdf_id`, which is the single most error-prone thing in the
document — the offsets table in FORMAT.md §1 exists only to manage it. A fixed
32-byte salt for both KDFs (PBKDF2 accepts any salt length; 32 bytes is not a
weakening) and a fixed-width KDF parameter block make every offset a constant.

**No header-length field.** It would be an attacker-controlled length read
before authentication, and the only thing it buys is appending fields within a
version — which the version byte already covers, more clearly. A field that
cannot be attacked is better than a field that must be bounded.

**No plaintext-length field.** Tempting for preallocation and truncation
detection, but it is an attacker-controlled allocation driver read before
authentication, and truncation is already detected by the final-chunk flag
(§5.2). The size is inferable from the container length anyway, so it would
leak nothing new — it would only add an attack surface to defend.

The through-line: **every header field is read while fully attacker-controlled,
so the cheapest way to bound one is not to have it.** That is KM-01 and KM-14
generalised from "bound the KDF parameters" to "minimise the fields that need
bounding at all".

### 3.2 KDF parameters (8 bytes, fixed)

`kdf_id = 0x00` — PBKDF2-HMAC-SHA-256:

| Offset | Size | Field |
|--------|------|-------|
| 40 | 4 | iterations, uint32 |
| 44 | 4 | reserved, MUST be zero |

`kdf_id = 0x01` — Argon2id:

| Offset | Size | Field |
|--------|------|-------|
| 40 | 2 | time_cost, uint16 |
| 42 | 4 | memory_kib, uint32 |
| 46 | 1 | parallelism, uint8 |
| 47 | 1 | reserved, MUST be zero |

### 3.3 Flags

| Bit | Meaning |
|-----|---------|
| 0 | A key file was used at encryption time (UX hint only, as in v1) |
| 1–7 | Reserved, MUST be zero |

**Reserved bits and bytes MUST be rejected when non-zero**, which is stricter
than v1 (§4 says ignore). The reasoning: the header is covered by AAD, so a
non-zero reserved field cannot be attacker-introduced without failing
authentication — it can only have been written deliberately by a writer that
believed it meant something. Continuing as if it were zero would silently
decrypt a container under an interpretation its author did not intend. Failing
closed is the right answer, and it costs nothing: new meanings get a version
byte, not a reclaimed reserved bit.

## 4. Key derivation

### 4.1 Key material (closes KM-05)

v1 computes `material = password_bytes || keyfile_bytes`, under which
`("ab", "c")` and `("a", "bc")` are the same KDF input. v2 encodes both
secrets unambiguously and separates the domain:

```
LP(x)      = uint32_be(len(x)) || x

keyfile_digest = SHA-256("keymaker.v2.keyfile" || keyfile_bytes)     (32 bytes)

kdf_input  = LP("keymaker.v2.kdf-input")
           || LP(NFC_UTF8(password))
           || LP(keyfile_digest)          -- LP("") when no key file is used
```

Length prefixes make the encoding injective: distinct `(password, key file)`
pairs produce distinct `kdf_input`. The leading context string separates this
input from any other use of the same KDF, now or later.

When no key file is used the third field is present with length zero. Omitting
it entirely would work too, but a fixed shape means one code path rather than
two, and the "no key file" case is then explicitly encoded rather than implied
by absence.

### 4.2 Key files are hashed first

`keyfile_digest` is 32 bytes regardless of the key file's size. This is the
second half of KM-05 and it is what makes a large key file free: the KDF sees
32 bytes, not 100 MB. The digest is domain-separated so a key file's bytes can
never be reinterpreted as some other field's.

The key file itself can be hashed in a stream, so it never needs to be resident
in full either.

### 4.3 Master key and subkeys

`master_key (32 B) = KDF(kdf_input, salt, params)`, then:

- cipher 0x00 / 0x01: the master key is the AEAD key.
- cipher 0x02 (chained): HKDF-SHA-256 (zero salt) into two 32-byte subkeys with
  info strings **`"keymaker-v2-aes"`** and **`"keymaker-v2-chacha"`**.

The info strings differ from v1's `"keymaker-aes"` / `"keymaker-chacha"`
deliberately. It costs nothing and it means a v1 master key and a v2 master key
can never expand to the same subkey, even if some future bug fed one into the
other's path.

## 5. Payload: chunked AEAD

The change that removes the 100 MB cap.

### 5.1 Structure

The plaintext is split into chunks of exactly **1 MiB (1,048,576 bytes)**,
except the last, which holds 0 to 1,048,576 bytes. Each chunk is encrypted
independently under the file key. The payload is the chunks in order, each
followed by its tag(s):

```
chunk_0 ciphertext || tag(s) | chunk_1 ciphertext || tag(s) | ... | chunk_n ...
```

Overhead is 16 bytes per chunk (32 for chained) — about 0.0015% at 1 MiB, which
is why the chunk size does not need to be tunable.

**The chunk size is a constant of the format, not a header field.** A header
field would be an attacker-controlled allocation size read before
authentication; a constant is bounded by construction. Varying it buys
essentially nothing at this overhead, and if a future need appears it is a
version bump. This is §3.1's principle applied to the one field most likely to
have been made configurable out of habit.

A zero-length plaintext is encoded as exactly one chunk containing zero
plaintext bytes, so a container always has at least one chunk and the final
chunk always exists.

### 5.2 Nonces and the final-chunk flag

Chunk `i` (zero-based) uses the 12-byte nonce:

```
nonce_i = uint88_be(i) || final_flag        final_flag = 0x01 on the last chunk, 0x00 otherwise
```

This is the STREAM construction, the same shape `age` uses for its payloads.
Deterministic counter nonces are safe here because the key is per-file: a fresh
random salt gives a fresh master key for every container, so no (key, nonce)
pair is ever reused.

The flag byte is what makes truncation detectable. Without it, an attacker
could drop trailing chunks and every surviving chunk would still authenticate
perfectly — the file would decrypt to a valid prefix of the original with no
error. With it, the final chunk is cryptographically distinguishable, so:

> A reader **MUST** reject a container in which the last chunk it consumes does
> not carry `final_flag = 0x01`.

That sentence is normative and load-bearing. It is exactly the class of
requirement that FORMAT.md originally omitted for parameter bounds (KM-14): the
implementation could satisfy every other check, produce plaintext, and still be
wrong.

For chained mode, both layers of a chunk use `nonce_i`. The two layers are
under independently derived keys, so an identical nonce value across them is
not a reuse.

### 5.3 AAD

Every AEAD invocation, for every chunk and every layer, takes the **48-byte
header** as additional authenticated data — the same rule as v1, applied per
chunk.

Chunk ordering is protected by the nonce rather than the AAD: a reordered chunk
is decrypted under the wrong counter and fails. Splicing chunks between two
containers fails because the keys differ (per-file salt), and separately
because the headers differ.

### 5.4 Encryption and decryption

Encrypting chunk `i`:

- cipher 0x00: `AES-256-GCM(key, nonce_i, chunk, aad=header)`
- cipher 0x01: `ChaCha20-Poly1305(key, nonce_i, chunk, aad=header)`
- cipher 0x02: `ChaCha20-Poly1305(chacha_key, nonce_i, AES-256-GCM(aes_key, nonce_i, chunk, aad=header), aad=header)`

Decryption reverses each chunk and, for chained mode, verifies the outer layer
before the inner one.

### 5.5 The streaming caveat that must not be lost

Chunked AEAD means plaintext becomes available a chunk at a time, and a chunk
that verifies is genuine — but **a prefix of verified chunks is not a verified
prefix of the file.** A container whose chunk 900 fails authentication has
already yielded 899 good chunks. An implementation that streamed those to their
destination has written 899 MB of attacker-chosen-truncation output.

Therefore:

> An implementation **MUST NOT** present partially decrypted output as a
> successful result, and **SHOULD** write to a temporary destination that is
> committed only after the final chunk verifies and carries `final_flag`.

This is the price of streaming and it should be stated in the specification
rather than discovered per implementation. v1 has no such hazard: it is
all-or-nothing by construction.

## 6. Bounds (normative from the start)

FORMAT.md §3.1 exists because the specification originally documented the cost
parameters and said nothing about bounding them, so the Python reference —
written faithfully from the prose — reproduced the vulnerability the TypeScript
had already fixed. In v2 the bounds are part of the format description rather
than an amendment to it.

| Parameter | Reading (MUST reject outside) | Writing (SHOULD enforce) |
|---|---|---|
| PBKDF2 `iterations` | 1 .. 10,000,000 | ≥ 600,000 |
| Argon2id `time_cost` | 1 .. 10 | 1 .. 10 |
| Argon2id `memory_kib` | 1 .. 262,144 | ≥ 8,192 |
| Argon2id `parallelism` | 1 .. 8 | 1 .. 8 |

Carried over unchanged, including the asymmetry: upper bounds are the security
control and apply on read; lower bounds are policy for new containers only, so
that files written with older or lower settings still open.

Additionally, a reader MUST:

- reject any container shorter than 48 bytes + the minimum payload for one chunk;
- reject a payload whose length is not a valid chunk sequence for the declared
  cipher's tag overhead;
- reject non-zero reserved fields (§3.2, §3.3);
- validate all of the above **before** invoking the KDF;
- report every rejection as an ordinary decryption failure, with no detail that
  distinguishes which check failed.

## 7. What this does not fix

- **Chained mode remains unproven as a combiner.** v2 does not change that and
  the wording in FORMAT.md §10 should carry over verbatim (this was KM-13).
- **Memory hygiene is still best-effort.** JavaScript gives no way to guarantee
  a buffer is gone.
- **The output side is not solved by the format.** Chunking removes the
  whole-file cost from encryption and derivation, but a browser that assembles
  the ciphertext into a Blob to trigger a download still holds it. Getting the
  full benefit needs the File System Access API where available, with the
  in-memory path as fallback — so the user-visible size cap may fall in stages
  rather than all at once. **The format change is necessary but not sufficient**,
  and claiming otherwise on the strength of the format alone would be the same
  mistake as claiming Argon2id worked because the Node tests passed.
- **Metadata.** Container length still reveals plaintext length to within a
  chunk, and v2 adds no padding scheme. Worth considering; deliberately not
  proposed here, because a padding scheme is its own design with its own
  trade-offs and bundling it would make this proposal harder to review.

## 8. Migration

1. `decryptData()` dispatches on the version byte. v1 containers keep the
   existing code path, byte for byte. The frozen fixtures guarantee it.
2. Writing switches to v2 once implemented and reviewed. v1 write support is
   retired rather than kept as an option — two writable formats means two
   formats to keep correct, and there is no reason to author new v1 files.
3. `reference/keym.py` implements v2 **from this document alone**, as it did for
   v1. That is the check that the specification is complete: the reference is
   the only thing in the project that tests the prose rather than the code, and
   it is what produced KM-14.
4. `docs/RECOVERY.md` and `reference/recovery_test.py` must be updated together
   — the test executes the printed procedure, so a doc edit that is not matched
   by a test edit makes the printed procedure false.
5. New fixtures are **added** to `scripts/fixtures/keymaker/`, never
   substituted, and the v1 fixtures stay exactly as they are.

## 9. Review checklist

Before any of this becomes code:

- [ ] Is the `kdf_input` encoding injective for every `(password, key file)` pair,
      including empty password and empty key file?
- [ ] Is `uint88_be(i) || flag` correct for the maximum container size the
      implementation will accept, with no counter overflow reachable?
- [ ] Does the final-chunk rule reject every truncation, including truncation
      exactly on a chunk boundary?
- [ ] Can a chunk from container A verify inside container B under any
      circumstances?
- [ ] Does every rejection path run before the KDF?
- [ ] Is 1 MiB defensible against both the tiny-file case (a 200-byte note) and
      the large-file case, or does either want a different constant badly enough
      to justify a header field after all?
- [ ] Does the Python reference, written only from this document, arrive at the
      same bytes as the TypeScript?
