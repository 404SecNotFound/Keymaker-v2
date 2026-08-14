# KEYM v2 — Design Proposal

**Status: proposal, with two implementations.** Nothing in `src/` *writes* this
format yet; `decryptData()` can already read it. `reference/keym2.py` implements
it — written from this document alone, before any TypeScript existed, which is
the order that makes the *specification* the thing under test. It found five
gaps; see §11.

**Amended for multi-slot envelope keys.** The first draft derived the AEAD key
straight from the KDF output. [ROADMAP.md](ROADMAP.md) §Phase 3 requires
otherwise — a random master key per container, wrapped independently by
passphrase / key-file / passkey-PRF / Shamir slots — and warns that adding it
later would mean a *second* format migration. The two documents disagreed; this
one was wrong. The amendment lands now because **nothing has written a v2
container yet**, so the format is still free to change, and that window closes
the moment the UI writes one. §3, §4 and §5.3 change substantively. §11.1
records what the amendment cost, including the part of §3.1's argument it
destroys.

It exists to be argued with on paper first, because a wire format is the one
part of this project that cannot be revised after users have files in it.

[FORMAT.md](FORMAT.md) is the normative specification of KEYM v1 and stays
that way. **KEYM v1 must remain readable exactly as it is today**, and the
frozen fixture corpus in `scripts/fixtures/keymaker/` is append-only, so no
change proposed here may alter how a v1 container is parsed or decrypted.

## 1. Why a new version at all

Six items, three of them carried over from
[SECURITY-AUDIT.md](../SECURITY-AUDIT.md#remaining-work).

| # | Problem | Source |
|---|---|---|
| 1 | `password_bytes \|\| keyfile_bytes` is an ambiguous encoding of two secrets | KM-05 (Low, deferred) |
| 2 | A 100 MB key file becomes a 100 MB KDF input | KM-05 follow-on |
| 3 | Encryption holds the whole plaintext, whole ciphertext and both in memory at once, which is what forces the 100 MB cap | audit remaining-work |
| 4 | Parameter bounds arrived as an amendment (§3.1) after an implementation had already reproduced the vulnerability from the prose | KM-14 |
| 5 | The text-armor prefix `KEYM1:` shares its first four bytes with the binary magic, so a text backup is misread as a raw container (§7) | found in use |
| 6 | A container has exactly one unlock path, welded to the payload. There is no way to add a second one, or to change the password, without re-encrypting everything | ROADMAP §Phase 3 |

Only the first is a soundness complaint, and even that one is not a practical
key-recovery path. The honest summary is that v1 is *correct but awkward*, and
the awkwardness is in exactly the places a second implementer would trip over.
That is the argument for v2 — not that v1 is broken.

**It is also the argument against rushing.** A format change costs every user a
migration and costs the project a second decryption path it must support
forever. If items 1, 2, 4 and 5 were the only motivation, deferring indefinitely
would be defensible. Items 3 and 6 are what tip it. The 100 MB cap is a
user-visible limit that exists purely because of how the code holds data, and no
amount of tuning removes it without changing the container. Item 6 is the one
with a deadline attached: three Phase 4 features are built on slots, and a
format that ships without them has to be migrated a second time to get them.

## 2. What does not change

Stated first, because the temptation with a version bump is to redesign things
that are working.

- **Primitives.** AES-256-GCM (WebCrypto), ChaCha20-Poly1305 (`@noble/ciphers`),
  Argon2id (`hash-wasm`, RFC 9106), PBKDF2-HMAC-SHA-256, HKDF-SHA-256. No new
  algorithm is introduced and none is retired.
- **The AAD rule**, in principle: no AEAD invocation is unauthenticated with
  respect to the header bytes that govern it. The slot table forces this to be
  stated as two rules rather than one (§5.3), and that is a real change from
  v1's single sentence — but the property the byte-flip sweep proves is the
  same, and the sweep is correspondingly split.
- **Per-container key, per-slot salt.** Fresh CSPRNG for both (§4.5).
- **NFC normalization** of the password before UTF-8 encoding.
- **Generic decryption errors.** Wrong password and corruption stay
  indistinguishable.
- **Chained mode** as algorithmic defence in depth with HKDF-separated subkeys,
  with the same caveat as v1 §10: a design property, not a proven combiner
  result.
- **Non-extractable keys and best-effort zeroing.**

## 3. Header

Two parts, and the split is load-bearing (§5.3): a fixed 8-byte **core header**
that every AEAD invocation in the container authenticates, and a **slot table**
that only its own slot authenticates.

All multi-byte integers big-endian.

```
+--------+------+------------------------------------------------+
| Offset | Size | Field                                          |
+--------+------+------------------------------------------------+
| 0      | 4    | magic: ASCII "KEYM" (4B 45 59 4D)              |
| 4      | 1    | version: 0x02                                  |
| 5      | 1    | cipher_id                                      |
| 6      | 1    | flags (§3.3)                                   |
| 7      | 1    | reserved, MUST be zero                         |
+========+======+================================================+
                     core header = bytes [0, 8)
+--------+------+------------------------------------------------+
| 8      | 1    | slot_count: 1 .. 8                             |
| 9      | ...  | slot table: slot_count × slot_len (§4.4)       |
+--------+------+------------------------------------------------+
| ...    | ...  | payload: chunk sequence (§5)                   |
+--------+------+------------------------------------------------+
```

```
slot_len(cipher_id) = 48 + 32 + tag_overhead(cipher_id)
                    = 96 for ciphers 0x00 and 0x01, 112 for 0x02 (chained)

payload_offset      = 9 + slot_count × slot_len(cipher_id)
```

`cipher_id` keeps its v1 meaning (FORMAT.md §2). Version 0x02 selects this
layout; a reader dispatches on bytes 0–4 exactly as v1's `decryptData()` already
does, so v1 containers are unaffected.

**`kdf_id` is no longer a container-level field.** Each slot declares its own
KDF and its own cost parameters (§4.4), because a passkey-PRF slot and an
Argon2id passphrase slot on the same container do not share a KDF and never
could. This is the first place the envelope pays for itself in the document
rather than in Phase 4.

### 3.1 What survives of "remove the fields", and what does not

The first draft had a fixed 48-byte header and made an argument out of it. The
slot table breaks that argument. Saying precisely which parts of it die is more
useful than quietly rewording the section, because the parts that survive are
what bound the slot table.

**Still removed: the header-length field.** It would be an attacker-controlled
length read before authentication, and the only thing it buys is appending
fields within a version — which the version byte already covers, more clearly.
`slot_count` is not that field wearing a different name: it counts fixed-width
records whose width is fully determined by `cipher_id`, so it selects one of
eight lengths rather than naming an arbitrary one.

**Still removed: the plaintext-length field.** Unchanged: an attacker-controlled
allocation driver read before authentication, while truncation is already
detected by the final-chunk flag (§5.2) and the size is inferable from the
container length anyway.

**No longer true: "no variable header size."** The header is now
`9 + slot_count × slot_len(cipher_id)` bytes and `payload_offset` is a function
of two fields rather than a constant. That was the headline benefit of the fixed
header, and this amendment spends it. What replaces it is weaker, but still
decided before anything is allocated: **every offset is a constant given the
first nine bytes.**

So the through-line is amended, not abandoned:

> Every header field is read while fully attacker-controlled. A field that must
> exist is bounded by a **constant of the format**, never by another field.

`slot_count` is one byte bounded to 1..8 by §6, and the largest slot table any
conforming reader will ever allocate is 8 × 112 = 896 bytes. That number is
known from `cipher_id` and the bound alone — not from anything the container
claims about itself.

**The cost this does impose, stated plainly.** A reader that does not hold the
right secret has to try every slot before it can say so, and each attempt is a
full KDF invocation. Eight slots at §6's maximum Argon2id cost is eight times
the work of one, all of it spent to reach a generic failure. That is a
denial-of-service amplification the first draft did not have. It is bounded
(8 × a bound §6 already fixes), the operation is cancellable in the Worker, and
the writer emits exactly one slot until Phase 4 — but it is a real price and it
should not have to be rediscovered by whoever profiles a slow failure.

### 3.2 KDF parameter block (8 bytes, fixed)

Carried inside each slot rather than in the core header, at **slot-relative**
offsets 40..47. The numbers are unchanged from the first draft — §4.4's slot
layout was chosen to keep them — but they are now relative to the start of the
slot, not the start of the container.

`slot_kdf_id = 0x00` — PBKDF2-HMAC-SHA-256:

| Offset | Size | Field |
|--------|------|-------|
| 40 | 4 | iterations, uint32 |
| 44 | 4 | reserved, MUST be zero |

`slot_kdf_id = 0x01` — Argon2id:

| Offset | Size | Field |
|--------|------|-------|
| 40 | 2 | time_cost, uint16 |
| 42 | 4 | memory_kib, uint32 |
| 46 | 1 | parallelism, uint8 |
| 47 | 1 | reserved, MUST be zero |

### 3.3 Flags

| Bit | Meaning |
|-----|---------|
| 0–7 | Reserved, MUST be zero |

The container-level flags byte is now **entirely reserved**. v1 and the first v2
draft spent bit 0 on "a key file was used at encryption time", as a UX hint.
That fact belongs to a slot rather than to a container — one slot may be a
passphrase plus a key file while another is a passkey — so it moves to
`slot_flags` (§4.4).

Wherever this document numbers bits, bit 0 is the **least significant** bit,
i.e. mask `0x01`. FORMAT.md §4 numbers the same field without saying which end,
and a rule of "reject non-zero reserved bits" should not leave which bits those
are to convention.

**Reserved bits and bytes MUST be rejected when non-zero**, which is stricter
than v1 (§4 says ignore). The reasoning: every reserved field in this format is
covered by one AAD or the other (§5.3) — the core header's by the payload, each
slot's by that slot's own wrap — so a non-zero reserved field cannot be
attacker-introduced without failing authentication. It can only have been
written deliberately by a writer that believed it meant something. Continuing as
if it were zero would silently decrypt a container under an interpretation its
author did not intend. Failing closed is the right answer, and it costs nothing:
new meanings get a version byte, not a reclaimed reserved bit.

`slot_count` is the one header field this argument does **not** cover, because
it is deliberately outside both AADs. §5.3 explains why, and why the exposure is
confined to denial of service. It is bounded rather than reserved, so there is
no "non-zero reserved" case to fail closed on.

## 4. Key derivation

Two levels, which is the whole of the amendment:

```
slot secret ──KDF(slot_salt, slot_params)──► slot_key ──unwraps──► master_key
                                                                        │
                                                        payload keys ◄──┘
```

The **master key** is 32 random bytes, generated once per container, and it is
what the payload is encrypted under. It is never derived from anything. Each
**slot** carries that same master key sealed under a key derived from one
secret, so any single slot opens the container on its own and no slot needs to
know that the others exist.

Three consequences worth naming before the details:

- **Re-passwording does not touch the payload.** Rewrite one slot; the
  ciphertext is unchanged, however large it is.
- **Deterministic nonces stop depending on salt freshness.** §5.2's counter
  nonces are safe because the payload key is fresh per container — and it is now
  fresh *by construction* rather than as a consequence of the salt being fresh.
  That is a direct reduction in the severity of finding F5; see §11.1.
- **Splicing gets harder, not easier.** Two containers written with the same
  password and, through a writer bug, the same salt still have unrelated master
  keys, so chunks still do not transfer between them. Under the first draft they
  would have.

### 4.1 Slot secret for a passphrase slot (closes KM-05)

This section defines the KDF input for `slot_type = 0x00`, which is the only
slot type v2 implements. It is unchanged from the first draft except in what it
produces: a **slot key** that unwraps the master key, rather than the payload
key itself.

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

Literal strings above are ASCII (byte-identical to UTF-8 for these). Stated
because the password beside them carries an explicit encoding, which invites
the reader to wonder whether the omission is meaningful.

Length prefixes make the concatenation injective: no two distinct field
sequences produce the same `kdf_input`, which is what keeps the encoding sound
as fields are added.

Note `keyfile_digest` concatenates *without* a length prefix, in a section
whose subject is that unprefixed concatenation is ambiguous. That is correct —
the prefix is a fixed constant, so `k ↦ "keymaker.v2.keyfile" ‖ k` is injective
— but it is worth saying so, because every careful reader stops on it.

Worth being precise about what closes KM-05, because the reference showed the
obvious answer is wrong: for the specific `(password, key file)` pair, the
collision is closed by **§4.2's hashing**, not by the length prefixes. A
fixed-width 32-byte field cannot slide, so `("ab", "c")` and `("a", "bc")`
differ whether or not anything is length-prefixed. Removing `LP` entirely still
passes a naive injectivity test — which is exactly what a negative control on
`reference/keym2.py` demonstrated.

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

### 4.3 Master key, slot keys and the wrap

**Master key.** `master_key = CSPRNG(32)`, generated once per container (§4.5).
For ciphers 0x00 and 0x01 it is the AEAD key for every chunk. For cipher 0x02
(chained) it expands via HKDF-SHA-256 (zero salt) into two 32-byte subkeys with
info strings **`"keymaker-v2-aes"`** and **`"keymaker-v2-chacha"`**.

Those two info strings differ from v1's `"keymaker-aes"` / `"keymaker-chacha"`
deliberately: a v1 master key and a v2 master key can never expand to the same
subkey, even if some future bug fed one into the other's path.

**Slot key.** For slot `j`:

```
slot_key_j = KDF_j(slot_secret_j, slot_salt_j, slot_params_j)      (32 bytes)
```

`KDF_j` is that slot's own `slot_kdf_id`, and for a passphrase slot
(`slot_type = 0x00`) `slot_secret_j` is exactly §4.1's `kdf_input`. Under cipher
0x02 the slot key expands into two subkeys the same way the master key does, but
under different info strings: **`"keymaker-v2-slot-aes"`** and
**`"keymaker-v2-slot-chacha"`**.

**The wrap.** The master key is sealed under the slot key using the container's
declared cipher:

```
wrap_nonce    = uint88_be(0) || 0xFF            (eleven zero bytes, then 0xFF)
wrapped_key_j = SEAL(slot_key_j, wrap_nonce, master_key, aad = slot_aad_j)
```

`SEAL` is §5.4's construction for `cipher_id`, so a chained container chains its
wrap too. That is deliberate rather than incidental: if the wrap were always
AES-256-GCM, a break in AES-GCM would surrender the master key outright and the
chained payload's defence in depth would be protecting nothing.

`slot_aad_j` is defined in §5.3.

**Why the wrap nonce is a constant, and not the slot index.** Every slot uses
the same nonce, which is safe because every slot has a different key —
`slot_salt` is fresh per slot (§4.5). Deriving it from the slot's position
instead looks strictly better and is not: it would lock each slot to its index,
so removing a slot would force every later slot to be re-wrapped, and
**re-wrapping a slot requires that slot's secret**, which the person removing a
different slot does not have. The same argument governs `slot_count`'s absence
from the AAD (§5.3). A slot table has to be mutable by someone holding one
secret, or slots are not worth having.

The chosen value sits one byte outside the payload's nonce space by
construction: §5.2's nonces end in 0x00 or 0x01, this one ends in 0xFF. The keys
already differ, so this buys nothing cryptographically. It buys a reviewer being
able to see at a glance that no wrap nonce and no payload nonce can coincide.

The residual case is worth naming rather than leaving to be noticed: two slots
in one container with the same secret **and** the same salt would produce
byte-identical `wrapped_key` values. Both wrap the same master key, so no
keystream is reused across differing plaintexts and nothing leaks beyond "these
two slots take the same secret" — which two identical slots already announce.
§4.5 forbids it regardless.

### 4.4 Slot record

Fixed width given `cipher_id`. All offsets below are relative to the start of
the slot.

```
+--------+------+------------------------------------------------+
| Offset | Size | Field                                          |
+--------+------+------------------------------------------------+
| 0      | 1    | slot_type                                      |
| 1      | 1    | slot_kdf_id                                    |
| 2      | 1    | slot_flags                                     |
| 3      | 5    | reserved, MUST be zero                         |
| 8      | 32   | slot_salt (always 32 bytes)                    |
| 40     | 8    | KDF parameters (§3.2)                          |
+========+======+================================================+
                   slot prefix = slot bytes [0, 48)
+--------+------+------------------------------------------------+
| 48     | 32+T | wrapped_key: the master key, sealed (§4.3)     |
+--------+------+------------------------------------------------+
```

`T` is the cipher's tag overhead — 16 bytes for 0x00 and 0x01, 32 for 0x02 — so
a slot is 96 or 112 bytes.

**`slot_type`:**

| Value | Meaning | Status in v2 |
|---|---|---|
| 0x00 | Passphrase, optionally with a key file (§4.1) | Implemented |
| 0x01 | Passkey / WebAuthn PRF | **Reserved**, Phase 4 |
| 0x02 | Shamir share set | **Reserved**, Phase 4 |
| 0x03–0xFF | Unassigned | Reserved |

The wire layouts for 0x01 and 0x02 are deliberately **not** written here. This
project's rule is that a specification is tested by an implementation written
from it, and neither has one — so specifying them now would be adding prose that
nothing has yet tried and failed to follow, which is the precise condition that
produced KM-14. Reserving the type code is what the *format* needs in order not
to require a second migration. The layouts are Phase 4's to add, under the same
process as everything else.

**`slot_flags`:**

| Bit | Meaning |
|-----|---------|
| 0 | A key file was used for this slot (UX hint only, as v1's flags bit 0 was) |
| 1–7 | Reserved, MUST be zero |

**Unknown slot types MUST be skipped, not rejected.**

> A reader **MUST** ignore any slot whose `slot_type` it does not implement.
>
> A reader **MUST NOT** validate the contents of a slot it does not attempt,
> beyond the fixed width that slot occupies.
>
> Every per-slot rejection — unknown type, a reserved field set, parameters
> outside §6's bounds, or simply the wrong secret — **MUST** disqualify that
> slot alone.
>
> A reader **MUST** report failure only once the slot table is exhausted with no
> master key recovered.

The last two sentences are finding F6, and the middle one is F7. Both came from
implementing this section, and both are cases where the first wording of the
amendment said something that fell apart on contact with a second slot.

**Why failure is slot-scoped and not container-scoped.** §3.3's "reject" was
written for a format with one unlock path, where rejecting the slot and
rejecting the container are the same event. They stop being the same event here.
A reader that refuses a whole container because slot 0 sets a reserved bit is
refusing a file whose slot 1 is ordinary and valid — and the reserved bit is
inside slot 0's own AAD, so it cannot have been introduced by an attacker. It
was written by a writer that meant something by it. Declining that slot and
using another is not misreading anything.

**Why a skipped slot is not validated at all.** If a reader checks the reserved
fields of slots it will never attempt, then the first Phase 4 slot type that
gives meaning to one of those bytes makes every container carrying it
unopenable by every reader shipped before it — through the passphrase slot that
is sitting untouched beside it. That is the same data-loss outcome the skip rule
exists to prevent, arriving via a rule in a different section. A slot that is
never attempted cannot contribute to the master key or to the payload; it is
inert bytes inside a length the reader already knows.

That reads like a contradiction of §3.3's "reject non-zero reserved fields", and
the two rules sit close enough together to be worth separating explicitly. A
non-zero *reserved field* means a writer put meaning into a structure this
reader believed it already understood, so proceeding would be misreading the
container. An unrecognised *slot type* means a writer offered an unlock path
this reader cannot walk, inside a fixed-width record whose length the reader
knows exactly. Skipping it misreads nothing; it declines one door and tries the
next.

Rejecting instead would mean that enrolling a passkey in Phase 4 renders the
container unopenable by every reader shipped before it — including by its own
passphrase, which is still sitting in slot 0, still perfectly valid, and now
unreachable. Getting this rule wrong turns a feature into a data-loss event, so
it is normative rather than advisory.

### 4.5 Freshness (normative)

> A writer **MUST** generate `master_key` with a CSPRNG, independently for every
> container.
>
> A writer **MUST** generate `slot_salt` with a CSPRNG, independently for every
> slot, including any slot added to a container that already exists.
>
> A writer **MUST NOT** expose caller-supplied values for either one in any
> interface intended for encrypting real data.

The master-key requirement is what §5.2's nonce construction now rests on; §11.1
records how it inherited that role from the salt. The salt requirement is what
keeps slot keys distinct — which is what makes a constant wrap nonce safe (§4.3)
— and what stops one precomputation from attacking many containers.

The one place fixed values are genuinely needed is cross-implementation byte
comparison, which both implementations expose under a separately named entry
point whose documentation states the hazard
(`encryptKeym2WithExplicitSecrets`, `--salt` and `--master-key`).

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

The chunk count is **`max(1, ceil(len(plaintext) / 1048576))`** — the fewest
chunks that can hold the plaintext.

A zero-length plaintext is therefore exactly one chunk containing zero
plaintext bytes, so a container always has at least one chunk and the final
chunk always exists. A plaintext whose length is a positive multiple of the
chunk size ends with a **full** final chunk; no empty trailing chunk is
emitted.

That second sentence is the one the reference had to add. Without it, a
plaintext of exactly 1,048,576 bytes has two readings that both satisfy "chunks
of exactly 1 MiB ... except the last, which holds 0 to 1,048,576 bytes": one
full final chunk, or a full chunk followed by an empty one. They differ by 16
bytes (32 chained) and in every nonce after the first, so two conforming
writers would produce different containers for the same input — and the decoder
accepts both, unambiguously, which is what makes it invisible to a round-trip
test inside a single implementation.

### 5.2 Nonces and the final-chunk flag

Chunk `i` (zero-based) uses the 12-byte nonce:

```
nonce_i = uint88_be(i) || final_flag        final_flag = 0x01 on the last chunk, 0x00 otherwise
```

This is the STREAM construction, the same shape `age` uses for its payloads.
Deterministic counter nonces are safe here because the key is per-container: the
master key is 32 fresh CSPRNG bytes for every container (§4.5), so no
(key, nonce) pair is ever reused.

**Master-key freshness is what makes this safe, and §4.5 states it as a MUST.**
This is the one place the envelope changed the shape of an existing requirement
rather than adding a new one, so it is worth being explicit about the move; §11.1
records it as an amendment to finding F5.

The first draft rested this property on the *salt*, because the salt was the
only thing that varied per container. Under that draft a writer who reused a
salt with the same password reused the key **and every nonce in the container**,
which for an AEAD means recoverable plaintext and forgeable tags. With a random
master key the salt no longer carries that weight: reusing one is back to being
what it was in v1 — bad practice that weakens per-container separation in the
KDF — rather than a total break.

The requirement did not disappear. It moved onto the field that now determines
the keys, and it is stated there.

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

Two AADs, because the slot table has to be mutable and the payload must not be.

```
payload_aad  = core header                      = container bytes [0, 8)
slot_aad_j   = core header || slot j's prefix   = bytes [0, 8) || slot_j[0, 48)
```

Both are contiguous ranges of actual container bytes. That is deliberate: an AAD
assembled out of fields a reader has to reconstruct is an AAD two
implementations can quietly disagree about.

Every chunk and every layer takes `payload_aad`. Each slot's wrap takes its own
`slot_aad_j`. Between them, every byte of the core header and every byte of
every slot prefix is authenticated.

**Why `slot_count` is in neither.** It is the one header byte no AEAD covers,
and that is a decision rather than an oversight:

- Putting it in `payload_aad` would mean adding a slot invalidates the whole
  payload. The point of the envelope is that it does not.
- Putting it in `slot_aad_j` would mean adding a slot invalidates every *other*
  slot's wrap — and re-wrapping those requires their secrets, which whoever is
  enrolling a passkey does not hold.

Either choice makes a container with more than one unlock path unmaintainable,
so it is left out of both. What that exposes, precisely:

- Editing `slot_count` moves `payload_offset`, so the reader reads the wrong
  bytes as slots, fails every unwrap, and reports a generic failure. No master
  key is recovered, so nothing downstream runs on attacker-chosen input.
- Truncating, duplicating or reordering the slot table achieves the same: a
  failure, or an unlock path that was already there.
- Nobody can *add* a working slot, because forging a `wrapped_key` needs the
  master key.

So the exposure is denial of service, on a file the attacker can already edit or
delete. That is a genuine gap in v1's single-sentence AAD rule and it is the
price of a mutable slot table — but it is not a confidentiality or integrity
gap, and the distinction is the whole reason the split is acceptable.

**Everything the AAD used to cover is still covered by one of the two.** The KDF
cost parameters moved into the slot prefix, so downgrading them breaks that
slot's unwrap before any payload byte is touched. `version` and `cipher_id` are
in the core header, so tampering with them breaks the payload.

**Ordering and splicing.** Chunk ordering is protected by the nonce rather than
the AAD: a reordered chunk is opened under the wrong counter and fails. Splicing
chunks between two containers fails because the master keys are independent
random values.

That last clause is narrower than the first draft's, which also claimed splicing
failed "because the headers differ". With the salt moved into the slot table,
two containers using the same cipher have byte-identical core headers, so that
half of the argument is gone. What replaces it is stronger than what it lost:
the first draft's two containers had equal keys whenever password and salt were
equal, and independent random master keys are unequal regardless.

### 5.4 Encryption and decryption

`SEAL(key, nonce, plaintext, aad)` for each `cipher_id`:

- cipher 0x00: `AES-256-GCM(key, nonce, plaintext, aad)`
- cipher 0x01: `ChaCha20-Poly1305(key, nonce, plaintext, aad)`
- cipher 0x02: `ChaCha20-Poly1305(chacha_key, nonce, AES-256-GCM(aes_key, nonce, plaintext, aad), aad)`

`OPEN` reverses it and, for chained mode, verifies the outer layer before the
inner one.

A chunk is `SEAL(payload key, nonce_i, chunk, payload_aad)`. **The slot wrap in
§4.3 uses the same `SEAL`**, under the slot key, the wrap nonce and that slot's
own AAD — which is why the wrap of a chained container is itself chained, and
why `slot_len` depends on `cipher_id`.

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

Every bound above applies **per slot**, to that slot's own parameter block, and
disqualifies that slot rather than the container (§4.4).

Additionally, a reader MUST:

- reject `slot_count` outside 1..8;
- reject any container shorter than `payload_offset` plus the minimum payload
  for one chunk;
- reject a payload whose length is not a valid chunk sequence for the declared
  cipher's tag overhead;
- reject non-zero reserved fields (§3.2, §3.3, §4.4) in any slot it attempts;
- validate a slot's bounds and reserved fields **before** invoking that slot's
  KDF;
- reject the container once the slot table is exhausted with no master key
  recovered — and only then;
- report every rejection as an ordinary decryption failure, with no detail that
  distinguishes which check failed.

An earlier draft of this list said "reject a container in which no slot carries
a `slot_type` it implements", which is a proxy for the exhaustion rule and
disagrees with it at the edges: a lone type-0x00 slot with `memory_kib` over the
cap has an implemented type, so that wording did not reject it, and it cannot be
attempted either, so nothing else did. Finding F6.

`slot_count`'s upper bound is 8. Nothing in the construction needs a small
number — the bound exists because §3.1's per-slot KDF cost multiplies by it, and
eight maximum-cost Argon2id derivations is roughly where a failed unlock stops
being something a user will sit through. It is a constant of the format for the
same reason the chunk size is one: a number an attacker cannot choose is worth
more than a number that can be tuned.

## 7. Text armor

v1 armors a container for copy-paste as `KEYM1:<base64>`. The first four ASCII
bytes of that prefix are `K`, `E`, `Y`, `M` — byte-identical to the binary
magic. Format detection that sniffs four bytes therefore classifies a text
backup as a raw container and fails on the version byte, which is `'1'` (0x31),
with `unsupported version 49`. Both wrong and baffling, and it was hit in
practice by a text backup pasted back into the app.

The shipped fix checks the text prefix before the magic. That works, but it
makes correctness depend on the order of two checks in every implementation
that will ever read the format — exactly the kind of unwritten obligation the
Python reference exists to catch, and exactly what KM-14 was about.

v2 removes the ambiguity from the encoding instead:

```
keym2:<base64url-unpadded>
```

Lowercase `k` is 0x6B; the magic's `K` is 0x4B. One byte at offset 0
distinguishes the two encodings, so detection is a switch on the first byte
with no ordering dependency and no way for a reader to get it subtly wrong.

The prefix is **case-sensitive** and matched byte-for-byte. A reader that
accepted `KEYM2:` would reintroduce the exact collision this section removes,
while believing it was being lenient.

Base64url without padding, so the armored form survives being pasted into a
URL, a filename, or a QR code without escaping — and so `=` never has to be
stripped by hand from a backup someone is trying to recover.

## 8. What this does not fix

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

## 9. Migration

1. `decryptData()` dispatches on the version byte. v1 containers keep the
   existing code path, byte for byte. The frozen fixtures guarantee it.
2. Writing switches to v2 once implemented and reviewed. v1 write support is
   retired rather than kept as an option — two writable formats means two
   formats to keep correct, and there is no reason to author new v1 files.
   **This is the step that freezes the format**, because it is the first moment
   a user holds a v2 container. Everything in this document is revisable until
   it happens and none of it is afterwards, which is why the slot amendment had
   to land before it rather than after.
3. `reference/keym2.py` implements v2 **from this document alone**, as
   `reference/keym.py` did for v1. That is the check that the specification is
   complete: the reference is the only thing in the project that tests the prose
   rather than the code, and it is what produced KM-14.
4. `docs/RECOVERY.md` and `reference/recovery_test.py` must be updated together
   — the test executes the printed procedure, so a doc edit that is not matched
   by a test edit makes the printed procedure false.
5. New fixtures are **added** to `scripts/fixtures/keymaker/`, never
   substituted, and the v1 fixtures stay exactly as they are.

## 10. Review checklist

Items marked ✅ are answered by `reference/keym2.py selftest`, which executes
them rather than reasoning about them. The unticked ones need a human.

- [x] Is the `kdf_input` encoding injective for every `(password, key file)` pair,
      including empty password and empty key file? — ✅ *and see §4.1: the
      reference showed the digest, not the length prefixes, is what closes the
      KM-05 pair.*
- [x] Is `uint88_be(i) || flag` correct for the maximum container size the
      implementation will accept, with no counter overflow reachable? — ✅
      2^88 chunks of 1 MiB is 2^108 bytes; unreachable by construction, not by
      argument.
- [x] Does the final-chunk rule reject every truncation, including truncation
      exactly on a chunk boundary? — ✅ four truncations and one append, all
      rejected. Removing the flag byte from the nonce fails exactly the two
      boundary cases, which is the negative control for this row.
- [x] Can a chunk from container A verify inside container B under any
      circumstances? — ✅ splice test; the salt differs, so both the key and
      the AAD differ.
- [x] Does every rejection path run before the KDF? — ✅ structurally: header
      parsing *is* validation, so no unbounded `Header` can exist.
- [ ] Is 1 MiB defensible against both the tiny-file case (a 200-byte note) and
      the large-file case, or does either want a different constant badly enough
      to justify a header field after all? — **still open.** A 200-byte note
      pays 16 bytes of tag, i.e. 8%. Tolerable, but it is a judgement call, not
      something a test settles.
- [x] Does the Python reference, written only from this document, arrive at the
      same bytes as the TypeScript? — ✅ `reference/crosstest2.py` compares bytes
      across every KDF × cipher × key-file combination and every chunk-boundary
      size. This is the row that motivated finding F1: until the chunk count was
      pinned, the two implementations could have differed *while both conformed*.
- [x] Does format detection distinguish `keym2:`, the binary magic, and every
      legacy prefix by inspecting bytes alone, with no dependence on the order
      the checks are written in? — ✅ the three cases are disjoint on byte 0.

Added by the slot amendment (§4):

- [x] Does a reader skip a slot type it does not implement and still open the
      container from a slot it does? — ✅ tested with a slot type no
      implementation understands. Getting this wrong is a data-loss bug, not an
      interop bug (§4.4).
- [x] Can a slot be rewritten, added and removed while holding exactly one
      slot's secret? — ✅ this is the requirement that forced both the constant
      wrap nonce (§4.3) and `slot_count`'s absence from the AAD (§5.3), so it is
      executed rather than argued.
- [x] Is every byte of the core header and every byte of every slot prefix
      covered by some AAD? — ✅ split byte-flip sweep, and the negative control
      is that removing either AAD leaves survivors.
- [x] Is `slot_count`'s exclusion from both AADs confined to denial of service —
      can a tampered `slot_count` ever yield a master key? — ✅ every mutation
      of it fails before the payload is reached.
- [ ] Is 8 the right cap on `slot_count`? — **open, and a judgement call.** It
      bounds worst-case failure time at eight KDF invocations (§6). Nobody has
      yet needed more than four slots, but nobody has used this yet either.

## 11. Findings from the reference implementation

`reference/keym2.py` was written from this document and nothing else, across two
passes. Four gaps came from the first draft (F1–F4), a fifth from writing the
TypeScript against the same prose (F5), and two more from re-deriving the
reference against the slot amendment (F6–F7). All seven are fixed above.

They are recorded here because the point of the exercise is the document, and a
fix with no record of what it fixed invites the same gap back on the next edit.
§11.1 is that record for the slot amendment itself.

The two newest are worth noting as a pair: **F6 and F7 are both cases of a rule
written for one unlock path failing on two.** §3.3's "reject" and §6's
rejection condition were each perfectly well-defined while a container had a
single slot, and each became ambiguous the moment it could have several. Neither
was a wrong statement; both were statements whose scope stopped being obvious.
That is the same shape as KM-14 and F1, in a section added specifically to avoid
repeating it.

| # | Section | Gap | Severity |
|---|---|---|---|
| F1 | §5.1 | Chunk count for a plaintext that is an exact multiple of the chunk size | **Interop-breaking** |
| F2 | §7 | Armor prefix case sensitivity unstated | Minor |
| F3 | §3.3 | "Bit 0" not defined as LSB or MSB | Minor |
| F4 | §4.1 | Character encoding of the context literals unstated | Cosmetic |
| F5 | §5.2 | Salt freshness stated as description, not requirement, though deterministic nonces make reuse catastrophic | **Normative gap** — since amended, §11.1 |
| F6 | §6, §4.4 | Rejection condition stated as "no slot of an implemented type" — a proxy for slot-table exhaustion that disagrees with it whenever a slot has a known type but unusable parameters | **Normative gap** |
| F7 | §4.4, §3.3 | Whether a *skipped* slot's reserved fields must still be rejected is unstated, and the two readings differ by whether a Phase 4 slot type bricks older readers | **Normative gap** |

**F5 came from writing the second implementation**, not the first: building a
byte-equality harness forces you to ask for a fixed salt, and asking exposes
that nothing in the document forbids it. v1 tolerated the same mistake far
better, so the instinct carried over from v1 is wrong here. Now stated as a
MUST in §5.2.

**F1 is the one that matters,** and it is worth understanding why it survived
review. Both readings decode correctly, and both round-trip perfectly *within*
one implementation — the ambiguity is on the writer side only. A test suite
built around round-trips cannot see it. It would have surfaced as a
cross-implementation byte mismatch months later, with two implementations each
correctly citing §5.1 in their defence.

That is the same shape as KM-14: not a wrong statement, an absent one, in a
place where every implementation quietly makes the same guess until one does
not.

### On the value of negative controls, again

Two of the four controls run against this reference did **not** fail when the
corresponding protection was removed, which means those two tests were proving
nothing:

- Stubbing `LP()` to the identity left all checks green — because §4.2's
  fixed-width digest already closes the collision the test was aimed at. The
  test was at the wrong layer.
- Removing both reserved-field checks left all checks green — because flipping
  a reserved bit in a finished container breaks the AAD, so it fails on the tag
  regardless. Testing §3.3 requires forging a container whose header is
  *internally consistent*: reserved bit set, payload sealed under that header.

Both tests were rewritten and both controls now bite. Neither gap was
detectable by reading the tests; only by deleting the code they were supposed
to be testing.

### 11.1 What the slot amendment cost

The slot table was added *after* both implementations existed and after this
document had been reviewed once. That is the wrong order, and recording why it
happened matters more than the fact that it did: `docs/ROADMAP.md` §Phase 3 had
required an envelope key from the beginning, this document never carried one,
and nobody noticed the disagreement until the TypeScript was already merged. Two
documents, one of them wrong, and no step in the process compares them to each
other.

The correction was affordable only because of a property that was days from
expiring: **nothing had written a v2 container.** Had the UI shipped first, the
same edit would have been a second migration for every user holding a v2 file —
precisely what the roadmap warned about, in the sentence this document failed to
act on.

What it spent, and what it bought:

| | |
|---|---|
| **Spent** | §3.1's fixed 48-byte header, and with it "every offset is a constant". `payload_offset` is now computed from two fields. |
| **Spent** | v1's single-sentence AAD rule. There are two AADs now (§5.3), and `slot_count` sits outside both — a denial-of-service exposure the first draft did not have. |
| **Spent** | Worst-case time to a failed unlock, multiplied by up to `slot_count` (§3.1). |
| **Spent** | Two fresh normative gaps, F6 and F7 — rules that were unambiguous with one unlock path and stopped being so with several. Re-deriving the reference found both, which is the process working, but they are gaps the first draft did not have. |
| **Gained** | F5 downgraded: deterministic nonces no longer depend on salt freshness, because the payload key is random per container (§5.2). |
| **Gained** | Splice resistance that survives a salt-reuse bug, which the first draft's did not (§5.3). |
| **Gained** | Re-passwording without re-encrypting, and Phase 4 items 1, 2 and 4 without a second migration. |

**F5 is amended, not closed.** The finding was that salt freshness was stated as
description in a design where deterministic nonces made it a requirement. The
requirement is still real and still a MUST — it has moved onto `master_key`,
which is now the field that determines the keys (§4.5). The salt keeps a weaker
freshness requirement of its own, for slot-key distinctness. Anyone who read the
original F5 and concluded "the salt is the load-bearing secret here" would now
be wrong, which is why the finding is edited in place rather than left standing
beside a section that contradicts it.

**What this amendment deliberately did not do.** It did not specify the
passkey-PRF or Shamir slot layouts (§4.4). Reserving their type codes is the
part that removes the second migration. Writing their wire formats now, with no
implementation to test the prose against, would be repeating KM-14 on purpose —
in a document whose §11 exists because of KM-14.
