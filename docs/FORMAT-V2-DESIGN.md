# KEYM v2 — Container Format Specification

**Status: shipped and frozen.** This is the normative specification of the
KEYM v2 container, and the application writes it. `encryptContainer()` in
`src/lib/keymaker-crypto.ts` is the writer every UI path reaches, and it
dispatches to `encryptKeym2()`; nothing under `src/components`,
`crypto-worker.ts` or `crypto-client.ts` calls the v1 writer any more. The
footer says `writes KEYM v2` and `/verify` reports the same. `reference/keym2.py`
implements this document independently — written from it alone, before any
TypeScript existed, which is the order that makes the *specification* the thing
under test. It found five gaps; see §11.

`encryptData()` still produces v1 and is deliberately kept, for one reason
given in full at its definition: `reference/crosstest.py` has to be able to
*construct* v1 containers in order to prove the v1 reader still opens them. It
is not reachable from the product.

**The file keeps its `-DESIGN` name on purpose.** That path is printed on every
paper vault (`src/components/paper-vault.tsx`) and inside every self-extracting
page (§7.2), so vaults already in the world point at it. Renaming the file would
make a printed recovery document cite something that does not exist, and a
recovery document that sends its reader to a dead path is the one class of
change this format is not allowed to make. The name is now historical; the
contents are normative.

**Amended once, for multi-slot envelope keys.** The first draft derived the AEAD
key straight from the KDF output. [ROADMAP.md](ROADMAP.md) §Phase 3 required
otherwise — a random master key per container, wrapped independently by
passphrase / key-file / passkey-PRF / Shamir slots — and warned that adding it
later would mean a *second* format migration. The two documents disagreed; this
one was wrong. The amendment landed while **nothing had yet written a v2
container**, which was the last moment it could: §3, §4 and §5.3 changed
substantively, and §11.1 records what that cost, including the part of §3.1's
argument it destroyed.

That window is shut. This document existed to be argued with on paper first,
because a wire format is the one part of this project that cannot be revised
once users have files in it — and they do now. What is written here is what
their containers contain. §9 states the freeze; §11 records what the second
implementation found before it took effect.

[FORMAT.md](FORMAT.md) remains the normative specification of KEYM v1.
**KEYM v1 must remain readable exactly as it is today**, and the frozen fixture
corpus in `scripts/fixtures/keymaker/` is append-only, so nothing here changes
how a v1 container is parsed or decrypted.

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
a container only carries the slots someone deliberately enrolled — but it is a
real price and it should not have to be rediscovered by whoever profiles a slow
failure.

§4.6 lowers the worst case rather than raising it: a Shamir slot derives under
HKDF (§3.2), so it costs microseconds to try and fail. The eight-Argon2id
scenario needs eight *passphrase* slots.

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

`slot_kdf_id = 0x02` — HKDF-SHA-256 (added by §4.6):

| Offset | Size | Field |
|--------|------|-------|
| 40 | 8 | reserved, MUST be zero |

```
slot_key = HKDF-SHA-256(ikm  = slot_secret,
                        salt = slot_salt,
                        info = "keymaker.v2.slot-key",
                        L    = 32)
```

**A KDF with no cost parameters is the point, not an omission.** 0x00 and 0x01
exist to make a low-entropy secret expensive to guess. A slot secret that is
already 32 CSPRNG bytes (§4.6) gains nothing from either: 2^256 does not get
larger when multiplied by a work factor, and the memory cost would be paid on
every unlock in exchange for that nothing.

The corollary is that 0x02 is only correct for a slot type whose secret is
uniformly random and full-width, so §6 makes the pairing normative in both
directions rather than leaving it as advice. A passphrase slot declaring 0x02
would be a password with no stretching at all — a failure mode worth making
structurally unreachable rather than merely discouraged, since it would be
invisible in every output the user ever sees.

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

This section defines the KDF input for `slot_type = 0x00`; §4.6 defines it for
`slot_type = 0x02`. It is unchanged from the first draft except in what it
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
| 0x01 | Passkey / WebAuthn PRF (§4.7) | Implemented |
| 0x02 | Shamir share set (§4.6) | Implemented |
| 0x03–0xFF | Unassigned | Reserved |

The wire layout for 0x01 is deliberately **not** written here. This project's
rule is that a specification is tested by an implementation written from it, and
0x01 has none — so specifying it now would be adding prose that nothing has yet
tried and failed to follow, which is the precise condition that produced KM-14.
Reserving the type code is what the *format* needs in order not to require a
second migration. The layout is that feature's to add, under the same process as
everything else.

0x01 was reserved on those terms and is now specified on them: §4.7 was written
first and `reference/keym2.py` derived from it, which is what moved it out of
this paragraph — the same route 0x02 took. It reached the same conclusion too:
**the slot record's shape does not change.** No new field, no variable-length
record, no change to the table walk below.

0x02 was reserved on those terms and is now specified on them: §4.6 was written
first and `reference/keym2.py` was derived from it, which is what moved it out of
this paragraph.

**The slot record's shape does not change for 0x02.** Same 48-byte prefix, same
offsets, same `wrapped_key`, and bytes 3..7 stay reserved and stay zero. Only two
things differ, and neither is a wire field: where `slot_secret` comes from
(§4.6 rather than §4.1) and which `slot_kdf_id` is legal (§6).

That is the envelope earning its cost. A share set is a slot, so a container can
carry a passphrase in slot 0 and a share set in slot 1, either one opens it, and
neither knows the other is there. A reader that only implements 0x00 skips the
share slot under the rule above and opens the container by passphrase — which is
the case §4.4's skip rule was written for, now with something real to skip.

One thing considered here and rejected: putting a four-byte digest of the
reconstructed secret into the reserved bytes, so a reader could tell "these
shares do not reconstruct this slot's secret" from "this container is damaged".
It buys little — the share checksum already catches transcription damage and the
set id already catches mixing — and it costs twice. It publishes a commitment to
a secret that nothing else commits to, and §6 requires every rejection to be
reported identically anyway, so the distinction it creates could not be shown to
the user without breaking that rule.

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
> A writer **MUST** generate `share_secret` with a CSPRNG, independently for
> every share set (§4.6).
>
> A writer **MUST** generate every Shamir polynomial coefficient with a CSPRNG,
> independently **per byte position and per coefficient index** — that is,
> `(k - 1) × 32` independent bytes for one share set.
>
> A writer **MUST NOT** expose caller-supplied values for any of these in any
> interface intended for encrypting real data.

The master-key requirement is what §5.2's nonce construction now rests on; §11.1
records how it inherited that role from the salt. The salt requirement is what
keeps slot keys distinct — which is what makes a constant wrap nonce safe (§4.3)
— and what stops one precomputation from attacking many containers.

The coefficient requirement is stated at this length because the natural
shortcut is fatal and does not look it. Suppose the same coefficients
`a_1 .. a_{k-1}` are reused across all 32 byte positions, so position `j` uses
`f_j(x) = s_j + a_1·x + … + a_{k-1}·x^{k-1}`. Write
`C(x) = a_1·x + … + a_{k-1}·x^{k-1}`, which no longer depends on `j`. Then the
share at index `x_i` is

```
y_i,j = s_j ⊕ C(x_i)        for every j
```

— the secret masked by **one** byte, repeated 32 times. A single share therefore
narrows the secret to 256 candidates, and the slot's own `wrapped_key` is an
oracle that tests all 256 in microseconds. A k-of-n scheme becomes 1-of-n, and
the shares still reconstruct correctly under every round-trip test, because
reconstruction is not what breaks.

That is the same class of error as reusing a nonce, with the same property of
being invisible to any test that only checks that the thing round-trips. §10 has
a checklist row for it and the reference has a negative control, because "we were
careful" is not evidence.

The one place fixed values are genuinely needed is cross-implementation byte
comparison, which both implementations expose under a separately named entry
point whose documentation states the hazard
(`encryptKeym2WithExplicitSecrets`, `--salt`, `--master-key`,
`--share-secret` and `--share-coefficients`).

### 4.6 Slot secret for a Shamir slot (`slot_type = 0x02`)

A share set is one slot. The container holds no shares and no threshold: it holds
a slot whose secret happens to be reconstructed from paper rather than typed.
Everything from §4.3 onwards is unchanged — the reconstructed secret goes through
`slot_kdf_id` into `slot_key`, which unwraps the same `master_key` every other
slot unwraps.

```
share_secret = CSPRNG(32)                                  never stored anywhere

shamir_input = LP("keymaker.v2.shamir-input") || LP(share_secret)

slot_key     = HKDF-SHA-256(shamir_input, slot_salt, "keymaker.v2.slot-key", 32)
```

`LP` is §4.1's length prefix, and the domain string differs from §4.1's so a
32-byte passphrase and a 32-byte share secret can never produce the same slot
key.

`share_secret` exists only during enrolment. Once the shares are produced and the
slot is wrapped, the writer discards it; there is nothing left in the container
from which it can be recovered short of unwrapping the slot, which requires it.

#### The field

GF(2^8) modulo `x^8 + x^4 + x^3 + x + 1` (0x11B) — the AES field, chosen because
every implementer already has a correct one to check against.

Addition and subtraction are both XOR, which matters twice below and is the usual
place a Shamir implementation transcribed from a textbook over the rationals goes
wrong.

> Multiplication **MUST NOT** be implemented with logarithm/antilogarithm
> tables.

Table lookups indexed by secret bytes leak through the cache, and every value
this multiplies is either a share value or a coefficient. Carry-less
multiply-and-reduce over the 8 bit positions, with the reduction applied through
an arithmetic mask rather than a branch, is around fifteen lines and has no
data-dependent memory access or control flow. Nothing here is hot enough for the
table version to buy anything worth that.

#### Splitting

For threshold `k` and share count `n`, and for each byte position `j` in
`0..31` **independently**:

```
f_j(x) = s_j + a_{1,j}·x + a_{2,j}·x² + … + a_{k-1,j}·x^{k-1}
```

where `s_j` is byte `j` of `share_secret` and every `a_{c,j}` is a fresh CSPRNG
byte. §4.5 is normative about the independence and explains what reusing
coefficients across `j` actually costs.

Share `i`, for `i` in `1..n`, is the index `x_i = i` together with
`[f_j(x_i) for j in 0..31]`.

Indices are `1..n` rather than random distinct values in `1..255`. Both are
sound, sequential is what makes a share referable as "share 3", and the index is
public either way — it is printed in the clear on the paper.

**`n` is deliberately not in the share record.** A share carries what recovery
needs, which is `k`; how many other shares exist is not needed to reconstruct and
is not something a share should tell whoever picks it up. A print kit knows `n`
at print time and can put "3 of 5" on the paper as text — that is a label, not
data the format has to carry.

#### Reconstruction

Lagrange interpolation at `x = 0`, per byte position, over a set `S` of `k`
shares:

```
s_j = Σ_{i∈S}  y_i,j · Π_{m∈S, m≠i}  x_m · inv(x_i ⊕ x_m)
```

`Σ` is XOR, `inv` is inversion in the field. The two places subtraction
disappeared: `(0 − x_m)` became `x_m`, and `(x_i − x_m)` became `x_i ⊕ x_m`.

> A reader given more than `k` shares **MUST** reconstruct from exactly the `k`
> lowest-indexed distinct shares.

Not because using all of them is wrong — with genuine shares every subset of size
`k` gives the same answer — but because with a corrupt share they give
*different* wrong answers, and two implementations that disagree about which
wrong answer they produce are two implementations a user cannot compare. Both
fail either way; determinism costs one sort.

#### The share record

42 bytes. This is the only structure in the format a human is expected to
transcribe, which is what shapes it.

```
+--------+------+------------------------------------------------+
| Offset | Size | Field                                          |
+--------+------+------------------------------------------------+
| 0      | 4    | share_set_id                                   |
| 4      | 1    | threshold: k                                   |
| 5      | 1    | index: x, 1..n                                 |
| 6      | 32   | value: [f_j(x) for j in 0..31]                 |
+========+======+================================================+
                   checksummed body = share bytes [0, 38)
+--------+------+------------------------------------------------+
| 38     | 4    | checksum                                       |
+--------+------+------------------------------------------------+
```

```
share_set_id = SHA-256("keymaker.v2.share-set"      || slot_salt)[0:4]
checksum     = SHA-256("keymaker.v2.share-checksum" || body)[0:4]
```

Both prefixes are fixed constants, so the unprefixed concatenation is injective
for the same reason §4.1's `keyfile_digest` is.

**`share_set_id` is derived, not stored.** It comes from `slot_salt`, which is
already in the container in the clear, so a reader can compute the id a slot
expects and reject a share from a different set before touching the field
arithmetic. Mixing two sets otherwise produces a clean reconstruction of a secret
that is not the right one, failing at the unwrap with the same generic error as a
wrong password — the specific confusion this catches.

It leaks, and the leak is worth naming rather than leaving to be found: anyone
holding a share and a container can test whether they belong together. That is
four bytes of linkability against a party who already holds both artifacts, and
the alternative — a random id stored in the slot — would leak the same fact to
anyone holding the container alone.

**The checksum catches transcription damage, and that is all it claims.** Four
bytes of SHA-256 is one in 4.3 billion for random corruption. It is deliberately
*not* a transcription-optimised code like SLIP-39's Reed-Solomon checksum, which
guarantees detection of specific human error classes rather than a probability
against all of them. Shares here are primarily scanned rather than typed, the
encoding below removes the confusable characters that produce most of those error
classes at the source, and a truncated hash is a construction both
implementations already have and cannot get subtly different. If shares turn out
to be typed more often than scanned, this is the decision to revisit.

#### Share text encoding

```
KMSHARE1:<Crockford base32, uppercase, in groups of 4 separated by ->
```

42 bytes is 336 bits, so 68 characters carrying 4 bits of zero padding in the
last one, in 17 groups of four. A reader **MUST** reject a share whose final
character carries non-zero padding bits, so that one share has exactly one
encoding.

Alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ` — Crockford's, which omits I, L, O
and U. A reader is case-insensitive, maps `I`/`L` to `1` and `O` to `0`, and
ignores hyphens and ASCII whitespace; every other character is rejected.

**Why base32 and not the base64url used everywhere else in this document.** The
whole string — uppercase letters, digits, `-` and `:` — lies inside QR code
*alphanumeric* mode, which packs two characters into 11 bits. base64url needs
lowercase and `_`, forcing byte mode at 8 bits per character:

| encoding | chars | QR mode | bits |
|---|---|---|---|
| Crockford base32 | 68 | alphanumeric | 374 |
| base64url | 56 | byte | 448 |

So the longer string produces the smaller QR code, by 16%, while also being the
one that survives being read aloud, faxed, or copied by hand. There is no
trade-off to make here; base64url loses on both axes.

**Why the prefix is not `KEYMSHARE1:`.** It would begin with the four bytes
`KEYM`, which is the binary magic, and §7 exists because that exact collision
made a text backup pasted into the app report `unsupported version 49`. Repeating
it while adding the feature that puts the most paper in front of users would be
hard to defend. `KM` is disjoint from every other prefix at byte 1 — `KE` for the
binary magic and the legacy `KEYM1:`, `ke` for `keym2:`, `KM` here — so the
detection property §7 established survives, over two bytes instead of one.

The prefix is uppercase, unlike `keym2:`, because `keym2:`'s lowercase `k` exists
solely to break the `KEYM` collision and there is nothing here to break.

#### Bounds

`k` in `2..16` and `n` in `k..16`, both normative on read and write.

`k = 1` is refused rather than treated as a degenerate case: it produces `n`
shares each of which *is* the secret, which is not what anyone reading "1 of 5"
on a piece of paper expects it to mean. `n = 1` is refused for the same reason.

16 is a print-kit bound, not a field bound — the field allows 255 — so it can be
raised later without touching the encoding. §6 carries the rest.

#### What this does and does not give the holder of one share

One share is information-theoretically independent of the secret: for any
candidate secret there are coefficients making that share consistent with it, so
a single share rules nothing out. This is the property that makes distributing
shares to people you trust unevenly reasonable.

Any `k` shares open the container without the password. **Each share is
therefore as sensitive as the password**, and the threat model changes from "one
secret I know" to "k secrets other people hold, who can combine them without
asking me". The UI and the print kit must say this on the artifact itself, not
only in the documentation — a share that ends up in a drawer because it looked
like a receipt is the realistic failure, not a cryptographic one.

### 4.7 Slot secret for a passkey slot (`slot_type = 0x01`)

> **Implemented.** `reference/keym2.py` was written from this section, the
> TypeScript matches it byte for byte under `crosstest2.py`, and three frozen
> fixtures pin the wire format. The section below described a design before any
> of that existed; it now describes shipped code, like every other section.

`0x01` has been reserved since §3.2. A passkey slot is a slot whose secret comes
out of an authenticator rather than off a keyboard.

```
prf_salt      = HKDF-SHA-256(slot_salt, "", "keymaker.v2.prf-salt", 32)

prf_output    = WebAuthn PRF(credential, prf_salt)      32 bytes, from the key

passkey_input = LP("keymaker.v2.passkey-input") || LP(prf_output)

slot_key      = HKDF-SHA-256(passkey_input, slot_salt, "keymaker.v2.slot-key", 32)
```

`LP` is §4.1's length prefix, and the domain string differs from §4.1's and
§4.6's for the same reason those differ from each other: a 32-byte passphrase, a
32-byte share secret and a 32-byte PRF output must never be able to produce the
same slot key.

`prf_salt` is **derived, not stored.** The salt is an *input* the authenticator
needs before it will produce anything, so a reader must hold it before it can
ask — but holding it and storing it are different things. The slot already
carries a random 32-byte `slot_salt`, so one more domain-separated derivation
from a value already in the record produces the PRF salt without spending 32
bytes on it. Its domain string differs from the slot key's for the usual reason:
two derivations from the same `slot_salt` must not be able to collide.

Neither value is secret. Without the credential the salt buys nothing, and the
PRF output cannot be computed without the authenticator.

The KDF is **HKDF only**, by the same §6 rule that binds a Shamir slot. The input
is an unguessable 32-byte value from a hardware key, so Argon2id's memory cost
over it would defend nothing that needs defending.

#### The slot body

**The slot record's shape does not change for 0x01**, exactly as it does not for
0x02. Same 48-byte prefix, same offsets, same `wrapped_key`, and bytes 3..7 stay
reserved and stay zero.

```
slot_type          1   0x01
slot_kdf_id        1   0x02  (HKDF)
slot_flags         1   §4.4 — the key-file bit applies here as elsewhere
reserved           5   MUST be zero
slot_salt         32   §4.4 — also the input `prf_salt` is derived from
KDF parameters     8   §3.2
wrapped_key      ...   §4.3, unchanged
```

There is no passkey-specific field. Only two things differ from a passphrase
slot, and neither is a wire field: where `slot_secret` comes from, and which
`slot_kdf_id` is legal.

That is what makes this section cheap to implement and safe to add. It was not
cheap in the first draft — see below.

The container therefore discloses **nothing** about the credential. Not its id,
not the authenticator, not that a particular key was involved beyond
`slot_type = 0x01` itself saying "a passkey opens this". The earlier draft stored
the credential id in the clear and accepted that disclosure; it no longer has to.

#### A passkey slot is not archival, and the format cannot make it so

> A passkey slot is the **one slot in this format that cannot be opened
> offline.** It is convenience, never the backup of record.

Every other slot can be opened by `reference/keym2.py` with Python, two
libraries and no network — that is the promise the rest of this project is
built to keep. A passkey slot cannot, and not for want of implementation: the
slot secret comes from an authenticator, and the reference cannot reach one.
Given the 32-byte PRF output it will open the slot, but obtaining those bytes
needs a browser, that authenticator, and one more thing that is easy to miss.

**A WebAuthn credential is bound to a relying-party id**, which for a site with
no explicit `rp.id` is the origin's registrable domain. So a passkey enrolled at
`404secnotfound.github.io` answers there and nowhere else. Not from a copy of
the app on another host, not from a self-extracting page opened as `file://`,
not from a future custom domain, and not from whatever serves this in ten years.

That is a dependency on infrastructure the rest of the format deliberately has
none of. Losing the origin does not corrupt the container and does not touch any
other slot — it removes exactly one unlock path, permanently, with no error the
UI can distinguish from a wrong key (§6).

Three consequences worth stating rather than leaving to be discovered:

1. **The other slot is the backup.** Not a fallback, not a belt-and-braces
   extra — the actual disaster-recovery mechanism. The rule below is what
   guarantees one exists.
2. **`docs/RECOVERY.md` must never route someone to a passkey.** The recovery
   procedure is for the case where this project is gone, and in that case the
   passkey slot is gone with it.
3. **The UI must not present a passkey as protection.** It is quick access to a
   container that a passphrase or a share set already protects.

None of this is a defect in §4.7. It is what a passkey *is*, and the honest
response is to say so in the format rather than let the convenience read as
security.

#### A passkey slot never travels alone

> A writer **MUST NOT** produce a container whose only slot is a passkey slot.

The one normative rule in this section that is not about bytes. A passkey is
hardware: it gets lost, broken, wiped, or left in a drawer the person who needs
the container cannot open. A container only a lost key opens is lost data, and
the format is the only place that rule can bind every implementation rather than
being remembered by each UI separately.

A reader **MUST** still open a container that violates it. The rule binds
writers; refusing to read a file someone already holds helps nobody.

#### The decisions, and what they cost

The first draft of this section **did not fit the slot record as it exists.** It
stored `prf_salt` and a variable-length `credential_id`, and §4.4 slots are a
fixed-length prefix followed by the wrapped key. Writing it as drawn meant
changing the slot layout and the table walk that parses it — surgery on the most
security-sensitive code here, and the place §6's bounds live. Two decisions
removed the need entirely.

**1. Derive `prf_salt` rather than store it.** One more domain-separated
derivation from the `slot_salt` already in the record. Removes 32 bytes and
loses nothing: the value was never secret, and a reader that can read the slot
can compute it.

**2. Use a discoverable credential, so nothing names it.** This is what removes
the variable-length field, and with it the parser change. It is not free, and
the costs belong here rather than in an implementer's surprise:

- Enrollment must request `residentKey: "required"`. A credential that is not
  discoverable cannot be found without its id, so this is load-bearing, not a
  preference.
- Discoverable credentials occupy **limited storage on hardware security keys** —
  some hold around 25 — where a non-discoverable credential costs none. Users
  who keep many resident credentials on one key will feel this.
- Unlock shows a credential picker. The earlier draft rejected discoverable
  credentials on the grounds that an heir would face "every passkey they own",
  and **that was overstated**: the picker is scoped to the relying party, so it
  lists the passkeys registered to Keymaker, which for most people is one.
- The real UX cost is narrower and worth stating plainly: with no id in the
  container, **a reader cannot tell one Keymaker passkey from another.** Someone
  with several enrolled across different containers who picks the wrong one gets
  a PRF output that fails to unwrap — and by §6's rule that is indistinguishable
  from a wrong password. The UI cannot say "wrong passkey", because the format
  deliberately does not let it know.

The trade is a parser change against a picker, and the picker wins: a
fixed-width slot keeps §6's table walk and its bounds untouched, and the
container discloses less than the alternative would have. What this project
cannot afford is a quiet bug in the parser; what it can afford is a second tap.

**Established, by the usual gates.** `reference/keym2.py` was written from this
section; `crosstest2.py` compares the two implementations byte for byte, and
checks the derived PRF salt on its own before anything else, because two sides
computing different salts would ask the authenticator different questions and
disagree in every byte afterwards for a reason no container comparison names.
Three fixtures are frozen, one per cipher, since a slot's length follows the
cipher's tag overhead.

Two things the implementation learned that are worth keeping here:

- **Enrolment asks the authenticator twice.** PRF results at creation time are
  optional, and an authenticator that omits them would otherwise enrol a
  credential that can never unlock anything. `create()` then `get()`, and only
  the assertion's output is used.
- **`residentKey` must be `required`.** Not a preference: with no credential id
  in the container, a non-discoverable credential cannot be found at unlock.

And the recorded wrinkle, now confirmed: WebAuthn rejects an IP address as an RP
ID, so the browser suite reaches the server on `localhost` rather than
`127.0.0.1`.

#### What this is, and is not

The blueprint proposed passkey PRF as a security upgrade. **It is not, and the UI
must not say it is.** With a mandatory passphrase slot alongside — which the rule
above guarantees — the container's strength is still bounded by that passphrase.
An attacker who would have brute-forced it still can. The passkey adds no bits.

What it does add is real: no password typed into a form that could be watched or
logged, no password to phish, and a credential the authenticator binds to this
origin. Convenience and phishing resistance. Saying "hardware-grade security"
over a file that a 12-character password also opens would be the KM-02
overstatement in a new place.

## 5. Payload: chunked AEAD

The change that removes the **format's** reason for a 100 MB cap. The app still
enforces one, and the distinction is worth stating precisely because the earlier
wording here — "the change that removes the 100 MB cap" — reads as a promise the
product does not keep.

v1 held the plaintext, the ciphertext and both together in memory, and
authenticated the whole thing as a single buffer; the cap followed from the
format. Chunking ends that: a conforming reader or writer can stream 1 MiB at a
time and nothing in this document imposes an upper bound on payload length.

What still imposes one is the application. `MAX_PLAINTEXT_SIZE` in
`src/lib/keymaker-crypto.ts` is 100 MB and the UI enforces it — the dropzone's
byte limit, the "100 MB max" label and the encrypted-text ceiling all read it —
because the browser build assembles the plaintext as one `Uint8Array` before
encrypting and again after decrypting. Removing the cap without making those
paths stream would trade a clear refusal for an out-of-memory tab, which is a
worse failure on a file someone is trying to back up.

So: the format is unbounded, `reference/keym2.py` is bounded only by the memory
of the machine running it, and the web app stops at 100 MB. A future change that
streams the browser paths is what would lift the last one.

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

`slot_kdf_id = 0x02` has no cost parameters and therefore no row: its eight
parameter bytes are reserved and the "reject non-zero reserved fields" rule below
is the whole of its validation.

**KDF and slot type are paired, in both directions:**

| `slot_type` | legal `slot_kdf_id` |
|---|---|
| 0x00 passphrase | 0x00, 0x01 — **never 0x02** |
| 0x02 Shamir | 0x02 — **only** |

A reader MUST disqualify a slot that violates either direction, before invoking
any KDF. The forbidden combinations are the two that would be silently wrong
rather than noisily wrong: a passphrase under HKDF is a password with no
stretching, and a 32-byte CSPRNG secret under Argon2id is a memory-hard cost paid
to defend an unguessable value. Only the first is a vulnerability, but a rule
that admits the second invites a writer to conclude the pairing is advisory.

Shamir-specific (§4.6). `n` is absent from the share record, so its bound binds
the writer only; everything else here is normative on read:

- a writer MUST reject `n` outside `k`..16;
- reject `k` outside 2..16;
- reject a share index of 0, and reject a supplied share set containing two
  shares with the same index;
- reject a share whose recomputed checksum differs, or whose `share_set_id` does
  not match the one derived from the slot's `slot_salt`;
- reject a share text whose final base32 character carries non-zero padding bits;
- reject a share set whose members disagree about `k`;
- reconstruct from exactly the `k` lowest-indexed distinct shares.

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

**Amended by §4.6.** The share prefix `KMSHARE1:` also begins with 0x4B, so byte
0 alone no longer separates every encoding this project defines. Byte 1 does:

| starts | encoding |
|---|---|
| `KE` | binary container, and the legacy `KEYM1:` armor — separated from each other at byte 4, as before |
| `ke` | `keym2:` armor |
| `KM` | `KMSHARE1:` share (§4.6) |

The property that mattered survives — the cases are disjoint on a fixed-length
prefix, so no reader depends on the order its checks are written in — but it is
now a two-byte property, and a sentence that says one byte should be corrected
rather than left to be true only of the version that wrote it.

A share pasted into the container field is precisely the wrong-box paste this
section exists for, so it must report *this is a share, not a container* rather
than a version error.

Armored output is **wrapped at 64 columns**. Line breaks are not part of the
encoding — every reader strips ASCII whitespace, v2's `dearmor` explicitly and
v1's via `atob`'s forgiving-base64 decode — so this is presentation only, needs
no version bump, and does not change any existing container.

It is not cosmetic, though. One unbroken line is measurably hostile: a
`<textarea>` laying out a single 1 MiB line blocks the main thread for
~12 400 ms, against ~407 ms for the same megabyte wrapped. Since armor is
precisely what a user copies out and pastes back in to recover, emitting one
line meant handing people input the app then choked on. 64 rather than MIME's
76 because it is what PGP uses, it survives quoted-printable mail without
re-wrapping, and it fits an 80-column terminal with a quote marker.

A writer **MAY** emit unwrapped armor where line breaks are pure overhead — a
QR code, where capacity is a hard cliff. Both forms decode identically.

**§4.6's share text wraps differently** — groups of four separated by hyphens,
not lines of 64 — and the difference is not inconsistency. Container armor is
sized for a terminal and a mail client; a share is sized for someone reading it
off paper into a keyboard, where a fixed small group is what keeps your place.
A hyphen also lies inside QR alphanumeric mode, where a newline does not.

The prefix is **case-sensitive** and matched byte-for-byte. A reader that
accepted `KEYM2:` would reintroduce the exact collision this section removes,
while believing it was being lenient.

Base64url without padding, so the armored form survives being pasted into a
URL, a filename, or a QR code without escaping — and so `=` never has to be
stripped by hand from a backup someone is trying to recover.

### 7.1 Paper parts

A container of any interesting size does not fit in one QR code. Version 40 at
error-correction level L holds 2,953 bytes, and **level L is the wrong choice
for paper**: it recovers 7% of a damaged symbol, and paper in a drawer for a
decade gets folded, stained, photocopied and sun-bleached. Paper wants level M
(15%, 2,331 bytes) at least. Either way a real backup spans several symbols, so
the format has to say how they are split and how they go back together.

```
KMPART1:<index>/<total>:<base64url-unpadded>
```

`index` is 1-based, `total` is the number of parts, both decimal without
leading zeros. The payload is a **slice of the raw container bytes**, not of the
armored text — slicing bytes and encoding each slice independently removes any
question about where one base64 group ends and the next begins.

Reassembly: collect the parts, require exactly one of each index in `1..total`
with every part agreeing on `total`, sort by index, concatenate the decoded
slices. The result is the container, byte for byte.

There is deliberately **no checksum**. An AEAD already covers the whole
container, so a mis-assembly fails authentication; a second integrity mechanism
would add nothing except a case where the two disagree and a reader has to
decide which to believe.

**The prefix continues §7's rule rather than bending it.** The two-byte table
above gains a third member and stays disjoint:

| starts | encoding |
|---|---|
| `KE` | binary container, and the legacy `KEYM1:` armor |
| `ke` | `keym2:` armor |
| `KM` | an auxiliary text artefact — **`KMS`** a share (§4.6), **`KMP`** a paper part |

`KM` is a family now rather than a single case, disambiguated at byte 2. A
prefix inside the `ke` family — `keym2p:`, say — was the obvious alternative and
is rejected: it would leave the container armor and a *fragment* of one
distinguishable only at byte 6, which is exactly the "correctness depends on the
order of two checks" problem §7 exists to remove.

A part pasted into the container field is the §7 wrong-box paste again, and gets
the same treatment: a reader **MUST** report *this is part i of n of a paper
backup, and you need all n of them* rather than failing it as a corrupt
container. It is the most likely wrong-box paste of the three, because someone
reassembling a paper backup is scanning symbols one at a time and the first one
has to go somewhere.

A single-part backup is still written `KMPART1:1/1:…` rather than as plain
armor. Special-casing `1/1` would mean an untested branch on the path that only
ever runs for the smallest backups, and the printed page saying "part 1 of 1" is
what stops someone searching a drawer for pages that were never printed.

### 7.2 The WebCrypto-only subset

A self-extracting page — one `.html` holding a container and a decryptor for it —
is not a new format. It is a **profile**: the subset of this document a reader
can implement using nothing but `crypto.subtle`, no WebAssembly and no
dependencies. Writing the subset down is what makes such a page checkable
against the specification rather than against itself.

The subset is forced, not chosen. WebCrypto has PBKDF2, HKDF, SHA-256 and
AES-GCM. It has never had Argon2id or ChaCha20-Poly1305 and no proposal exists
to add either. So:

| Field | Value in the subset | Why nothing else is possible |
|---|---|---|
| `cipher_id` | `0x00` only | 0x01 and 0x02 need ChaCha20-Poly1305 |
| `slot_type` | `0x00` only | 0x02's reconstruction is arithmetic, but §4.6's share text is a second encoding to get right — see below |
| `slot_kdf_id` | `0x00` only | 0x01 is Argon2id; §6 forbids 0x02 on a passphrase slot |

A writer of a self-extracting page **MUST** emit a container in this subset, and
**MUST NOT** emit one that carries a key file (§4.1's third field is `LP("")`).
A reader of the subset is otherwise an ordinary conforming reader: §4.4's skip
rule, §5.2's final-chunk rule and §6's bounds all apply unchanged, and a
subset reader that meets a slot it cannot attempt skips it exactly as §4.4 says.

**The container is ordinary.** That is the property worth protecting. The bytes
inside a self-extracting page are a KEYM v2 container that `reference/keym2.py`
opens, that the app opens, and that the page opens — three independent readers
of one file, which is the same argument the Python reference makes for the
format as a whole. A bespoke "simplified" container for this artefact would have
thrown that away in exchange for nothing.

**The downgrade is real and must be stated wherever the artefact is offered.**
PBKDF2-HMAC-SHA-256 is not Argon2id. It has no memory cost, so it is exactly the
KDF that GPUs and ASICs are good at, and a self-extracting page is the copy of a
backup most likely to be sitting somewhere an attacker can copy it from. This is
a durability-for-strength trade, and it is only worth making deliberately.

**Which is why the page carries its own container rather than a slot on the
user's.** The envelope makes the other option look free: add a second,
PBKDF2 slot to the container the user already has, and the page opens it while
the app keeps using the Argon2id slot. That is wrong, and the reason generalises
past this feature — **a container is only as strong as its weakest slot.**
Anyone holding those bytes attacks the PBKDF2 slot and ignores the other one, so
adding the slot would silently downgrade the user's real backup to buy a
convenience for a copy of it. The artefact gets a separate container, written
for it, and the user's backup is not touched. Slots are an unlock-path
mechanism, not a strength mechanism, and this is the case that shows the
difference.

**Key files are excluded rather than supported.** A self-extracting page that
embedded the key file would put both factors in one file, which is precisely the
property a key file exists to deny; one that silently dropped it would write a
weaker container than the user believes they have. Refusing is the only honest
third option, and it is what a writer MUST do.

**Shamir slots are excluded for a smaller reason and it is worth naming**, since
GF(256) is about forty lines and the exclusion looks over-cautious next to the
two that are forced. §4.6's share *text* — base32 with a checksum, a set id and a
threshold agreement rule — is a second encoding, and every line of it in the page
is a line that has to still be right in 2040 with nobody to fix it. The heir path
for a share set is `keym2.py`, which implements it once and is tested.

#### The embedding

```
<!--KEYM2-BEGIN-->
keym2:<base64url, wrapped per §7>
<!--KEYM2-END-->
```

A reader **MUST** take the bytes between the first `KEYM2-BEGIN` sentinel and
the next `KEYM2-END`, strip ASCII whitespace, and require the result to be a
single `keym2:` armor string. A page carrying zero sentinel pairs, or more than
one, **MUST** be rejected rather than guessed at.

**Sentinels rather than "find the `keym2:` in the file", which is the obvious
alternative and is wrong.** The page's own prose contains that string — it tells
the reader to run `keym2.py`, and it has to explain what the armor is — so a
scanner finds a sentence before it finds the backup. The failure would be silent
and would depend on wording.

**Comments rather than a `<script>` or a data attribute**, so that the armor sits
in the document as visible text. This is the case the whole artefact exists for:
if the page's JavaScript does not run in 2040 — a CSP, a locked-down viewer, a
browser that moved on — the container is still there in a text editor, still
`keym2:` armor, still openable by `keym2.py` or by any reader written since. The
sentinels are inside the `<pre>` so a comment node never reaches `textContent`
and the page's own parser and an external extractor read the same bytes.

This artefact is the one case in this document detected by a **substring** rather
than a prefix, so §7's order-independence needs restating rather than assuming:
the sentinel cannot occur inside any of the prefixed encodings, because `<` and
`!` are outside base64url, base32 and every prefix defined here. The cases stay
disjoint, so a reader may test for the sentinel before or after the prefix table
and get the same answer — which is the property §7 bought, kept rather than
weakened.

**A self-extracting page pasted into the container field is §7's wrong-box paste
again**, and takes the same treatment: a reader that recognises the sentinels
**MUST** extract the container and proceed rather than reporting a corrupt one.
Of the four artefacts this document defines it is the likeliest of all to be
pasted, because it is the one that looks least like a backup — it is a web page,
and someone who opens it and sees a password box has no reason to think the
bytes they need are in the same file.

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
- **Metadata.** Container length reveals plaintext length *exactly*: neither the
  payload nor the final chunk is padded, so overhead is a constant and container
  length determines plaintext length byte for byte. v2 adds no padding scheme:
  one is its own design with its own trade-offs, and bundling it would have made
  this document harder to review at the point where review was the only thing
  standing between a mistake and a permanent one. That decision is now settled
  rather than open — the format is frozen (§9), so padding is a v3 question.
  README.md states the leak plainly rather than leaving it to be discovered.

## 9. Migration — done, and the format is frozen

Written as a plan; kept as a record. Every step below has happened, and step 2
is the one that closed the document.

1. `decryptData()` dispatches on the version byte. v1 containers keep the
   existing code path, byte for byte. The frozen fixtures guarantee it.
2. Writing switched to v2. `encryptContainer()` is the application's writer and
   it produces v2 only; nothing under `src/components`, `crypto-worker.ts` or
   `crypto-client.ts` reaches `encryptData()`, the v1 writer, any more — two
   writable formats would mean two formats to keep correct, and there is no
   reason to author new v1 files. `encryptData()` is not deleted, for a reason
   that is about testing rather than about the product: `reference/crosstest.py`
   has to be able to *construct* v1 containers to prove the v1 reader still
   opens them, and the frozen corpus was generated the same way. Retiring it
   outright would remove the v1 reader's strongest test.

   **This was the step that froze the format**, because it was the first moment
   a user held a v2 container. Everything in this document was revisable until
   it happened and none of it is afterwards, which is why the slot amendment had
   to land before it rather than after. It did; §11.1 records what that cost.
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

Added by the Shamir slot (§4.6):

- [x] Are the polynomial coefficients independent across all 32 byte positions,
      demonstrated rather than asserted? — ✅ and this is the row that justifies
      the whole checklist. The control splits with one coefficient set shared
      across positions; it **still round-trips**, and a one-share attack then
      recovers the secret from 256 candidates. The suite carries both halves
      permanently: the attack must succeed against the degenerate split and fail
      against the real one. Reverting `shamir_split` to reuse coefficients fails
      exactly one check — the one that exists for it.
- [x] Does `k−1` shares yield nothing? — ✅ all ten 2-subsets of a 3-of-5 split
      reconstructed; none is the secret and all ten differ from each other. By
      enumeration, not by citing the theorem.
- [x] Do the Python and TypeScript implementations produce identical share bytes
      from identical coefficients, and identical containers from identical share
      secrets? — ✅ `crosstest2.py` compares the enrolled container and all five
      share strings. Both controls confirm it bites: transposing the coefficient
      block and regrouping the base32 each fail the share comparison.

      **The first control is the reason this row is worded about shares and not
      just containers.** Transposing the coefficients leaves the container
      *byte-identical* — the wrapped key does not depend on them — and changes
      only the printed strings. A conformance test that compared containers
      alone would have passed while the two implementations issued
      mutually-unusable share sets.
- [x] Does a reader skip a Shamir slot it does not implement and still open the
      container from a passphrase slot beside it? — ✅ §4.4's skip rule with a
      real slot type behind it for the first time, tested by narrowing the
      implemented-types set to simulate a reader shipped before §4.6. Getting
      this wrong is a data-loss bug: enrolling shares would make the container
      unopenable by the passphrase still sitting in slot 0.
- [x] Is the share text encoding injective — does exactly one text decode to a
      given share, with non-zero padding bits rejected? — ✅ removing the padding
      check fails exactly that test; without it each share has 16 spellings.
- [x] Does a share from a different set fail on `share_set_id` rather than
      reconstructing a plausible wrong secret? — ✅ two checks, and removing the
      id comparison fails both and nothing else.
- [x] Is the GF(256) multiply free of secret-indexed table lookups and
      data-dependent branches? — ✅ by reading it, since no test can see this;
      both conditionals are arithmetic masks and the only branch is on the
      public constant 254. The suite additionally asserts the function holds no
      large constant, which catches a later "optimisation" back to tables.

One more row, added by implementing it rather than by planning it:

- [x] Is "reconstruct from exactly the `k` lowest-indexed shares" observable, or
      is it unfalsifiable prose? — ✅ it looked unfalsifiable, since genuine
      shares agree on every subset. Corrupting a high-indexed share *with a
      valid checksum* makes the rule the difference between recovering the
      secret and not, and removing the sort fails that check alone.

## 11. Findings from the reference implementation

`reference/keym2.py` was written from this document and nothing else, across
three passes. Four gaps came from the first draft (F1–F4), a fifth from writing
the TypeScript against the same prose (F5), two more from re-deriving the
reference against the slot amendment (F6–F7), and an eighth from deriving it
against §4.6 (F8). All eight are fixed above.

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
| F8 | §4.6, §F | Re-passwording a slot writes a *passphrase* slot, so aiming it at a share-set slot converts one and invalidates every printed share, silently | **Data loss**, tool-level |

**F8 is the first finding in this project that is not about the format at all.**
The container is fine either way: replacing one unlock path with another is
exactly what a mutable slot table is for, and §4.3's constant wrap nonce exists
so that it can be done holding one secret. What the amendment changed is what
sits on the other end of a slot. Re-passwording used to move a secret that lives
in someone's head; now it can annihilate `n` pieces of paper distributed to `n`
people, with the same call and no output.

Fixed in the reference by refusing unless `replace_slot_type=True` is passed,
which is the same shape as `remove_slot`'s refusal to remove the last slot. It
is recorded here rather than only in the code because any second implementation
inherits the hazard the moment it implements §4.6, and nothing in §4.6 warns it.

That the reference has this guard and the specification cannot mandate it is the
honest position: "do not silently destroy an artifact the user is holding in
their hand" is a property of a tool, not of a byte layout.

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
