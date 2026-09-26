# KEYM v4 — Container Format Specification

**Status: design.** This document specifies KEYM v4 as a **delta on v3**.
Everything in [FORMAT-V3-DESIGN.md](FORMAT-V3-DESIGN.md), and through it
everything in [FORMAT-V2-DESIGN.md](FORMAT-V2-DESIGN.md), applies unchanged
unless a section here says otherwise. Where this document and v3 disagree
about v4, this document wins; where this document is silent, v3 is normative.

v4 changes one thing: **the payload is padded**, so that the length of a
container no longer states the length of what is inside it. The header, the
slot table and its MAC, the key derivation, the chunking, the nonces, the
bounds and the text armor are all v3's, byte for byte.

---

## 1. Why v4 exists

v2 §8 records the leak and defers it:

> Container length reveals plaintext length *exactly*: neither the payload nor
> the final chunk is padded, so overhead is a constant and container length
> determines plaintext length byte for byte.

v3 §7 defers it again, for the same reason both times: a padding scheme is its
own design, and bundling it with the change each of those revisions was
actually making would have made both harder to review. This document is the
padding scheme on its own, which is what both deferrals asked for.

### 1.1 What the leak costs

For a container with `s` slots and a plaintext of `L` bytes, v3's length is

```
57 + s × slot_len(cipher_id) + L + 16 × ceil(L / 1048576)      (32 × for chained)
```

Every term but `L` is readable from the header without a secret, so anyone
holding the file reads `L` off it. That is a small thing for a photograph and
a large thing for the inputs this tool exists for:

| what is inside | `L` | what its length says |
|---|---|---|
| a 12-word seed phrase | about 75 bytes | "a 12-word seed phrase" |
| a 24-word seed phrase | about 150 bytes | "a 24-word seed phrase" |
| a 24-word seed phrase with a passphrase line | about 170 bytes | "with a passphrase" |
| a password | 16 to 40 bytes | "a password" |

A backup whose size announces what kind of secret it protects has told an
attacker which file to spend the KDF budget on. The cipher hides the words;
the length hands over the category.

### 1.2 What padding can and cannot do

Padding hides `L` to within a **bucket**: a reader without the secret learns
which bucket `L` falls in and nothing finer. It cannot hide that a backup
exists, which cipher it uses, how many ways it can be unlocked, or how large
the container itself is. §5 states the bound and the residual leak precisely,
because a padding scheme described as "hides the size" is the same class of
overstatement as the ones the roadmap's *Honest framing* exists to prevent.

---

## 2. What does not change

- The header layout (v3 §3): magic, `cipher_id`, `flags`, the reserved byte,
  `container_id`, `slot_count`, `slot_table_mac`, the slot table. Only the
  version byte differs.
- `container_id` (v3 §4) and `slot_table_mac` (v3 §5), including §5.2's
  report-do-not-refuse rule and §5.3's enrolment rule.
- Slot layout, slot types, the 48-byte prefix, key derivation, the KDF
  parameter block and every bound (v2 §4, §6).
- The chunked payload, nonce construction, `final_flag` and both AADs (v2 §5).
  v4 chunks a *padded stream* rather than the plaintext; the chunking itself is
  untouched.
- Text armor, paper parts, the share encodings (v2 §7).
- The rejection rule: every failure reports as one generic decryption error
  (v2 §6), with v3 §5.2 as the single exception. Nothing in this document adds
  a second.
- Slot editing. Adding, removing and re-wrapping a slot copy the payload
  through untouched (v2 §4, v3 §5.3), and padding lives inside the payload, so
  every slot operation works on a v4 container exactly as on a v3 one, and
  leaves it v4.

**The version byte is inside both AADs.** Byte 4 is part of the core header,
which every chunk and every slot wrap authenticates. So a v4 container cannot
be relabelled as v3 to make a v3 reader hand back the padded stream as if it
were the plaintext: every chunk fails to open under the altered header. That
property is inherited, not new, and it is what makes a version byte the right
place to put a change to what the plaintext bytes *mean*.

---

## 3. Header

v3 §3's layout with `version = 0x04`:

```
+--------+------+------------------------------------------------+
| Offset | Size | Field                                          |
+--------+------+------------------------------------------------+
| 0      | 4    | magic: ASCII "KEYM" (4B 45 59 4D)              |
| 4      | 1    | version: 0x04                                  |
| 5      | 1    | cipher_id                                      |
| 6      | 1    | flags (v2 §3.3, entirely reserved)             |
| 7      | 1    | reserved, MUST be zero                         |
| 8      | 16   | container_id (v3 §4)                           |
+========+======+================================================+
                     core header = bytes [0, 24)
+--------+------+------------------------------------------------+
| 24     | 1    | slot_count: 1 .. 8                             |
| 25     | 32   | slot_table_mac (v3 §5)                         |
| 57     | ...  | slot table: slot_count × slot_len              |
+--------+------+------------------------------------------------+
| ...    | ...  | payload: chunk sequence over the padded stream |
+--------+------+------------------------------------------------+
```

```
payload_offset = 57 + slot_count × slot_len(cipher_id)
```

A reader dispatches on bytes 0–4 as before. A v4 reader MUST open v1, v2, v3
and v4. A v3 reader meeting `0x04` rejects it as an unknown version, which v2
§3's dispatch and v3 §6 already require of it.

A flag bit was the other place this could have gone, and v2 §3.3 rules it out
in so many words: "new meanings get a version byte, not a reclaimed reserved
bit."

---

## 4. The padded payload

### 4.1 Construction

The writer seals a **stream** rather than the plaintext:

```
L       = len(plaintext)                                  a uint64
n       = 8 + L
P       = padded_len(n)                                   §4.2
stream  = uint64_be(L) ‖ plaintext ‖ zero bytes × (P − n)
```

The stream is then split into chunks and sealed exactly as v2 §5 describes
for the plaintext: chunks of 1,048,576 bytes except the last, `nonce_i =
uint88_be(i) ‖ final_flag`, `payload_aad` = the core header, and the chunk
count `max(1, ceil(P / 1048576))`. Since `P ≥ 256`, the first chunk always
holds the whole 8-byte prefix.

The prefix is inside the AEAD. Nothing about `L` is readable without the key,
and nothing about it can be altered without failing authentication.

### 4.2 `padded_len`

```
padded_len(n):                       n = 8 + L, so n ≥ 8
    if n ≤ 256:
        return 256                   the floor, §4.3
    E = floor(log2(n))
    S = floor(log2(E)) + 1
    z = E − S
    return n rounded up to a multiple of 2^z
```

Above the floor this is **Padmé** (Nikitin, Barman, Lueks, Underwood, Hubaux
and Ford, *Reducing Metadata Leakage from Encrypted Files and Communication
with PURBs*, PETS 2019). Within each doubling `[2^E, 2^(E+1))` it admits only
`2^S` distinct padded lengths, so the granularity grows with the size: two
bytes at 16, sixteen at 256, 2 KiB at 64 KiB, 2 MiB at 64 MiB. The overhead
stays bounded (§5) and no parameter is chosen by the writer, so two writers
cannot disagree about it.

Worked values, which an implementation SHOULD pin in its own tests:

| `n` | `E` | `S` | `2^z` | `padded_len(n)` |
|---|---|---|---|---|
| 8 | — | — | — | 256 (floor) |
| 256 | — | — | — | 256 (floor) |
| 257 | 8 | 4 | 16 | 272 |
| 300 | 8 | 4 | 16 | 304 |
| 1,000 | 9 | 4 | 32 | 1,024 |
| 1,025 | 10 | 4 | 64 | 1,088 |
| 65,544 | 16 | 5 | 2,048 | 67,584 |
| 1,048,584 | 20 | 5 | 32,768 | 1,081,344 |
| 100,000,008 | 26 | 5 | 2,097,152 | 100,663,296 |

`padded_len` is a function of the format, like the chunk size. An
implementation MUST NOT vary it, and a reader MUST verify it (§4.4): a
container padded by any other rule is not a v4 container.

### 4.3 The floor

Padmé's granularity at the small end is two to sixteen bytes, which is exact
enough to keep every line of §1.1's table distinguishable. Below a few hundred
bytes the thing worth hiding is not the size but the *kind* of secret, and only
a floor hides that. 256 bytes is the smallest power of two that covers every
row of that table with room for a passphrase line and a note.

It is also the largest floor that keeps a padded backup on one printed
symbol. A KMPART2 symbol at the paper vault's size carries 702 container bytes
(v2 §7.3); a v4 container at the floor is `57 + 96 s + 256 + 16 = 329 + 96 s`
bytes for `s` AES or ChaCha slots, so up to three slots fit. A floor of 512
would have needed two symbols from the first slot.

The floor costs at most 248 bytes, once, and nothing at all above it: for
`n > 256`, `padded_len(n) ≥ n > 256`, so the two branches of §4.2 meet without
a step.

### 4.4 Reading

A reader opens every chunk exactly as v2 §5 requires, including the final-flag
rule, and holds the whole stream. Then, with `P′` the stream's length:

1. reject if `P′ < 8`;
2. read `L = uint64_be(stream[0, 8))`;
3. reject if `L > P′ − 8`;
4. reject if `P′ ≠ padded_len(8 + L)`;
5. reject if any byte of `stream[8 + L, P′)` is non-zero;
6. return `stream[8, 8 + L)`, and nothing else.

Every rejection is v2 §6's generic decryption failure. Step 3 comes before
step 4 so that `8 + L` is computed only when it fits; an implementation whose
integers are narrower than 64 bits must not be led into an overflow by a
prefix an attacker cannot forge but a broken writer could emit.

A reader **MUST NOT** return any padding byte, and **MUST NOT** report success
before steps 1–5 have all passed on the complete stream. v2 §5.5 already
forbids presenting partially decrypted output as a result; padding adds a
second reason, since the last chunk is where the padding is and the checks on
it are the last to run.

**Streaming is still possible.** Chunk 0 carries `L`, so a reader may emit
plaintext as chunks verify and stop emitting at byte `8 + L`, checking each
later chunk's bytes for zero as it goes, provided the result is not committed
until the final chunk has verified and every check above has passed. That is
v2 §5.5's temporary-destination rule with one more thing to check at the end.

### 4.5 Why this shape

**A prefix, not a trailer or a marker.** A length at the *end* of the stream
would force a streaming reader to hold back every byte until the last chunk,
since it could not know which bytes were padding. A marker byte before the
zeros (`0x80 00 00 …`) would force it to hold back every trailing run of
zeros in case the marker was still to come. A prefix in chunk 0 lets a reader
know the answer before the second chunk arrives, and it costs eight bytes.

**The cost of the prefix is on the writer.** It must know `L` before sealing
chunk 0, so a writer that reads its input from an unbounded stream cannot
write v4. Every writer in this project already holds the plaintext, or a
`File` whose size is known; the constraint is stated so that a future
streaming writer finds it here rather than in a bug.

**Zeros, verified.** The padding's value carries no security: the AEAD
authenticates every byte of the stream, so an attacker cannot change a
padding byte any more than a plaintext byte. The reader checks them anyway,
and the reason is the one that runs through this whole project: the two
implementations must agree on every input. A writer that emitted anything but
zeros would be a non-conforming writer, and an unchecked reader would open its
output while a checking reader refused it. A rule with an exception is a rule
two implementations can disagree about; "every padding byte is zero, and the
reader says so" has none.

---

## 5. What it hides, and what it does not

**Hidden.** `L`, to within a bucket. A reader without the secret learns
`padded_len(8 + L)` and nothing finer. Above the floor that is `E` (the order
of magnitude of `L`) and `S` further bits of position within the doubling,
about `log2(log2 L) + 1` bits — in place of every bit of `L`. At or below the
floor it learns only that `L ≤ 248`.

**Cost.** The floor adds at most 248 bytes, once. Above it the overhead is
below 2^−S of the size: under 7% at any size (the worst case above the floor
is 2,047 bytes on 32,769), under 4% from 64 KiB, under 2% from 4 GiB. A
100 MB file pads by about 660 KB.

**Not hidden.** That a backup exists and is a KEYM container; that it is
padded (the version byte is in the clear, as every version byte is); the
cipher; the number of slots, their types and their KDF costs; `container_id`;
the container's own length; and, for a plaintext just above a bucket
boundary, which side of it the plaintext is on. A container is exactly as
identifiable as a v3 container; what changed is what its length says.

**Not hidden either.** The identity of the plaintext among candidates that
fall in the same bucket. Padding is not deniability, and a size that "could
be anything from 1 to 248 bytes" is still a size.

**Not padded.** v1, v2 and v3 containers. Their lengths still say exactly what
v2 §8 records, and nothing rewrites one (§6).

---

## 6. Migration

- A v4 reader MUST open v1, v2, v3 and v4 containers. Version dispatch on
  byte 4 is unchanged.
- A v3 reader encountering version `0x04` MUST reject it as an unknown
  version, which its existing bounds check already does.
- Writers **MAY** emit v4. This document does not say SHOULD, and does not
  move any default, because the cost falls on the writer's medium: a padded
  backup takes more bytes, and on paper more bytes are more symbols. Whether
  that is worth the bucket is a decision to put in front of the person whose
  paper it is, stated where the choice is made, and the reference CLI takes
  it as `--pad`. A writer that emits v4 MUST do so under the rules of §4; a
  writer that emits v3 is unchanged.
- There is no in-place upgrade. Moving an existing backup to v4 means
  decrypting and re-encrypting it, which is a user's decision and needs their
  secret.
- Slot enrolment, revocation and re-wrapping on a v4 container follow v3 §5.3
  and leave the version, the `container_id` and the payload untouched.
- **The §7.2 subset excludes v4.** A writer of a self-extracting page MUST NOT
  emit a v4 container into it. The page carries its own container, written
  for it and separate from the user's backup (v2 §7.2, "which is why the page
  carries its own container"), so nothing is lost: the user's backup can be
  v4 while the page's container stays v3. Widening the subset would mean
  every page written from now on carries a reader for a format one more
  revision away from the one it was born with; the subset stays what it is
  until there is a reason to move it that is not "because we can".

---

## 7. What this does not fix

- **Metadata confidentiality.** v3 §7's list stands in full. v4 authenticates
  the same header v3 does and hides none of it.
- **The bucket.** §5's residual leak is a property of the scheme, not a bug in
  it. A scheme that leaked nothing would have to pad every container to the
  largest size it will ever hold.
- **Older containers.** A v1, v2 or v3 container's length still states its
  plaintext's length exactly.
- **What a reader with the secret learns.** `L` is in chunk 0. Padding hides
  the length from someone who cannot open the container, and from no one
  else.
- **A writer that does not know its input's length** cannot write v4 (§4.5).

---

## 8. Test vector

Produced by `reference/keym2.py`. The TypeScript core must reproduce this
container **byte for byte** from the same inputs, exactly as v3 §8 requires for
its vector: a container that differs only in its payload has a padding bug, and
one that differs earlier has a header bug, and the two are diagnosed
differently.

Test-only credentials. Never use any of these values for real data: a pinned
salt and a pinned master key reuse every (key, nonce) pair in the container.

**Inputs** — v3 §8's, with the version and the plaintext's label changed:

| field | value |
|---|---|
| password | `correct horse battery staple — test only` (UTF-8, NFC) |
| plaintext | `Keymaker fixture - KEYM v4 / argon2id / aes-256-gcm` (51 bytes, ASCII) |
| `cipher_id` | `0x00` (AES-256-GCM) |
| KDF | Argon2id, `t=3`, `m=65536` KiB, `p=4` |
| slot salt | `00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff` |
| master key | `404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f` |
| `container_id` | `0123456789abcdef0123456789abcdef` |
| slots | one, `slot_type = 0x00` |

**Intermediates**

```
L              51
n              59
P              256                         (the floor)
stream[0, 8)   0000000000000033
stream[8, 59)  the plaintext
stream[59, 256) 197 zero bytes
core_header    4b45594d040000000123456789abcdef0123456789abcdef
K_table        351351be1b09b978ae98feede32b49f98af1acd365aeda6943178985395e7cf6
slot_table_mac 2b57f2b782ba97fe97cf4f18455c21e27d9286d749ce5aa5ff9c76a1fed44c11
```

`core_header` differs from v3 §8's in one byte, the version. `K_table` is
v3 §8's exactly, since it depends on the master key alone; `slot_table_mac`
and every byte after byte 57 differ, because the core header is inside the
MAC's message, the slot wrap's AAD and every chunk's AAD. An implementation
that reproduces `K_table` but not the MAC has the header wrong; one that
reproduces the MAC and the slot but not the payload has the padding wrong.

**Container** — 425 bytes: 24 core header, 1 `slot_count`, 32 MAC, 96 slot,
272 payload (256 stream + 16 tag).

```
4b45594d040000000123456789abcdef0123456789abcdef012b57f2b782ba97
fe97cf4f18455c21e27d9286d749ce5aa5ff9c76a1fed44c1100010000000000
0000112233445566778899aabbccddeeff00112233445566778899aabbccddee
ff00030001000004008e7b9e001250f449d30882f58e5d93c85bb8a8e6459ea5
8ebba4ecc919f86d5c31a2e4a961d80c1b34957112c55e92ddb3ae733192a6e4
725beff0a4ed88081ff33e43e1706716c145d27e0a55965b2bb169dd9f809630
121604f971fec25aa62f06aac5737bd0c139e7a07d41a6a48edcf2868f64b1f9
e31146e75116808c42530044fa45aa06db4459dda1d22ef646d4790d3769ba81
26b022115b28841829f1f40096ebc4acf10b9dad99fada24566f1b6ba0604336
5d5a508c80572e3c1486888e3f4cafcbe3a225b1bafe3fd211dcecfd635f2b32
c5de3ffe575d3c696e8cb27777cb148bdf285d75e8464065939853297de066e2
dbe384123dda057182fb2656f5c735cbc975e8fd07b1d019807174fc25b084fd
3ad0326314c796dde9346618e2ec7e29768b432206d2a99d212e17be19e8fb44
420bacf2a03e69291d
```

Both implementations are held to these bytes by `reference/crosstest2.py`, and
the frozen corpus under `scripts/fixtures/keymaker/` carries v4 vectors beside
v2's and v3's. `scripts/keymaker-generate-fixtures.mts` writes them and skips
any that already exist, so the corpus only ever grows.
