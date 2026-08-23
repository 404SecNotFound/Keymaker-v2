# KEYM v3 — Container Format Specification

**Status: design.** This document specifies KEYM v3 as a **delta on v2**.
Everything in [FORMAT-V2-DESIGN.md](FORMAT-V2-DESIGN.md) applies unchanged
unless a section here says otherwise. Where the two disagree about v3, this
document wins; where this document is silent, v2 is normative.

That structure is deliberate. v3 changes the header and adds one authentication
tag. The slot construction, the key derivation, the chunked payload, the bounds
and the text armor are all v2's, byte for byte, and restating them here would
create a second copy free to drift from the one the reference implements.

---

## 1. Why v3 exists

One attack, reproduced before this document was written.

A KEYM v2 slot table is authenticated only slot-by-slot: each slot's wrap
covers the 8-byte core header and that slot's own 48-byte prefix (§4.3, §5.3).
Nothing covers the table as a whole. `slot_count` is deliberately outside every
AAD, and §5.3 explains why — a table that only its own payload could
authenticate would need the payload re-encrypted every time a slot was added.

So an attacker who can write the file can **delete a slot**, and the container
still opens for everyone else.

### 1.1 What was measured

A two-slot container — the owner's passphrase, plus an heir's passkey — was
built and then attacked three ways:

| attack | result |
|---|---|
| **Strip** a slot (`slot_count` 2 → 1, drop the record) | Owner opens it normally. **Heir permanently locked out.** |
| **Reorder** the two slots | Both secrets still work. No effect. |
| **Transplant** a slot from another container | Attacker's password **refused**; owner unaffected. |

Only the first is a vulnerability, and its shape is what makes it worth a
format revision: **nothing looks wrong**. The owner opens the backup, sees
their data, and has no way to notice that the recovery path they set up for
somebody else is gone. The failure surfaces years later, at the one moment
nobody can repair it.

Reordering is inert because the unlock walk (§4.4) tries every slot and stops
at the first that unwraps; position carries no meaning. It is pinned in v3
anyway, because doing so costs nothing once a table-wide MAC exists.

The transplant is inert for a reason worth recording, since the obvious reading
of v2's AAD says it should work. A slot's wrap covers the core header, and the
v2 core header is `magic ‖ version ‖ cipher_id ‖ flags ‖ reserved` — entirely
determined by the container's settings, with no per-container randomness. Two
containers written with the same cipher therefore share the slot AAD exactly,
and a slot moved between them **does** verify. It buys nothing: the slot
unwraps to *its own* container's master key, which does not open this
container's payload. The tag check passes and the decryption fails one step
later.

v3 closes that too — `container_id` makes the AAD unique per container — but it
is closing a gap that was never load-bearing, and this document says so rather
than claiming a defeated attack.

### 1.2 The constraint that rules out the obvious fix

Putting `slot_count` and the slot table under the payload AAD would authenticate
them, and would also mean that enrolling a passkey on a 100 MB backup requires
re-encrypting 100 MB. Worse, it would break the property `keym-v2.ts` states at
`WRAP_NONCE`:

> A slot table has to be mutable by someone holding one secret, or slots are
> not worth having.

Any v3 design has to keep that true. The design below does: recomputing the
authentication tag requires the **master key**, and unwrapping any one slot
yields the master key. One secret still suffices to add or remove a slot, and
no other slot has to be touched.

---

## 2. What does not change

- Slot layout, slot types, and the 48-byte slot prefix (§4.4, §4.6, §4.7).
- Key derivation, KDF parameter block and bounds (§4, §6).
- Chunked payload, nonce construction, `final_flag` (§5).
- Text armor, part-splitting, and the self-extracting page (§7).
- The rejection rule: every failure reports as one generic decryption error
  (§6). The slot-table check in §5 below is the single, deliberate exception,
  and §5.2 explains why it does not leak.
- `slot_len(cipher_id) = 48 + 32 + tag_overhead(cipher_id)`.

---

## 3. Header

Two changes: a 16-byte `container_id`, and a 32-byte `slot_table_mac`.

```
+--------+------+------------------------------------------------+
| Offset | Size | Field                                          |
+--------+------+------------------------------------------------+
| 0      | 4    | magic: ASCII "KEYM" (4B 45 59 4D)              |
| 4      | 1    | version: 0x03                                  |
| 5      | 1    | cipher_id                                      |
| 6      | 1    | flags (v2 §3.3)                                |
| 7      | 1    | reserved, MUST be zero                         |
| 8      | 16   | container_id: 16 CSPRNG bytes (§4)             |
+========+======+================================================+
                     core header = bytes [0, 24)
+--------+------+------------------------------------------------+
| 24     | 1    | slot_count: 1 .. 8                             |
| 25     | 32   | slot_table_mac (§5)                            |
| 57     | ...  | slot table: slot_count × slot_len              |
+--------+------+------------------------------------------------+
| ...    | ...  | payload: chunk sequence (v2 §5)                |
+--------+------+------------------------------------------------+
```

```
payload_offset = 57 + slot_count × slot_len(cipher_id)
```

The core header grows from 8 bytes to 24 and keeps its role exactly: it is the
payload AAD, and the first half of every slot's wrap AAD. Widening it is what
gives per-container binding, at no cost to either construction.

`slot_table_mac` sits **before** the table, at a fixed offset, so a reader
reaches it without first trusting `slot_count`.

A reader dispatches on bytes 0–4 as before. v1 and v2 containers are
unaffected, and a v3 reader MUST continue to open both.

---

## 4. `container_id`

16 bytes from a CSPRNG, drawn once when the container is created and never
changed — not on enrolment, not on revocation, not on any rewrite of the slot
table. It identifies *this container* for the lifetime of the file.

It is not a secret and MUST NOT be treated as one. It appears in the clear in
every copy of the backup, and two copies of the same backup share it. Its only
job is to make the slot AAD and the payload AAD differ between containers that
would otherwise be byte-identical, so that a slot or a payload chunk moved
between them fails to authenticate rather than verifying uselessly (§1.1).

16 bytes rather than 32 because the requirement is uniqueness across the
containers one person creates, not unguessability. A 128-bit random value
collides with probability below 2⁻⁶⁴ after 2³² containers, and 16 bytes keeps
the core header at a convenient 24.

---

## 5. `slot_table_mac`

### 5.1 Construction

```
K_table = HKDF-SHA-256(
              ikm  = master_key,
              salt = "" (empty),
              info = "keymaker.v3.slot-table",
              L    = 32)

slot_table_mac = HMAC-SHA-256(
              key  = K_table,
              msg  = core_header            (24 bytes, §3)
                   ‖ slot_count             (1 byte)
                   ‖ slot_record[0]         (slot_len bytes)
                   ‖ ...
                   ‖ slot_record[n-1])
```

Whole records, not just prefixes. The wrapped key and its tag are already
authenticated by the slot itself, so including them adds no cryptographic
strength — it adds simplicity. "Every byte of the table, in order" is a rule
with no edge cases, and it pins slot order as a side effect.

HKDF with an empty salt and an ASCII `info`, matching every other derivation in
this format (v2 §4.1). The `info` string differs from all of v2's, so `K_table`
cannot collide with a payload key, a slot key, or a PRF salt.

### 5.2 Verification: report, do not refuse

A reader MUST verify `slot_table_mac` after recovering the master key and
before returning the plaintext. On mismatch the reader **MUST still return the
plaintext**, and **MUST report that the slot table is not authentic.**

Refusing would be the wrong trade. The payload is intact and independently
authenticated; a container whose MAC does not match is one whose *recovery
options* have changed, not one whose data is suspect. Refusing to open it would
convert a detectable tampering into a lost backup, which is the more severe
outcome and the one this project consistently declines to cause.

This is the single exception to §6's generic-error rule, and it does not leak.
The check runs only *after* a secret has already unwrapped a slot, so reaching
it at all proves the caller holds valid key material. There is no oracle: an
attacker who cannot open the container never sees this result.

The report MUST NOT claim to say which slot was removed. It cannot: the MAC
covers the table as a whole, and the sealed table is not recoverable from the
tampered one. "The slot table has changed since this backup was created" is the
whole of what is known.

### 5.3 Enrolment and revocation

Adding or removing a slot:

1. Unwrap the master key through any one slot the actor holds a secret for.
2. Rewrite the slot table.
3. Recompute `slot_table_mac` over the new table.
4. Leave `container_id` and the payload untouched.

No other slot is re-wrapped, and the payload is not re-encrypted. This is what
keeps §1.2's property true, and it means authorised revocation and unauthorised
stripping produce different files: the first carries a valid MAC, the second
does not.

An implementation that cannot recompute the MAC — because it holds no slot
secret — MUST NOT write a slot table at all. There is no partial edit.

---

## 6. Migration

- A v3 reader MUST open v1, v2 and v3 containers. Version dispatch on byte 4 is
  unchanged.
- A v2 reader encountering version `0x03` MUST reject it as an unknown version,
  which v2's existing bounds check already does.
- Writers SHOULD emit v3. Nothing forces a rewrite of existing backups: a v2
  container remains readable indefinitely, and the §1.1 attack against it
  remains possible. That is a deliberate acceptance — silently re-encrypting
  someone's archive to fix a detection gap would be a larger risk than the gap.
- There is no in-place upgrade. Moving a v2 backup to v3 means decrypting and
  re-encrypting it, which is a user's decision and needs their secret.

---

## 7. What this does not fix

- **A v2 container is still strippable.** v3 protects containers written as v3.
- **Deletion.** An attacker who can write the file can also truncate or delete
  it. v3 makes *silent* modification detectable; it does not make the file
  durable. Backups in more than one place remain the answer to that.
- **Tampering before the first read.** The MAC is checked when the container is
  opened. If a slot is stripped and the owner never opens the backup again, the
  detection never fires. It fires for the person doing the recovery, which is
  when it matters most and also when it is least actionable — see §5.2.
- **Metadata confidentiality.** `cipher_id`, `slot_count`, each slot's type and
  KDF cost parameters, and now `container_id`, are all readable without any
  secret. v3 authenticates the header; it does not hide it.
- **Padding.** v2 §8 defers the length leak — container length still determines
  plaintext length byte for byte — to "a v3 question". This v3 does not answer
  it. A padding scheme is its own design with its own trade-offs, and bundling
  it with an authentication fix would make both harder to review; that is the
  same reasoning v2 used to defer it in the first place. It stays open, and
  bumping the version here does not close it.

---

## 8. Test vectors

Produced by `reference/keym2.py` (phase 2). The TypeScript core must reproduce
this container **byte for byte** from the same inputs; that is the check that
catches a header-layout or MAC-construction disagreement, and round-tripping is
not a substitute for it — two writers can decode each other's output happily
while disagreeing about how to write it.

Test-only credentials. Never use any of these values for real data: a pinned
salt and a pinned master key reuse every (key, nonce) pair in the container.

**Inputs**

| field | value |
|---|---|
| password | `correct horse battery staple — test only` (UTF-8, NFC) |
| plaintext | `Keymaker fixture - KEYM v3 / argon2id / aes-256-gcm` (51 bytes, ASCII) |
| `cipher_id` | `0x00` (AES-256-GCM) |
| KDF | Argon2id, `t=3`, `m=65536` KiB, `p=4` |
| slot salt | `00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff` |
| master key | `404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f` |
| `container_id` | `0123456789abcdef0123456789abcdef` |
| slots | one, `slot_type = 0x00` |

**Intermediates** — worth checking on their own, because a container that
differs only in its last 32 bytes has a MAC bug and a container that differs
earlier has a header bug, and the two are diagnosed differently.

```
core_header    4b45594d030000000123456789abcdef0123456789abcdef
K_table        351351be1b09b978ae98feede32b49f98af1acd365aeda6943178985395e7cf6
slot_table_mac 5ff0c0fb11b44058abe6be48b590178d0752bc88f0f3954de69c98a68007c418
```

`core_header` reads as `KEYM` ‖ `03` ‖ `00` (AES) ‖ `00` (flags) ‖ `00`
(reserved) ‖ the 16-byte `container_id`, which is §3's layout with nothing
elided.

**Container** — 220 bytes: 24 core header, 1 `slot_count`, 32 MAC, 96 slot
(48 prefix + 32 wrapped key + 16 tag), 67 payload (51 plaintext + 16 tag).

```
4b45594d030000000123456789abcdef0123456789abcdef015ff0c0fb11b440
58abe6be48b590178d0752bc88f0f3954de69c98a68007c41800010000000000
0000112233445566778899aabbccddeeff00112233445566778899aabbccddee
ff00030001000004008e7b9e001250f449d30882f58e5d93c85bb8a8e6459ea5
8ebba4ecc919f86d5c86811a5e72ed5e5b7f66708362672c51f8cb0a5cf3cd81
3330ece0b1f8961f08f3750ad2414b298413cc7e6e30ae646ca833cfd9c4d76d
55180fb835a8d743ab2900b4543989f311892569c7f62c755f03c23e
```

Both implementations are held to these bytes by `reference/crosstest2.py`, and
the frozen corpus under `scripts/fixtures/keymaker/` carries thirteen v3 vectors
alongside v2's — including one whose slot table was stripped, which §5.2 requires
to open and to be reported. `scripts/keymaker-generate-fixtures.mts` writes them
and skips any that already exist, so the corpus only ever grows.
