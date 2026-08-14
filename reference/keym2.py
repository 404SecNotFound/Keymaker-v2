#!/usr/bin/env python3
"""
Independent reference implementation of the **KEYM v2** container format.

Written from ``docs/FORMAT-V2-DESIGN.md`` alone — which is the entire point of
it. The v1 reference caught KM-14 this way: the specification documented the KDF
cost parameters and never said to bound them, so an implementer working
faithfully from the prose reproduced a vulnerability the TypeScript had already
fixed. The document was the defect.

So this file is not a port. Nothing here was read off an implementation, and
where the specification failed to determine the bytes, that is recorded as a
finding rather than resolved by looking at what some other code happens to do.

  Reading order for a reviewer:
    §A  what the specification did not pin down  (the findings)
    §B  constants and bounds
    §C  core header and slot table
    §D  key derivation and the envelope
    §E  payload
    §F  slot mutation
    §G  armor and format detection
    §H  CLI and self-test

Two dependencies, pinned in requirements.txt, both for primitives only:
``cryptography`` and ``argon2-cffi``. Every format decision is in this file.


================================================================================
§A  WHAT THE SPECIFICATION DID NOT PIN DOWN
================================================================================

Six gaps across two passes. A1–A4 came from the first draft of the document.
A5–A6 came from the multi-slot amendment (document §4) and are new; they are
recorded in the document as F6 and F7.

Only A1 can make two conforming implementations disagree on the bytes, and it is
the reason this exercise exists.

--------------------------------------------------------------------------------
A1. BLOCKING — the chunk count for a plaintext that is an exact multiple of the
    chunk size is not determined.

§5.1 says the plaintext is split into chunks "of exactly 1 MiB ... except the
last, which holds 0 to 1,048,576 bytes". For a plaintext of exactly 1,048,576
bytes, both of these satisfy that sentence:

    (a) one chunk carrying 1,048,576 bytes, final_flag = 1
    (b) one full chunk (final_flag = 0) then an empty chunk (final_flag = 1)

They differ in length by 16 bytes (32 chained) and in every nonce after the
first. Two conforming writers therefore produce different containers for the
same input, which breaks the cross-implementation byte-equality check the
project relies on.

Note the decoder is *not* ambiguous: both forms parse, unambiguously, to the
same plaintext (see ``_chunk_layout``). This is a writer-side gap only, which is
what makes it easy to miss — a round-trip test inside one implementation passes
either way.

    RESOLVED HERE AS (a): the fewest chunks that can hold the plaintext,
    i.e. ``max(1, ceil(n / CHUNK_SIZE))``. The document now says so.

--------------------------------------------------------------------------------
A2. MINOR — the armor prefix's case sensitivity is not stated.

§7's whole argument is that one byte at offset 0 distinguishes armor from the
binary magic: lowercase ``k`` (0x6B) versus ``K`` (0x4B). A reader that accepted
``KEYM2:`` case-insensitively would reintroduce precisely the collision the
section exists to remove, and would do so while believing it was being helpful.

    RESOLVED HERE AS: byte-exact, case-sensitive ``keym2:``. See ``dearmor``.

--------------------------------------------------------------------------------
A3. MINOR — "Bit 0" is not defined as least- or most-significant.

Inherited from FORMAT.md §4, which does the same. Universally read as LSB-first,
but a specification that turns on rejecting non-zero reserved bits should say
which bits those are.

    RESOLVED HERE AS: bit 0 is the least significant bit, value 0x01.

--------------------------------------------------------------------------------
A4. MINOR — the character encoding of the context strings is not stated.

§4.1 writes ``LP("keymaker.v2.kdf-input")`` without saying how the literal
becomes bytes, while the password in the same expression *is* given an explicit
encoding ("NFC_UTF8"), which invites the reader to wonder whether the omission
next to it is meaningful.

    RESOLVED HERE AS: ASCII, byte-identical to UTF-8 for these literals.

--------------------------------------------------------------------------------
A5. SUBSTANTIVE (new; document F6) — "no slot it implements" is the wrong
    rejection condition, and the document states it twice in incompatible ways.

§6 requires a reader to "reject a container in which no slot carries a
``slot_type`` it implements". But §6 also says bounds apply per slot, and that a
slot whose parameters are out of bounds is "unusable, which is the same outcome
as a slot whose secret the reader does not hold".

Those two sentences disagree about a container holding exactly one slot, of type
0x00, with ``memory_kib`` above the cap. Its type *is* implemented, so the first
sentence does not reject it — but it cannot be attempted either, so the reader
reaches the end of the slot table with no master key and no rule telling it what
to do.

    RESOLVED HERE AS: the condition is **no slot the reader can attempt**, which
    subsumes both unknown types and unusable parameters. A reader fails when the
    slot table is exhausted without a master key, whatever the reason each
    individual slot was passed over. See ``decrypt``.

    The document is corrected to state the exhaustion rule once, rather than
    stating a proxy for it in two places that disagree at the edges.

--------------------------------------------------------------------------------
A6. SUBSTANTIVE (new; document F7) — whether a skipped slot's reserved fields
    must still be rejected is unstated, and the two plausible answers have
    opposite forward-compatibility consequences.

§3.3 says reserved fields MUST be rejected when non-zero. §4.4 says a reader
MUST skip a slot whose ``slot_type`` it does not implement. Neither says which
rule wins for the reserved bytes *inside* a slot that is being skipped.

It matters, and not subtly. If a reader validates the internals of slots it
skips, then any future slot type that gives meaning to a currently-reserved byte
makes every container carrying one unopenable by every reader shipped before it
— including through its own passphrase slot, which is untouched and valid. That
is the exact data-loss outcome §4.4's skip rule exists to prevent, reintroduced
by a rule from a different section.

    RESOLVED HERE AS: **a reader validates only the slots it attempts.** A
    skipped slot is checked for nothing but the space it occupies. This is safe
    because a slot that is never attempted cannot contribute to the master key
    or to the payload — it is inert bytes inside a length the reader already
    knows.

    §3.3's argument survives unchanged for every slot that is attempted, which
    is the only place it was ever doing work.

--------------------------------------------------------------------------------
Not a defect, but worth a sentence in the document: ``keyfile_digest``
concatenates without a length prefix, in a section whose subject is that
unprefixed concatenation is ambiguous. It is fine — the prefix is a fixed
constant, so ``k -> "keymaker.v2.keyfile" || k`` is injective — but every
careful reader will stop on it.

Also not a defect, but worth knowing: this reader stops at the first slot that
unwraps. The document does not require it to, and the alternative (attempt every
slot regardless) would hide *which* slot matched from an observer timing the
unlock. Stopping early is chosen because eight Argon2id invocations to open a
file that opened on the first one is not a cost worth paying to conceal an index
from someone who is already holding the container.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import math
import os
import struct
import sys
import unicodedata
from dataclasses import dataclass
from typing import Optional

from argon2.low_level import Type as Argon2Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# =============================================================================
# §B  CONSTANTS AND BOUNDS
# =============================================================================

MAGIC = b"KEYM"
VERSION = 2

# §3. The header is in two parts and the split is load-bearing (§5.3): the core
# header is authenticated by the payload, each slot prefix by its own wrap, and
# slot_count by neither.
CORE_HEADER_LEN = 8      # bytes [0, 8) — the payload AAD
SLOT_COUNT_OFFSET = 8
SLOT_TABLE_OFFSET = 9

SLOT_PREFIX_LEN = 48     # §4.4, bytes [0, 48) of a slot
SLOT_SALT_OFFSET = 8     # within the slot
SLOT_PARAMS_OFFSET = 40  # within the slot

SALT_LEN = 32            # §4.4, both KDFs
KDF_PARAM_LEN = 8        # §3.2
MASTER_KEY_LEN = 32      # §4.3
SLOT_KEY_LEN = 32        # §4.3
NONCE_LEN = 12           # §5.2, uint88 counter || flag byte
TAG_LEN = 16             # AES-GCM and Poly1305 alike

# §6. Bounded by a constant of the format, never by another field.
SLOT_COUNT_MIN, SLOT_COUNT_MAX = 1, 8

# §5.1. A constant of the format, deliberately not a header field: a header
# field would be an attacker-controlled allocation size read before
# authentication.
CHUNK_SIZE = 1024 * 1024

KDF_PBKDF2 = 0x00
KDF_ARGON2ID = 0x01
CIPHER_AES = 0x00
CIPHER_CHACHA = 0x01
CIPHER_CHAINED = 0x02

# §4.4. Only 0x00 is implemented; 0x01 and 0x02 are reserved for Phase 4 and
# their wire layouts are deliberately unspecified until something implements
# them. A reader skips what it does not implement (§4.4, finding A6).
SLOT_TYPE_PASSPHRASE = 0x00
SLOT_TYPE_PASSKEY_PRF = 0x01     # reserved, unimplemented
SLOT_TYPE_SHAMIR = 0x02          # reserved, unimplemented
IMPLEMENTED_SLOT_TYPES = frozenset({SLOT_TYPE_PASSPHRASE})

# §3.3. The container flags byte is entirely reserved now; the key-file hint
# moved to slot_flags, because it describes a slot and not a container.
CORE_FLAGS_RESERVED_MASK = 0xFF
SLOT_FLAG_KEYFILE = 0x01         # §4.4 bit 0 — see finding A3
SLOT_FLAGS_RESERVED_MASK = 0xFE

# §4.3. Constant, and deliberately not the slot index: binding a wrap to its
# position would mean removing a slot forces every later slot to be re-wrapped,
# and re-wrapping needs that slot's secret. The 0xFF final byte puts it outside
# §5.2's nonce space, where every payload nonce ends in 0x00 or 0x01.
WRAP_NONCE = (0).to_bytes(11, "big") + b"\xff"

ARMOR_PREFIX = b"keym2:"  # §7 — case-sensitive, see finding A2

# §4.1 / §4.3 domain separation. ASCII, see finding A4.
CTX_KDF_INPUT = b"keymaker.v2.kdf-input"
CTX_KEYFILE = b"keymaker.v2.keyfile"
INFO_AES = b"keymaker-v2-aes"
INFO_CHACHA = b"keymaker-v2-chacha"
INFO_SLOT_AES = b"keymaker-v2-slot-aes"
INFO_SLOT_CHACHA = b"keymaker-v2-slot-chacha"

# §6. Upper bounds are the security control and are enforced on read; lower
# bounds are policy for new containers only, so that files written with older or
# lower settings still open.
PBKDF2_ITER_MIN, PBKDF2_ITER_MAX = 1, 10_000_000
PBKDF2_ITER_POLICY_MIN = 600_000
ARGON2_TIME_MIN, ARGON2_TIME_MAX = 1, 10
ARGON2_MEM_MIN, ARGON2_MEM_MAX = 1, 262_144
ARGON2_MEM_POLICY_MIN = 8_192
ARGON2_PAR_MIN, ARGON2_PAR_MAX = 1, 8


class KeymError(Exception):
    """
    Every rejection, with one message.

    §6: "report every rejection as an ordinary decryption failure, with no
    detail that distinguishes which check failed." A caller cannot learn whether
    the password was wrong, a reserved bit was set, or the payload length was
    malformed — the string is fixed at the raise site below and the reason never
    reaches it.
    """


DECRYPT_FAILED = "decryption failed"


def _reject() -> "KeymError":
    return KeymError(DECRYPT_FAILED)


class UsageError(Exception):
    """Caller error — bad CLI arguments, a policy violation when writing.

    Deliberately distinct from KeymError: refusing to *write* a container with a
    5-iteration PBKDF2 is a message to the operator, not an oracle for an
    attacker holding someone else's file.
    """


def tag_overhead(cipher_id: int) -> int:
    """Bytes of tag per AEAD invocation. §5.1: 16, or 32 for chained."""
    return TAG_LEN * 2 if cipher_id == CIPHER_CHAINED else TAG_LEN


def slot_len(cipher_id: int) -> int:
    """§3. 48-byte prefix + the wrapped master key and its tag(s)."""
    return SLOT_PREFIX_LEN + MASTER_KEY_LEN + tag_overhead(cipher_id)


# =============================================================================
# §C  CORE HEADER AND SLOT TABLE
# =============================================================================

@dataclass(frozen=True)
class CoreHeader:
    """§3, bytes [0, 8). The payload AAD, and the only part every AEAD
    invocation in the container agrees on."""

    cipher_id: int
    flags: int = 0

    @property
    def tag_overhead(self) -> int:
        return tag_overhead(self.cipher_id)

    def pack(self) -> bytes:
        out = MAGIC + bytes([VERSION, self.cipher_id, self.flags, 0])
        assert len(out) == CORE_HEADER_LEN
        return out


@dataclass(frozen=True)
class Slot:
    """§4.4, a parsed and fully bounds-checked slot.

    As with the v1 reference's Header, parsing *is* validation: there is no way
    to obtain a Slot whose KDF parameters have not been bounded, so no caller
    can forget to check them before deriving. That is the structural answer to
    KM-14.
    """

    slot_type: int
    kdf_id: int
    slot_flags: int
    salt: bytes
    wrapped_key: bytes
    # PBKDF2
    iterations: int = 0
    # Argon2id
    time_cost: int = 0
    memory_kib: int = 0
    parallelism: int = 0

    @property
    def keyfile_used(self) -> bool:
        return bool(self.slot_flags & SLOT_FLAG_KEYFILE)

    def pack_prefix(self) -> bytes:
        if self.kdf_id == KDF_PBKDF2:
            params = struct.pack(">I4x", self.iterations)
        elif self.kdf_id == KDF_ARGON2ID:
            params = struct.pack(">HIBx", self.time_cost, self.memory_kib, self.parallelism)
        else:
            raise UsageError(f"unknown kdf_id {self.kdf_id}")
        assert len(params) == KDF_PARAM_LEN
        out = bytes([self.slot_type, self.kdf_id, self.slot_flags]) + b"\x00" * 5 \
            + self.salt + params
        assert len(out) == SLOT_PREFIX_LEN
        return out

    def pack(self) -> bytes:
        return self.pack_prefix() + self.wrapped_key


def parse_core_header(data: bytes) -> CoreHeader:
    """
    §3 and §6, everything that can be checked before the slot table is located.

    Every check here runs before any KDF is invoked, and before a single byte is
    allocated on the strength of something the container claims.
    """
    if len(data) < SLOT_TABLE_OFFSET:
        raise _reject()
    if data[:4] != MAGIC:
        raise _reject()
    if data[4] != VERSION:
        raise _reject()

    cipher_id = data[5]
    flags = data[6]

    if cipher_id not in (CIPHER_AES, CIPHER_CHACHA, CIPHER_CHAINED):
        raise _reject()
    # §3.3 — the container flags byte is entirely reserved since the slot
    # amendment; the key-file hint lives in slot_flags now.
    if flags & CORE_FLAGS_RESERVED_MASK:
        raise _reject()
    if data[7] != 0:  # §3 reserved
        raise _reject()

    return CoreHeader(cipher_id=cipher_id, flags=flags)


def parse_container(data: bytes) -> tuple[CoreHeader, list[bytes], bytes]:
    """
    Split a container into (core header, raw slot records, payload).

    Slot *contents* are deliberately not parsed here — see finding A6. A reader
    validates only the slots it attempts, because validating a slot it is going
    to skip would let a future slot type make old readers reject containers they
    could otherwise open through a perfectly valid passphrase slot.

    What is checked here is structural and applies to every container: the
    declared slot count is in range, and the container is long enough to hold
    the slot table plus the smallest possible payload.
    """
    core = parse_core_header(data)

    slot_count = data[SLOT_COUNT_OFFSET]
    if not (SLOT_COUNT_MIN <= slot_count <= SLOT_COUNT_MAX):
        raise _reject()

    width = slot_len(core.cipher_id)
    payload_offset = SLOT_TABLE_OFFSET + slot_count * width

    # §6: shorter than payload_offset plus the minimum payload for one chunk.
    # The minimum chunk is zero plaintext bytes and its tag(s).
    if len(data) < payload_offset + core.tag_overhead:
        raise _reject()

    slots = [
        data[SLOT_TABLE_OFFSET + i * width: SLOT_TABLE_OFFSET + (i + 1) * width]
        for i in range(slot_count)
    ]
    return core, slots, data[payload_offset:]


def parse_slot(record: bytes) -> Slot:
    """
    §4.4 and §6, for one slot. Raises rather than returning None so that the
    bounds checks read the same way the v1 reference's do.

    Callers that are walking the slot table use ``_attemptable`` instead, which
    turns a rejection into "skip this one" — per finding A5, an unusable slot
    and an unknown slot type have the same consequence for the reader.
    """
    if len(record) < SLOT_PREFIX_LEN:
        raise _reject()

    slot_type = record[0]
    kdf_id = record[1]
    slot_flags = record[2]
    salt = record[SLOT_SALT_OFFSET:SLOT_SALT_OFFSET + SALT_LEN]
    params = record[SLOT_PARAMS_OFFSET:SLOT_PARAMS_OFFSET + KDF_PARAM_LEN]
    wrapped_key = record[SLOT_PREFIX_LEN:]

    if slot_type not in IMPLEMENTED_SLOT_TYPES:
        raise _reject()
    if record[3:8] != b"\x00" * 5:          # §4.4 reserved
        raise _reject()
    if slot_flags & SLOT_FLAGS_RESERVED_MASK:  # §4.4 reserved bits
        raise _reject()

    if kdf_id == KDF_PBKDF2:
        (iterations,) = struct.unpack(">I", params[:4])
        if params[4:] != b"\x00\x00\x00\x00":   # §3.2 reserved
            raise _reject()
        if not (PBKDF2_ITER_MIN <= iterations <= PBKDF2_ITER_MAX):
            raise _reject()
        return Slot(slot_type, kdf_id, slot_flags, salt, wrapped_key,
                    iterations=iterations)

    if kdf_id == KDF_ARGON2ID:
        time_cost, memory_kib, parallelism = struct.unpack(">HIB", params[:7])
        if params[7] != 0:                      # §3.2 reserved
            raise _reject()
        if not (ARGON2_TIME_MIN <= time_cost <= ARGON2_TIME_MAX):
            raise _reject()
        if not (ARGON2_MEM_MIN <= memory_kib <= ARGON2_MEM_MAX):
            raise _reject()
        if not (ARGON2_PAR_MIN <= parallelism <= ARGON2_PAR_MAX):
            raise _reject()
        return Slot(slot_type, kdf_id, slot_flags, salt, wrapped_key,
                    time_cost=time_cost, memory_kib=memory_kib,
                    parallelism=parallelism)

    raise _reject()


def _attemptable(record: bytes) -> Optional[Slot]:
    """Finding A5: unknown type and out-of-bounds parameters are the same
    outcome — this slot cannot be tried. Neither condemns the container."""
    try:
        return parse_slot(record)
    except KeymError:
        return None


def check_write_policy(slot: Slot) -> None:
    """§6's lower bounds. Writing only — a reader stays permissive."""
    if slot.kdf_id == KDF_PBKDF2 and slot.iterations < PBKDF2_ITER_POLICY_MIN:
        raise UsageError(
            f"refusing to write PBKDF2 with {slot.iterations} iterations; "
            f"policy minimum is {PBKDF2_ITER_POLICY_MIN}"
        )
    if slot.kdf_id == KDF_ARGON2ID and slot.memory_kib < ARGON2_MEM_POLICY_MIN:
        raise UsageError(
            f"refusing to write Argon2id with memory_kib={slot.memory_kib}; "
            f"policy minimum is {ARGON2_MEM_POLICY_MIN}"
        )


# =============================================================================
# §D  KEY DERIVATION AND THE ENVELOPE
# =============================================================================

def lp(x: bytes) -> bytes:
    """§4.1 ``LP(x) = uint32_be(len(x)) || x``."""
    return struct.pack(">I", len(x)) + x


def keyfile_digest(keyfile_bytes: bytes) -> bytes:
    """
    §4.2. 32 bytes regardless of the key file's size — this is what makes a
    large key file free, and it is the half of KM-05 that the length prefixes
    alone do not solve.
    """
    return hashlib.sha256(CTX_KEYFILE + keyfile_bytes).digest()


def build_kdf_input(password: str, keyfile_bytes: Optional[bytes]) -> bytes:
    """
    §4.1, the slot secret for ``slot_type = 0x00``. Injective over
    ``(password, key file)`` pairs.

    v1 used ``password_bytes || keyfile_bytes``, under which ("ab", "c") and
    ("a", "bc") are the same KDF input. Length prefixes remove that.

    "No key file" is ``LP(b"")`` rather than an omitted field — one shape, one
    code path, and the absent case explicitly encoded rather than implied. It
    cannot collide with a present-but-empty key file: that hashes to 32 bytes,
    and SHA-256 never outputs zero of them.
    """
    normalized = unicodedata.normalize("NFC", password).encode("utf-8")
    digest = keyfile_digest(keyfile_bytes) if keyfile_bytes is not None else b""
    return lp(CTX_KDF_INPUT) + lp(normalized) + lp(digest)


def derive_slot_key(slot: Slot, kdf_input: bytes) -> bytes:
    """§4.3. Assumes `slot` came from parse_slot, i.e. is already bounded."""
    if slot.kdf_id == KDF_PBKDF2:
        return PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=SLOT_KEY_LEN,
            salt=slot.salt,
            iterations=slot.iterations,
        ).derive(kdf_input)

    if slot.kdf_id == KDF_ARGON2ID:
        return hash_secret_raw(
            secret=kdf_input,
            salt=slot.salt,
            time_cost=slot.time_cost,
            memory_cost=slot.memory_kib,
            parallelism=slot.parallelism,
            hash_len=SLOT_KEY_LEN,
            type=Argon2Type.ID,
            version=0x13,  # RFC 9106 / Argon2 v1.3
        )

    raise _reject()


def _expand(cipher_id: int, key: bytes, info_aes: bytes,
            info_chacha: bytes) -> tuple[bytes, bytes]:
    """
    §4.3. For chained mode, two independent 32-byte subkeys.

    "Zero salt" is passed explicitly rather than as ``salt=None``. The two are
    identical by construction — RFC 5869 substitutes HashLen zeros for an absent
    salt, and HMAC pads any short key with zeros to the block size, so an empty
    salt and a 32-zero-byte salt produce the same PRK — but writing it out means
    a second implementer does not have to work that out to be sure they match.
    """
    if cipher_id != CIPHER_CHAINED:
        return key, key

    def expand(info: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"\x00" * 32,
            info=info,
        ).derive(key)

    return expand(info_aes), expand(info_chacha)


def payload_keys(cipher_id: int, master_key: bytes) -> tuple[bytes, bytes]:
    """§4.3. The keys the chunks are sealed under."""
    return _expand(cipher_id, master_key, INFO_AES, INFO_CHACHA)


def wrap_keys(cipher_id: int, slot_key: bytes) -> tuple[bytes, bytes]:
    """
    §4.3. The keys one slot's wrap is sealed under.

    Distinct info strings from ``payload_keys``. A collision would need the slot
    key and the master key to be equal, and they cannot be — one is a KDF output
    and the other is CSPRNG — but separating them costs nothing and means the
    property holds without needing that argument.
    """
    return _expand(cipher_id, slot_key, INFO_SLOT_AES, INFO_SLOT_CHACHA)


def slot_aad(core: CoreHeader, slot_prefix: bytes) -> bytes:
    """
    §5.3 ``slot_aad_j = core header || slot j's prefix``.

    Both halves are contiguous ranges of real container bytes, which is
    deliberate: an AAD assembled out of fields a reader has to reconstruct is an
    AAD two implementations can quietly disagree about.

    ``slot_count`` is not here, and not in the payload AAD either. §5.3 explains
    why — including it would mean adding a slot invalidates every other slot's
    wrap, and re-wrapping those requires their secrets.
    """
    if len(slot_prefix) != SLOT_PREFIX_LEN:
        raise _reject()
    return core.pack() + slot_prefix


def wrap_master_key(core: CoreHeader, slot_prefix: bytes, slot_key: bytes,
                    master_key: bytes) -> bytes:
    """§4.3. Seal the master key under one slot's key."""
    aes_key, chacha_key = wrap_keys(core.cipher_id, slot_key)
    return _seal(core.cipher_id, aes_key, chacha_key, WRAP_NONCE,
                 master_key, slot_aad(core, slot_prefix))


def unwrap_master_key_from_slot(core: CoreHeader, record: bytes, slot: Slot,
                                kdf_input: bytes) -> Optional[bytes]:
    """
    §4.3, one slot's attempt. None means "this slot did not open it", which is
    not yet a failure — the caller tries the next one.
    """
    slot_key = derive_slot_key(slot, kdf_input)
    aes_key, chacha_key = wrap_keys(core.cipher_id, slot_key)
    try:
        master = _open(core.cipher_id, aes_key, chacha_key, WRAP_NONCE,
                       slot.wrapped_key, slot_aad(core, record[:SLOT_PREFIX_LEN]))
    except KeymError:
        return None
    if len(master) != MASTER_KEY_LEN:
        return None
    return master


# =============================================================================
# §E  PAYLOAD
# =============================================================================

def nonce_for(index: int, is_final: bool) -> bytes:
    """
    §5.2 ``nonce_i = uint88_be(i) || final_flag``.

    11 bytes of counter and one flag byte. The counter cannot overflow within
    any container this implementation will accept: 2^88 chunks of 1 MiB is
    2^108 bytes, so the checklist's "no counter overflow reachable" holds by an
    enormous margin rather than by an argument.

    Deterministic counter nonces are safe because the payload key is per
    container: the master key is fresh CSPRNG for every container (§4.5), so no
    (key, nonce) pair is ever reused. Before the slot amendment this rested on
    the salt being fresh instead — see the document's §11.1.
    """
    if index < 0 or index >= (1 << 88):
        raise _reject()
    return index.to_bytes(11, "big") + (b"\x01" if is_final else b"\x00")


def _chunk_layout(payload_len: int, tag: int) -> list[int]:
    """
    Recover the plaintext length of each chunk from the payload length alone.

    §6: "reject a payload whose length is not a valid chunk sequence for the
    declared cipher's tag overhead."

    A payload is chunks 0..m-1, m >= 1, where chunks 0..m-2 each carry
    CHUNK_SIZE plaintext bytes and chunk m-1 carries r, 0 <= r <= CHUNK_SIZE:

        payload_len = (m-1) * (CHUNK_SIZE + tag) + r + tag

    so with ``q, rem = divmod(payload_len - tag, CHUNK_SIZE + tag)`` we get
    m-1 = q and r = rem, valid exactly when rem <= CHUNK_SIZE. A remainder in
    (CHUNK_SIZE, CHUNK_SIZE + tag) is a truncated or padded payload.

    This parse accepts both encodings described in finding A1, and does so
    unambiguously — which is why A1 is a writer-side gap that a round-trip test
    inside a single implementation cannot detect.
    """
    if payload_len < tag:
        raise _reject()
    q, rem = divmod(payload_len - tag, CHUNK_SIZE + tag)
    if rem > CHUNK_SIZE:
        raise _reject()
    return [CHUNK_SIZE] * q + [rem]


def _split_plaintext(plaintext: bytes) -> list[bytes]:
    """
    §5.1, resolved per finding A1: the fewest chunks that can hold it.

    A zero-length plaintext is one chunk of zero bytes; a plaintext that is a
    positive multiple of CHUNK_SIZE ends with a *full* final chunk and no empty
    trailing chunk.
    """
    if not plaintext:
        return [b""]
    count = math.ceil(len(plaintext) / CHUNK_SIZE)
    return [plaintext[i * CHUNK_SIZE:(i + 1) * CHUNK_SIZE] for i in range(count)]


def _seal(cipher_id: int, aes_key: bytes, chacha_key: bytes,
          nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """§5.4. Chained is AES inner, ChaCha outer — both under the same nonce,
    which is not a reuse because the keys are independently derived."""
    if cipher_id == CIPHER_AES:
        return AESGCM(aes_key).encrypt(nonce, plaintext, aad)
    if cipher_id == CIPHER_CHACHA:
        return ChaCha20Poly1305(chacha_key).encrypt(nonce, plaintext, aad)
    inner = AESGCM(aes_key).encrypt(nonce, plaintext, aad)
    return ChaCha20Poly1305(chacha_key).encrypt(nonce, inner, aad)


def _open(cipher_id: int, aes_key: bytes, chacha_key: bytes,
          nonce: bytes, blob: bytes, aad: bytes) -> bytes:
    """§5.4. Chained verifies the outer layer before the inner one."""
    try:
        if cipher_id == CIPHER_AES:
            return AESGCM(aes_key).decrypt(nonce, blob, aad)
        if cipher_id == CIPHER_CHACHA:
            return ChaCha20Poly1305(chacha_key).decrypt(nonce, blob, aad)
        inner = ChaCha20Poly1305(chacha_key).decrypt(nonce, blob, aad)
        return AESGCM(aes_key).decrypt(nonce, inner, aad)
    except KeymError:
        raise
    except Exception:
        raise _reject() from None


def build_passphrase_slot(
    core: CoreHeader,
    master_key: bytes,
    password: str,
    *,
    kdf_id: int = KDF_ARGON2ID,
    keyfile_bytes: Optional[bytes] = None,
    iterations: int = 1_000_000,
    time_cost: int = 3,
    memory_kib: int = 65_536,
    parallelism: int = 4,
    salt: Optional[bytes] = None,
    enforce_write_policy: bool = True,
) -> bytes:
    """
    §4.3 / §4.4. Build one ``slot_type = 0x00`` record wrapping ``master_key``.

    The prefix is built first because it is part of its own wrap's AAD (§5.3),
    so the bytes have to exist before the seal that authenticates them.
    """
    if salt is None:
        salt = os.urandom(SALT_LEN)
    if len(salt) != SALT_LEN:
        raise UsageError("slot salt must be 32 bytes")
    if len(master_key) != MASTER_KEY_LEN:
        raise UsageError("master key must be 32 bytes")

    draft = Slot(
        slot_type=SLOT_TYPE_PASSPHRASE,
        kdf_id=kdf_id,
        slot_flags=SLOT_FLAG_KEYFILE if keyfile_bytes is not None else 0,
        salt=salt,
        wrapped_key=b"",
        iterations=iterations,
        time_cost=time_cost,
        memory_kib=memory_kib,
        parallelism=parallelism,
    )
    if enforce_write_policy:
        check_write_policy(draft)

    prefix = draft.pack_prefix()
    # Round-trip the prefix through the reader's own validator before using it.
    # A writer that can emit a slot its own parser rejects is a bug worth
    # catching here rather than in a user's hands.
    parse_slot(prefix + b"\x00" * (MASTER_KEY_LEN + core.tag_overhead))

    slot_key = derive_slot_key(draft, build_kdf_input(password, keyfile_bytes))
    return prefix + wrap_master_key(core, prefix, slot_key, master_key)


def assemble(core: CoreHeader, slots: list[bytes], payload: bytes) -> bytes:
    """§3. Core header, slot count, slot table, payload."""
    if not (SLOT_COUNT_MIN <= len(slots) <= SLOT_COUNT_MAX):
        raise UsageError(f"slot_count must be {SLOT_COUNT_MIN}..{SLOT_COUNT_MAX}")
    width = slot_len(core.cipher_id)
    for record in slots:
        if len(record) != width:
            raise UsageError("slot record has the wrong width for this cipher")
    return core.pack() + bytes([len(slots)]) + b"".join(slots) + payload


def encrypt_payload(core: CoreHeader, master_key: bytes, plaintext: bytes) -> bytes:
    """§5. The chunk sequence, sealed under the master key."""
    aes_key, chacha_key = payload_keys(core.cipher_id, master_key)
    aad = core.pack()
    chunks = _split_plaintext(plaintext)
    out = []
    for i, chunk in enumerate(chunks):
        out.append(_seal(core.cipher_id, aes_key, chacha_key,
                         nonce_for(i, i == len(chunks) - 1), chunk, aad))
    return b"".join(out)


def encrypt(
    plaintext: bytes,
    password: str,
    *,
    kdf_id: int = KDF_ARGON2ID,
    cipher_id: int = CIPHER_AES,
    keyfile_bytes: Optional[bytes] = None,
    iterations: int = 1_000_000,
    time_cost: int = 3,
    memory_kib: int = 65_536,
    parallelism: int = 4,
    salt: Optional[bytes] = None,
    master_key: Optional[bytes] = None,
    enforce_write_policy: bool = True,
) -> bytes:
    """
    Write a single-slot v2 container.

    ``salt`` and ``master_key`` exist for cross-implementation byte comparison
    and nothing else. §4.5 forbids caller-supplied values for either in any
    interface meant for real data: reusing a master key reuses every (key,
    nonce) pair in the container, which for an AEAD means recoverable plaintext
    and forgeable tags. The CLI exposes them behind ``--salt`` / ``--master-key``
    with the same warning.
    """
    core = CoreHeader(cipher_id=cipher_id)
    if cipher_id not in (CIPHER_AES, CIPHER_CHACHA, CIPHER_CHAINED):
        raise UsageError(f"unknown cipher_id {cipher_id}")

    if master_key is None:
        master_key = os.urandom(MASTER_KEY_LEN)
    elif len(master_key) != MASTER_KEY_LEN:
        raise UsageError("master key must be 32 bytes")

    record = build_passphrase_slot(
        core, master_key, password,
        kdf_id=kdf_id, keyfile_bytes=keyfile_bytes, iterations=iterations,
        time_cost=time_cost, memory_kib=memory_kib, parallelism=parallelism,
        salt=salt, enforce_write_policy=enforce_write_policy,
    )
    return assemble(core, [record], encrypt_payload(core, master_key, plaintext))


def recover_master_key(
    container: bytes,
    password: str,
    *,
    keyfile_bytes: Optional[bytes] = None,
) -> tuple[CoreHeader, list[bytes], bytes, bytes]:
    """
    Walk the slot table until one opens, returning everything the caller needs
    to either decrypt or rewrite the container.

    §4.4 and finding A5: a slot is passed over when its type is not implemented,
    when its parameters are out of bounds, or when its secret is not the one we
    hold. All three are the same event from here — this slot did not open it —
    and only exhausting the table is a failure.
    """
    core, records, payload = parse_container(container)
    kdf_input = build_kdf_input(password, keyfile_bytes)

    for record in records:
        slot = _attemptable(record)
        if slot is None:
            continue
        master = unwrap_master_key_from_slot(core, record, slot, kdf_input)
        if master is not None:
            return core, records, payload, master

    raise _reject()


def decrypt(
    container: bytes,
    password: str,
    *,
    keyfile_bytes: Optional[bytes] = None,
) -> bytes:
    """
    Decrypt a v2 container, or raise KeymError with a single generic message.

    §5.5's hazard is why this returns bytes rather than yielding them: "a prefix
    of verified chunks is not a verified prefix of the file". Nothing is
    returned until the final chunk has verified *and* carried final_flag, so a
    caller cannot accidentally treat 899 good chunks out of 900 as a result.
    """
    core, _records, payload, master = recover_master_key(
        container, password, keyfile_bytes=keyfile_bytes)

    tag = core.tag_overhead
    sizes = _chunk_layout(len(payload), tag)
    aes_key, chacha_key = payload_keys(core.cipher_id, master)
    aad = core.pack()

    out = []
    offset = 0
    last = len(sizes) - 1
    for i, size in enumerate(sizes):
        blob = payload[offset:offset + size + tag]
        if len(blob) != size + tag:
            raise _reject()
        offset += len(blob)
        # §5.2, normative: the last chunk consumed must carry final_flag = 1.
        #
        # Enforced by *construction* rather than by inspection — there is no
        # flag to read, only a nonce to get right. Chunk `last` is opened with
        # final_flag = 1, so a truncated container (whose surviving last chunk
        # was sealed with 0) fails authentication. Truncation exactly on a chunk
        # boundary is the case this catches that a length check cannot.
        out.append(_open(core.cipher_id, aes_key, chacha_key,
                         nonce_for(i, i == last), blob, aad))

    if offset != len(payload):
        raise _reject()
    return b"".join(out)


# =============================================================================
# §F  SLOT MUTATION
# =============================================================================
#
# The document's §4.3 and §5.3 both turn on one requirement: a slot table must
# be editable by someone holding exactly one slot's secret. It is why the wrap
# nonce is a constant rather than the slot index, and why slot_count is outside
# both AADs. A requirement that shapes two design decisions should be executed
# rather than asserted, so these three functions exist and the selftest uses
# them.
#
# Note what none of them need: any other slot's password, and any access to the
# payload. The payload bytes are copied through untouched.

def add_slot(
    container: bytes,
    unlock_password: str,
    new_password: str,
    *,
    unlock_keyfile: Optional[bytes] = None,
    new_keyfile: Optional[bytes] = None,
    kdf_id: int = KDF_ARGON2ID,
    iterations: int = 1_000_000,
    time_cost: int = 3,
    memory_kib: int = 65_536,
    parallelism: int = 4,
    salt: Optional[bytes] = None,
    enforce_write_policy: bool = True,
) -> bytes:
    """Enrol a second secret, holding only the first. §5.3."""
    core, records, payload, master = recover_master_key(
        container, unlock_password, keyfile_bytes=unlock_keyfile)
    if len(records) >= SLOT_COUNT_MAX:
        raise UsageError(f"container already has {SLOT_COUNT_MAX} slots")

    record = build_passphrase_slot(
        core, master, new_password,
        kdf_id=kdf_id, keyfile_bytes=new_keyfile, iterations=iterations,
        time_cost=time_cost, memory_kib=memory_kib, parallelism=parallelism,
        salt=salt, enforce_write_policy=enforce_write_policy,
    )
    return assemble(core, records + [record], payload)


def remove_slot(container: bytes, index: int) -> bytes:
    """
    Drop a slot by position. Needs no secret at all — which is correct: removing
    an unlock path is not a privileged operation on a file you already hold, and
    the remaining slots are untouched because no wrap depends on its position.
    """
    core, records, payload = parse_container(container)
    if not (0 <= index < len(records)):
        raise UsageError(f"no slot at index {index}")
    if len(records) == 1:
        raise UsageError("refusing to remove the last slot; the container would be unopenable")
    return assemble(core, records[:index] + records[index + 1:], payload)


def rewrap_slot(
    container: bytes,
    index: int,
    unlock_password: str,
    new_password: str,
    *,
    unlock_keyfile: Optional[bytes] = None,
    new_keyfile: Optional[bytes] = None,
    kdf_id: int = KDF_ARGON2ID,
    iterations: int = 1_000_000,
    time_cost: int = 3,
    memory_kib: int = 65_536,
    parallelism: int = 4,
    salt: Optional[bytes] = None,
    enforce_write_policy: bool = True,
) -> bytes:
    """Re-password in place. The payload is not re-encrypted — §4's first
    consequence, and the cheapest thing the envelope buys."""
    core, records, payload, master = recover_master_key(
        container, unlock_password, keyfile_bytes=unlock_keyfile)
    if not (0 <= index < len(records)):
        raise UsageError(f"no slot at index {index}")

    record = build_passphrase_slot(
        core, master, new_password,
        kdf_id=kdf_id, keyfile_bytes=new_keyfile, iterations=iterations,
        time_cost=time_cost, memory_kib=memory_kib, parallelism=parallelism,
        salt=salt, enforce_write_policy=enforce_write_policy,
    )
    return assemble(core, records[:index] + [record] + records[index + 1:], payload)


# =============================================================================
# §G  ARMOR AND FORMAT DETECTION
# =============================================================================

def armor(container: bytes) -> str:
    """§7 ``keym2:<base64url-unpadded>``."""
    return ARMOR_PREFIX.decode() + base64.urlsafe_b64encode(container).decode().rstrip("=")


def dearmor(text: str) -> bytes:
    """
    §7, case-sensitive per finding A2.

    Accepting ``KEYM2:`` would put back the exact collision the section removes:
    a reader sniffing four bytes would see the binary magic again.
    """
    raw = text.strip().encode("utf-8", errors="strict")
    if not raw.startswith(ARMOR_PREFIX):
        raise _reject()
    body = raw[len(ARMOR_PREFIX):]
    try:
        return base64.urlsafe_b64decode(body + b"=" * (-len(body) % 4))
    except Exception:
        raise _reject() from None


def detect(data: bytes) -> str:
    """
    §7 / §10's last checklist item: distinguish the encodings by inspecting
    bytes alone, with no dependence on the order the checks are written in.

    The three cases are disjoint on byte 0 — ``k`` (0x6B) for v2 armor, ``K``
    (0x4B) for the binary magic, ``I`` for legacy IBTZ — so this returns the
    same answer under any permutation of the branches. That is the property §7
    was written to buy, and it is worth asserting rather than assuming: v1's
    ``KEYM1:`` armor shares all four magic bytes, which is the bug.
    """
    if data.startswith(ARMOR_PREFIX):
        return "keym2-armor"
    if data.startswith(b"KEYM1:"):
        return "keym1-armor"
    if data.startswith(MAGIC):
        return f"keym-binary-v{data[4]}" if len(data) > 4 else "keym-binary"
    if data.startswith(b"IBTZ"):
        return "ibtz"
    return "unknown"


# =============================================================================
# §H  CLI AND SELF-TEST
# =============================================================================

def _describe_slot(index: int, record: bytes) -> list[str]:
    slot = _attemptable(record)
    if slot is None:
        # Finding A6: a reader does not validate slots it cannot attempt, so
        # inspect does not pretend to know more about one than a reader would.
        return [f"  slot {index}     type 0x{record[0]:02x}, not usable by this implementation"]
    kdf = (
        f"PBKDF2-HMAC-SHA-256, iterations={slot.iterations}"
        if slot.kdf_id == KDF_PBKDF2
        else f"Argon2id, t={slot.time_cost} m={slot.memory_kib}KiB p={slot.parallelism}"
    )
    return [
        f"  slot {index}     type 0x{slot.slot_type:02x} (passphrase)",
        f"    kdf       {kdf}",
        f"    key file  {'yes' if slot.keyfile_used else 'no'}",
        f"    salt      {slot.salt.hex()}",
    ]


def _inspect(container: bytes) -> str:
    core, records, payload = parse_container(container)
    sizes = _chunk_layout(len(payload), core.tag_overhead)
    cipher = {
        CIPHER_AES: "AES-256-GCM",
        CIPHER_CHACHA: "ChaCha20-Poly1305",
        CIPHER_CHAINED: "chained (AES-256-GCM then ChaCha20-Poly1305)",
    }[core.cipher_id]
    lines = [
        "KEYM v2",
        f"  cipher      {cipher}",
        f"  slots       {len(records)}",
    ]
    for i, record in enumerate(records):
        lines.extend(_describe_slot(i, record))
    lines.append(f"  chunks      {len(sizes)} ({sum(sizes)} plaintext bytes)")
    return "\n".join(lines)


def _selftest() -> int:
    """
    Round-trips, plus the questions in §10's checklist that can be answered by
    execution rather than by reading.

    Cheap parameters throughout: this exercises the *format*, and paying for
    real Argon2id costs would only make it something nobody runs.
    """
    checks: list[tuple[str, bool]] = []

    def check(name: str, ok: bool) -> None:
        checks.append((name, ok))

    def rejects(name: str, fn) -> None:
        try:
            fn()
            check(f"reject {name}", False)
        except KeymError:
            check(f"reject {name}", True)

    def opens(name: str, fn, expected: bytes) -> None:
        """Like check(), but a rejection is a failed check rather than a crash.

        Negative controls need this. A control that breaks slot skipping should
        report *which* checks noticed; without this it aborts the run on the
        first KeymError and leaves the rest of the suite unmeasured, which reads
        as "the control bit" while proving nothing about coverage.
        """
        try:
            check(name, fn() == expected)
        except KeymError:
            check(name, False)

    pw = "correct horse battery staple"
    pw2 = "a second, entirely different secret"
    kf = b"\x01\x02\x03" * 100
    fast = dict(iterations=1000, time_cost=1, memory_kib=8, parallelism=1,
                enforce_write_policy=False)

    # --- round-trips across every combination ---
    for kdf_id, kdf_name in ((KDF_PBKDF2, "pbkdf2"), (KDF_ARGON2ID, "argon2id")):
        for cipher_id, c_name in ((CIPHER_AES, "aes"), (CIPHER_CHACHA, "chacha"),
                                  (CIPHER_CHAINED, "chained")):
            for keyfile in (None, kf):
                msg = b"attack at dawn \xf0\x9f\x94\x91" * 3
                blob = encrypt(msg, pw, kdf_id=kdf_id, cipher_id=cipher_id,
                               keyfile_bytes=keyfile, **fast)
                got = decrypt(blob, pw, keyfile_bytes=keyfile)
                label = f"{kdf_name}+{c_name}{'+keyfile' if keyfile else ''}"
                check(f"round-trip {label}", got == msg)

    # --- boundary sizes, including the one finding A1 is about ---
    for n in (0, 1, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, 2 * CHUNK_SIZE,
              2 * CHUNK_SIZE + 7):
        msg = bytes((i * 7 + 13) & 0xFF for i in range(n))
        blob = encrypt(msg, pw, kdf_id=KDF_PBKDF2, cipher_id=CIPHER_CHAINED, **fast)
        check(f"round-trip {n} bytes", decrypt(blob, pw) == msg)

    # A1: an exact multiple must be the minimum chunk count, not a full chunk
    # plus an empty one. Asserted on the container length, which is the thing
    # two implementations have to agree on.
    one_slot_aes = SLOT_TABLE_OFFSET + slot_len(CIPHER_AES)
    check("A1: exact multiple is one chunk",
          len(encrypt(b"\x00" * CHUNK_SIZE, pw, kdf_id=KDF_PBKDF2,
                      cipher_id=CIPHER_AES, **fast))
          == one_slot_aes + CHUNK_SIZE + TAG_LEN)
    check("A1: one chunk over is two chunks",
          len(encrypt(b"\x00" * (CHUNK_SIZE + 1), pw, kdf_id=KDF_PBKDF2,
                      cipher_id=CIPHER_AES, **fast))
          == one_slot_aes + CHUNK_SIZE + TAG_LEN + 1 + TAG_LEN)

    # --- §3: the layout constants two implementations must agree on ---
    check("slot is 96 bytes for aes", slot_len(CIPHER_AES) == 96)
    check("slot is 96 bytes for chacha", slot_len(CIPHER_CHACHA) == 96)
    check("slot is 112 bytes for chained", slot_len(CIPHER_CHAINED) == 112)
    check("core header is 8 bytes", len(CoreHeader(CIPHER_AES).pack()) == CORE_HEADER_LEN)
    check("wrap nonce is outside the payload nonce space",
          WRAP_NONCE[-1] not in (0x00, 0x01)
          and WRAP_NONCE != nonce_for(0, False) and WRAP_NONCE != nonce_for(0, True))

    # §4.3's domain separation between the wrap's subkeys and the payload's.
    # This restates a pair of constants rather than exercising a behaviour, and
    # it is here for exactly that reason: reusing the payload's info strings for
    # the wrap is self-consistent, so every round-trip in this file passes with
    # the separation removed. A negative control confirmed it — nothing else in
    # the suite noticed. Cross-implementation byte equality is the other place
    # this is caught, and that lives in crosstest2.py.
    _probe = bytes(range(32))
    check("wrap and payload subkeys are domain-separated",
          wrap_keys(CIPHER_CHAINED, _probe) != payload_keys(CIPHER_CHAINED, _probe))

    # --- checklist: is kdf_input injective? ---
    #
    # Tested at the layer that actually carries the property. Comparing two
    # build_kdf_input() results is not that layer: §4.2 hashes the key file to a
    # fixed 32 bytes, and a fixed-width field cannot slide, so the classic
    # ("ab","c") vs ("a","bc") collision is already closed by the digest alone.
    # A negative control proved it: stubbing lp() to the identity left every
    # check green.
    check("injective: lp() concatenation cannot be re-split",
          lp(b"ab") + lp(b"c") != lp(b"a") + lp(b"bc"))
    check("injective: lp() distinguishes empty from absent",
          lp(b"") + lp(b"x") != lp(b"x") + lp(b""))
    check("injective: password/keyfile split cannot collide",
          build_kdf_input("ab", b"c") != build_kdf_input("a", b"bc"))
    check("injective: no key file differs from empty key file",
          build_kdf_input("x", None) != build_kdf_input("x", b""))
    check("injective: empty password differs from no password bytes",
          build_kdf_input("", b"k") != build_kdf_input("\x00", b"k"))

    # --- checklist: does the final-chunk rule reject every truncation? ---
    msg = b"z" * (2 * CHUNK_SIZE + 500)
    blob = encrypt(msg, pw, kdf_id=KDF_PBKDF2, cipher_id=CIPHER_AES, **fast)
    for label, cut in (
        ("truncated mid-chunk", len(blob) - 100),
        ("truncated on a chunk boundary", one_slot_aes + 2 * (CHUNK_SIZE + TAG_LEN)),
        ("truncated to one chunk", one_slot_aes + CHUNK_SIZE + TAG_LEN),
        ("payload removed entirely", one_slot_aes),
    ):
        rejects(label, lambda c=cut: decrypt(blob[:c], pw))

    # Appending a plausible extra chunk must fail too — the previously-final
    # chunk was sealed with final_flag = 1 and is now opened with 0.
    rejects("appended chunk", lambda: decrypt(blob + b"\x00" * (CHUNK_SIZE + TAG_LEN), pw))

    # --- checklist: can a chunk from container A verify inside container B? ---
    #
    # Both halves matter now. The core headers of two same-cipher containers are
    # byte-identical since the salt moved into the slot table, so the only thing
    # standing between them is that the master keys are independent randoms —
    # which is why the document's §5.3 dropped the "the headers differ" clause.
    a = encrypt(b"A" * 64, pw, kdf_id=KDF_PBKDF2, cipher_id=CIPHER_AES, **fast)
    b = encrypt(b"B" * 64, pw, kdf_id=KDF_PBKDF2, cipher_id=CIPHER_AES, **fast)
    check("two containers share a core header",
          a[:CORE_HEADER_LEN] == b[:CORE_HEADER_LEN])
    rejects("payload spliced between containers",
            lambda: decrypt(b[:one_slot_aes] + a[one_slot_aes:], pw))
    rejects("slot table spliced between containers",
            lambda: decrypt(a[:SLOT_TABLE_OFFSET] + b[SLOT_TABLE_OFFSET:one_slot_aes]
                            + a[one_slot_aes:], pw))

    # --- §5.3: the split byte-flip sweep ---
    #
    # v1 had one AAD and one sweep. There are two AADs now, so the sweep is
    # split to match: every byte of the core header must be caught by the
    # payload, every byte of every slot prefix by that slot's own wrap. The one
    # byte deliberately covered by neither is slot_count, and it gets its own
    # check below rather than being quietly excluded from this one.
    base = encrypt(b"tamper me", pw, kdf_id=KDF_PBKDF2, cipher_id=CIPHER_AES, **fast)

    def survives(index: int) -> bool:
        mutated = bytearray(base)
        mutated[index] ^= 0x01
        try:
            decrypt(bytes(mutated), pw)
            return True
        except KeymError:
            return False

    core_survivors = [i for i in range(CORE_HEADER_LEN) if survives(i)]
    check(f"every core header byte is authenticated (survivors: {core_survivors})",
          not core_survivors)

    prefix_survivors = [
        i for i in range(SLOT_TABLE_OFFSET, SLOT_TABLE_OFFSET + SLOT_PREFIX_LEN)
        if survives(i)
    ]
    check(f"every slot prefix byte is authenticated (survivors: {prefix_survivors})",
          not prefix_survivors)

    wrap_survivors = [
        i for i in range(SLOT_TABLE_OFFSET + SLOT_PREFIX_LEN, one_slot_aes)
        if survives(i)
    ]
    check(f"every wrapped-key byte is authenticated (survivors: {wrap_survivors})",
          not wrap_survivors)

    # --- §5.3: slot_count is outside both AADs, and that is bounded to DoS ---
    #
    # The document concedes this byte is unauthenticated. The claim it makes in
    # exchange is specific — no tampered slot_count can ever yield a master key
    # — so that is what gets tested, rather than the weaker "it fails somehow".
    def with_slot_count(value: int) -> bytes:
        m = bytearray(base)
        m[SLOT_COUNT_OFFSET] = value
        return bytes(m)

    for value in (0, 2, 3, 8, 9, 0xFF):
        rejects(f"tampered slot_count = {value}",
                lambda v=value: decrypt(with_slot_count(v), pw))
        try:
            recover_master_key(with_slot_count(value), pw)
            check(f"tampered slot_count = {value} yields no master key", False)
        except KeymError:
            check(f"tampered slot_count = {value} yields no master key", True)

    # --- §4.4: unknown slot types are skipped, not rejected ---
    #
    # The data-loss case. A container carrying a slot type from a later version
    # must still open through the passphrase slot it already had, or enrolling a
    # passkey in Phase 4 bricks every container for every reader shipped before
    # it.
    two_slot = add_slot(base, pw, pw2, **fast)
    opens("second slot opens the same container",
          lambda: decrypt(two_slot, pw2), b"tamper me")
    opens("first slot still opens it",
          lambda: decrypt(two_slot, pw), b"tamper me")

    def retype(container: bytes, index: int, new_type: int) -> bytes:
        """Rewrite one slot's type byte in place, leaving everything else."""
        m = bytearray(container)
        m[SLOT_TABLE_OFFSET + index * slot_len(CIPHER_AES)] = new_type
        return bytes(m)

    # Slot 0 becomes a type nothing implements. Slot 1 is untouched and valid.
    alien_first = retype(two_slot, 0, 0x7F)
    opens("unknown slot type is skipped, later slot still opens",
          lambda: decrypt(alien_first, pw2), b"tamper me")
    # And the reverse order, so the result does not depend on the alien slot
    # happening to come first.
    alien_second = retype(two_slot, 1, 0x7F)
    opens("unknown slot type is skipped, earlier slot still opens",
          lambda: decrypt(alien_second, pw), b"tamper me")
    # Every slot unusable is the only case that is a failure (finding A5).
    rejects("container whose every slot type is unknown",
            lambda: decrypt(retype(alien_first, 1, 0x7F), pw2))

    # Finding A6: a per-slot failure is scoped to the slot, never to the
    # container.
    #
    # The obvious test here — set a reserved byte inside the *alien* slot — is
    # worthless, and a negative control said so: that slot is skipped for its
    # type before its reserved bytes are ever looked at, so the check passes
    # whichever rule the reader follows. The case that separates §3.3's
    # "reject" from §4.4's "skip" is a reserved byte in a slot whose type the
    # reader *does* implement, in a container that has another slot to fall
    # back to.
    slot1 = SLOT_TABLE_OFFSET + slot_len(CIPHER_AES)
    reserved_in_known = bytearray(two_slot)
    reserved_in_known[SLOT_TABLE_OFFSET + 3] = 0xAB
    opens("a reserved byte in one slot does not condemn the container",
          lambda: decrypt(bytes(reserved_in_known), pw2), b"tamper me")
    rejects("that slot's own password once it is unusable",
            lambda: decrypt(bytes(reserved_in_known), pw))

    flags_in_known = bytearray(two_slot)
    flags_in_known[slot1 + 2] = 0x02
    opens("a reserved slot_flags bit in one slot does not condemn the container",
          lambda: decrypt(bytes(flags_in_known), pw), b"tamper me")

    # --- §4.3 / §5.3: a slot table is editable holding one secret ---
    #
    # This is the requirement that forced the constant wrap nonce and
    # slot_count's absence from the AAD. Both decisions are only justified if
    # this actually works, so it is executed rather than asserted.
    check("add_slot leaves the payload byte-identical",
          two_slot[SLOT_TABLE_OFFSET + 2 * slot_len(CIPHER_AES):]
          == base[SLOT_TABLE_OFFSET + slot_len(CIPHER_AES):])
    check("add_slot did not touch the first slot",
          two_slot[SLOT_TABLE_OFFSET:SLOT_TABLE_OFFSET + slot_len(CIPHER_AES)]
          == base[SLOT_TABLE_OFFSET:SLOT_TABLE_OFFSET + slot_len(CIPHER_AES)])

    dropped = remove_slot(two_slot, 0)
    opens("removing a slot needs no secret and leaves the other working",
          lambda: decrypt(dropped, pw2), b"tamper me")
    rejects("removed slot's password", lambda: decrypt(dropped, pw))

    repassworded = rewrap_slot(base, 0, pw, pw2, **fast)
    opens("re-passworded container opens with the new password",
          lambda: decrypt(repassworded, pw2), b"tamper me")
    rejects("old password after re-passwording", lambda: decrypt(repassworded, pw))
    check("re-passwording leaves the payload byte-identical",
          repassworded[one_slot_aes:] == base[one_slot_aes:])

    # --- §6: slot_count's cap is a bound, not a side effect of the length check
    #
    # Every tampered-slot_count case above is on a 130-byte container, where an
    # inflated count is caught because the file is too short to hold the slots
    # it claims. That proves nothing about the cap: a negative control removing
    # the 1..8 range check left the whole suite green. The bound exists to cap
    # worst-case KDF work (§3.1), so the case that tests it is a container long
    # enough to actually contain the slots it declares.
    eight = base
    for i in range(SLOT_COUNT_MAX - 1):
        eight = add_slot(eight, pw, f"{pw2}#{i}", **fast)
    check("eight slots is the maximum slot_count", eight[SLOT_COUNT_OFFSET] == 8)
    opens("a full slot table still opens on the first slot",
          lambda: decrypt(eight, pw), b"tamper me")
    opens("a full slot table still opens on the last slot",
          lambda: decrypt(eight, f"{pw2}#{SLOT_COUNT_MAX - 2}"), b"tamper me")

    try:
        add_slot(eight, pw, "one too many", **fast)
        check("refuse to write a ninth slot", False)
    except UsageError:
        check("refuse to write a ninth slot", True)

    # The ninth slot has to be the *only* way in, or the test passes for the
    # wrong reason. Padding a container and bumping its count was the first
    # attempt and it was worthless: the reader opened slot 0 exactly as before
    # and then failed on a payload that had moved, so the check went green with
    # the cap removed. A control caught that.
    #
    # This version builds a genuinely well-formed nine-slot container whose
    # ninth slot wraps the real master key. Nothing rejects it except the cap.
    core9, records9, payload9, master9 = recover_master_key(eight, pw)
    pw9 = "the ninth slot"
    ninth = build_passphrase_slot(core9, master9, pw9, kdf_id=KDF_PBKDF2, **fast)

    # assemble() refuses to write nine, which is the writer half of the bound,
    # so the reader half has to be tested against hand-built bytes.
    over_count = core9.pack() + bytes([9]) + b"".join(records9) + ninth + payload9
    check("the over-cap container is structurally well-formed",
          len(over_count) == SLOT_TABLE_OFFSET + 9 * slot_len(CIPHER_AES) + len(payload9))
    opens("the ninth slot is a valid slot when it is within the cap",
          lambda: decrypt(assemble(core9, records9[:7] + [ninth], payload9), pw9),
          b"tamper me")
    rejects("slot_count above the cap, with the ninth slot the only way in",
            lambda: decrypt(over_count, pw9))

    # --- §6: reserved fields and bounds are rejected ---
    def mutate(index: int, value: int) -> bytes:
        m = bytearray(base)
        m[index] = value
        return bytes(m)

    slot0 = SLOT_TABLE_OFFSET

    # A crafted container that is *internally consistent*: the reserved field is
    # non-zero and everything is sealed under that exact header, so the AADs
    # match and authentication would succeed.
    #
    # This is the only way to test §3.3's fail-closed rule. Simply flipping a
    # reserved bit in a finished container proves nothing — it fails on the tag
    # whether or not the reader checks reserved fields at all. A negative
    # control proved that against the first draft: removing both reserved-field
    # checks left every check green.
    def forge(core_bytes: bytes, slot_prefix: bytes) -> bytes:
        """Seal a container under a header this implementation refuses to write.

        Both AADs are the *literal* forged bytes, not a re-packed CoreHeader.
        Re-packing would silently zero the very reserved field under test, and
        the container would then fail on a mismatched AAD rather than on the
        reserved-field check — passing the test for the wrong reason, which is
        the failure mode this whole helper exists to avoid.
        """
        cipher_id = core_bytes[5]
        master = os.urandom(MASTER_KEY_LEN)
        draft = Slot(slot_type=slot_prefix[0], kdf_id=slot_prefix[1],
                     slot_flags=slot_prefix[2],
                     salt=slot_prefix[SLOT_SALT_OFFSET:SLOT_SALT_OFFSET + SALT_LEN],
                     wrapped_key=b"",
                     iterations=struct.unpack(">I", slot_prefix[40:44])[0])
        slot_key = derive_slot_key(draft, build_kdf_input(pw, None))
        wk_aes, wk_chacha = wrap_keys(cipher_id, slot_key)
        wrapped = _seal(cipher_id, wk_aes, wk_chacha, WRAP_NONCE, master,
                        core_bytes + slot_prefix)
        pk_aes, pk_chacha = payload_keys(cipher_id, master)
        payload = _seal(cipher_id, pk_aes, pk_chacha, nonce_for(0, True),
                        b"forged", core_bytes)
        return core_bytes + b"\x01" + slot_prefix + wrapped + payload

    good_core = bytearray(base[:CORE_HEADER_LEN])
    good_prefix = bytearray(base[slot0:slot0 + SLOT_PREFIX_LEN])

    core_flags_set = bytearray(good_core); core_flags_set[6] = 0x01
    core_pad_set = bytearray(good_core); core_pad_set[7] = 0x01
    slot_reserved_set = bytearray(good_prefix); slot_reserved_set[3] = 0x01
    slot_flags_set = bytearray(good_prefix); slot_flags_set[2] = 0x02
    slot_kdf_reserved = bytearray(good_prefix); slot_kdf_reserved[44] = 0x01

    for label, forged in (
        ("sealed container with a reserved core flag bit",
         forge(bytes(core_flags_set), bytes(good_prefix))),
        ("sealed container with a non-zero core pad byte",
         forge(bytes(core_pad_set), bytes(good_prefix))),
        ("sealed container with non-zero slot reserved bytes",
         forge(bytes(good_core), bytes(slot_reserved_set))),
        ("sealed container with a reserved slot_flags bit",
         forge(bytes(good_core), bytes(slot_flags_set))),
        ("sealed container with non-zero KDF reserved bytes",
         forge(bytes(good_core), bytes(slot_kdf_reserved))),
    ):
        rejects(label, lambda f=forged: decrypt(f, pw))

    for label, blob2 in (
        ("reserved core flag bit", mutate(6, 0x02)),
        ("non-zero core pad byte", mutate(7, 0x01)),
        ("reserved slot_flags bit", mutate(slot0 + 2, 0x02)),
        ("non-zero slot reserved byte", mutate(slot0 + 3, 0x01)),
        ("PBKDF2 reserved bytes", mutate(slot0 + 44, 0x01)),
        ("iterations = 0",
         base[:slot0 + 40] + b"\x00\x00\x00\x00" + base[slot0 + 44:]),
        ("iterations over cap",
         base[:slot0 + 40] + struct.pack(">I", 10_000_001) + base[slot0 + 44:]),
        ("unknown cipher_id", mutate(5, 0x09)),
        ("unknown slot kdf_id", mutate(slot0 + 1, 0x09)),
        ("wrong version", mutate(4, 0x03)),
        ("truncated to the core header", base[:CORE_HEADER_LEN]),
        ("empty container", b""),
    ):
        rejects(label, lambda x=blob2: decrypt(x, pw))

    # §6's per-slot bounds: an out-of-bounds slot is unusable, not fatal to a
    # container that has another slot (finding A5).
    over_cap = bytearray(two_slot)
    over_cap[slot0 + 40:slot0 + 44] = struct.pack(">I", 10_000_001)
    opens("out-of-bounds slot is skipped, not fatal",
          lambda: decrypt(bytes(over_cap), pw2), b"tamper me")
    rejects("out-of-bounds slot's own password",
            lambda: decrypt(bytes(over_cap), pw))

    # --- §7: armor round-trip and order-independent detection ---
    check("armor round-trips", dearmor(armor(base)) == base)
    check("armor is unpadded base64url", "=" not in armor(base))
    check("armor prefix is case-sensitive", detect(b"KEYM2:abc") != "keym2-armor")
    check("v2 armor detected", detect(armor(base).encode()) == "keym2-armor")
    check("binary detected", detect(base) == "keym-binary-v2")
    check("v1 armor no longer collides with the magic",
          detect(b"KEYM1:AAAA") == "keym1-armor")
    check("armor and magic differ at byte 0", armor(base).encode()[0] != MAGIC[0])

    # --- wrong credentials ---
    with_kf = encrypt(b"x", pw, kdf_id=KDF_PBKDF2, cipher_id=CIPHER_AES,
                      keyfile_bytes=kf, **fast)
    for label, password, keyfile in (
        ("wrong password", "nope", kf),
        ("missing key file", pw, None),
        ("wrong key file", pw, b"different"),
    ):
        try:
            decrypt(with_kf, password, keyfile_bytes=keyfile)
            check(f"reject {label}", False)
        except KeymError as e:
            check(f"reject {label}", str(e) == DECRYPT_FAILED)

    # --- §4.5: the conformance entry point is the only way to fix either ---
    fixed_salt = bytes(range(32))
    fixed_mk = bytes(range(32, 64))
    twice = [
        encrypt(b"determinism", pw, kdf_id=KDF_PBKDF2, cipher_id=CIPHER_AES,
                salt=fixed_salt, master_key=fixed_mk, **fast)
        for _ in range(2)
    ]
    check("fixed salt and master key give byte-identical containers",
          twice[0] == twice[1])
    check("default encryption does not repeat itself",
          encrypt(b"x", pw, kdf_id=KDF_PBKDF2, **fast)
          != encrypt(b"x", pw, kdf_id=KDF_PBKDF2, **fast))
    # The property the envelope bought: a reused salt no longer reuses the
    # payload key, so two containers written with the same salt and password
    # still differ in every payload byte (§11.1).
    same_salt = [
        encrypt(b"same salt", pw, kdf_id=KDF_PBKDF2, cipher_id=CIPHER_AES,
                salt=fixed_salt, **fast)
        for _ in range(2)
    ]
    check("a reused salt does not reuse the payload key",
          same_salt[0][one_slot_aes:] != same_salt[1][one_slot_aes:])

    failed = [name for name, ok in checks if not ok]
    for name, ok in checks:
        print(f"  {'ok  ' if ok else 'FAIL'} {name}")
    print()
    if failed:
        print(f"{len(failed)} of {len(checks)} checks FAILED")
        return 1
    print(f"All {len(checks)} checks passed.")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="keym2.py",
        description="Independent reference implementation of the KEYM v2 container format.",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    for name in ("encrypt", "decrypt"):
        p = sub.add_parser(name, help=f"{name} a KEYM v2 container")
        p.add_argument("--password", required=True)
        p.add_argument("--key-file", help="path to the key file, if one was used")
        p.add_argument("--in", dest="infile", help="input path (default: stdin)")
        p.add_argument("--out", dest="outfile", help="output path (default: stdout)")
        p.add_argument("--armor", action="store_true",
                       help="encrypt: emit keym2: text. decrypt: expect it.")
        if name == "encrypt":
            p.add_argument("--kdf", choices=["pbkdf2", "argon2id"], default="argon2id")
            p.add_argument("--cipher", choices=["aes", "chacha", "chained"], default="aes")
            p.add_argument("--iterations", type=int, default=1_000_000)
            p.add_argument("--time-cost", type=int, default=3)
            p.add_argument("--memory-kib", type=int, default=65_536)
            p.add_argument("--parallelism", type=int, default=4)
            # Conformance only, both of them. Byte-equality against the
            # TypeScript is the only check that catches a chunking, nonce or
            # slot-layout disagreement — the two implementations decode each
            # other's output happily even when they disagree about how to write
            # it — and comparing bytes needs both values pinned.
            #
            # §4.5 forbids either on real data. Reusing a master key reuses
            # every (key, nonce) pair in the container.
            p.add_argument("--salt", help="32-byte hex slot salt (conformance testing only)")
            p.add_argument("--master-key",
                           help="32-byte hex master key (conformance testing only)")

    insp = sub.add_parser("inspect", help="describe a container without decrypting it")
    insp.add_argument("--in", dest="infile", help="input path (default: stdin)")

    sub.add_parser("selftest", help="round-trip this implementation against itself")

    args = ap.parse_args(argv)

    if args.cmd == "selftest":
        return _selftest()

    data = open(args.infile, "rb").read() if args.infile else sys.stdin.buffer.read()

    if args.cmd == "inspect":
        if detect(data) == "keym2-armor":
            data = dearmor(data.decode())
        print(_inspect(data))
        return 0

    keyfile = open(args.key_file, "rb").read() if args.key_file else None

    try:
        if args.cmd == "encrypt":
            out = encrypt(
                data, args.password,
                kdf_id=KDF_PBKDF2 if args.kdf == "pbkdf2" else KDF_ARGON2ID,
                cipher_id={"aes": CIPHER_AES, "chacha": CIPHER_CHACHA,
                           "chained": CIPHER_CHAINED}[args.cipher],
                keyfile_bytes=keyfile,
                iterations=args.iterations,
                time_cost=args.time_cost,
                memory_kib=args.memory_kib,
                parallelism=args.parallelism,
                salt=bytes.fromhex(args.salt) if args.salt else None,
                master_key=bytes.fromhex(args.master_key) if args.master_key else None,
            )
            if args.armor:
                out = armor(out).encode()
        else:
            if args.armor or detect(data) == "keym2-armor":
                data = dearmor(data.decode())
            out = decrypt(data, args.password, keyfile_bytes=keyfile)
    except (KeymError, UsageError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if args.outfile:
        open(args.outfile, "wb").write(out)
    else:
        sys.stdout.buffer.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
