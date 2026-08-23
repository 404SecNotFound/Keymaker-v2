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
    §D2 Shamir share sets (document §4.6)
    §E  payload
    §F  slot mutation
    §G  armor and format detection
    §H  CLI and self-test

Two dependencies, pinned in requirements.txt, both for primitives only:
``cryptography`` and ``argon2-cffi``. Every format decision is in this file.


================================================================================
§A  WHAT THE SPECIFICATION DID NOT PIN DOWN
================================================================================

Seven gaps across three passes. A1–A4 came from the first draft of the document.
A5–A6 came from the multi-slot amendment (document §4). A7 came from the Shamir
amendment (document §4.6). They are recorded in the document as F6, F7 and F8.

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
A7. SUBSTANTIVE (new; document F8) — §4.6 adds a slot type whose secret is a
    physical artifact, and nothing warns that the existing slot operations can
    destroy it.

Re-passwording writes a *passphrase* slot. Point it at a share-set slot and it
converts one: the container stays valid, the new password works, and every
printed share for that set is now scrap, with no output saying so. Before §4.6
the worst case was forgetting a password you had just replaced. Now it is `n`
pieces of paper in `n` people's hands.

The format cannot fix this — replacing one unlock path with another is exactly
what a mutable slot table is for, and §4.3's constant wrap nonce exists so that
it can be done holding a single secret. The hazard is that "re-password" and
"annihilate the share set" became the same call.

    RESOLVED HERE AS: ``rewrap_slot`` refuses unless ``replace_slot_type=True``,
    the same shape as ``remove_slot``'s refusal to remove the last slot. Recorded
    in the document as F8 so that a second implementation inherits the warning
    rather than the bug — nothing in §4.6 itself would have told it.

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
import hmac
import math
import os
import re
import struct
import sys
import unicodedata
from dataclasses import dataclass
from typing import Iterable, Optional

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
KDF_HKDF = 0x02          # §3.2, added by §4.6 — no cost parameters, on purpose
CIPHER_AES = 0x00
CIPHER_CHACHA = 0x01
CIPHER_CHAINED = 0x02

# §4.4. A reader skips what it does not implement (§4.4, finding A6).
SLOT_TYPE_PASSPHRASE = 0x00
SLOT_TYPE_PASSKEY_PRF = 0x01     # §4.7
SLOT_TYPE_SHAMIR = 0x02          # §4.6
IMPLEMENTED_SLOT_TYPES = frozenset(
    {SLOT_TYPE_PASSPHRASE, SLOT_TYPE_PASSKEY_PRF, SLOT_TYPE_SHAMIR})

# §6, and normative in both directions. A passphrase under HKDF is a password
# with no stretching at all, and nothing in any output would reveal it; a
# 32-byte CSPRNG secret under Argon2id is a memory-hard cost paid to defend an
# unguessable value. Only the first is a vulnerability, but a rule that admits
# the second invites a writer to read the pairing as advice.
LEGAL_KDFS_FOR_SLOT_TYPE = {
    SLOT_TYPE_PASSPHRASE: frozenset({KDF_PBKDF2, KDF_ARGON2ID}),
    SLOT_TYPE_PASSKEY_PRF: frozenset({KDF_HKDF}),
    SLOT_TYPE_SHAMIR: frozenset({KDF_HKDF}),
}

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

# §7. Presentation only; whitespace is not part of the encoding. 64 matches the
# TypeScript, and PGP, and survives quoted-printable mail without re-wrapping.
ARMOR_COLUMNS = 64

# §4.1 / §4.3 domain separation. ASCII, see finding A4.
CTX_KDF_INPUT = b"keymaker.v2.kdf-input"
CTX_KEYFILE = b"keymaker.v2.keyfile"
INFO_AES = b"keymaker-v2-aes"
INFO_CHACHA = b"keymaker-v2-chacha"
INFO_SLOT_AES = b"keymaker-v2-slot-aes"
INFO_SLOT_CHACHA = b"keymaker-v2-slot-chacha"

# §4.6 domain separation. The input string differs from CTX_KDF_INPUT so that a
# 32-byte passphrase and a 32-byte share secret can never derive the same slot
# key, and INFO_SLOT_KEY is HKDF's info rather than a context prefix.
CTX_SHAMIR_INPUT = b"keymaker.v2.shamir-input"
CTX_SHARE_SET = b"keymaker.v2.share-set"
CTX_SHARE_CHECKSUM = b"keymaker.v2.share-checksum"
INFO_SLOT_KEY = b"keymaker.v2.slot-key"

# §4.7, and the same separation argument a third time: a 32-byte passphrase, a
# 32-byte share secret and a 32-byte PRF output must not be able to reach the
# same slot key.
CTX_PASSKEY_INPUT = b"keymaker.v2.passkey-input"

# §4.7. The PRF salt is derived from slot_salt rather than stored.
#
# It differs from INFO_SLOT_KEY as hygiene, not because anything rests on it:
# the two HKDF calls already take different IKMs — slot_salt here, the
# length-prefixed passkey_input there — and those cannot coincide, since one is
# 32 bytes and the other 65. Saying so plainly beats implying a separation the
# info strings are not in fact providing.
INFO_PRF_SALT = b"keymaker.v2.prf-salt"

# §4.7. WebAuthn's PRF extension returns 32 bytes.
PRF_OUTPUT_LEN = 32

# §4.6, the share record. 42 bytes: set id, threshold, index, value, checksum.
SHARE_SET_ID_LEN = 4
SHARE_VALUE_LEN = 32
SHARE_CHECKSUM_LEN = 4
SHARE_BODY_LEN = SHARE_SET_ID_LEN + 1 + 1 + SHARE_VALUE_LEN   # 38, checksummed
SHARE_LEN = SHARE_BODY_LEN + SHARE_CHECKSUM_LEN               # 42

# §4.6. k binds on read; n is absent from the share record, so its bound binds
# the writer only. 16 is a print-kit bound rather than a field bound — the index
# byte allows 255 — so it can be raised without touching the encoding.
SHAMIR_K_MIN, SHAMIR_K_MAX = 2, 16
SHAMIR_N_MAX = 16

# §7.2. The sentinels bracketing the armor inside a self-extracting page.
#
# HTML comments rather than a <script> or a data attribute, so the armor is
# visible text in the document: the case the artefact exists for is the one
# where the page's JavaScript does not run, and the container has to still be
# reachable with a text editor.
#
# Note these are matched as a *substring*, which is the one place this format is
# not detected by a prefix. It stays disjoint from every prefixed encoding for a
# reason that is checked rather than assumed (see _selftest): "<" and "!" are
# outside base64url, outside Crockford base32, and outside all four prefixes.
SELFEXTRACT_BEGIN = "<!--KEYM2-BEGIN-->"
SELFEXTRACT_END = "<!--KEYM2-END-->"

# §4.6 share text. Crockford's alphabet, which omits I, L, O and U.
SHARE_PREFIX = "KMSHARE1:"
B32_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
SHARE_GROUP = 4
# Explicitly ASCII rather than str.isspace(), which is Unicode-aware. Two
# implementations that disagree about whether U+00A0 is whitespace disagree
# about whether a share decodes.
ASCII_WHITESPACE = " \t\n\r\v\f"

# §4.6. GF(2^8) modulo x^8 + x^4 + x^3 + x + 1 — the AES field. 0x1B is the low
# byte of 0x11B, which is what gets folded back in after a shift overflows.
GF_REDUCTION = 0x1B

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
        elif self.kdf_id == KDF_HKDF:
            params = b"\x00" * KDF_PARAM_LEN   # §3.2, all reserved
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
    # §6, the slot_type/slot_kdf_id pairing, checked before any KDF runs. This
    # is what makes "a passphrase slot declaring HKDF" unreachable rather than
    # merely discouraged.
    if kdf_id not in LEGAL_KDFS_FOR_SLOT_TYPE[slot_type]:
        raise _reject()

    if kdf_id == KDF_HKDF:
        if params != b"\x00" * KDF_PARAM_LEN:   # §3.2, all eight reserved
            raise _reject()
        return Slot(slot_type, kdf_id, slot_flags, salt, wrapped_key)

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


def webcrypto_profile_violations(container: bytes) -> list[str]:
    """
    §7.2. The reasons a WebCrypto-only reader could not open this container.

    Empty means it can. Reasons rather than a bool because each one names a
    different thing the writer has to change — the cipher, the KDF, the key file
    — and "unsuitable" on its own tells a caller nothing they can act on.

    Everything here is a *write*-side policy question, so it raises nothing and
    reports freely. §6's rule about indistinguishable rejections governs readers
    holding someone else's file; this function is asked about a container by the
    person who just wrote it.
    """
    reasons: list[str] = []
    core, records, _ = parse_container(container)

    if core.cipher_id != CIPHER_AES:
        reasons.append(
            f"cipher_id 0x{core.cipher_id:02x} needs ChaCha20-Poly1305, which "
            "WebCrypto has never had; the subset is AES-256-GCM only"
        )

    # §4.4's skip rule applies here too: a slot this implementation cannot parse
    # is not evidence about the container, so an unparseable slot simply is not a
    # candidate. The question is whether *some* slot is in the subset.
    usable = False
    keyfile_only = False
    for record in records:
        slot = _attemptable(record)
        if slot is None:
            continue
        if slot.slot_type != SLOT_TYPE_PASSPHRASE or slot.kdf_id != KDF_PBKDF2:
            continue
        if slot.keyfile_used:
            keyfile_only = True
            continue
        usable = True

    if not usable:
        if keyfile_only:
            reasons.append(
                "every PBKDF2 passphrase slot declares a key file. Embedding it "
                "would put both factors in one file, which is the property a key "
                "file exists to deny; dropping it would write a weaker container "
                "than you think you have"
            )
        else:
            reasons.append(
                "no slot is a PBKDF2 passphrase slot. Argon2id needs WebAssembly, "
                "and a share set needs §4.6's share text — neither survives in a "
                "page with nobody to maintain it"
            )
    return reasons


def check_selfextract_policy(container: bytes) -> None:
    """§7.2, the writer's MUST. Refuses with every reason at once."""
    reasons = webcrypto_profile_violations(container)
    if reasons:
        raise UsageError(
            "this container is outside the WebCrypto-only subset (§7.2):\n  - "
            + "\n  - ".join(reasons)
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


def build_shamir_input(share_secret: bytes) -> bytes:
    """
    §4.6, the slot secret for ``slot_type = 0x02``.

    Same shape as build_kdf_input and a different domain string, which is the
    entire reason a 32-byte passphrase and a 32-byte share secret cannot collide
    into the same slot key.
    """
    if len(share_secret) != SHARE_VALUE_LEN:
        raise UsageError("share secret must be 32 bytes")
    return lp(CTX_SHAMIR_INPUT) + lp(share_secret)


def derive_prf_salt(slot_salt: bytes) -> bytes:
    """
    §4.7. The salt handed to the authenticator, derived rather than stored.

    It is an *input* the authenticator needs before it will produce anything, so
    a reader must hold it before it can ask — but holding and storing are
    different things. The slot already carries 32 random bytes, and this spends
    no wire space to reach a value that is not secret anyway: without the
    credential the salt buys nothing.
    """
    if len(slot_salt) != SALT_LEN:
        raise UsageError("slot salt must be 32 bytes")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=PRF_OUTPUT_LEN,
        salt=b"",
        info=INFO_PRF_SALT,
    ).derive(slot_salt)


def build_passkey_input(prf_output: bytes) -> bytes:
    """
    §4.7, the slot secret for ``slot_type = 0x01``.

    Same shape as build_kdf_input and build_shamir_input, third domain string.
    The PRF output is 32 unguessable bytes from an authenticator, which is why
    §6 pairs this slot type with HKDF and nothing else.
    """
    if len(prf_output) != PRF_OUTPUT_LEN:
        raise UsageError(f"PRF output must be {PRF_OUTPUT_LEN} bytes")
    return lp(CTX_PASSKEY_INPUT) + lp(prf_output)


def derive_slot_key(slot: Slot, kdf_input: bytes) -> bytes:
    """§4.3. Assumes `slot` came from parse_slot, i.e. is already bounded."""
    if slot.kdf_id == KDF_HKDF:
        # §3.2. No cost parameters, because the secret this stretches is
        # already 32 CSPRNG bytes and 2^256 does not get larger when multiplied
        # by a work factor. parse_slot is what guarantees this branch is only
        # reachable for a slot type whose secret has that property.
        return HKDF(
            algorithm=hashes.SHA256(),
            length=SLOT_KEY_LEN,
            salt=slot.salt,
            info=INFO_SLOT_KEY,
        ).derive(kdf_input)

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
    # §4.4/F6: a slot that cannot be used disqualifies itself, never the walk.
    #
    # Defence in depth here rather than a live bug. This reader's §6 floor on
    # memory_kib already rejects the case that broke the TypeScript one — a
    # slot declaring mem=1 with p=8, each inside §6's independent ranges and
    # together illegal for Argon2id, which raises inside the KDF. There the
    # exception escaped the whole slot walk, so six rewritten bytes in slot 0
    # made a container unopenable through an untouched, valid slot 1.
    #
    # Worth noting what that divergence means: the two implementations disagree
    # about whether such a container is readable at all, and the byte-for-byte
    # crosstest cannot see it, because it compares containers both sides agree
    # to write rather than hostile ones neither would.
    try:
        slot_key = derive_slot_key(slot, kdf_input)
    except Exception:
        return None
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
# §D2  SHAMIR SHARE SETS (§4.6)
# =============================================================================
#
# Nothing below touches the container layout. A share set is a slot whose secret
# is reconstructed from paper instead of typed; §4.3 onwards is unchanged.


def gf_mul(a: int, b: int) -> int:
    """
    §4.6. Multiply in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1.

    Carry-less multiply-and-reduce, with both conditionals expressed as
    arithmetic masks. §4.6 forbids the log/antilog table version: every value
    this multiplies is a share value or a coefficient, so a table indexed by one
    of them is a cache-timing oracle on the secret. ``-(x & 1)`` is 0 or -1, and
    -1 & v == v for the non-negative v used here.
    """
    p = 0
    for _ in range(8):
        p ^= a & -(b & 1)
        b >>= 1
        high = a & 0x80
        a = (a << 1) & 0xFF
        a ^= GF_REDUCTION & -(high >> 7)
    return p & 0xFF


def gf_inv(a: int) -> int:
    """
    §4.6. a^254 == a^-1 in GF(2^8), by Fermat: the multiplicative group has
    order 255.

    Square-and-multiply over the *public* constant 254, so branching on the
    exponent's bits is not a secret-dependent branch. gf_inv(0) is 0, which is
    never reached: the only inversions here are of ``x_i ^ x_m`` for distinct
    indices, and combine_shares rejects duplicates before it gets this far.
    """
    result = 1
    for bit in (1, 1, 1, 1, 1, 1, 1, 0):   # 254, most significant bit first
        result = gf_mul(result, result)
        if bit:
            result = gf_mul(result, a)
    return result


def shamir_split(secret: bytes, k: int, n: int, *,
                 coefficients: Optional[bytes] = None) -> list[tuple[int, bytes]]:
    """
    §4.6. Split ``secret`` into ``n`` shares, any ``k`` of which reconstruct it.

    Returns [(index, value)], indices 1..n.

    ``coefficients`` exists for cross-implementation byte comparison and nothing
    else — §4.5 forbids caller-supplied values in any interface meant for real
    data, and here the reason is unusually direct: the coefficients *are* the
    only thing standing between one share and the secret. Layout is (k-1) blocks
    of 32 bytes, block c-1 holding a_{c,j} for every byte position j, which is
    the convention crosstest2.py drives both implementations with.
    """
    if not (SHAMIR_K_MIN <= k <= SHAMIR_K_MAX):
        raise UsageError(f"threshold must be {SHAMIR_K_MIN}..{SHAMIR_K_MAX}")
    if not (k <= n <= SHAMIR_N_MAX):
        raise UsageError(f"share count must be {k}..{SHAMIR_N_MAX}")
    if len(secret) != SHARE_VALUE_LEN:
        raise UsageError("share secret must be 32 bytes")

    width = SHARE_VALUE_LEN
    need = (k - 1) * width
    if coefficients is None:
        # §4.5: independently per byte position *and* per coefficient index.
        # One draw of (k-1)*32 bytes is exactly that; the failure mode the
        # section describes is drawing (k-1) bytes and reusing them across j.
        coefficients = os.urandom(need)
    elif len(coefficients) != need:
        raise UsageError(f"expected {need} coefficient bytes for k={k}")

    shares: list[tuple[int, bytes]] = []
    for x in range(1, n + 1):
        value = bytearray(width)
        for j in range(width):
            # Horner from the highest-degree coefficient down to the secret.
            acc = 0
            for c in range(k - 1, 0, -1):
                acc = gf_mul(acc, x) ^ coefficients[(c - 1) * width + j]
            value[j] = gf_mul(acc, x) ^ secret[j]
        shares.append((x, bytes(value)))
    return shares


def shamir_combine(shares: list[tuple[int, bytes]]) -> bytes:
    """
    §4.6. Lagrange interpolation at x = 0, per byte position.

    ``s_j = XOR_i  y_i,j * PROD_{m != i} x_m * inv(x_i ^ x_m)``

    Both subtractions from the textbook form vanished in characteristic 2:
    (0 - x_m) is x_m, and (x_i - x_m) is x_i ^ x_m. Transcribing the rational
    version and leaving a minus sign in place is the classic way to get an
    implementation that is wrong only for some inputs.

    Caller-side selection: this reconstructs from exactly the shares it is
    given. combine_shares applies §4.6's "k lowest-indexed distinct" rule.
    """
    if not shares:
        raise _reject()
    xs = [x for x, _ in shares]
    if len(set(xs)) != len(xs):
        raise _reject()
    if any(x == 0 for x in xs):
        raise _reject()
    width = len(shares[0][1])
    if any(len(v) != width for _, v in shares):
        raise _reject()

    out = bytearray(width)
    for x_i, y_i in shares:
        num, den = 1, 1
        for x_m, _ in shares:
            if x_m == x_i:
                continue
            num = gf_mul(num, x_m)
            den = gf_mul(den, x_i ^ x_m)
        basis = gf_mul(num, gf_inv(den))
        for j in range(width):
            out[j] ^= gf_mul(y_i[j], basis)
    return bytes(out)


def share_set_id(slot_salt: bytes) -> bytes:
    """
    §4.6. Derived from the slot salt, not stored.

    The salt is already in the container in the clear, so this lets a reader
    reject a share from a different set before doing any field arithmetic —
    mixing two sets otherwise reconstructs a perfectly clean secret that happens
    to be the wrong one, and fails at the unwrap with the same generic error as
    a wrong password.
    """
    if len(slot_salt) != SALT_LEN:
        raise UsageError("slot salt must be 32 bytes")
    return hashlib.sha256(CTX_SHARE_SET + slot_salt).digest()[:SHARE_SET_ID_LEN]


def _share_checksum(body: bytes) -> bytes:
    """§4.6. Four bytes of SHA-256 over share bytes [0, 38)."""
    return hashlib.sha256(CTX_SHARE_CHECKSUM + body).digest()[:SHARE_CHECKSUM_LEN]


@dataclass(frozen=True)
class Share:
    """§4.6's 42-byte share record, parsed and validated."""

    set_id: bytes
    threshold: int
    index: int
    value: bytes

    def pack(self) -> bytes:
        if len(self.set_id) != SHARE_SET_ID_LEN:
            raise UsageError("share set id must be 4 bytes")
        if len(self.value) != SHARE_VALUE_LEN:
            raise UsageError("share value must be 32 bytes")
        if not (SHAMIR_K_MIN <= self.threshold <= SHAMIR_K_MAX):
            raise UsageError(f"threshold must be {SHAMIR_K_MIN}..{SHAMIR_K_MAX}")
        if not (1 <= self.index <= 255):
            raise UsageError("share index must be 1..255")
        body = self.set_id + bytes([self.threshold, self.index]) + self.value
        assert len(body) == SHARE_BODY_LEN
        return body + _share_checksum(body)


def parse_share(record: bytes) -> Share:
    """§4.6 and §6, for one share. Parsing is validation, as with Slot."""
    if len(record) != SHARE_LEN:
        raise _reject()
    body, checksum = record[:SHARE_BODY_LEN], record[SHARE_BODY_LEN:]
    # Public data, but compared in constant time so that nobody has to work out
    # whether it is public before deciding the comparison is safe.
    if not hmac.compare_digest(checksum, _share_checksum(body)):
        raise _reject()

    threshold = body[SHARE_SET_ID_LEN]
    index = body[SHARE_SET_ID_LEN + 1]
    if not (SHAMIR_K_MIN <= threshold <= SHAMIR_K_MAX):
        raise _reject()
    if index == 0:
        raise _reject()
    return Share(
        set_id=body[:SHARE_SET_ID_LEN],
        threshold=threshold,
        index=index,
        value=body[SHARE_SET_ID_LEN + 2:],
    )


def _b32_encode(data: bytes) -> str:
    """§4.6. Crockford base32, no padding character, zero padding bits."""
    nchars = (len(data) * 8 + 4) // 5
    pad = nchars * 5 - len(data) * 8
    bits = int.from_bytes(data, "big") << pad
    return "".join(B32_ALPHABET[(bits >> (5 * i)) & 31] for i in range(nchars - 1, -1, -1))


def _b32_decode(text: str, nbytes: int) -> bytes:
    """
    §4.6. Case-insensitive, I/L map to 1, O maps to 0, hyphens and ASCII
    whitespace ignored, everything else rejected.

    Non-zero padding bits in the final character are rejected so that one share
    has exactly one encoding — without that check, 16 texts decode to each share
    and a printed share is no longer something two people can compare by eye.
    """
    cleaned: list[int] = []
    for ch in text:
        if ch == "-" or ch in ASCII_WHITESPACE:
            continue
        u = ch.upper()
        if u in ("I", "L"):
            u = "1"
        elif u == "O":
            u = "0"
        pos = B32_ALPHABET.find(u)
        if pos < 0:
            raise _reject()
        cleaned.append(pos)

    nchars = (nbytes * 8 + 4) // 5
    if len(cleaned) != nchars:
        raise _reject()

    bits = 0
    for pos in cleaned:
        bits = (bits << 5) | pos
    pad = nchars * 5 - nbytes * 8
    if bits & ((1 << pad) - 1):
        raise _reject()
    return (bits >> pad).to_bytes(nbytes, "big")


def encode_share(share: Share) -> str:
    """§4.6 ``KMSHARE1:`` plus Crockford base32 in groups of four."""
    body = _b32_encode(share.pack())
    groups = [body[i:i + SHARE_GROUP] for i in range(0, len(body), SHARE_GROUP)]
    return SHARE_PREFIX + "-".join(groups)


def decode_share(text: str) -> Share:
    """§4.6. The inverse, with every rejection in §6 applied."""
    stripped = text.strip()
    if not stripped.upper().startswith(SHARE_PREFIX):
        raise _reject()
    return parse_share(_b32_decode(stripped[len(SHARE_PREFIX):], SHARE_LEN))


def combine_shares(texts: list[str], expected_set_id: Optional[bytes] = None) -> bytes:
    """
    §4.6 and §6. Decode, validate as a set, and reconstruct the share secret.

    The set-level rules live here rather than in parse_share because none of
    them are properties of one share: agreement on k, distinct indices, and
    "exactly the k lowest-indexed distinct shares".

    That last rule is why this sorts. With genuine shares every k-subset gives
    the same answer, so it looks like it does not matter — but with one corrupt
    share the subsets give *different* wrong answers, and two implementations
    that disagree about which wrong answer they produce cannot be compared by
    the person trying to work out which share is bad.
    """
    if not texts:
        raise _reject()
    shares = [decode_share(t) for t in texts]

    thresholds = {s.threshold for s in shares}
    if len(thresholds) != 1:
        raise _reject()
    k = thresholds.pop()

    if len({s.set_id for s in shares}) != 1:
        raise _reject()
    if expected_set_id is not None and not hmac.compare_digest(
            shares[0].set_id, expected_set_id):
        raise _reject()

    indices = [s.index for s in shares]
    if len(set(indices)) != len(indices):
        raise _reject()
    if len(shares) < k:
        raise _reject()

    chosen = sorted(shares, key=lambda s: s.index)[:k]
    return shamir_combine([(s.index, s.value) for s in chosen])


def build_passkey_slot(
    core: CoreHeader,
    master_key: bytes,
    prf_output: bytes,
    *,
    salt: Optional[bytes] = None,
) -> bytes:
    """
    §4.7. Build one ``slot_type = 0x01`` record.

    Note what this does *not* take: any identifier for the credential. §4.7
    stores nothing about it, so this record is the same 48-byte prefix as every
    other slot and differs only in its type byte and where its secret came from.

    ``prf_output`` is the 32 bytes WebAuthn's PRF extension returned when asked
    for ``derive_prf_salt(salt)``. This module cannot obtain it — there is no
    authenticator behind a Python process — so it is a parameter, which is also
    what makes the derivation testable without one.
    """
    if salt is None:
        salt = os.urandom(SALT_LEN)
    if len(salt) != SALT_LEN:
        raise UsageError("slot salt must be 32 bytes")
    if len(master_key) != MASTER_KEY_LEN:
        raise UsageError("master key must be 32 bytes")

    draft = Slot(
        slot_type=SLOT_TYPE_PASSKEY_PRF,
        kdf_id=KDF_HKDF,
        slot_flags=0,
        salt=salt,
        wrapped_key=b"",
    )
    prefix = draft.pack_prefix()
    # The same round-trip through the reader's own validator that the other two
    # builders do: a writer that can emit a slot its own parser rejects is worth
    # catching here rather than in someone's hands.
    parse_slot(prefix + b"\x00" * (MASTER_KEY_LEN + core.tag_overhead))

    slot_key = derive_slot_key(draft, build_passkey_input(prf_output))
    return prefix + wrap_master_key(core, prefix, slot_key, master_key)


def build_shamir_slot(
    core: CoreHeader,
    master_key: bytes,
    k: int,
    n: int,
    *,
    salt: Optional[bytes] = None,
    share_secret: Optional[bytes] = None,
    coefficients: Optional[bytes] = None,
) -> tuple[bytes, list[str]]:
    """
    §4.6. Build one ``slot_type = 0x02`` record and the ``n`` shares that open
    it. Returns (slot record, share texts).

    The salt has to be chosen before the shares exist, because share_set_id is
    derived from it — which is also why enrolling a share set cannot reuse an
    existing slot's salt without reusing its share set id.

    ``share_secret`` and ``coefficients`` are for byte comparison only (§4.5).
    """
    if salt is None:
        salt = os.urandom(SALT_LEN)
    if len(salt) != SALT_LEN:
        raise UsageError("slot salt must be 32 bytes")
    if len(master_key) != MASTER_KEY_LEN:
        raise UsageError("master key must be 32 bytes")
    if share_secret is None:
        share_secret = os.urandom(SHARE_VALUE_LEN)

    draft = Slot(
        slot_type=SLOT_TYPE_SHAMIR,
        kdf_id=KDF_HKDF,
        slot_flags=0,
        salt=salt,
        wrapped_key=b"",
    )
    prefix = draft.pack_prefix()
    # Same round-trip through the reader's own validator as the passphrase path:
    # a writer that can emit a slot its own parser rejects is worth catching
    # here rather than in someone's hands.
    parse_slot(prefix + b"\x00" * (MASTER_KEY_LEN + core.tag_overhead))

    slot_key = derive_slot_key(draft, build_shamir_input(share_secret))
    record = prefix + wrap_master_key(core, prefix, slot_key, master_key)

    set_id = share_set_id(salt)
    texts = [
        encode_share(Share(set_id=set_id, threshold=k, index=x, value=value))
        for x, value in shamir_split(share_secret, k, n, coefficients=coefficients)
    ]
    return record, texts


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


def slot_secret_for(
    slot: Slot,
    *,
    password: Optional[str],
    keyfile_bytes: Optional[bytes],
    shares: Optional[list[str]],
    prf_output: Optional[bytes],
) -> Optional[bytes]:
    """
    §4.1 / §4.6. The slot secret this caller can offer *this* slot, or None if
    it holds nothing of the kind the slot wants.

    This is the whole of what the Shamir slot changed about the read path: the
    walk below is unchanged, and only the question "what secret does this slot
    take" grew a second answer.
    """
    if slot.slot_type == SLOT_TYPE_PASSPHRASE:
        if password is None:
            return None
        return build_kdf_input(password, keyfile_bytes)

    if slot.slot_type == SLOT_TYPE_SHAMIR:
        if not shares:
            return None
        try:
            # The set id is checked against *this* slot's salt, so a share set
            # belonging to a different Shamir slot declines rather than
            # reconstructing a clean secret that is simply the wrong one.
            secret = combine_shares(shares, expected_set_id=share_set_id(slot.salt))
        except KeymError:
            return None
        return build_shamir_input(secret)

    if slot.slot_type == SLOT_TYPE_PASSKEY_PRF:
        if prf_output is None:
            return None
        # No equivalent of the Shamir set-id check exists, and cannot: §4.7
        # stores nothing identifying the credential, so there is no way to ask
        # "is this the right passkey" before trying it. A PRF output from the
        # wrong credential simply fails to unwrap, which by §6 is
        # indistinguishable from a wrong password — deliberately, and at the
        # cost of never being able to say "wrong passkey".
        try:
            return build_passkey_input(prf_output)
        except KeymError:
            return None

    return None


def recover_master_key(
    container: bytes,
    password: Optional[str] = None,
    *,
    keyfile_bytes: Optional[bytes] = None,
    shares: Optional[list[str]] = None,
    prf_output: Optional[bytes] = None,
) -> tuple[CoreHeader, list[bytes], bytes, bytes]:
    """
    Walk the slot table until one opens, returning everything the caller needs
    to either decrypt or rewrite the container.

    §4.4 and finding A5: a slot is passed over when its type is not implemented,
    when its parameters are out of bounds, when the caller holds no secret of
    the kind it wants, or when the secret it does hold is the wrong one. All
    four are the same event from here — this slot did not open it — and only
    exhausting the table is a failure.
    """
    core, records, payload = parse_container(container)
    if password is None and not shares and prf_output is None:
        raise UsageError("need a password, a set of shares, or a PRF output")

    for record in records:
        slot = _attemptable(record)
        if slot is None:
            continue
        secret = slot_secret_for(
            slot, password=password, keyfile_bytes=keyfile_bytes, shares=shares,
            prf_output=prf_output)
        if secret is None:
            continue
        master = unwrap_master_key_from_slot(core, record, slot, secret)
        if master is not None:
            return core, records, payload, master

    raise _reject()


def decrypt(
    container: bytes,
    password: Optional[str] = None,
    *,
    keyfile_bytes: Optional[bytes] = None,
    shares: Optional[list[str]] = None,
    prf_output: Optional[bytes] = None,
) -> bytes:
    """
    Decrypt a v2 container, or raise KeymError with a single generic message.

    §5.5's hazard is why this returns bytes rather than yielding them: "a prefix
    of verified chunks is not a verified prefix of the file". Nothing is
    returned until the final chunk has verified *and* carried final_flag, so a
    caller cannot accidentally treat 899 good chunks out of 900 as a result.
    """
    core, _records, payload, master = recover_master_key(
        container, password, keyfile_bytes=keyfile_bytes, shares=shares,
        prf_output=prf_output)

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
    unlock_password: Optional[str],
    new_password: str,
    *,
    unlock_keyfile: Optional[bytes] = None,
    unlock_shares: Optional[list[str]] = None,
    unlock_prf_output: Optional[bytes] = None,
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
        container, unlock_password, keyfile_bytes=unlock_keyfile,
        shares=unlock_shares, prf_output=unlock_prf_output)
    if len(records) >= SLOT_COUNT_MAX:
        raise UsageError(f"container already has {SLOT_COUNT_MAX} slots")

    record = build_passphrase_slot(
        core, master, new_password,
        kdf_id=kdf_id, keyfile_bytes=new_keyfile, iterations=iterations,
        time_cost=time_cost, memory_kib=memory_kib, parallelism=parallelism,
        salt=salt, enforce_write_policy=enforce_write_policy,
    )
    return assemble(core, records + [record], payload)


def add_shamir_slot(
    container: bytes,
    unlock_password: Optional[str],
    k: int,
    n: int,
    *,
    unlock_keyfile: Optional[bytes] = None,
    unlock_shares: Optional[list[str]] = None,
    unlock_prf_output: Optional[bytes] = None,
    salt: Optional[bytes] = None,
    share_secret: Optional[bytes] = None,
    coefficients: Optional[bytes] = None,
) -> tuple[bytes, list[str]]:
    """
    §4.6. Enrol a share set on an existing container, holding one other secret.
    Returns (container, share texts).

    This is the composition the envelope was built for: slot 0 stays the
    passphrase the owner uses daily, slot 1 becomes k-of-n shares for whoever
    inherits it, neither knows the other exists, and the payload is not
    re-encrypted however large it is.

    The share texts are returned once and are not recoverable afterwards. The
    share secret is discarded here; the only way back to it is k shares.
    """
    core, records, payload, master = recover_master_key(
        container, unlock_password, keyfile_bytes=unlock_keyfile,
        shares=unlock_shares, prf_output=unlock_prf_output)
    if len(records) >= SLOT_COUNT_MAX:
        raise UsageError(f"container already has {SLOT_COUNT_MAX} slots")

    record, texts = build_shamir_slot(
        core, master, k, n,
        salt=salt, share_secret=share_secret, coefficients=coefficients)
    return assemble(core, records + [record], payload), texts


def _passkey_only(records: list[bytes]) -> bool:
    """
    True when every slot a reader could attempt is a passkey slot.

    Unparseable records are counted as *not* passkey slots, which is the
    conservative direction: a slot this build cannot read may be a passphrase
    slot a newer one can, and refusing to write on the strength of a record we
    do not understand would block a legitimate container.
    """
    attemptable = [_attemptable(r) for r in records]
    return bool(attemptable) and all(
        s is not None and s.slot_type == SLOT_TYPE_PASSKEY_PRF for s in attemptable)


def add_passkey_slot(
    container: bytes,
    unlock_password: Optional[str],
    prf_output: bytes,
    *,
    unlock_keyfile: Optional[bytes] = None,
    unlock_shares: Optional[list[str]] = None,
    unlock_prf_output: Optional[bytes] = None,
    salt: Optional[bytes] = None,
) -> bytes:
    """
    §4.7. Enrol a passkey on an existing container, holding one other secret.

    There is no ``encrypt(..., passkey=...)`` counterpart, and that is the
    never-travels-alone rule expressed as an API rather than as a warning: a
    container is created with a passphrase, and a passkey is added to one that
    already opens some other way. A writer cannot reach the forbidden state by
    following the obvious path, which is the only kind of rule that holds.
    """
    core, records, payload, master = recover_master_key(
        container, unlock_password, keyfile_bytes=unlock_keyfile,
        shares=unlock_shares, prf_output=unlock_prf_output)
    if len(records) >= SLOT_COUNT_MAX:
        raise UsageError(f"container already has {SLOT_COUNT_MAX} slots")

    record = build_passkey_slot(core, master, prf_output, salt=salt)
    out = records + [record]

    # §4.7's one normative rule that is not about bytes. Checked on the result
    # rather than the input, so it cannot be walked around by ordering.
    if _passkey_only(out):
        raise UsageError(
            "refusing to write a container whose only slot is a passkey slot: "
            "a passkey is hardware, and a container only a lost key opens is "
            "lost data (§4.7)"
        )
    return assemble(core, out, payload)


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

    remaining = records[:index] + records[index + 1:]
    # §4.7 again, and this is the path that would otherwise walk around it:
    # removing the passphrase from a {passphrase, passkey} container leaves a
    # container only a piece of hardware opens. The rule is about the resulting
    # file, so every operation that produces one has to ask.
    if _passkey_only(remaining):
        raise UsageError(
            f"refusing to remove slot {index}: it would leave a container whose "
            "only slot is a passkey slot, and a passkey is hardware (§4.7). "
            "Add another unlock path first."
        )
    return assemble(core, remaining, payload)


def rewrap_slot(
    container: bytes,
    index: int,
    unlock_password: Optional[str],
    new_password: str,
    *,
    unlock_keyfile: Optional[bytes] = None,
    unlock_shares: Optional[list[str]] = None,
    unlock_prf_output: Optional[bytes] = None,
    new_keyfile: Optional[bytes] = None,
    kdf_id: int = KDF_ARGON2ID,
    iterations: int = 1_000_000,
    time_cost: int = 3,
    memory_kib: int = 65_536,
    parallelism: int = 4,
    salt: Optional[bytes] = None,
    enforce_write_policy: bool = True,
    replace_slot_type: bool = False,
) -> bytes:
    """
    Re-password in place. The payload is not re-encrypted — §4's first
    consequence, and the cheapest thing the envelope buys.

    ``replace_slot_type`` is finding F8. Rewrapping always writes a passphrase
    slot, so aiming it at a Shamir slot silently converts one and every printed
    share for that set becomes scrap. Replacing a share set with a password is a
    legitimate thing to want; arriving at it by asking to re-password is not.
    """
    core, records, payload, master = recover_master_key(
        container, unlock_password, keyfile_bytes=unlock_keyfile,
        shares=unlock_shares, prf_output=unlock_prf_output)
    if not (0 <= index < len(records)):
        raise UsageError(f"no slot at index {index}")

    existing = _attemptable(records[index])
    if (existing is not None and existing.slot_type != SLOT_TYPE_PASSPHRASE
            and not replace_slot_type):
        raise UsageError(
            f"slot {index} is type 0x{existing.slot_type:02x}, not a passphrase "
            f"slot; rewrapping writes a passphrase slot, which would invalidate "
            f"every secret already issued for this one. Pass "
            f"replace_slot_type=True if that is the intent."
        )

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

def armor(container: bytes, columns: int = ARMOR_COLUMNS) -> str:
    """
    §7 ``keym2:<base64url-unpadded>``, wrapped at ``columns``.

    Line breaks are not part of the encoding — ``dearmor`` strips whitespace,
    and so does every other reader — so this is presentation only. Matching the
    TypeScript matters anyway: two implementations of one format that emit
    different text for the same container is the drift this project spends its
    conformance suite preventing.

    ``columns=0`` emits one line, for channels where every byte costs.
    """
    body = base64.urlsafe_b64encode(container).decode().rstrip("=")
    if columns > 0:
        body = "\n".join(body[i:i + columns] for i in range(0, len(body), columns))
    return ARMOR_PREFIX.decode() + body


def dearmor(text: str) -> bytes:
    """
    §7, case-sensitive per finding A2.

    Accepting ``KEYM2:`` would put back the exact collision the section removes:
    a reader sniffing four bytes would see the binary magic again.
    """
    raw = text.strip().encode("utf-8", errors="strict")
    if not raw.startswith(ARMOR_PREFIX):
        raise _reject()

    # Whitespace inside the body is removed before anything else, because the
    # padding below is computed from the body's length. A backup that arrived
    # line-wrapped — which is how most of them arrive, having been stored in a
    # notes app or printed — would otherwise have its newlines counted as
    # base64 characters, and the padding would come out wrong.
    #
    # docs/RECOVERY.md tells people line breaks are fine. This is the line that
    # makes that true, and the TypeScript's dearmorKeym2 has always done it;
    # the two had quietly diverged here.
    body = b"".join(raw[len(ARMOR_PREFIX):].split())
    try:
        # `validate=True`, because the default silently *discards* every
        # character outside the alphabet before decoding. `keym2:AAAA!!!!BBBB`
        # came back as six bytes here and threw `Invalid character` in the
        # browser — the oracle was laxer than the implementation it exists to
        # check, which is the one direction a reference must never diverge in.
        #
        # `altchars` rather than `urlsafe_b64decode` so the accepted set is
        # exactly the TypeScript's. `fromBase64Url` maps `-_` onto `+/` and
        # hands the result to `atob`, so both alphabets decode there; altchars
        # translates first and validates after, which admits the same union and
        # rejects the same rest. Verified byte-for-byte against the browser on
        # `AAAA++++BBBB`, `abc-_123` and `AAAA//AA` (accepted, identical bytes)
        # and on `AAAA!!!!BBBB` and `AA*A` (both rejected).
        return base64.b64decode(body + b"=" * (-len(body) % 4),
                                altchars=b"-_", validate=True)
    except Exception:
        raise _reject() from None


PART_PREFIX = "KMPART1:"

# KMPART1:<index>/<total>:<body>. Anchored, and the counts are bounded to four
# digits: a part claiming 90000 siblings is not a backup anyone printed, and the
# reassembler below iterates over `total`.
_PART_RE = re.compile(r"^KMPART1:(\d{1,4})/(\d{1,4}):([A-Za-z0-9_-]+)$")


def encode_parts(container: bytes, capacity: int) -> list[str]:
    """
    §7.1. Split a container across paper parts of at most ``capacity`` raw bytes.

    ``capacity`` is in *container* bytes, not encoded characters, because the
    caller's real constraint is a QR symbol's byte capacity and base64 inflates
    by 4/3. The prefix has to fit inside the symbol too — ``paper_capacity``
    does that arithmetic.

    A single-part backup is still ``1/1`` rather than plain armor: §7.1 on why
    special-casing it buys an untested branch and a drawer search.
    """
    if capacity < 1:
        raise ValueError("capacity must be at least one byte")
    if not container:
        raise ValueError("refusing to write paper parts for an empty container")

    slices = [container[i:i + capacity] for i in range(0, len(container), capacity)]
    total = len(slices)
    if total > 9999:
        raise ValueError(f"{total} parts is not a paper backup anyone will reassemble")
    return [
        f"{PART_PREFIX}{i}/{total}:" + base64.urlsafe_b64encode(s).decode().rstrip("=")
        for i, s in enumerate(slices, start=1)
    ]


def decode_parts(parts: Iterable[str]) -> bytes:
    """
    §7.1. Reassemble paper parts into the container, byte for byte.

    Every failure here is a *reassembly* failure and says so. The alternative —
    concatenating whatever arrived and letting the AEAD reject it — is
    indistinguishable to the user from a wrong password, and that is the report
    they will act on, by retyping a password they already know is right.

    No checksum, per §7.1: the AEAD covers the container, and a second integrity
    mechanism would only create a case where the two disagree.
    """
    seen: dict[int, bytes] = {}
    totals: set[int] = set()

    for raw in parts:
        text = "".join(raw.split())
        if not text:
            continue
        m = _PART_RE.match(text)
        if not m:
            raise ValueError(
                f"not a paper part: {text[:24]!r}. Parts look like "
                f"{PART_PREFIX}1/4:… — check the whole symbol scanned."
            )
        index, total = int(m.group(1)), int(m.group(2))
        if total < 1:
            raise ValueError("a part claims to be one of zero parts")
        if not 1 <= index <= total:
            raise ValueError(f"part {index} of {total} is out of range")
        if index in seen:
            raise ValueError(f"part {index} was supplied twice")
        totals.add(total)
        body = m.group(3).encode()
        seen[index] = base64.urlsafe_b64decode(body + b"=" * (-len(body) % 4))

    if not seen:
        raise ValueError("no parts supplied")
    if len(totals) != 1:
        raise ValueError(
            f"parts disagree about how many there are ({sorted(totals)}) — "
            "they are from different backups"
        )

    total = totals.pop()
    missing = [i for i in range(1, total + 1) if i not in seen]
    if missing:
        raise ValueError(
            f"missing part(s) {', '.join(map(str, missing))} of {total}. "
            "Every part is needed — this is not a k-of-n share set."
        )
    return b"".join(seen[i] for i in range(1, total + 1))


def paper_capacity(qr_byte_capacity: int, total_hint: int = 9999) -> int:
    """
    Raw container bytes that fit in one symbol of ``qr_byte_capacity`` bytes.

    Subtracts the widest prefix this run can produce, then reverses base64's 4/3
    inflation. ``total_hint`` keeps a small backup from being charged for the
    four-digit counts it will never print.
    """
    prefix = len(PART_PREFIX) + 2 * len(str(total_hint)) + 2  # index "/" total ":"
    usable = qr_byte_capacity - prefix
    if usable < 4:
        raise ValueError("symbol too small to hold a part")
    return (usable // 4) * 3


def embed_selfextract(container: bytes, columns: int = ARMOR_COLUMNS) -> str:
    """
    §7.2. The sentinel block a self-extracting page carries.

    This is the whole of what the *format* says about that artefact. The page
    around it — the decryptor, the prose, the password box — belongs to whoever
    builds it, and pinning it here would make the specification a description of
    one implementation's HTML.

    The policy check is not optional and not the caller's to skip: a page built
    around a ChaCha or Argon2id container is a file whose own decryptor cannot
    open it, and the person who finds that out is an heir with no other copy.
    """
    check_selfextract_policy(container)
    return f"{SELFEXTRACT_BEGIN}\n{armor(container, columns)}\n{SELFEXTRACT_END}"


def extract_selfextract(data: bytes | str) -> bytes:
    """
    §7.2. Recover the container from a self-extracting page.

    Decoded with ``errors="replace"`` deliberately. Both the sentinels and the
    armor are ASCII, so a stray byte anywhere else in a decade-old page — a
    mojibake filename in a comment, a smart quote saved by some editor — must
    not be what stops a backup opening.

    Zero pairs or more than one is a rejection rather than a guess. Two pairs
    means either two backups in one page or a page quoting another, and picking
    one of them is how a reader hands someone the wrong container with a
    perfectly ordinary "decryption failed" to explain it.
    """
    text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data

    if text.count(SELFEXTRACT_BEGIN) != 1:
        raise ValueError(
            f"expected exactly one {SELFEXTRACT_BEGIN} marker, found "
            f"{text.count(SELFEXTRACT_BEGIN)}"
        )
    start = text.index(SELFEXTRACT_BEGIN) + len(SELFEXTRACT_BEGIN)
    end = text.find(SELFEXTRACT_END, start)
    if end == -1:
        raise ValueError(f"{SELFEXTRACT_BEGIN} is not closed by {SELFEXTRACT_END}")

    # Only the ends, and only so the prefix check below sees the prefix — the
    # sentinels sit on their own lines. Whitespace *inside* the armor is
    # dearmor's business, and stripping it twice was a redundancy that made a
    # negative control here impossible to write: removing this loop changed
    # nothing observable, because dearmor did the same work again.
    body = body_raw.strip(ASCII_WHITESPACE) if (body_raw := text[start:end]) else ""

    # Structural failures are ValueError and crypto failures are KeymError, and
    # the split is load-bearing rather than tidy. dearmor would reject the line
    # below on its own — with "decryption failed", which a user reads as a wrong
    # password and acts on by retyping one they already know is right. The real
    # problem is that the page does not contain what it claims to. §7.1 made the
    # same argument for a short set of paper parts.
    if not body.startswith(ARMOR_PREFIX.decode()):
        raise ValueError("the marked region is not keym2: armor")
    return dearmor(body)


def looks_like_selfextract(data: bytes | str) -> bool:
    """§7.2's wrong-box paste, answered without committing to the page being valid."""
    text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
    return SELFEXTRACT_BEGIN in text


def detect(data: bytes) -> str:
    """
    §7 / §10's last checklist item: distinguish the encodings by inspecting
    bytes alone, with no dependence on the order the checks are written in.

    §7 as amended by §4.6 and §7.1: the cases are disjoint on the first *two*
    bytes — ``ke`` for v2 armor, ``KE`` for the binary magic and the legacy
    ``KEYM1:`` armor (separated from each other at byte 4), ``KM`` for an
    auxiliary artefact, ``IB`` for legacy IBTZ. ``KM`` is a family: byte 2
    separates a share (``KMS``) from a paper part (``KMP``). So this returns the same answer under any permutation of the
    branches, which is the property §7 was written to buy.

    It was one byte until the share prefix arrived. ``KMSHARE1:`` deliberately
    does not begin ``KEYM``, because that is v1's bug — ``KEYM1:`` shares all
    four magic bytes with the binary magic, so a text backup pasted into the app
    reported ``unsupported version 49``.

    A share is included here even though it is not a container, because the
    wrong-box paste is the whole reason this function exists and "this is a
    share, not a container" is the only useful thing to say about it.

    §7.2's self-extracting page is the exception to "prefix", and the comment at
    that branch explains why the exception costs nothing.
    """
    if data.startswith(ARMOR_PREFIX):
        return "keym2-armor"
    if data.startswith(b"KEYM1:"):
        return "keym1-armor"
    if data.startswith(SHARE_PREFIX.encode()):
        return "keym2-share"
    # §7.1. A part is the likeliest wrong-box paste of them all: reassembling a
    # paper backup means scanning symbols one at a time, and the first one has
    # to go somewhere. Naming it is the only useful thing to say.
    if data.startswith(PART_PREFIX.encode()):
        return "keym2-part"
    if data.startswith(MAGIC):
        return f"keym-binary-v{data[4]}" if len(data) > 4 else "keym-binary"
    if data.startswith(b"IBTZ"):
        return "ibtz"
    # §7.2. The one case detected by a substring rather than a prefix, because
    # the artefact is a whole HTML document and the container sits inside it.
    #
    # Its position in this function is not load-bearing, which is the property
    # §7 bought and this case had to keep: "<" and "!" are outside base64url,
    # outside Crockford base32, and outside all four prefixes above, so no input
    # can match both this and one of them. _selftest checks that rather than
    # trusting the paragraph.
    if looks_like_selfextract(data):
        return "keym2-selfextract"
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
    if slot.slot_type == SLOT_TYPE_PASSKEY_PRF:
        # Nothing identifies the credential, so there is nothing to print about
        # it. That absence is the §4.7 design, not missing support, and saying
        # so here is cheaper than someone concluding inspect is incomplete.
        return [
            f"  slot {index}       type 0x{slot.slot_type:02x} (passkey / WebAuthn PRF)",
            f"    kdf         HKDF-SHA-256",
            f"    salt        {slot.salt.hex()}",
            f"    credential  not stored — §4.7 keeps no identifier, so which "
            f"passkey opens this is not knowable from the file",
        ]
    if slot.slot_type == SLOT_TYPE_SHAMIR:
        # No threshold and no share count: §4.6 keeps both out of the container,
        # so inspect reports what is actually there rather than inventing it.
        # k comes off a share when one is presented.
        return [
            f"  slot {index}       type 0x{slot.slot_type:02x} (Shamir share set)",
            f"    kdf         HKDF-SHA-256",
            f"    set id      {share_set_id(slot.salt).hex()}",
            f"    salt        {slot.salt.hex()}",
        ]
    kdf = (
        f"PBKDF2-HMAC-SHA-256, iterations={slot.iterations}"
        if slot.kdf_id == KDF_PBKDF2
        else f"Argon2id, t={slot.time_cost} m={slot.memory_kib}KiB p={slot.parallelism}"
    )
    return [
        f"  slot {index}       type 0x{slot.slot_type:02x} (passphrase)",
        f"    kdf         {kdf}",
        # "required" / "not used", matching keym.py word for word.
        # docs/RECOVERY.md's troubleshooting tells a stuck user to look for
        # `required`, and that instruction has to hold for whichever of the two
        # scripts they ended up running.
        f"    key file    {'required' if slot.keyfile_used else 'not used'}",
        f"    salt        {slot.salt.hex()}",
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

    # --- §7.1: paper parts ---
    long_container = encrypt(os.urandom(5_000), pw, kdf_id=KDF_PBKDF2,
                             cipher_id=CIPHER_AES, **fast)
    parts = encode_parts(long_container, 1_734)
    check("a real container spans several paper parts", len(parts) > 1)
    check("paper parts round-trip", decode_parts(parts) == long_container)
    # The order they come off a scanner is the order someone picked them up in.
    check("parts reassemble out of order",
          decode_parts(list(reversed(parts))) == long_container)
    check("a part is recognised as a part, not as a container",
          detect(parts[0].encode()) == "keym2-part")
    check("§7.1 parts are disjoint from shares at byte 2",
          PART_PREFIX[:2] == SHARE_PREFIX[:2] and PART_PREFIX[2] != SHARE_PREFIX[2])
    check("a one-part backup still says 1/1",
          encode_parts(b"tiny", 1_734)[0].startswith("KMPART1:1/1:"))

    # Each of these produces the same symptom if it is not caught here — an
    # AEAD failure, which reads to a user as a wrong password.
    for bad, why in (
        (parts[:-1], "a missing part"),
        (parts + [parts[0]], "a duplicated part"),
        (["KMPART1:1/2:AAAA", "KMPART1:2/3:AAAA"], "parts from different backups"),
        (["KMPART1:0/1:AAAA"], "a zero index"),
        (["KMPART1:2/1:AAAA"], "an index past the total"),
        (["keym2:AAAA"], "armor supplied as a part"),
        ([], "no parts at all"),
    ):
        try:
            decode_parts(bad)
            check(f"reassembly refuses {why}", False)
        except ValueError:
            check(f"reassembly refuses {why}", True)

    check("paper_capacity leaves room for the prefix",
          len(encode_parts(long_container, paper_capacity(2_331))[0]) <= 2_331)

    # --- §7.2: the WebCrypto-only subset and the self-extracting page ---
    subset = encrypt(b"read this when I am gone", pw, kdf_id=KDF_PBKDF2,
                     cipher_id=CIPHER_AES, **fast)
    check("a PBKDF2/AES container is in the subset",
          webcrypto_profile_violations(subset) == [])

    def page(block: str) -> bytes:
        """A page shaped like the real one: the block is not the whole file."""
        return (
            "<!doctype html><html><head><title>Keymaker backup</title></head>\n"
            "<body><h1>Encrypted backup</h1>\n"
            "<p>Type the password. Nothing leaves this page.</p>\n"
            f'<pre id="keym2-container">{block}</pre>\n'
            "<p>Or run: <code>python3 keym2.py decrypt --in backup.html</code></p>\n"
            "<script>/* the decryptor */</script></body></html>\n"
        ).encode()

    embedded = page(embed_selfextract(subset))
    check("a self-extracting page round-trips",
          extract_selfextract(embedded) == subset)
    check("the extracted container decrypts",
          decrypt(extract_selfextract(embedded), pw) == b"read this when I am gone")
    check("a page is detected as a page", detect(embedded) == "keym2-selfextract")

    # §7.2's disjointness claim, checked rather than asserted in prose. If any
    # prefixed encoding could contain the sentinel, detect() would depend on the
    # order its branches are written in — which is the property §7 exists to buy.
    check("no prefixed encoding can contain the sentinel",
          not any(looks_like_selfextract(x) for x in (
              armor(subset).encode(),
              base,
              b"KEYM1:AAAA",
              encode_parts(subset, 1_734)[0].encode(),
              SHARE_PREFIX.encode() + b"ABCD-EFGH",
          )))

    # The prose says the armor stays reachable with a text editor when the
    # JavaScript does not run. That is only true if it is *text* in the page.
    check("the armor is visible text in the page, not an attribute or a script",
          armor(subset).split("\n")[0].encode() in embedded)

    # Every one of these is a page that would open its own container wrongly or
    # not at all, discovered by an heir with no second copy.
    for bad_kwargs, why in (
        (dict(kdf_id=KDF_ARGON2ID, cipher_id=CIPHER_AES), "an Argon2id slot"),
        (dict(kdf_id=KDF_PBKDF2, cipher_id=CIPHER_CHACHA), "a ChaCha20 payload"),
        (dict(kdf_id=KDF_PBKDF2, cipher_id=CIPHER_CHAINED), "a chained payload"),
    ):
        outside = encrypt(b"x", pw, **bad_kwargs, **fast)
        check(f"the subset excludes {why}", webcrypto_profile_violations(outside) != [])
        try:
            embed_selfextract(outside)
            check(f"embedding refuses {why}", False)
        except UsageError:
            check(f"embedding refuses {why}", True)

    # A key file is the one exclusion that is a choice rather than WebCrypto's
    # limit, so it gets its own check and its own reason.
    kf_container = encrypt(b"x", pw, kdf_id=KDF_PBKDF2, cipher_id=CIPHER_AES,
                           keyfile_bytes=kf, **fast)
    check("the subset excludes a key-file slot",
          any("key file" in r for r in webcrypto_profile_violations(kf_container)))

    # ValueError specifically, never KeymError. An extraction failure reported as
    # a decryption failure sends someone to retype a password that was never the
    # problem — §7.1's argument about a short set of paper parts, and the reason
    # the armor check in extract_selfextract is not redundant with dearmor's.
    for bad, why in (
        (page("").replace(SELFEXTRACT_BEGIN.encode(), b""), "a page with no marker"),
        (embedded + embedded, "two backups in one page"),
        (embedded.replace(SELFEXTRACT_END.encode(), b""), "an unclosed marker"),
        (page(f"{SELFEXTRACT_BEGIN}KMSHARE1:ABCD{SELFEXTRACT_END}"),
         "a share where the container should be"),
        (page(f"{SELFEXTRACT_BEGIN}{SELFEXTRACT_END}"), "a marked region with nothing in it"),
        (b"<html>nothing here</html>", "a page that is not one of ours"),
    ):
        try:
            extract_selfextract(bad)
            check(f"extraction refuses {why}", False)
        except ValueError:
            check(f"extraction refuses {why}", True)
        except KeymError:
            check(f"extraction refuses {why} as a page problem, not a password one",
                  False)

    # A decade-old page will not have survived unedited. None of this is allowed
    # to be what stops a backup opening.
    check("extraction survives a mojibake byte elsewhere in the page",
          extract_selfextract(embedded.replace(b"Keymaker backup",
                                               b"Sicherheitskopie \xff")) == subset)
    check("extraction survives the armor being re-wrapped",
          extract_selfextract(page(embed_selfextract(subset, columns=20))) == subset)
    check("extraction survives an unwrapped one-line armor",
          extract_selfextract(page(embed_selfextract(subset, columns=0))) == subset)

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

    # =========================================================================
    # §4.6 — Shamir share sets
    # =========================================================================

    secret32 = bytes(range(32))

    # --- the field, against AES's own published products -------------------
    check("gf_mul matches AES's worked example 0x57*0x83=0xc1",
          gf_mul(0x57, 0x83) == 0xC1)
    check("gf_mul matches AES's worked example 0x57*0x13=0xfe",
          gf_mul(0x57, 0x13) == 0xFE)
    check("gf_inv inverts every non-zero element",
          all(gf_mul(a, gf_inv(a)) == 1 for a in range(1, 256)))
    # Not a stylistic preference: §4.6 forbids the log/antilog version because
    # every value multiplied here is a share value or a coefficient, so a table
    # indexed by one is a cache-timing oracle. No test can see this, so this
    # asserts the shape of the code instead of its behaviour.
    check("gf_mul holds no lookup table",
          not any(isinstance(c, (bytes, tuple, list)) and len(c) > 16
                  for c in (gf_mul.__code__.co_consts or ())))

    # --- round-trips over the useful (k, n) space ---------------------------
    for k, n in ((2, 2), (2, 3), (3, 5), (5, 5), (8, 12), (16, 16)):
        parts = shamir_split(secret32, k, n)
        check(f"{k}-of-{n} reconstructs from the first k",
              shamir_combine(parts[:k]) == secret32)
        check(f"{k}-of-{n} reconstructs from the last k",
              shamir_combine(parts[-k:]) == secret32)

    # --- §10: k-1 shares must yield nothing ---------------------------------
    #
    # By subsets, not by citing the theorem. The theorem is about the scheme;
    # this is about the code in this file.
    import itertools
    parts35 = shamir_split(secret32, 3, 5)
    short = [shamir_combine(list(sub)) for sub in itertools.combinations(parts35, 2)]
    check("no 2-subset of a 3-of-5 split reveals the secret",
          all(s != secret32 for s in short))
    check("each 2-subset of a 3-of-5 split gives a different wrong answer",
          len(set(short)) == len(short))

    # --- §4.5's negative control: coefficients reused across byte positions --
    #
    # The failure mode is invisible to round-trip testing, so the control has to
    # be an attack. With one coefficient set shared across all 32 positions,
    # share i is the secret XOR a single repeated byte, so 256 candidates
    # exhaust it — from *one* share.
    shared_coeffs = os.urandom(32)          # 32 bytes = a_1 for one position...
    bad_split = shamir_split(               # ...reused for all 32 of them
        secret32, 3, 5,
        coefficients=bytes(shared_coeffs[c] for c in range(2) for _ in range(32)))
    check("the degenerate split still round-trips, which is why it is dangerous",
          shamir_combine(bad_split[:3]) == secret32)

    def one_share_attack(share_value: bytes) -> bool:
        """True if XOR-ing one repeated byte over a single share finds it."""
        return any(bytes(b ^ c for b in share_value) == secret32 for c in range(256))

    check("CONTROL: reusing coefficients across byte positions breaks it from one share",
          one_share_attack(bad_split[0][1]))
    check("independent coefficients survive the same attack",
          not one_share_attack(parts35[0][1]))

    # --- the share record and its text encoding -----------------------------
    set_id = share_set_id(fixed_salt)
    sh = Share(set_id=set_id, threshold=3, index=2, value=secret32)
    text = encode_share(sh)
    check("a share is 42 bytes", len(sh.pack()) == SHARE_LEN)
    check("share text is the documented shape",
          text.startswith("KMSHARE1:") and len(text) == len(SHARE_PREFIX) + 68 + 16)
    check("share text round-trips", decode_share(text) == sh)
    check("share text is entirely QR-alphanumeric",
          all(c in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:" for c in text))
    # Crockford's whole point: the characters a human confuses are accepted as
    # what they were meant to be, and case does not matter.
    # Only the body is mangled: the prefix contains a "1" of its own, and
    # KMSHAREL: is not this format.
    confusable = text[len(SHARE_PREFIX):].lower().replace("1", "l").replace("0", "o")
    check("Crockford confusables and case decode to the same share",
          decode_share(SHARE_PREFIX + confusable) == sh)
    check("whitespace and hyphens are insignificant",
          decode_share(SHARE_PREFIX + " \n".join(text[len(SHARE_PREFIX):].split("-"))) == sh)

    rejects("a share with a flipped character",
            lambda: decode_share(text[:-2] + ("Z" if text[-2] != "Z" else "Y") + text[-1]))
    rejects("a share truncated by one character", lambda: decode_share(text[:-1]))
    rejects("a share with a character outside Crockford's alphabet",
            lambda: decode_share(text[:-1] + "U"))
    # §4.6: one share, one encoding. Without this the last character has 16
    # spellings and two people cannot compare printed shares by eye.
    rejects("a share whose final character carries non-zero padding bits",
            lambda: decode_share(
                text[:-1] + B32_ALPHABET[B32_ALPHABET.index(text[-1]) | 1]))

    # --- set-level rules (§6) -----------------------------------------------
    known_secret = bytes(range(200, 232))
    _, texts35 = build_shamir_slot(CoreHeader(cipher_id=CIPHER_AES),
                                   fixed_mk, 3, 5, salt=fixed_salt,
                                   share_secret=known_secret)
    check("combine_shares recovers the secret it was built from",
          combine_shares(texts35[:3]) == known_secret)
    check("combine_shares accepts more than k",
          combine_shares(texts35) == known_secret)
    rejects("fewer shares than the threshold", lambda: combine_shares(texts35[:2]))

    # §4.6's "exactly the k lowest-indexed distinct shares", made observable.
    #
    # With genuine shares every k-subset agrees, so the rule looks like it
    # cannot be tested. Corrupt one high-indexed share — with a *valid*
    # checksum, so nothing upstream catches it — and the rule becomes the
    # difference between recovering the secret and not.
    corrupt_body = set_id + bytes([3, 5]) + bytes(32)
    corrupt5 = encode_share(parse_share(corrupt_body + _share_checksum(corrupt_body)))
    check("a corrupt high share is ignored when k good ones are present",
          combine_shares(texts35[:3] + [corrupt5]) == known_secret)
    check("...and that same corrupt share does change the answer if it is used",
          shamir_combine([(1, decode_share(texts35[0]).value),
                          (2, decode_share(texts35[1]).value),
                          (3, decode_share(texts35[2]).value),
                          (5, decode_share(corrupt5).value)]) != known_secret)
    rejects("the same share supplied twice",
            lambda: combine_shares([texts35[0], texts35[0], texts35[1]]))

    other_salt = bytes(32)
    _, other_texts = build_shamir_slot(CoreHeader(cipher_id=CIPHER_AES),
                                       fixed_mk, 3, 5, salt=other_salt)
    rejects("shares from two different sets mixed together",
            lambda: combine_shares([texts35[0], texts35[1], other_texts[2]]))
    rejects("a complete share set from the wrong slot",
            lambda: combine_shares(other_texts[:3], expected_set_id=share_set_id(fixed_salt)))

    forged = Share(set_id=set_id, threshold=4, index=4, value=secret32)
    rejects("a share set whose members disagree about k",
            lambda: combine_shares(texts35[:2] + [encode_share(forged)]))

    # Reader-side, so the bytes are forged directly with a *valid* checksum.
    # Going through Share.pack() would only prove the writer refuses to build
    # one, which is a different and much weaker claim than the reader refusing
    # to accept one somebody else built.
    def _forge_share(threshold: int, index: int) -> bytes:
        body = set_id + bytes([threshold, index]) + secret32
        return body + _share_checksum(body)

    for bad_k in (0, 1, 17, 255):
        rejects(f"a forged share declaring threshold {bad_k}",
                lambda bad_k=bad_k: parse_share(_forge_share(bad_k, 1)))
    rejects("a forged share with index zero", lambda: parse_share(_forge_share(3, 0)))
    check("a forged share that stays in bounds is still accepted",
          parse_share(_forge_share(3, 7)).index == 7)

    # Writer-side bounds raise UsageError rather than KeymError, because "you
    # asked for a 1-of-3 split" is a caller mistake and not untrusted input.
    def refuses(name: str, fn) -> None:
        try:
            fn()
            check(f"refuse {name}", False)
        except UsageError:
            check(f"refuse {name}", True)

    refuses("splitting with a threshold above the share count",
            lambda: shamir_split(secret32, 4, 3))
    refuses("splitting into more shares than the bound allows",
            lambda: shamir_split(secret32, 2, SHAMIR_N_MAX + 1))
    refuses("a 1-of-n split", lambda: shamir_split(secret32, 1, 3))
    refuses("a split of something that is not 32 bytes",
            lambda: shamir_split(secret32[:16], 2, 3))
    refuses("the wrong number of explicit coefficients",
            lambda: shamir_split(secret32, 3, 5, coefficients=os.urandom(32)))

    # --- the slot, in a container -------------------------------------------
    for cipher_id, c_name in ((CIPHER_AES, "aes"), (CIPHER_CHACHA, "chacha"),
                              (CIPHER_CHAINED, "chained")):
        msg = b"an inheritance, in " + c_name.encode()
        base = encrypt(msg, pw, kdf_id=KDF_PBKDF2, cipher_id=cipher_id, **fast)
        enrolled, share_texts = add_shamir_slot(base, pw, 3, 5)
        opens(f"{c_name}: the passphrase still opens a container after enrolment",
              lambda: decrypt(enrolled, pw), msg)
        opens(f"{c_name}: three shares open it with no password",
              lambda: decrypt(enrolled, shares=share_texts[:3]), msg)
        opens(f"{c_name}: a different three shares open it",
              lambda: decrypt(enrolled, shares=share_texts[2:5]), msg)
        rejects(f"{c_name}: two shares",
                lambda: decrypt(enrolled, shares=share_texts[:2]))
        check(f"{c_name}: the payload was not re-encrypted by enrolment",
              enrolled.endswith(base[9 + slot_len(cipher_id):]))

    # The composition the envelope exists for, exercised rather than described:
    # enrol shares holding only the password, then re-password holding only the
    # shares. Neither operation has the other's secret at any point.
    base = encrypt(b"succession", pw, kdf_id=KDF_PBKDF2, **fast)
    enrolled, share_texts = add_shamir_slot(base, pw, 2, 3)
    repassworded = rewrap_slot(enrolled, 0, None, pw2,
                               unlock_shares=share_texts[:2],
                               kdf_id=KDF_PBKDF2, **fast)
    opens("shares can re-password a slot whose password nobody has",
          lambda: decrypt(repassworded, pw2), b"succession")
    rejects("the replaced password stops working",
            lambda: decrypt(repassworded, pw))
    opens("the shares still open the re-passworded container",
          lambda: decrypt(repassworded, shares=share_texts[1:3]), b"succession")

    # Finding F8. Rewrapping writes a passphrase slot, so pointing it at the
    # share slot converts one and turns n printed papers into scrap. Refused by
    # default, because "re-password" is not a request to do that.
    refuses("rewrapping a Shamir slot without saying so",
            lambda: rewrap_slot(enrolled, 1, pw, pw2, kdf_id=KDF_PBKDF2, **fast))
    converted = rewrap_slot(enrolled, 1, pw, pw2, replace_slot_type=True,
                            kdf_id=KDF_PBKDF2, **fast)
    opens("...and does it when asked explicitly",
          lambda: decrypt(converted, pw2), b"succession")
    rejects("the shares stop working once their slot is deliberately replaced",
            lambda: decrypt(converted, shares=share_texts[:2]))

    # --- §4.4's skip rule, with a real slot type behind it for the first time
    #
    # Simulating a reader shipped before §4.6 by narrowing the implemented set.
    # The claim being tested is a data-loss claim: enrolling shares must not
    # make the container unopenable by the passphrase sitting in slot 0.
    two_slot, _ = add_shamir_slot(encrypt(b"skip me", pw, kdf_id=KDF_PBKDF2, **fast),
                                  pw, 2, 3)
    saved_types = IMPLEMENTED_SLOT_TYPES
    try:
        globals()["IMPLEMENTED_SLOT_TYPES"] = frozenset({SLOT_TYPE_PASSPHRASE})
        opens("a reader without Shamir skips the share slot and uses the passphrase",
              lambda: decrypt(two_slot, pw), b"skip me")
    finally:
        globals()["IMPLEMENTED_SLOT_TYPES"] = saved_types

    # --- §6's KDF/slot-type pairing, in both directions ----------------------
    def _prefix(slot_type: int, kdf_id: int, params: bytes) -> bytes:
        return bytes([slot_type, kdf_id, 0]) + b"\x00" * 5 + fixed_salt + params

    rejects("a passphrase slot declaring HKDF",
            lambda: parse_slot(_prefix(SLOT_TYPE_PASSPHRASE, KDF_HKDF, bytes(8))
                               + b"\x00" * 48))
    rejects("a Shamir slot declaring Argon2id",
            lambda: parse_slot(_prefix(SLOT_TYPE_SHAMIR, KDF_ARGON2ID,
                                       struct.pack(">HIBx", 1, 8, 1)) + b"\x00" * 48))
    rejects("a Shamir slot declaring PBKDF2",
            lambda: parse_slot(_prefix(SLOT_TYPE_SHAMIR, KDF_PBKDF2,
                                       struct.pack(">I4x", 1000)) + b"\x00" * 48))
    rejects("an HKDF slot with a non-zero parameter block",
            lambda: parse_slot(_prefix(SLOT_TYPE_SHAMIR, KDF_HKDF,
                                       b"\x00" * 7 + b"\x01") + b"\x00" * 48))

    # --- determinism, for the cross-implementation comparison ----------------
    fixed_secret = bytes(range(100, 132))
    fixed_coeffs = bytes(range(64))
    twice_shamir = [
        build_shamir_slot(CoreHeader(cipher_id=CIPHER_AES), fixed_mk, 3, 5,
                          salt=fixed_salt, share_secret=fixed_secret,
                          coefficients=fixed_coeffs)
        for _ in range(2)
    ]
    check("explicit secret and coefficients give byte-identical slots and shares",
          twice_shamir[0] == twice_shamir[1])
    check("a share set does not repeat itself by default",
          build_shamir_slot(CoreHeader(cipher_id=CIPHER_AES), fixed_mk, 3, 5)[1]
          != build_shamir_slot(CoreHeader(cipher_id=CIPHER_AES), fixed_mk, 3, 5)[1])

    check("a share is recognised as a share and not as a container",
          detect(text.encode()) == "keym2-share")

    # --- §4.7, the passkey slot ---------------------------------------------
    fixed_prf = bytes(range(200, 232))
    other_prf = bytes(range(1, 33))

    # The derived salt, which is the whole of what replaced a stored field.
    check("the PRF salt is derived deterministically from the slot salt",
          derive_prf_salt(fixed_salt) == derive_prf_salt(fixed_salt))
    check("a different slot salt gives a different PRF salt",
          derive_prf_salt(fixed_salt) != derive_prf_salt(bytes(32)))
    check("the PRF salt is 32 bytes",
          len(derive_prf_salt(fixed_salt)) == PRF_OUTPUT_LEN)
    # The derivation must actually transform. "Simplifying" it to return
    # slot_salt would hand the authenticator a value that is stored in the file
    # and look entirely reasonable doing it.
    check("the derived PRF salt is not the slot salt passed through",
          derive_prf_salt(fixed_salt) != fixed_salt)

    # Domain separation, a third time: one 32-byte value must not reach the same
    # slot key through two different doors.
    check("a PRF output and a share secret of the same bytes give different inputs",
          build_passkey_input(fixed_prf) != build_shamir_input(fixed_prf))

    refuses("a PRF output that is not 32 bytes",
            lambda: build_passkey_input(fixed_prf[:31]))
    refuses("a slot salt that is not 32 bytes",
            lambda: derive_prf_salt(fixed_salt[:31]))

    # §6's pairing, refused before any KDF runs.
    rejects("a passkey slot declaring PBKDF2",
            lambda: parse_slot(_prefix(SLOT_TYPE_PASSKEY_PRF, KDF_PBKDF2,
                                       struct.pack(">I4x", 1_000_000)) + b"\x00" * 48))
    rejects("a passkey slot declaring Argon2id",
            lambda: parse_slot(_prefix(SLOT_TYPE_PASSKEY_PRF, KDF_ARGON2ID,
                                       struct.pack(">IHBx", 65536, 3, 4)) + b"\x00" * 48))

    # Round trip, on a container that already has a passphrase — the only way
    # §4.7 permits a passkey slot to exist at all.
    pk_base = encrypt(b"opened by a passkey", pw, kdf_id=KDF_PBKDF2, **fast)
    pk_container = add_passkey_slot(pk_base, pw, fixed_prf)
    check("a passkey slot opens the container with its PRF output",
          decrypt(pk_container, prf_output=fixed_prf) == b"opened by a passkey")
    check("the password that was already there still opens it",
          decrypt(pk_container, pw) == b"opened by a passkey")
    rejects("the wrong PRF output",
            lambda: decrypt(pk_container, prf_output=other_prf))
    rejects("a PRF output offered to a container with no passkey slot",
            lambda: decrypt(pk_base, prf_output=fixed_prf))
    check("a passkey slot adds exactly one slot",
          len(parse_container(pk_container)[1])
          == len(parse_container(pk_base)[1]) + 1)
    check("the payload was not re-encrypted",
          parse_container(pk_container)[2] == parse_container(pk_base)[2])

    # §4.7's normative rule, from both directions that could reach it.
    refuses("removing the last non-passkey slot",
            lambda: remove_slot(pk_container, 0))
    check("removing the passkey slot itself is fine",
          len(parse_container(remove_slot(pk_container, 1))[1]) == 1)

    # Determinism, for the cross-implementation comparison.
    check("an explicit salt gives a byte-identical passkey slot",
          build_passkey_slot(CoreHeader(cipher_id=CIPHER_AES), fixed_mk,
                             fixed_prf, salt=fixed_salt)
          == build_passkey_slot(CoreHeader(cipher_id=CIPHER_AES), fixed_mk,
                                fixed_prf, salt=fixed_salt))
    check("a passkey slot does not repeat itself by default",
          build_passkey_slot(CoreHeader(cipher_id=CIPHER_AES), fixed_mk, fixed_prf)
          != build_passkey_slot(CoreHeader(cipher_id=CIPHER_AES), fixed_mk, fixed_prf))
    check("a passkey slot is the same length as every other slot",
          len(build_passkey_slot(CoreHeader(cipher_id=CIPHER_AES), fixed_mk,
                                 fixed_prf, salt=fixed_salt))
          == slot_len(CIPHER_AES))

    # --- the CLI's handling of secrets on disk and in argv -------------------
    #
    # Placed above the summary deliberately. An earlier test in this project was
    # appended below `process.exit(1)`, printed FAIL and exited 0 — unreachable
    # code that read as a passing suite.

    # Armor decoding must be exactly as strict as the browser's. Python's
    # default b64 decoder *discards* characters outside the alphabet, so
    # `keym2:AAAA!!!!BBBB` used to come back as six bytes here while
    # `dearmorKeym2` threw. A reference that accepts more than the
    # implementation it checks cannot detect the implementation being too lax.
    #
    # Every rejection probe below is chosen so the *lax* decoder accepts it. `keym2:AA*A`
    # was the first attempt and proved nothing: discarding the `*` leaves three
    # characters, so the old decoder rejected it too — on length, never on
    # validation. A negative control caught that; the cases below leave a
    # legal-length body behind after the junk is discarded, which is the only
    # shape that separates the two decoders.
    rejects("armor with characters outside the alphabet",
            lambda: dearmor("keym2:AAAA!!!!BBBB"))
    rejects("armor with interleaved junk that leaves a legal length",
            lambda: dearmor("keym2:AA!!AA!!"))
    rejects("armor with junk before the body", lambda: dearmor("keym2:$$$$AAAA"))
    # The stricter decoder must not break the promise RECOVERY.md makes: a
    # backup stored in a notes app or printed comes back line-wrapped, and
    # those newlines are stripped before validation rather than rejected by it.
    check("line-wrapped armor still decodes",
          dearmor("keym2:AAAA\n++++\nBBBB") == bytes.fromhex("000000fbefbe041041"))
    # The other half: everything the browser accepts must still decode, and to
    # the same bytes. `atob` is reached through a `-_` → `+/` rewrite, so both
    # alphabets are legal there and must be legal here.
    check("armor accepts the urlsafe alphabet",
          dearmor("keym2:abc-_123") == bytes.fromhex("69b73eff5db7"))
    check("armor accepts the standard alphabet, as the browser does",
          dearmor("keym2:AAAA++++BBBB") == bytes.fromhex("000000fbefbe041041"))
    check("armor accepts a standard-alphabet slash, as the browser does",
          dearmor("keym2:AAAA//AA") == bytes.fromhex("000000fff000"))

    # `--outfile` must not leave a secret world-readable. The decrypt path
    # writes the plaintext through this helper, so on a shared machine the mode
    # is the only thing between an heir's seed phrase and every other account.
    import stat as _stat
    import tempfile as _tempfile

    with _tempfile.TemporaryDirectory() as _d:
        _fresh = os.path.join(_d, "fresh.txt")
        with open_private(_fresh) as _fh:
            _fh.write(b"seed phrase")
        _mode = _stat.S_IMODE(os.stat(_fresh).st_mode)
        check("a new --outfile is not readable by group or other",
              _mode & 0o077 == 0)
        check("a new --outfile is still readable by its owner", _mode & 0o400 != 0)
        check("open_private actually wrote the bytes",
              open(_fresh, "rb").read() == b"seed phrase")

        # O_CREAT's mode is ignored when the path already exists, so without the
        # fchmod this case keeps whatever bits were there. Decrypting twice to
        # the same filename is the ordinary way to hit it.
        _existing = os.path.join(_d, "existing.txt")
        open(_existing, "wb").write(b"old")
        os.chmod(_existing, 0o644)
        check("the 0644 precondition really was set",
              _stat.S_IMODE(os.stat(_existing).st_mode) == 0o644)
        with open_private(_existing) as _fh:
            _fh.write(b"new plaintext")
        check("an existing world-readable --outfile is narrowed, not left alone",
              _stat.S_IMODE(os.stat(_existing).st_mode) & 0o077 == 0)

    # Key material passed as an argument is in the shell history and was in the
    # process list. --password has said so since keym.py; a share and a PRF
    # output open the container just as directly and said nothing.
    import io as _io
    import contextlib as _contextlib

    def _warns_for(**kw) -> str:
        fields = {"shares": None, "prf_output": None}
        fields.update(kw)
        ns = argparse.Namespace(**fields)
        buf = _io.StringIO()
        with _contextlib.redirect_stderr(buf):
            warn_argv_secrets(ns)
        return buf.getvalue()

    check("--share on the command line warns", "--share" in _warns_for(shares=["KMSHARE1:x"]))
    check("--prf-output on the command line warns",
          "--prf-output" in _warns_for(prf_output="ab12"))
    check("the share warning points at the file-based alternative",
          "--shares-from" in _warns_for(shares=["KMSHARE1:x"]))
    # No secret, no warning — otherwise the warning is noise and gets ignored
    # on the run where it matters.
    check("no warning when neither was passed", _warns_for() == "")

    failed = [name for name, ok in checks if not ok]
    for name, ok in checks:
        print(f"  {'ok  ' if ok else 'FAIL'} {name}")
    print()
    if failed:
        print(f"{len(failed)} of {len(checks)} checks FAILED")
        return 1
    print(f"All {len(checks)} checks passed.")
    return 0


def open_private(path: str):
    """
    Open `path` for writing, readable only by its owner.

    `open(path, "wb")` creates at 0666 & ~umask, which on a stock Linux or
    macOS account is 0644 — world-readable. On the decrypt path that file is
    the plaintext, so an heir following RECOVERY.md on a shared machine writes
    a seed phrase every other account can read, and nothing tells them.

    Applied to every `--outfile` write, not only the plaintext one. A container
    is not secret, so this is stricter than it needs to be there; one rule with
    no exceptions is the version that survives the next subcommand being added,
    where a conditional is the thing someone forgets. Widening afterwards is
    one `chmod`, and it is the user's call to make.

    O_CREAT's mode is ignored when the file already exists, so an existing 0644
    `seed.txt` would otherwise keep its bits. `fchmod` on the descriptor just
    opened covers that without the race a path-based `chmod` would have. Where
    it is unavailable or refused — Windows, a FIFO, a filesystem with no mode
    bits — the write still goes ahead: failing to narrow permissions is not a
    reason to refuse someone their own plaintext.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    if hasattr(os, "fchmod"):
        try:
            os.fchmod(fd, 0o600)
        except OSError:
            pass
    return os.fdopen(fd, "wb")


def warn_argv_secrets(args: argparse.Namespace) -> None:
    """
    Say so when key material arrived as a command-line argument.

    `--password` has warned about this since keym.py and the reason is
    unchanged for the other two: an argument is written to the shell's history
    file and is visible in `ps` to every other account on the machine for as
    long as the process runs. What differs is only how directly the argument
    opens the container. A Shamir share is one of the k pieces that
    reconstruct the master key, and a PRF output unwraps a passkey slot on its
    own — neither is a hint about a secret, both are the secret.

    `--shares-from` is the way out for shares, so the warning names it. There
    is no file-based equivalent for `--prf-output`: it comes from an
    authenticator, one invocation at a time.
    """
    if getattr(args, "shares", None):
        print(
            "warning: --share was read from the command line, so it is now in "
            "your shell history and was visible in the process list. A share is "
            "key material. Prefer --shares-from with a file only you can read.",
            file=sys.stderr,
        )
    if getattr(args, "prf_output", None):
        print(
            "warning: --prf-output was read from the command line, so it is now "
            "in your shell history and was visible in the process list. It "
            "unwraps a passkey slot on its own.",
            file=sys.stderr,
        )


def resolve_password(supplied: Optional[str], confirm: bool = False) -> str:
    """
    Prefer an interactive prompt over --password.

    Identical in behaviour to keym.py's, and identical for the same reason: a
    password passed as an argument lands in shell history and is visible in the
    process list to every other user on the machine, for as long as the KDF runs
    — which for Argon2id is seconds, by design. That is the wrong default for a
    tool whose entire job is handling someone's real secret.
    """
    if supplied is not None:
        print(
            "warning: --password was read from the command line, so it is now in "
            "your shell history and was visible in the process list. Prefer the "
            "interactive prompt for real secrets.",
            file=sys.stderr,
        )
        return supplied

    import getpass

    pw = getpass.getpass("Password: ")
    if confirm and pw != getpass.getpass("Confirm password: "):
        raise UsageError("passwords did not match")
    return pw


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="keym2.py",
        description="Independent reference implementation of the KEYM v2 container format.",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    for name in ("encrypt", "decrypt"):
        p = sub.add_parser(name, help=f"{name} a KEYM v2 container")
        # Optional, and deliberately so — see resolve_password. This mirrors
        # keym.py, and docs/RECOVERY.md tells people to use the prompt; a
        # required flag here would have made that instruction false for exactly
        # the containers the app now writes.
        p.add_argument("--password")
        p.add_argument("--key-file", help="path to the key file, if one was used")
        p.add_argument("--in", dest="infile", help="input path (default: stdin)")
        p.add_argument("--out", dest="outfile", help="output path (default: stdout)")
        p.add_argument("--armor", action="store_true",
                       help="encrypt: emit keym2: text. decrypt: expect it.")
        if name == "decrypt":
            # §4.6. Repeatable, and enough of them means no password is needed
            # at all — which is the entire point of a share set and the thing an
            # heir will be doing with this script.
            p.add_argument("--share", action="append", dest="shares", metavar="KMSHARE1:...",
                           help="a share; repeat until you have the threshold")
            p.add_argument("--shares-from", metavar="PATH",
                           help="read shares from a file, one per line")
            # §4.7. Same role as --share: a secret that is not a password, so
            # holding it means the password prompt is skipped entirely.
            p.add_argument("--prf-output", metavar="HEX",
                           help="32-byte hex WebAuthn PRF output, for a passkey slot")
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

    # §7.1. Paper parts, both directions. `split` is a convenience — the app
    # prints the kit — but `join` is the one that matters: a paper backup only
    # anyone with the app can reassemble is not a paper backup.
    spl = sub.add_parser("split", help="split a container into paper parts (§7.1)")
    spl.add_argument("--in", dest="infile", help="input path (default: stdin)")
    spl.add_argument("--out", dest="outfile", help="output path (default: stdout)")
    spl.add_argument("--armor", action="store_true", help="input is keym2: text")
    spl.add_argument("--capacity", type=int, default=1734, metavar="BYTES",
                     help="container bytes per part (default 1734: a version-40 "
                          "QR at ECC level M, which is what paper needs)")

    jn = sub.add_parser(
        "join", help="reassemble paper parts into a container (§7.1)")
    jn.add_argument("--in", dest="infile", help="file of parts, one per line (default: stdin)")
    jn.add_argument("--out", dest="outfile", help="output path (default: stdout)")
    jn.add_argument("--part", action="append", dest="parts", metavar="KMPART1:...",
                    help="a part; repeatable, and mixable with --in")
    jn.add_argument("--armor", action="store_true",
                    help="write keym2: text instead of a binary container")

    # §7.2. `extract` is the one that matters and the reason both exist: a
    # self-extracting page whose JavaScript no longer runs is still a file with a
    # container in it, and this is how it comes back out without a browser.
    ext = sub.add_parser(
        "extract",
        help="recover the container from a self-extracting page (§7.2)")
    ext.add_argument("--in", dest="infile", help="the .html page (default: stdin)")
    ext.add_argument("--out", dest="outfile", help="output path (default: stdout)")
    ext.add_argument("--armor", action="store_true",
                     help="write keym2: text instead of a binary container")

    emb = sub.add_parser(
        "embed",
        help="emit the §7.2 sentinel block for a container, checking the subset")
    emb.add_argument("--in", dest="infile", help="input path (default: stdin)")
    emb.add_argument("--out", dest="outfile", help="output path (default: stdout)")
    emb.add_argument("--armor", action="store_true", help="input is keym2: text")

    shr = sub.add_parser(
        "add-shares",
        help="enrol a k-of-n Shamir share set on an existing container (§4.6)")
    shr.add_argument("--password", help="a password that already opens the container")
    shr.add_argument("--key-file")
    shr.add_argument("--in", dest="infile", help="input path (default: stdin)")
    shr.add_argument("--out", dest="outfile", required=True,
                     help="where to write the container with the new slot")
    shr.add_argument("--threshold", type=int, required=True, metavar="K")
    shr.add_argument("--shares", type=int, required=True, metavar="N")
    shr.add_argument("--armor", action="store_true", help="input is keym2: text")
    # Conformance only, and more directly dangerous than --salt: the
    # coefficients are the only thing between one share and the secret (§4.5).
    shr.add_argument("--salt", help="32-byte hex slot salt (conformance testing only)")
    shr.add_argument("--share-secret",
                     help="32-byte hex share secret (conformance testing only)")
    shr.add_argument("--share-coefficients",
                     help="(k-1)*32 hex coefficient bytes (conformance testing only)")

    pk = sub.add_parser(
        "add-passkey",
        help="enrol a passkey slot on an existing container (§4.7)")
    pk.add_argument("--password", help="a password that already opens the container")
    pk.add_argument("--key-file")
    pk.add_argument("--in", dest="infile", help="input path (default: stdin)")
    pk.add_argument("--out", dest="outfile", required=True,
                    help="where to write the container with the new slot")
    # Not optional, and there is no way for this script to obtain it: a PRF
    # output comes from an authenticator, and Python is not a browser. The
    # recovery story for a passkey slot is the *other* slot §4.7 requires —
    # this subcommand exists so the format is exercisable and so a container
    # written by the app can be opened here given the PRF output, not because
    # a shell is a sensible place to tap a security key.
    pk.add_argument("--prf-output", required=True, metavar="HEX",
                    help="32-byte hex WebAuthn PRF output for this slot's derived salt")
    pk.add_argument("--armor", action="store_true", help="input is keym2: text")
    pk.add_argument("--salt", help="32-byte hex slot salt (conformance testing only)")

    prf = sub.add_parser(
        "prf-salt",
        help="print the PRF salt a passkey slot derives from its slot salt (§4.7)")
    prf.add_argument("--slot-salt", required=True, metavar="HEX",
                     help="32-byte hex slot salt")

    sub.add_parser("selftest", help="round-trip this implementation against itself")

    args = ap.parse_args(argv)

    # Before any work, so the warning is on screen while the KDF runs rather
    # than after the secret has already been used.
    warn_argv_secrets(args)

    if args.cmd == "selftest":
        return _selftest()

    # Before the unconditional read below: like selftest, this takes no
    # container. It exists so an implementer can check their own derivation
    # against this one without building a container first.
    if args.cmd == "prf-salt":
        try:
            print(derive_prf_salt(bytes.fromhex(args.slot_salt)).hex())
        except (ValueError, KeymError, UsageError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        return 0

    data = open(args.infile, "rb").read() if args.infile else sys.stdin.buffer.read()

    if args.cmd == "inspect":
        if detect(data) == "keym2-armor":
            data = dearmor(data.decode())
        print(_inspect(data))
        return 0

    # §7.1, before the key-file lookup: neither of these takes a credential.
    if args.cmd == "split":
        if args.armor or detect(data) == "keym2-armor":
            data = dearmor(data.decode())
        try:
            parts = encode_parts(data, args.capacity)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        text = "".join(f"# part {i} of {len(parts)}\n{p}\n"
                       for i, p in enumerate(parts, 1))
        if args.outfile:
            with open_private(args.outfile) as fh:
                fh.write(text.encode("utf-8"))
        else:
            sys.stdout.write(text)
        return 0

    if args.cmd == "join":
        supplied = list(args.parts or [])
        if args.infile or not supplied:
            supplied += [ln for ln in data.decode("utf-8", "replace").splitlines()
                         if ln.strip() and not ln.lstrip().startswith("#")]
        try:
            container = decode_parts(supplied)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        if args.armor:
            out_text = armor(container) + "\n"
            if args.outfile:
                with open_private(args.outfile) as fh:
                    fh.write(out_text.encode("utf-8"))
            else:
                sys.stdout.write(out_text)
        elif args.outfile:
            with open_private(args.outfile) as fh:
                fh.write(container)
        else:
            sys.stdout.buffer.write(container)
        return 0

    # §7.2, and beside split/join for the same reason: neither takes a credential.
    if args.cmd == "extract":
        try:
            container = extract_selfextract(data)
        except (ValueError, KeymError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        if args.armor:
            out_text = armor(container) + "\n"
            if args.outfile:
                with open_private(args.outfile) as fh:
                    fh.write(out_text.encode("utf-8"))
            else:
                sys.stdout.write(out_text)
        elif args.outfile:
            with open_private(args.outfile) as fh:
                fh.write(container)
        else:
            sys.stdout.buffer.write(container)
        return 0

    if args.cmd == "embed":
        if args.armor or detect(data) == "keym2-armor":
            data = dearmor(data.decode())
        try:
            text = embed_selfextract(data) + "\n"
        except (UsageError, KeymError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        if args.outfile:
            with open_private(args.outfile) as fh:
                fh.write(text.encode("utf-8"))
        else:
            sys.stdout.write(text)
        return 0

    keyfile = open(args.key_file, "rb").read() if args.key_file else None

    if args.cmd == "add-shares":
        if args.armor or detect(data) == "keym2-armor":
            data = dearmor(data.decode())
        try:
            container, texts = add_shamir_slot(
                data, resolve_password(args.password), args.threshold, args.shares,
                unlock_keyfile=keyfile,
                salt=bytes.fromhex(args.salt) if args.salt else None,
                share_secret=(bytes.fromhex(args.share_secret)
                              if args.share_secret else None),
                coefficients=(bytes.fromhex(args.share_coefficients)
                              if args.share_coefficients else None),
            )
        except (KeymError, UsageError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        with open_private(args.outfile) as fh:
            fh.write(container)
        # To stdout, so the shares can be piped or redirected, and never into
        # the container file. They are printed exactly once: the share secret is
        # gone by the time this returns, and nothing can reissue them.
        print(f"# {args.threshold} of these {args.shares} shares open the container.")
        print("# Each is as sensitive as the password. Anyone holding "
              f"{args.threshold} of them needs nothing else.")
        for i, t in enumerate(texts, 1):
            print(f"# share {i} of {args.shares}")
            print(t)
        return 0

    if args.cmd == "add-passkey":
        if args.armor or detect(data) == "keym2-armor":
            data = dearmor(data.decode())
        try:
            container = add_passkey_slot(
                data, resolve_password(args.password),
                bytes.fromhex(args.prf_output),
                unlock_keyfile=keyfile,
                salt=bytes.fromhex(args.salt) if args.salt else None,
            )
        except ValueError:
            print("error: --prf-output must be hex", file=sys.stderr)
            return 1
        except (KeymError, UsageError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        with open_private(args.outfile) as fh:
            fh.write(container)
        print("# A passkey slot was added. The container still opens with the "
              "password it already had —", file=sys.stderr)
        print("# §4.7 requires that, because a passkey is hardware and hardware "
              "gets lost.", file=sys.stderr)
        return 0

    shares: Optional[list[str]] = None
    prf_output: Optional[bytes] = None
    if args.cmd == "decrypt":
        shares = list(args.shares or [])
        if args.shares_from:
            shares += [ln.strip() for ln in open(args.shares_from, encoding="utf-8")
                       if ln.strip() and not ln.lstrip().startswith("#")]
        if args.prf_output:
            try:
                prf_output = bytes.fromhex(args.prf_output)
            except ValueError:
                print("error: --prf-output must be hex", file=sys.stderr)
                return 1

    try:
        # With enough shares in hand the password prompt would be a dead end —
        # an heir does not have one. Skipping it is the difference between this
        # script being usable for inheritance and merely supporting it.
        password = (None if (shares or prf_output)
                    else resolve_password(args.password,
                                          confirm=(args.cmd == "encrypt")))
    except UsageError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    try:
        if args.cmd == "encrypt":
            out = encrypt(
                data, password,
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
            # §7.2. Handing this script the page itself is the obvious thing for
            # an heir to try — it is the file they were left — so it works,
            # rather than reporting a corrupt container at the one person least
            # able to work out why.
            if detect(data) == "keym2-selfextract":
                data = extract_selfextract(data)
            elif args.armor or detect(data) == "keym2-armor":
                data = dearmor(data.decode())
            out = decrypt(data, password, keyfile_bytes=keyfile, shares=shares,
                          prf_output=prf_output)
    except (KeymError, UsageError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if args.outfile:
        # 0600. On the decrypt branch `out` is the plaintext.
        with open_private(args.outfile) as fh:
            fh.write(out)
    else:
        sys.stdout.buffer.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
