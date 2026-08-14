#!/usr/bin/env python3
"""
Independent reference implementation of the **KEYM v2** container format.

Written from ``docs/FORMAT-V2-DESIGN.md`` alone, before any TypeScript exists
for v2 — which is the entire point of it. The v1 reference caught KM-14 this
way: the specification documented the KDF cost parameters and never said to
bound them, so an implementer working faithfully from the prose reproduced a
vulnerability the TypeScript had already fixed. The document was the defect.

So this file is not a port. Nothing here was read off an implementation, and
where the specification failed to determine the bytes, that is recorded as a
finding rather than resolved by looking at what some other code happens to do.

  Reading order for a reviewer:
    §A  what the specification did not pin down  (the findings)
    §B  constants and bounds
    §C  header
    §D  key derivation
    §E  payload
    §F  armor and format detection
    §G  CLI and self-test

Two dependencies, pinned in requirements.txt, both for primitives only:
``cryptography`` and ``argon2-cffi``. Every format decision is in this file.


================================================================================
§A  WHAT THE SPECIFICATION DID NOT PIN DOWN
================================================================================

Four gaps. Only the first can make two conforming implementations disagree on
the bytes, and it is the reason this exercise exists.

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
project relies on — the one in §10's checklist: "Does the Python reference,
written only from this document, arrive at the same bytes as the TypeScript?"

Note the decoder is *not* ambiguous: both forms parse, unambiguously, to the
same plaintext (see ``_chunk_layout``). This is a writer-side gap only, which
is what makes it easy to miss — a round-trip test inside one implementation
passes either way.

    RESOLVED HERE AS (a): the fewest chunks that can hold the plaintext,
    i.e. ``max(1, ceil(n / CHUNK_SIZE))``.

    Reasoning: §5.1's upper bound on the final chunk is inclusive ("0 to
    1,048,576"), so a full final chunk is explicitly allowed; and the one
    boundary case the section *does* pin — "a zero-length plaintext is encoded
    as exactly one chunk" — chooses the minimum chunk count. (a) is the rule
    that generalises it. (b) requires reading the inclusive bound as exclusive,
    which contradicts the sentence.

    The specification needs one added sentence. Suggested wording:

        The number of chunks is ``max(1, ceil(len(plaintext) / 1048576))``.
        A plaintext whose length is a positive multiple of the chunk size ends
        with a full final chunk; no empty trailing chunk is emitted.

--------------------------------------------------------------------------------
A2. MINOR — the armor prefix's case sensitivity is not stated.

§7's whole argument is that one byte at offset 0 distinguishes armor from the
binary magic: lowercase ``k`` (0x6B) versus ``K`` (0x4B). A reader that
accepted ``KEYM2:`` case-insensitively would reintroduce precisely the
collision the section exists to remove, and would do so while believing it was
being helpful. The document never says the prefix is case-sensitive.

    RESOLVED HERE AS: byte-exact, case-sensitive ``keym2:``. See ``dearmor``.

--------------------------------------------------------------------------------
A3. MINOR — "Bit 0" is not defined as least- or most-significant.

§3.3 numbers the flag bits 0..7 without saying which end. Inherited from
FORMAT.md §4, which does the same. Universally read as LSB-first, and both
documents are almost certainly intended that way, but a specification that
turns on rejecting non-zero reserved bits should say which bits those are.

    RESOLVED HERE AS: bit 0 is the least significant bit, value 0x01.

--------------------------------------------------------------------------------
A4. MINOR — the character encoding of the context strings is not stated.

§4.1 writes ``LP("keymaker.v2.kdf-input")`` and ``SHA-256("keymaker.v2.keyfile"
|| ...)`` without saying how the literals become bytes. Both are pure ASCII so
every plausible choice agrees, but the password in the same expression *is*
given an explicit encoding ("NFC_UTF8"), which invites the reader to wonder
whether the omission next to it is meaningful.

    RESOLVED HERE AS: ASCII, which is byte-identical to UTF-8 for these
    literals.

--------------------------------------------------------------------------------
Not a defect, but worth a sentence in the document: ``keyfile_digest`` is the
one place §4.1 concatenates without a length prefix, in a section whose subject
is that unprefixed concatenation is ambiguous. It is fine — the prefix is a
fixed constant, so ``k -> "keymaker.v2.keyfile" || k`` is injective — but every
careful reader will stop on it, and saying so costs one line.
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
from typing import Iterator, Optional

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

HEADER_LEN = 48          # §3, fixed — no length field, by design
SALT_LEN = 32            # §3, both KDFs
KDF_PARAM_LEN = 8        # §3.2
MASTER_KEY_LEN = 32      # §4.3
NONCE_LEN = 12           # §5.2, uint88 counter || flag byte
TAG_LEN = 16             # AES-GCM and Poly1305 alike

# §5.1. A constant of the format, deliberately not a header field: a header
# field would be an attacker-controlled allocation size read before
# authentication.
CHUNK_SIZE = 1024 * 1024

KDF_PBKDF2 = 0x00
KDF_ARGON2ID = 0x01
CIPHER_AES = 0x00
CIPHER_CHACHA = 0x01
CIPHER_CHAINED = 0x02

FLAG_KEYFILE = 0x01      # §3.3 bit 0 — see finding A3
FLAG_RESERVED_MASK = 0xFE

ARMOR_PREFIX = b"keym2:"  # §7 — case-sensitive, see finding A2

# §4.1 / §4.3 domain separation. ASCII, see finding A4.
CTX_KDF_INPUT = b"keymaker.v2.kdf-input"
CTX_KEYFILE = b"keymaker.v2.keyfile"
INFO_AES = b"keymaker-v2-aes"
INFO_CHACHA = b"keymaker-v2-chacha"

# §6. Upper bounds are the security control and are enforced on read; lower
# bounds are policy for new containers only, so that files written with older
# or lower settings still open.
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
    detail that distinguishes which check failed." A caller cannot learn
    whether the password was wrong, a reserved bit was set, or the payload
    length was malformed — the string is fixed at the raise site below and the
    reason never reaches it.
    """


DECRYPT_FAILED = "decryption failed"


def _reject() -> "KeymError":
    return KeymError(DECRYPT_FAILED)


class UsageError(Exception):
    """Caller error — bad CLI arguments, a policy violation when writing.

    Deliberately distinct from KeymError: refusing to *write* a container with
    a 5-iteration PBKDF2 is a message to the operator, not an oracle for an
    attacker holding someone else's file.
    """


# =============================================================================
# §C  HEADER
# =============================================================================

@dataclass(frozen=True)
class Header:
    kdf_id: int
    cipher_id: int
    flags: int
    salt: bytes
    # PBKDF2
    iterations: int = 0
    # Argon2id
    time_cost: int = 0
    memory_kib: int = 0
    parallelism: int = 0

    @property
    def keyfile_used(self) -> bool:
        return bool(self.flags & FLAG_KEYFILE)

    @property
    def tag_overhead(self) -> int:
        """Bytes of tag per chunk. §5.1: 16, or 32 for chained."""
        return TAG_LEN * 2 if self.cipher_id == CIPHER_CHAINED else TAG_LEN

    def pack(self) -> bytes:
        if self.kdf_id == KDF_PBKDF2:
            params = struct.pack(">I4x", self.iterations)
        elif self.kdf_id == KDF_ARGON2ID:
            params = struct.pack(">HIBx", self.time_cost, self.memory_kib, self.parallelism)
        else:
            raise UsageError(f"unknown kdf_id {self.kdf_id}")
        assert len(params) == KDF_PARAM_LEN
        out = MAGIC + bytes([VERSION, self.kdf_id, self.cipher_id, self.flags]) + self.salt + params
        assert len(out) == HEADER_LEN
        return out


def parse_header(data: bytes) -> Header:
    """
    Parse and fully validate the 48-byte header.

    §6 requires every one of these checks to run *before* the KDF is invoked,
    which is why parsing and validation are the same function: there is no way
    to obtain a Header that has not been bounds-checked, so no caller can
    forget. That is the structural answer to KM-14 — the v1 reference bounded
    nothing because the prose never told it to, and nothing about the shape of
    the code made the omission visible.
    """
    if len(data) < HEADER_LEN:
        raise _reject()

    if data[:4] != MAGIC:
        raise _reject()
    if data[4] != VERSION:
        raise _reject()

    kdf_id = data[5]
    cipher_id = data[6]
    flags = data[7]
    salt = data[8:40]
    params = data[40:48]

    if cipher_id not in (CIPHER_AES, CIPHER_CHACHA, CIPHER_CHAINED):
        raise _reject()

    # §3.3 — stricter than v1, which says ignore. A non-zero reserved bit
    # cannot be attacker-introduced without failing authentication (the header
    # is AAD), so it can only have been written deliberately by a writer that
    # believed it meant something. Decrypting anyway would be decrypting under
    # an interpretation the author did not intend.
    if flags & FLAG_RESERVED_MASK:
        raise _reject()

    if kdf_id == KDF_PBKDF2:
        (iterations,) = struct.unpack(">I", params[:4])
        if params[4:] != b"\x00\x00\x00\x00":        # §3.2 reserved
            raise _reject()
        if not (PBKDF2_ITER_MIN <= iterations <= PBKDF2_ITER_MAX):
            raise _reject()
        return Header(kdf_id, cipher_id, flags, salt, iterations=iterations)

    if kdf_id == KDF_ARGON2ID:
        time_cost, memory_kib, parallelism = struct.unpack(">HIB", params[:7])
        if params[7] != 0:                            # §3.2 reserved
            raise _reject()
        if not (ARGON2_TIME_MIN <= time_cost <= ARGON2_TIME_MAX):
            raise _reject()
        if not (ARGON2_MEM_MIN <= memory_kib <= ARGON2_MEM_MAX):
            raise _reject()
        if not (ARGON2_PAR_MIN <= parallelism <= ARGON2_PAR_MAX):
            raise _reject()
        return Header(
            kdf_id, cipher_id, flags, salt,
            time_cost=time_cost, memory_kib=memory_kib, parallelism=parallelism,
        )

    raise _reject()


def check_write_policy(header: Header) -> None:
    """§6's lower bounds. Writing only — a reader stays permissive."""
    if header.kdf_id == KDF_PBKDF2 and header.iterations < PBKDF2_ITER_POLICY_MIN:
        raise UsageError(
            f"refusing to write PBKDF2 with {header.iterations} iterations; "
            f"policy minimum is {PBKDF2_ITER_POLICY_MIN}"
        )
    if header.kdf_id == KDF_ARGON2ID and header.memory_kib < ARGON2_MEM_POLICY_MIN:
        raise UsageError(
            f"refusing to write Argon2id with memory_kib={header.memory_kib}; "
            f"policy minimum is {ARGON2_MEM_POLICY_MIN}"
        )


# =============================================================================
# §D  KEY DERIVATION
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
    §4.1. Injective over ``(password, key file)`` pairs.

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


def derive_master_key(header: Header, kdf_input: bytes) -> bytes:
    """§4.3. Assumes `header` came from parse_header, i.e. is already bounded."""
    if header.kdf_id == KDF_PBKDF2:
        return PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=MASTER_KEY_LEN,
            salt=header.salt,
            iterations=header.iterations,
        ).derive(kdf_input)

    if header.kdf_id == KDF_ARGON2ID:
        return hash_secret_raw(
            secret=kdf_input,
            salt=header.salt,
            time_cost=header.time_cost,
            memory_cost=header.memory_kib,
            parallelism=header.parallelism,
            hash_len=MASTER_KEY_LEN,
            type=Argon2Type.ID,
            version=0x13,  # RFC 9106 / Argon2 v1.3
        )

    raise _reject()


def subkeys(header: Header, master_key: bytes) -> tuple[bytes, bytes]:
    """
    §4.3. For chained mode, two independent 32-byte subkeys.

    "Zero salt" is passed explicitly rather than as ``salt=None``. The two are
    identical by construction — RFC 5869 substitutes HashLen zeros for an
    absent salt, and HMAC pads any short key with zeros to the block size, so
    an empty salt and a 32-zero-byte salt produce the same PRK — but writing it
    out means a second implementer does not have to work that out to be sure
    they match.
    """
    if header.cipher_id != CIPHER_CHAINED:
        return master_key, master_key

    def expand(info: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=MASTER_KEY_LEN,
            salt=b"\x00" * 32,
            info=info,
        ).derive(master_key)

    return expand(INFO_AES), expand(INFO_CHACHA)


# =============================================================================
# §E  PAYLOAD
# =============================================================================

def nonce_for(index: int, is_final: bool) -> bytes:
    """
    §5.2 ``nonce_i = uint88_be(i) || final_flag``.

    11 bytes of counter and one flag byte. The counter cannot overflow within
    any container this implementation will accept: 2^88 chunks of 1 MiB is
    2^108 bytes, so the checklist's "no counter overflow reachable" holds by
    an enormous margin rather than by an argument.

    Deterministic counter nonces are safe because the key is per-file: a fresh
    random salt gives a fresh master key for every container, so no
    (key, nonce) pair is ever reused.
    """
    if index < 0 or index >= (1 << 88):
        raise _reject()
    return index.to_bytes(11, "big") + (b"\x01" if is_final else b"\x00")


def _chunk_layout(payload_len: int, tag_overhead: int) -> list[int]:
    """
    Recover the plaintext length of each chunk from the payload length alone.

    §6: "reject a payload whose length is not a valid chunk sequence for the
    declared cipher's tag overhead."

    A payload is chunks 0..m-1, m >= 1, where chunks 0..m-2 each carry
    CHUNK_SIZE plaintext bytes and chunk m-1 carries r, 0 <= r <= CHUNK_SIZE:

        payload_len = (m-1) * (CHUNK_SIZE + tag) + r + tag

    so with ``q, rem = divmod(payload_len - tag, CHUNK_SIZE + tag)`` we get
    m-1 = q and r = rem, valid exactly when rem <= CHUNK_SIZE. A remainder in
    (CHUNK_SIZE, CHUNK_SIZE + tag) is a truncated or padded payload and is
    rejected.

    This parse accepts both encodings described in finding A1, and does so
    unambiguously — which is why A1 is a writer-side gap that a round-trip test
    inside a single implementation cannot detect.
    """
    if payload_len < tag_overhead:
        raise _reject()
    q, rem = divmod(payload_len - tag_overhead, CHUNK_SIZE + tag_overhead)
    if rem > CHUNK_SIZE:
        raise _reject()
    return [CHUNK_SIZE] * q + [rem]


def _split_plaintext(plaintext: bytes) -> list[bytes]:
    """
    §5.1, resolved per finding A1: the fewest chunks that can hold it.

    A zero-length plaintext is one chunk of zero bytes, which §5.1 states
    outright; a plaintext that is a positive multiple of CHUNK_SIZE ends with a
    *full* final chunk and no empty trailing chunk, which §5.1 does not state
    and should.
    """
    if not plaintext:
        return [b""]
    count = math.ceil(len(plaintext) / CHUNK_SIZE)
    return [plaintext[i * CHUNK_SIZE:(i + 1) * CHUNK_SIZE] for i in range(count)]


def _seal(header: Header, aes_key: bytes, chacha_key: bytes,
          nonce: bytes, chunk: bytes, aad: bytes) -> bytes:
    """§5.4. Chained is AES inner, ChaCha outer — both under the same nonce,
    which is not a reuse because the keys are independently derived."""
    if header.cipher_id == CIPHER_AES:
        return AESGCM(aes_key).encrypt(nonce, chunk, aad)
    if header.cipher_id == CIPHER_CHACHA:
        return ChaCha20Poly1305(chacha_key).encrypt(nonce, chunk, aad)
    inner = AESGCM(aes_key).encrypt(nonce, chunk, aad)
    return ChaCha20Poly1305(chacha_key).encrypt(nonce, inner, aad)


def _open(header: Header, aes_key: bytes, chacha_key: bytes,
          nonce: bytes, blob: bytes, aad: bytes) -> bytes:
    """§5.4. Chained verifies the outer layer before the inner one."""
    try:
        if header.cipher_id == CIPHER_AES:
            return AESGCM(aes_key).decrypt(nonce, blob, aad)
        if header.cipher_id == CIPHER_CHACHA:
            return ChaCha20Poly1305(chacha_key).decrypt(nonce, blob, aad)
        inner = ChaCha20Poly1305(chacha_key).decrypt(nonce, blob, aad)
        return AESGCM(aes_key).decrypt(nonce, inner, aad)
    except Exception:
        raise _reject() from None


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
    enforce_write_policy: bool = True,
) -> bytes:
    header = Header(
        kdf_id=kdf_id,
        cipher_id=cipher_id,
        flags=FLAG_KEYFILE if keyfile_bytes is not None else 0,
        salt=salt if salt is not None else os.urandom(SALT_LEN),
        iterations=iterations,
        time_cost=time_cost,
        memory_kib=memory_kib,
        parallelism=parallelism,
    )
    if len(header.salt) != SALT_LEN:
        raise UsageError("salt must be 32 bytes")
    if enforce_write_policy:
        check_write_policy(header)

    aad = header.pack()
    # Round-trip the header through the reader's own validator before using it.
    # A writer that can emit a container its own parser rejects is a bug worth
    # catching here rather than in a user's hands.
    parse_header(aad)

    master = derive_master_key(header, build_kdf_input(password, keyfile_bytes))
    aes_key, chacha_key = subkeys(header, master)

    chunks = _split_plaintext(plaintext)
    out = [aad]
    for i, chunk in enumerate(chunks):
        out.append(_seal(header, aes_key, chacha_key,
                         nonce_for(i, i == len(chunks) - 1), chunk, aad))
    return b"".join(out)


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
    A streaming caller must write to a temporary destination and commit only on
    a clean return.
    """
    header = parse_header(container)          # every §6 check, before the KDF
    aad = container[:HEADER_LEN]
    payload = container[HEADER_LEN:]

    tag = header.tag_overhead
    sizes = _chunk_layout(len(payload), tag)  # also before the KDF

    master = derive_master_key(header, build_kdf_input(password, keyfile_bytes))
    aes_key, chacha_key = subkeys(header, master)

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
        # was sealed with 0) fails authentication. Truncation exactly on a
        # chunk boundary is the case this catches that a length check cannot.
        out.append(_open(header, aes_key, chacha_key,
                         nonce_for(i, i == last), blob, aad))

    if offset != len(payload):
        raise _reject()
    return b"".join(out)


# =============================================================================
# §F  ARMOR AND FORMAT DETECTION
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
    same answer under any permutation of the branches. That is the property
    §7 was written to buy, and it is worth asserting rather than assuming:
    v1's ``KEYM1:`` armor shares all four magic bytes, which is the bug.
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
# §G  CLI AND SELF-TEST
# =============================================================================

def _inspect(container: bytes) -> str:
    h = parse_header(container)
    payload = len(container) - HEADER_LEN
    sizes = _chunk_layout(payload, h.tag_overhead)
    kdf = (
        f"PBKDF2-HMAC-SHA-256, iterations={h.iterations}"
        if h.kdf_id == KDF_PBKDF2
        else f"Argon2id, t={h.time_cost} m={h.memory_kib}KiB p={h.parallelism}"
    )
    cipher = {
        CIPHER_AES: "AES-256-GCM",
        CIPHER_CHACHA: "ChaCha20-Poly1305",
        CIPHER_CHAINED: "chained (AES-256-GCM then ChaCha20-Poly1305)",
    }[h.cipher_id]
    return "\n".join([
        "KEYM v2",
        f"  kdf         {kdf}",
        f"  cipher      {cipher}",
        f"  key file    {'yes' if h.keyfile_used else 'no'}",
        f"  salt        {h.salt.hex()}",
        f"  chunks      {len(sizes)} ({sum(sizes)} plaintext bytes)",
    ])


def _selftest() -> int:
    """
    Round-trips, plus the four questions in §10's checklist that can be
    answered by execution rather than by reading.

    Cheap parameters throughout: this exercises the *format*, and paying for
    real Argon2id costs would only make it something nobody runs.
    """
    checks: list[tuple[str, bool]] = []

    def check(name: str, ok: bool) -> None:
        checks.append((name, ok))

    pw = "correct horse battery staple"
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
    blob = encrypt(b"\x00" * CHUNK_SIZE, pw, kdf_id=KDF_PBKDF2, cipher_id=CIPHER_AES, **fast)
    check("A1: exact multiple is one chunk",
          len(blob) == HEADER_LEN + CHUNK_SIZE + TAG_LEN)
    check("A1: one chunk over is two chunks",
          len(encrypt(b"\x00" * (CHUNK_SIZE + 1), pw, kdf_id=KDF_PBKDF2,
                      cipher_id=CIPHER_AES, **fast))
          == HEADER_LEN + CHUNK_SIZE + TAG_LEN + 1 + TAG_LEN)

    # --- checklist: is kdf_input injective? ---
    #
    # Tested at the layer that actually carries the property. Comparing two
    # build_kdf_input() results is not that layer: §4.2 hashes the key file to
    # a fixed 32 bytes, and a fixed-width field cannot slide, so the classic
    # ("ab","c") vs ("a","bc") collision is already closed by the digest alone
    # — those two inputs differ whether or not lp() prefixes anything. A
    # negative control proved it: stubbing lp() to the identity left all 46
    # checks green.
    #
    # What the length prefixes buy is injectivity of the *concatenation* for
    # variable-length fields, which is what keeps the encoding sound as fields
    # are added, and which does fail without them.
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
        ("truncated on a chunk boundary", HEADER_LEN + 2 * (CHUNK_SIZE + TAG_LEN)),
        ("truncated to one chunk", HEADER_LEN + CHUNK_SIZE + TAG_LEN),
        ("payload removed entirely", HEADER_LEN),
    ):
        try:
            decrypt(blob[:cut], pw)
            check(f"reject {label}", False)
        except KeymError:
            check(f"reject {label}", True)

    # Appending a plausible extra chunk must fail too — the previously-final
    # chunk was sealed with final_flag = 1 and is now opened with 0.
    try:
        decrypt(blob + b"\x00" * (CHUNK_SIZE + TAG_LEN), pw)
        check("reject appended chunk", False)
    except KeymError:
        check("reject appended chunk", True)

    # --- checklist: can a chunk from container A verify inside container B? ---
    a = encrypt(b"A" * 64, pw, kdf_id=KDF_PBKDF2, cipher_id=CIPHER_AES, **fast)
    b = encrypt(b"B" * 64, pw, kdf_id=KDF_PBKDF2, cipher_id=CIPHER_AES, **fast)
    spliced = b[:HEADER_LEN] + a[HEADER_LEN:]
    try:
        decrypt(spliced, pw)
        check("reject chunk spliced between containers", False)
    except KeymError:
        check("reject chunk spliced between containers", True)

    # --- header tamper sweep: every byte of the header is AAD ---
    base = encrypt(b"tamper me", pw, kdf_id=KDF_PBKDF2, cipher_id=CIPHER_AES, **fast)
    survivors = []
    for i in range(HEADER_LEN):
        mutated = bytearray(base)
        mutated[i] ^= 0x01
        try:
            decrypt(bytes(mutated), pw)
            survivors.append(i)
        except KeymError:
            pass
    check(f"every header byte is authenticated (survivors: {survivors})", not survivors)

    # --- §6: reserved fields and bounds are rejected ---
    def mutate(index: int, value: int) -> bytes:
        m = bytearray(base)
        m[index] = value
        return bytes(m)

    # A crafted container whose header is *internally consistent*: the
    # reserved field is non-zero and the payload was sealed under that exact
    # header, so the AAD matches and authentication would succeed.
    #
    # This is the only way to test §3.3's fail-closed rule. Simply flipping a
    # reserved bit in a finished container proves nothing — the header is AAD,
    # so it fails on the tag whether or not the reader checks reserved fields
    # at all. A negative control proved that too: removing both reserved-field
    # checks left all 46 checks green.
    def forge_with_reserved(hdr: bytes) -> bytes:
        """Seal a payload under a header this implementation refuses to write."""
        fake = Header(kdf_id=KDF_PBKDF2, cipher_id=CIPHER_AES, flags=hdr[7],
                      salt=hdr[8:40], iterations=struct.unpack(">I", hdr[40:44])[0])
        master = derive_master_key(fake, build_kdf_input(pw, None))
        aes_key, chacha_key = subkeys(fake, master)
        return hdr + _seal(fake, aes_key, chacha_key, nonce_for(0, True), b"forged", hdr)

    hdr_reserved_flag = bytearray(base[:HEADER_LEN]); hdr_reserved_flag[7] = 0x02
    hdr_reserved_kdf = bytearray(base[:HEADER_LEN]); hdr_reserved_kdf[44] = 0x01

    for label, blob2 in (
        ("sealed container with a reserved flag bit",
         forge_with_reserved(bytes(hdr_reserved_flag))),
        ("sealed container with non-zero KDF reserved bytes",
         forge_with_reserved(bytes(hdr_reserved_kdf))),
        ("reserved flag bit", mutate(7, 0x02)),
        ("PBKDF2 reserved bytes", mutate(44, 0x01)),
        ("iterations = 0", base[:40] + b"\x00\x00\x00\x00" + base[44:]),
        ("iterations over cap", base[:40] + struct.pack(">I", 10_000_001) + base[44:]),
        ("unknown cipher_id", mutate(6, 0x09)),
        ("wrong version", mutate(4, 0x03)),
    ):
        try:
            decrypt(blob2, pw)
            check(f"reject {label}", False)
        except KeymError:
            check(f"reject {label}", True)

    # --- §7: armor round-trip and order-independent detection ---
    check("armor round-trips", dearmor(armor(base)) == base)
    check("armor is unpadded base64url", "=" not in armor(base))
    check("armor prefix is case-sensitive", detect(b"KEYM2:abc") != "keym2-armor")
    check("v2 armor detected", detect(armor(base).encode()) == "keym2-armor")
    check("binary detected", detect(base) == "keym-binary-v2")
    check("v1 armor no longer collides with the magic",
          detect(b"KEYM1:AAAA") == "keym1-armor")
    # The property §7 buys: byte 0 alone separates armor from binary.
    check("armor and magic differ at byte 0", armor(base).encode()[0] != MAGIC[0])

    # --- wrong credentials ---
    for label, kwargs in (
        ("wrong password", dict(password="nope")),
        ("missing key file", dict(password=pw, keyfile_bytes=None)),
    ):
        blob3 = encrypt(b"x", pw, kdf_id=KDF_PBKDF2, cipher_id=CIPHER_AES,
                        keyfile_bytes=kf, **fast)
        try:
            decrypt(blob3, kwargs.get("password", pw),
                    keyfile_bytes=kwargs.get("keyfile_bytes"))
            check(f"reject {label}", False)
        except KeymError as e:
            check(f"reject {label}", str(e) == DECRYPT_FAILED)

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
            # Conformance only. Byte-equality against the TypeScript is the
            # only check that catches a chunking or nonce disagreement — both
            # implementations decode each other's output happily even when
            # they disagree about how to write it — and comparing bytes needs
            # a shared salt. Reusing one with the same password reuses every
            # (key, nonce) pair in the container, so this is not something to
            # use on real data.
            p.add_argument("--salt", help="32-byte hex salt (conformance testing only)")

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
                enforce_write_policy=args.salt is None,
            )
            result = armor(out).encode() if args.armor else out
        else:
            if args.armor or detect(data) == "keym2-armor":
                data = dearmor(data.decode())
            result = decrypt(data, args.password, keyfile_bytes=keyfile)
    except (KeymError, UsageError) as e:
        print(f"keym2: {e}", file=sys.stderr)
        return 1

    if args.outfile:
        with open(args.outfile, "wb") as f:
            f.write(result)
    else:
        sys.stdout.buffer.write(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
