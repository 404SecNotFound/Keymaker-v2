#!/usr/bin/env python3
"""
KEYM v2 conformance — Python reference vs TypeScript implementation.

## Why this is a stricter test than crosstest.py

For v1, bidirectional round-trips are enough: each side encrypts, the other
decrypts, and agreement on the plaintext implies agreement on the format.

For v2 that is **not** enough, and the reference proved it before either
implementation existed. `FORMAT-V2-DESIGN.md` §5.1 originally admitted two
different chunkings for a plaintext that is an exact multiple of the chunk
size, and both of them decode correctly. Python could have written one and
TypeScript the other, round-tripped perfectly in both directions, and shipped
two mutually incompatible writers — each correctly citing the specification.

So the load-bearing check here is **byte equality**: given the same salt, master
key, password, key file and parameters, the two implementations must produce the
identical container. Both CLIs expose those two inputs only for this purpose and
both label them unsafe for real data (§4.5 — deterministic nonces make master
key reuse catastrophic).

Round-trips are still run, because byte equality alone would not catch a decoder
that disagrees with its own encoder.

## The multi-slot section is not decoration

Since the slot amendment, the rules two implementations are most likely to
diverge on are §4.4's — skip an unrecognised slot type, scope a per-slot failure
to that slot, fail only on exhaustion. Divergence there is a **data-loss** bug
rather than an interop bug: a reader that rejects instead of skipping refuses a
container whose passphrase slot is sitting valid beside the slot it did not
understand. The TypeScript has no slot-mutation API yet, so byte equality cannot
cover this; Python writes the awkward containers and TypeScript is made to read
them.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

sys.path.insert(0, str(HERE))
import keym2  # noqa: E402

PASSWORD = "correct horse battery staple 2024!"
PASSWORD2 = "the second slot's entirely separate secret"
KEYFILE = bytes(range(256)) * 4  # 1 KiB, every byte value

# §4.5 forbids both of these on real data. Pinned here because byte equality is
# impossible without them: the salt fixes the slot key, the master key fixes
# every payload byte.
SALT = bytes(range(32))
MASTER_KEY = bytes(range(32, 64))

# Cheap on purpose. This exercises the format, not the KDF; paying real Argon2id
# costs on every combination would only make it something nobody runs.
PBKDF2_ITERS = 600_000
ARGON2 = dict(time_cost=1, memory_kib=8192, parallelism=1)

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))


BRIDGE = HERE / "bridge.mjs"


class BridgeError(Exception):
    """The TypeScript side refused. Carries its stderr, not its argv."""


def bridge(*args: str) -> None:
    """
    Drive the TypeScript implementation as a black box.

    Through bridge.mjs, which esbuild-bundles bridge.mts first. Node's
    --experimental-strip-types cannot load the crypto core directly: it is
    strip-only, and `enum KdfId` is real emitted code rather than a type
    annotation. The core also lazy-imports hash-wasm and @noble/ciphers, which
    needs true ESM resolution.

    Raises BridgeError rather than CalledProcessError so a caller can report a
    disagreement as a named failing check. Using check=True meant the first
    round-trip mismatch aborted the whole run with a traceback whose argv
    included a 1 KiB key file in hex — several screens of noise in place of the
    one line saying which combination disagreed. Found by a negative control:
    reverting the v2 HKDF info strings to v1's produced exactly that.
    """
    proc = subprocess.run(
        ["node", str(BRIDGE), *args], capture_output=True, cwd=ROOT
    )
    if proc.returncode != 0:
        detail = proc.stderr.decode(errors="replace").strip().splitlines()
        raise BridgeError(detail[-1] if detail else f"exit {proc.returncode}")


def bridge_stdout(*args: str) -> str:
    """As bridge(), but hands back what the command printed.

    Only `prfsalt` needs this: it produces 32 bytes and no container, and those
    32 bytes are the one thing both implementations must agree on before either
    can ask an authenticator anything at all.
    """
    proc = subprocess.run(
        ["node", str(BRIDGE), *args], capture_output=True, cwd=ROOT
    )
    if proc.returncode != 0:
        detail = proc.stderr.decode(errors="replace").strip().splitlines()
        raise BridgeError(detail[-1] if detail else f"exit {proc.returncode}")
    return proc.stdout.decode().strip()


def kdf_flags(kdf: str) -> list[str]:
    if kdf == "argon2id":
        return ["--kdf", "argon2id", "--time", str(ARGON2["time_cost"]),
                "--mem", str(ARGON2["memory_kib"]), "--par", str(ARGON2["parallelism"])]
    return ["--kdf", "pbkdf2", "--iterations", str(PBKDF2_ITERS)]


CIPHER_IDS = {"aes": keym2.CIPHER_AES, "chacha": keym2.CIPHER_CHACHA,
              "chained": keym2.CIPHER_CHAINED}


def payload_offset(cipher: str, slots: int = 1) -> int:
    """§3. Where the chunks start — a function of two fields now, not a constant."""
    return keym2.SLOT_TABLE_OFFSET + slots * keym2.slot_len(CIPHER_IDS[cipher])


def py_encrypt(plaintext: bytes, kdf: str, cipher: str, keyfile: bytes | None,
               salt: bytes, master_key: bytes = MASTER_KEY) -> bytes:
    return keym2.encrypt(
        plaintext,
        PASSWORD,
        kdf_id=keym2.KDF_ARGON2ID if kdf == "argon2id" else keym2.KDF_PBKDF2,
        cipher_id=CIPHER_IDS[cipher],
        keyfile_bytes=keyfile,
        iterations=PBKDF2_ITERS,
        salt=salt,
        master_key=master_key,
        **ARGON2,
    )


def main() -> int:
    if shutil.which("node") is None:
        print("crosstest2: node not found", file=sys.stderr)
        return 1

    tmp = Path(tempfile.mkdtemp(prefix="keym2-cross-"))
    try:
        keyfile_path = tmp / "key.bin"
        keyfile_path.write_bytes(KEYFILE)
        keyfile_hex = KEYFILE.hex()

        # ---------------------------------------------------------------
        # 0. Frozen v2 fixtures, read by the independent implementation
        # ---------------------------------------------------------------
        #
        # The other half of crosstest.py's section 1, which now filters the
        # corpus to v1 because the v1 reference cannot read a v2 container. The
        # v2 vectors would otherwise be written by the generator and checked by
        # nothing but the TypeScript that produced them.
        print("\nFrozen v2 fixtures decrypted by the Python reference:")
        corpus = ROOT / "scripts" / "fixtures" / "keymaker"
        meta = json.loads((corpus / "fixtures.json").read_text())
        fx_pw, fx_kf = meta["password"], bytes.fromhex(meta["keyFileHex"])
        v2_fixtures = [f for f in meta["fixtures"] if f.get("version") == 2]
        for f in v2_fixtures:
            blob = (corpus / f["file"]).read_bytes()
            # §7.2. A page is a container wearing an HTML document; unwrap it and
            # it takes exactly the same checks as every other frozen vector.
            if f.get("selfextract"):
                blob = keym2.extract_selfextract(blob)
            try:
                got = keym2.decrypt(blob, fx_pw,
                                    keyfile_bytes=fx_kf if f["keyFile"] else None)
                check(f["name"], got.decode() == f["plaintext"])
            except keym2.KeymError as e:
                check(f["name"], False, str(e))

            # §4.6. The share strings in the corpus were written by the
            # TypeScript. Nothing else in this project checks that the *other*
            # implementation can use them, and that is the whole promise a share
            # fixture makes — the paper outlives whichever implementation
            # printed it.
            # §4.7. The PRF output in the corpus was written by the TypeScript.
            # Same promise as a share: the container outlives whichever
            # implementation enrolled the key, and the only way to hold anyone
            # to that is for the other implementation to open it.
            if "passkey" in f:
                prf = bytes.fromhex(f["passkey"]["prfOutputHex"])
                try:
                    got = keym2.decrypt(blob, prf_output=prf)
                    check(f"{f['name']}: python opens it with the js-written PRF output",
                          got.decode() == f["plaintext"])
                except keym2.KeymError as e:
                    check(f"{f['name']}: python opens it with the js-written PRF output",
                          False, str(e))
                try:
                    keym2.decrypt(blob, prf_output=bytes(32))
                    check(f"{f['name']}: a wrong PRF output is still refused", False)
                except keym2.KeymError:
                    check(f"{f['name']}: a wrong PRF output is still refused", True)

            if "shamir" in f:
                k = f["shamir"]["threshold"]
                shares = f["shamir"]["shares"]
                try:
                    got = keym2.decrypt(blob, shares=shares[-k:])
                    check(f"{f['name']}: python reconstructs from js-written shares",
                          got.decode() == f["plaintext"])
                except keym2.KeymError as e:
                    check(f"{f['name']}: python reconstructs from js-written shares",
                          False, str(e))
                try:
                    keym2.decrypt(blob, shares=shares[:k - 1])
                    check(f"{f['name']}: k-1 js-written shares still refused", False)
                except keym2.KeymError:
                    check(f"{f['name']}: k-1 js-written shares still refused", True)

        shamir_fixtures = [f for f in v2_fixtures if "shamir" in f]
        passkey_fixtures = [f for f in v2_fixtures if "passkey" in f]
        # Counted rather than assumed, because the corpus is append-only and a
        # fixture that silently stopped being listed would otherwise just stop
        # being tested. Update deliberately when the corpus grows.
        check("v2 corpus has all thirteen vectors: three share sets, three passkeys, one page",
              len(v2_fixtures) == 13 and len(shamir_fixtures) == 3
              and len(passkey_fixtures) == 3
              and len([f for f in v2_fixtures if f.get("selfextract")]) == 1,
              f"found {len(v2_fixtures)} v2, {len(shamir_fixtures)} shamir, "
              f"{len(passkey_fixtures)} passkey")

        # ---------------------------------------------------------------
        # 1. Byte equality — the check that catches a writer disagreement
        # ---------------------------------------------------------------
        print("\nByte equality (same salt and master key => identical container):")
        salt = SALT
        for kdf in ("pbkdf2", "argon2id"):
            for cipher in ("aes", "chacha", "chained"):
                for keyfile in (None, KEYFILE):
                    label = f"{kdf} + {cipher}" + (" + keyfile" if keyfile else "")
                    plaintext = b"conformance payload \xf0\x9f\x94\x91 " * 40

                    src = tmp / "pt.bin"
                    src.write_bytes(plaintext)
                    js_out = tmp / "js.keym2"
                    bridge("encrypt2", "--password", PASSWORD, "--in", str(src),
                           "--out", str(js_out), "--cipher", cipher, "--salt", salt.hex(),
                           "--master-key", MASTER_KEY.hex(), *kdf_flags(kdf),
                           *(["--keyfile", keyfile_hex] if keyfile else []))

                    py_bytes = py_encrypt(plaintext, kdf, cipher, keyfile, salt)
                    js_bytes = js_out.read_bytes()

                    if py_bytes == js_bytes:
                        check(label, True)
                    else:
                        # Name the first divergence — "they differ" is not
                        # actionable when the container is 2 KB of ciphertext.
                        n = min(len(py_bytes), len(js_bytes))
                        at = next((i for i in range(n) if py_bytes[i] != js_bytes[i]), n)
                        off = payload_offset(cipher)
                        if at < keym2.CORE_HEADER_LEN:
                            where = "core header"
                        elif at < keym2.SLOT_TABLE_OFFSET:
                            where = "slot_count"
                        elif at < off:
                            where = f"slot+{at - keym2.SLOT_TABLE_OFFSET}"
                        else:
                            where = f"payload+{at - off}"
                        check(label, False,
                              f"len py={len(py_bytes)} js={len(js_bytes)}, "
                              f"first difference at byte {at} ({where})")

        # ---------------------------------------------------------------
        # 2. Chunk-boundary sizes — where finding F1 lived
        # ---------------------------------------------------------------
        print("\nChunk boundaries (F1: the exact-multiple case):")
        C = keym2.CHUNK_SIZE
        for n, why in (
            (0, "empty"),
            (1, "one byte"),
            (C - 1, "one below the chunk size"),
            (C, "exactly the chunk size"),
            (C + 1, "one above the chunk size"),
            (2 * C, "exactly two chunks"),
        ):
            plaintext = bytes((i * 31 + 7) & 0xFF for i in range(n))
            src = tmp / "pt.bin"
            src.write_bytes(plaintext)
            js_out = tmp / "js.keym2"
            bridge("encrypt2", "--password", PASSWORD, "--in", str(src),
                   "--out", str(js_out), "--cipher", "aes", "--salt", salt.hex(),
                   "--master-key", MASTER_KEY.hex(), *kdf_flags("pbkdf2"))
            py_bytes = py_encrypt(plaintext, "pbkdf2", "aes", None, salt)
            js_bytes = js_out.read_bytes()
            check(f"{why} ({n} B)", py_bytes == js_bytes,
                  f"py={len(py_bytes)} js={len(js_bytes)}")

        # ---------------------------------------------------------------
        # 3. Round-trips in both directions
        # ---------------------------------------------------------------
        print("\nRound-trips (py -> js and js -> py):")
        for kdf in ("pbkdf2", "argon2id"):
            for cipher in ("aes", "chacha", "chained"):
                plaintext = f"round trip {kdf}/{cipher} éèê".encode()

                # Python writes, TypeScript reads.
                blob = tmp / "py.keym2"
                blob.write_bytes(py_encrypt(plaintext, kdf, cipher, KEYFILE,
                                            os.urandom(32), os.urandom(32)))
                got = tmp / "got.bin"
                try:
                    bridge("decrypt2", "--password", PASSWORD, "--keyfile", keyfile_hex,
                           "--in", str(blob), "--out", str(got))
                    check(f"py->js {kdf}/{cipher}", got.read_bytes() == plaintext)
                except BridgeError as e:
                    check(f"py->js {kdf}/{cipher}", False, f"js refused: {e}")

                # TypeScript writes, Python reads.
                src = tmp / "pt.bin"
                src.write_bytes(plaintext)
                js_out = tmp / "js.keym2"
                bridge("encrypt2", "--password", PASSWORD, "--keyfile", keyfile_hex,
                       "--in", str(src), "--out", str(js_out), "--cipher", cipher,
                       "--salt", os.urandom(32).hex(),
                       "--master-key", os.urandom(32).hex(), *kdf_flags(kdf))
                try:
                    check(f"js->py {kdf}/{cipher}",
                          keym2.decrypt(js_out.read_bytes(), PASSWORD, keyfile_bytes=KEYFILE)
                          == plaintext)
                except keym2.KeymError as e:
                    check(f"js->py {kdf}/{cipher}", False, f"python refused: {e}")

        # ---------------------------------------------------------------
        # 4. Rejection agrees across implementations
        # ---------------------------------------------------------------
        print("\nRejection agrees (both refuse, neither leaks which check failed):")
        # Deliberately larger than one chunk. A single-chunk container cannot
        # exercise boundary truncation at all — slicing it at
        # HEADER + CHUNK + tag returns the whole container unchanged, and the
        # case passes for the wrong reason. Caught by the test failing here
        # while the implementations were in fact correct.
        off = payload_offset("aes")
        good = py_encrypt(b"tamper me" * 250_000, "pbkdf2", "aes", None,
                          os.urandom(32), os.urandom(32))
        assert len(good) > off + 2 * (keym2.CHUNK_SIZE + 16), "need >2 chunks"

        def js_rejects(blob: bytes) -> bool:
            path = tmp / "bad.keym2"
            path.write_bytes(blob)
            try:
                bridge("decrypt2", "--password", PASSWORD, "--in", str(path),
                       "--out", str(tmp / "out.bin"))
                return False
            except BridgeError:
                return True

        def py_rejects(blob: bytes) -> bool:
            try:
                keym2.decrypt(blob, PASSWORD)
                return False
            except keym2.KeymError:
                return True

        def flip(blob: bytes, index: int, mask: int = 0x01) -> bytes:
            return blob[:index] + bytes([blob[index] ^ mask]) + blob[index + 1:]

        slot0 = keym2.SLOT_TABLE_OFFSET
        cases = {
            # Covered by the payload AAD (§5.3): the core header.
            "flipped cipher_id": flip(good, 5),
            "reserved core flag bit": good[:6] + b"\x02" + good[7:],
            "non-zero core reserved byte": flip(good, 7),
            "unknown cipher_id": good[:5] + b"\x09" + good[6:],
            # Covered by that slot's own wrap AAD (§5.3): its 48-byte prefix.
            "flipped slot reserved byte": flip(good, slot0 + 3),
            "flipped slot salt byte": flip(good, slot0 + 20),
            "flipped KDF parameter byte": flip(good, slot0 + 43),
            "flipped wrapped-key byte": flip(good, slot0 + 60),
            # Covered by neither, deliberately. §5.3's claim is not that this is
            # authenticated — it is that tampering with it can never yield a
            # master key, so the exposure stops at denial of service.
            "tampered slot_count": good[:8] + b"\x03" + good[9:],
            # The payload itself. Truncation exactly on a chunk boundary is the
            # case the final-chunk flag exists for: the payload length stays
            # valid, so only the nonce catches it.
            "flipped ciphertext byte": good[:-1] + bytes([good[-1] ^ 0x01]),
            "truncated on a chunk boundary": good[: off + keym2.CHUNK_SIZE + 16],
        }
        for label, blob in cases.items():
            check(f"{label}: both reject", js_rejects(blob) and py_rejects(blob))

        check("untampered still opens (python)", not py_rejects(good))
        check("untampered still opens (js)", not js_rejects(good))

        # ---------------------------------------------------------------
        # 5. Multi-slot: Python writes the awkward containers, TypeScript reads
        # ---------------------------------------------------------------
        #
        # §4.4's rules are the ones a second implementation is most likely to
        # get differently, and getting them differently loses data rather than
        # merely failing to interoperate: a reader that rejects an unrecognised
        # slot type instead of skipping it refuses containers whose passphrase
        # slot is valid and untouched.
        #
        # Byte equality cannot reach this — the TypeScript has no slot-mutation
        # API yet — so Python builds the containers and both sides are asked the
        # same question about each.
        print("\nMulti-slot (§4.4: skip what you cannot use, fail only on exhaustion):")
        MULTI = b"two ways in"

        def js_opens(blob: bytes, password: str) -> bool:
            path = tmp / "multi.keym2"
            path.write_bytes(blob)
            out = tmp / "multi.out"
            if out.exists():
                out.unlink()
            try:
                bridge("decrypt2", "--password", password, "--in", str(path),
                       "--out", str(out))
            except BridgeError:
                return False
            return out.read_bytes() == MULTI

        def py_opens(blob: bytes, password: str) -> bool:
            try:
                return keym2.decrypt(blob, password) == MULTI
            except keym2.KeymError:
                return False

        def retype(blob: bytes, index: int, new_type: int) -> bytes:
            at = keym2.SLOT_TABLE_OFFSET + index * keym2.slot_len(keym2.CIPHER_AES)
            return blob[:at] + bytes([new_type]) + blob[at + 1:]

        one_slot = py_encrypt(MULTI, "pbkdf2", "aes", None, os.urandom(32), os.urandom(32))
        two_slot = keym2.add_slot(one_slot, PASSWORD, PASSWORD2,
                                  kdf_id=keym2.KDF_PBKDF2, iterations=PBKDF2_ITERS)

        params_at = keym2.SLOT_TABLE_OFFSET + 40
        over_cap = (two_slot[:params_at] + (10_000_001).to_bytes(4, "big")
                    + two_slot[params_at + 4:])

        for label, blob, password, expected in (
            ("two slots, slot 0's password", two_slot, PASSWORD, True),
            ("two slots, slot 1's password", two_slot, PASSWORD2, True),
            ("unknown slot type in slot 0, slot 1 still opens",
             retype(two_slot, 0, 0x7F), PASSWORD2, True),
            ("unknown slot type in slot 1, slot 0 still opens",
             retype(two_slot, 1, 0x7F), PASSWORD, True),
            ("every slot an unknown type is the only rejection",
             retype(retype(two_slot, 0, 0x7F), 1, 0x7F), PASSWORD2, False),
            ("out-of-bounds slot 0, slot 1 still opens", over_cap, PASSWORD2, True),
            ("out-of-bounds slot 0, its own password fails", over_cap, PASSWORD, False),
        ):
            js = js_opens(blob, password)
            py = py_opens(blob, password)
            check(label, js == expected and py == expected,
                  f"js={js} py={py} expected={expected}")

        check("the payload survived slot addition byte for byte",
              two_slot[payload_offset("aes", 2):] == one_slot[payload_offset("aes", 1):])

        # ---------------------------------------------------------------
        # 6. Shamir share sets (§4.6) — byte equality, both directions
        # ---------------------------------------------------------------
        #
        # Round-trips would not settle this. Two implementations can decode each
        # other's shares perfectly while disagreeing about how to *write* them —
        # a different Horner order, a different coefficient layout, base32 padded
        # the other way — and every one of those disagreements is silent until
        # someone tries to reconstruct a set written by the other side.
        #
        # So every random input is pinned and the bytes are compared: the slot
        # record, the container, and all five share strings.
        print("\nShamir share sets (§4.6):")
        SHAMIR_MSG = b"an inheritance, byte for byte"
        SH_SALT = bytes(range(32))
        SH_SECRET = bytes(range(100, 132))
        SH_COEFFS = bytes(range(64))          # k-1 = 2 blocks of 32
        K, N = 3, 5

        base = py_encrypt(SHAMIR_MSG, "pbkdf2", "aes", None, os.urandom(32), os.urandom(32))
        base_path = tmp / "shamir-base.keym2"
        base_path.write_bytes(base)

        py_container, py_shares = keym2.add_shamir_slot(
            base, PASSWORD, K, N,
            salt=SH_SALT, share_secret=SH_SECRET, coefficients=SH_COEFFS)

        js_container_path = tmp / "shamir-js.keym2"
        js_shares_path = tmp / "shamir-js.txt"
        bridge("addshares", "--password", PASSWORD, "--in", str(base_path),
               "--out", str(js_container_path), "--shares-out", str(js_shares_path),
               "--threshold", str(K), "--shares", str(N),
               "--salt", SH_SALT.hex(), "--share-secret", SH_SECRET.hex(),
               "--share-coefficients", SH_COEFFS.hex())
        js_container = js_container_path.read_bytes()
        js_shares = [ln for ln in js_shares_path.read_text().split("\n") if ln.strip()]

        check("the enrolled container is byte-identical",
              py_container == js_container,
              f"py={len(py_container)}B js={len(js_container)}B")
        check("all five shares are byte-identical", py_shares == js_shares,
              f"first mismatch: {next((f'{a} != {b}' for a, b in zip(py_shares, js_shares) if a != b), 'none')}")
        share_slot_at = keym2.SLOT_TABLE_OFFSET + keym2.slot_len(keym2.CIPHER_AES)
        check("the new slot declares type 0x02 and kdf 0x02",
              py_container[share_slot_at] == 0x02 and py_container[share_slot_at + 1] == 0x02)
        check("its parameter block is eight reserved zero bytes",
              py_container[share_slot_at + 40:share_slot_at + 48] == bytes(8))
        check("the payload survived enrolment byte for byte",
              py_container[payload_offset("aes", 2):] == base[payload_offset("aes", 1):])

        def js_opens_with_shares(blob: bytes, shares: list[str]) -> bool:
            path = tmp / "shamir-in.keym2"
            path.write_bytes(blob)
            sf = tmp / "shamir-in.txt"
            sf.write_text("\n".join(shares) + "\n")
            out = tmp / "shamir.out"
            if out.exists():
                out.unlink()
            try:
                # No --password at all. An heir has none, and a bridge that
                # quietly supplied one would test a path nobody will walk.
                bridge("decrypt2", "--share-file", str(sf), "--in", str(path),
                       "--out", str(out))
            except BridgeError:
                return False
            return out.read_bytes() == SHAMIR_MSG

        def py_opens_with_shares(blob: bytes, shares: list[str]) -> bool:
            try:
                return keym2.decrypt(blob, shares=shares) == SHAMIR_MSG
            except keym2.KeymError:
                return False

        # Each side reads the other's output, which is the claim byte equality
        # is a proxy for and worth checking directly anyway.
        check("js opens the python container with python's shares",
              js_opens_with_shares(py_container, py_shares))
        check("python opens the js container with js's shares",
              py_opens_with_shares(js_container, js_shares))
        check("js opens with a different k of the n",
              js_opens_with_shares(py_container, py_shares[2:5]))
        check("python opens with a different k of the n",
              py_opens_with_shares(js_container, py_shares[2:5]))

        check("neither opens on k-1 shares",
              not js_opens_with_shares(py_container, py_shares[:2])
              and not py_opens_with_shares(py_container, py_shares[:2]))

        # The passphrase slot is untouched by enrolment, on both sides. This is
        # the data-loss claim: enrolling shares must not cost the owner the way
        # in they already had.
        def js_opens_with_password(blob: bytes, password: str) -> bool:
            path = tmp / "shamir-pw.keym2"
            path.write_bytes(blob)
            out = tmp / "shamir-pw.out"
            out.unlink(missing_ok=True)
            try:
                bridge("decrypt2", "--password", password, "--in", str(path), "--out", str(out))
            except BridgeError:
                return False
            return out.read_bytes() == SHAMIR_MSG

        check("the original password still opens it (js)",
              js_opens_with_password(py_container, PASSWORD))
        check("the original password still opens it (python)",
              py_opens_with_shares(py_container, py_shares)
              and keym2.decrypt(py_container, PASSWORD) == SHAMIR_MSG)

        # A share is not a container, and both sides must say so rather than
        # reporting a version error — §7 as amended by §4.6.
        check("py classifies a share as a share",
              keym2.detect(py_shares[0].encode()) == "keym2-share")

        # ---------------------------------------------------------------
        # 6b. Passkey slots (§4.7) — byte equality, both directions
        # ---------------------------------------------------------------
        #
        # Neither side can reach an authenticator, and that turns out not to
        # matter: everything §4.7 specifies happens either side of the PRF call.
        # Pinning the PRF output stands in for the key, and what is left — the
        # derived salt, the slot secret, the wrap — is exactly the part two
        # implementations can disagree about silently.
        #
        # The derived salt is checked *first* and on its own. If the two sides
        # computed different PRF salts they would ask the authenticator
        # different questions, get different answers, and every byte after that
        # would differ for a reason no container comparison would name.
        print("\nPasskey slots (§4.7):")
        PK_MSG = b"opened by a key you can hold"
        PK_SALT = bytes(range(40, 72))
        PK_PRF = bytes(range(200, 232))
        PK_WRONG_PRF = bytes(range(1, 33))

        check("both derive the same PRF salt from the same slot salt",
              bridge_stdout("prfsalt", "--slot-salt", PK_SALT.hex())
              == keym2.derive_prf_salt(PK_SALT).hex(),
              f"js={bridge_stdout('prfsalt', '--slot-salt', PK_SALT.hex())} "
              f"py={keym2.derive_prf_salt(PK_SALT).hex()}")

        pk_base = py_encrypt(PK_MSG, "pbkdf2", "aes", None, os.urandom(32), os.urandom(32))
        pk_base_path = tmp / "passkey-base.keym2"
        pk_base_path.write_bytes(pk_base)

        py_pk = keym2.add_passkey_slot(pk_base, PASSWORD, PK_PRF, salt=PK_SALT)

        js_pk_path = tmp / "passkey-js.keym2"
        bridge("addpasskey", "--password", PASSWORD, "--in", str(pk_base_path),
               "--out", str(js_pk_path), "--prf-output", PK_PRF.hex(),
               "--salt", PK_SALT.hex())
        js_pk = js_pk_path.read_bytes()

        check("the enrolled container is byte-identical", py_pk == js_pk,
              f"py={len(py_pk)}B js={len(js_pk)}B")
        pk_slot_at = keym2.SLOT_TABLE_OFFSET + keym2.slot_len(keym2.CIPHER_AES)
        check("the new slot declares type 0x01 and kdf 0x02",
              py_pk[pk_slot_at] == 0x01 and py_pk[pk_slot_at + 1] == 0x02)
        check("its parameter block is eight reserved zero bytes",
              py_pk[pk_slot_at + 40:pk_slot_at + 48] == bytes(8))
        check("the slot carries no credential id — it is the same length as any other",
              len(py_pk) == len(pk_base) + keym2.slot_len(keym2.CIPHER_AES))
        check("the payload survived enrolment byte for byte",
              py_pk[payload_offset("aes", 2):] == pk_base[payload_offset("aes", 1):])

        def js_opens_with_prf(blob: bytes, prf: bytes) -> bool:
            path = tmp / "passkey-in.keym2"
            path.write_bytes(blob)
            out = tmp / "passkey.out"
            out.unlink(missing_ok=True)
            try:
                # No --password. Someone unlocking with a passkey has none, and
                # a bridge that quietly supplied one would test a path nobody
                # walks.
                bridge("decrypt2", "--prf-output", prf.hex(),
                       "--in", str(path), "--out", str(out))
            except BridgeError:
                return False
            return out.read_bytes() == PK_MSG

        def py_opens_with_prf(blob: bytes, prf: bytes) -> bool:
            try:
                return keym2.decrypt(blob, prf_output=prf) == PK_MSG
            except keym2.KeymError:
                return False

        check("js opens the python container with the PRF output",
              js_opens_with_prf(py_pk, PK_PRF))
        check("python opens the js container with the PRF output",
              py_opens_with_prf(js_pk, PK_PRF))
        check("neither opens on the wrong PRF output",
              not js_opens_with_prf(py_pk, PK_WRONG_PRF)
              and not py_opens_with_prf(py_pk, PK_WRONG_PRF))

        # The passphrase slot is untouched, which is §4.7's whole premise: the
        # passkey is the convenient path, never the only one.
        def js_opens_passkey_container_with_password(blob: bytes) -> bool:
            # Not the Shamir block's helper: that one compares against
            # SHAMIR_MSG, so reusing it here failed for the plaintext rather
            # than for anything about passkeys.
            path = tmp / "passkey-pw.keym2"
            path.write_bytes(blob)
            out = tmp / "passkey-pw.out"
            out.unlink(missing_ok=True)
            try:
                bridge("decrypt2", "--password", PASSWORD, "--in", str(path), "--out", str(out))
            except BridgeError:
                return False
            return out.read_bytes() == PK_MSG

        check("the original password still opens it (js)",
              js_opens_passkey_container_with_password(py_pk))
        check("the original password still opens it (python)",
              keym2.decrypt(py_pk, PASSWORD) == PK_MSG)

        # §4.7's normative rule, on the side that can express it. The bridge
        # cannot reach this state either — addPasskeySlotKeym2 refuses — so the
        # check is that both refuse rather than that one does.
        pk_only_base = keym2.add_passkey_slot(pk_base, PASSWORD, PK_PRF, salt=PK_SALT)
        try:
            keym2.remove_slot(pk_only_base, 0)
            check("python refuses to leave a passkey as the only slot", False)
        except (keym2.KeymError, keym2.UsageError):
            check("python refuses to leave a passkey as the only slot", True)

        # ---------------------------------------------------------------
        # 7. Armor agrees
        # ---------------------------------------------------------------
        print("\nText armor:")
        check("py armor round-trips", keym2.dearmor(keym2.armor(good)) == good)
        check("armor is unpadded base64url", "=" not in keym2.armor(good))
        check("armor starts with lowercase k", keym2.armor(good)[0] == "k")

        # ---------------------------------------------------------------
        # 8. §7.1 paper parts agree — on the strings, not just the bytes
        # ---------------------------------------------------------------
        print("\nPaper parts (§7.1):")
        # `good` is one of the containers built above, so this is a real
        # container rather than a synthetic buffer.
        long_src = tmp / "paper-src.bin"
        long_src.write_bytes(good)

        py_parts = keym2.encode_parts(good, 1_734)
        js_parts_file = tmp / "js-parts.txt"
        bridge("split", "--in", str(long_src), "--out", str(js_parts_file),
               "--capacity", "1734")
        js_parts = [ln for ln in js_parts_file.read_text().splitlines() if ln.strip()]

        # The whole reason this compares strings: transposing a slice boundary
        # leaves both sides reassembling correctly while their printed pages are
        # mutually unusable. A container-only comparison would pass.
        check("python and js emit byte-identical paper parts", py_parts == js_parts,
              f"py {len(py_parts)} parts, js {len(js_parts)}")

        check("py reassembles js's parts", keym2.decode_parts(js_parts) == good)

        py_parts_file = tmp / "py-parts.txt"
        py_parts_file.write_text("\n".join(py_parts) + "\n")
        js_rejoined = tmp / "js-rejoined.bin"
        bridge("join", "--in", str(py_parts_file), "--out", str(js_rejoined))
        check("js reassembles python's parts", js_rejoined.read_bytes() == good)

        # A part is not a container, and §7.1 requires both sides to say which.
        check("py classifies a part as a part",
              keym2.detect(py_parts[0].encode()) == "keym2-part")

        # ---------------------------------------------------------------
        # 9. §7.2 self-extracting pages agree
        # ---------------------------------------------------------------
        #
        # The page's decryptor is JavaScript and cannot be run from here — that
        # is tests/browser/self-extract.spec.ts, in a browser, which is the only
        # environment where the claim means anything. What conformance owns is
        # the part both implementations must agree on: the *embedding*, and which
        # containers are allowed inside one.
        #
        # The failure this section exists to catch is the quiet one. A page whose
        # container the app can read and keym2.py cannot is a page that opens for
        # as long as the app exists and no longer — precisely the promise the
        # artefact was built to make, and the last thing anyone would think to
        # test.
        print("\nSelf-extracting pages (§7.2):")

        se_src = tmp / "se-pt.bin"
        se_src.write_bytes("read this when I am gone 🗝 ".encode() * 30)
        se_container = tmp / "se.keym2"
        bridge("encrypt2", "--password", PASSWORD, "--in", str(se_src),
               "--out", str(se_container), "--cipher", "aes", "--salt", SALT.hex(),
               "--master-key", MASTER_KEY.hex(), *kdf_flags("pbkdf2"))
        se_bytes = se_container.read_bytes()

        js_page = tmp / "js-page.html"
        bridge("selfextract", "--in", str(se_container), "--out", str(js_page),
               "--created-on", "2026-01-01", "--app-version", "0.0.0")
        page_text = js_page.read_text(encoding="utf-8")

        # Guarded, for the reason bridge() is: the disagreement this section
        # exists to catch — the two sides using different sentinels — makes
        # extraction *raise* rather than return a wrong answer. Unguarded, that
        # replaces the one line naming the disagreement with a traceback, and
        # skips every check below it. Found by a negative control that appeared
        # not to bite because the suite had already crashed.
        try:
            extracted = keym2.extract_selfextract(page_text)
        except (ValueError, keym2.KeymError) as e:
            extracted = None
            check("py extracts the container from a js-written page", False, str(e))
        if extracted is not None:
            check("py extracts the container from a js-written page", extracted == se_bytes)
            check("py decrypts what it extracted",
                  keym2.decrypt(extracted, PASSWORD) == se_src.read_bytes())
        check("py classifies a page as a page",
              keym2.detect(page_text.encode()) == "keym2-selfextract")

        # Both directions, and on the *string*, for the reason §7.1's parts are
        # compared as strings: two implementations that each read their own
        # embedding and not the other's would pass every round-trip test either
        # one ran against itself.
        py_block = keym2.embed_selfextract(se_bytes)
        js_block_file = tmp / "js-block.txt"
        bridge("embed", "--in", str(se_container), "--out", str(js_block_file))
        check("python and js emit byte-identical sentinel blocks",
              py_block == js_block_file.read_text(encoding="utf-8").rstrip("\n"))

        py_page = tmp / "py-page.html"
        py_page.write_text(
            "<!doctype html><html><body><pre>" + py_block + "</pre></body></html>",
            encoding="utf-8")
        js_extracted = tmp / "js-extracted.keym2"
        try:
            bridge("unselfextract", "--in", str(py_page), "--out", str(js_extracted))
            check("js extracts the container from a py-written page",
                  js_extracted.read_bytes() == se_bytes)
        except BridgeError as e:
            check("js extracts the container from a py-written page", False, str(e))

        # A page carrying two backups must be refused by both, and refused as a
        # *page* problem rather than surfacing as a decryption failure later.
        # Added because a negative control that relaxed the JS extractor's count
        # check changed nothing here — the suite only ever handed it valid pages.
        doubled = tmp / "doubled.html"
        doubled.write_text(page_text + page_text, encoding="utf-8")
        try:
            keym2.extract_selfextract(doubled.read_text(encoding="utf-8"))
            check("py refuses a page holding two backups", False)
        except ValueError:
            check("py refuses a page holding two backups", True)
        try:
            bridge("unselfextract", "--in", str(doubled), "--out", str(tmp / "no.bin"))
            check("js refuses a page holding two backups", False, "the bridge accepted it")
        except BridgeError:
            check("js refuses a page holding two backups", True)

        # §7.2's subset, enforced identically on both sides. A disagreement here
        # means one implementation writes a page the other calls impossible.
        #
        # The key-file row is here for the same reason as the doubled page above:
        # a control that removed the JS key-file check went unnoticed, because
        # every container this section built was password-only.
        for cipher, kdf, keyfile, why in (
            ("chacha", "pbkdf2", None, "a ChaCha20 payload"),
            ("chained", "pbkdf2", None, "a chained payload"),
            ("aes", "argon2id", None, "an Argon2id slot"),
            ("aes", "pbkdf2", KEYFILE, "a key-file slot"),
        ):
            outside = tmp / f"outside-{cipher}-{kdf}{'-kf' if keyfile else ''}.keym2"
            bridge("encrypt2", "--password", PASSWORD, "--in", str(se_src),
                   "--out", str(outside), "--cipher", cipher, "--salt", SALT.hex(),
                   "--master-key", MASTER_KEY.hex(), *kdf_flags(kdf),
                   *(["--keyfile", keyfile.hex()] if keyfile else []))
            blob = outside.read_bytes()
            check(f"py refuses to embed {why}",
                  keym2.webcrypto_profile_violations(blob) != [])
            try:
                bridge("profile", "--in", str(outside), "--out", str(tmp / "why.txt"))
                check(f"js refuses to embed {why}", False, "the bridge accepted it")
            except BridgeError:
                check(f"js refuses to embed {why}", True)

        check("py accepts the one container the subset allows",
              keym2.webcrypto_profile_violations(se_bytes) == [])
        try:
            bridge("profile", "--in", str(se_container), "--out", str(tmp / "why.txt"))
            check("js accepts it too", True)
        except BridgeError as e:
            check("js accepts it too", False, str(e))

        # The frozen page from the corpus — the durability claim itself, which is
        # that a page written on a particular day still gives its container up.
        se_fixtures = [f for f in v2_fixtures if f.get("selfextract")]
        check("the corpus carries a frozen self-extracting page", len(se_fixtures) == 1)
        for f in se_fixtures:
            frozen = (corpus / f["file"]).read_text(encoding="utf-8")
            try:
                got = keym2.decrypt(keym2.extract_selfextract(frozen), fx_pw)
                check(f"{f['name']}: the frozen page still opens",
                      got.decode() == f["plaintext"])
            except (keym2.KeymError, ValueError) as e:
                check(f"{f['name']}: the frozen page still opens", False, str(e))

    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    failed = [(n, d) for n, ok, d in results if not ok]
    for name, ok, detail in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {name}" + (f"   {detail}" if detail and not ok else ""))
    print()
    print(f"{len(results) - len(failed)} passed, {len(failed)} failed")
    if failed:
        print("KEYM v2 conformance FAILED — the implementations disagree.")
        return 1
    print("Conformance passed: independent implementations agree on KEYM v2, byte for byte.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
