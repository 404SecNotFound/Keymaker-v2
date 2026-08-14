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
            try:
                got = keym2.decrypt(blob, fx_pw,
                                    keyfile_bytes=fx_kf if f["keyFile"] else None)
                check(f["name"], got.decode() == f["plaintext"])
            except keym2.KeymError as e:
                check(f["name"], False, str(e))
        check("v2 corpus has all six vectors", len(v2_fixtures) == 6,
              f"found {len(v2_fixtures)}")

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
        # 6. Armor agrees
        # ---------------------------------------------------------------
        print("\nText armor:")
        check("py armor round-trips", keym2.dearmor(keym2.armor(good)) == good)
        check("armor is unpadded base64url", "=" not in keym2.armor(good))
        check("armor starts with lowercase k", keym2.armor(good)[0] == "k")

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
