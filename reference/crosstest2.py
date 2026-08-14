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

So the load-bearing check here is **byte equality**: given the same salt,
password, key file and parameters, the two implementations must produce the
identical container. That requires a shared salt, which both CLIs expose only
for this purpose and both label as unsafe for real data (deterministic nonces
make salt reuse catastrophic in v2 in a way it was not in v1).

Round-trips are still run, because byte equality alone would not catch a
decoder that disagrees with its own encoder.
"""
from __future__ import annotations

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
KEYFILE = bytes(range(256)) * 4  # 1 KiB, every byte value

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


def py_encrypt(plaintext: bytes, kdf: str, cipher: str, keyfile: bytes | None,
               salt: bytes) -> bytes:
    return keym2.encrypt(
        plaintext,
        PASSWORD,
        kdf_id=keym2.KDF_ARGON2ID if kdf == "argon2id" else keym2.KDF_PBKDF2,
        cipher_id={"aes": keym2.CIPHER_AES, "chacha": keym2.CIPHER_CHACHA,
                   "chained": keym2.CIPHER_CHAINED}[cipher],
        keyfile_bytes=keyfile,
        iterations=PBKDF2_ITERS,
        salt=salt,
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
        # 1. Byte equality — the check that catches a writer disagreement
        # ---------------------------------------------------------------
        print("\nByte equality (same salt, same inputs => identical container):")
        salt = bytes(range(32))
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
                           *kdf_flags(kdf),
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
                        where = ("header" if at < keym2.HEADER_LEN
                                 else f"payload+{at - keym2.HEADER_LEN}")
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
                   *kdf_flags("pbkdf2"))
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
                blob.write_bytes(py_encrypt(plaintext, kdf, cipher, KEYFILE, os.urandom(32)))
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
                       "--salt", os.urandom(32).hex(), *kdf_flags(kdf))
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
        good = py_encrypt(b"tamper me" * 250_000, "pbkdf2", "aes", None, os.urandom(32))
        assert len(good) > keym2.HEADER_LEN + 2 * (keym2.CHUNK_SIZE + 16), "need >2 chunks"

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

        cases = {
            "flipped header byte": bytes([good[7] ^ 0x02]).join([good[:7], good[8:]]),
            "flipped ciphertext byte": good[:-1] + bytes([good[-1] ^ 0x01]),
            # Truncation exactly on a chunk boundary is the case the final-chunk
            # flag exists for: the payload length stays valid, so only the nonce
            # catches it.
            "truncated on a chunk boundary": good[: keym2.HEADER_LEN + keym2.CHUNK_SIZE + 16],
            "reserved flag bit set": good[:7] + b"\x02" + good[8:],
            "unknown cipher_id": good[:6] + b"\x09" + good[7:],
        }
        for label, blob in cases.items():
            check(f"{label}: both reject", js_rejects(blob) and py_rejects(blob))

        check("untampered still opens (python)", not py_rejects(good))
        check("untampered still opens (js)", not js_rejects(good))

        # ---------------------------------------------------------------
        # 5. Armor agrees
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
