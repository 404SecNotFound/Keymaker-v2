"""
Bidirectional conformance test: the Python reference against the TypeScript
implementation.

Run with:  npm run test:conformance

Why this exists
---------------
scripts/fixtures/keymaker/ is an append-only corpus of real ciphertexts, and it
is genuinely valuable — it is what guarantees that a file encrypted by a
shipped release still opens. But every fixture in it was produced by the same
implementation that reads it back. A misreading of docs/FORMAT.md would be
encoded identically into the code and the vectors, and the suite would report
agreement forever.

reference/keym.py was written only from the specification prose. This script
makes the two implementations exchange containers in both directions. If they
disagree, one of them has misread the spec, and the spec decides which.

What it checks
--------------
  1. Python decrypts the frozen JS-generated fixtures.
  2. JS encrypts  -> Python decrypts, across all 6 KDF x cipher combinations,
     with and without a key file.
  3. Python encrypts -> JS decrypts, same matrix.
  4. Payload edge cases: empty-ish, single byte, Unicode, binary, and a size
     that crosses the AEAD block boundary.
  5. Negative: a container tampered by one implementation is rejected by the
     other, so both agree on what "authenticated" means.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from reference.keym import (  # noqa: E402
    Argon2idParams,
    CIPHER_AES_256_GCM,
    CIPHER_CHACHA20_POLY1305,
    CIPHER_CHAINED,
    KDF_ARGON2ID,
    KDF_PBKDF2,
    KeymError,
    Pbkdf2Params,
    decrypt,
    encrypt,
)

ROOT = Path(__file__).resolve().parent.parent
BRIDGE = ROOT / "reference" / "bridge.mjs"

PASSWORD = "correct horse battery staple — conformance ✅"
KEYFILE = bytes(range(64))

# Cheap but in-policy parameters. encryptData() enforces the OWASP floor on
# PBKDF2, so the cross-test has to respect it too.
PBKDF2 = Pbkdf2Params(600_000)
ARGON2 = Argon2idParams(time_cost=2, memory_kib=16384, parallelism=2)

CIPHERS = [
    ("aes", CIPHER_AES_256_GCM),
    ("chacha", CIPHER_CHACHA20_POLY1305),
    ("chained", CIPHER_CHAINED),
]
KDFS = [("pbkdf2", KDF_PBKDF2, PBKDF2), ("argon2id", KDF_ARGON2ID, ARGON2)]

PAYLOADS = {
    "single byte": b"x",
    "ascii": b"the quick brown fox jumps over the lazy dog",
    "unicode": "seed: ünïcode ✅ 日本語 — emoji 🔑".encode("utf-8"),
    "binary": bytes(range(256)) * 3,
    "block boundary": b"A" * 4096,
}

passed = 0
failed = 0


def check(ok: bool, label: str, detail: str = "") -> None:
    global passed, failed
    if ok:
        passed += 1
        print(f"  ok   {label}")
    else:
        failed += 1
        print(f"  FAIL {label}{(' — ' + detail) if detail else ''}")


def js(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["node", str(BRIDGE), *args], capture_output=True, text=True, cwd=ROOT
    )


def js_encrypt(plaintext: bytes, kdf: str, cipher: str, keyfile: bytes | None, tmp: Path) -> bytes:
    src, dst = tmp / "pt.bin", tmp / "ct.keym"
    src.write_bytes(plaintext)
    args = ["encrypt", "--password", PASSWORD, "--kdf", kdf, "--cipher", cipher,
            "--in", str(src), "--out", str(dst)]
    if kdf == "pbkdf2":
        args += ["--iterations", str(PBKDF2.iterations)]
    else:
        args += ["--time", str(ARGON2.time_cost), "--mem", str(ARGON2.memory_kib),
                 "--par", str(ARGON2.parallelism)]
    if keyfile:
        args += ["--keyfile", keyfile.hex()]
    r = js(args)
    if r.returncode != 0:
        raise RuntimeError(f"js encrypt failed: {r.stderr.strip()}")
    return dst.read_bytes()


def js_decrypt(container: bytes, keyfile: bytes | None, tmp: Path) -> bytes:
    src, dst = tmp / "ct.keym", tmp / "pt.out"
    src.write_bytes(container)
    args = ["decrypt", "--password", PASSWORD, "--in", str(src), "--out", str(dst)]
    if keyfile:
        args += ["--keyfile", keyfile.hex()]
    r = js(args)
    if r.returncode != 0:
        raise RuntimeError(f"js decrypt failed: {r.stderr.strip()}")
    return dst.read_bytes()


def main() -> int:
    print("\nKEYM v1 conformance — Python reference vs TypeScript implementation\n")

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)

        # ---- 1. Frozen JS fixtures, read by the independent implementation ----
        print("Frozen JS fixtures decrypted by the Python reference:")
        meta = json.loads((ROOT / "scripts/fixtures/keymaker/fixtures.json").read_text())
        fx_pw, fx_kf = meta["password"], bytes.fromhex(meta["keyFileHex"])
        for f in meta["fixtures"]:
            blob = (ROOT / "scripts/fixtures/keymaker" / f["file"]).read_bytes()
            try:
                got = decrypt(blob, fx_pw, fx_kf if f["keyFile"] else None).decode()
                check(got == f["plaintext"], f["name"])
            except KeymError as e:
                check(False, f["name"], str(e))

        # ---- 2. JS encrypts -> Python decrypts ----
        print("\nJS encrypt -> Python decrypt (6 combos x key file):")
        for kdf_name, _kdf_id, _params in KDFS:
            for cipher_name, _cipher_id in CIPHERS:
                for use_kf in (False, True):
                    kf = KEYFILE if use_kf else None
                    label = f"{kdf_name} + {cipher_name}{' + keyfile' if use_kf else ''}"
                    try:
                        ct = js_encrypt(PAYLOADS["unicode"], kdf_name, cipher_name, kf, tmp)
                        got = decrypt(ct, PASSWORD, kf)
                        check(got == PAYLOADS["unicode"], label)
                    except Exception as e:  # noqa: BLE001
                        check(False, label, str(e))

        # ---- 3. Python encrypts -> JS decrypts ----
        print("\nPython encrypt -> JS decrypt (6 combos x key file):")
        for kdf_name, kdf_id, params in KDFS:
            for cipher_name, cipher_id in CIPHERS:
                for use_kf in (False, True):
                    kf = KEYFILE if use_kf else None
                    label = f"{kdf_name} + {cipher_name}{' + keyfile' if use_kf else ''}"
                    try:
                        ct = encrypt(PAYLOADS["unicode"], PASSWORD, kf, kdf_id, params, cipher_id)
                        got = js_decrypt(ct, kf, tmp)
                        check(got == PAYLOADS["unicode"], label)
                    except Exception as e:  # noqa: BLE001
                        check(False, label, str(e))

        # ---- 4. Payload edge cases, both directions ----
        print("\nPayload shapes (chained cipher, both directions):")
        for name, payload in PAYLOADS.items():
            try:
                ct = encrypt(payload, PASSWORD, None, KDF_PBKDF2, PBKDF2, CIPHER_CHAINED)
                check(js_decrypt(ct, None, tmp) == payload, f"py->js  {name} ({len(payload)} B)")
            except Exception as e:  # noqa: BLE001
                check(False, f"py->js  {name}", str(e))
            try:
                ct = js_encrypt(payload, "pbkdf2", "chained", None, tmp)
                check(decrypt(ct, PASSWORD, None) == payload, f"js->py  {name} ({len(payload)} B)")
            except Exception as e:  # noqa: BLE001
                check(False, f"js->py  {name}", str(e))

        # ---- 5. Both must reject the same tampering ----
        print("\nTamper rejection agrees across implementations:")
        ct = encrypt(PAYLOADS["ascii"], PASSWORD, None, KDF_PBKDF2, PBKDF2, CIPHER_AES_256_GCM)

        # Flip a header byte (the AAD) and a ciphertext byte in turn.
        for label, index in (("header byte 5 (kdf_id)", 5), ("last ciphertext byte", len(ct) - 1)):
            bad = bytearray(ct)
            bad[index] ^= 0x01
            bad = bytes(bad)

            py_rejected = False
            try:
                decrypt(bad, PASSWORD, None)
            except KeymError:
                py_rejected = True

            js_rejected = False
            try:
                js_decrypt(bad, None, tmp)
            except RuntimeError:
                js_rejected = True

            check(py_rejected and js_rejected,
                  f"{label} rejected by both",
                  f"python={py_rejected} js={js_rejected}")

        # A correct container must still open in both, so the tests above are
        # not passing merely because everything fails.
        try:
            check(decrypt(ct, PASSWORD, None) == PAYLOADS["ascii"], "untampered container still opens (python)")
            check(js_decrypt(ct, None, tmp) == PAYLOADS["ascii"], "untampered container still opens (js)")
        except Exception as e:  # noqa: BLE001
            check(False, "untampered control", str(e))

    print(f"\n{passed} passed, {failed} failed")
    if failed:
        print("CONFORMANCE FAILED — the implementations disagree. docs/FORMAT.md decides which is wrong.")
        return 1
    print("Conformance passed: independent implementations agree on KEYM v1.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
