"""
Tests the recovery procedure exactly as docs/RECOVERY.md describes it.

Run with:  npm run test:recovery

RECOVERY.md tells someone holding a years-old backup that one Python file and
two libraries will get their data back. That is a promise, and a promise in a
document nothing executes is just a hope. This drives the CLI the way the page
says to — as a subprocess, through its real argument parsing, with the password
on stdin — so the instructions cannot rot while the library underneath keeps
passing its own tests.

Deliberately *not* imported as a module: the point is to exercise the published
interface, including argument names and exit codes, because those are what the
document commits to.
"""

from __future__ import annotations

import base64
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KEYM = ROOT / "reference" / "keym.py"
BRIDGE = ROOT / "reference" / "bridge.mjs"

PASSWORD = "a real user password — with ünicode 2031"
SECRET = "twelve words that stand between you and everything you own".encode("utf-8")
KEYFILE = bytes(range(64))

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


def cli(args: list[str], stdin: str | None = None) -> subprocess.CompletedProcess:
    """Invoke the recovery tool as a user would, from the shell."""
    return subprocess.run(
        [sys.executable, str(KEYM), *args],
        input=stdin,
        capture_output=True,
        text=True,
        cwd=ROOT,
    )


def js_encrypt(plaintext: bytes, kdf: str, cipher: str, keyfile: bytes | None, tmp: Path) -> Path:
    """Produce a container with the *shipping* implementation, not the reference."""
    src, dst = tmp / "pt.bin", tmp / f"{kdf}-{cipher}.keym"
    src.write_bytes(plaintext)
    args = ["encrypt", "--password", PASSWORD, "--kdf", kdf, "--cipher", cipher,
            "--in", str(src), "--out", str(dst)]
    args += ["--iterations", "600000"] if kdf == "pbkdf2" else ["--time", "2", "--mem", "16384", "--par", "2"]
    if keyfile:
        args += ["--keyfile", keyfile.hex()]
    r = subprocess.run(["node", str(BRIDGE), *args], capture_output=True, text=True, cwd=ROOT)
    if r.returncode != 0:
        raise RuntimeError(f"bridge encrypt failed: {r.stderr.strip()}")
    return dst


def main() -> int:
    print("\nRecovery procedure — docs/RECOVERY.md, executed\n")

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)

        # Step 2 of the document: inspect without a password.
        print("Step 2 — inspect reports the container's parameters, no password:")
        for kdf, cipher, kf in (
            ("argon2id", "chained", None),
            ("pbkdf2", "aes", KEYFILE),
        ):
            container = js_encrypt(SECRET, kdf, cipher, kf, tmp)
            r = cli(["inspect", "--in", str(container)])
            out = r.stdout
            check(r.returncode == 0, f"{kdf}/{cipher}: inspect exits 0", r.stderr.strip())
            check("KEYM v1" in out, f"{kdf}/{cipher}: reports the format")
            expected_kdf = "Argon2id" if kdf == "argon2id" else "PBKDF2"
            check(expected_kdf in out, f"{kdf}/{cipher}: names the KDF")
            # The key-file line is what tells a stuck user whether they are
            # missing a factor, so it has to be right in both directions.
            check(
                ("required" in out) == (kf is not None),
                f"{kdf}/{cipher}: key-file requirement stated correctly",
                out,
            )

        # Step 3: decrypt with the password supplied interactively.
        print("\nStep 3 — decrypt with the password on the prompt:")
        for kdf, cipher, kf in (
            ("pbkdf2", "aes", None),
            ("pbkdf2", "chacha", None),
            ("pbkdf2", "chained", None),
            ("argon2id", "aes", None),
            ("argon2id", "chacha", None),
            ("argon2id", "chained", None),
            ("argon2id", "chained", KEYFILE),
        ):
            container = js_encrypt(SECRET, kdf, cipher, kf, tmp)
            args = ["decrypt", "--in", str(container), "--out", str(tmp / "out.bin")]
            if kf:
                kfp = tmp / "key.bin"
                kfp.write_bytes(kf)
                args += ["--key-file", str(kfp)]
            r = cli(args, stdin=PASSWORD + "\n")
            recovered = (tmp / "out.bin").read_bytes() if r.returncode == 0 else b""
            check(
                r.returncode == 0 and recovered == SECRET,
                f"{kdf}/{cipher}{' +keyfile' if kf else ''} recovered",
                r.stderr.strip()[:160],
            )

        # The document promises both wire forms are accepted.
        print("\nBoth backup forms the document mentions:")
        container = js_encrypt(SECRET, "pbkdf2", "aes", None, tmp)
        raw = container.read_bytes()

        text = tmp / "backup.txt"
        text.write_text("KEYM1:" + base64.b64encode(raw).decode())
        r = cli(["decrypt", "--in", str(text)], stdin=PASSWORD + "\n")
        check(r.returncode == 0 and SECRET.decode() in r.stdout, "KEYM1: text form")

        # A pasted backup often arrives wrapped by whatever stored it.
        wrapped = tmp / "wrapped.txt"
        body = "KEYM1:" + base64.b64encode(raw).decode()
        wrapped.write_text("\n".join(body[i : i + 40] for i in range(0, len(body), 40)) + "\n")
        r = cli(["decrypt", "--in", str(wrapped)], stdin=PASSWORD + "\n")
        check(r.returncode == 0 and SECRET.decode() in r.stdout, "line-wrapped text form")

        # Failure modes the "if it does not work" section describes.
        print("\nFailures are refused, and stay non-committal:")
        r = cli(["decrypt", "--in", str(container)], stdin="the wrong password\n")
        check(r.returncode != 0, "wrong password exits non-zero")
        check(SECRET.decode() not in r.stdout, "wrong password reveals no plaintext")
        # Must not say *which* input was wrong — that would be an oracle.
        lowered = r.stderr.lower()
        check(
            "decryption failed" in lowered
            and "wrong password" not in lowered.replace("the password, the key file", ""),
            "error does not identify which input was wrong",
            r.stderr.strip()[:160],
        )

        junk = tmp / "junk.txt"
        junk.write_text("this is not a container")
        r = cli(["inspect", "--in", str(junk)])
        check(r.returncode != 0, "non-container rejected by inspect")

        truncated = tmp / "truncated.keym"
        truncated.write_bytes(raw[: len(raw) - 8])
        r = cli(["decrypt", "--in", str(truncated)], stdin=PASSWORD + "\n")
        check(r.returncode != 0, "truncated container refused")

    print(f"\n{passed} passed, {failed} failed")
    if failed:
        print("RECOVERY PROCEDURE BROKEN — docs/RECOVERY.md no longer describes reality.")
        return 1
    print("Recovery procedure verified: docs/RECOVERY.md works as written.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
