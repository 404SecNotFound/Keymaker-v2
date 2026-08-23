"""
Tests the recovery procedure exactly as docs/RECOVERY.md describes it.

Run with:  npm run test:recovery

RECOVERY.md tells someone holding a years-old backup that one Python file and
two libraries will get their data back. That is a promise, and a promise in a
document nothing executes is just a hope. This drives the CLIs the way the page
says to — as subprocesses, through their real argument parsing, with the
password on stdin — so the instructions cannot rot while the libraries
underneath keep passing their own tests.

Deliberately *not* imported as modules: the point is to exercise the published
interface, including argument names and exit codes, because those are what the
document commits to.

## Two scripts now, and the seam between them is the risky part

The app writes v2; every backup made before Phase 3 is v1. The page therefore
has a step it did not have before — *work out which version you have* — and
that step is a claim about how each script behaves when handed the other's
format. It is tested here in both directions, because a user who follows the
wrong branch of step 2 sees "decryption failed", which reads exactly like a
wrong password.

Writing this pass found three ways the document had already stopped being true
of v2, none of which any other suite could have noticed:

  - `keym2.py` required `--password` as a flag, while the page says you will be
    prompted and tells you not to pass it on the command line;
  - `dearmor` counted newlines toward the base64 padding, so the line-wrapped
    text form the page promises to accept did not decode — the TypeScript had
    stripped whitespace all along and the two had quietly diverged;
  - `inspect` said "key file yes/no" where the troubleshooting section tells a
    stuck user to look for the word `required`.
"""

from __future__ import annotations

import base64
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Keyed by container version, not by script: v2 and v3 are both keym2.py, which
# is the point of §6's dispatch — an heir runs one command whatever year the
# backup is from, and the script works out the rest.
SCRIPTS = {
    1: ROOT / "reference" / "keym.py",
    2: ROOT / "reference" / "keym2.py",
    3: ROOT / "reference" / "keym2.py",
}
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


def cli(version: int, args: list[str], stdin: str | None = None) -> subprocess.CompletedProcess:
    """Invoke a recovery tool as a user would, from the shell."""
    return subprocess.run(
        [sys.executable, str(SCRIPTS[version]), *args],
        input=stdin,
        capture_output=True,
        text=True,
        cwd=ROOT,
    )


def js_encrypt(version: int, plaintext: bytes, kdf: str, cipher: str,
               keyfile: bytes | None, tmp: Path, tag: str = "") -> Path:
    """
    Produce a container with the *shipping* implementation, not the reference.

    v2 and v3 go through `encryptapp`, which is `encryptContainer` — the
    function the worker and the UI actually call, with real random secrets. The
    conformance entry point with pinned salt and master key would be the wrong
    thing to recover from: the promise this page makes is about containers the
    app wrote.

    The version is passed explicitly rather than taken from the app's default.
    An heir following this document may hold a backup from any year, so the
    document has to be executed against every version the app has ever written,
    not only the one it writes today.
    """
    src, dst = tmp / "pt.bin", tmp / f"v{version}-{kdf}-{cipher}{tag}.keym"
    src.write_bytes(plaintext)
    cmd = "encrypt" if version == 1 else "encryptapp"
    args = [cmd, "--password", PASSWORD, "--kdf", kdf, "--cipher", cipher,
            "--in", str(src), "--out", str(dst)]
    if version != 1:
        args += ["--version", str(version)]
    args += ["--iterations", "600000"] if kdf == "pbkdf2" else ["--time", "2", "--mem", "16384", "--par", "2"]
    if keyfile:
        args += ["--keyfile", keyfile.hex()]
    r = subprocess.run(["node", str(BRIDGE), *args], capture_output=True, text=True, cwd=ROOT)
    if r.returncode != 0:
        raise RuntimeError(f"bridge {cmd} failed: {r.stderr.strip()}")
    return dst


def main() -> int:
    print("\nRecovery procedure — docs/RECOVERY.md, executed\n")

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)

        # ------------------------------------------------------------------
        # Step 2: "The right one prints a description. The wrong one refuses."
        # ------------------------------------------------------------------
        print("Step 2 — each script identifies its own format and refuses the other's:")
        v1_file = js_encrypt(1, SECRET, "pbkdf2", "aes", None, tmp)
        v2_file = js_encrypt(2, SECRET, "pbkdf2", "aes", None, tmp)

        for version, container, other in ((1, v1_file, 2), (2, v2_file, 1)):
            r = cli(version, ["inspect", "--in", str(container)])
            check(r.returncode == 0, f"keym{'' if version == 1 else '2'}.py inspects a v{version} container",
                  r.stderr.strip()[:160])
            r = cli(other, ["inspect", "--in", str(container)])
            check(r.returncode != 0,
                  f"keym{'' if other == 1 else '2'}.py refuses a v{version} container",
                  r.stdout.strip()[:160])

        # ------------------------------------------------------------------
        # Step 3: inspect reports the container's parameters, no password.
        # ------------------------------------------------------------------
        print("\nStep 3 — inspect reports the parameters, no password:")
        for version, kdf, cipher, kf in (
            (1, "argon2id", "chained", None),
            (1, "pbkdf2", "aes", KEYFILE),
            (2, "argon2id", "chained", None),
            (2, "pbkdf2", "aes", KEYFILE),
            # v3 is what the app writes now, so it is what most heirs will be
            # holding. Added rather than substituted: v2 backups do not stop
            # existing because the default moved, and the document is for
            # whoever is stuck, whenever they got stuck.
            (3, "argon2id", "chained", None),
            (3, "pbkdf2", "aes", KEYFILE),
        ):
            container = js_encrypt(version, SECRET, kdf, cipher, kf, tmp)
            r = cli(version, ["inspect", "--in", str(container)])
            out = r.stdout
            tag = f"v{version} {kdf}/{cipher}"
            check(r.returncode == 0, f"{tag}: inspect exits 0", r.stderr.strip())
            check(f"KEYM v{version}" in out, f"{tag}: reports the format", out[:120])
            expected_kdf = "Argon2id" if kdf == "argon2id" else "PBKDF2"
            check(expected_kdf in out, f"{tag}: names the KDF", out[:120])
            # The key-file line is what tells a stuck user whether they are
            # missing a factor, so it has to be right in both directions — and
            # it has to use the same word in both scripts, because the
            # troubleshooting section names that word.
            check(
                ("required" in out) == (kf is not None),
                f"{tag}: key-file requirement stated as required/not used",
                out[:200],
            )

        # The page explains `slots` and says app-written containers have one.
        r = cli(2, ["inspect", "--in", str(v2_file)])
        check("slots" in r.stdout and "slots       1" in r.stdout,
              "v2 inspect reports the slot count the page describes", r.stdout[:200])

        # ------------------------------------------------------------------
        # Step 4: decrypt with the password supplied interactively.
        # ------------------------------------------------------------------
        print("\nStep 4 — decrypt with the password on the prompt:")
        for version in (1, 2):
            for kdf, cipher, kf in (
                ("pbkdf2", "aes", None),
                ("pbkdf2", "chacha", None),
                ("pbkdf2", "chained", None),
                ("argon2id", "aes", None),
                ("argon2id", "chacha", None),
                ("argon2id", "chained", None),
                ("argon2id", "chained", KEYFILE),
            ):
                container = js_encrypt(version, SECRET, kdf, cipher, kf, tmp)
                args = ["decrypt", "--in", str(container), "--out", str(tmp / "out.bin")]
                if kf:
                    kfp = tmp / "key.bin"
                    kfp.write_bytes(kf)
                    args += ["--key-file", str(kfp)]
                r = cli(version, args, stdin=PASSWORD + "\n")
                recovered = (tmp / "out.bin").read_bytes() if r.returncode == 0 else b""
                check(
                    r.returncode == 0 and recovered == SECRET,
                    f"v{version} {kdf}/{cipher}{' +keyfile' if kf else ''} recovered",
                    r.stderr.strip()[:160],
                )
                (tmp / "out.bin").unlink(missing_ok=True)

        # ------------------------------------------------------------------
        # Both wire forms, for both versions.
        # ------------------------------------------------------------------
        print("\nBoth backup forms the document mentions:")
        v1_raw = v1_file.read_bytes()
        v2_raw = v2_file.read_bytes()

        # v1: KEYM1: + standard base64.
        text = tmp / "v1.txt"
        text.write_text("KEYM1:" + base64.b64encode(v1_raw).decode())
        r = cli(1, ["decrypt", "--in", str(text)], stdin=PASSWORD + "\n")
        check(r.returncode == 0 and SECRET.decode() in r.stdout, "KEYM1: text form",
              r.stderr.strip()[:160])

        # v2: keym2: + unpadded base64url. Both differences matter — a reader
        # that assumed standard base64 would mangle any container whose bytes
        # happen to encode a `-` or `_`.
        v2_body = base64.urlsafe_b64encode(v2_raw).decode().rstrip("=")
        text2 = tmp / "v2.txt"
        text2.write_text("keym2:" + v2_body)
        r = cli(2, ["decrypt", "--in", str(text2)], stdin=PASSWORD + "\n")
        check(r.returncode == 0 and SECRET.decode() in r.stdout, "keym2: text form",
              r.stderr.strip()[:160])
        check("=" not in v2_body, "v2 armor is unpadded, as the page shows it")

        # A pasted backup often arrives wrapped by whatever stored it. The page
        # says line breaks are fine; that has to be true of both.
        #
        # Three container lengths for v2, not one, and the reason is worth
        # writing down. The newlines have to be stripped *before* the base64
        # padding is computed, or they are counted as data characters and the
        # padding comes out wrong — but Python's decoder stops at the first `=`,
        # so an over-supplied pad is harmless whenever the body length is
        # already a multiple of four. That is one container length in three.
        #
        # The first version of this test used a single 165-byte container, which
        # is exactly that case, and passed with the whitespace stripping
        # reverted. A negative control said so. Varying the plaintext by a byte
        # walks the container length through all three residues, and two of them
        # now fail without the fix.
        wrapped_cases: list[tuple[int, str, str, str]] = [
            (1, "KEYM1:" + base64.b64encode(v1_raw).decode(), "KEYM1:", SECRET.decode()),
        ]
        for extra in (0, 1, 2):
            secret = SECRET + b"x" * extra
            container = js_encrypt(2, secret, "pbkdf2", "aes", None, tmp, tag=f"-wrap{extra}")
            raw = container.read_bytes()
            body = "keym2:" + base64.urlsafe_b64encode(raw).decode().rstrip("=")
            wrapped_cases.append((2, body, f"keym2: ({len(raw)} B, len%3={len(raw) % 3})",
                                  secret.decode()))

        for i, (version, body, name, expected) in enumerate(wrapped_cases):
            wrapped = tmp / f"wrapped{i}.txt"
            wrapped.write_text("\n".join(body[j:j + 40] for j in range(0, len(body), 40)) + "\n")
            r = cli(version, ["decrypt", "--in", str(wrapped)], stdin=PASSWORD + "\n")
            check(r.returncode == 0 and expected in r.stdout,
                  f"line-wrapped {name} text form", r.stderr.strip()[:160])

        # The page states plainly that keym2: is case-sensitive and that
        # `KEYM2:` will not be recognised. That is a promise about a failure,
        # and it is the one a "helpful" editor is most likely to trigger.
        shouted = tmp / "shouted.txt"
        shouted.write_text("KEYM2:" + v2_body)
        r = cli(2, ["decrypt", "--in", str(shouted)], stdin=PASSWORD + "\n")
        check(r.returncode != 0, "KEYM2: is refused, exactly as the page warns",
              r.stdout.strip()[:160])

        # ------------------------------------------------------------------
        # Failure modes the "if it does not work" section describes.
        # ------------------------------------------------------------------
        print("\nFailures are refused, and stay non-committal:")
        for version, container in ((1, v1_file), (2, v2_file)):
            r = cli(version, ["decrypt", "--in", str(container)], stdin="the wrong password\n")
            check(r.returncode != 0, f"v{version} wrong password exits non-zero")
            check(SECRET.decode() not in r.stdout, f"v{version} wrong password reveals no plaintext")
            # Must not say *which* input was wrong — that would be an oracle.
            lowered = r.stderr.lower()
            check(
                "decryption failed" in lowered
                and "wrong password" not in lowered.replace("the password, the key file", ""),
                f"v{version} error does not identify which input was wrong",
                r.stderr.strip()[:160],
            )

            truncated = tmp / f"truncated{version}.keym"
            raw = container.read_bytes()
            truncated.write_bytes(raw[: len(raw) - 8])
            r = cli(version, ["decrypt", "--in", str(truncated)], stdin=PASSWORD + "\n")
            check(r.returncode != 0, f"v{version} truncated container refused")

        junk = tmp / "junk.txt"
        junk.write_text("this is not a container")
        for version in (1, 2):
            r = cli(version, ["inspect", "--in", str(junk)])
            check(r.returncode != 0, f"v{version} non-container rejected by inspect")

    walkthrough()

    print(f"\n{passed} passed, {failed} failed")
    if failed:
        print("RECOVERY PROCEDURE BROKEN — the documents no longer describe reality.")
        return 1
    print("Verified: docs/RECOVERY.md and docs/WALKTHROUGH.md work as written.")
    return 0


# ----------------------------------------------------------------------------
# docs/WALKTHROUGH.md — Part 3, executed rather than transcribed
# ----------------------------------------------------------------------------

WALKTHROUGH = ROOT / "docs" / "WALKTHROUGH.md"

# Needs the network and a package index. Skipped rather than dropped silently,
# and *reported* as skipped, because a suite that quietly stops covering a step
# reads exactly like one that covers it.
SKIP_PREFIXES = ("pip install",)


def bash_blocks(markdown: str) -> list[str]:
    """Every ```bash fence in a document, in order."""
    blocks, inside, current = [], False, []
    for line in markdown.splitlines():
        if line.strip() == "```bash":
            inside, current = True, []
        elif inside and line.strip() == "```":
            inside = False
            blocks.append("\n".join(current))
        elif inside:
            current.append(line)
    return blocks


def walkthrough() -> None:
    """
    Run Part 3 of the walkthrough the way a reader would, from the document.

    Extracted rather than re-typed here, for the same reason the release notes
    are generated from docs/VERIFYING.md: a second hand-maintained copy of a
    command is free to drift from the one people actually follow, and the copy
    that drifts is the one nobody runs. This *is* the copy people follow.

    The container comes from the shipping encryptor, not the reference, because
    the promise the page makes is about backups the app wrote.
    """
    print("\ndocs/WALKTHROUGH.md — Part 3, executed:")

    try:
        doc = WALKTHROUGH.read_text(encoding="utf-8")
    except FileNotFoundError:
        check(False, "docs/WALKTHROUGH.md exists")
        return

    commands = [
        line.strip()
        for block in bash_blocks(doc)
        for line in block.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    runnable = [c for c in commands if not c.startswith(SKIP_PREFIXES)]
    skipped = [c for c in commands if c.startswith(SKIP_PREFIXES)]

    check(len(runnable) >= 3,
          f"the walkthrough carries runnable commands ({len(runnable)} found)")
    for c in skipped:
        print(f"  skip {c}  (needs a package index; the libraries are a prerequisite, not a step)")

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)

        # The page tells the reader to keep a copy of keym2.py beside the
        # backup, and then runs `python3 keym2.py` — not a path into a clone.
        # Reproduce that exactly: the file sits in the working directory.
        (tmp / "keym2.py").write_bytes(SCRIPTS[2].read_bytes())

        produced = js_encrypt(2, SECRET, "argon2id", "chained", None, tmp, tag="-walk")
        vault = tmp / "vault.keym"
        vault.write_bytes(produced.read_bytes())

        # The armored form the page offers as the alternative: the same bytes,
        # wrapped the way the app wraps them. The page says both forms hold
        # identical bytes, so this is built from the container rather than
        # produced separately — if that claim stops being true, the decrypt of
        # vault.txt below stops matching SECRET.
        body = base64.urlsafe_b64encode(vault.read_bytes()).decode().rstrip("=")
        wrapped = "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
        (tmp / "vault.txt").write_text("keym2:" + wrapped + "\n")

        # §7.1 paper parts, pre-created for the same reason vault.keym is:
        # someone following Part 3 already *has* their backup, in whichever
        # form they kept it. The page presents `join` before `split` because
        # that is the order a reader needs them — recovery first, reprinting
        # second — and the runner supplies what recovery assumes.
        subprocess.run(
            [sys.executable, "keym2.py", "split", "--in", "vault.keym",
             "--out", "parts.txt"],
            capture_output=True, text=True, cwd=tmp, check=True,
        )

        # §7.2. Step 8's page, pre-created for the same reason, and built by the
        # *shipping* writer rather than assembled here — the page a reader holds
        # came out of the app, and a hand-built approximation would let the two
        # drift apart without anything saying so.
        #
        # A second container, not `vault.keym`: the walkthrough's backup is
        # Argon2id + chained, which §7.2's subset excludes outright. That is the
        # feature rather than an inconvenience to route around — a page carries
        # its own PBKDF2/AES container precisely so that making one cannot weaken
        # the backup it came from.
        page_container = js_encrypt(2, SECRET, "pbkdf2", "aes", None, tmp, tag="-page")
        r = subprocess.run(
            ["node", str(BRIDGE), "selfextract", "--in", str(page_container),
             "--out", str(tmp / "backup.html"),
             "--created-on", "2026-01-01", "--app-version", "0.0.0"],
            capture_output=True, text=True, cwd=ROOT,
        )
        if r.returncode != 0:
            raise RuntimeError(f"bridge selfextract failed: {r.stderr.strip()}")

        for command in runnable:
            argv = command.split()
            if argv[:1] == ["python3"]:
                argv[0] = sys.executable
            r = subprocess.run(argv, input=PASSWORD + "\n", capture_output=True,
                               text=True, cwd=tmp)
            check(r.returncode == 0, f"`{command}` succeeds",
                  (r.stderr or r.stdout).strip()[:200])

            # Step 5's claim: inspect reports what the app called the
            # "Effective configuration", with no password involved.
            if "inspect" in argv:
                for expected in ("KEYM v2", "Argon2id", "ChaCha20-Poly1305"):
                    check(expected in r.stdout,
                          f"  inspect reports {expected}", r.stdout.strip()[:200])

        # Step 6's claim, and the only one that matters: the bytes come back.
        recovered = tmp / "recovered.txt"
        check(recovered.exists(), "the walkthrough produced recovered.txt")
        if recovered.exists():
            check(recovered.read_bytes() == SECRET,
                  "recovered.txt is byte-identical to what was encrypted",
                  f"{recovered.read_bytes()[:60]!r}")

        # §7.2, Step 8's claim, and the same standard: an exit code of zero from
        # a decrypt that wrote the wrong bytes would satisfy the loop above and
        # mean nothing. This is the assertion that makes the page a backup.
        from_page = tmp / "recovered-from-page.txt"
        check(from_page.exists(), "the walkthrough produced recovered-from-page.txt")
        if from_page.exists():
            check(from_page.read_bytes() == SECRET,
                  "the self-extracting page gives back exactly what went in",
                  f"{from_page.read_bytes()[:60]!r}")

        # Every screenshot the page embeds has to be a file that exists. A
        # broken image in a walkthrough is a step the reader cannot follow.
        for image in re.findall(r"!\[[^\]]*\]\(([^)]+)\)", doc):
            path = (WALKTHROUGH.parent / image).resolve()
            check(path.is_file(), f"illustration {image} exists")


if __name__ == "__main__":
    raise SystemExit(main())
