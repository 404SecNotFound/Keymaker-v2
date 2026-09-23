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
import os
import shlex
import stat
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
        v3_file = js_encrypt(3, SECRET, "pbkdf2", "aes", None, tmp)

        for version, container, other in ((1, v1_file, 2), (2, v2_file, 1), (3, v3_file, 1)):
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
        # v3 is what the app writes today, so it is the backup an heir is most
        # likely to be holding. This loop covered v1 and v2 only for as long as
        # v3 has been the default.
        for version in (1, 2, 3):
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
        # Step 4, with recovery shares instead of the password.
        # ------------------------------------------------------------------
        # The share set is issued by the shipping enrolment (addShamirSlotKeym2,
        # through the bridge) on a container the shipping encryptor wrote, and
        # opened with the page's own command: two of three strips in a file
        # with a comment line, one of them lower-cased with its hyphens typed
        # as spaces, the way a person copying it by hand might, and nothing on
        # stdin.
        print("\nStep 4 — decrypt with recovery shares, no password:")
        base = js_encrypt(3, SECRET, "pbkdf2", "aes", None, tmp, tag="-shares")
        shared, issued = tmp / "shared.keym", tmp / "issued.txt"
        r = subprocess.run(
            ["node", str(BRIDGE), "addshares", "--password", PASSWORD,
             "--in", str(base), "--out", str(shared), "--shares-out", str(issued),
             "--threshold", "2", "--shares", "3",
             "--salt", os.urandom(32).hex(), "--share-secret", os.urandom(32).hex(),
             "--share-coefficients", os.urandom(32).hex()],
            capture_output=True, text=True, cwd=ROOT)
        strips = [ln for ln in issued.read_text().split("\n") if ln.strip()] if r.returncode == 0 else []
        check(len(strips) == 3, "the shipping enrolment issued three strips", r.stderr.strip()[:160])
        if len(strips) == 3:
            prefix, _, code = strips[2].partition(":")
            (tmp / "shares.txt").write_text(
                "# strips 1 and 3 of 3\n" + strips[0] + "\n"
                + prefix + ":" + code.lower().replace("-", " ") + "\n")
            r = cli(2, ["decrypt", "--in", str(shared), "--shares-from",
                        str(tmp / "shares.txt"), "--out", str(tmp / "out.bin")], stdin="")
            recovered = (tmp / "out.bin").read_bytes() if r.returncode == 0 else b""
            check(r.returncode == 0 and recovered == SECRET,
                  "two of three strips open the backup with no password",
                  r.stderr.strip()[:160])
            (tmp / "out.bin").unlink(missing_ok=True)
            (tmp / "one.txt").write_text(strips[1] + "\n")
            r = cli(2, ["decrypt", "--in", str(shared), "--shares-from",
                        str(tmp / "one.txt"), "--out", str(tmp / "out.bin")], stdin="")
            check(r.returncode != 0 and not (tmp / "out.bin").exists(),
                  "one strip of a 2-of-3 set does not", r.stderr.strip()[:160])

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

        # A text backup that picked up a blank first line or a leading space on
        # the way into a notes app or an email. §7 says readers strip ASCII
        # whitespace, and the app always has; keym2.py sniffed the prefix on
        # the raw bytes, missed it, and fell through to "decryption failed",
        # which sends the reader to retype a password that was never wrong.
        padded = tmp / "v2-padded.txt"
        padded.write_text("\n  \n\tkeym2:" + v2_body + "\n")
        r = cli(2, ["decrypt", "--in", str(padded)], stdin=PASSWORD + "\n")
        check(r.returncode == 0 and SECRET.decode() in r.stdout,
              "keym2: text form after a blank line and leading spaces",
              r.stderr.strip()[:160])

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
            # A traceback also exits non-zero, which is how the traceback got
            # past this check for as long as it did. What an heir needs is a
            # sentence; what they got was forty lines of Python ending in
            # `KeymError: decryption failed`, which reads as "the file is gone".
            check(
                "Traceback (most recent call last)" not in r.stderr,
                f"v{version} says so in a sentence rather than a traceback",
                r.stderr.strip()[-160:],
            )

        error_paths(tmp)

    recovery_version_claims()
    recovery_examples()
    recovery_commands()
    walkthrough()

    print(f"\n{passed} passed, {failed} failed")
    if failed:
        print("RECOVERY PROCEDURE BROKEN — the documents no longer describe reality.")
        return 1
    print("Verified: docs/RECOVERY.md and docs/WALKTHROUGH.md work as written.")
    return 0


# ----------------------------------------------------------------------------
# The ways a person gets it wrong
# ----------------------------------------------------------------------------
#
# Everything above checks that the documented procedure works. This checks what
# happens when it does not — which for a recovery tool is not a lesser concern.
# The person running these scripts is, by construction, someone whose usual way
# in has failed: they are guessing at paths, pasting shares they are unsure of,
# and reading every line of output for a verdict on whether the money is gone.
#
# A traceback is that verdict, wrongly delivered. So is "decryption failed" on a
# container that opens fine.


def error_paths(tmp: Path) -> None:
    print("\n# Getting it wrong: what the tools say when the input is bad\n")

    # A complete command line that needs no input stream. `join` read stdin
    # before looking at what it had been given, so this waited forever at a
    # terminal — indistinguishable from a hang, on the one tool whose job is to
    # reassure. Run with stdin held open and never closed, which is what a
    # terminal is; a closed stdin would make the old code pass.
    reader, writer = os.pipe()
    try:
        r = subprocess.run(
            [sys.executable, str(SCRIPTS[2]), "join", "--part", "KMPART1:1/1:AAAA"],
            stdin=reader, capture_output=True, text=True, cwd=ROOT, timeout=20,
        )
        check(True, "join --part returns without reading stdin", r.stderr.strip()[:120])
    except subprocess.TimeoutExpired:
        check(False, "join --part returns without reading stdin",
              "still waiting on stdin after 20s")
    finally:
        os.close(reader)
        os.close(writer)

    # A mistyped path is the most ordinary mistake there is.
    for version in (1, 2):
        r = cli(version, ["inspect", "--in", str(tmp / "no-such-file.keym")])
        check(r.returncode != 0 and "Traceback" not in r.stderr,
              f"v{version} names a missing input file plainly", r.stderr.strip()[-160:])

    # A writer parameter outside §6's range is a writer's mistake, and saying
    # "decryption failed" during an encrypt names neither the operation that
    # failed nor the number that caused it.
    pt = tmp / "range-pt.txt"
    pt.write_bytes(SECRET)
    r = cli(2, ["encrypt", "--kdf", "pbkdf2", "--iterations", "20000000",
                "--in", str(pt), "--out", str(tmp / "never.keym")],
            stdin="a strong test password\n" * 2)
    check(r.returncode != 0 and "decryption failed" not in r.stderr
          and "iterations" in r.stderr,
          "an out-of-range iteration count is reported as what it is",
          r.stderr.strip()[-160:])

    # The one with a wrong answer rather than an ugly one. Someone holding a
    # password *and* some shares they are unsure about passes both, hoping one
    # works. The password was silently discarded, so a container that opens
    # perfectly well came back as "decryption failed".
    src = tmp / "both-pt.txt"
    src.write_bytes(SECRET)
    both = tmp / "both.keym"
    r = cli(2, ["encrypt", "--kdf", "pbkdf2", "--iterations", "600000",
                "--in", str(src), "--out", str(both)],
            stdin="a strong test password\n" * 2)
    check(r.returncode == 0 and both.exists(),
          "wrote a container for the password-plus-shares case",
          r.stderr.strip()[-160:])
    if both.exists():
        out = tmp / "both-out.txt"
        r = cli(2, ["decrypt", "--in", str(both), "--out", str(out),
                    "--password", "a strong test password",
                    "--share", "KMSHARE1:NOTAREALSHARE"])
        check(r.returncode == 0 and out.exists() and out.read_bytes() == SECRET,
              "a correct password still opens it when useless shares are given too",
              r.stderr.strip()[-160:])

    # O_NOFOLLOW. Writing through a planted symlink puts the plaintext where
    # whoever planted it chose; the 0600 that follows only narrows the target.
    if hasattr(os, "O_NOFOLLOW"):
        sym_pt, target, link = tmp / "sym-pt.txt", tmp / "target.txt", tmp / "link.txt"
        sym_pt.write_bytes(SECRET)
        target.write_text("")
        os.symlink(target, link)
        r = cli(2, ["encrypt", "--kdf", "pbkdf2", "--iterations", "600000",
                    "--in", str(sym_pt), "--out", str(link)],
                stdin="a strong test password\n" * 2)
        check(r.returncode != 0 and target.read_text() == ""
              and "Traceback" not in r.stderr,
              "a symlink at --out is refused, and said so in a sentence",
              r.stderr.strip()[-160:])

    # The CLI's own default. `VERSION` has said v3 since the app started
    # writing it, but this parser opted *in* with --v3, so the reference
    # implementation was the least safe way to make a container: it wrote the
    # one format §1.1's strip attack works on, beside a browser tool writing
    # the one that detects it.
    v3out = tmp / "cli-default.keym"
    dpt = tmp / "cli-default-pt.txt"
    dpt.write_bytes(SECRET)
    r = cli(2, ["encrypt", "--kdf", "pbkdf2", "--iterations", "600000",
                "--in", str(dpt), "--out", str(v3out)],
            stdin="a strong test password\n" * 2)
    check(r.returncode == 0 and v3out.exists() and v3out.read_bytes()[4] == 3,
          "the reference CLI writes v3 by default, like everything else",
          r.stderr.strip()[-160:])
    v2out = tmp / "cli-v2.keym"
    r = cli(2, ["encrypt", "--kdf", "pbkdf2", "--iterations", "600000", "--v2",
                "--in", str(dpt), "--out", str(v2out)],
            stdin="a strong test password\n" * 2)
    check(r.returncode == 0 and v2out.exists() and v2out.read_bytes()[4] == 2,
          "--v2 is still there for an older reader that needs it",
          r.stderr.strip()[-160:])

    # Both references write owner-only. keym.py is the one an heir with a *v1*
    # backup runs, so it is if anything the more important of the two, and it
    # was the one still writing 0644.
    for version in (1, 2):
        src, enc, dec = tmp / f"p{version}.txt", tmp / f"c{version}.keym", tmp / f"d{version}.txt"
        src.write_bytes(SECRET)
        cmd = ["encrypt", "--kdf", "pbkdf2", "--iterations", "600000",
               "--in", str(src), "--out", str(enc)]
        r = cli(version, cmd, stdin="a strong test password\n" * 2)
        if r.returncode != 0:
            check(False, f"v{version} wrote a container for the mode check",
                  r.stderr.strip()[-160:])
            continue
        r = cli(version, ["decrypt", "--in", str(enc), "--out", str(dec)],
                stdin="a strong test password\n")
        check(r.returncode == 0 and dec.exists() and dec.read_bytes() == SECRET,
              f"v{version} round-trips through --out", r.stderr.strip()[-160:])
        if dec.exists():
            mode = stat.S_IMODE(dec.stat().st_mode)
            check(mode == 0o600,
                  f"v{version} writes the plaintext owner-only, not {oct(mode)}")


# ----------------------------------------------------------------------------
# docs/RECOVERY.md — the version it claims must be the version we write
# ----------------------------------------------------------------------------

RECOVERY = ROOT / "docs" / "RECOVERY.md"


def recovery_version_claims() -> None:
    """
    Every version this document asserts, checked against what the CLI writes.

    RECOVERY.md said "Keymaker writes **v2** today" in one paragraph and "**v3**
    — what the app writes today" seventy lines later, for as long as v3 has been
    the default. Both sentences were hand-written and nothing compared either to
    the code, so the document contradicted itself in front of the one reader who
    cannot check: an heir, holding a container, with the app gone.

    Other surfaces were made constant-driven when v3 landed; this one was missed
    because it is prose rather than a template — which is why it needs a gate
    rather than a proofread.

    """
    doc = RECOVERY.read_text(encoding="utf-8")
    # Paragraph wrapping put "writes **v2**" and "today" on different lines in
    # the original, so the claim has to be matched against unwrapped text.
    flat = re.sub(r"\s+", " ", doc)

    sys.path.insert(0, str(ROOT / "reference"))
    import keym2

    version = keym2.VERSION

    for claimed in re.findall(r"writes \*\*v(\d+)\*\*", flat):
        check(int(claimed) == version,
              f"RECOVERY.md's 'writes **v{claimed}**' matches what is written",
              f"document says v{claimed}, the app writes v{version}")

    check(f"**v{version}**" in doc,
          f"RECOVERY.md names v{version}, the version being written",
          "the current version is not mentioned at all")

    # The armor-prefix table must name the current version against keym2:, which
    # covers v2 and v3 alike. A row listing only the older one tells an heir
    # their fresh backup is something it is not.
    row = re.search(r"^\|\s*`keym2:`\s*\|([^|]*)\|", doc, re.MULTILINE)
    check(row is not None, "RECOVERY.md has a keym2: row in the prefix table")
    if row is not None:
        listed = re.findall(r"v(\d+)", row.group(1))
        check(str(version) in listed,
              f"the keym2: prefix row lists v{version}",
              f"row lists {listed or 'no versions'}; the app writes v{version}")

    # Two scripts, three versions. A sentence claiming one script per version is
    # the shape the original error took.
    check("two container versions" not in doc,
          "RECOVERY.md no longer claims there are two container versions",
          "there are three (v1, v2, v3) and two scripts; keym2.py reads v2 and v3")



# ----------------------------------------------------------------------------
# docs/RECOVERY.md — the sample output must be output the tools produce
# ----------------------------------------------------------------------------

# Lines whose value is random per container. Their *label* still has to match,
# because a line the page leaves out is a line an heir sees and cannot place.
RANDOM_VALUED = ("container", "table mac", "salt")


def fenced_after(doc: str, marker: str) -> str | None:
    """The first ``` block after `marker`, or None."""
    at = doc.find(marker)
    if at < 0:
        return None
    m = re.search(r"^```[^\n]*\n(.*?)^```", doc[at:], re.MULTILINE | re.DOTALL)
    return m.group(1) if m else None


def inspect_lines(text: str) -> list[tuple[str, str]]:
    """(label, whole line) for each line of `inspect` output."""
    out = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # A continuation line (v1's "time cost …") starts deep in the value
        # column and has no label of its own.
        indent = len(line) - len(line.lstrip())
        label = "" if indent >= 8 else re.split(r"\s{2,}", stripped, maxsplit=1)[0]
        out.append((label, stripped))
    return out


def recovery_examples() -> None:
    """
    Step 3's two sample outputs, compared against what `inspect` prints.

    The v3 sample was typed in by hand when v3 landed and was missing two of
    the lines the tool prints — `container` and `table mac` — so an heir
    comparing their screen with the page saw output the page did not describe.
    Nothing read the sample, so nothing noticed.

    Each sample is compared with a container built to match it: the same KDF
    costs, the same cipher, and a plaintext of the length the sample states.
    Lines that are random per container are compared by label only.
    """
    print("\ndocs/RECOVERY.md — Step 3's sample output is real output:")
    doc = RECOVERY.read_text(encoding="utf-8")

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        for version, marker, kdf, cipher, script in (
            (3, "For a **v3** container", "argon2id", "aes", 3),
            (1, "For a **v1** container", "argon2id", "chained", 1),
        ):
            sample = fenced_after(doc, marker)
            check(sample is not None, f"RECOVERY.md has a v{version} inspect sample")
            if sample is None:
                continue

            # The plaintext length the sample claims, so the chunk and
            # ciphertext lines can be compared exactly rather than by label.
            m = re.search(r"\((\d+) plaintext bytes\)", sample) if version != 1 \
                else re.search(r"ciphertext\s+(\d+) bytes", sample)
            length = int(m.group(1)) if m else 1
            if version == 1 and cipher == "chained":
                length -= 32  # two 16-byte tags
            container = tmp / f"sample-v{version}.keym"
            src = tmp / "sample-pt.bin"
            src.write_bytes(b"x" * max(length, 1))
            args = ["encrypt" if version == 1 else "encryptapp", "--password", PASSWORD,
                    "--kdf", kdf, "--cipher", cipher, "--in", str(src), "--out", str(container),
                    "--time", "3", "--mem", "65536", "--par", "4"]
            if version != 1:
                args += ["--version", str(version)]
            r = subprocess.run(["node", str(BRIDGE), *args], capture_output=True, text=True, cwd=ROOT)
            if r.returncode != 0:
                check(False, f"built a container matching the v{version} sample", r.stderr.strip()[:160])
                continue

            r = cli(script, ["inspect", "--in", str(container)])
            actual = inspect_lines(r.stdout)
            shown = inspect_lines(sample)
            check([a for a, _ in actual] == [s for s, _ in shown],
                  f"the v{version} sample has the lines inspect prints, in order",
                  f"page: {[s for s, _ in shown]}; tool: {[a for a, _ in actual]}")
            tool = dict(actual)
            for label, want in shown:
                if label in RANDOM_VALUED or label not in tool:
                    continue
                check(tool[label] == want, f"  v{version} sample line {label or '(continued)'!r} matches",
                      f"page: {want!r}; tool: {tool[label]!r}")


# ----------------------------------------------------------------------------
# docs/RECOVERY.md — every command on the page, executed
# ----------------------------------------------------------------------------

# The names the page uses. The runner supplies each one, the way the reader
# already has them: their backup, their key file, the codes off their strips.
PLACEHOLDERS = ("backup.keym", "mykey.bin", "shares.txt", "recovered.txt")


def claimed_versions(command: str) -> set[int]:
    """The versions a line's trailing comment says it is for: `# v3 or v2`."""
    _, _, comment = command.partition("#")
    return {int(v) for v in re.findall(r"\bv(\d+)\b", comment)}


def run_doc_command(command: str, cwd: Path, stdin: str,
                    extra: list[str] | None = None) -> subprocess.CompletedProcess:
    argv = shlex.split(command, comments=True) + (extra or [])
    if argv[:1] == ["python3"]:
        argv[0] = sys.executable
    return subprocess.run(argv, input=stdin, capture_output=True, text=True, cwd=cwd)


def recovery_commands() -> None:
    """
    Run every command in RECOVERY.md's `bash` blocks, from the page.

    Everything above drives the scripts with argument lists written *here*,
    which is the copy nobody follows. This extracts the page's own lines, so a
    renamed flag or a wrong script in the document fails the build rather than
    an heir.

    Every command must be recognised. A block added to the page that this
    runner does not know how to check fails, rather than being skipped, because
    an unexecuted command in a recovery document is exactly the drift this
    exists to stop.

    Each `inspect` and `decrypt` line carries a comment naming the versions it
    is for (`# v3 or v2`). That comment is a claim, and it is checked: each
    version must be claimed by exactly one line, that line must work on it, and
    the others must refuse it, which is Step 2's "the wrong one refuses".
    """
    print("\ndocs/RECOVERY.md — every command on the page, executed:")
    doc = RECOVERY.read_text(encoding="utf-8")
    commands = [
        line.strip()
        for block in bash_blocks(doc)
        for line in block.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    identify, decrypt, shares, joins, unknown = [], [], [], [], []
    for c in commands:
        argv = shlex.split(c, comments=True)
        if argv[:1] == ["pip"]:
            print(f"  skip {c}  (needs a package index; the libraries are a prerequisite, not a step)")
        elif argv[:1] == ["python3"] and "decrypt" in argv and "--shares-from" in argv:
            shares.append(c)
        elif argv[:1] == ["python3"] and "join" in argv:
            joins.append(c)
        # A line without a `# vN` comment cannot be checked against the version
        # it is for, so it counts as unrecognised rather than as "for none".
        elif argv[:1] == ["python3"] and "inspect" in argv and claimed_versions(c):
            identify.append(c)
        elif argv[:1] == ["python3"] and "decrypt" in argv and claimed_versions(c):
            decrypt.append(c)
        else:
            unknown.append(c)

    for c in unknown:
        check(False, f"RECOVERY.md command is executed by this runner: `{c}`",
              "add a case for it here rather than leaving it unchecked")
    for group, name in ((identify, "inspect"), (decrypt, "decrypt")):
        for version in (1, 2, 3):
            owners = [c for c in group if version in claimed_versions(c)]
            check(len(owners) == 1,
                  f"exactly one {name} line on the page is for v{version}",
                  f"{len(owners)} lines claim it: {owners}")
    check(len(shares) >= 1, "the page carries a shares command")
    check(len(joins) >= 1, "the page carries a join command for strips that carry the backup")

    # "Add `--key-file mykey.bin` if step 3 reported one was required."
    m = re.search(r"Add `(--key-file [^`]+)`", doc)
    check(m is not None, "the page says how to add a key file")
    keyfile_args = shlex.split(m.group(1)) if m else []

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        # The page's commands run `python3 keym2.py`, a copy beside the backup,
        # not a path into a clone.
        for name in ("keym.py", "keym2.py"):
            (tmp / name).write_bytes((ROOT / "reference" / name).read_bytes())
        backup, mykey = tmp / PLACEHOLDERS[0], tmp / PLACEHOLDERS[1]
        shares_file, recovered = tmp / PLACEHOLDERS[2], tmp / PLACEHOLDERS[3]
        mykey.write_bytes(KEYFILE)

        # Step 2: the right script describes the file, the wrong one refuses.
        for version in (1, 2, 3):
            backup.write_bytes(js_encrypt(version, SECRET, "pbkdf2", "aes", None, tmp).read_bytes())
            for c in identify:
                r = run_doc_command(c, tmp, stdin="")
                if version in claimed_versions(c):
                    check(r.returncode == 0 and f"KEYM v{version}" in r.stdout,
                          f"v{version}: `{c}` describes it", (r.stderr or r.stdout).strip()[:160])
                else:
                    check(r.returncode != 0, f"v{version}: `{c}` refuses it", r.stdout.strip()[:160])

        # Step 4: the line for this version, with the password on the prompt,
        # and again with the key file the page tells you to add.
        for version in (1, 2, 3):
            for kf in (None, KEYFILE):
                backup.write_bytes(js_encrypt(version, SECRET, "argon2id", "chained", kf, tmp,
                                              tag="-doc").read_bytes())
                for c in decrypt:
                    recovered.unlink(missing_ok=True)
                    r = run_doc_command(c, tmp, stdin=PASSWORD + "\n",
                                        extra=keyfile_args if kf else None)
                    tag = f"v{version}{' +key file' if kf else ''}: `{c}`"
                    if version in claimed_versions(c):
                        got = recovered.read_bytes() if recovered.exists() else b""
                        check(r.returncode == 0 and got == SECRET, f"{tag} recovers the bytes",
                              r.stderr.strip()[:160])
                    else:
                        # Troubleshooting item 1: the wrong script fails, and
                        # writes nothing a reader could mistake for a result.
                        check(r.returncode != 0 and not recovered.exists(),
                              f"{tag} refuses it", r.stderr.strip()[:160])

        # Step 4 with shares: two of three strips, one of them copied by hand.
        base = js_encrypt(3, SECRET, "pbkdf2", "aes", None, tmp, tag="-docshares")
        issued = tmp / "issued.txt"
        r = subprocess.run(
            ["node", str(BRIDGE), "addshares", "--password", PASSWORD,
             "--in", str(base), "--out", str(backup), "--shares-out", str(issued),
             "--threshold", "2", "--shares", "3",
             "--salt", os.urandom(32).hex(), "--share-secret", os.urandom(32).hex(),
             "--share-coefficients", os.urandom(32).hex()],
            capture_output=True, text=True, cwd=ROOT)
        strips = [ln for ln in issued.read_text().split("\n") if ln.strip()] if r.returncode == 0 else []
        check(len(strips) == 3, "issued a share set for the shares command", r.stderr.strip()[:160])
        if len(strips) == 3:
            prefix, _, code = strips[2].partition(":")
            shares_file.write_text("# strips 1 and 3\n" + strips[0] + "\n"
                                   + prefix + ":" + code.lower().replace("-", " ") + "\n")
            for c in shares:
                recovered.unlink(missing_ok=True)
                r = run_doc_command(c, tmp, stdin="")
                got = recovered.read_bytes() if recovered.exists() else b""
                check(r.returncode == 0 and got == SECRET, f"`{c}` recovers the bytes",
                      r.stderr.strip()[:160])

            # Strips that carry the backup: the second code on a strip is the
            # backup's one paper part, exactly as the app prints it. Saved as
            # parts.txt, the page's join turns it back into backup.keym, and
            # the page's shares command then opens that with the strips.
            shared_container = backup.read_bytes()
            r = subprocess.run(["node", str(BRIDGE), "split", "--in", str(backup),
                                "--out", str(tmp / "printed-parts.txt"), "--print"],
                               capture_output=True, text=True, cwd=ROOT)
            printed = [ln for ln in (tmp / "printed-parts.txt").read_text().splitlines() if ln.strip()] \
                if r.returncode == 0 else []
            check(len(printed) == 1 and printed[0].startswith("KMPART2:1/1:"),
                  "a small backup prints as one KMPART2:1/1 part, as the page says",
                  f"{len(printed)} parts: {r.stderr.strip()[:120]}")
            if printed:
                backup.unlink()
                (tmp / "parts.txt").write_text(printed[0] + "\n")
                for c in joins:
                    r = run_doc_command(c, tmp, stdin="")
                    check(r.returncode == 0 and backup.exists() and backup.read_bytes() == shared_container,
                          f"`{c}` rebuilds the backup from a strip's second code", r.stderr.strip()[:160])
                for c in shares:
                    recovered.unlink(missing_ok=True)
                    r = run_doc_command(c, tmp, stdin="")
                    got = recovered.read_bytes() if recovered.exists() else b""
                    check(r.returncode == 0 and got == SECRET,
                          f"and then `{c}` opens it with the strips alone", r.stderr.strip()[:160])

            # "inspect prints it on the line `set code`", and it is what every
            # strip begins with. Run with the page's own inspect line for v3.
            v3_inspect = [c for c in identify if 3 in claimed_versions(c)]
            if v3_inspect:
                r = run_doc_command(v3_inspect[0], tmp, stdin="")
                m = re.search(r"^\s*set code\s+(\S+)$", r.stdout, re.MULTILINE)
                check(m is not None and all(t.startswith("KMSHARE2:" + m.group(1) + "-") for t in strips),
                      "inspect's `set code` is what every strip of the set begins with",
                      r.stdout.strip()[-200:])
            check(re.search(r"KMSHARE2:[0-9A-Z]{4}-[0-9A-Z]{4}-`", doc) is not None
                  and "`set code`" in doc,
                  "the page shows a set code and names inspect's `set code` line")


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
