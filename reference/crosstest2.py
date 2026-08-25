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
import unicodedata
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


def check_call(name: str, fn, expected) -> None:
    """
    check(), for an assertion that has to *call the reference* to evaluate.

    A KeymError becomes a failed check rather than a crash. The reason is the
    one bridge() gives for raising BridgeError instead of CalledProcessError,
    and it generalises: results are printed only at the end of the run, so an
    exception anywhere in the middle prints nothing at all. A malformed
    container produced by a regression would abort the suite and show zero
    failing checks — indistinguishable, at a glance, from a clean run.
    """
    try:
        check(name, fn() == expected)
    except keym2.KeymError as e:
        check(name, False, f"the reference refused: {e}")



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
    """
    A **v2** container, pinned rather than defaulted.

    Both implementations write v3 by default now, and the v2 section below is
    still worth running: v2 containers exist, and the two implementations have
    to keep agreeing about them byte for byte for as long as anyone holds one.
    `bridge.mts` selects v2 whenever no --container-id is given, so this side
    says v2 out loud to match. Left on the default the two would be compared
    across versions and every case would fail at byte 4 — which looks like a
    header disagreement and is really just both sides writing what was asked.
    """
    return keym2.encrypt(
        plaintext,
        PASSWORD,
        kdf_id=keym2.KDF_ARGON2ID if kdf == "argon2id" else keym2.KDF_PBKDF2,
        cipher_id=CIPHER_IDS[cipher],
        keyfile_bytes=keyfile,
        iterations=PBKDF2_ITERS,
        salt=salt,
        master_key=master_key,
        version=keym2.VERSION_V2,
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
        print("\nFrozen v2 and v3 fixtures decrypted by the Python reference:")
        corpus = ROOT / "scripts" / "fixtures" / "keymaker"
        meta = json.loads((corpus / "fixtures.json").read_text())
        fx_pw, fx_kf = meta["password"], bytes.fromhex(meta["keyFileHex"])
        v2_fixtures = [f for f in meta["fixtures"] if f.get("version") == 2]
        v3_fixtures = [f for f in meta["fixtures"] if f.get("version") == 3]
        for f in v2_fixtures + v3_fixtures:
            blob = (corpus / f["file"]).read_bytes()
            # §7.2. A page is a container wearing an HTML document; unwrap it and
            # it takes exactly the same checks as every other frozen vector.
            if f.get("selfextract"):
                blob = keym2.extract_selfextract(blob)
            try:
                # decrypt_report rather than decrypt, because for a v3 vector the
                # verdict is half of what the fixture promises. §5.2 makes the
                # two inseparable: a stripped container that opens is only
                # correct if the reader also says the table changed, and one that
                # says so but refuses to open is worse than v2.
                got = keym2.decrypt_report(blob, fx_pw,
                                           keyfile_bytes=fx_kf if f["keyFile"] else None)
                check(f["name"], got.plaintext.decode() == f["plaintext"])
                # `slotTableAuthentic` is recorded only on v3 entries, which are
                # the only containers carrying a slot_table_mac. Absent means the
                # format makes no claim, and `None` is the answer the reference
                # must give — not False, which would call every v2 vector here
                # tampered with.
                expected_verdict = f.get("slotTableAuthentic")
                check(f"{f['name']}: slot table reported as "
                      f"{'not claimed' if expected_verdict is None else expected_verdict}",
                      got.slot_table_authentic is expected_verdict)
            except keym2.KeymError as e:
                check(f["name"], False, str(e))

            # v3 §1.1. The credential that was cut out of this container's
            # table. Both implementations have to agree that it no longer opens
            # the file — the lock-out is the damage the MAC exists to announce,
            # and a reference that still let this key in would mean the strip
            # had not actually removed anything.
            if "strippedPasskey" in f:
                gone = bytes.fromhex(f["strippedPasskey"]["prfOutputHex"])
                try:
                    keym2.decrypt(blob, prf_output=gone)
                    check(f"{f['name']}: the stripped heir's passkey is refused", False)
                except keym2.KeymError:
                    check(f"{f['name']}: the stripped heir's passkey is refused", True)

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

        modern = v2_fixtures + v3_fixtures
        shamir_fixtures = [f for f in modern if "shamir" in f]
        passkey_fixtures = [f for f in modern if "passkey" in f]
        stripped_fixtures = [f for f in modern if "strippedPasskey" in f]
        # Counted rather than assumed, because the corpus is append-only and a
        # fixture that silently stopped being listed would otherwise just stop
        # being tested. Update deliberately when the corpus grows.
        check("v2+v3 corpus has all twenty-six vectors: six share sets, six "
              "passkeys, one page, one stripped table",
              len(v2_fixtures) == 13 and len(v3_fixtures) == 13
              and len(shamir_fixtures) == 6 and len(passkey_fixtures) == 6
              and len([f for f in v2_fixtures if f.get("selfextract")]) == 1
              and len(stripped_fixtures) == 1,
              f"found {len(v2_fixtures)} v2, {len(v3_fixtures)} v3, "
              f"{len(shamir_fixtures)} shamir, {len(passkey_fixtures)} passkey, "
              f"{len(stripped_fixtures)} stripped")

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
        # 3b. Unicode normalization (§4.1)
        # ---------------------------------------------------------------
        #
        # `build_kdf_input` normalizes to NFC in both implementations, and until
        # now nothing here exercised it: every password in this file is ASCII,
        # and for ASCII the NFC and NFD forms are the same string. The step that
        # matters most for the promise "open this in twenty years with an
        # implementation nobody has written yet" was the one step never
        # compared across the boundary.
        #
        # It matters because the two spellings arrive from different places
        # through no fault of the user. macOS hands out NFD from its
        # filesystem; most Linux and Windows input methods produce NFC; an iOS
        # keyboard and a password manager can disagree about the same typed
        # character. Someone who sets a password with an accent in it on one
        # machine and types the identical password on another must get in.
        #
        # Four cases, because NFC is four mechanisms and an implementation can
        # get some and miss others. A hand-rolled composer that only handles
        # the Latin-1 precomposed table passes the first and fails the rest.
        def _refuses(fn) -> bool:
            try:
                fn()
            except keym2.KeymError:
                return True
            return False

        NFC_CASES = [
            # Canonical composition: base + combining acute -> precomposed.
            ("composition", "cafe\u0301 u\u0308", "caf\u00e9 \u00fc"),
            # Canonical *ordering*: two combining marks supplied in the wrong
            # class order. Composition alone does not fix this; reordering does.
            ("reordering", "q\u0307\u0323w", "q\u0323\u0307w"),
            # Hangul composition, which is algorithmic rather than table-driven.
            ("hangul", "\u1100\u1161\u11a8pw", "\uac01pw"),
            # A singleton mapping: ANGSTROM SIGN -> LATIN CAPITAL A WITH RING.
            ("singleton", "\u212bngstr\u00f6m", "\u00c5ngstr\u00f6m"),
        ]
        print("\nUnicode normalization (§4.1 — NFC, across the boundary):")
        nfc_salt = bytes(range(32))
        for label, decomposed, composed in NFC_CASES:
            # Precondition. Without it a case where the two spellings are the
            # same string proves nothing, and a source file that got normalized
            # by an editor on the way in would make every check below vacuous
            # while still passing.
            check(f"{label}: the two spellings are actually different strings",
                  decomposed != composed,
                  f"both are {decomposed!a}")
            check(f"{label}: Python agrees on the NFC form",
                  unicodedata.normalize("NFC", decomposed) == composed,
                  f"got {unicodedata.normalize('NFC', decomposed)!a}")

            # The conformance claim: same pinned salt and master key, one side
            # given the decomposed spelling and the other the composed one, and
            # the containers must be byte-identical. Anything less than equal
            # bytes means the two derived different keys from what a user would
            # call the same password.
            src = tmp / "nfc-pt.bin"
            src.write_bytes(b"normalization vector")
            js_out = tmp / "nfc-js.keym2"
            bridge("encrypt2", "--password", decomposed, "--in", str(src),
                   "--out", str(js_out), "--cipher", "aes", "--salt", nfc_salt.hex(),
                   "--master-key", MASTER_KEY.hex(), *kdf_flags("pbkdf2"))
            py_bytes = keym2.encrypt(
                b"normalization vector", composed,
                kdf_id=keym2.KDF_PBKDF2, cipher_id=keym2.CIPHER_AES,
                iterations=PBKDF2_ITERS, salt=nfc_salt, master_key=MASTER_KEY,
                version=keym2.VERSION_V2,
            )
            check(f"{label}: js(NFD) and py(NFC) are byte-identical",
                  js_out.read_bytes() == py_bytes,
                  f"js={len(js_out.read_bytes())} py={len(py_bytes)}")

            # And both directions open, which is the property a person
            # experiences: set it on one machine, type it on another.
            try:
                check(f"{label}: python opens the js container with the other spelling",
                      keym2.decrypt(js_out.read_bytes(), composed) == b"normalization vector")
            except keym2.KeymError as e:
                check(f"{label}: python opens the js container with the other spelling",
                      False, f"python refused: {e}")

            py_blob = tmp / "nfc-py.keym2"
            py_blob.write_bytes(py_bytes)
            got = tmp / "nfc-got.bin"
            try:
                bridge("decrypt2", "--password", decomposed, "--in", str(py_blob),
                       "--out", str(got))
                check(f"{label}: js opens the python container with the other spelling",
                      got.read_bytes() == b"normalization vector")
            except BridgeError as e:
                check(f"{label}: js opens the python container with the other spelling",
                      False, f"js refused: {e}")

        # The control on all of the above. If normalization were implemented as
        # "strip anything non-ASCII" — which passes every check so far — this
        # fails: two passwords that are not normalization variants of each other
        # must still be different passwords.
        confusable = tmp / "nfc-confusable.keym2"
        confusable.write_bytes(keym2.encrypt(
            b"normalization vector", "caf\u00e9",
            kdf_id=keym2.KDF_PBKDF2, cipher_id=keym2.CIPHER_AES,
            iterations=PBKDF2_ITERS, salt=nfc_salt, master_key=MASTER_KEY,
            version=keym2.VERSION_V2,
        ))
        for other in ("cafe", "caf", "caf\u00e8"):
            check(f"a password that is not a normalization variant is still refused ({other!a})",
                  _refuses(lambda: keym2.decrypt(confusable.read_bytes(), other)))

        # ---------------------------------------------------------------
        # 3c. The empty key file (§4.1)
        # ---------------------------------------------------------------
        #
        # §4.1 encodes "no key file" as LP(b"") and a present-but-empty one as
        # LP(sha256(b"")) — 32 bytes — specifically so the two cannot collide.
        # Both implementations say so in a comment. Neither had been asked.
        #
        # It could not be asked: `bridge.mts` tested `keyfileHex ? … : null`,
        # and "" is falsy, so an empty key file arrived on the TypeScript side
        # as no key file at all. The one property §4.1 goes out of its way to
        # provide was the one property this harness was structurally unable to
        # check. That is fixed above; this is the check it was blocking.
        #
        # Not a hypothetical input, either. A key file is a file someone
        # chooses, and "the file I picked is zero bytes" happens — a truncated
        # copy, a sync that created the entry before the contents, a
        # placeholder someone meant to fill in. It must not silently become
        # "no key file", because the container it opens is a different one.
        print("\nThe empty key file (§4.1 — present-but-empty is not absent):")
        ek_salt = bytes(range(31, -1, -1))
        ek_pt = b"empty key file vector"

        def py_ek(keyfile):
            return keym2.encrypt(
                ek_pt, PASSWORD, kdf_id=keym2.KDF_PBKDF2,
                cipher_id=keym2.CIPHER_AES, keyfile_bytes=keyfile,
                iterations=PBKDF2_ITERS, salt=ek_salt, master_key=MASTER_KEY,
                version=keym2.VERSION_V2,
            )

        py_none, py_empty = py_ek(None), py_ek(b"")
        check("python: an empty key file is not the same container as no key file",
              py_none != py_empty)
        check("python: only the empty-key-file container sets the key-file flag",
              keym2.parse_slot(
                  py_empty[keym2.SLOT_TABLE_OFFSET:
                           keym2.SLOT_TABLE_OFFSET + keym2.slot_len(keym2.CIPHER_AES)]
              ).keyfile_used
              and not keym2.parse_slot(
                  py_none[keym2.SLOT_TABLE_OFFSET:
                          keym2.SLOT_TABLE_OFFSET + keym2.slot_len(keym2.CIPHER_AES)]
              ).keyfile_used)

        src = tmp / "ek-pt.bin"
        src.write_bytes(ek_pt)
        for label, extra, expected in (
            ("no key file", [], py_none),
            ("an empty key file", ["--keyfile", ""], py_empty),
        ):
            js_out = tmp / "ek-js.keym2"
            bridge("encrypt2", "--password", PASSWORD, "--in", str(src),
                   "--out", str(js_out), "--cipher", "aes", "--salt", ek_salt.hex(),
                   "--master-key", MASTER_KEY.hex(), *kdf_flags("pbkdf2"), *extra)
            check(f"js and py agree byte for byte on {label}",
                  js_out.read_bytes() == expected,
                  f"js={len(js_out.read_bytes())} py={len(expected)}")

        # And the property that makes the distinction worth having: the two are
        # not interchangeable at unlock time, in either implementation.
        check("python refuses the empty-key-file container when given no key file",
              _refuses(lambda: keym2.decrypt(py_empty, PASSWORD)))
        check("python refuses the no-key-file container when given an empty key file",
              _refuses(lambda: keym2.decrypt(py_none, PASSWORD, keyfile_bytes=b"")))

        blob = tmp / "ek-py.keym2"
        blob.write_bytes(py_empty)
        got = tmp / "ek-got.bin"
        try:
            bridge("decrypt2", "--password", PASSWORD, "--keyfile", "",
                   "--in", str(blob), "--out", str(got))
            check("js opens the empty-key-file container with an empty key file",
                  got.read_bytes() == ek_pt)
        except BridgeError as e:
            check("js opens the empty-key-file container with an empty key file",
                  False, f"js refused: {e}")
        js_refused = False
        try:
            bridge("decrypt2", "--password", PASSWORD, "--in", str(blob),
                   "--out", str(tmp / "ek-nope.bin"))
        except BridgeError:
            js_refused = True
        check("js refuses that same container when given no key file", js_refused)

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

        # §6's pairing rule, made observable.
        #
        # Editing a slot's kdf_id byte does not test this. A slot wrapped under
        # a PBKDF2-derived key cannot open through HKDF regardless of the rule,
        # so "disqualified before the KDF" and "derived the wrong key" produce
        # the same answer and the case passes with the rule deleted. That is not
        # hypothetical: it is what the first version of this test did, and the
        # negative control is what caught it.
        #
        # So the slot is *built*: slot_type = passphrase, kdf_id = HKDF, and the
        # master key genuinely sealed under HKDF(build_kdf_input(password)).
        # With the rule, both implementations refuse it before deriving
        # anything. Without the rule it opens on a password that was never
        # stretched, which is the vulnerability §6 exists to prevent, and the
        # control confirms exactly that.
        HKDF_PASSWORD = "a password nothing stretched"
        _core, _records, _payload, _master = keym2.recover_master_key(two_slot, PASSWORD)
        _hkdf_slot = keym2.Slot(
            slot_type=keym2.SLOT_TYPE_PASSPHRASE, kdf_id=keym2.KDF_HKDF,
            slot_flags=0, salt=bytes(range(32)), wrapped_key=b"")
        _prefix = _hkdf_slot.pack_prefix()
        _records2 = _records + [
            _prefix + keym2.wrap_master_key(
                _core, _prefix,
                keym2.derive_slot_key(_hkdf_slot, keym2.build_kdf_input(HKDF_PASSWORD, None)),
                _master)
        ]
        unstretched = (two_slot[:keym2.SLOT_TABLE_OFFSET - 1] + bytes([len(_records2)])
                       + b"".join(_records2) + _payload)

        def rekdf(blob: bytes, index: int, kdf_id: int, params: bytes) -> bytes:
            """Rewrite a slot's kdf_id *and* its 8-byte parameter block.

            Both together, deliberately. Flipping kdf_id alone would leave
            PBKDF2's parameters behind, and §4.6 already refuses an HKDF slot
            whose parameter block is non-zero — so the case would be refused for
            a reason that has nothing to do with the pairing, and would keep
            passing if the pairing rule were deleted. Zeroing the block leaves
            the §6 pairing as the only thing standing between the slot and a
            derivation.
            """
            at = keym2.SLOT_TABLE_OFFSET + index * keym2.slot_len(keym2.CIPHER_AES)
            return (blob[:at + 1] + bytes([kdf_id]) + blob[at + 2:at + 40]
                    + params + blob[at + 48:])

        HKDF_NO_PARAMS = b"\x00" * 8

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
            # §6's pairing, in the direction that is a vulnerability rather
            # than merely wasteful. See `unstretched` above for why the slot is
            # built rather than edited: only a slot that *would* open makes the
            # rule observable.
            ("a passphrase slot wrapped under HKDF does not open, whatever it declares",
             unstretched, HKDF_PASSWORD, False),
            ("...and the honest slots in that same container still do",
             unstretched, PASSWORD, True),
            # Disqualified is not the same as fatal. §4.4 still applies: a slot
            # nobody can use must cost the container nothing.
            ("a slot edited to declare HKDF is skipped, not fatal",
             rekdf(two_slot, 0, keym2.KDF_HKDF, HKDF_NO_PARAMS), PASSWORD2, True),
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

        # What `keym2.py split` actually writes, comments and all.
        #
        # The hand-built file below is bare parts, and `bridge.mts`'s join had a
        # private `#` filter, so between them this suite handed the decoder a
        # text no heir ever holds. The one artefact that matters — the file the
        # CLI produced — had never crossed the boundary. It does now, through
        # the same splitPaperParts the app uses.
        cli_parts_file = tmp / "cli-parts.txt"
        subprocess.run(
            [sys.executable, str(HERE / "keym2.py"), "split",
             "--in", str(long_src), "--out", str(cli_parts_file),
             "--capacity", "1734"],
            check=True,
        )
        cli_text = cli_parts_file.read_text()
        check("the CLI's split output carries # comment lines",
              "# part 1 of" in cli_text, cli_text[:60])
        js_from_cli = tmp / "js-from-cli.bin"
        # Guarded: a divergence here makes the bridge *raise*, and an unguarded
        # call would abort the suite with a traceback instead of printing the
        # one line that names the disagreement — which reads exactly like a
        # negative control that did not fire. It is how this check behaved the
        # first time its control was run.
        try:
            bridge("join", "--in", str(cli_parts_file), "--out", str(js_from_cli))
            joined = js_from_cli.read_bytes()
        except BridgeError as exc:
            joined = None
            js_join_detail = str(exc)
        else:
            js_join_detail = ""
        check("js reassembles the CLI's own split output, comments and all",
              joined == good, js_join_detail)
        check("py reassembles it too, from the same file",
              keym2.decode_parts([ln for ln in cli_text.splitlines()
                                  if ln.strip() and not ln.lstrip().startswith("#")]) == good)

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

        # ---------------------------------------------------------------
        # KEYM v3 (docs/FORMAT-V3-DESIGN.md)
        # ---------------------------------------------------------------
        #
        # Byte equality first, for the same reason §5.1 needed it in v2: the two
        # implementations decode each other's containers happily even when they
        # disagree about how to write one. A v3 container adds two things a
        # round-trip cannot pin — where container_id sits in the widened core
        # header, and what exactly the MAC covers — and both are invisible to
        # anything except comparing bytes.
        print("\nKEYM v3 byte equality (pinned salt, master key and container_id):")
        CONTAINER_ID = bytes.fromhex("0123456789abcdef0123456789abcdef")
        for kdf in ("pbkdf2", "argon2id"):
            for cipher in ("aes", "chacha", "chained"):
                label = f"v3: {kdf} + {cipher}"
                plaintext = b"v3 conformance payload \xf0\x9f\x97\x9d " * 40

                src = tmp / "pt3.bin"
                src.write_bytes(plaintext)
                js_out = tmp / "js3.keym2"
                # Caught, not allowed to propagate. A bridge that refuses to
                # write is a disagreement like any other, and letting it escape
                # aborts the run with no FAIL lines at all — which reads as
                # "nothing noticed" when in fact nothing got to look.
                try:
                    bridge("encrypt2", "--password", PASSWORD, "--in", str(src),
                           "--out", str(js_out), "--cipher", cipher, "--salt", SALT.hex(),
                           "--master-key", MASTER_KEY.hex(),
                           "--container-id", CONTAINER_ID.hex(), *kdf_flags(kdf))
                except BridgeError as e:
                    check(label, False, f"js refused to write: {e}")
                    continue


                py_bytes = keym2.encrypt(
                    plaintext, PASSWORD,
                    kdf_id=keym2.KDF_ARGON2ID if kdf == "argon2id" else keym2.KDF_PBKDF2,
                    cipher_id=CIPHER_IDS[cipher], iterations=PBKDF2_ITERS,
                    salt=SALT, master_key=MASTER_KEY, container_id=CONTAINER_ID,
                    version=keym2.VERSION_V3, enforce_write_policy=False, **ARGON2)
                js_bytes = js_out.read_bytes()

                if py_bytes == js_bytes:
                    check(label, True)
                else:
                    n = min(len(py_bytes), len(js_bytes))
                    at = next((i for i in range(n) if py_bytes[i] != js_bytes[i]), n)
                    if at < keym2.CORE_HEADER_LEN_V3:
                        where = "core header" if at < 8 else f"container_id+{at - 8}"
                    elif at < keym2.SLOT_TABLE_MAC_OFFSET_V3:
                        where = "slot_count"
                    elif at < keym2.SLOT_TABLE_OFFSET_V3:
                        where = f"slot_table_mac+{at - keym2.SLOT_TABLE_MAC_OFFSET_V3}"
                    elif at < keym2.SLOT_TABLE_OFFSET_V3 + keym2.slot_len(CIPHER_IDS[cipher]):
                        where = f"slot+{at - keym2.SLOT_TABLE_OFFSET_V3}"
                    else:
                        where = f"payload+{at - keym2.SLOT_TABLE_OFFSET_V3 - keym2.slot_len(CIPHER_IDS[cipher])}"
                    check(label, False,
                          f"first difference at byte {at} ({where}); "
                          f"py {len(py_bytes)}B, js {len(js_bytes)}B")

        # The §8 vector, pinned in both directions. The document publishes these
        # bytes as what a second implementation must reproduce, so the document
        # is what both are held to here rather than each other.
        print("\nKEYM v3 published test vector (docs/FORMAT-V3-DESIGN.md §8):")
        VEC_PW = "correct horse battery staple — test only"
        VEC_PT = b"Keymaker fixture - KEYM v3 / argon2id / aes-256-gcm"
        VEC_SALT = bytes.fromhex(
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
        VEC_MK = bytes.fromhex(
            "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")
        VEC_CID = bytes.fromhex("0123456789abcdef0123456789abcdef")
        VEC_HEX = (
            "4b45594d030000000123456789abcdef0123456789abcdef015ff0c0fb11b440"
            "58abe6be48b590178d0752bc88f0f3954de69c98a68007c41800010000000000"
            "0000112233445566778899aabbccddeeff00112233445566778899aabbccddee"
            "ff00030001000004008e7b9e001250f449d30882f58e5d93c85bb8a8e6459ea5"
            "8ebba4ecc919f86d5c86811a5e72ed5e5b7f66708362672c51f8cb0a5cf3cd81"
            "3330ece0b1f8961f08f3750ad2414b298413cc7e6e30ae646ca833cfd9c4d76d"
            "55180fb835a8d743ab2900b4543989f311892569c7f62c755f03c23e")
        vec_src = tmp / "vec.bin"
        vec_src.write_bytes(VEC_PT)
        vec_js = tmp / "vec.keym2"
        try:
            bridge("encrypt2", "--password", VEC_PW, "--in", str(vec_src),
                   "--out", str(vec_js), "--cipher", "aes", "--salt", VEC_SALT.hex(),
                   "--master-key", VEC_MK.hex(), "--container-id", VEC_CID.hex(),
                   "--kdf", "argon2id", "--time", "3", "--mem", "65536", "--par", "4")
            check("the TypeScript reproduces the §8 vector",
                  vec_js.read_bytes().hex() == VEC_HEX)
        except BridgeError as e:
            check("the TypeScript reproduces the §8 vector", False, f"js refused: {e}")

        py_vec = keym2.encrypt(VEC_PT, VEC_PW, salt=VEC_SALT, master_key=VEC_MK,
                               container_id=VEC_CID, version=keym2.VERSION_V3)
        check("the reference reproduces the §8 vector", py_vec.hex() == VEC_HEX)

        # ---------------------------------------------------------------
        # v3 §5.2 — the report each implementation makes about the table
        # ---------------------------------------------------------------
        #
        # The attack the format revision exists for, driven across the boundary:
        # the reference writes and strips, the TypeScript reads and must reach
        # the same verdict. A disagreement here is worse than a byte mismatch —
        # it would mean one implementation tells an heir their recovery options
        # are intact when the other can see they are not.
        print("\nKEYM v3 slot-table verdicts (reference writes, TypeScript reads):")
        v3_pw, v3_heir = PASSWORD, PASSWORD2
        fast3 = dict(iterations=PBKDF2_ITERS, kdf_id=keym2.KDF_PBKDF2,
                     enforce_write_policy=False)
        v3_one = keym2.encrypt(b"an heir needs this", v3_pw,
                               version=keym2.VERSION_V3, **fast3)
        v3_two = keym2.add_slot(v3_one, v3_pw, v3_heir,
                                kdf_id=keym2.KDF_PBKDF2, iterations=PBKDF2_ITERS,
                                enforce_write_policy=False)
        v3_core, v3_recs, v3_pay = keym2.parse_container(v3_two)
        _head = bytearray(v3_two[:keym2.slot_table_offset(v3_core.version)])
        _head[keym2.slot_count_offset(v3_core.version)] = 1
        v3_stripped = bytes(_head) + v3_recs[0] + v3_pay
        v3_revoked = keym2.remove_slot(v3_two, 1, unlock_password=v3_pw)
        v2_plain = keym2.encrypt(b"an heir needs this", v3_pw,
                                 version=keym2.VERSION_V2, **fast3)

        for name, blob, want in (
            ("a fresh v3 container", v3_one, "authentic"),
            ("a v3 container with an enrolled second slot", v3_two, "authentic"),
            ("a v3 container whose slot was revoked with a secret", v3_revoked, "authentic"),

            ("a v3 container with a slot stripped", v3_stripped, "not-authentic"),
            ("a v2 container, which has no MAC to check", v2_plain, "absent"),
        ):
            blob_path = tmp / "verdict.keym2"
            blob_path.write_bytes(blob)
            out_path = tmp / "verdict.out"
            try:
                said = bridge_stdout("decrypt2", "--password", v3_pw,
                                     "--in", str(blob_path), "--out", str(out_path))
            except BridgeError as e:
                check(f"{name}: TypeScript reports {want}", False, str(e))
                continue
            check(f"{name}: TypeScript reports {want}",
                  said.strip() == f"slot-table: {want}", said.strip())
            # §5.2 is two requirements, and the second is the one an
            # implementation is most likely to get wrong by being cautious.
            check(f"{name}: the plaintext comes back regardless",
                  out_path.read_bytes() == b"an heir needs this")
            check_call(f"{name}: the reference agrees with the TypeScript",
                       lambda b=blob: {True: "authentic", False: "not-authentic",
                                       None: "absent"}[
                           keym2.decrypt_report(b, v3_pw).slot_table_authentic],
                       want)


        # ---------------------------------------------------------------
        # v3 §5.3 — enrolment re-seals the table, on both sides
        # ---------------------------------------------------------------
        #
        # The TypeScript's enrolment path recomputes slot_table_mac, and until
        # here nothing exercised it: every v3 container above was written and
        # mutated by the reference. Byte equality on the enrolled container
        # covers the MAC and the new slot together, and the verdict check
        # afterwards is what would catch a MAC that is merely *self*-consistent.
        print("\nKEYM v3 enrolment (both implementations add a slot to the same container):")
        SH3_SALT = bytes(range(64, 96))
        SH3_SECRET = bytes(range(96, 128))
        SH3_COEFFS = bytes(range(128, 160))
        K3, N3 = 2, 3

        v3_base = keym2.encrypt(b"v3 enrolment base", PASSWORD,
                                salt=SALT, master_key=MASTER_KEY,
                                container_id=CONTAINER_ID, version=keym2.VERSION_V3,
                                **fast3)
        v3_base_path = tmp / "v3-base.keym2"
        v3_base_path.write_bytes(v3_base)

        py_v3_enrolled, py_v3_shares = keym2.add_shamir_slot(
            v3_base, PASSWORD, K3, N3,
            salt=SH3_SALT, share_secret=SH3_SECRET, coefficients=SH3_COEFFS)

        js_v3_path = tmp / "v3-enrolled-js.keym2"
        js_v3_shares_path = tmp / "v3-enrolled-js.txt"
        try:
            bridge("addshares", "--password", PASSWORD, "--in", str(v3_base_path),
                   "--out", str(js_v3_path), "--shares-out", str(js_v3_shares_path),
                   "--threshold", str(K3), "--shares", str(N3),
                   "--salt", SH3_SALT.hex(), "--share-secret", SH3_SECRET.hex(),
                   "--share-coefficients", SH3_COEFFS.hex())
        except BridgeError as e:
            check("the enrolled v3 container is byte-identical", False,
                  f"js refused to enrol: {e}")
            js_v3_enrolled = None
        else:
            js_v3_enrolled = js_v3_path.read_bytes()


        if js_v3_enrolled is not None:
            check("the enrolled v3 container is byte-identical",
                  py_v3_enrolled == js_v3_enrolled,
                  f"py={len(py_v3_enrolled)}B js={len(js_v3_enrolled)}B")
            check("enrolling on v3 kept container_id unchanged",
                  js_v3_enrolled[8:24] == CONTAINER_ID)
            check("enrolling on v3 did not re-encrypt the payload",
                  js_v3_enrolled[keym2.SLOT_TABLE_OFFSET_V3 + 2 * keym2.slot_len(keym2.CIPHER_AES):]
                  == v3_base[keym2.SLOT_TABLE_OFFSET_V3 + keym2.slot_len(keym2.CIPHER_AES):])
            # A MAC the TypeScript merely agrees with itself about would pass byte
            # equality only if the reference computed the same bytes — which is the
            # point — but this asserts the reference will also *accept* it.
            check_call("the reference accepts the TypeScript's recomputed MAC",
                       lambda: keym2.decrypt_report(
                           js_v3_enrolled, PASSWORD).slot_table_authentic,
                       True)

            js_v3_shares = [ln for ln in js_v3_shares_path.read_text().split("\n") if ln.strip()]
            check("the v3 share set is byte-identical", py_v3_shares == js_v3_shares)
            check_call("the enrolled v3 container opens with the shares",
                       lambda: keym2.decrypt(js_v3_enrolled, shares=js_v3_shares[:K3]),
                       b"v3 enrolment base")


    finally:
        shutil.rmtree(tmp, ignore_errors=True)



    failed = [(n, d) for n, ok, d in results if not ok]
    for name, ok, detail in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {name}" + (f"   {detail}" if detail and not ok else ""))
    print()
    print(f"{len(results) - len(failed)} passed, {len(failed)} failed")
    if failed:
        print("KEYM v2/v3 conformance FAILED — the implementations disagree.")
        return 1
    print("Conformance passed: independent implementations agree on KEYM v2 and v3, "
          "byte for byte.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
