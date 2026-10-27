#!/usr/bin/env python3
"""
The test-vector pack under docs/vectors/ (see its README): generate it from
keym2.py, and check that the committed files still say what keym2.py says.

    python3 reference/vectors.py            check (the default, and what CI runs)
    python3 reference/vectors.py --write    append vectors whose ids are new

The pack is append-only. --check fails if regenerating would change or drop a
committed vector, if a generated vector is missing from the pack, if the count
is not VECTOR_COUNT, if the hex printed in v3 §8 or v4 §8 differs from the pack,
if keym2.py's own primitives disagree with a published known answer, or if
keym2.py accepts a row of reject.json. --write refuses to change a committed
vector, so a wrong one is superseded rather than edited (README, "How the pack
grows").

The TypeScript reproduces the same files in scripts/vectors-test.mts.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PACK = ROOT / "docs" / "vectors"
sys.path.insert(0, str(HERE))
import keym2  # noqa: E402

from argon2.low_level import Type as Argon2Type, hash_secret_raw  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402

FAMILIES = ("primitives", "containers", "shares", "parts", "text", "reject", "accept")
FORMAT = 1

# Asserted here and in scripts/vectors-test.mts, so a vector that silently
# stopped being listed fails both. Adding a vector means changing both.
VECTOR_COUNT = 94

# v3 §8's inputs, the ones every container below varies from.
S8_PASSWORD = "correct horse battery staple \u2014 test only"
S8_SALT = bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
S8_MASTER = bytes(range(0x40, 0x60))
S8_CONTAINER_ID = bytes.fromhex("0123456789abcdef0123456789abcdef")
S8_ARGON2 = {"id": "argon2id", "time_cost": 3, "memory_kib": 65536, "parallelism": 4}
KEYFILE = bytes(range(256)) * 4
REJECT_PASSWORD = "the reject base \u2014 test only"
REJECT_PLAINTEXT = b"reject.json's rows are each one change to this container."


def hx(b: bytes) -> str:
    return b.hex()


# ---------------------------------------------------------------------------
# primitives.json: transcribed, never computed here
# ---------------------------------------------------------------------------

_PYCA = "pyca cryptography_vectors 50.0.2, "


def primitives() -> list[dict]:
    """Published known answers. Each `source` names where the bytes were copied from."""
    hkdf = [
        ("1", "0b" * 22, "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9", 42,
         "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
         "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"),
        ("2", bytes(range(0x00, 0x50)).hex(), bytes(range(0x60, 0xb0)).hex(),
         bytes(range(0xb0, 0x100)).hex(), 82,
         "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
         "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"),
        ("3", "0b" * 22, "", "", 42,
         "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
         "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"),
    ]
    out: list[dict] = []
    for case, ikm, salt, info, length, prk, okm in hkdf:
        out.append({
            "id": f"hkdf-sha256-rfc5869-a{case}", "primitive": "hkdf-sha256",
            "source": f"RFC 5869 Appendix A.{case}, via {_PYCA}KDF/rfc-5869-HKDF-SHA256.txt",
            "note": "The slot keys, the slot-table key and chained mode's subkeys are HKDF-SHA-256.",
            "ikm": ikm, "salt": salt, "info": info, "length": length, "prk": prk, "okm": okm})
    sunscreen = ("Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
                 "for the future, sunscreen would be it.").encode().hex()
    out.append({
        "id": "chacha20poly1305-rfc8439", "primitive": "chacha20-poly1305",
        "source": f"RFC 7539 and RFC 8439 §2.8.2, via {_PYCA}"
                  "ciphers/ChaCha20Poly1305/boringssl.txt COUNT 1",
        "note": "cipher_id 0x01, and the outer layer of 0x02.",
        "key": "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        "nonce": "070000004041424344454647", "aad": "50515253c0c1c2c3c4c5c6c7",
        "plaintext": sunscreen,
        "ciphertext": "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e"
                      "8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c"
                      "9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d265"
                      "86cec64b6116",
        "tag": "1ae10b594f09e26a7e902ecbd0600691"})
    out.append({
        "id": "chacha20poly1305-rfc8439-a5", "primitive": "chacha20-poly1305",
        "source": f"RFC 7539 and RFC 8439 Appendix A.5, as carried in OpenSSL's "
                  f"test/evpciph.txt, via {_PYCA}ciphers/ChaCha20Poly1305/openssl.txt COUNT 1",
        "note": "A 265-byte message, so the final Poly1305 block is partial.",
        "key": "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
        "nonce": "000000000102030405060708", "aad": "f33388860000000000004e91",
        "plaintext": "496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076"
                     "616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64"
                     "206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65"
                     "746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20"
                     "497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d"
                     "447261667473206173207265666572656e6365206d6174657269616c206f7220746f2063"
                     "697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070"
                     "726f67726573732e2fe2809d",
        "ciphertext": "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18"
                      "755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce"
                      "98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e"
                      "2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e9"
                      "9040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04"
                      "b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a10"
                      "73a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d"
                      "6c6f2c29a6ad5cb4022b02709b",
        "tag": "eead9d67890cbb22392336fea1851f38"})
    out.append({
        "id": "aes256gcm-nist-cavp", "primitive": "aes-256-gcm",
        "source": f"NIST CAVP gcmEncryptExtIV256.rsp, [Keylen = 256] [IVlen = 96] "
                  f"[PTlen = 408] [AADlen = 160] [Taglen = 128] Count = 0, via "
                  f"{_PYCA}ciphers/AES/GCM/gcmEncryptExtIV256.rsp",
        "note": "cipher_id 0x00, and the inner layer of 0x02. A 96-bit IV and a 128-bit tag, the only shape the format uses.",
        "key": "24501ad384e473963d476edcfe08205237acfd49b5b8f33857f8114e863fec7f",
        "nonce": "9ff18563b978ec281b3f2794", "aad": "adb5ec720ccf9898500028bf34afccbcaca126ef",
        "plaintext": "27f348f9cdc0c5bd5e66b1ccb63ad920ff2219d14e8d631b3872265cf117ee86757accb1"
                     "58bd9abb3868fdc0d0b074b5f01b2c",
        "ciphertext": "eb7cb754c824e8d96f7c6d9b76c7d26fb874ffbf1d65c6f64a698d839b0b06145dae8205"
                      "7ad55994cf59ad7f67c0fa5e85fab8",
        "tag": "bc95c532fecc594c36d1550286a7a3f0"})
    argon = [
        ("argon2id-rfc9106-5-3", f"RFC 9106 §5.3, via {_PYCA}KDF/argon2id.txt COUNT 0", False,
         "01" * 32, "02" * 16, 3, 32, 4, 32,
         "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
         {"secret": "03" * 8, "ad": "04" * 12},
         "Sets the optional secret and associated data. The format never uses either. "
         "keym2.py's library checks it through its low-level interface, and the "
         "TypeScript's library takes no associated data, so that suite skips it."),
        ("argon2id-openssl-2", f"OpenSSL evpkdf_argon2.txt, via {_PYCA}KDF/argon2id.txt COUNT 2",
         True, "01" * 32, "02" * 16, 3, 32, 4, 32,
         "03aab965c12001c9d7d0d2de33192c0494b684bb148196d73c1df1acaf6d0c2e", {},
         "RFC 9106 §5.3's inputs without the secret and associated data."),
        ("argon2id-cli-4", f"the argon2 command-line tool, via {_PYCA}KDF/argon2id.txt COUNT 4",
         True, b"password".hex(), b"pycasalt".hex(), 4, 50, 4, 8, "e469b777841e543f", {},
         "memory_kib not a multiple of 4 x parallelism, so the lane length rounds down."),
        ("argon2id-cli-5", f"the argon2 command-line tool, via {_PYCA}KDF/argon2id.txt COUNT 5",
         True, b"password".hex(), b"pycasalt".hex(), 1, 8, 1, 4, "009c7809", {},
         "One pass over 8 KiB in one lane, with a 4-byte output. The format itself "
         "always derives 32 bytes."),
    ]
    for vid, source, exercised, pw, salt, t, m, p, length, output, extra, note in argon:
        out.append({"id": vid, "primitive": "argon2id", "source": source,
                    **({} if exercised else {"typescript": False}), "note": note, "password": pw, "salt": salt, "time_cost": t,
                    "memory_kib": m, "parallelism": p, "length": length, "output": output,
                    **extra})
    return out


def _argon2id_with_secret(v: dict) -> bytes:
    """
    RFC 9106 §5.3 sets a secret and associated data, which hash_secret_raw does
    not take. argon2-cffi's low-level context does, through the reference C
    implementation's own entry point.
    """
    from argon2.low_level import ffi, lib, core  # noqa: PLC0415

    fields = {k: bytes.fromhex(v[k]) for k in ("password", "salt", "secret", "ad")}
    keep = {k: ffi.new("uint8_t[]", b) for k, b in fields.items()}
    out = ffi.new("uint8_t[]", v["length"])
    ctx = ffi.new("argon2_context *", dict(
        version=0x13, out=out, outlen=v["length"],
        pwd=keep["password"], pwdlen=len(fields["password"]),
        salt=keep["salt"], saltlen=len(fields["salt"]),
        secret=keep["secret"], secretlen=len(fields["secret"]),
        ad=keep["ad"], adlen=len(fields["ad"]),
        t_cost=v["time_cost"], m_cost=v["memory_kib"], lanes=v["parallelism"],
        threads=v["parallelism"], allocate_cbk=ffi.NULL, free_cbk=ffi.NULL,
        flags=lib.ARGON2_DEFAULT_FLAGS))
    if core(ctx, Argon2Type.ID.value) != 0:
        raise ValueError("argon2_ctx failed")
    return bytes(ffi.buffer(out, v["length"]))


def check_primitives(vectors: list[dict]) -> list[str]:
    """keym2.py's libraries against each published value. Not generated, so checked here."""
    bad: list[str] = []
    for v in vectors:
        try:
            if v["primitive"] == "hkdf-sha256":
                got = HKDF(algorithm=hashes.SHA256(), length=v["length"],
                           salt=bytes.fromhex(v["salt"]),
                           info=bytes.fromhex(v["info"])).derive(bytes.fromhex(v["ikm"]))
                # RFC 5869 §2.2: an absent salt is HashLen zeros.
                prk = hmac.new(bytes.fromhex(v["salt"]) or bytes(32), bytes.fromhex(v["ikm"]),
                               hashlib.sha256).digest()
                ok = got.hex() == v["okm"] and prk.hex() == v["prk"]
            elif v["primitive"] in ("chacha20-poly1305", "aes-256-gcm"):
                aead = (ChaCha20Poly1305 if v["primitive"] == "chacha20-poly1305" else AESGCM)(
                    bytes.fromhex(v["key"]))
                sealed = aead.encrypt(bytes.fromhex(v["nonce"]), bytes.fromhex(v["plaintext"]),
                                      bytes.fromhex(v["aad"]))
                ok = sealed.hex() == v["ciphertext"] + v["tag"]
            elif v["primitive"] == "argon2id" and "secret" in v:
                got = _argon2id_with_secret(v)
                ok = got.hex() == v["output"]
            elif v["primitive"] == "argon2id":
                got = hash_secret_raw(
                    secret=bytes.fromhex(v["password"]), salt=bytes.fromhex(v["salt"]),
                    time_cost=v["time_cost"], memory_cost=v["memory_kib"],
                    parallelism=v["parallelism"], hash_len=v["length"],
                    type=Argon2Type.ID, version=0x13)
                ok = got.hex() == v["output"]
            else:
                ok = False
        except Exception as e:  # noqa: BLE001
            bad.append(f"{v['id']}: {type(e).__name__}: {e}")
            continue
        if not ok:
            bad.append(f"{v['id']}: keym2.py's library does not reproduce the published value")
    return bad


# ---------------------------------------------------------------------------
# containers.json
# ---------------------------------------------------------------------------

_KDF_IDS = {"pbkdf2": keym2.KDF_PBKDF2, "argon2id": keym2.KDF_ARGON2ID}
_CIPHERS = {0: "aes-256-gcm", 1: "chacha20-poly1305", 2: "chained"}


def _container(vid: str, note: str, version: int, cipher: int, kdf: dict, password: str,
               keyfile: bytes | None, plaintext: bytes, salt: bytes, master: bytes,
               container_id: bytes) -> dict:
    kwargs = {"iterations": kdf["iterations"]} if kdf["id"] == "pbkdf2" else {
        "time_cost": kdf["time_cost"], "memory_kib": kdf["memory_kib"],
        "parallelism": kdf["parallelism"]}
    container = keym2.encrypt(
        plaintext, password, kdf_id=_KDF_IDS[kdf["id"]], cipher_id=cipher,
        keyfile_bytes=keyfile, salt=salt, master_key=master, version=version,
        container_id=container_id if version != keym2.VERSION_V2 else None,
        enforce_write_policy=False, **kwargs)
    core, records, _payload = keym2.parse_container(container)
    kdf_input = keym2.build_kdf_input(password, keyfile)
    slot_key = keym2.derive_slot_key(keym2.parse_slot(records[0]), kdf_input)
    vec = {
        "id": vid, "note": note, "version": version, "cipher": _CIPHERS[cipher], "kdf": kdf,
        "password": password, "keyfile": hx(keyfile) if keyfile is not None else None,
        "plaintext": hx(plaintext), "salt": hx(salt), "master_key": hx(master),
        "container_id": hx(container_id) if version != keym2.VERSION_V2 else "",
        "kdf_input": hx(kdf_input), "slot_key": hx(slot_key),
        "core_header": hx(container[:keym2.core_header_len(version)]),
    }
    if version != keym2.VERSION_V2:
        vec["k_table"] = hx(keym2.slot_table_key(master))
        vec["slot_table_mac"] = hx(keym2.read_slot_table_mac(container))
    vec["container"] = hx(container)
    return vec


def containers() -> list[dict]:
    label = "Keymaker fixture - KEYM v{} / {} / {}".format
    pbkdf2 = {"id": "pbkdf2", "iterations": 600_000}
    return [
        _container("v3-s8-argon2id-aes", "v3 §8's vector, byte for byte.", 3, 0, S8_ARGON2,
                   S8_PASSWORD, None, label(3, "argon2id", "aes-256-gcm").encode(), S8_SALT,
                   S8_MASTER, S8_CONTAINER_ID),
        _container("v4-s8-argon2id-aes", "v4 §8's vector, byte for byte.", 4, 0, S8_ARGON2,
                   S8_PASSWORD, None, label(4, "argon2id", "aes-256-gcm").encode(), S8_SALT,
                   S8_MASTER, S8_CONTAINER_ID),
        _container("v3-argon2id-chacha20", "v3 §8's inputs under cipher_id 0x01.", 3, 1,
                   S8_ARGON2, S8_PASSWORD, None,
                   label(3, "argon2id", "chacha20-poly1305").encode(), S8_SALT, S8_MASTER,
                   S8_CONTAINER_ID),
        _container("v3-argon2id-chained", "v3 §8's inputs under cipher_id 0x02, so the "
                   "HKDF subkeys of v2 §4.3 are in play.", 3, 2, S8_ARGON2, S8_PASSWORD, None,
                   label(3, "argon2id", "chained").encode(), S8_SALT, S8_MASTER,
                   S8_CONTAINER_ID),
        _container("v2-pbkdf2-aes", "v2, which has no container_id and no slot-table MAC.",
                   2, 0, pbkdf2, S8_PASSWORD, None, label(2, "pbkdf2", "aes-256-gcm").encode(),
                   S8_SALT, S8_MASTER, b""),
        _container("v3-pbkdf2-aes-keyfile", "A password and a key file (v2 §4.2), so "
                   "kdf_input carries the key file's digest and slot_flags bit 0 is set.",
                   3, 0, pbkdf2, S8_PASSWORD, KEYFILE,
                   label(3, "pbkdf2 + keyfile", "aes-256-gcm").encode(), S8_SALT, S8_MASTER,
                   S8_CONTAINER_ID),
        _container("v3-nfc-password", "A password typed decomposed (e + U+0301), which "
                   "v2 §4.1 normalises to NFC, so kdf_input matches the precomposed é.",
                   3, 0, {"id": "pbkdf2", "iterations": 1000}, "cafe\u0301 \u2014 test only",
                   None, b"normalised", S8_SALT, S8_MASTER, S8_CONTAINER_ID),
        _container("reject-base", "The container every reject.json container row changes "
                   "one field of. Cheap on purpose (PBKDF2, 1,000 iterations).", 3, 0,
                   {"id": "pbkdf2", "iterations": 1000}, REJECT_PASSWORD, None,
                   REJECT_PLAINTEXT, S8_SALT,
                   S8_MASTER, S8_CONTAINER_ID),
    ]


def check_containers_open(vectors: list[dict]) -> list[str]:
    """Each container opens to its plaintext through keym2.py's own reader."""
    bad = []
    for v in vectors:
        try:
            got = keym2.decrypt(bytes.fromhex(v["container"]), v["password"],
                                keyfile_bytes=bytes.fromhex(v["keyfile"]) if v["keyfile"] else None)
        except Exception as e:  # noqa: BLE001
            bad.append(f"{v['id']}: keym2.py does not open it ({type(e).__name__})")
            continue
        if got != bytes.fromhex(v["plaintext"]):
            bad.append(f"{v['id']}: keym2.py opens it to different bytes")
    return bad


# ---------------------------------------------------------------------------
# shares.json, parts.json, text.json
# ---------------------------------------------------------------------------

def shares() -> list[dict]:
    secret, k, n = bytes(range(100, 132)), 3, 5
    coefficients, slot_salt = bytes(range(64)), bytes(range(32))
    sid1, sid2 = keym2.share_set_id(slot_salt), keym2.share_set_id_v2(slot_salt)
    rows = []
    for index, value in keym2.shamir_split(secret, k, n, coefficients=coefficients):
        rows.append({
            "index": index, "value": hx(value),
            "kmshare1": keym2.encode_share(keym2.Share(set_id=sid1, threshold=k, index=index,
                                                       value=value)),
            "kmshare2": keym2.encode_share_v2(keym2.Share(set_id=sid2, threshold=k,
                                                          index=index, value=value)),
        })
    return [{
        "id": "shamir-3-of-5", "note": "v2 §4.6. Any three of the five shares reconstruct "
        "secret; the k lowest-indexed are the ones a reader uses.",
        "secret": hx(secret), "k": k, "n": n, "coefficients": hx(coefficients),
        "slot_salt": hx(slot_salt), "set_id_v1": hx(sid1), "set_id_v2": hx(sid2),
        "set_code": keym2.share_set_code(slot_salt), "shares": rows,
    }]


def parts(base: bytes) -> list[dict]:
    return [{
        "id": "parts-v3-s8-64", "note": "v2 §7.1 and §7.3, of v3 §8's container, 64 bytes a part.",
        "container": hx(base), "capacity": 64,
        "kmpart1": keym2.encode_parts(base, 64), "kmpart2": keym2.encode_parts_v2(base, 64),
    }]


def text(base: bytes) -> list[dict]:
    lengths = [8, 9, 255, 256, 257, 300, 1000, 1024, 1025, 4096, 65535, 65536, 65537,
               1048576, 1048584, 1_000_000_007, (1 << 40) + 1]
    return [
        {"id": "ignorable", "note": "§7, Characters a reader ignores. A reader's own table "
         "must equal this exactly.",
         "ignorable": sorted(ord(c) for c in keym2.IGNORABLE)},
        {"id": "armor-v3-s8", "note": "§7 of v3 §8's container, wrapped at 64 columns and on "
         "one line. Line breaks are presentation only.",
         "container": hx(base), "wrapped": keym2.armor(base),
         "compact": keym2.armor(base, columns=0)},
        {"id": "padded-len", "note": "v4 §4.2, on each side of the floor and of several "
         "powers of two.", "padded_len": [[n, keym2.padded_len(n)] for n in lengths]},
    ]


# ---------------------------------------------------------------------------
# reject.json
# ---------------------------------------------------------------------------

def _flip(data: bytes, at: int, value: int) -> str:
    out = bytearray(data)
    out[at] = value
    return hx(bytes(out))


def _record(core: bytes, *, slot_type: int = keym2.SLOT_TYPE_PASSPHRASE,
            kdf_id: int = keym2.KDF_PBKDF2, slot_flags: int = 0, slot_reserved: int = 0,
            params: bytes | None = None, iterations: int = 1000, time_cost: int = 0,
            memory_kib: int = 0, parallelism: int = 0, dummy_key: bool = False) -> bytes:
    """
    One slot record wrapping S8_MASTER, its AAD over the bytes as written.

    `dummy_key` wraps under 32 zero bytes instead of the derived key: for a slot
    a reader must skip before deriving anything, where deriving it here would
    only cost time (or, for memory_kib below 8 x parallelism, cannot be done).
    """
    slot = keym2.Slot(slot_type=slot_type, kdf_id=kdf_id, slot_flags=slot_flags,
                      salt=S8_SALT, wrapped_key=b"", iterations=iterations,
                      time_cost=time_cost, memory_kib=memory_kib, parallelism=parallelism)
    prefix = bytearray(slot.pack_prefix())
    prefix[3] = slot_reserved
    if params is not None:
        prefix[keym2.SLOT_PARAMS_OFFSET:keym2.SLOT_PARAMS_OFFSET + keym2.KDF_PARAM_LEN] = params
    prefix = bytes(prefix)
    slot_key = bytes(32) if dummy_key else keym2._stretch(
        slot, keym2.build_kdf_input(REJECT_PASSWORD, None))
    aes, chacha = keym2.wrap_keys(keym2.CIPHER_AES, slot_key)
    return prefix + keym2._seal(keym2.CIPHER_AES, aes, chacha, keym2.WRAP_NONCE,
                                S8_MASTER, core + prefix)


def _sealed(*, flags: int = 0, reserved: int = 0, slots: list[dict] | None = None,
            copies: int = 1, final: bool = True, version: int = 3,
            stream: bytes | None = None, table_from: list[dict] | None = None) -> bytes:
    """
    A container sealed correctly around one deliberate violation.

    Every AAD, wrap, tag and the slot-table MAC are computed over the bytes as
    written, so nothing but the rule the row names refuses it: a reader that
    skips that rule opens it. Built from keym2.py's own primitives rather than
    its writer, because the writer refuses to produce any of these.

    `table_from` computes the MAC over a different slot table from the one
    written, which is what a stripped table looks like (v3 §5.2).
    """
    core = keym2.MAGIC + bytes([version, keym2.CIPHER_AES, flags, reserved]) + S8_CONTAINER_ID
    records = [_record(core, **s) for s in (slots or [{}])] * copies
    macced = records if table_from is None else [_record(core, **s) for s in table_from]
    mac = hmac.new(keym2.slot_table_key(S8_MASTER),
                   core + bytes([len(macced)]) + b"".join(macced), hashlib.sha256).digest()
    if stream is None:
        stream = keym2.pad_stream(REJECT_PLAINTEXT) if version == 4 else REJECT_PLAINTEXT
    aes, chacha = keym2.payload_keys(keym2.CIPHER_AES, S8_MASTER)
    payload = keym2._seal(keym2.CIPHER_AES, aes, chacha, keym2.nonce_for(0, final), stream, core)
    return core + bytes([len(records)]) + mac + b"".join(records) + payload


# The slot-level violations: each disqualifies its slot alone (v2 §4.4), and a
# container whose only slot is disqualified is refused by exhaustion (v2 §6).
_ARGON = keym2.KDF_ARGON2ID
BAD_SLOTS = [
    ("slot-type-unknown", dict(slot_type=0x07),
     "A slot type the reader does not implement is skipped, never guessed at."),
    ("slot-flags-reserved", dict(slot_flags=0x02), "slot_flags bits 1 to 7 are reserved."),
    ("slot-reserved", dict(slot_reserved=0x01), "Slot bytes 3 to 7 are reserved."),
    ("kdf-pairing", dict(kdf_id=keym2.KDF_HKDF),
     "A passphrase slot never declares HKDF, which would be a password with no stretching."),
    ("pbkdf2-param-reserved", dict(params=struct.pack(">I", 1000) + b"\x01\x00\x00\x00"),
     "The last four PBKDF2 parameter bytes are reserved (v2 §3.2)."),
    ("pbkdf2-iterations-over", dict(iterations=10_000_001),
     "PBKDF2 iterations above 10,000,000, refused before any derivation."),
    ("argon2id-time-over", dict(kdf_id=_ARGON, time_cost=11, memory_kib=8, parallelism=1),
     "Argon2id time_cost above 10."),
    ("argon2id-memory-over", dict(kdf_id=_ARGON, time_cost=1, memory_kib=262_145, parallelism=1),
     "Argon2id memory_kib above 262,144, refused before allocating it."),
    ("argon2id-parallelism-over", dict(kdf_id=_ARGON, time_cost=1, memory_kib=72, parallelism=9),
     "Argon2id parallelism above 8."),
]


def reject(base: bytes, share_vec: dict, parts_vec: dict) -> list[dict]:
    """Inputs a reader MUST refuse, each one change to a known-good input."""
    # The sealer, given nothing to violate, must be the format itself, in v3 and v4.
    if _sealed() != base:
        raise SystemExit("vectors.py: _sealed() does not reproduce reject-base; "
                         "the authentic rows would not be containers")
    v4 = keym2.encrypt(REJECT_PLAINTEXT, REJECT_PASSWORD, kdf_id=keym2.KDF_PBKDF2,
                       iterations=1000, salt=S8_SALT, master_key=S8_MASTER,
                       container_id=S8_CONTAINER_ID, version=4, enforce_write_policy=False)
    if _sealed(version=4) != v4:
        raise SystemExit("vectors.py: _sealed(version=4) is not the v4 format")
    slot = keym2.slot_table_offset(3)               # 57 for v3
    payload = slot + keym2.slot_len(keym2.CIPHER_AES)
    params = slot + keym2.SLOT_PARAMS_OFFSET
    n = len(REJECT_PLAINTEXT)
    prefix = struct.pack(">Q", n)
    padded = keym2.pad_stream(REJECT_PLAINTEXT)
    loud = bytearray(padded)
    loud[-1] = 0x01

    # Sealed correctly around one violation: only the named rule refuses them.
    authentic = [
        ("core-flags", "v2 §3.3", _sealed(flags=0x01), "The flags byte is entirely reserved."),
        ("core-reserved", "v2 §3", _sealed(reserved=0x01), "The reserved header byte is non-zero."),
        ("slot-count-nine", "v2 §6", _sealed(copies=9),
         "Nine well-formed slots, the first of which opens. slot_count is outside 1..8."),
    ]
    authentic += [(name, "v2 §4.4, v2 §6", _sealed(slots=[slot_kw]),
                   note + " The only slot is disqualified, so the table is exhausted. "
                   "accept.json holds the same slot beside a good one.")
                  for name, slot_kw, note in BAD_SLOTS]
    authentic += [
        ("final-flag", "v2 §5.2", _sealed(final=False),
         "The only chunk is sealed with final_flag 0, so the stream has no end."),
        ("v4-too-short", "v4 §4.4 step 1", _sealed(version=4, stream=b"\x00" * 7),
         "A v4 stream shorter than its 8-byte length prefix."),
        ("v4-length-overrun", "v4 §4.4 step 3",
         _sealed(version=4, stream=struct.pack(">Q", 1000) + padded[8:]),
         "The length prefix claims more bytes than the stream holds."),
        ("v4-wrong-bucket", "v4 §4.4 step 4",
         _sealed(version=4, stream=prefix + REJECT_PLAINTEXT + bytes(512 - 8 - n)),
         "The stream is 512 bytes, but padded_len(8 + L) is 256."),
        ("v4-padding-nonzero", "v4 §4.4 step 5", _sealed(version=4, stream=bytes(loud)),
         "The last padding byte is 0x01."),
    ]
    # Refused by their structure; these check a reader refuses rather than crashes.
    structural = [
        ("magic", "v2 §3", _flip(base, 0, ord("X")), "The magic is KEYM."),
        ("version-unknown", "v2 §3, v3 §3", _flip(base, 4, 0x05), "No version 5 exists."),
        ("cipher-unknown", "v2 §3", _flip(base, 5, 0x03), "cipher_id 0x03 is not defined."),
        ("slot-count-zero", "v2 §6", _flip(base, 24, 0),
         "slot_count outside 1..8. With no slot to try, exhaustion refuses it too."),
        ("cut-in-header", "v2 §6", hx(base[:20]), "Shorter than payload_offset."),
        ("cut-before-tag", "v2 §6", hx(base[:payload + 15]),
         "Shorter than payload_offset plus one chunk's tag."),
        ("pbkdf2-iterations-zero", "v2 §6", hx(bytes(base[:params]) + struct.pack(">I", 0)
                                              + base[params + 4:]),
         "PBKDF2 iterations below 1. No library derives with zero, so a reader that "
         "skips the bound must still refuse it, not crash."),
        ("wrapped-key", "v2 §4.3, v2 §6", _flip(base, slot + keym2.SLOT_PREFIX_LEN,
                                                 base[slot + keym2.SLOT_PREFIX_LEN] ^ 1),
         "The wrapped master key fails its tag, which exhausts the table."),
        ("payload-byte", "v2 §5.4", _flip(base, payload, base[payload] ^ 1),
         "A payload byte fails chunk 0's tag."),
        ("payload-cut", "v2 §5.2, v2 §5.4", hx(base[:-1]),
         "The final chunk is one byte short, so its tag fails."),
        ("wrong-password", "v2 §6", hx(base),
         "The right container with the wrong password, so no slot opens."),
    ]
    rows = [{"id": f"reject-container-{name}", "rule": rule, "kind": "container",
             "authentic": True, "password": REJECT_PASSWORD, "input": hx(data), "note": note}
            for name, rule, data, note in authentic]
    rows += [{"id": f"reject-container-{name}", "rule": rule, "kind": "container",
              "authentic": False,
              "password": REJECT_PASSWORD + ("!" if name == "wrong-password" else ""),
              "input": data, "note": note}
             for name, rule, data, note in structural]

    arm = keym2.armor(base, columns=0)
    rows += [
        {"id": "reject-armor-uppercase-prefix", "rule": "v2 §7", "kind": "armor",
         "input": "KEYM2:" + arm[len("keym2:"):], "note": "The prefix is case-sensitive."},
        {"id": "reject-armor-outside-alphabet", "rule": "v2 §7", "kind": "armor",
         "input": arm[:20] + "!" + arm[21:], "note": "A character outside base64url."},
        {"id": "reject-armor-control", "rule": "v2 §7", "kind": "armor",
         "input": arm[:20] + "\u001c" + arm[20:],
         "note": "U+001C is a control character, not IGNORABLE."},
    ]

    sid = bytes.fromhex(share_vec["set_id_v1"])
    s1 = share_vec["shares"][0]

    def v1_share(threshold: int, index: int, value: bytes) -> str:
        body = sid + bytes([threshold, index]) + value
        return keym2.SHARE_PREFIX + keym2._b32_encode(body + keym2._share_checksum(body))

    value1 = bytes.fromhex(s1["value"])
    flat = s1["kmshare1"].replace("-", "")
    record = bytearray(keym2.decode_share(s1["kmshare1"]).pack())
    record[-1] ^= 1
    rows += [
        {"id": "reject-share-k-one", "rule": "v2 §6", "kind": "share",
         "input": v1_share(1, 1, value1), "note": "k outside 2..16, with a valid checksum."},
        {"id": "reject-share-k-seventeen", "rule": "v2 §6", "kind": "share",
         "input": v1_share(17, 1, value1), "note": "k outside 2..16, with a valid checksum."},
        {"id": "reject-share-index-zero", "rule": "v2 §6", "kind": "share",
         "input": v1_share(3, 0, value1), "note": "Index 0 is the secret's own point."},
        {"id": "reject-share-checksum", "rule": "v2 §6", "kind": "share",
         "input": keym2.SHARE_PREFIX + keym2._b32_encode(bytes(record)),
         "note": "The checksum does not match the record."},
        {"id": "reject-share-padding-bits", "rule": "v2 §4.6, v2 §6", "kind": "share",
         "input": flat[:-1] + keym2.B32_ALPHABET[keym2.B32_ALPHABET.index(flat[-1]) | 1],
         "note": "The final character carries a non-zero padding bit."},
        {"id": "reject-share-dotless-i", "rule": "v2 §7", "kind": "share",
         "input": flat[:9] + flat[9:].replace("1", "\u0131", 1),
         "note": "Folding is ASCII-only, so U+0131 is not I."},
    ]
    texts = [s["kmshare1"] for s in share_vec["shares"]]
    rows += [
        {"id": "reject-combine-too-few", "rule": "v2 §6", "kind": "combine",
         "input": "\n".join(texts[:2]), "note": "Two shares of a 3-of-5 set."},
        {"id": "reject-combine-repeat-for-missing", "rule": "v2 §6", "kind": "combine",
         "input": "\n".join([texts[0], texts[0], texts[1]]),
         "note": "A share supplied twice counts once, so this is two of three."},
        {"id": "reject-combine-same-index", "rule": "v2 §6", "kind": "combine",
         "input": "\n".join([texts[0], v1_share(3, 1, bytes(32)), texts[1], texts[2]]),
         "note": "Two different shares at index 1."},
        {"id": "reject-combine-k-disagrees", "rule": "v2 §6", "kind": "combine",
         "input": "\n".join([texts[0], texts[1], v1_share(4, 3, bytes(32))]),
         "note": "The members disagree about k."},
    ]
    # KMSHARE2, the version a writer emits now (§4.6 v2), with its 16-byte set id.
    sid2 = bytes.fromhex(share_vec["set_id_v2"])
    v2 = [s["kmshare2"] for s in share_vec["shares"]]
    v2rec = bytearray(keym2._pack_share_v2(keym2.decode_share_any(v2[0])))
    v2rec[-1] ^= 1
    v2flat = v2[0].replace("-", "")
    other_sid = sid2[:-1] + bytes([sid2[-1] ^ 1])
    other_set = [_v2_share(other_sid, 3, x, v) for x, v in
                 keym2.shamir_split(bytes(32), 3, 5, coefficients=bytes(64))]
    rows += [
        {"id": "reject-share2-k-one", "rule": "v2 §6", "kind": "share",
         "input": _v2_share(sid2, 1, 1, value1), "note": "k outside 2..16, with a valid checksum."},
        {"id": "reject-share2-index-zero", "rule": "v2 §6", "kind": "share",
         "input": _v2_share(sid2, 3, 0, value1), "note": "Index 0 is the secret's own point."},
        {"id": "reject-share2-checksum", "rule": "v2 §6", "kind": "share",
         "input": keym2.SHARE2_PREFIX + keym2._b32_encode(bytes(v2rec)),
         "note": "The 16-byte checksum does not match the record."},
        {"id": "reject-share2-padding-bits", "rule": "v2 §4.6, v2 §6", "kind": "share",
         "input": v2flat[:-1] + keym2.B32_ALPHABET[keym2.B32_ALPHABET.index(v2flat[-1]) | 1],
         "note": "The final character carries a non-zero padding bit."},
        {"id": "reject-combine-two-sets", "rule": "v2 §6", "kind": "combine",
         "input": "\n".join([v2[0], v2[1], other_set[2]]),
         "note": "Two shares of one set and one of a set whose id differs only in its "
                 "last byte, so a reader that compares the first four bytes takes them "
                 "for one set."},
        {"id": "reject-combine-v1-with-v2", "rule": "v2 §6", "kind": "combine",
         "input": "\n".join([texts[0], v2[1], v2[2]]),
         "note": "KMSHARE1 and KMSHARE2 strips of the same split. Their set ids differ in "
                 "length, so they are not one set."},
    ]
    p2 = parts_vec["kmpart2"]
    damaged = p2[0][:-1] + ("A" if p2[0][-1] != "A" else "B")
    rows += [
        {"id": "reject-parts-missing", "rule": "v2 §7.3", "kind": "parts",
         "input": "\n".join(p2[:-1]), "note": "Every part is needed."},
        {"id": "reject-parts-twice", "rule": "v2 §7.3", "kind": "parts",
         "input": "\n".join(p2 + [p2[0]]), "note": "A part supplied twice."},
        {"id": "reject-parts-checksum", "rule": "v2 §7.3", "kind": "parts",
         "input": "\n".join([damaged] + p2[1:]), "note": "A part's checksum does not match."},
    ]
    return rows


def _v2_share(sid: bytes, threshold: int, index: int, value: bytes) -> str:
    """A KMSHARE2 text with a valid checksum, whatever its fields (none validated)."""
    body = sid + bytes([threshold, index]) + value
    return keym2.SHARE2_PREFIX + keym2._b32_encode(body + keym2._share_checksum_v2(body))


def _v1_share(sid: bytes, threshold: int, index: int, value: bytes) -> str:
    """A KMSHARE1 text with a valid checksum, whatever its fields (none validated)."""
    body = sid + bytes([threshold, index]) + value
    return keym2.SHARE_PREFIX + keym2._b32_encode(body + keym2._share_checksum(body))


def accept(base: bytes, share_vec: dict, parts_vec: dict) -> list[dict]:
    """
    Inputs a reader MUST open, each something a reader is tempted to refuse.
    Every reader in the format is here at least once, so a reader that refuses
    everything fails this family, not only reject.json's base.
    """
    rows: list[dict] = []

    def container(vid: str, rule: str, data: bytes, note: str, table: str = "authentic") -> None:
        rows.append({"id": vid, "rule": rule, "kind": "container", "password": REJECT_PASSWORD,
                     "input": hx(data), "expect": hx(REJECT_PLAINTEXT), "slot_table": table,
                     "note": note})

    good = {}
    for name, kw, note in BAD_SLOTS:
        container(f"accept-skip-{name}", "v2 §4.4", _sealed(slots=[{**kw, "dummy_key": True}, good]),
                  "Slot 0 is disqualified (" + note.rstrip(".") + "), and slot 1 opens. "
                  "Refusing the container here loses data a good slot protects.")
    container("accept-skip-argon2id-memory-below-lanes", "v2 §4.4, v2 §6",
              _sealed(slots=[dict(kdf_id=_ARGON, time_cost=1, memory_kib=1, parallelism=8,
                                  dummy_key=True), good]),
              "Slot 0 declares memory_kib 1 and parallelism 8. §6 admits both, but Argon2id "
              "needs memory_kib of at least 8 x parallelism, so no library can derive it. "
              "The slot is skipped, and slot 1 opens.")
    container("accept-skip-wrong-wrap", "v2 §4.4, v2 §6",
              _sealed(slots=[{"dummy_key": True}, good]),
              "Slot 0 is well formed but wrapped under another key, so the password does "
              "not open it. The walk goes on, and slot 1 opens.")
    container("accept-eight-slots", "v2 §6", _sealed(slots=[{"dummy_key": True}] * 7 + [good]),
              "slot_count 8, the most §6 admits. Only the last slot opens.")
    container("accept-stripped-table", "v3 §5.2",
              _sealed(slots=[good], table_from=[good, {"dummy_key": True}]),
              "A slot was removed after the MAC was computed, so slot_table_mac does not "
              "verify. v3 §5.2 says open it and report that the table changed, never refuse.",
              table="changed")

    # Armor with every IGNORABLE character inside it (§7).
    compact = keym2.armor(base, columns=0)
    body = compact[len("keym2:"):]
    step = max(1, len(body) // (len(keym2.IGNORABLE) + 1))
    spread = "".join(ch + body[i * step:(i + 1) * step]
                     for i, ch in enumerate(keym2.IGNORABLE)) + body[len(keym2.IGNORABLE) * step:]
    rows.append({"id": "accept-armor-every-ignorable", "rule": "v2 §7", "kind": "armor",
                 "input": "\ufeff keym2:" + spread + "\u3000\n", "expect": hx(base),
                 "note": "v3 §8's armor with each IGNORABLE character once inside its body "
                         "and some at either end."})

    # Shares (§4.6, §6).
    sv = share_vec
    sid2 = bytes.fromhex(sv["set_id_v2"])
    by_index = {s["index"]: s for s in sv["shares"]}
    s3 = by_index[3]
    respelt = s3["kmshare2"].lower().replace("-", " ").replace("1", "l").replace("0", "o")
    rows.append({"id": "accept-share-respelt", "rule": "v2 §4.6", "kind": "share",
                 "input": "\t" + respelt.replace("kmshare2:", "KmShArE2:", 1) + "\u00a0",
                 "expect": {"set_id": sv["set_id_v2"], "k": sv["k"], "index": 3,
                            "value": s3["value"]},
                 "note": "Share 3 in lower case, with spaces for hyphens, l for 1 and o for 0, "
                         "and ignorable characters at both ends."})

    def combine(vid: str, rule: str, lines: list[str], note: str) -> None:
        rows.append({"id": vid, "rule": rule, "kind": "combine", "input": "\n".join(lines),
                     "expect": sv["secret"], "note": note})

    combine("accept-combine-v1-any-order", "v2 §4.6",
            [by_index[i]["kmshare1"] for i in (5, 3, 1)],
            "Shares 5, 3 and 1, out of order. A reader interpolates at each share's own "
            "index, never at its position in the list.")
    combine("accept-combine-v2-any-order", "v2 §4.6",
            [by_index[i]["kmshare2"] for i in (4, 2, 5)], "Shares 4, 2 and 5, out of order.")
    combine("accept-combine-k-lowest", "v2 §6",
            [_v2_share(sid2, sv["k"], 9, bytes(range(32)))]
            + [by_index[i]["kmshare2"] for i in (2, 3, 1)],
            "A share at index 9 from the same set with a valid checksum but the wrong "
            "value, listed first, then shares 2, 3 and 1. §6 reconstructs from the k "
            "lowest indices, so index 9 is never used.")
    combine("accept-combine-repeat", "v2 §6",
            [by_index[1]["kmshare2"], by_index[1]["kmshare2"].lower(), by_index[2]["kmshare2"],
             by_index[3]["kmshare2"]],
            "Share 1 twice, in two spellings, with shares 2 and 3. A share supplied twice "
            "counts once.")
    combine("accept-combine-lines", "v2 §7",
            ["# shares 1, 2 and 4", by_index[1]["kmshare2"], "", "\u0085",
             by_index[2]["kmshare2"] + "\r", by_index[4]["kmshare2"]],
            "A comment, a blank line and a line of only U+0085 are skipped, and a line "
            "ending in CR is one line (§7, one item per line).")

    # Paper parts (§7.1, §7.3).
    p2 = parts_vec["kmpart2"]
    lines = []
    for j, part in enumerate(reversed(p2)):
        lines += [f"# part {len(p2) - j} of {len(p2)}", part[:30] + "\u2028" + part[30:]]
    rows.append({"id": "accept-parts-any-order", "rule": "v2 §7.3, v2 §7", "kind": "parts",
                 "input": "\r\n".join(lines), "expect": parts_vec["container"],
                 "note": "KMPART2 parts in reverse order, each with a comment line before it, "
                         "U+2028 inside it and CRLF line ends."})
    return rows


def _open_container(r: dict) -> tuple[bytes, str]:
    """Open an accept row through keym2.py, noting whether it reported the table."""
    changed: list[bytes] = []
    got = keym2.decrypt(bytes.fromhex(r["input"]), r["password"],
                        on_slot_table_change=changed.append)
    return got, "changed" if changed else "authentic"


def check_accept(rows: list[dict]) -> list[str]:
    """keym2.py opens each row to what it expects."""
    bad = []
    for r in rows:
        try:
            if r["kind"] == "container":
                got, table = _open_container(r)
                if table != r["slot_table"]:
                    bad.append(f"{r['id']}: keym2.py reports the slot table {table}, "
                               f"expected {r['slot_table']} ({r['rule']})")
                ok = got.hex() == r["expect"]
            elif r["kind"] == "armor":
                ok = keym2.dearmor(r["input"]).hex() == r["expect"]
            elif r["kind"] == "share":
                s = keym2.decode_share_any(r["input"])
                ok = {"set_id": s.set_id.hex(), "k": s.threshold, "index": s.index,
                      "value": s.value.hex()} == r["expect"]
            elif r["kind"] == "combine":
                ok = keym2.combine_shares(keym2.text_lines(r["input"])).hex() == r["expect"]
            elif r["kind"] == "parts":
                ok = keym2.decode_parts_any(keym2.text_lines(r["input"])).hex() == r["expect"]
            else:
                bad.append(f"{r['id']}: unknown kind {r['kind']}")
                continue
        except Exception as e:  # noqa: BLE001
            bad.append(f"{r['id']}: keym2.py does not open it ({type(e).__name__}, {r['rule']})")
            continue
        if not ok:
            bad.append(f"{r['id']}: keym2.py reads it as something else ({r['rule']})")
    return bad


def check_reject(rows: list[dict]) -> list[str]:
    """
    keym2.py refuses each row with v2 §6's one generic failure, or for parts
    with §7.3's own ValueError naming the problem. Anything else is a crash, or
    a refusal that says more than §6 lets it.
    """
    bad = []
    for r in rows:
        try:
            if r["kind"] == "container":
                keym2.decrypt(bytes.fromhex(r["input"]), r["password"])
            elif r["kind"] == "armor":
                keym2.dearmor(r["input"])
            elif r["kind"] == "share":
                keym2.decode_share_any(r["input"])
            elif r["kind"] == "combine":
                keym2.combine_shares(keym2.text_lines(r["input"]))
            elif r["kind"] == "parts":
                keym2.decode_parts_any(keym2.text_lines(r["input"]))
            else:
                bad.append(f"{r['id']}: unknown kind {r['kind']}")
                continue
            bad.append(f"{r['id']}: keym2.py accepted it ({r['rule']})")
        except keym2.KeymError as e:
            if r["kind"] == "parts" or str(e) != "decryption failed":
                bad.append(f"{r['id']}: keym2.py refused it with {e!r}, not §6's failure")
        except Exception as e:  # noqa: BLE001
            if not (r["kind"] == "parts" and type(e) is ValueError):
                bad.append(f"{r['id']}: keym2.py crashed instead of refusing ({e!r})")
    return bad


# ---------------------------------------------------------------------------
# The pack
# ---------------------------------------------------------------------------

def build() -> dict[str, list[dict]]:
    cont = containers()
    base = bytes.fromhex(next(v for v in cont if v["id"] == "v3-s8-argon2id-aes")["container"])
    reject_base = bytes.fromhex(next(v for v in cont if v["id"] == "reject-base")["container"])
    sh = shares()
    pa = parts(base)
    return {"primitives": primitives(), "containers": cont, "shares": sh, "parts": pa,
            "text": text(base), "reject": reject(reject_base, sh[0], pa[0]),
            "accept": accept(base, sh[0], pa[0])}


def guarded_build() -> tuple[dict[str, list[dict]] | None, str]:
    """build(), with a crash reported as a problem rather than a traceback."""
    try:
        return build(), ""
    except Exception as e:  # noqa: BLE001
        import traceback  # noqa: PLC0415
        where = traceback.extract_tb(e.__traceback__)[-1]
        return None, (f"keym2.py could not generate the pack ({type(e).__name__}: {e}, "
                      f"at {where.name}:{where.lineno})")


def render(family: str, vectors: list[dict]) -> str:
    # ensure_ascii, so every non-ASCII character is a \\u escape. A tool that
    # normalises Unicode in a file it rewrites cannot then silently turn
    # v3-nfc-password's decomposed é into the precomposed one it exists to test.
    return json.dumps({"family": family, "format": FORMAT, "vectors": vectors},
                      indent=2, ensure_ascii=True) + "\n"


def load(family: str) -> list[dict]:
    path = PACK / f"{family}.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["vectors"]


def _design_hex(doc: str) -> dict[str, str]:
    """§8's printed bytes: the intermediates and the container."""
    text_ = (ROOT / "docs" / doc).read_text(encoding="utf-8")
    s8 = text_[text_.index("\n## 8. Test vector"):]
    found: dict[str, str] = {}
    for name in ("core_header", "K_table", "slot_table_mac"):
        m = re.search(rf"^{name}\s+([0-9a-f]+)\s*$", s8, re.M)
        if m:
            found[name] = m.group(1)
    m = re.search(r"\*\*Container\*\*.*?```\n([0-9a-f\n]+)```", s8, re.S)
    if m:
        found["container"] = m.group(1).replace("\n", "")
    return found


def check_readers(pack: dict[str, list[dict]]) -> list[str]:
    """keym2.py's readers on the good inputs the writer families hold."""
    bad = []

    def expect(vid: str, what: str, fn) -> None:
        try:
            if not fn():
                bad.append(f"{vid}: keym2.py reads {what} wrongly")
        except Exception as e:  # noqa: BLE001
            bad.append(f"{vid}: keym2.py refuses {what} ({type(e).__name__})")

    for v in pack["shares"]:
        for s in v["shares"]:
            for field, sid in (("kmshare1", v["set_id_v1"]), ("kmshare2", v["set_id_v2"])):
                want = (sid, v["k"], s["index"], s["value"])
                expect(v["id"], f"share {s['index']}'s {field}",
                       lambda t=s[field], w=want: (lambda x: (x.set_id.hex(), x.threshold,
                                                              x.index, x.value.hex()))(
                           keym2.decode_share_any(t)) == w)
        sid2 = bytes.fromhex(v["set_id_v2"])
        lowest = v["shares"][:v["k"]]
        for field in ("kmshare1", "kmshare2"):
            expect(v["id"], f"k {field} strips against the slot's set id",
                   lambda f=field: keym2.combine_shares([s[f] for s in lowest],
                                                         expected_set_id=sid2).hex() == v["secret"])
    for v in pack["parts"]:
        for field in ("kmpart1", "kmpart2"):
            expect(v["id"], field,
                   lambda f=field: keym2.decode_parts_any(v[f]).hex() == v["container"])
    for v in pack["text"]:
        if "wrapped" in v:
            for field in ("wrapped", "compact"):
                expect(v["id"], f"{field} armor",
                       lambda f=field: keym2.dearmor(v[f]).hex() == v["container"])
    return bad


def _design_inputs(doc: str) -> dict[str, str]:
    """§8's printed inputs table, as field -> the value cell's text."""
    text_ = (ROOT / "docs" / doc).read_text(encoding="utf-8")
    at = text_.find("\n## 8. Test vector")
    s8 = text_[at:] if at >= 0 else ""
    return {m.group(1).strip("` "): m.group(2).strip()
            for m in re.finditer(r"^\| ([^|]+?) \| ([^|]+) \|$", s8, re.M)}


def _expected_inputs(v: dict) -> dict[str, str]:
    k = v["kdf"]
    return {
        "password": f"`{v['password']}` (UTF-8, NFC)",
        "plaintext": f"`{bytes.fromhex(v['plaintext']).decode()}` "
                     f"({len(bytes.fromhex(v['plaintext']))} bytes, ASCII)",
        "cipher_id": "`0x00` (AES-256-GCM)",
        "KDF": f"Argon2id, `t={k['time_cost']}`, `m={k['memory_kib']}` KiB, "
               f"`p={k['parallelism']}`",
        "slot salt": f"`{v['salt']}`",
        "master key": f"`{v['master_key']}`",
        "container_id": f"`{v['container_id']}`",
    }


def check_design_docs(cont: list[dict]) -> list[str]:
    bad = []
    by_id = {v["id"]: v for v in cont}
    for doc, vid in (("FORMAT-V3-DESIGN.md", "v3-s8-argon2id-aes"),
                     ("FORMAT-V4-DESIGN.md", "v4-s8-argon2id-aes")):
        try:
            printed = _design_hex(doc)
            inputs = _design_inputs(doc)
        except Exception as e:  # noqa: BLE001
            bad.append(f"{vid}: {doc} §8 could not be read ({type(e).__name__})")
            continue
        v = by_id.get(vid)
        if v is None:
            bad.append(f"{vid}: not in containers.json")
            continue
        # The inputs a third implementer copies, not only the outputs.
        for field, want in _expected_inputs(v).items():
            if inputs.get(field) != want:
                bad.append(f"{vid}: {doc} §8 prints {field} as {inputs.get(field)!r}, "
                           f"the pack has {want!r}")
        for doc_name, field in (("core_header", "core_header"), ("K_table", "k_table"),
                                ("slot_table_mac", "slot_table_mac"), ("container", "container")):
            if printed.get(doc_name) != v[field]:
                bad.append(f"{vid}: {doc} §8 prints a different {doc_name} from the pack")
    return bad


def _live(vectors: list[dict]) -> list[dict]:
    """The vectors a reader is held to: every one not superseded by an erratum."""
    return [v for v in vectors if "erratum" not in v]


def check() -> int:
    built, crash = guarded_build()
    if built is None:
        print(f"  FAIL {crash}\n\nVector pack FAILED: 1 problem(s).")
        return 1
    generated = built
    problems: list[str] = []
    seen: set[str] = set()
    committed_all: dict[str, list[dict]] = {}
    total = 0
    for family in FAMILIES:
        committed = load(family)
        committed_all[family] = committed
        total += len(committed)
        gen_by_id = {v["id"]: v for v in generated[family]}
        com_ids = {v["id"] for v in committed}
        for v in committed:
            if v["id"] in seen:
                problems.append(f"{v['id']}: the id is used twice in the pack")
            seen.add(v["id"])
            if "erratum" in v:
                # Frozen as published. Its replacement is what keym2.py writes now.
                continue
            g = gen_by_id.get(v["id"])
            if g is None:
                problems.append(f"{family}/{v['id']}: committed, but keym2.py no longer "
                                f"produces it (supersede it with an erratum instead)")
            elif v != g:
                problems.append(f"{family}/{v['id']}: keym2.py now produces different bytes")
        for vid in gen_by_id:
            if vid not in com_ids:
                problems.append(f"{family}/{vid}: generated but not in the pack "
                                f"(python3 reference/vectors.py --write)")
        path = PACK / f"{family}.json"
        if not path.exists():
            problems.append(f"{family}.json: missing")
        elif path.read_text(encoding="utf-8") != render(family, committed):
            # Byte for byte, so the file a third reader downloads is the file
            # this check read: same order, same family, same escaping.
            problems.append(f"{family}.json: not in the pack's canonical form "
                            f"(python3 reference/vectors.py --write rewrites it)")
    for family, vectors in committed_all.items():
        for v in vectors:
            if "erratum" in v and not str(v["erratum"]).split()[0] in seen:
                problems.append(f"{family}/{v['id']}: its erratum names no vector in the pack")
    if total != VECTOR_COUNT:
        problems.append(f"the pack holds {total} vectors, VECTOR_COUNT says {VECTOR_COUNT}")

    problems += check_primitives(_live(committed_all["primitives"]))
    problems += check_containers_open(_live(committed_all["containers"]))
    problems += check_reject(_live(committed_all["reject"]))
    problems += check_accept(_live(committed_all["accept"]))
    problems += check_readers({f: _live(committed_all[f]) for f in ("shares", "parts", "text")})
    problems += check_design_docs(committed_all["containers"])

    for p in problems:
        print(f"  FAIL {p}")
    if problems:
        print(f"\nVector pack FAILED: {len(problems)} problem(s).")
        return 1
    print(f"Vector pack: {total} vectors in {len(FAMILIES)} families, all reproduced by "
          f"keym2.py; v3 §8 and v4 §8 match it.")
    return 0


def write() -> int:
    """
    Append vectors whose ids are new, and rewrite each file in canonical form.
    Every family is validated before any file is written, so a refusal leaves
    the pack exactly as it was.
    """
    generated, crash = guarded_build()
    if generated is None:
        print(f"refusing: {crash}")
        return 1
    plan: dict[str, list[dict]] = {}
    for family in FAMILIES:
        committed = load(family)
        by_id = {v["id"]: v for v in committed}
        for g in generated[family]:
            old = by_id.get(g["id"])
            if old is not None and "erratum" not in old and old != g:
                print(f"refusing: {family}/{g['id']} is committed and keym2.py now writes "
                      f"different bytes. The pack is append-only; add a new vector and give "
                      f"this one an erratum naming it. Nothing was written.")
                return 1
        plan[family] = committed + [g for g in generated[family] if g["id"] not in by_id]
    added = sum(len(plan[f]) - len(load(f)) for f in FAMILIES)
    PACK.mkdir(parents=True, exist_ok=True)
    for family, vectors in plan.items():
        (PACK / f"{family}.json").write_text(render(family, vectors), encoding="utf-8")
    print(f"appended {added} vector(s)")
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--write"]:
        sys.exit(write())
    if sys.argv[1:] in ([], ["--check"]):
        sys.exit(check())
    print(__doc__.strip().splitlines()[0])
    print("usage: python3 reference/vectors.py [--check | --write]")
    sys.exit(2)
