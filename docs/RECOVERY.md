# Recovering a Keymaker file without Keymaker

**Print this page and keep it with your backups.**

If you are reading it because the Keymaker site is gone, the repository has
disappeared, or you no longer trust the copy in front of you — that is what
this page is for. Your data is not tied to the app that produced it.

Everything below uses one small Python file and two mainstream libraries. No
browser, no Node, no npm, no network.

---

## What you need

| | |
|---|---|
| The encrypted file | `something.keym`, or the text form starting `KEYM1:` |
| The password | Exactly as typed, including spaces and accents |
| The key file | **Only if one was used** — the container will tell you |
| Python | 3.10 or newer |
| Two libraries | `cryptography` and `argon2-cffi` |
| The recovery script | `reference/keym.py` from this repository |

Nothing else. In particular you do **not** need this repository's application,
its dependencies, or any part of the JavaScript.

---

## Step 1 — Install the two libraries

```bash
pip install cryptography argon2-cffi
```

If you are offline, both ship wheels you can download in advance and install
with `pip install --no-index --find-links <folder> cryptography argon2-cffi`.
Storing those wheels beside your backup is a reasonable precaution.

## Step 2 — Look at the container before you try anything

```bash
python3 keym.py inspect --in backup.keym
```

```
format          KEYM v1
key derivation  Argon2id
                time cost 3, memory 64 MiB, parallelism 4
cipher          AES-256-GCM then ChaCha20-Poly1305 (chained)
key file        not used
salt            32 bytes
nonces          2 x 12 bytes
header          71 bytes (authenticated as AAD)
ciphertext      75 bytes
```

This needs no password. The container states its own parameters — that is the
point of the format — so you can confirm you have the right file, and whether
a key file is required, before doing anything else.

Those values are authenticated: if decryption later succeeds, they were not
tampered with. Until then, treat them as claims the file makes about itself.

## Step 3 — Decrypt

```bash
python3 keym.py decrypt --in backup.keym --out recovered.txt
```

You will be prompted for the password. Add `--key-file mykey.bin` if step 2
reported one was used. Omit `--out` to print to the terminal.

**Do not pass `--password` on the command line** unless you have a reason to.
It lands in your shell history and is visible to every other user on the
machine while the key derivation runs — seconds, for Argon2id.

---

## If it does not work

The error is deliberately vague: *"decryption failed"* covers a wrong
password, a wrong key file, and a corrupted file alike. That is intentional —
a tool that distinguished them would help an attacker who has your file but
not your password. It does mean you have to diagnose it yourself.

Work through these in order:

1. **Is a key file expected?** Run `inspect`. If it says `required` and you do
   not have it, the password alone will never work.
2. **Is the password exactly right?** Case, spaces, and trailing newlines all
   matter. If you stored it in a password manager, copy rather than retype.
3. **Unicode in the password?** Keymaker normalises to NFC before deriving the
   key, and so does this script, so a password containing accented characters
   works across platforms. A password typed on a different keyboard layout may
   still differ in ways that look identical on screen.
4. **Is the file intact?** Compare its size against the copy you originally
   made. A truncated or re-encoded file — one that passed through a text
   editor, or a chat app that "helpfully" fixed its encoding — will fail
   authentication even with the correct password.
5. **Text form pasted correctly?** The `KEYM1:` prefix and every base64
   character must be present. Line breaks are fine; missing characters are not.

If `inspect` itself fails, the file is not a KEYM container — check you have
the right one, and that it was not renamed from something else.

---

## Why this works, and why it should keep working

Keymaker's format is specified in [`FORMAT.md`](FORMAT.md), byte by byte. The
recovery script was written from that specification alone, without reference
to the application's source. It is tested in both directions against the real
implementation on every push, so the two cannot silently diverge.

That gives you two independent implementations of the same documented format.
If one is unavailable or untrustworthy, the other decrypts your data — and if
both vanished, the specification is enough to write a third.

This is the property that matters for a backup you may not open for a decade:
your data depends on a **documented format**, not on a particular program
continuing to exist.

---

## The primitives, for anyone writing their own

| Layer | Standard |
|---|---|
| Key derivation | Argon2id (RFC 9106) or PBKDF2-HMAC-SHA-256 (RFC 8018) |
| Ciphers | AES-256-GCM (NIST SP 800-38D), ChaCha20-Poly1305 (RFC 8439) |
| Subkey split, chained mode | HKDF-SHA-256 (RFC 5869), labels `keymaker-aes` and `keymaker-chacha` |
| Password encoding | NFC-normalised, UTF-8 |
| Key file | Raw bytes appended after the password bytes |
| Authentication | The whole header is AAD on every AEAD layer |

All standard, all implementable from public specifications.

---

*Keymaker is a fork of [IttyBitz](https://github.com/seQRets/ittybitz), GPL-3.
This page and the recovery script may be copied freely.*
