# Recovering a Keymaker file without Keymaker

**Print this page and keep it with your backups.**

If you are reading it because the Keymaker site is gone, the repository has
disappeared, or you no longer trust the copy in front of you — that is what
this page is for. Your data is not tied to the app that produced it.

Everything below uses one small Python file and two mainstream libraries. No
browser, no Node, no npm, no network.

If nothing has gone wrong yet and you are reading to find out how the whole
thing works, [WALKTHROUGH.md](WALKTHROUGH.md) is the illustrated version — a
first encryption through to this page's procedure. This one is the emergency
card: shorter, printable, and assuming the worst.

---

## What you need

| | |
|---|---|
| The encrypted file | `something.keym`, or the text form starting `keym2:` or `KEYM1:` |
| The password | Exactly as typed, including spaces and accents |
| The key file | **Only if one was used** — the container will tell you |
| Python | 3.10 or newer |
| Two libraries | `cryptography` and `argon2-cffi` |
| The recovery scripts | `reference/keym2.py` **and** `reference/keym.py` |

Nothing else. In particular you do **not** need this repository's application,
its dependencies, or any part of the JavaScript.

**There are two scripts because there are two container versions.** Keymaker
writes **v2** today and wrote **v1** before that. Both stay readable forever;
neither script reads the other's format, and step 2 tells you which one you
have. Keep both — an old backup needs the old script, and *old backups are the
ones most likely to need this page.*

**If you enrolled a passkey, it will not help you here.** A passkey is quick
access, not a backup. It only answers at the website it was created on, so if
you are reading this page it is already unavailable — and no script can stand in
for it, because the secret lives in the authenticator rather than in the file.
Use the password, or the recovery shares. Keymaker refuses to write a container
that a passkey is the only way into, precisely so that this paragraph always has
something to point you at.

---

## Step 1 — Install the two libraries

```bash
pip install cryptography argon2-cffi
```

If you are offline, both ship wheels you can download in advance and install
with `pip install --no-index --find-links <folder> cryptography argon2-cffi`.
Storing those wheels beside your backup is a reasonable precaution.

## Step 2 — Find out which version you have

If your backup is **text**, the first six characters say it outright:

| Starts with | Version | Script |
|---|---|---|
| `keym2:` | v2 | `keym2.py` |
| `KEYM1:` | v1 | `keym.py` |

Note the case. They differ by one letter and it is deliberate — see *Why the
prefixes look almost the same* below.

If your backup is a **file**, ask each script in turn. Neither needs a password
and neither can damage the file:

```bash
python3 keym2.py inspect --in backup.keym     # v2
python3 keym.py  inspect --in backup.keym     # v1
```

The right one prints a description. The wrong one refuses. That is the whole
test — you do not need a hex editor.

## Step 3 — Read what the container says about itself

For a **v2** container:

```
KEYM v2
  cipher      AES-256-GCM
  slots       1
  slot 0       type 0x00 (passphrase)
    kdf         Argon2id, t=3 m=65536KiB p=4
    key file    not used
    salt        0f1e2d3c...
  chunks      1 (75 plaintext bytes)
```

For a **v1** container:

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

Either way this needs no password. The container states its own parameters —
that is the point of the format — so you can confirm you have the right file,
and whether a key file is required, before doing anything else.

Those values are authenticated: if decryption later succeeds, they were not
tampered with. Until then, treat them as claims the file makes about itself.

**About `slots`.** A v2 container can hold up to eight ways of unlocking the
same data, and any one of them opens it. Containers written by the app have
exactly one — your password. If yours says more, any of the secrets listed will
work, and you only need one of them.

## Step 4 — Decrypt

```bash
python3 keym2.py decrypt --in backup.keym --out recovered.txt     # v2
python3 keym.py  decrypt --in backup.keym --out recovered.txt     # v1
```

You will be prompted for the password. Add `--key-file mykey.bin` if step 3
reported one was required. Omit `--out` to print to the terminal.

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

1. **Are you running the right script?** A v1 file in `keym2.py`, or the
   reverse, fails exactly like a wrong password. Re-run step 2.
2. **Is a key file expected?** Run `inspect`. If it says `required` and you do
   not have it, the password alone will never work.
3. **Is the password exactly right?** Case, spaces, and trailing newlines all
   matter. If you stored it in a password manager, copy rather than retype.
4. **Unicode in the password?** Keymaker normalises to NFC before deriving the
   key, and so do both scripts, so a password containing accented characters
   works across platforms. A password typed on a different keyboard layout may
   still differ in ways that look identical on screen.
5. **Is the file intact?** Compare its size against the copy you originally
   made. A truncated or re-encoded file — one that passed through a text
   editor, or a chat app that "helpfully" fixed its encoding — will fail
   authentication even with the correct password.
6. **Text form pasted correctly?** The prefix and every character after it must
   be present. Line breaks are fine; missing characters are not.

If `inspect` fails under *both* scripts, the file is not a KEYM container —
check you have the right one, and that it was not renamed from something else.

### Why the prefixes look almost the same

`KEYM1:` and `keym2:` differ by more than the digit, and the lowercase `k`
is the part that matters. A binary container starts with the four bytes `KEYM`,
so v1's text prefix is indistinguishable from a raw container in its first four
bytes — software that checked only those got it wrong, and did so confusingly.
`keym2:` starts with lowercase `k`, which no binary container ever does, so one
byte separates the two encodings.

The consequence for you: **`keym2:` is case-sensitive.** A backup rewritten as
`KEYM2:` by something that "tidied" it will not be recognised. Change it back to
lowercase and it will.

---

## Why this works, and why it should keep working

Keymaker's formats are specified byte by byte — v1 in [`FORMAT.md`](FORMAT.md),
v2 in [`FORMAT-V2-DESIGN.md`](FORMAT-V2-DESIGN.md). Each recovery script was
written from its specification alone, without reference to the application's
source. Both are tested against the real implementation on every push — v2 by
comparing the *bytes* the two produce, not merely by checking they can read each
other — so they cannot silently diverge.

That gives you two independent implementations of each documented format. If one
is unavailable or untrustworthy, the other decrypts your data — and if both
vanished, the specification is enough to write a third.

This is the property that matters for a backup you may not open for a decade:
your data depends on a **documented format**, not on a particular program
continuing to exist.

---

## The primitives, for anyone writing their own

Shared by both versions:

| Layer | Standard |
|---|---|
| Key derivation | Argon2id (RFC 9106) or PBKDF2-HMAC-SHA-256 (RFC 8018) |
| Ciphers | AES-256-GCM (NIST SP 800-38D), ChaCha20-Poly1305 (RFC 8439) |
| Subkey split, chained mode | HKDF-SHA-256 (RFC 5869) |
| Password encoding | NFC-normalised, UTF-8 |

Where they differ:

| | v1 | v2 |
|---|---|---|
| HKDF labels | `keymaker-aes`, `keymaker-chacha` | `keymaker-v2-aes`, `keymaker-v2-chacha`; the slot wrap uses `keymaker-v2-slot-aes` and `keymaker-v2-slot-chacha` |
| Key file | Raw bytes appended after the password bytes | SHA-256 of `"keymaker.v2.keyfile" ‖ bytes`, then length-prefixed alongside the password |
| Payload key | Derived from the password directly | A random 32-byte master key, carried in each slot sealed under a key derived from that slot's secret |
| Payload | One AEAD invocation over the whole plaintext | 1 MiB chunks, counter nonces, the last chunk flagged |
| Authentication | The whole header is AAD on every AEAD layer | The 8-byte core header is AAD for every chunk; each slot's wrap adds its own 48-byte record |

All standard, all implementable from public specifications.

---

*Keymaker is a fork of [IttyBitz](https://github.com/seQRets/ittybitz), GPL-3.
This page and the recovery scripts may be copied freely.*
