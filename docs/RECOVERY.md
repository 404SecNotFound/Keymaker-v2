# Recovering a Keymaker file without Keymaker

**Print this page and keep it with your backups.**

If you are reading it because the Keymaker site is gone, the repository has
disappeared, or you no longer trust the copy in front of you — that is what
this page is for. Your data is not tied to the app that produced it.

Everything below uses one small Python file and two mainstream libraries. No
browser, no Node, no npm.

**One honest caveat about "no network".** The *decryption* needs none — the
script and your container are enough. Getting the two libraries onto the
machine is the step that normally reaches a package index, and step 1 says how
to do it without one. If you want a genuinely offline kit, download the wheels
now, while you can, and store them beside the backup.

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

**There are two scripts because there are two generations of the format.**
`keym2.py` reads everything Keymaker writes today: **v3**, the current default,
and **v2** before it. `keym.py` reads **v1**, which came first. All three stay
readable forever; neither script reads the other's generation, and step 2 tells
you which one you have. Keep both — an old backup needs the old script, and *old
backups are the ones most likely to need this page.*

You do not need to work out whether you have v2 or v3. `keym2.py` reads both and
says which it found; the distinction matters to the format, not to you.

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

The versions these scripts are tested against are in `requirements.txt`, which
ships beside them in the recovery kit:

```bash
pip install -r requirements.txt
```

Those pinned versions are the only ones the project runs. The format uses
standard primitives and nothing specific to either library, so a newer release
should work, and the frozen fixtures in the repository are how you would check:
they must still open. But no test runs against any version except the pinned
one, so treat "should work" as a reasonable expectation rather than a tested
fact. If a newer version fails, install the pinned one.

**Offline.** Both libraries ship wheels you can download in advance:

```bash
pip download -r requirements.txt -d wheels        # now, while you have a network
pip install --no-index --find-links wheels -r requirements.txt   # later, when you do not
```

Storing that `wheels` folder beside your backup is the difference between a
procedure that needs no network and one that only claims to. The recovery kit
carries the scripts and the requirements file; it does not carry the wheels,
because they are platform-specific and would have to be chosen for a machine
nobody can predict.

## Step 2 — Find out which version you have

If your backup is **text**, the first six characters say it outright:

| Starts with | Version | Script |
|---|---|---|
| `keym2:` | v3 or v2 | `keym2.py` |
| `KEYM1:` | v1 | `keym.py` |

**`keym2:` covers both v3 and v2 on purpose.** The prefix names the generation,
not the revision, so a backup written today and one written before v3 existed
look identical here — and both open with the same script. If you want to know
which one you are holding, `keym2.py inspect` says so.

Note the case. `keym2:` and `KEYM1:` differ by one letter and it is deliberate —
see *Why the prefixes look almost the same* below.

If your backup is a **file**, ask each script in turn. Neither needs a password
and neither can damage the file:

```bash
python3 keym2.py inspect --in backup.keym     # v3 or v2
python3 keym.py  inspect --in backup.keym     # v1
```

The right one prints a description. The wrong one refuses. That is the whole
test — you do not need a hex editor.

## Step 3 — Read what the container says about itself

For a **v3** container — what the app writes today:

```
KEYM v3
  cipher      AES-256-GCM
  container   22dcae81ce97b6d0fd220e0b5cf48625
  table mac   9e2aa9e87e0f1dce... (unverified: needs a secret)
  slots       1
  slot 0       type 0x00 (passphrase)
    kdf         Argon2id, t=3 m=65536KiB p=4
    key file    not used
    salt        84e893d5eccecf1a...
  chunks      1 (75 plaintext bytes)
```

`container` is an identifier for this backup, not a secret; every copy of the
same backup shows the same one. `table mac` protects the list of ways in
(below). It says `unverified` here because checking it needs the password or the
shares, and `decrypt` checks it for you. A v2 container has neither line.

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

**About `slots`.** A v3 or v2 container can hold up to eight ways of unlocking the
same data, and any one of them opens it. Containers written by the app have one
for the password, plus one for recovery shares or a passkey if either was set
up when it was made. If yours says more than one, any of the secrets listed will
work, and you only need one of them.

## Step 4 — Decrypt

```bash
python3 keym2.py decrypt --in backup.keym --out recovered.txt     # v3 or v2
python3 keym.py  decrypt --in backup.keym --out recovered.txt     # v1
```

You will be prompted for the password. Add `--key-file mykey.bin` if step 3
reported one was required. Omit `--out` to print to the terminal.

**Do not pass `--password` on the command line** unless you have a reason to.
It lands in your shell history and is visible to every other user on the
machine while the key derivation runs — seconds, for Argon2id.

### With recovery shares instead of the password

If you were given recovery strips rather than the password, you need as many as
the strip itself says ("Any 2 of them open it"). Put the code from each strip
(the line that starts `KMSHARE2:` or `KMSHARE1:`) into a plain text file, one
per line, then:

```bash
python3 keym2.py decrypt --in backup.keym --shares-from shares.txt --out recovered.txt
```

No password is asked for. Case, spaces and hyphens inside a code do not matter,
lines starting with `#` are ignored, and it does not matter which strips you
use or in what order. If it reports `decryption failed`, you have fewer strips
than the backup needs, or one of them was mistyped. `--share KMSHARE2:…`,
repeated once per strip, also works, but like `--password` it leaves the codes
in your shell history.

---

## If the web app said the backup was too large

That limit belongs to the web app, not to your backup and not to the format.
A browser tab has to hold the container and the recovered file in memory at
once, so the app stops at 100 MB. `keym2.py` does not: it has no size limit,
and the steps above are the whole procedure regardless of how big the file is.

Measured on an ordinary laptop, a 150 MiB backup decrypts in about two seconds
and needs roughly 640 MB of RAM while it runs. Larger files scale from there —
budget several times the file size in memory, and use a machine with room for
it rather than the smallest one to hand.

Nothing else changes. Same command, same password, same output.

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
v2 in [`FORMAT-V2-DESIGN.md`](FORMAT-V2-DESIGN.md), and v3 as a short change to v2
in [`FORMAT-V3-DESIGN.md`](FORMAT-V3-DESIGN.md). Each recovery script was
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

| | v1 | v2 and v3 |
|---|---|---|
| HKDF labels | `keymaker-aes`, `keymaker-chacha` | `keymaker-v2-aes`, `keymaker-v2-chacha`; the slot wrap uses `keymaker-v2-slot-aes` and `keymaker-v2-slot-chacha` |
| Key file | Raw bytes appended after the password bytes | SHA-256 of `"keymaker.v2.keyfile" ‖ bytes`, then length-prefixed alongside the password |
| Payload key | Derived from the password directly | A random 32-byte master key, carried in each slot sealed under a key derived from that slot's secret |
| Payload | One AEAD invocation over the whole plaintext | 1 MiB chunks, counter nonces, the last chunk flagged |
| Authentication | The whole header is AAD on every AEAD layer | The core header is AAD for every chunk: 8 bytes in v2, 24 in v3 (which adds a random 16-byte container id). Each slot's wrap adds its own 48-byte record. v3 also stores an HMAC-SHA-256 over the core header and the whole slot table, keyed from the master key (HKDF info `keymaker.v3.slot-table`) |

All standard, all implementable from public specifications.

---

*Keymaker is a fork of [IttyBitz](https://github.com/seQRets/ittybitz), GPL-3.
This page and the recovery scripts may be copied freely.*
