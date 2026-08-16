# Keymaker

[![CI](https://github.com/404SecNotFound/Keymaker-v2/actions/workflows/ci.yml/badge.svg)](https://github.com/404SecNotFound/Keymaker-v2/actions/workflows/ci.yml)
[![Browser tests](https://github.com/404SecNotFound/Keymaker-v2/actions/workflows/browser.yml/badge.svg)](https://github.com/404SecNotFound/Keymaker-v2/actions/workflows/browser.yml)
[![Format conformance](https://github.com/404SecNotFound/Keymaker-v2/actions/workflows/conformance.yml/badge.svg)](https://github.com/404SecNotFound/Keymaker-v2/actions/workflows/conformance.yml)
[![Reproducible build](https://img.shields.io/badge/build-reproducible-2ea44f)](docs/VERIFYING.md)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue)](LICENSE)

### [→ Launch the app](https://404secnotfound.github.io/Keymaker-v2/)

<sub>Runs entirely in the browser. Nothing is uploaded, no account is needed, and it keeps
working offline once loaded. &nbsp;·&nbsp;
[Verify the build you are running](https://404secnotfound.github.io/Keymaker-v2/verify.html)</sub>

---

**Client-side encryption for files and text. Nothing ever leaves your browser.**

Keymaker encrypts confidential documents, personal notes, and seed phrases entirely
in the browser tab. There is no server, no account, and no upload — the production
build is a static export that makes zero network requests after load, enforced by a
`default-src 'none'` Content Security Policy rather than promised in a privacy page.

<p align="center">
  <img alt="Keymaker — Encrypt everything. Trust nothing." src="docs/screenshots/01-landing.png" width="820" />
</p>

---

## Contents

- [Why Keymaker?](#why-keymaker)
- [What's new in v2](#whats-new-in-v2)
- [The Advanced panel](#the-advanced-panel)
- [Self-describing containers](#self-describing-containers)
- [Seed-phrase awareness](#seed-phrase-awareness)
- [Dice entropy calculator](#dice-entropy-calculator)
- [Full feature list](#full-feature-list)
- [A backup, end to end](#a-backup-end-to-end)
- [Security model](#security-model)
- [Run it locally](#run-it-locally)
- [Documentation](#documentation)
- [Attribution and license](#attribution-and-license)

---

## Why Keymaker?

Four tools already do encryption well. Keymaker is not trying to replace them, and the
comparison is only worth reading if it says where they win — so it does.

| | Keymaker | [age](https://age-encryption.org/) | GPG | [Cryptomator](https://cryptomator.org/) | Typical browser tools |
|---|---|---|---|---|---|
| **Install needed** | none — open a URL | CLI binary | CLI + keyring | desktop/mobile app | none |
| **Trust anchor** | **whoever serves the page** | the binary you installed | the binary you installed | the app you installed | whoever serves the page |
| Format specified in writing | [yes](docs/FORMAT-V2-DESIGN.md) | yes | yes (RFC 4880) | yes | rarely |
| Independent implementation you can decrypt with | [`keym2.py`](reference/keym2.py), no browser | rage and others | many | Cyberduck, Mountain Duck | almost never |
| Signed releases | [Sigstore, keyless](docs/VERIFYING.md) | checksums + signed tags | distro-dependent | signed installers | almost never |
| [Reproducible](docs/VERIFYING.md) build, enforced in CI | yes | — | — | — | almost never |
| Hardware keys / smartcards | [passkeys](docs/FORMAT-V2-DESIGN.md) only | plugins | **yes** | no | no |
| Whole-folder, continuous use | no | no | no | **yes** | no |
| Works on a phone with nothing installed | **yes** | no | no | app | yes |
| Split a secret k-of-n | **yes** ([Shamir](docs/FORMAT-V2-DESIGN.md)) | no | no | no | no |
| Seed-phrase tooling (BIP-39, SeedQR, dice) | **yes** | no | no | no | no |

A dash means *not claimed here* rather than *absent* — these projects are Go, C and Java
respectively, and whether any given release is bit-reproducible is a question for their
own documentation, not one this table should answer on their behalf.

**"Passkeys only" is the honest cell.** Keymaker can unlock a backup with a passkey via
WebAuthn PRF, which is a real hardware path and a phishing-proof one. It is not smartcard
or PKCS#11 support, and it is **not extra strength**: the format requires a passkey slot
to sit beside another way in, so a container is exactly as strong as the weaker of the
two. What it buys is convenience and phishing resistance, which is worth having and is
not the same claim.

**Where the others are the better answer.** If you are comfortable at a terminal, `age`
is simpler than this and has no served-bundle problem at all — its trust anchor is a
binary you installed once and can pin. GPG is the only one here that talks to a YubiKey
or a smartcard, and the only one whose files anything will still open in twenty years.
Cryptomator solves a genuinely different problem: a vault you keep working inside, synced
to cloud storage, mounted like a drive. None of those jobs is Keymaker's.

**The honest weakness.** A web app has the weakest trust anchor of the four: code
delivered fresh on every visit by whoever controls the host. That is not a footnote — it
is the main reason to prefer a CLI. Keymaker's answer is not to deny it but to make it
checkable: every deployment ships a signed `SHA256SUMS`, the build is byte-for-byte
reproducible from a commit you can read, and the app tells you how to check the copy you
were served on its own [verify page](https://404secnotfound.github.io/Keymaker-v2/verify.html).
That narrows the gap. It does not close it, and [docs/VERIFYING.md](docs/VERIFYING.md)
says exactly what it leaves open.

**Where Keymaker is the better answer.** Someone needs to encrypt a seed phrase, a
recovery document or a photo of a passport, on a device whose toolchain they do not
control, without installing anything — and needs to open it again years later on a
machine that may not have this website, this app, or a browser. That is the case the
whole design is bent around: a specified container format, an independent Python
implementation shipped alongside the app, and a printed recovery procedure that involves
no software of ours at all.

---

## What's new in v2

v2 is a fork of [IttyBitz](https://github.com/seQRets/ittybitz) with the crypto design
from the Morpheus project ported in. IttyBitz offered exactly one configuration:
PBKDF2 at 1,000,000 iterations with AES-256-GCM, in a headerless container. v2 makes
the algorithm a choice, and writes that choice into the file.

| | IttyBitz (v1) | Keymaker (v2) |
|---|---|---|
| Key derivation | PBKDF2-SHA-256 only | PBKDF2 **or Argon2id** (memory-hard) |
| Cipher | AES-256-GCM only | AES-256-GCM, **ChaCha20-Poly1305**, or **both chained** |
| Container | headerless / `IBTZ` | self-describing **`KEYM`** with authenticated header |
| Tamper protection | ciphertext only | **entire header authenticated as AAD** |
| Unicode passwords | no normalization | **NFC-normalized** before derivation |
| Filenames | leaked in plaintext | optional **filename obscuring** |
| Seed phrases | BIP-39 validity hint | validity hint plus **Standard SeedQR export** |
| Entropy tooling | none | **dice entropy calculator** |
| Reading old files | n/a | **decrypts IBTZ v0 and v1 transparently** |

Everything IttyBitz could open, Keymaker still opens. That is enforced by a fixture
corpus of real ciphertexts from earlier releases, gated in CI.

---

## Two ways to get a password you can trust

<p align="center">
  <img alt="The password row — Copy, Clear, Random and Passphrase — showing a generated seven-word passphrase with its exact entropy stated beneath" src="docs/screenshots/10-passphrase-generator.png" width="620" />
</p>

**Random** draws 32 characters from a 91-character set — 208 bits, and
completely unmemorable. **Passphrase** draws 7 words from the EFF Long
Wordlist — 90 bits, and you can copy it off a card without a transcription
error.

The second is not the weaker option. There is no server here and no account
recovery, so a password nobody can write down correctly is its own kind of
failure mode. 90 bits against a memory-hard KDF is not the number an attacker
goes after.

Both use rejection sampling, so neither inherits modulo bias, and the entropy
figures are exact rather than estimated. Keymaker states a figure **only** for
a password it generated itself: a typed one gets "minimum policy met" and a
plain admission that a string carries no evidence of how it was chosen.

The wordlist is the part that could go quietly wrong — a single duplicate entry
would make every printed bit-count an overstatement. So it is not transcribed
from memory. It is fetched from three independent redistributions that must
agree on the full ordered 7,776-word sequence, and CI re-derives EFF's own file
checksum from the shipped array offline on every run.

---

## The Advanced panel

Every new cryptographic choice lives behind one collapsible section, so the default
path stays a password field and a button.

<p align="center">
  <img alt="Advanced panel showing key derivation, cipher selection, key file and filename options" src="docs/screenshots/05-advanced-panel.png" width="620" />
</p>

### Key derivation

Argon2id is the recommended default for new data. Time cost, memory, and parallelism
are all adjustable, with a live estimate of derivation cost per attempt — which is
also the cost imposed on anyone brute-forcing the password.

<p align="center">
  <img alt="Argon2id parameters: time cost, memory, parallelism" src="docs/screenshots/03-kdf-argon2id.png" width="620" />
</p>

PBKDF2 at 1,000,000 iterations remains available for maximum compatibility. It runs
entirely on WebCrypto and needs no WebAssembly.

### Cipher

<p align="center">
  <img alt="Cipher selection: AES-256-GCM, ChaCha20-Poly1305, or chained" src="docs/screenshots/04-cipher-chained.png" width="620" />
</p>

Chained mode encrypts with AES-256-GCM, then encrypts that ciphertext again with
ChaCha20-Poly1305 under an independent subkey derived via HKDF. This is algorithmic
defence in depth: recovering the plaintext means defeating both constructions, and
neither key is derivable from the other. It reduces reliance on any single cipher —
it is not a quantified guarantee, and it does nothing for a guessable password,
where the KDF is the bottleneck.

---

## Self-describing containers

A KEYM file carries its own parameters. Decryption needs no configuration — you supply
the password, and the container states which KDF, which cipher, and which parameters
were used. Those bytes are authenticated, so they cannot be rewritten to force a
downgrade.

<p align="center">
  <img alt="Decrypting a KEYM container; the format and parameters are read back from the header" src="docs/screenshots/07-decrypt-detection.png" width="620" />
</p>

The readback line above is not a guess. It is the header the file itself declares,
after that header has been verified as additional authenticated data by every AEAD
layer. Flip one bit of it and decryption fails, rather than silently doing something
weaker.

See [`docs/FORMAT.md`](docs/FORMAT.md) for the byte-level specification and
[`docs/HOW-IT-WORKS.md`](docs/HOW-IT-WORKS.md) for the diagrams.

---

## Seed-phrase awareness

Keymaker recognizes BIP-39 seed phrases and signals validity through border color
alone — never with a label. A shoulder-surfer sees a green outline, not the words
"valid seed phrase", so the screen does not announce that it is holding a wallet.

<p align="center">
  <img alt="Secret text field showing BIP-39 validity through border color only" src="docs/screenshots/02-seed-detection.png" width="620" />
</p>

A phrase that is seed-shaped but fails its checksum turns red *before* you encrypt it,
catching a transcription error while it is still fixable, rather than after a bad
backup has been sealed and stored.

On decryption, a recovered seed can be exported as a **Standard SeedQR** for direct
import into Coldcard, SeedSigner, Sparrow, Specter, Krux, Keystone, or Jade.

<p align="center">
  <img alt="Standard SeedQR export dialog, with the QR hidden behind an explicit reveal step" src="docs/screenshots/08-seedqr.png" width="520" />
</p>

Note what this dialog does *not* do: the QR is not rendered until you press Reveal.
Plaintext QR codes are mount-gated and blurred, while ciphertext QR codes are shown
immediately — the interface treats "this pixel pattern is your seed" as a different
category of risk from "this pixel pattern is encrypted".

---

## Dice entropy calculator

Under the Tools tab. It answers one question: how many physical dice rolls do you need
for 128 or 256 bits of entropy?

<p align="center">
  <img alt="Dice entropy calculator showing bits per roll, rolls counted, and progress to target" src="docs/screenshots/09-dice-entropy.png" width="620" />
</p>

Bits per roll is log2(sides); total entropy is rolls times bits per roll. 128 bits is
treated as a floor and 256 bits as the target.

This tool **computes bits — it does not generate seeds**. It exists because hardware
RNGs have failed in the field, and physical dice derive their entropy from mechanics
you can watch rather than from silicon you have to trust. Generate the actual seed
from your recorded rolls on an air-gapped device, using dedicated, audited software.

---

## Full feature list

**Cryptography**

- Argon2id (RFC 9106, via hash-wasm) or PBKDF2-HMAC-SHA-256 at 1,000,000 iterations
- AES-256-GCM, ChaCha20-Poly1305 (RFC 8439), or the two chained with HKDF-derived
  independent subkeys
- Self-describing KEYM v1 container with the full header authenticated as AAD
- NFC password normalization, so a password typed in a different Unicode form on
  macOS still decrypts elsewhere
- Optional key file, usable alongside a password; key files can be generated in-app
  from `crypto.getRandomValues`
- Rejection-sampled generators with no modulo bias: a 32-character random
  password, or a seven-word Diceware passphrase drawn from the EFF Long Wordlist
  (90 bits). An entropy figure is stated only for what Keymaker generated
  itself — a typed password gets "minimum policy met" and nothing more, because
  a string carries no evidence of how it was chosen
- The bundled wordlist is fetched from three independent redistributions that
  must agree, and checksummed against EFF's file in CI rather than trusted

**Files and transport**

- Files and text. Encrypted files use `.keym`; encrypted text is prefixed `KEYM1:` so
  blobs are self-identifying
- Optional filename obscuring, replacing the name with `keymaker-<random>.keym`
- QR export for encrypted text, and Standard SeedQR export for recovered seeds
- Transparent import of legacy IttyBitz `.ibitz` files and bare IBTZ blobs

**Privacy and operation**

- Static export with a `default-src 'none'` CSP and per-file inline-script hashes
- Installable PWA with full offline support; works air-gapped after first load.
  Every chunk the build emits is precached by the service worker at install, so
  offline does not depend on the browser's own HTTP cache still holding what you
  need days later
- Updates never install themselves over a live page. A new version waits and
  asks; you choose when to reload, because a page may be mid-derivation holding
  key material
- Secret input and decrypted output blurred by default
- Clipboard auto-clear after 60 seconds (best-effort)
- No accounts, no analytics, no fonts or assets from third-party origins

---

## A backup, end to end

[**docs/WALKTHROUGH.md**](docs/WALKTHROUGH.md) is the illustrated version: an
empty browser tab through to opening the file years later with Python and no
website. Every command in it is executed on each change and every screenshot is
generated from the production build, so it cannot quietly stop being true.

---

## Three ways to run this, and what each one costs

They are not the same trust model, and the difference deserves stating plainly
rather than being left in a footnote.

| | What you trust | What it costs |
|---|---|---|
| **Hosted** — [the live site](https://404secnotfound.github.io/Keymaker-v2/) | Whoever serves the bundle, **on every visit** | Nothing. Open a URL |
| **Downloaded and verified** — a [release](https://github.com/404SecNotFound/Keymaker-v2/releases), checked, then opened from disk | Whoever served it **once**, at a moment you chose and checked | One download, two commands, and re-doing it on upgrade |
| **Built from source** | The toolchain and the source you read | Node, an `npm ci`, and the willingness to read a diff |

**Hosted is the weakest, and it is the default**, because a tool nobody can open
protects nothing. But be clear what it means: the JavaScript is fetched fresh
every time, so a compromise of the host — or of anything between the host and
you — is a compromise of every future session, not only the one it happened in.
Verifying today says nothing about tomorrow's visit.

**Downloaded-and-verified is the real upgrade**, and it is why releases exist.
Fetch the tarball, check `SHA256SUMS` against its Sigstore signature, extract,
and open `index.html` from disk. From then on the code is a file you control:
nothing re-fetches it, and an attacker needs your machine rather than the host.
[docs/VERIFYING.md](docs/VERIFYING.md) has the commands, and the in-app
[verify page](https://404secnotfound.github.io/Keymaker-v2/verify.html) prints
them filled in for the build in front of you.

**Built-from-source removes the last party**, at the cost of trusting Node and
the dependency tree instead. The build is reproducible and CI enforces that, so
there is also a fourth posture — build it, compare your manifest to the
deployment's, and keep using the hosted one having *checked* it rather than
adopted it.

None of the three protects a compromised device. That is the next section.

---

## Security model

| Property | Strength of guarantee |
|---|---|
| Data never leaves the device | **Strong, with one gap.** Static export, no telemetry, `connect-src 'none'` gated in the build — the page cannot open a connection. The policy ships as a `<meta>` tag, and a `<meta>` policy does not reach Web Workers, so the crypto worker is not covered by it. Nothing in the shipped code makes a request from there, and the reproducible build lets you check that — but for the worker the guarantee rests on the code rather than on the browser. [Detail](docs/HOW-IT-WORKS.md#the-gap-a-meta-tag-csp-does-not-reach-workers). |
| Header cannot be downgraded | **Cryptographic.** The full header is AAD on every AEAD layer. |
| Old files keep opening | **Tested.** Fixture corpus from prior releases, gated in CI. |
| Wrong password indistinguishable from corruption | **By design.** Errors are generic, to avoid an oracle. |
| Key material is wiped | **Best-effort.** Buffers are zero-filled; the JavaScript GC may retain copies. |
| Clipboard is cleared | **Best-effort.** The browser may refuse the write. |

### What this does not protect against

Keymaker protects **data at rest**. Named plainly, because a vague disclaimer is
a way of not saying anything:

- **A compromised device.** Malware, a keylogger, or a hostile OS sees the
  plaintext and the password as you type them. No web app can fix this, and one
  that implied otherwise would be lying.
- **A malicious browser extension.** Extensions run inside the page's origin
  with permission to read the DOM. The CSP does not apply to them. An extension
  with access to this tab can read a secret before it is ever encrypted.
- **The clipboard.** Copying a container or a password puts it somewhere every
  other app on the machine can read, and on some platforms somewhere it syncs to
  other devices. Keymaker clears its own copies on a timer, but the browser can
  refuse, and anything that read it in the meantime already has it.
- **Someone looking at your screen.** Secret fields blur by default and reveal
  toggles exist for that reason, but a shoulder, a webcam and a screen-recorder
  all defeat it.
- **How long your plaintext is.** The container is not padded, so its length
  reveals the plaintext's length to within a 1 MiB chunk. If the mere *size* of
  what you are protecting is sensitive — which document, which of two possible
  answers — that leaks regardless of the cipher. This is stated in
  [§8 of the format design](docs/FORMAT-V2-DESIGN.md) and a padding scheme is
  deliberately not in v2: it is its own design with its own trade-offs.
- **A weak password.** Argon2id makes guessing expensive; it cannot make a
  guessable password unguessable.
- **Forgetting the password.** There is no reset, no recovery email and nobody
  to call. This is the failure that actually happens.

For the highest-value secrets, run a
[verified download](#three-ways-to-run-this-and-what-each-one-costs) offline, on
a machine that never rejoins a network.

Report vulnerabilities via the contact in [SECURITY.md](SECURITY.md).

---

## Run it locally

Requires Node.js 20 or newer.

```bash
npm ci                    # reproducible install from the lockfile
npm run dev               # development server on :9002
npm run build             # static export to out/, with CSP hash post-processing
npm run typecheck

npm run test:crypto       # frozen IBTZ core — the legacy decryption contract
npm run test:keymaker     # KEYM v1 — round-trips, tamper rejection, fixtures
npm run test:fuzz         # malformed containers against the parser
npm run test:browser      # the built export, in a real browser (needs build)
npm run test:conformance  # cross-test vs the independent Python reference
npm run test:recovery     # the documented recovery procedure, end to end
```

`test:browser` needs `npx playwright install` once. `test:conformance` needs
`pip install -r reference/requirements.txt`.

`npm run build` produces a fully static `out/` directory. Serve it from any static
host, or open it from disk on a machine with no network connection.

---

## Recovering a file without Keymaker

A backup is only as durable as your ability to open it. If this app is gone,
unreachable, or you no longer trust the copy in front of you, your data is
still recoverable — the format is specified, and a second implementation of it
ships in this repository.

```bash
pip install cryptography argon2-cffi

python3 reference/keym2.py inspect --in backup.keym   # what is this file?
python3 reference/keym2.py decrypt --in backup.keym   # prompts for the password
```

No browser, no Node, no npm, no network. `inspect` reports the container's KDF,
cipher, and whether a key file is needed **without** asking for a password.

**Two scripts, because there are two container versions.** The app writes
**KEYM v2** and `keym2.py` reads it. Backups made before that are **v1** and
need `keym.py`; neither script reads the other's format, and the one that
refuses is telling you which you have.
[docs/RECOVERY.md](docs/RECOVERY.md) is the printable procedure, and
[docs/WALKTHROUGH.md](docs/WALKTHROUGH.md) walks the whole path with pictures.

[`docs/RECOVERY.md`](docs/RECOVERY.md) is the full procedure, written to be
printed and stored alongside your backups. `npm run test:recovery` executes
those instructions on every push, so the page cannot quietly stop being true.

This is the point of specifying the format in [`docs/FORMAT.md`](docs/FORMAT.md)
and building a second implementation from that spec alone: your data depends on
a documented format, not on one program continuing to exist.

---

## Publishing

The **Launch the app** link at the top points at GitHub Pages. Every merge to
`main` publishes via [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml);
the workflow can also be run by hand from the Actions tab to redeploy without a
new commit. Enabling it once, on a fresh clone or fork, is
**Settings → Pages → Source: GitHub Actions**.

A Pages project site is served from `/Keymaker-v2/` rather than the domain root, so
the deploy builds with `KEYMAKER_BASE_PATH=/Keymaker-v2`. Without it the exported
HTML would request its assets from the root and serve a blank page. The service
worker derives its own scope from where it is served, so it needs no configuration.

To host somewhere else — a custom domain, Netlify, Vercel, an internal server —
build without `KEYMAKER_BASE_PATH` and upload `out/`. Nothing in the app assumes a
particular origin.

Because Keymaker does all its work in the browser, **whoever serves the bundle is
the trust anchor.** For high-value secrets, prefer a copy you built and verified
yourself, kept offline.

You no longer have to take that on trust, though. Every deployment publishes a
`SHA256SUMS` manifest of the exact bytes it served, signed with Sigstore by the
deploy workflow's own identity — no long-lived key to leak, and verification
asks "did *this repository's workflow* sign this", not "do you trust this key".
And the build is reproducible: two clean builds of a commit produce identical
output, and CI enforces it, so you can rebuild the commit yourself and compare
manifests.

Those are two different claims and both matter. The signature says the site is
the artifact CI produced; the rebuild says that artifact matches the source you
can read. See [`docs/VERIFYING.md`](docs/VERIFYING.md) — the first check needs
nothing but `sha256sum`.

The Argon2id suite is deliberately slow. It runs real memory-hard derivations across
every KDF and cipher combination, and takes a few minutes.

---

## Documentation

| Document | Contents |
|---|---|
| [`docs/HOW-IT-WORKS.md`](docs/HOW-IT-WORKS.md) | Architecture and data flow, with diagrams |
| [`docs/FORMAT.md`](docs/FORMAT.md) | Normative KEYM v1 byte-level specification |
| [`docs/FORMAT-V2-DESIGN.md`](docs/FORMAT-V2-DESIGN.md) | Normative KEYM v2 specification — the format the app writes today |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Phased plan: what ships next, and what was cut |
| [`docs/VERIFYING.md`](docs/VERIFYING.md) | Checking that the site you loaded is the code you read |
| [`docs/WALKTHROUGH.md`](docs/WALKTHROUGH.md) | A backup end to end, illustrated — first encryption through to recovery |
| [`docs/RECOVERY.md`](docs/RECOVERY.md) | Opening a backup without Keymaker — printable |
| [`reference/README.md`](reference/README.md) | Independent Python implementation, and why it exists |
| [`SECURITY.md`](SECURITY.md) | Threat model and vulnerability reporting |
| [`SECURITY-AUDIT.md`](SECURITY-AUDIT.md) | Current Keymaker v2 audit, findings and disposition |
| [`SECURITY-AUDIT-ITTYBITZ-2026-04.md`](SECURITY-AUDIT-ITTYBITZ-2026-04.md) | Historical IttyBitz audit — legacy core only |
| [`CHANGELOG.md`](CHANGELOG.md) | Release history |

---

## Attribution and license

Keymaker is a fork of [IttyBitz](https://github.com/seQRets/ittybitz) by seQRets,
licensed GPL-3. The cryptographic design — Argon2id, chained AEAD ciphers, the
self-describing authenticated container, and the dice entropy calculator — is ported
from the Morpheus project.

Licensed under the **GNU General Public License v3.0**. See [LICENSE](LICENSE).
