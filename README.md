# Keymaker

### [→ Launch the app](https://404secnotfound.github.io/Keymaker-v2/)

<sub>Runs entirely in the browser. Nothing is uploaded, no account is needed, and it keeps
working offline once loaded.</sub>

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

- [What's new in v2](#whats-new-in-v2)
- [The Advanced panel](#the-advanced-panel)
- [Self-describing containers](#self-describing-containers)
- [Seed-phrase awareness](#seed-phrase-awareness)
- [Dice entropy calculator](#dice-entropy-calculator)
- [Full feature list](#full-feature-list)
- [Security model](#security-model)
- [Run it locally](#run-it-locally)
- [Documentation](#documentation)
- [Attribution and license](#attribution-and-license)

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
- Installable PWA with full offline support; works air-gapped after first load
- Secret input and decrypted output blurred by default
- Clipboard auto-clear after 60 seconds (best-effort)
- No accounts, no analytics, no fonts or assets from third-party origins

---

## Security model

| Property | Strength of guarantee |
|---|---|
| Data never leaves the device | **Structural.** Static export, `connect-src 'none'` — the page cannot open a connection at all — and no telemetry. Gated in the build. |
| Header cannot be downgraded | **Cryptographic.** The full header is AAD on every AEAD layer. |
| Old files keep opening | **Tested.** Fixture corpus from prior releases, gated in CI. |
| Wrong password indistinguishable from corruption | **By design.** Errors are generic, to avoid an oracle. |
| Key material is wiped | **Best-effort.** Buffers are zero-filled; the JavaScript GC may retain copies. |
| Clipboard is cleared | **Best-effort.** The browser may refuse the write. |

Keymaker protects **data at rest**. It cannot defend against a compromised device, a
malicious browser extension, a keylogger, or a weak password. For the highest-value
secrets, run it offline on a machine that never rejoins a network.

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

python3 reference/keym.py inspect --in backup.keym    # what is this file?
python3 reference/keym.py decrypt --in backup.keym    # prompts for the password
```

No browser, no Node, no npm, no network. It reads both backup forms — a
`.keym` file or pasted `KEYM1:` text — and `inspect` reports the container's
KDF, cipher, and whether a key file is needed **without** asking for a
password.

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

The Argon2id suite is deliberately slow. It runs real memory-hard derivations across
every KDF and cipher combination, and takes a few minutes.

---

## Documentation

| Document | Contents |
|---|---|
| [`docs/HOW-IT-WORKS.md`](docs/HOW-IT-WORKS.md) | Architecture and data flow, with diagrams |
| [`docs/FORMAT.md`](docs/FORMAT.md) | Normative KEYM v1 byte-level specification |
| [`docs/FORMAT-V2-DESIGN.md`](docs/FORMAT-V2-DESIGN.md) | Proposed KEYM v2 — design only, nothing implemented |
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
