# Changelog

## Unreleased

### Added
- **Diceware passphrase generator.** Seven words drawn uniformly from the EFF
  Long Wordlist with rejection sampling — 90 bits, stated exactly. The wordlist
  is fetched from three independent redistributions that must agree on the full
  ordered sequence, and `npm run test:wordlist` re-derives EFF's own file
  checksum from the shipped array, offline, in CI. Closes the enhancement left
  open under KM-02.
- **`docs/FORMAT-V2-DESIGN.md`** — the KEYM v2 container, specified before it
  was built. Written first, implemented twice from the document alone (the
  TypeScript in `src/lib/keym-v2.ts` and `reference/keym2.py`), and since
  Phase 3 it is the format the app writes. KEYM v1 is unchanged and stays
  readable: the version byte dispatches, and the frozen fixtures prove it.

### Changed
- **The reproducibility claim now matches what is checked.** The gate built
  twice on one runner, which answers "is the build a function of its source"
  and not "does *my* machine reproduce your bytes" — the question a verifier is
  actually asking. `verify:reproducible` now varies the clock, the locale and
  `HOME` between its two builds, and a new `reproducible-elsewhere` matrix
  rebuilds the same commit on separate runners under a different checkout path
  and a different Node major, comparing manifests. `docs/VERIFYING.md` states
  what each gate covers, and says plainly that a different OS or CPU
  architecture is not among it.
- **The deployed layout is tested.** The browser suite serves `out/` at the
  origin root; GitHub Pages serves it from `/Keymaker-v2/`, which is a different
  set of asset URLs and was never loaded in a browser. the base-path browser run
  builds the export the way `deploy.yml` builds it and checks that no URL the
  page declares or requests escapes the prefix, that the crypto worker really
  loads (a 404 there silently moves derivation onto the main thread rather than
  failing), and that the service worker registers in scope. The base path is
  read out of the workflow, so the gate follows the deployment.
- **Service-worker updates now wait for the user.** A new version installs and
  stops; the page offers a reload and only the user's click promotes it.
  Previously `skipWaiting()` plus `clients.claim()` replaced the running
  version underneath an open tab and evicted its cache, which could break a
  lazily imported crypto chunk part-way through an encryption (KM-25).
- The password policy gate now accepts a secret on provenance when Keymaker
  generated it, instead of re-judging it on morphology. Without this, a uniform
  seven-word draw that happened to repeat a word — about one in 370 — would
  have been certified at 90 bits in the UI and then refused by the Encrypt
  button.
- The update banner is a `<button>` rather than a `<div>` with a click handler,
  so the update path is reachable from the keyboard.
- The build emits a precache manifest and the service worker installs every
  content-hashed chunk, rather than caching whatever the fetch handler happens
  to intercept.

### Fixed
- `resetState()` did not clear the "this password came from the CSPRNG" flag.
- **Offline support was resting on the browser's HTTP cache** (KM-26). With the
  worker no longer seizing control on install, chunks fetched before it took
  over were never cached: 3 of 17 on a first visit. The offline tests passed
  anyway, because Chromium's HTTP cache answered — a cache the browser may
  evict at any time. Now 17 of 17, with a browser test that counts what the
  worker itself holds.
- Screenshots in the README showed a password row that no longer exists.
- **Documentation still called KEYM v2 a proposal.** `docs/FORMAT-V2-DESIGN.md`
  was titled "Design Proposal" and opened by saying nothing in `src/` writes the
  format — while the app writes it, the footer says so, and the paper vault
  prints that document's path as the specification. It is now titled and
  written as the normative specification it has been since Phase 3, with §9
  recording that the format is frozen. `docs/FORMAT.md` said the same thing and
  no longer does. The file keeps its `-DESIGN` name deliberately: printed paper
  vaults and self-extracting pages already cite that path.
  `scripts/capture-screenshots.mjs` regenerates them from the production
  export, so the next UI change is cheap to reflect.

## Keymaker v1.0.0

First Keymaker release, forked from IttyBitz v2.8.0 (the previous
RELEASE-NOTES-*.md history is consolidated into this file).

### Rebrand
- Renamed to **Keymaker** (app title, PWA manifest, package name, docs).
- New visual identity: deep amber/bronze key motif; `.keym` file extension;
  `KEYM1:` prefix for encrypted text blobs.

### New crypto core (KEYM v1)
- Self-describing, AAD-authenticated container header (KDF id, cipher id,
  KDF params, key-file flag) — decryption needs no options.
- Argon2id KDF (via hash-wasm) alongside PBKDF2-HMAC-SHA-256 (1M iters).
- ChaCha20-Poly1305 (via @noble/ciphers) alongside AES-256-GCM, plus chained
  AES-256-GCM → ChaCha20-Poly1305 with HKDF-derived independent subkeys.
- Transparent legacy support: IttyBitz IBTZ v1 and headerless v0 payloads
  (files and bare base64 blobs) decrypt as before, with an import notice.

### UI/UX
- Collapsible **Advanced** section on the Encrypt tab: KDF choice with
  Argon2id parameter sliders, cipher choice with explanations, key-file
  toggle, filename obscuring, and an effective-configuration summary.
- New **Tools** tab with a dice entropy calculator (ported from Morpheus):
  bits per roll, rolls needed for the 128-bit floor / 256-bit target,
  progress bar, verdict, and educational context.
- Encrypt-side secret field now defaults to blurred (matching decrypt side).
- Entropy-aware password strength: 4+ word passphrases count as strong even
  without symbol/uppercase classes.
- Post-decryption info line shows the detected container format and
  parameters.
