# Changelog

## Keymaker v2.1.0

Everything below shipped between v1.0.0 and v2.1.0. There is no separate
v2.0.0 section: that tag was cut mid-stream, while this file still said
"Unreleased", and splitting the entries after the fact would be a guess about
which side of a lightweight ref each one fell on. The commit range is the
authority for that; this is the record of what changed.

### Added
- **A container inspector beside the form.** The desktop layout is now a
  two-pane workbench: the form on the left, and on the right a pane that
  reads the container's header out loud — the magic bytes, the format
  generation, and every slot in the table with its KDF and cost. It parses
  with the same functions the unlock path trusts, live as a container is
  loaded on the Decrypt side and from a header peek captured at seal time on
  the Encrypt side; before anything exists it restates the form's plan,
  labelled as a plan. A v2 container is called out as having an
  unauthenticated slot table; the browser suite holds the pane's slot count
  to the container's own slot-count byte, and a corrupted version byte must
  produce no rows at all.

### Changed
- **The visual identity moved from amber glass to a hairline near-black
  system** — `#08090a` ground, `0.5px`-feel borders instead of blur and
  shadows, radii of 12px/6px, Inter (self-hosted, lockfile-pinned, the Latin
  faces precached for offline) with tight display tracking, and a single
  acid-lime accent reserved for the primary action. The KDF and cipher
  option cards now carry `aria-pressed`, so selection is machine-readable
  rather than a paint detail; the logo, PWA icons, theme colour and social
  card follow, and the social card's source template lives in
  `scripts/og-card-template.html` so it regenerates from the repository like
  everything else.

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
- **`docs/FORMAT-V3-DESIGN.md`** — KEYM v3, specified as a delta on v2, and
  implemented in `reference/keym2.py` behind an opt-in. v3 authenticates the
  slot table as a whole, which v2 does not: a v2 table is authenticated
  slot-by-slot, so anyone who can write the file can **delete a slot** and the
  container still opens normally for everyone else. The owner sees their data
  and has no way to notice that an heir's recovery path is gone. That attack was
  reproduced before anything was designed; the other two tried — reordering and
  transplanting a slot — turned out to be inert, and the document says so rather
  than claiming defeated attacks.

  The fix is a `slot_table_mac`: HMAC-SHA-256 under
  `HKDF(master_key, "keymaker.v3.slot-table")` over the core header, the slot
  count and every slot record, plus a 16-byte `container_id` that makes each
  container's AAD unique. Recomputing it needs only the master key, which
  unwrapping any one slot already yields — so a table stays editable by someone
  holding one secret, which is the property `keym-v2.ts` protects at
  `WRAP_NONCE` and which any v3 design had to keep.

  On a mismatch the reader **still returns the plaintext** and reports that the
  table is not authentic. Refusing would turn detectable tampering into a lost
  backup, which is the worse outcome; the payload is independently authenticated
  and is not what changed. This is the one exception to the generic-error rule,
  and it leaks nothing — the check runs only after a secret has already opened a
  slot.

  Python writes v2 by default and v3 on request (`--v3`). Until the TypeScript
  core writes v3 too, defaulting to it would leave the byte-for-byte conformance
  job with nothing to compare against, which would weaken the one test that
  proves the two implementations agree.

  **The TypeScript core now writes and reads v3 as well**, and the two
  implementations are held to the same bytes: `crosstest2.py` compares v3
  containers across all six KDF and cipher combinations, both sides reproduce
  the vector published in §8 of the design document, and an enrolment performed
  by the TypeScript is byte-identical to the same enrolment performed by the
  reference — which is what actually pins the MAC, since the two decode each
  other's containers happily even when they disagree about how to write one.
  The §5.2 verdict is cross-checked too: the reference writes a container, strips
  a slot out of it, and the TypeScript must reach the same three-state answer.
  **v3 is now frozen into the fixture corpus**, which is what turns the format
  from implemented into promised. Thirteen new vectors: six across every KDF and
  cipher pair, three share sets and three passkey slots — the enrolment paths,
  because §5.3's re-seal is the work v3 adds and a MAC that verified only on the
  day it was written would look identical to a correct one — and one container
  with an heir's slot cut out of it. Both implementations open all thirteen and
  agree on the §5.2 verdict for each.

  That stripped vector is §1.1's attack frozen as bytes, and the corpus is where
  it belongs rather than only in a test that builds one at runtime: a detection
  checked against a container the same code produced can agree with itself. It
  asserts the whole of §5.2 — the plaintext still comes back, the report still
  says the table changed, and the heir whose slot was cut is locked out for
  good.

  **The app can now open a v3 container at all.** `detectFormat` named only v2
  and v1, so `decryptData` routed version 3 to the v1 path and refused it as
  "a newer KEYM version" — a reader turning away a format it had already
  implemented, and a plain violation of §6. The container parser had learned
  0x03; the dispatcher in front of it had not. Both are named now, and the
  §5.2 verdict travels out through the worker to the screen, because a report
  that stops inside the crypto core is not reported to anyone: opening a
  container whose slot table has changed now says so, in as many words, without
  claiming to know which unlock method moved.

  **Both implementations now write v3 by default.** New backups carry an
  authenticated slot table; nothing rewrites an existing file, and v1 and v2
  containers open exactly as before.

  What gated this was not the format but the readers. Three of them open a
  Keymaker backup, and only two can ever be updated: the app and `keym2.py`.
  The third is the decryptor inside a §7.2 self-extracting page, which travels
  *in* the backup — a page written today runs the reader it was born with for as
  long as the file exists. That reader was v2-only, so moving the default before
  teaching it v3 would have made every page exported afterwards a backup with no
  way into it. It now reads both, and reports §5.2's verdict on its own face:
  a page whose slot table has changed still opens, and says so.

  Two more places had learned v2's layout by hand and had to be shown the
  version byte. The page *builder*'s subset check read `slot_count` from offset
  8, which in v3 is the first byte of `container_id` — it answered "the password
  slot uses Argon2id" for a PBKDF2 container, because it was walking the header
  as though it were the slot table. `isKeym2Binary` compared against "the
  version we write" rather than naming v2 and v3, so the flip would have made it
  stop recognising every v2 backup in existence.



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
