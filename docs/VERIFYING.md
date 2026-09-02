# Verifying a Keymaker deployment

Keymaker's README says plainly that **whoever serves the bundle is the trust
anchor**. Reading the source on GitHub tells you nothing about the JavaScript
that arrived in your browser this morning. That is true of every web app, and
it matters more here than for most, because this one is asked to hold seed
phrases.

This document is how you stop taking that on trust.

The running app links to a
[**Verify this build**](https://404secnotfound.github.io/Keymaker-v2/verify.html) page
that names the commit it was built from and prints these commands filled in for that
deployment — generated from this file, so the two cannot drift. Start there if you have
the app open; this document is the full reasoning behind it, including what the checks
do not cover.

There are two separate questions, they fail for different reasons, and it is
worth knowing which one you are answering.

| Question | Answered by | What a failure means |
|---|---|---|
| Is the site I fetched the artifact CI produced? | the signed manifest | someone altered the files after the build |
| Does that artifact correspond to the source I can read? | rebuilding it | the published source is not what was deployed |

The first without the second is weak: it proves GitHub built *something*, not
that the something matches the code you reviewed. The second without the first
tells you the source is reproducible but not what is actually being served.

---

## 1. Check the deployed site against its signed manifest

Every deployment publishes two extra files at its root:

- `SHA256SUMS` — a SHA-256 for every file in the build
- `SHA256SUMS.sigstore` — a Sigstore bundle signing that manifest

Download the site and check it:

```bash
# Fetch the manifest, then exactly the files it names.
mkdir -p site && cd site
BASE=https://404secnotfound.github.io/Keymaker-v2
curl -fsSL -o SHA256SUMS          "$BASE/SHA256SUMS"
curl -fsSL -o SHA256SUMS.sigstore "$BASE/SHA256SUMS.sigstore"
sed 's/^[0-9a-f]\{64\}  //' SHA256SUMS |
  while IFS= read -r path; do
    curl -fsSL --create-dirs -o "$path" "$BASE/$path"
  done

sha256sum -c SHA256SUMS
```

**Why this fetches a list instead of crawling.** `wget -r` follows links, and a
deployment contains files nothing links to: `.nojekyll`, the error page, and the
router payloads the app requests at runtime. Measured on the current build, **23
of 58 manifest entries are unreachable by link-following** — a mirror made that
way is missing a third of the artifact, and `sha256sum -c` reports every one as
a failure. That is a recipe which cries wolf on an honest deployment, and the
first thing it teaches is to ignore it.

The manifest is the file list. Reading it is also the stronger check: a crawler
can only find what the site chooses to link, whereas every signed file appears
here whether the site links it or not.

`sha256sum` is on every Unix machine and has nothing to do with this project,
which is the point: that step needs no software you have to trust us about.

Then check who signed the manifest. With [cosign](https://docs.sigstore.dev/):

```bash
cosign verify-blob \
  --bundle SHA256SUMS.sigstore \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity 'https://github.com/404SecNotFound/Keymaker-v2/.github/workflows/deploy.yml@refs/heads/main' \
  SHA256SUMS
```

Or, from a clone of this repository, which does both halves at once — file
hashes *and* signature identity:

```bash
npm ci
node scripts/verify-manifest.mjs ./site
```

### The same check, against a tagged release

A release carries those same two files as assets, alongside a tarball of the
build. Its purpose is to give you something to download and check *against* —
without one, both files exist only at the root of the live site, which is the
very thing in question.

One thing changes, and only one: a release is produced by
`.github/workflows/release.yml` running on a tag, not `deploy.yml` running on
`main`, so the certificate identity ends in `release.yml@refs/tags/<tag>`.
Substitute that into the command above and nothing else moves.

Do not skip the substitution and do not guess at it. Neither identity verifies
the other's artifact, and that failure looks exactly like tampering. You do not
have to retype it either — every release's notes print the command already
filled in, and those notes are **generated from this file** by
`scripts/release-notes.mjs`. There is one copy of that command in this
repository, and `scripts/release-notes-test.mjs` fails the build if a second one
appears or if the two drift.

From a clone, the same substitution works for the script:

```bash
tar -xzf keymaker-v2.0.0.tar.gz
KEYMAKER_CERT_IDENTITY='https://github.com/404SecNotFound/Keymaker-v2/.github/workflows/release.yml@refs/tags/v2.0.0' \
  node scripts/verify-manifest.mjs ./keymaker-v2.0.0
```

A release is built with the Pages base path, which is why it is not a drop-in
for hosting somewhere else, and it is labelled as the tagged release: the
footer says `v2.0.0` rather than `v2.0.0-dev`. That label is compiled in, so a
release is **not** byte-identical to a deployment of the same commit: the
chunk that carries the label, the HTML and router payloads that reference that
chunk by its content hash, and the service worker's precache list all differ.
Every other file is the same bytes. Rebuilding a release therefore sets one
more variable than rebuilding the deployment; [section 2](#2-rebuild-it-yourself)
gives both commands, and `scripts/release-recipe-test.mjs` fails the build if
the release one stops matching what `release.yml` actually sets.

### What the signature actually asserts

Keyless signing means there is no long-lived private key to store, rotate, or
leak. The deploy workflow proves its identity with the OIDC token GitHub mints
for it, Fulcio issues a short-lived certificate bound to that identity, and the
signature is logged in Rekor.

So the check is **not** "was this signed by a key we published" — that only
moves the trust problem to however you got the key. It is "was this signed by
*this workflow*, in *this repository*". If someone serves you a modified bundle,
they cannot produce that signature without compromising the repository itself.

The certificate identity is the load-bearing argument, so pass it explicitly.
`cosign verify-blob` without `--certificate-identity` will happily accept a
signature from *anybody*.

### Where you got that identity is the whole question

The paragraph above holds only if the identity you passed is the right one, and
it is worth following what happens when it is not — because that failure is
silent and it looks exactly like success.

Sigstore keyless signing is available to **any** GitHub repository, free and
without approval. Someone who controls the origin serving you Keymaker can
therefore:

1. build a modified bundle;
2. generate `SHA256SUMS` over their own files;
3. sign that manifest with a workflow in *their* repository, obtaining a real
   Fulcio certificate and a real Rekor entry; and
4. serve a verify page that prints their own workflow in
   `--certificate-identity`.

Run the commands exactly as that page presents them and `sha256sum -c` passes,
`cosign verify-blob` prints **Verified OK**, and both results are correct.
Nothing has been forged. The signature is genuine — it is simply not ours.
`--certificate-oidc-issuer` does not discriminate either, because their workflow
authenticates to the same GitHub issuer this one does.

So the identity string is the trust root of everything on this page, and a trust
root obtained from the artifact under examination is not a trust root at all.
**The identity has to reach you by some route other than the deployment you are
checking.** Reading it here, in the repository, is such a route. Reading it off
the running app's verify page is not: that page is served by the origin whose
honesty is the open question.

No better-written page can fix this. A page cannot establish its own provenance,
and one that appeared to would be lying — which is why the in-app page states
what the build *claims* and refuses to certify itself. The only useful response
is to be explicit about which value carries the weight, and this is it.

#### The form of the check that does not have this problem

`node scripts/verify-manifest.mjs ./site`, shown above, is run from a clone with
no `KEYMAKER_CERT_IDENTITY` set. It uses the identity compiled into the script —
the one in the source you cloned, not one handed to you by the site being
tested. That makes it strictly stronger than pasting the `cosign` command out of
a running deployment, and it is the form to prefer when the question is *"is
this deployment genuine?"* rather than *"are these files internally
consistent?"*.

The `cosign` invocation stays, because it depends on nothing of ours and is the
right tool when you would rather not run our script either. Take the identity
from the repository rather than from the page, and it answers the same question.

---

## 2. Rebuild it yourself

The build is reproducible: rebuild the commit a deployment claims to be, and
you get the same bytes it is serving. CI enforces that on every change, and
[what it enforces exactly](#what-reproducibility-is-actually-checked-against)
is written down below rather than left to be assumed.

```bash
git clone https://github.com/404SecNotFound/Keymaker-v2
cd Keymaker-v2
git checkout <the commit the deployment claims>
npm ci

# The deployed site is served from a subdirectory, which is baked into the
# asset paths — a root build will not match it.
KEYMAKER_BASE_PATH=/Keymaker-v2 npm run build

diff out/SHA256SUMS ../site/SHA256SUMS && echo "identical"
```

If those manifests match, the deployed artifact was built from exactly the
source you just read.

A tagged release is rebuilt the same way with one more variable. `release.yml`
sets `KEYMAKER_RELEASE_TAG` to the tag it is building, which is what labels the
artifact as the release rather than a rolling build of `main`; leave it unset
and six files come out different, for the reason given in
[section 1](#the-same-check-against-a-tagged-release). Substitute the tag:

```bash
git checkout <tag>
npm ci

# The same two variables release.yml builds with, and nothing else.
KEYMAKER_RELEASE_TAG=<tag> KEYMAKER_BASE_PATH=/Keymaker-v2 npm run build

diff out/SHA256SUMS ../keymaker-<tag>/SHA256SUMS && echo "identical"
```

### What makes this possible

Next generates a random build id per build, which appears in
`_next/static/<buildId>/` paths and inside the emitted HTML. That single value
was the only thing making two builds of one commit differ — every JS and CSS
chunk already hashed identically. It is now pinned to the commit SHA
(`next.config.js`), and CI compares whole builds so it cannot quietly regress.

### What reproducibility is actually checked against

Worth being exact, because "reproducible" is a word that invites a reader to
assume more than was measured. Two things run on every change:

| Gate | What it varies | What it therefore proves |
|---|---|---|
| `npm run verify:reproducible` | Nothing but the clock, the locale and `HOME`, on one runner, once as a rolling build and once labelled as the release since the label is compiled in | The build is a function of its source, not of when it ran, on both channels. Catches a `Date.now()` in a bundle on the change that introduces it. |
| `reproducible-elsewhere` (ci.yml) | A different runner per leg, a different checkout path, a different Node major (22 and 24) | A *different machine* building the same commit gets the same bytes — which is the claim this page asks you to act on. |

Both build with `KEYMAKER_BASE_PATH=/Keymaker-v2`, so what is compared is the
artifact that gets published rather than a root build that never ships.

**Not checked: a different operating system, or a different CPU architecture.**
Every runner above is x86-64 Linux, and this page will not tell you something
has been verified when it has not. The caveat is not a formality either: the
build pulls platform-specific native binaries — SWC, Lightning CSS, esbuild,
libvips — so a macOS or arm64 machine compiles the bundle with *different
compiler code*, not merely on a different kernel. Whether it emits identical
bytes is untested here.

If you rebuild on another platform and the manifests match, that is the
strongest result available and worth saying so. If they differ, please report
it rather than assuming it is expected: the difference would tell us which of
those binaries is not deterministic across targets, which is worth knowing.

If you are building from a source tarball with no git metadata, set the id
explicitly:

```bash
KEYMAKER_BUILD_ID=<commit sha> KEYMAKER_BASE_PATH=/Keymaker-v2 npm run build
```

---

## What this does not prove

Being precise here matters more than sounding reassuring.

- **It does not audit the code.** Verification tells you the bytes you ran match
  the source in the repository. Whether that source is correct is what
  [SECURITY-AUDIT.md](../SECURITY-AUDIT.md), the test suites and the
  independent Python implementation in `reference/` are for.
- **It does not protect against a compromised repository.** If someone can push
  to `main` and trigger the deploy workflow, the signature will be valid — it
  is an honest signature over a malicious build. Reproducibility does not help
  either, because the source would match too. What catches that is the commit
  history being public and the diff being reviewable.
- **It does not cover a browser extension**, a compromised device, or a
  compromised TLS path *after* you have verified. Verification is a check on
  the artifact, not on the machine running it.
- **A signature is not a promise about behaviour.** It says who produced these
  bytes. It says nothing about whether those bytes are any good.
- **It does not verify itself, and neither does the in-app page.** Every check
  here is only as good as the certificate identity you passed, and a deployment
  that is lying to you will hand you an identity that makes its own signature
  verify. See [Where you got that identity is the whole
  question](#where-you-got-that-identity-is-the-whole-question) — this is the
  limit worth understanding before any of the others.

## If verification fails

Do not use the deployment, and do not assume it is a bug in these instructions.

- `sha256sum -c` reporting a mismatch means the file differs from what was
  signed.
- `verify-manifest.mjs` reporting an **unsigned** file means something is being
  served from the same origin, under the same CSP, that nobody signed for.
- A signature failure with the correct identity flags means the manifest was not
  signed by this repository's workflow. Check first that the identity matches
  the artifact in front of you — `deploy.yml@refs/heads/main` for the live site,
  `release.yml@refs/tags/<tag>` for a release. Verifying one against the other's
  identity fails, and it fails in a way indistinguishable from a forgery.

Any of the three is worth reporting through
[SECURITY.md](../SECURITY.md). Your existing `.keym` files are unaffected either
way — they are decryptable with `reference/keym.py` and the printed procedure
in [RECOVERY.md](RECOVERY.md), neither of which involves the website at all.
