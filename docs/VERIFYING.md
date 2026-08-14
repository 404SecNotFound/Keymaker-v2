# Verifying a Keymaker deployment

Keymaker's README says plainly that **whoever serves the bundle is the trust
anchor**. Reading the source on GitHub tells you nothing about the JavaScript
that arrived in your browser this morning. That is true of every web app, and
it matters more here than for most, because this one is asked to hold seed
phrases.

This document is how you stop taking that on trust.

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
# Mirror the deployment (or use a copy you already have)
wget -r -np -nH --cut-dirs=1 https://404secnotfound.github.io/Keymaker-v2/ -P site

cd site
sha256sum -c SHA256SUMS
```

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

---

## 2. Rebuild it yourself

The build is reproducible: two clean builds of the same commit produce
byte-identical output, and CI enforces that on every change.

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

### What makes this possible

Next generates a random build id per build, which appears in
`_next/static/<buildId>/` paths and inside the emitted HTML. That single value
was the only thing making two builds of one commit differ — every JS and CSS
chunk already hashed identically. It is now pinned to the commit SHA
(`next.config.js`), and `npm run verify:reproducible` builds twice and compares
every file so it cannot quietly regress.

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

## If verification fails

Do not use the deployment, and do not assume it is a bug in these instructions.

- `sha256sum -c` reporting a mismatch means the file differs from what was
  signed.
- `verify-manifest.mjs` reporting an **unsigned** file means something is being
  served from the same origin, under the same CSP, that nobody signed for.
- A signature failure with the correct identity flags means the manifest was not
  signed by this repository's deploy workflow.

Any of the three is worth reporting through
[SECURITY.md](../SECURITY.md). Your existing `.keym` files are unaffected either
way — they are decryptable with `reference/keym.py` and the printed procedure
in [RECOVERY.md](RECOVERY.md), neither of which involves the website at all.
