# Phase 8, outreach drafts

Drafts for the owner to post. **Nothing here has been published**, and nothing
here should be posted by anyone but the account that owns the project.

Three preconditions, and none is optional.

1. **The release must exist before the post does.** The first thing a
   security-minded visitor does is look for something to check `SHA256SUMS`
   against. Push the `v2.4.0` tag first, and wait until its release page
   carries `SHA256SUMS`, the signature and the build attestation. Posting
   before that spends the one arrival that matters on a repo that cannot yet
   back its own claims.
2. **Read the claims below against the code before posting.** Every claim was
   checked against `main` on 29 September 2026, when these drafts were
   refreshed for v2.4.0. A post is the one artefact in this project that a
   later commit cannot correct.
3. **Settle how the review is described.** The drafts below say "not audited"
   and "self-reviewed". `SECURITY-AUDIT.md` calls its findings the result of
   external review, and one of its sections a third-party audit by a
   four-agent swarm. `docs/AUDIT-BRIEF.md` records the conflict and says only
   the owner can settle it. A reader who finds both descriptions will quote
   them side by side, so decide which is true, make the documents agree, and
   then make the drafts match.

## What to lead with

The roadmap is explicit, and it is worth restating, because the instinct is to
lead with the cipher list and the cipher list is the least interesting thing
here.

> lead with the offline guarantee and the recovery path rather than the cipher
> list. The demonstration that lands is "every network request blocked, full
> round trip still works", which the UAT already measured.

Three claims, in this order, all checkable.

1. **Nothing is sent, and you can check that rather than trust it.** No
   telemetry, no code that transmits, a reproducible build and a signed
   manifest. `connect-src 'none'` is enforced by a build that fails if the
   directive changes. With every network request aborted at the browser level,
   UAT completed a full Argon2id text round trip with zero requests attempted.

   Claim it as *auditable*, never as *impossible*. `connect-src` covers the
   connection APIs, not resource loads, so an image URL can still carry data
   off the page, and a `<meta>` policy does not reach the Web Worker the key
   derivation runs in. This audience checks, and an overclaim found by a reader
   costs more than the caveat ever would.
2. **Your file outlives the tool.** A specified format, an independent Python
   implementation that decrypts without a browser, and a written recovery
   procedure. The procedure's commands are run by the test suite on every pull
   request and before every deploy, rather than asserted.
3. **You can check what you were served.** Reproducible builds, a Sigstore
   signature over the manifest, a GitHub build attestation on each release,
   and a page in the app that gives you the commands.

## What not to say

- **Not "hardware-grade", "unbreakable", "military-grade" or "zero-knowledge".**
  The last one has a specific meaning this does not implement.
- **Not "audited".** It has a self-audit and a documented findings list. Calling
  that an audit is the kind of claim that gets deservedly taken apart in the
  comments.
- **Do not oversell chained AEAD.** It is defence in depth against one cipher
  breaking, not a proven construction, and the app says so. A post that says
  more than the app does is a post the app contradicts.
- **Do not sell the passkey slot as extra strength.** The format requires a
  passkey slot to sit beside another way in, so a container is as strong as
  the weaker of the two, and the README says so.
- **Do not compare on security to `age` or GPG.** The README's comparison is
  honest that a browser tool has the weakest trust anchor of the four. Leading
  with a comparison the project itself qualifies invites exactly the reply that
  ends the thread.

---

## r/privacy, draft

> **Title:** I built a browser encryption tool that makes no network requests,
> and a Python script that opens its files without it
>
> Most browser crypto tools ask you to trust that the page isn't sending your
> data anywhere. There's no way to check, so the honest answer has been "don't
> use them for anything that matters".
>
> Keymaker is my attempt at the version you *can* check.
>
> - **Nothing is sent, and you don't have to take my word for it.** There's no
>   telemetry and no code that transmits. The build is reproducible and the
>   manifest is signed, so you can check the bytes you were served against the
>   source. The CSP is `connect-src 'none'` and the build fails if that's ever
>   loosened. With every network request blocked at the browser level, a full
>   encrypt and decrypt round trip still completed. What I won't claim is that
>   it's *impossible*. `connect-src` covers fetch and friends, not an image URL
>   with data in it, and a `<meta>` policy doesn't reach the worker the key
>   derivation runs in. The guarantee is that it's auditable, not that the
>   browser is stopping me.
> - **Your file doesn't depend on the website.** The container format is
>   specified, and one Python file decrypts it with two mainstream libraries,
>   no browser and no npm. The written recovery procedure is run by the test
>   suite on every change, so it can't quietly stop being true.
> - **You can verify the build you were served.** Reproducible builds, a
>   Sigstore signature over the file manifest, a GitHub build attestation on
>   each release, and a page in the app that prints the exact commands for the
>   build you're looking at.
>
> Argon2id or PBKDF2, and AES-256-GCM or ChaCha20-Poly1305 or both chained.
> k-of-n Shamir recovery shares. A paper backup that prints as scannable codes
> and scans back in with a phone camera. For PBKDF2 and AES-GCM backups, a
> single self-contained HTML page an heir can open with no tools.
>
> It's GPL-3, with no account, no telemetry and nothing to buy. I'd genuinely
> like the CSP and format claims picked apart. Those are the ones that matter,
> and they're the ones I can be wrong about.
>
> [repo] · [live app] · [verify page]

## Hacker News (Show HN), draft

HN requires the `Show HN:` prefix, so this title keeps its colon.

> **Title:** Show HN: Keymaker, browser encryption with no network requests and
> a Python decryptor
>
> The problem with browser-based encryption is that you can't verify the code
> you were served. I couldn't fix that, so I did the next three things instead.
>
> 1. `connect-src 'none'` in the CSP, blocking fetch, XHR, WebSocket,
>    EventSource and sendBeacon, with a build step that fails if the directive
>    changes. Not a structural guarantee, and I don't pitch it as one. Resource
>    loads aren't covered, and a `<meta>` policy doesn't reach the worker. What's
>    checkable is that no code in the bundle transmits, and the build is
>    reproducible so you can verify the bundle.
> 2. An independent Python implementation of the container format, so a file
>    encrypted today opens in ten years without this site, this app or a
>    browser. Both implementations are compared byte for byte in CI, on the
>    bytes they write and not only on whether they read each other.
> 3. Reproducible builds, a Sigstore signature over the manifest, a GitHub
>    build attestation on each release, and an in-app page that gives you the
>    verification commands for the running build.
>
> The thing I'd most like feedback on is the format design doc. It records the
> decisions and, more usefully, the things it deliberately does *not* fix.
> Chained AEAD is unproven as a combiner, and memory hygiene in JS is
> best-effort. Container length reveals plaintext length unless you opt into
> the padded variant.
>
> Not audited. Self-reviewed with the findings written down, which is a
> different and lesser thing.
>
> [repo] · [format design] · [live app]

## r/crypto, draft

Narrower and more technical. This audience will go straight to the format.

> **Title:** The KEYM container format, with envelope key slots, chunked STREAM
> AEAD and k-of-n Shamir shares, plus a design doc and two implementations
>
> I'd appreciate review of the format rather than the app. The design document
> records the reasoning and the open problems.
>
> - Envelope encryption with independent slots, so a passphrase, a k-of-n
>   Shamir share set, a WebAuthn PRF credential, or a password and a share set
>   together can each unwrap the same master key. The slot table is
>   authenticated.
> - Chunked STREAM-style AEAD in 1 MiB chunks, with `uint88_be(i) || final_flag`
>   nonces, and both the header and the chunk index authenticated.
> - Shamir over GF(2^8) with the AES polynomial, and a constant-time multiply
>   specified normatively. The doc forbids log and antilog tables because the
>   indices are secret bytes.
> - An opt-in padded payload, so a container's length need not reveal the
>   plaintext's.
> - Two independent implementations, Python and TypeScript, compared byte for
>   byte in CI on containers *and* on the emitted share strings. A
>   container-only comparison passes while two implementations issue mutually
>   unusable shares, which is a mistake I made and caught.
>
> What it does not fix is written down in §8, and I'd rather hear about
> something I've missed there than about the parts I already know are weak.
>
> [format design] · [Python reference] · [conformance suite]

---

## After posting

- **Do not argue.** Answer factual questions, concede real hits, and link the
  document that already says so. This project's credibility rests on having
  written its weaknesses down first, and a defensive reply spends that.
- **A correction is cheap on day one and expensive on day three.** If a claim
  above turns out to be wrong, edit the post immediately and say what changed.
- **Expect the trust-anchor objection**, and welcome it. It is correct, the
  README already concedes it, and "here is the section where I say that, and
  here is what narrows it" is a much better answer than a defence.
