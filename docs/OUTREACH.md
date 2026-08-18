# Phase 8 — outreach drafts

Drafts for the owner to post. **Nothing here has been published**, and nothing
here should be posted by anyone but the account that owns the project.

Two preconditions, both from the roadmap's own gate, and neither is optional:

1. **A tagged release must exist.** The first thing a security-minded visitor
   does is look for something to check `SHA256SUMS` against. Posting before
   there is one spends the single arrival that matters on a repo that cannot yet
   substantiate its own claims. Cut `v2.0.0` first (owner register O5).
2. **Read the claims below against the code before posting.** Every number in
   them was true at the commit this file was written on. A post is the one
   artefact in this project that cannot be corrected by a later commit.

## What to lead with

The roadmap is explicit and it is worth restating, because the instinct is to
lead with the cipher list and the cipher list is the least interesting thing
here:

> lead with the offline guarantee and the recovery path rather than the cipher
> list. The demonstration that lands is "every network request blocked, full
> round trip still works", which the UAT already measured.

Three claims, in this order, all checkable:

1. **Nothing is sent, and you can check that rather than trust it.** No
   telemetry, no transmitting code, reproducible build, signed manifest.
   `connect-src 'none'` is enforced by a build that fails closed if the
   directive changes, and UAT measured a full Argon2id round trip with 100% of
   requests aborted at the browser level.

   Claim it as *auditable*, never as *impossible*. `connect-src` covers the
   connection APIs and not resource loads — one `new Image().src` with a query
   string leaves the browser, measured — and a `<meta>` policy does not reach
   the Web Worker the key derivation runs in. This audience checks; an
   overclaim found by a reader costs more than the caveat ever would.
2. **Your file outlives the tool.** A specified format, an independent Python
   implementation that decrypts without a browser, and a printed procedure —
   all three tested on every commit rather than asserted.
3. **You can check what you were served.** Reproducible builds, a Sigstore
   signature over the manifest, and an in-app page that hands you the commands.

## What not to say

- **Not "hardware-grade", "unbreakable", "military-grade", or "zero-knowledge".**
  The last one has a specific meaning this does not implement.
- **Not "audited".** It has a self-audit and a documented findings list. Calling
  that an audit is the kind of claim that gets deservedly taken apart in the
  comments.
- **Do not oversell chained AEAD.** It is defence in depth against one cipher
  breaking, not a proven construction, and the app says so — a post that says
  more than the app does is a post the app contradicts.
- **Do not compare on security to `age` or GPG.** The README's comparison is
  honest that a browser tool has the weakest trust anchor of the four. Leading
  with a comparison the project itself qualifies invites exactly the reply that
  ends the thread.

---

## r/privacy — draft

> **Title:** I built a browser encryption tool that makes zero network requests
> — and a Python script that opens its files without it
>
> Most browser crypto tools ask you to trust that the page isn't exfiltrating
> your data. There's no way to check, so the honest answer has been "don't use
> them for anything that matters".
>
> Keymaker is my attempt at the version you *can* check:
>
> - **Nothing is sent, and you don't have to take my word for it.** There's no
>   telemetry and no code that transmits. The build is reproducible and the
>   manifest is signed, so you can check the bytes you were served against the
>   source. The CSP is `connect-src 'none'` and the build fails if that's ever
>   loosened; a UAT run blocked 100% of network requests and a full encrypt →
>   decrypt round trip still completed. What I won't claim is that it's
>   *impossible* — `connect-src` covers fetch and friends, not an image URL with
>   a query string on it, and a `<meta>` policy doesn't reach the worker the key
>   derivation runs in. The guarantee is that it's auditable, not that the
>   browser is stopping me.
> - **Your file doesn't depend on the website.** The container format is
>   specified, and there's a ~600-line Python script that decrypts it with two
>   mainstream libraries, no browser and no npm. There's a printed recovery
>   procedure that's executed by the test suite on every commit, so it can't
>   quietly stop being true.
> - **You can verify the build you were served.** Reproducible builds, a
>   Sigstore signature over the file manifest, and a page in the app that prints
>   the exact `cosign verify-blob` command for the build you're looking at.
>
> Argon2id or PBKDF2, AES-256-GCM or ChaCha20-Poly1305 or both chained, k-of-n
> Shamir recovery shares, and a paper backup that prints as scannable codes with
> the recovery procedure on the same page.
>
> It's GPL-3, there's no account, no telemetry and nothing to buy. I'd
> genuinely like the CSP and format claims picked apart — those are the ones
> that matter, and they're the ones I can be wrong about.
>
> [repo] · [live app] · [verify page]

## Hacker News (Show HN) — draft

> **Title:** Show HN: Keymaker – browser encryption that makes no network
> requests, and a Python decryptor
>
> The problem with browser-based encryption is that you can't verify the code
> you were served. I couldn't fix that, so I did the next three things instead:
>
> 1. `connect-src 'none'` in the CSP, blocking fetch, XHR, WebSocket and
>    sendBeacon, with a build step that fails closed if the directive changes.
>    Not a structural guarantee and I don't pitch it as one: resource loads
>    aren't covered, and a `<meta>` policy doesn't reach the worker. What's
>    checkable is that no code in the bundle transmits, and the build is
>    reproducible so you can verify the bundle.
> 2. An independent Python implementation of the container format, so a file
>    encrypted today opens in ten years without this site, this app, or a
>    browser. Both implementations are compared byte-for-byte in CI.
> 3. Reproducible builds and a Sigstore signature over the manifest, plus an
>    in-app page that gives you the verification commands for the running build.
>
> The thing I'd most like feedback on is the format design doc — it records the
> decisions and, more usefully, the things it deliberately does *not* fix
> (container length leaks plaintext length, chained AEAD is unproven as a
> combiner, memory hygiene in JS is best-effort).
>
> Not audited. Self-reviewed with the findings written down, which is a
> different and lesser thing.
>
> [repo] · [format design] · [live app]

## r/crypto — draft

Narrower and more technical. This audience will go straight to the format.

> **Title:** KEYM v2: a container format with multi-slot envelope keys, chunked
> STREAM AEAD, and a k-of-n Shamir slot — design doc and two implementations
>
> I'd appreciate review of the format rather than the app. The design document
> records the reasoning and the open problems:
>
> - Envelope encryption with independent slots, so a passphrase, a k-of-n Shamir
>   share set and (designed, not built) a WebAuthn PRF credential can each unwrap
>   the same master key.
> - Chunked STREAM-style AEAD, 1 MiB chunks, `uint88_be(i) || final_flag`
>   nonces, with both the header and the chunk index authenticated.
> - Shamir over GF(2^8) with the AES polynomial, constant-time multiply
>   specified normatively — the doc forbids log/antilog tables because the
>   indices are secret bytes.
> - Two independent implementations, Python and TypeScript, compared byte for
>   byte in CI on containers *and* on the emitted share strings — a
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
- **Expect the trust-anchor objection**, and welcome it: it is correct, the
  README already concedes it, and "here is the section where I say that, and
  here is what narrows it" is a much better answer than a defence.
