import type { Metadata } from "next";

/**
 * Roadmap 6.3 — "Verify this build", in the app rather than only in a document.
 *
 * The infrastructure has been complete for a while: a signed manifest, a
 * reproducible build, an independent reference implementation. None of it was
 * reachable from the thing a user actually opens. This page is the missing
 * step, and its job is narrow on purpose.
 *
 * ## What this page deliberately is not
 *
 * It is **not a button that says "verified"**. It cannot be. Everything on this
 * page arrived from the same server as the JavaScript in question, so a page
 * asserting its own integrity is asserting exactly the thing under doubt. That
 * is the KM-02 failure class — a reassuring claim the software is not entitled
 * to make — and this project has already fixed it once in the password-strength
 * meter. It would be worse here, because the whole point of the page is to be
 * believed about trust.
 *
 * So the page states what the build *claims*, hands over the commands that
 * check the claim, and gets out of the way.
 *
 * ## Why there is no manifest digest printed here
 *
 * The obvious thing to show — sha256 of SHA256SUMS — cannot be shown honestly:
 *
 * - **Baking it is circular.** `SHA256SUMS` covers this page, so writing the
 *   digest into the page changes the page, which changes the manifest, which
 *   changes the digest. There is no fixed point.
 * - **Fetching it needs `connect-src 'self'`.** The policy is `connect-src
 *   'none'`, which KM-07 was raised specifically to obtain and
 *   `platform.spec.ts` exists to keep. Trading a zero-egress guarantee for a
 *   convenience is a bad trade in a tool whose pitch is zero egress.
 * - **It would prove nothing.** A digest served by the same host as the bundle
 *   is a number that host chose.
 *
 * The commit is different: it is an *input* to the build, it is already baked
 * into every asset path, and checking it is the first step of the procedure
 * rather than a substitute for it.
 */

export const metadata: Metadata = {
  title: "Verify this build",
  description:
    "Check that the Keymaker you are running is the artifact this repository's CI produced, and that it was built from the published source.",
};

const BASE = process.env.KEYMAKER_BASE_PATH || "";
const COMMIT = process.env.KEYMAKER_COMMIT || "unknown";
const APP_VERSION = process.env.KEYMAKER_APP_VERSION || "unknown";

// Extracted from docs/VERIFYING.md at build time by next.config.js, so this
// page cannot print a command that has drifted from the document. See
// scripts/verifying-doc.cjs.
const COSIGN = process.env.KEYMAKER_VERIFY_COSIGN || "";
const SHA256SUM = process.env.KEYMAKER_VERIFY_SHA256SUM || "";

const REPO = "https://github.com/404SecNotFound/Keymaker-v2";

/** A commit SHA is 40 hex characters; anything else is a local or untracked build. */
const isCommit = /^[0-9a-f]{40}$/.test(COMMIT);

function Command({ children }: { children: string }) {
  return (
    <pre className="overflow-x-auto rounded-lg border border-white/10 bg-black/40 p-4 text-[12.5px] leading-relaxed text-foreground">
      <code>{children}</code>
    </pre>
  );
}

export default function VerifyBuild() {
  return (
    <main className="mx-auto min-h-screen w-full max-w-3xl px-5 py-10 sm:py-14">
      {/*
        A plain anchor rather than next/link. The export is served by whatever
        static host it lands on, under a base path that is a build-time
        constant — one fewer router assumption between a visitor and the page
        that is supposed to make them less trusting, not more.
      */}
      <p className="text-[13px]">
        <a href={`${BASE}/`} className="text-muted-foreground hover:text-foreground hover:underline">
          ← Back to Keymaker
        </a>
      </p>

      <h1 className="mt-6 text-2xl font-semibold tracking-tight sm:text-3xl">Verify this build</h1>

      <p className="mt-4 text-[15px] leading-relaxed text-muted-foreground">
        Keymaker runs entirely in your browser, which means{" "}
        <strong className="text-foreground">whoever served you this page is the trust anchor</strong>.
        Reading the source on GitHub tells you nothing about the JavaScript that arrived here. That
        is true of every web app and it matters more here, because this one is asked to hold seed
        phrases.
      </p>

      <p className="mt-4 text-[15px] leading-relaxed text-muted-foreground">
        This page will not tell you it has verified itself. It cannot: everything on it came from
        the same place as the code you are questioning. What it can do is tell you exactly what this
        build claims to be, and give you the commands that check the claim from outside.
      </p>

      {/* ---- What this build says it is ---- */}

      <h2 className="mt-10 text-lg font-semibold tracking-tight">What this build claims</h2>

      <dl className="mt-4 divide-y divide-white/6 rounded-xl border border-white/10 bg-white/2">
        <div className="flex flex-col gap-1 px-4 py-3 sm:flex-row sm:items-baseline sm:gap-4">
          <dt className="w-40 shrink-0 text-[13px] text-muted-foreground">Application version</dt>
          <dd className="font-mono text-[13px]" data-testid="verify-app-version">
            {APP_VERSION}
          </dd>
        </div>
        <div className="flex flex-col gap-1 px-4 py-3 sm:flex-row sm:items-baseline sm:gap-4">
          <dt className="w-40 shrink-0 text-[13px] text-muted-foreground">Container format</dt>
          <dd className="font-mono text-[13px]">KEYM v2</dd>
        </div>
        <div className="flex flex-col gap-1 px-4 py-3 sm:flex-row sm:items-baseline sm:gap-4">
          <dt className="w-40 shrink-0 text-[13px] text-muted-foreground">Source commit</dt>
          <dd className="min-w-0 break-all font-mono text-[13px]" data-testid="verify-commit">
            {isCommit ? (
              <a
                className="hover:underline"
                href={`${REPO}/commit/${COMMIT}`}
                target="_blank"
                rel="noopener noreferrer"
              >
                {COMMIT}
              </a>
            ) : (
              COMMIT
            )}
          </dd>
        </div>
      </dl>

      <p className="mt-3 text-[13px] leading-relaxed text-muted-foreground">
        {isCommit ? (
          <>
            That commit is also baked into every asset path under{" "}
            <code className="font-mono">_next/static/</code>, so it is not a label that can be
            changed without changing the build. It is still a <em>claim</em> — the checks below are
            what turn it into a fact.
          </>
        ) : (
          <>
            This build was not made from a git checkout, so it names no commit and cannot be
            reproduced or verified. That is expected for a local <code className="font-mono">npm
            run build</code>, and it should never appear on a deployment.
          </>
        )}
      </p>

      {/* ---- Check 1 ---- */}

      <h2 className="mt-10 text-lg font-semibold tracking-tight">
        1. Are these the files CI produced?
      </h2>

      <p className="mt-3 text-[15px] leading-relaxed text-muted-foreground">
        Every deployment publishes a{" "}
        <a className="underline hover:no-underline" href={`${BASE}/SHA256SUMS`}>
          SHA256SUMS
        </a>{" "}
        manifest and a{" "}
        <a className="underline hover:no-underline" href={`${BASE}/SHA256SUMS.sigstore`}>
          Sigstore bundle
        </a>{" "}
        signing it. Mirror the site and check the files against the manifest:
      </p>

      <div className="mt-3">
        <Command>{SHA256SUM}</Command>
      </div>

      <p className="mt-3 text-[13px] leading-relaxed text-muted-foreground">
        <code className="font-mono">sha256sum</code> is on every Unix machine and has nothing to do
        with this project, which is the point: that step needs no software you have to trust us
        about.
      </p>

      <h2 className="mt-10 text-lg font-semibold tracking-tight">
        2. Who signed that manifest?
      </h2>

      <p className="mt-3 text-[15px] leading-relaxed text-muted-foreground">
        With <a className="underline hover:no-underline" href="https://docs.sigstore.dev/" target="_blank" rel="noopener noreferrer">cosign</a>:
      </p>

      <div className="mt-3">
        <Command>{COSIGN}</Command>
      </div>

      <p className="mt-3 text-[13px] leading-relaxed text-muted-foreground">
        Keyless signing, so there is no published key to obtain and no key distribution to get
        wrong. The check is not &ldquo;signed by a key we told you about&rdquo; — it is{" "}
        <em>signed by this workflow, in this repository</em>, and{" "}
        <code className="font-mono">--certificate-identity</code> is the flag that makes it so.
        Without that flag <code className="font-mono">cosign verify-blob</code> accepts a signature
        from anybody and still prints <span className="font-mono">Verified OK</span>.
      </p>

      {/* ---- Check 3 ---- */}

      <h2 className="mt-10 text-lg font-semibold tracking-tight">
        3. Does that artifact match the source?
      </h2>

      <p className="mt-3 text-[15px] leading-relaxed text-muted-foreground">
        The first two checks prove GitHub built <em>something</em> and served it to you intact. They
        say nothing about whether that something matches the code you can read. The build is
        reproducible — two clean builds of one commit produce identical bytes, and CI enforces it on
        every change — so you can settle that yourself by rebuilding{" "}
        {isCommit ? <span className="font-mono break-all">{COMMIT.slice(0, 12)}</span> : "the commit above"}{" "}
        and diffing the manifests.
      </p>

      <p className="mt-3 text-[15px] leading-relaxed text-muted-foreground">
        The full procedure, including what these checks do <em>not</em> prove, is in{" "}
        <a
          className="underline hover:no-underline"
          href={`${REPO}/blob/main/docs/VERIFYING.md`}
          target="_blank"
          rel="noopener noreferrer"
        >
          docs/VERIFYING.md
        </a>
        . The commands above are generated from that document at build time rather than copied
        beside it, so the two cannot drift.
      </p>

      {/* ---- The honest limits ---- */}

      <h2 className="mt-10 text-lg font-semibold tracking-tight">What none of this proves</h2>

      <ul className="mt-3 space-y-2 text-[14px] leading-relaxed text-muted-foreground">
        <li>
          <strong className="text-foreground">Not that the code is correct.</strong> Verification
          says the bytes you ran match the source in the repository. Whether that source is any good
          is what the audit, the test suites and the independent Python implementation are for.
        </li>
        <li>
          <strong className="text-foreground">Not that the repository is honest.</strong> Anyone who
          can push to <span className="font-mono">main</span> gets a valid signature over whatever
          they built. What catches that is the history being public and the diff reviewable.
        </li>
        <li>
          <strong className="text-foreground">Not your machine.</strong> A browser extension, a
          compromised device or a hostile TLS path after you verified are all outside what a
          signature can reach.
        </li>
        <li>
          <strong className="text-foreground">Not this page.</strong> If the bundle were replaced,
          this page would be replaced with it — and a tampered copy would happily print reassuring
          text. Run the commands; do not take the page&rsquo;s word for anything.
        </li>
      </ul>

      <p className="mt-8 border-t border-white/8 pt-6 text-[13px] leading-relaxed text-muted-foreground">
        Your encrypted files do not depend on any of this. A{" "}
        <span className="font-mono">.keym</span> container is decryptable with{" "}
        <a
          className="underline hover:no-underline"
          href={`${REPO}/blob/main/reference/keym2.py`}
          target="_blank"
          rel="noopener noreferrer"
        >
          reference/keym2.py
        </a>{" "}
        and no browser at all — a copy ships with this app, under{" "}
        <a className="underline hover:no-underline" href={`${BASE}/recovery/keym2.py`}>
          /recovery/
        </a>
        .
      </p>
    </main>
  );
}
