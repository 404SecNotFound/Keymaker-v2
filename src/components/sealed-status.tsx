"use client";

/**
 * The sealed status — trust you can test, not read (10× plan, Bet 5).
 *
 * The export is forbidden by its own policy from contacting any server, and
 * the build is reproducible with a signed manifest — and both of those lived
 * in a footer link and a document. Every competitor *says* client-side; a
 * user could not tell the difference from inside the app. This is the
 * inspector's footer, expanded into three things the page can prove about
 * itself, here, without asking anyone.
 *
 * The standing rule, kept: every row is a **structural fact the page can
 * establish locally**, never live telemetry. A status light that could be
 * wrong is worse than none.
 *
 * - **The policy line is read, not typed.** `connect-src 'none'` is quoted
 *   from the page's own CSP meta tag as it was served. If the tag is missing
 *   or says something else — a development build — the status says *that*,
 *   and the dot is not green.
 * - **Offline is noticed, not claimed.** `navigator.onLine` is a fact about
 *   the browser; the page reports it and says the one true thing about it:
 *   nothing here ever needed a connection.
 * - **The in-place check reads the Cache API and nothing else.** The service
 *   worker holds a copy of this build and, as of this change, the build's
 *   manifest beside it; this hashes what the cache holds against that
 *   manifest. No request is made — none is allowed, and the check has to run
 *   inside the policy rather than around it. What it proves is that the set
 *   of files this page runs is the set its manifest names: *consistent*, not
 *   *honest*. A hostile host ships a consistent set too. The digest of the
 *   manifest is shown so the outside procedure — cosign, on a mirror — can be
 *   run against the same bytes; that is the bridge, and the verify page could
 *   never print it because baking the digest into the page is circular and
 *   fetching it is forbidden. Reading it back from the cache is neither.
 */

import { useEffect, useId, useState } from "react";
import { CheckCircle2, ChevronDown, Loader2, ShieldCheck, TriangleAlert, WifiOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const BASE_PATH = (process.env.KEYMAKER_BASE_PATH || "").replace(/\/$/, "");

/** The connect-src directive of this page's own policy, read from the served document. */
export function readConnectSrc(): string | null {
  const meta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
  const content = meta?.getAttribute("content") ?? "";
  return (
    content
      .split(";")
      .map((d) => d.trim())
      .find((d) => d.startsWith("connect-src")) ?? null
  );
}

export type VerifyOutcome =
  | { kind: "idle" }
  | { kind: "running" }
  | { kind: "ok"; checked: number; manifestDigest: string }
  | { kind: "mismatch"; checked: number; wrong: string[]; manifestDigest: string }
  | { kind: "unavailable"; reason: string };

async function sha256Hex(bytes: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Hash every file the service worker holds for this build against the
 * manifest it holds beside them. Cache API only — see the header.
 */
export async function verifyCachedBuild(): Promise<VerifyOutcome> {
  if (typeof caches === "undefined") {
    return {
      kind: "unavailable",
      reason: "This browser has no cache storage, so the page cannot read what it is running.",
    };
  }
  const keys = (await caches.keys()).filter((k) => k.startsWith("keymaker-"));
  if (keys.length === 0) {
    return {
      kind: "unavailable",
      reason: "The service worker has not finished caching this build yet. Try again in a moment.",
    };
  }
  const manifestPath = `${BASE_PATH}/SHA256SUMS`;
  let cache: Cache | null = null;
  let manifestText = "";
  for (const key of keys) {
    const candidate = await caches.open(key);
    const held = await candidate.match(manifestPath);
    if (held) {
      cache = candidate;
      manifestText = await held.text();
      break;
    }
  }
  if (!cache) {
    return {
      kind: "unavailable",
      reason:
        "This build's manifest is not in the cache, so the page cannot check itself. " +
        "Reload once while online.",
    };
  }
  const manifestDigest = await sha256Hex(
    new TextEncoder().encode(manifestText).buffer as ArrayBuffer
  );
  const entries: Array<[string, string]> = [];
  for (const line of manifestText.split("\n")) {
    const m = /^([a-f0-9]{64})\s\s(.+)$/.exec(line.trim());
    if (m) entries.push([m[2]!, m[1]!]);
  }
  if (entries.length === 0) {
    return { kind: "unavailable", reason: "The cached manifest is empty or unreadable." };
  }
  let checked = 0;
  const wrong: string[] = [];
  for (const [rel, expected] of entries) {
    // The app shell is cached under its URL, "/", and listed under its name.
    const url = rel === "index.html" ? `${BASE_PATH}/` : `${BASE_PATH}/${rel}`;
    const held = await cache.match(url);
    // Fetched on demand rather than held: nothing to compare, nothing to claim.
    if (!held) continue;
    const actual = await sha256Hex(await held.arrayBuffer());
    checked++;
    if (actual !== expected) wrong.push(rel);
  }
  if (checked === 0) {
    return {
      kind: "unavailable",
      reason: "None of the manifest's files are in the cache yet. Try again in a moment.",
    };
  }
  return wrong.length === 0
    ? { kind: "ok", checked, manifestDigest }
    : { kind: "mismatch", checked, wrong, manifestDigest };
}

export function SealedStatus({ writes }: { writes: number }) {
  const uid = useId();
  const panelId = `${uid}-panel`;
  const [open, setOpen] = useState(false);
  // null until mounted: the export is static HTML, and the server has no
  // network state to render.
  const [online, setOnline] = useState<boolean | null>(null);
  // undefined until read; null when the page carries no such directive.
  const [connectSrc, setConnectSrc] = useState<string | null | undefined>(undefined);
  const [verify, setVerify] = useState<VerifyOutcome>({ kind: "idle" });

  useEffect(() => {
    setConnectSrc(readConnectSrc());
    const update = () => setOnline(navigator.onLine);
    update();
    window.addEventListener("online", update);
    window.addEventListener("offline", update);
    return () => {
      window.removeEventListener("online", update);
      window.removeEventListener("offline", update);
    };
  }, []);

  const sealed = connectSrc === "connect-src 'none'";
  const offline = online === false;

  const runCheck = async () => {
    setVerify({ kind: "running" });
    try {
      setVerify(await verifyCachedBuild());
    } catch (e) {
      setVerify({
        kind: "unavailable",
        reason: `The check could not run: ${e instanceof Error ? e.message : String(e)}`,
      });
    }
  };

  const rowTitle = "text-[13px] font-medium text-foreground";
  const rowText = "mt-0.5 text-[12.5px] leading-relaxed text-muted-foreground";

  return (
    <>
      {/* The footer line, as before, with its first claim now a disclosure:
          what "runs in this tab" rests on is one click away. */}
      <footer className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-border px-4 py-2.5 font-mono text-[12px] text-subtle-foreground">
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
          aria-controls={panelId}
          data-testid="sealed-toggle"
          // U8: a standalone control in a 12px mono line is 18px tall, under
          // the 24px floor. py-1.5 takes it past; the negative margin keeps
          // the footer's own spacing where it was — the same idiom the app
          // footer's controls use.
          className="-my-1.5 flex cursor-pointer items-center gap-1.5 rounded-md py-1.5 text-subtle-foreground transition-colors hover:text-foreground focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-card"
        >
          <span
            className={cn(
              "inline-block h-1.5 w-1.5 rounded-full",
              // Green only once the directive has been read and says 'none'.
              // Until the read — the static HTML, before hydration — the dot
              // claims nothing and takes the muted tone; on a build that
              // carries no such rule it is the warning token. A light that
              // could be wrong is worse than none.
              connectSrc === undefined
                ? "bg-subtle-foreground"
                : sealed
                  ? "bg-success"
                  : "bg-warning"
            )}
            aria-hidden="true"
          />
          {connectSrc === undefined ? "" : sealed ? "sealed · " : "unsealed · "}runs in this tab
          <ChevronDown
            className={cn("h-3.5 w-3.5 transition-transform duration-200", open && "rotate-180")}
            aria-hidden="true"
          />
        </button>
        {/* "nothing leaves" rather than the old "nothing is uploaded": three
            characters shorter is what keeps this line to one row at the
            inspector's desktop width now that the first claim carries a
            disclosure, and it is the phrase the policy row above it proves. */}
        <span>nothing leaves</span>
        {offline && (
          <span data-testid="offline-notice" className="flex items-center gap-1.5 text-foreground">
            <WifiOff className="h-3.5 w-3.5" aria-hidden="true" />
            offline · still works
          </span>
        )}
        <span className="ml-auto">writes KEYM v{writes}</span>
      </footer>

      {open && (
        <section
          id={panelId}
          aria-label="What keeps this page sealed"
          data-testid="sealed-panel"
          className="animate-in fade-in-50 space-y-4 border-t border-border px-4 py-3"
        >
          {/* 1. The policy, quoted from the page as served. */}
          <div className="flex items-start gap-2.5">
            {sealed ? (
              <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-success" aria-hidden="true" />
            ) : (
              <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-warning" aria-hidden="true" />
            )}
            <div className="min-w-0">
              <p className={rowTitle}>
                {sealed ? "Forbidden to talk to any server" : "Not sealed — a development build"}
              </p>
              <p className={rowText}>
                {sealed ? (
                  <>
                    Not a promise: a rule the browser enforces before a request starts, for
                    every request to anywhere. The line that says so, read from this page as
                    it was served — not typed here:
                  </>
                ) : (
                  <>
                    The production export carries a rule that forbids every request, and the
                    build fails on purpose if it changes. This copy does not carry it, so it
                    is not that export.{" "}
                    {connectSrc === null ? "No policy line was found." : "It says:"}
                  </>
                )}
              </p>
              {connectSrc && (
                <code
                  data-testid="sealed-directive"
                  className="mt-1.5 inline-block rounded-md border border-border bg-inset px-1.5 py-0.5 font-mono text-[12px] text-foreground"
                >
                  {connectSrc}
                </code>
              )}
            </div>
          </div>

          {/* 2. Offline, noticed rather than claimed. */}
          <div className="flex items-start gap-2.5">
            <WifiOff
              className={cn("mt-0.5 h-3.5 w-3.5 shrink-0", offline ? "text-success" : "text-muted-foreground")}
              aria-hidden="true"
            />
            <div className="min-w-0">
              <p className={rowTitle}>{offline ? "Offline — and still working" : "Works with the network off"}</p>
              <p className={rowText} data-testid="offline-row">
                {offline ? (
                  <>
                    You are offline. Encrypting and decrypting work exactly as before, because
                    nothing here ever needed a connection — the whole app was cached the first
                    time it loaded.
                  </>
                ) : (
                  <>
                    Try it: switch your connection off. The footer will say so, and nothing else
                    changes — encrypting needs no server, and the whole app was cached the first
                    time it loaded.
                  </>
                )}
              </p>
            </div>
          </div>

          {/* 3. The in-place check. */}
          <div className="flex items-start gap-2.5">
            <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
            <div className="min-w-0 flex-1">
              <p className={rowTitle}>Check the files this page is running</p>
              <p className={rowText}>
                The build ships a signed manifest of every file. The service worker keeps a copy
                of this build and of that manifest, and this hashes the one against the other —
                no request is made, and none is allowed. It proves the set is <em>consistent</em>,
                not who made it: for that, run the commands on <em>Verify this build</em> against
                the digest it prints.
              </p>
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <Button
                  type="button"
                  variant="secondary"
                  size="sm"
                  onClick={() => void runCheck()}
                  disabled={verify.kind === "running"}
                  className="rounded-lg"
                >
                  {verify.kind === "running" ? (
                    <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                  ) : null}
                  {verify.kind === "running" ? "Hashing…" : "Check now"}
                </Button>
              </div>
              {verify.kind === "ok" && (
                <p
                  role="status"
                  data-testid="verify-result"
                  data-outcome="ok"
                  className="mt-2 rounded-lg border border-success/40 bg-success/10 px-3 py-2 text-[12px] leading-snug text-success"
                >
                  <CheckCircle2 className="mr-1.5 inline h-3.5 w-3.5 align-[-2px]" aria-hidden="true" />
                  {verify.checked} of {verify.checked} cached files match the manifest this build
                  shipped. Manifest sha256{" "}
                  <span className="break-all font-mono text-[12px]">{verify.manifestDigest}</span> —
                  the digest <em>Verify this build</em> should agree with.
                </p>
              )}
              {verify.kind === "mismatch" && (
                <p
                  role="alert"
                  data-testid="verify-result"
                  data-outcome="mismatch"
                  className="mt-2 rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-[12px] leading-snug text-destructive"
                >
                  <TriangleAlert className="mr-1.5 inline h-3.5 w-3.5 align-[-2px]" aria-hidden="true" />
                  {verify.wrong.length} of {verify.checked} cached files do not match the manifest:{" "}
                  <span className="break-all font-mono text-[12px]">{verify.wrong.join(", ")}</span>.
                  Do not trust this copy. Verify from a clean mirror before using it for anything.
                </p>
              )}
              {verify.kind === "unavailable" && (
                <p
                  role="status"
                  data-testid="verify-result"
                  data-outcome="unavailable"
                  className="mt-2 rounded-lg border border-border px-3 py-2 text-[12px] leading-snug text-muted-foreground"
                >
                  {verify.reason}
                </p>
              )}
            </div>
          </div>
        </section>
      )}
    </>
  );
}
