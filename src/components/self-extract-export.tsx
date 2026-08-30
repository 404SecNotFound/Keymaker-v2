"use client";

/**
 * 4.3 — the self-extracting page export (`docs/FORMAT-V2-DESIGN.md` §7.2).
 *
 * One `.html` holding the container and a WebCrypto-only decryptor for it, for
 * the person who inherits a backup and not the toolchain that made it.
 *
 * The interesting part of this component is the branch where it *refuses*.
 * §7.2's subset is AES-256-GCM with a PBKDF2 passphrase slot, and the app's
 * recommended default is Argon2id — so most containers cannot become a page,
 * and the honest thing is to say which change would let them rather than to
 * hide the option from the majority of users.
 */

import { useMemo, useState } from "react";
import { FileDown } from "lucide-react";
import { dearmorKeym2 } from "@/lib/keym-v2";
import {
  buildSelfExtractingPage,
  webcryptoProfileViolations,
} from "@/lib/keym-v2-selfextract";

const APP_VERSION = process.env.KEYMAKER_APP_VERSION || "unknown";

function triggerDownload(text: string, filename: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/html" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export function SelfExtractExport({ armored }: { armored: string }) {
  const [done, setDone] = useState(false);

  // The container is parsed once per output, not per render: dearmoring a
  // multi-megabyte backup on every keystroke elsewhere in the form is the class
  // of cost 5.1 was about.
  const { container, reasons } = useMemo(() => {
    try {
      const bytes = dearmorKeym2(armored);
      return { container: bytes, reasons: webcryptoProfileViolations(bytes) };
    } catch {
      return { container: null, reasons: ["this is not a KEYM v2 container"] };
    }
  }, [armored]);

  if (reasons.length > 0 || !container) {
    return (
      <div
        data-testid="selfextract-unavailable"
        className="rounded-xl border border-border px-3 py-2 text-[12px] text-muted-foreground"
      >
        <p className="font-medium text-foreground/80">
          A self-extracting page is not available for this backup
        </p>
        <ul className="mt-1 list-disc space-y-0.5 pl-4">
          {reasons.map((r) => (
            <li key={r}>{r}</li>
          ))}
        </ul>
        <p className="mt-1.5">
          The page can only use what a browser has built in for ever, which means
          AES-256-GCM and PBKDF2. Choose those before encrypting if you want one —
          and read it as the trade it is: easier to open in twenty years, weaker
          against someone who copies the file today.
        </p>
      </div>
    );
  }

  return (
    <button
      type="button"
      data-testid="selfextract-download"
      onClick={() => {
        triggerDownload(
          buildSelfExtractingPage({
            container,
            createdOn: new Date().toISOString().slice(0, 10),
            appVersion: APP_VERSION,
          }),
          "keymaker-backup.html"
        );
        setDone(true);
      }}
      className="flex w-full cursor-pointer items-center justify-center gap-1.5 rounded-xl border border-border px-3 py-2 text-[12px] text-muted-foreground transition-colors hover:border-border-strong hover:text-foreground"
    >
      <FileDown className="h-3.5 w-3.5" />
      {done
        ? "Saved — one file that opens itself in any browser"
        : "Save a self-extracting page — one .html an heir can open with no tools"}
    </button>
  );
}
