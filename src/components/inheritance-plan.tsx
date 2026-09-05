"use client";

/**
 * Roadmap 4.5, the inheritance wizard.
 *
 * This is a "pure composition": it adds no cryptography and no wire format. It
 * is guidance, entered on purpose, that frames one intent the three doors do not
 * name on their own (leaving a backup someone can open after you), and orders
 * the steps that carry it out. Every step it lists drives a control that already
 * exists on the encrypt form: recovery shares (§4.6), the paper vault (§7.1),
 * the self-extracting page (§7.2) and the recovery kit. It renders nothing the
 * user acts on; it tells them, in order, which of those to use.
 *
 * The honest framing is stated here and not only where the shares are set,
 * because this panel is where someone decides to set up an inheritance at all:
 * any `threshold` shares open the container without the password, so each share
 * is as sensitive as the password itself. Roadmap, "Honest framing to preserve".
 */

import { ScrollText, X } from "lucide-react";

export function InheritancePlan({
  threshold,
  count,
  onDismiss,
}: {
  threshold: number;
  count: number;
  onDismiss: () => void;
}) {
  return (
    <section
      data-testid="inheritance-plan"
      aria-label="Inheritance plan"
      className="mb-5 space-y-3 rounded-xl border border-border-strong bg-inset p-4"
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2">
          <ScrollText className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
          <h3 className="text-sm font-medium text-foreground">Inheritance plan</h3>
        </div>
        <button
          type="button"
          onClick={onDismiss}
          aria-label="Hide the inheritance plan"
          className="cursor-pointer rounded-md p-1 text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
        >
          <X className="h-3.5 w-3.5" aria-hidden="true" />
        </button>
      </div>

      <p className="text-[13px] leading-snug text-muted-foreground">
        A backup someone can open after you, without you handing over your
        password today.
      </p>

      <p
        data-testid="inheritance-warning"
        className="rounded-md bg-warning/10 px-3 py-2 text-[12px] leading-snug text-warning"
      >
        You keep your password. Your heirs hold recovery shares, and any{" "}
        {threshold} of the {count} shares open this backup on their own. Each
        share is as sensitive as the password itself, so give them to different
        people and keep them apart.
      </p>

      <ol className="list-decimal space-y-1.5 pl-5 text-[13px] leading-snug text-foreground/90">
        <li data-testid="inheritance-step">
          Put what you are leaving in the field below: a seed phrase, a file, or
          text such as account details and instructions.
        </li>
        <li data-testid="inheritance-step">
          Recovery shares are already turned on. Set how many shares exist and
          how many are needed to open it, in the form below.
        </li>
        <li data-testid="inheritance-step">
          Encrypt, and write the shares down once. They are shown a single time
          and cannot be reissued.
        </li>
        <li data-testid="inheritance-step">
          Print the paper vault for the container, and put each share on its own
          sheet.
        </li>
        <li data-testid="inheritance-step">
          Keep the recovery kit, <code>keym2.py</code> and{" "}
          <code>RECOVERY.md</code>, with the shares, so an heir can open the
          backup with no website and no account.
        </li>
      </ol>

      <p className="text-[12px] leading-snug text-muted-foreground">
        None of this reaches a server. You are assembling paper and files to hand
        on. The recovery kit is the link in the footer below.
      </p>
    </section>
  );
}
