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
 * because this panel is where someone decides to set up an inheritance at all.
 * What it says follows the backup the form will actually write, read from the
 * same access policy the worker request is built from: by default any
 * `threshold` shares open the container without the password, so each share is
 * as sensitive as the password itself; with "The strips need the password too"
 * (§4.8) the shares open nothing alone, so the heirs need the password as well.
 * It used to say the first in both cases. Roadmap, "Honest framing to
 * preserve", and 9.1.
 */

import { ScrollText, X } from "lucide-react";
import { sharesOf, type AccessPolicy } from "@/lib/access-policy";

export function InheritancePlan({
  policy,
  onDismiss,
}: {
  policy: AccessPolicy;
  onDismiss: () => void;
}) {
  const shares = sharesOf(policy);
  const combined = policy.waysIn.find((w) => w.kind === "password-and-shares");
  const secret = combined?.keyFile ? "the password and the key file" : "the password";
  const them = combined?.keyFile ? "them" : "it";
  const lost = combined?.keyFile ? "Lose either" : "Lose it";
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
        {!shares ? (
          <>
            Recovery shares are off, so there is nothing yet for your heirs to
            hold. Turn recovery shares on in the form below.
          </>
        ) : combined ? (
          <>
            You keep your password. Your heirs hold recovery shares, but this
            backup is set so the shares open it only together with {secret}. It
            takes any {shares.threshold} of the {shares.count} shares and{" "}
            {secret}, all needed. Without {secret} the shares open nothing, so
            your heirs must also be able to get {them}, for example from a sealed
            letter kept apart from the shares. {lost} and the backup is lost.
          </>
        ) : (
          <>
            You keep your password. Your heirs hold recovery shares, and any{" "}
            {shares.threshold} of the {shares.count} shares open this backup on
            their own. Each share is as sensitive as the password itself, so give
            them to different people and keep them apart.
          </>
        )}
      </p>

      <ol className="list-decimal space-y-1.5 pl-5 text-[13px] leading-snug text-foreground/90">
        <li data-testid="inheritance-step">
          Put what you are leaving in the field below: a seed phrase, a file, or
          text such as account details and instructions.
        </li>
        <li data-testid="inheritance-step">
          {shares
            ? "Recovery shares are turned on. Set how many shares exist and how many are needed to open it, in the form below."
            : "Turn recovery shares on in the form below, then set how many shares exist and how many are needed to open it."}
        </li>
        <li data-testid="inheritance-step">
          Encrypt, and write the shares down once. They are shown a single time
          and cannot be reissued.
        </li>
        <li data-testid="inheritance-step">
          Print the paper vault: the container as QR symbols, and each share on
          its own strip to cut apart. The vault prints what was sealed as text;
          if you sealed a file instead, keep the downloaded <code>.keym</code>{" "}
          with the shares.
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
