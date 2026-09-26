"use client";

/**
 * The "Save these shares now" dialog: shown once, right after a share set is
 * issued, with the print/rehearse actions that follow from it. Moved
 * verbatim out of `encryptor-tool.tsx`'s `issuedShares` Dialog.
 */
import {
  ShieldAlert,
  Copy,
  Printer,
  Timer,
  Loader2,
  Unlock,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { loadKeym2 } from "@/lib/keymaker-crypto";
import { LockWarning } from "./shared-ui";
import { preparePaperParts } from "./shared";
import { useEncryptorContext } from "./context";

export function SharesDialog() {
  const {
    issuedShares, setIssuedShares, setRehearsalOpen, setRehearsalInput,
    setRehearsalPassword, setRehearsalInputRejected, lockSecondsLeft,
    keepOpen, backupFitsOnStrip, stripsCarryBackup, setStripsCarryBackup,
    handleCopy, outputText, toast, setPaperVault, rehearsalStamp,
    rehearsalOpen, rehearsalInput, handleRehearsalInputChange,
    rehearsalInputRejected, rehearsalPassword, rehearsal, rehearsalLines,
    runRehearsal,
  } = useEncryptorContext();

  return (
      <Dialog
        open={issuedShares !== null}
        onOpenChange={(open) => {
          if (!open) {
            setIssuedShares(null);
            // The rehearsal box held k strips — the password, in effect —
            // and it unmounts with the dialog; the state behind it must not
            // outlive it. The outcome stays: it is ink for the next print,
            // and the encrypt-side Print button is still on the page.
            setRehearsalOpen(false);
            setRehearsalInput("");
            setRehearsalPassword("");
            setRehearsalInputRejected(null);
          }
        }}
      >
        {/*
          Closing this dialog destroys the only copy of the shares, so it closes
          only when someone means it: the X or the button at the bottom. Escape
          and a click on the backdrop are the two gestures people make without
          deciding anything (dismissing a toast, reaching for another window),
          and each of them used to turn a share set into scrap.
        */}
        <DialogContent
          // Scrolls rather than overflowing: eight share strings plus the
          // rehearsal panel are taller than a phone, and the dialog is fixed
          // and centred, so without this its lower half was off-screen with no
          // way to reach it.
          className="max-h-[90dvh] max-w-lg overflow-y-auto"
          onEscapeKeyDown={(e) => e.preventDefault()}
          onInteractOutside={(e) => e.preventDefault()}
        >
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-warning" />
              Save these {issuedShares?.shares.length} shares now
            </DialogTitle>
            <DialogDescription>
              {issuedShares?.withPassword ? (
                <>
                  Any {issuedShares?.threshold} of them open this container together with the
                  password, and only with it.
                </>
              ) : (
                <>
                  Any {issuedShares?.threshold} of them open this container without the
                  password.
                </>
              )}{" "}
              They are shown once and cannot be reissued. Closing this window loses them.
            </DialogDescription>
          </DialogHeader>

          {/*
            The lock warning, again, inside the dialog.

            Not belt and braces: the page's copy is unreachable from here. Radix
            hides the rest of the document from assistive technology and covers
            it with an overlay, so on the one screen whose contents cannot be
            regenerated, the countdown was invisible and the Keep open button
            could not be clicked. Transcribing shares onto paper is minutes of
            no pointer or key events, which is exactly what the idle timer
            measures.
          */}
          {lockSecondsLeft !== null && (
            <LockWarning secondsLeft={lockSecondsLeft} onKeepOpen={keepOpen} />
          )}

          <div className="space-y-2">
            {issuedShares?.shares.map((share, i) => (
              <div key={share} className="rounded-lg border border-border bg-inset p-2.5">
                <p className="mb-1 text-[12px] text-muted-foreground">
                  Share {i + 1} of {issuedShares.shares.length}
                </p>
                <p className="break-all font-mono text-[12px] leading-relaxed text-foreground">
                  {share}
                </p>
              </div>
            ))}
          </div>

          {issuedShares?.withPassword ? (
            <p className="rounded-md bg-warning/10 px-3 py-2 text-[12px] leading-snug text-warning">
              Keep the strips apart from each other and from the password. Anyone
              holding {issuedShares.threshold} of them, the password and a copy of the
              backup opens it. With fewer strips, or without the password, nobody
              does, you included.
            </p>
          ) : (
            <p className="rounded-md bg-warning/10 px-3 py-2 text-[12px] leading-snug text-warning">
              Each share is as sensitive as your password. Store them in separate
              places, with people who would not casually combine them. Anyone
              holding {issuedShares?.threshold} of them and a copy of the backup
              needs nothing else from you.
            </p>
          )}

          {/*
            Self-contained strips. Offered only when the backup fits one
            printed symbol (§7.3 "Symbol size"), and off by default, because
            it removes the one thing strip holders otherwise still need from
            the owner: the backup itself. Both halves of that are on screen.
          */}
          {backupFitsOnStrip && issuedShares ? (
            <div className="space-y-2 rounded-lg border border-border p-3" data-testid="strips-carry-backup">
              <div className="flex items-center gap-3">
                <Switch
                  id="strips-carry-backup"
                  checked={stripsCarryBackup}
                  onCheckedChange={setStripsCarryBackup}
                />
                <Label htmlFor="strips-carry-backup" className="cursor-pointer text-sm text-foreground">
                  Put the whole backup on every strip
                </Label>
              </div>
              <p className="text-[12px] leading-snug text-muted-foreground">
                This backup is small enough to print on each strip. Then any{" "}
                {issuedShares.threshold} strips{issuedShares.withPassword ? " and the password" : ""} open it,
                with no sheet and no file from you. That is also the cost:{" "}
                {issuedShares.threshold} holders who get together
                {issuedShares.withPassword ? " and have the password" : ""} need nothing else. Leave
                this off to keep the backup itself with you.
              </p>
            </div>
          ) : null}

          <div className="flex flex-wrap gap-2">
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() =>
                handleCopy(
                  (issuedShares?.shares ?? [])
                    .map((s, i) => `# share ${i + 1} of ${issuedShares?.shares.length}\n${s}`)
                    .join("\n")
                )
              }
              className="text-muted-foreground hover:text-foreground"
            >
              <Copy className="mr-2 h-3.5 w-3.5" />
              Copy all
            </Button>
            {/*
              4.2. Was `window.print()` against this dark dialog, which produced
              a screenshot of a modal rather than a backup. Now it renders the
              paper vault sheet — the container as scannable symbols, the shares
              on cut-apart slips, and the procedure to open them without this
              app — and prints that instead.
            */}
            <Button
              type="button"
              variant="ghost"
              size="sm"
              // Gated on the container being here, the same way the encrypt-side
              // copy of this button is. `outputText` is only written on the
              // *text* branch; encrypting a file downloads the container and
              // leaves it empty. Ungated, this called dearmorKeym2('') — which
              // fails its prefix check and throws — inside an async handler with
              // no catch. So on the commonest path to this dialog, encrypting a
              // file with shares, the button did nothing at all: no print, no
              // error, no toast. Twice, and then the user closes the dialog to
              // retry and the shares are gone.
              disabled={!outputText.startsWith("keym2:")}
              onClick={async () => {
                if (!issuedShares || !outputText.startsWith("keym2:")) return;
                try {
                  const { dearmorKeym2 } = await loadKeym2();
                  const container = dearmorKeym2(outputText);
                  const { parts, tooLarge, setCodes } = await preparePaperParts(container);
                  setPaperVault({
                    container,
                    parts,
                    tooLarge,
                    setCodes,
                    // Only a one-symbol backup can ride on a strip; the switch
                    // is not offered otherwise, and this re-checks rather than
                    // trusting that.
                    stripBackupPart: stripsCarryBackup && parts.length === 1 ? parts[0] : undefined,
                    shares: issuedShares.shares,
                    threshold: issuedShares.threshold,
                    sharesNeedPassword: issuedShares.withPassword ?? false,
                    printedOn: new Date().toISOString().slice(0, 10),
                    rehearsal: rehearsalStamp,
                  });
                } catch {
                  // Belt and braces behind the gate above. An unhandled
                  // rejection here is indistinguishable from a dead button, and
                  // the one thing this dialog must never be is silent.
                  toast({
                    title: "Could not build the paper vault",
                    description:
                      "The container could not be read back. Copy the shares from this " +
                      "window before closing it — they are not shown again.",
                    variant: "destructive",
                  });
                }
              }}
              className="text-muted-foreground hover:text-foreground"
            >
              <Printer className="mr-2 h-3.5 w-3.5" />
              Print paper vault
            </Button>
            {/*
              The rehearsal, opened here and nowhere else for now: the strips
              are on screen exactly once, and this is the moment to find out
              whether they work. Gated like the print button, and for the
              same reason — a file container is not here to open.
            */}
            <Button
              type="button"
              variant="ghost"
              size="sm"
              disabled={!outputText.startsWith("keym2:")}
              aria-expanded={rehearsalOpen}
              aria-controls="rehearsal-panel"
              onClick={() => setRehearsalOpen((v) => !v)}
              className="text-muted-foreground hover:text-foreground"
            >
              <Timer className="mr-2 h-3.5 w-3.5" />
              Rehearse now
            </Button>
            {!outputText.startsWith("keym2:") && (
              <p className="w-full text-[12px] leading-snug text-muted-foreground">
                The paper vault prints the container beside the shares, and a file
                container is downloaded rather than kept on screen — so it is not
                here to print, or to rehearse with. Copy these shares now; to print
                a paper vault or rehearse instead, encrypt in Text mode.
              </p>
            )}
          </div>

          {rehearsalOpen && (
            <section
              id="rehearsal-panel"
              aria-labelledby="rehearsal-title"
              data-testid="rehearsal"
              className="animate-in fade-in-50 space-y-2.5 rounded-xl border border-border p-3"
            >
              <h3 id="rehearsal-title" className="text-[13px] font-medium text-foreground">
                Rehearse the recovery
              </h3>
              <p className="text-[12px] leading-snug text-muted-foreground">
                Do what an heir would do: pick any {issuedShares?.threshold} of the{" "}
                {issuedShares?.shares.length} strips above and paste them here, one per
                line.{" "}
                {issuedShares?.withPassword
                  ? "The backup is opened with them and the password, and closed again without showing anything."
                  : "The backup is opened with them alone — no password — and closed again without showing anything."}
              </p>
              {issuedShares?.withPassword ? (
                <Input
                  id="rehearsal-password"
                  type="password"
                  autoComplete="off"
                  value={rehearsalPassword}
                  onChange={(e) => setRehearsalPassword(e.target.value)}
                  placeholder="The password, typed again"
                  aria-label="Password to rehearse with"
                  className="h-10 rounded-xl border-border bg-inset"
                />
              ) : null}
              <Textarea
                id="rehearsal-input"
                value={rehearsalInput}
                onChange={(e) => handleRehearsalInputChange(e.target.value)}
                placeholder={"KMSHARE2:...\nKMSHARE2:...\nOne strip per line"}
                rows={3}
                spellCheck={false}
                autoCorrect="off"
                autoCapitalize="off"
                aria-label="Strips to rehearse with"
                aria-describedby={
                  [
                    "rehearsal-count",
                    rehearsalInputRejected ? "rehearsal-size-error" : null,
                  ]
                    .filter(Boolean)
                    .join(" ")
                }
                aria-invalid={rehearsalInputRejected ? true : undefined}
                className="min-h-[72px] rounded-xl border-border bg-inset font-mono text-[12px]"
              />
              {rehearsalInputRejected && (
                <p
                  id="rehearsal-size-error"
                  role="alert"
                  className="text-[12px] leading-snug text-destructive"
                >
                  {rehearsalInputRejected} Nothing was pasted, so what you already had is
                  still there.
                </p>
              )}
              <div className="flex flex-wrap items-center gap-2">
                <Button
                  type="button"
                  variant="secondary"
                  size="sm"
                  onClick={() => void runRehearsal()}
                  disabled={
                    rehearsal.kind === "running" ||
                    rehearsalLines.length < (issuedShares?.threshold ?? 1)
                  }
                  className="rounded-lg"
                >
                  {rehearsal.kind === "running" ? (
                    <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Unlock className="mr-2 h-3.5 w-3.5" />
                  )}
                  {rehearsal.kind === "running" ? "Opening…" : "Open with these strips"}
                </Button>
                <p id="rehearsal-count" role="status" className="text-[12px] text-muted-foreground">
                  {rehearsalLines.length} of {issuedShares?.threshold} strips pasted
                </p>
              </div>
              {rehearsal.kind === "ok" && (
                <p
                  role="status"
                  data-testid="rehearsal-result"
                  className="flex items-start gap-2 rounded-lg border border-success/40 bg-success/10 px-3 py-2 text-[12px] leading-snug text-success"
                >
                  <ShieldCheck className="mt-px h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                  <span>
                    {/* A share unlock is HKDF, not a KDF: often under a tenth
                        of a second, which "0.0 s" reports as nothing at all. */}
                    Opened in {rehearsal.seconds < 1 ? "under a second" : `${rehearsal.seconds.toFixed(1)} s`} with{" "}
                    {rehearsal.strips.length > 0
                      ? `strips ${rehearsal.strips.length === 1 ? rehearsal.strips[0] : `${rehearsal.strips.slice(0, -1).join(", ")} and ${rehearsal.strips[rehearsal.strips.length - 1]}`}`
                      : "the strips pasted"}{" "}
                    — {rehearsal.bytes.toLocaleString("en-US")} bytes, kept hidden. The next
                    paper vault records this as a rehearsal.
                  </span>
                </p>
              )}
              {rehearsal.kind === "failed" && (
                <p
                  role="alert"
                  data-testid="rehearsal-result"
                  className="flex items-start gap-2 rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-[12px] leading-snug text-destructive"
                >
                  <TriangleAlert className="mt-px h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                  <span>{rehearsal.message}</span>
                </p>
              )}
            </section>
          )}

          <div className="flex justify-end">
            <DialogClose asChild>
              <Button type="button" variant="outline" size="sm">
                I have saved these shares
              </Button>
            </DialogClose>
          </div>
        </DialogContent>
      </Dialog>
  );
}
