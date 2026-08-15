"use client";

/**
 * Roadmap 4.5 — the inheritance wizard.
 *
 * Composition of 4.1, 4.2 and 4.3, and nothing else: no new format, no new
 * crypto, no artefact that does not already have a Python counterpart and a
 * conformance gate. The orchestration lives in `keym-v2-inheritance.ts` so that
 * the package `crosstest2.py` verifies is built by the same function this
 * dialog calls — the alternative is two implementations of a package and a
 * guarantee that only one of them is tested.
 *
 * **What the wizard is actually for.** The three artefacts disagree about the
 * container. The backup file and the paper vault want the strongest settings
 * available; §7.2's page cannot have them, because WebCrypto has never had
 * Argon2id. Somebody has to decide, and doing it inside one guided flow with
 * the consequence written on the screen is better than leaving a user to
 * discover it by trying an export and being refused.
 *
 * **Everything is issued once.** The share set exists exactly once by §4.6 —
 * nothing can reissue it — so the results step is not a summary to be closed
 * and reopened. It says so, and it keeps the artefacts until the dialog is
 * dismissed deliberately.
 */

import { useState } from "react";
import { Loader2, Package, Printer, Download } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { encryptViaWorker } from "@/lib/crypto-client";
import type { CipherId, KdfParams } from "@/lib/keymaker-crypto";
import {
  buildInheritancePackage,
  inheritanceLetter,
  type InheritancePackage,
  type InheritancePlan,
} from "@/lib/keym-v2-inheritance";

const APP_VERSION = process.env.KEYMAKER_APP_VERSION || "unknown";

function download(data: BlobPart, filename: string, type: string) {
  const url = URL.createObjectURL(new Blob([data], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export interface InheritanceWizardProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** The secret being left. Supplied by the caller, never held here longer than the build. */
  plaintext: Uint8Array;
  password: string;
  kdf: KdfParams;
  cipher: CipherId;
  /** Fixed by the caller so a re-render cannot change what the letter says. */
  createdOn: string;
  onPrint: (pkg: InheritancePackage) => void;
}

export function InheritanceWizard({
  open,
  onOpenChange,
  plaintext,
  password,
  kdf,
  cipher,
  createdOn,
  onPrint,
}: InheritanceWizardProps) {
  const [threshold, setThreshold] = useState(2);
  const [count, setCount] = useState(3);
  const [includePage, setIncludePage] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pkg, setPkg] = useState<InheritancePackage | null>(null);

  const plan: InheritancePlan = {
    threshold,
    count,
    kdf,
    cipher,
    includePage,
    createdOn,
    appVersion: APP_VERSION,
  };

  async function build() {
    setBusy(true);
    setError(null);
    try {
      const built = await buildInheritancePackage(plaintext, password, plan, async (pt, pw, opts, shamir) => {
        const out = await encryptViaWorker(
          pt.buffer.slice(pt.byteOffset, pt.byteOffset + pt.byteLength) as ArrayBuffer,
          pw,
          null,
          opts,
          shamir
        );
        return { container: new Uint8Array(out.data), shares: out.shares };
      });
      setPkg(built);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-lg" data-testid="inheritance-wizard">
        {pkg === null ? (
          <>
            <DialogHeader>
              <DialogTitle>Prepare an inheritance package</DialogTitle>
              <DialogDescription>
                One box holding the backup, the slips that open it without a password,
                and a letter explaining both to somebody who has never heard of any of this.
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-4 py-2">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <Label htmlFor="inh-threshold" className="text-[12px] text-muted-foreground">
                    Slips needed to open it
                  </Label>
                  <Input
                    id="inh-threshold"
                    type="number"
                    min={2}
                    max={count}
                    value={threshold}
                    onChange={(e) => {
                      const n = Number(e.target.value);
                      if (Number.isFinite(n)) setThreshold(Math.min(Math.max(n, 2), count));
                    }}
                  />
                </div>
                <div className="space-y-1">
                  <Label htmlFor="inh-count" className="text-[12px] text-muted-foreground">
                    Slips to print
                  </Label>
                  <Input
                    id="inh-count"
                    type="number"
                    min={2}
                    max={16}
                    value={count}
                    onChange={(e) => {
                      const n = Number(e.target.value);
                      if (!Number.isFinite(n)) return;
                      const next = Math.min(Math.max(n, 2), 16);
                      setCount(next);
                      // The threshold can never exceed the count. Clamping here
                      // rather than validating later is what stops the pair
                      // becoming impossible while somebody is still typing.
                      setThreshold((t) => Math.min(t, next));
                    }}
                  />
                </div>
              </div>

              <p className="rounded-lg border border-amber-500/25 bg-amber-500/5 px-3 py-2 text-[12px] text-muted-foreground">
                Any <strong className="text-foreground">{threshold}</strong> of the {count} slips
                open this backup <em>without the password</em>. That makes each slip exactly as
                sensitive as the password itself — the letter says so, and they should not all
                live in one place.
              </p>

              <div className="flex items-start justify-between gap-3 rounded-lg border border-white/10 px-3 py-2">
                <div>
                  <Label htmlFor="inh-page" className="cursor-pointer text-sm text-foreground">
                    Include a self-extracting page
                  </Label>
                  <p className="mt-0.5 text-[12px] text-muted-foreground">
                    One <code>.html</code> that opens in any browser with no tools at all. It has
                    to use PBKDF2 rather than Argon2id, so it gets its own, weaker copy of the
                    backup — your main backup is not changed. Leave it off and nothing in the
                    package is weaker than what you chose.
                  </p>
                </div>
                <Switch id="inh-page" checked={includePage} onCheckedChange={setIncludePage} />
              </div>

              {error && (
                <p data-testid="inheritance-error" className="text-[12px] font-medium text-destructive">
                  {error}
                </p>
              )}

              <Button onClick={build} disabled={busy} className="w-full" data-testid="inheritance-build">
                {busy ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Package className="mr-2 h-4 w-4" />}
                {busy ? "Building — this runs the key derivation twice" : "Build the package"}
              </Button>
            </div>
          </>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle>Your package is ready</DialogTitle>
              <DialogDescription>
                Save all of it now. The {pkg.shares.length} slips exist exactly once — nothing,
                including this app, can reissue them.
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-2 py-2" data-testid="inheritance-results">
              <Button variant="outline" className="w-full justify-start" data-testid="inh-save-backup"
                onClick={() => download(new Uint8Array(pkg.container), "backup.keym", "application/octet-stream")}>
                <Download className="mr-2 h-4 w-4" /> The backup file — backup.keym
              </Button>
              <Button variant="outline" className="w-full justify-start" data-testid="inh-save-shares"
                onClick={() =>
                  download(
                    pkg.shares.map((s, i) => `# share ${i + 1} of ${pkg.shares.length}\n${s}`).join("\n") + "\n",
                    "shares.txt",
                    "text/plain"
                  )
                }>
                <Download className="mr-2 h-4 w-4" /> The {pkg.shares.length} recovery slips — shares.txt
              </Button>
              <Button variant="outline" className="w-full justify-start" data-testid="inh-save-letter"
                onClick={() => download(inheritanceLetter(pkg, plan), "LETTER.txt", "text/plain")}>
                <Download className="mr-2 h-4 w-4" /> The letter for whoever opens this — LETTER.txt
              </Button>
              {pkg.page && (
                <Button variant="outline" className="w-full justify-start" data-testid="inh-save-page"
                  onClick={() => download(pkg.page!.html, "backup.html", "text/html")}>
                  <Download className="mr-2 h-4 w-4" /> The self-extracting page — backup.html
                </Button>
              )}
              <Button variant="outline" className="w-full justify-start" data-testid="inh-print"
                onClick={() => onPrint(pkg)}>
                <Printer className="mr-2 h-4 w-4" /> Print the paper vault and the slips
              </Button>
            </div>

            <p className="text-[12px] text-muted-foreground">
              Keep the slips apart from the backup, and apart from each other. Anyone holding{" "}
              {pkg.threshold} of them needs nothing else from you.
            </p>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
