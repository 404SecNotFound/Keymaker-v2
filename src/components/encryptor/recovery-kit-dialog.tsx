"use client";

/**
 * The recovery kit dialog: the standalone files an heir needs when this
 * website is gone. Moved verbatim out of `encryptor-tool.tsx`'s
 * `isRecoveryOpen` Dialog.
 */
import { LifeBuoy, Download } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { KEYM2_VERSION } from "@/lib/keym-v2";
import { BASE_PATH } from "./shared";
import { useEncryptorContext } from "./context";

export function RecoveryKitDialog() {
  const { isRecoveryOpen, setIsRecoveryOpen } = useEncryptorContext();

  return (
    <Dialog open={isRecoveryOpen} onOpenChange={setIsRecoveryOpen}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <LifeBuoy className="h-4 w-4 text-muted-foreground" />
            Recovery kit
          </DialogTitle>
          <DialogDescription>
            A <code className="rounded bg-inset px-1 py-0.5 text-[12px]">.keym</code> file
            does not need this website. Save these next to your backups.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-2.5">
          {/*
            keym2.py first, because it is the one that opens what this app
            writes. The kit used to offer keym.py alone, and keym.py reads
            KEYM v1 only: an heir who saved the kit exactly as offered held a
            script that refuses every backup made since v2.
          */}
          {[
            {
              href: `${BASE_PATH}/recovery/keym2.py`,
              name: 'keym2.py',
              what: `The standalone Python decryptor for KEYM v2 and v3, which covers every backup this app writes (it writes KEYM v${KEYM2_VERSION}). Opens password, key-file and recovery-share containers; no browser, no npm, no network.`,
            },
            {
              href: `${BASE_PATH}/recovery/requirements.txt`,
              name: 'requirements.txt',
              what: 'The two libraries the scripts need, pinned. RECOVERY.md shows how to download them now so the install works offline later.',
            },
            {
              href: `${BASE_PATH}/recovery/RECOVERY.md`,
              name: 'RECOVERY.md',
              what: 'The procedure in writing, including how to decrypt by hand if even the script is gone. Worth printing and storing with the backup.',
            },
            {
              href: `${BASE_PATH}/recovery/keym.py`,
              name: 'keym.py',
              what: 'Only for older KEYM v1 backups. It refuses v2 and v3 containers; use keym2.py for those.',
            },
          ].map((item) => (
            <div
              key={item.name}
              className="rounded-xl border border-border p-3"
            >
              <div className="flex items-center justify-between gap-3">
                <span className="font-mono text-[13px] font-medium">{item.name}</span>
                <a
                  href={item.href}
                  download
                  className="shrink-0 rounded-lg border border-border px-2.5 py-1 text-[12px] font-medium text-muted-foreground transition-colors hover:border-border-strong hover:text-foreground"
                >
                  <Download className="mr-1 inline h-3.5 w-3.5 align-[-2px]" />
                  Save
                </a>
              </div>
              <p className="mt-1.5 text-[12px] leading-snug text-muted-foreground">{item.what}</p>
            </div>
          ))}
        </div>

        <p className="text-[12px] leading-snug text-muted-foreground">
          These are the same files as in the repository, copied into this build — so
          the copy you save is the one that matches the version that encrypted your
          data. The format itself is specified in{' '}
          <code className="rounded bg-inset px-1 py-0.5">docs/FORMAT-V2-DESIGN.md</code> in
          the repository, and{' '}
          <code className="rounded bg-inset px-1 py-0.5">keym2.py</code> was written
          from that document independently of the code running here, which is how
          specification bugs got caught before they shipped.
        </p>
      </DialogContent>
    </Dialog>
  );
}
