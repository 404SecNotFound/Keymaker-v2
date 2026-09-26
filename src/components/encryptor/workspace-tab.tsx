"use client";

/**
 * The Workspace landing page: the hero, and the three doors plus "Prepare
 * recovery". Moved verbatim out of `encryptor-tool.tsx`'s
 * `TabsContent value="workspace"` block.
 */
import { LifeBuoy } from "lucide-react";
import { TabsContent } from "@/components/ui/tabs";
import { BASE_PATH, DOORS } from "./shared";
import { useEncryptorContext } from "./context";

export function WorkspaceTab() {
  const { openDoor, setWorkspacePage } = useEncryptorContext();

  return (
    <TabsContent value="workspace" className="mt-0" tabIndex={-1}>
      <div className="km-home-hero">
        <div className="km-home-intro">
          <h2>Your files. Your keys.</h2>
          <p>No account or upload is needed. Keymaker does not keep a library of your backups — save each encrypted container somewhere you control.</p>
        </div>
        {/*
          Illustration plate, not a marketing hero: framed like a panel,
          beside the copy and never behind it, so no text sits on an image
          and the contrast gates keep measuring text on solid grounds.
          Same-origin and precached like every other asset (sw.js).
        */}
        <figure className="km-art km-art-home">
          <img src={`${BASE_PATH}/art-cipher-field.webp`} alt="A field of encrypted glyph blocks converging on a keyhole cut from dark metal" width={1400} height={788} decoding="async" />
        </figure>
      </div>
      <div className="km-task-list">
        {DOORS.map(({ id, icon: Icon, title, blurb }) => (
          <button key={id} type="button" onClick={() => openDoor(id)} className="km-task">
            <Icon className="h-4 w-4" aria-hidden="true" />
            <span><strong>{title}</strong><span>{blurb}</span></span>
            <span className="km-task-arrow" aria-hidden="true">→</span>
          </button>
        ))}
        <button type="button" onClick={() => setWorkspacePage("recovery")} className="km-task">
          <LifeBuoy className="h-4 w-4" aria-hidden="true" />
          <span><strong>Prepare recovery</strong><span>Print a backup, manage shares, and verify a way back in.</span></span>
          <span className="km-task-arrow" aria-hidden="true">→</span>
        </button>
      </div>
    </TabsContent>
  );
}
