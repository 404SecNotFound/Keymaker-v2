"use client";

/**
 * Presentational components shared by more than one Encryptor tab module.
 * Each one is a leaf: props in, JSX out, no access to the tool's own state.
 *
 * Moved verbatim out of `encryptor-tool.tsx` as part of the module split —
 * see `shared.ts`'s header for why. Behaviour is unchanged.
 */
import { type ChangeEvent, type DragEvent, type ReactNode, type RefObject, useCallback, useRef, useState } from "react";
import { QRCodeCanvas } from "qrcode.react";
import { TriangleAlert, X, Eye, EyeOff, Download, QrCode, Info, Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { OFFSCREEN_STYLE, formatBytes } from "./shared";

/**
 * The imminent-lock warning, and the control that answers it.
 *
 * A component rather than JSX written once, because it has to render in two
 * places. Radix marks everything outside an open dialog `aria-hidden` and
 * covers it with an overlay, so while a dialog is up the page's copy of this
 * banner is neither clickable nor announced — a `role="alert"` inside an
 * aria-hidden subtree reaches nobody.
 *
 * That turned the one screen showing secrets which exist exactly once into the
 * one screen where the warning could not be acted on. Freshly issued shares are
 * read slowly onto paper, reading is not activity, and `lastActivityRef` only
 * moves on pointer and key events — so the five-minute lock fires mid
 * transcription and the Keep open button is behind the overlay.
 */
export function LockWarning({
  secondsLeft,
  onKeepOpen,
}: {
  secondsLeft: number;
  onKeepOpen: () => void;
}) {
  // The visible count ticks every second; the announcement does not. A live
  // region around the whole banner re-read "Locking in 29s", "28s", ... thirty
  // times over, which buries the one thing a screen-reader user needs from
  // it: that there is a Keep open button. So the live text changes twice,
  // when the warning appears and at ten seconds.
  const announcement =
    secondsLeft > 10
      ? "Nothing has been touched for a while. Secrets will be cleared in 30 seconds unless you choose Keep open."
      : "Secrets will be cleared in 10 seconds unless you choose Keep open.";
  return (
    <div
      className="flex items-center justify-between gap-3 rounded-xl border border-warning/40 bg-warning/10 px-3 py-2 text-[12px]"
    >
      <span role="alert" className="sr-only" data-testid="lock-announcement">
        {announcement}
      </span>
      <span className="flex min-w-0 items-center gap-1.5 text-warning">
        <TriangleAlert className="h-3.5 w-3.5 shrink-0" />
        <span className="truncate">
          Locking in <span className="tabular-nums font-medium">{secondsLeft}s</span> — secrets will be cleared
        </span>
      </span>
      <button
        type="button"
        onClick={onKeepOpen}
        className="shrink-0 cursor-pointer rounded-lg border border-warning/40 px-2.5 py-1 font-medium text-warning transition-colors hover:bg-warning/15"
      >
        Keep open
      </button>
    </div>
  );
}

interface FileSelectorProps {
  id: string;
  onFileChange: (event: ChangeEvent<HTMLInputElement> | DragEvent<HTMLDivElement>) => void;
  onClear: () => void;
  selectedFile: File | null;
  icon: React.ReactNode;
  label: string;
  description: string;
}

// Not memoized: callers pass fresh inline callbacks/icon each render, so
// React.memo could never bail out — it would only add a comparison cost.
export const FileSelector = ({
  id,
  onFileChange,
  onClear,
  selectedFile,
  icon,
  label,
  description,
}: FileSelectorProps) => {
  const inputRef = useRef<HTMLInputElement>(null);
  const [isDragging, setIsDragging] = useState(false);
  // U22. A drop that carried no files was swallowed: the dashed border lit up,
  // then went dark, and nothing happened. Indistinguishable from a bug in the
  // page — dragging a selection out of a text editor, or a folder, both land
  // here.
  //
  // An inline notice rather than a toast, for the reason the U4 gate records:
  // a toast is gone in a second, leaving someone staring at a dropzone that
  // quietly did not take what they dropped.
  const [dropRejected, setDropRejected] = useState<string | null>(null);

  const handleContainerClick = useCallback(() => {
    inputRef.current?.click();
  }, []);

  const handleDragEnter = useCallback((e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  }, []);

  const handleDragOver = useCallback((e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
  }, []);

  const handleDrop = useCallback((e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      setDropRejected(null);
      onFileChange(e);
      return;
    }
    // A directory drop reports zero files in every browser here, so the two
    // cases are named together rather than guessed apart — claiming "that was
    // a folder" about a dragged text selection would be worse than vague.
    setDropRejected(
      e.dataTransfer.items && e.dataTransfer.items.length > 0
        ? "That drop carried no file — a folder or a text selection, most likely. Drop a single file, or click to browse."
        : "Nothing was dropped. Drop a file, or click to browse."
    );
  }, [onFileChange]);


  return (
    <div>
      {selectedFile ? (
        <div className="km-selected-file" data-testid="selected-file" onDrop={handleDrop} onDragOver={handleDragOver}>
          <span className="km-file-icon">{icon}</span>
          <div className="km-file-name"><span title={selectedFile.name}>{selectedFile.name}</span><small>{formatBytes(selectedFile.size)}</small></div>
          <Button type="button" variant="ghost" size="sm" className="km-action" onClick={handleContainerClick}>Replace</Button>
          <Button type="button" variant="ghost" size="icon" onClick={onClear} aria-label="Remove file"><X className="h-4 w-4" /></Button>
        </div>
      ) : (
      <div
        className={cn(
          // Three states that have to read as three: resting is the plain
          // hairline, hover firms it, and a drag in flight firms it *and*
          // fills. The mechanical token mapping had all three landing on
          // border-strong, which left the hover and drag affordances
          // invisible on the one control the whole encrypt flow starts at.
          "km-dropzone relative flex w-full cursor-pointer flex-col items-center justify-center rounded-xl border border-dashed border-border px-6 py-10 text-center transition-all duration-200 hover:border-border-strong hover:bg-inset",
          { 'border-border-strong bg-inset': isDragging }
        )}
        onClick={handleContainerClick}
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragEnter={handleDragEnter}
        onDragLeave={handleDragLeave}
        data-dragging={isDragging}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          // U18. `role="button"` promises Space activates it as well as Enter —
          // that is what a native button does and what a keyboard user will
          // try. Space also scrolls the page by default while this has focus,
          // so preventing it is part of the fix rather than a flourish:
          // otherwise it opens the picker *and* jumps the view.
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            handleContainerClick();
          }
        }}
      >
        <div className="km-upload-icon mb-3 grid h-12 w-12 place-items-center rounded-xl border border-border bg-inset">
          {icon}
        </div>
        <div className="w-full overflow-hidden">
          {/*
            U18. The only headings on the page are the hero h1 and this one, so
            h3 skipped a level — a screen-reader user navigating by heading
            hears a gap and reasonably assumes they have missed something.
            Visual weight is set by the class, not the tag, so this changes
            nothing on screen.
          */}
          <p className="km-upload-label text-[14px] font-medium">{label}</p>
          <p className={cn(
            "mt-1 w-full overflow-hidden truncate text-[13px]",
            selectedFile ? "font-medium text-foreground" : "text-muted-foreground"
          )}>
            {description}
          </p>
        </div>
      </div>
      )}
      {dropRejected && (
        <p role="status" className="mt-2 text-[12px] leading-snug text-warning">
          {dropRejected}
        </p>
      )}
      <Input
        id={id}
        ref={inputRef}
        type="file"
        className="hidden"
        onChange={(e) => {
          // Clear the drop notice once a file arrives by any route, or it
          // outlives the problem it describes.
          setDropRejected(null);
          onFileChange(e);
        }}
      />
    </div>
  );
};
FileSelector.displayName = "FileSelector";

// Blurred-by-default QR with a reveal gate and PNG download, shared by the
// decrypted-secret modal's seed and plain-text branches so the reveal/blur
// security behavior has a single source of truth.
//
// Security-relevant invariants (must not regress):
//  - The live QR canvas is only MOUNTED while revealed. A CSS blur alone
//    would leave the sharp QR in the DOM (devtools, extensions,
//    canvas.toDataURL). While hidden, only a neutral placeholder renders.
//  - `getValue` is invoked only inside the revealed branch, so the encoded
//    secret is never computed (or held) while the QR is hidden.
//  - Download is disabled until revealed.
interface RevealableQrProps {
  getValue: () => string;
  revealed: boolean;
  onToggleReveal: () => void;
  onDownload: () => void;
  // Nullable element type: React 19's `useRef<T>(null)` yields
  // RefObject<T | null>. Written this way it type-checks under both the
  // React 18 and 19 type definitions.
  hiResRef: RefObject<HTMLDivElement | null>;
  warning: string;
  caption?: ReactNode;
  /**
   * U28. Optional, and only the SeedQR branch supplies it.
   *
   * A Standard SeedQR *is* a digit string, and an air-gapped workflow often
   * cannot scan — the device holding the seed is the one with no camera, which
   * is rather the point of it being air-gapped. Without this the only routes
   * off the screen are photographing a QR code or reading 48 digits aloud.
   *
   * Gated on `revealed` for the same reason Download is: it invokes
   * `getValue`, and the invariant above is that the encoded secret is never
   * computed while the QR is hidden.
   */
  onCopyDigits?: (() => void) | undefined;
}

export function RevealableQr({
  getValue,
  revealed,
  onToggleReveal,
  onDownload,
  hiResRef,
  warning,
  caption,
  onCopyDigits,
}: RevealableQrProps) {
  return (
    <>
      {revealed ? (
        <>
          <div className="rounded-lg bg-white p-4">
            <QRCodeCanvas value={getValue()} size={256} level="L" marginSize={0} />
          </div>
          <div ref={hiResRef} style={OFFSCREEN_STYLE}>
            {/* marginSize={4} is the QR-spec quiet zone. Do not lower it —
                the exported PNG is printed as a seed backup, and scanners
                need the full 4-module margin to acquire the code. */}
            <QRCodeCanvas value={getValue()} size={1024} level="L" marginSize={4} />
          </div>
        </>
      ) : (
        <div className="flex h-[288px] w-[288px] items-center justify-center rounded-lg bg-inset">
          <QrCode className="h-16 w-16 text-muted-foreground/40" />
        </div>
      )}
      {caption && (
        <p className="text-center text-xs text-muted-foreground">{caption}</p>
      )}
      <p className="rounded-md bg-warning/10 px-3 py-2 text-center text-xs text-warning">
        {warning}
      </p>
      <div className="flex items-center gap-2">
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={onToggleReveal}
          className="w-32 text-muted-foreground hover:text-foreground"
        >
          {revealed ? <EyeOff className="mr-2 h-3.5 w-3.5" /> : <Eye className="mr-2 h-3.5 w-3.5" />}
          {revealed ? 'Hide QR' : 'Reveal QR'}
        </Button>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          disabled={!revealed}
          onClick={onDownload}
          className="w-32 text-muted-foreground hover:text-foreground"
        >
          <Download className="mr-2 h-3.5 w-3.5" />
          Download PNG
        </Button>
      </div>
      {onCopyDigits && (
        <Button
          type="button"
          variant="ghost"
          size="sm"
          disabled={!revealed}
          onClick={onCopyDigits}
          className="w-[264px] text-muted-foreground hover:text-foreground"
        >
          <Copy className="mr-2 h-3.5 w-3.5" />
          Copy digits
        </Button>
      )}
    </>
  );
}

/**
 * The little ⓘ next to a setting.
 *
 * Three copies of this existed inline, and all three shared two defects that
 * axe reports as critical:
 *
 *  1. **No accessible name.** An icon-only `<button>` with an SVG inside is
 *     announced as "button" and nothing else. These are the controls that
 *     explain the key file, the password policy and filename privacy — the
 *     security-relevant choices — so "button" is the least useful thing a
 *     screen reader could say about them.
 *  2. **`focus:outline-hidden`.** The focus ring was removed and nothing put
 *     back, so a keyboard user tabbing through the form simply loses track of
 *     where they are. That is WCAG 2.4.7, and it is invisible to anyone who
 *     drives the page with a mouse — which is why it survived this long.
 *
 * Radix wires the tooltip content up as `aria-describedby` while it is open,
 * so `label` is the short name and the tooltip carries the detail.
 */
export function InfoTip({ label, children }: { label: string; children: ReactNode }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          aria-label={label}
          // U8. The icon stays 14x14; the *target* grows to 26x26 via padding
          // pulled straight back out with a negative margin, so nothing moves
          // on screen and no neighbouring text reflows. WCAG 2.5.8 measures the
          // target, not the glyph.
          className="-m-1.5 rounded-sm p-1.5 text-subtle-foreground transition-colors hover:text-muted-foreground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
        >
          <Info className="h-3.5 w-3.5" aria-hidden="true" />
        </button>
      </TooltipTrigger>
      <TooltipContent>{children}</TooltipContent>
    </Tooltip>
  );
}
