
"use client";

import { useState, useRef, type ChangeEvent, type DragEvent, type RefObject, type ReactNode, useCallback, useEffect, useMemo } from "react";
import { QRCodeCanvas } from "qrcode.react";
import { PaperVault } from "@/components/paper-vault";
import { SelfExtractExport } from "@/components/self-extract-export";
import { armorKeym2, KEYM2_VERSION } from "@/lib/keym-v2";
import { looksLikeSelfExtract, extractSelfExtract } from "@/lib/keym-v2-selfextract";
import { looksLikePaperPart, describePaperPart } from "@/lib/keym-v2-paper";
import {
  KeyRound,
  Lock,
  Unlock,
  Loader2,
  FileText,
  Copy,
  Eye,
  EyeOff,
  RefreshCw,
  X,
  Heart,
  Info,
  Download,
  QrCode,
  Shield,
  Globe,
  UserX,
  Dices,
  ChevronDown,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  LifeBuoy,
  Printer,
  Trash2,
  Timer,
} from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import {
  encryptData,
  decryptData,
  inspectKeym,
  isArgon2idAvailable,
  isUserFacingError,
  KeymakerError,
  warmCryptoDependencies,
  MAX_PLAINTEXT_SIZE,
  MAX_CONTAINER_SIZE,
  oversizeRecoveryHelp,
  MAX_BASE64_INPUT_CHARS,
  MAX_TEXT_PLAINTEXT_BYTES,
  MAX_TEXT_ARMOR_CHARS,
  MAX_PASSWORD_LENGTH,
  KdfId,
  CipherId,
  DEFAULT_ARGON2ID,
  type KdfParams,
  type DetectedFormat,
} from "@/lib/keymaker-crypto";
import {
  encryptViaWorker,
  calibrateViaWorker,
  decryptViaWorker,
  cancelAllCryptoWork,
  warmCryptoWorker,
} from "@/lib/crypto-client";
import {
  describeCalibration,
  predictArgon2Ms,
  type DeviceFit,
} from "@/lib/kdf-calibration";
import { EFF_LARGE_WORDLIST, EFF_LARGE_WORDLIST_SIZE } from "@/lib/eff-wordlist";
import { DiceEntropyTool } from "@/components/dice-entropy-tool";
import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/utils";
import { Textarea } from "@/components/ui/textarea";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";


type Mode = "encrypt" | "decrypt" | "tools";
type InputType = "file" | "text";

// The BIP-39 module embeds the full English wordlist (~13 KB), so it is
// loaded lazily to keep it out of the initial bundle. It is warmed in the
// background right after mount (see the effect in EncryptorTool) so the
// service worker caches the chunk for offline use, and awaited on the
// decrypt path before seed detection. `bip39Module` is the synchronous
// handle for render-time use; it is guaranteed non-null once any
// `loadBip39()` call has resolved.
type Bip39Module = typeof import("@/lib/bip39");
let bip39Module: Bip39Module | null = null;
let bip39ModulePromise: Promise<Bip39Module> | null = null;
function loadBip39(): Promise<Bip39Module> {
  bip39ModulePromise ??= import("@/lib/bip39").then((m) => {
    bip39Module = m;
    return m;
  });
  return bip39ModulePromise;
}

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
function LockWarning({
  secondsLeft,
  onKeepOpen,
}: {
  secondsLeft: number;
  onKeepOpen: () => void;
}) {
  return (
    <div
      role="alert"
      className="flex items-center justify-between gap-3 rounded-xl border border-yellow-500/40 bg-yellow-500/10 px-3 py-2 text-[12px]"
    >
      <span className="flex min-w-0 items-center gap-1.5 text-yellow-400">
        <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
        <span className="truncate">
          Locking in <span className="tabular-nums font-medium">{secondsLeft}s</span> — secrets will be cleared
        </span>
      </span>
      <button
        type="button"
        onClick={onKeepOpen}
        className="shrink-0 cursor-pointer rounded-lg border border-yellow-500/40 px-2.5 py-1 font-medium text-yellow-400 transition-colors hover:bg-yellow-500/15"
      >
        Keep open
      </button>
    </div>
  );
}

// Chunked base64 decode to avoid stack overflow on large buffers.
//
// The encoding half of this pair used to live here and is gone: text output is
// v2 armor now, which is base64url and comes from `armorKeym2`. B9's fix — the
// array-and-join instead of `+=` — moved with it, and is called out there
// rather than dropped.
function base64ToUint8Array(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// Offscreen positioning for the hidden hi-res QR canvases used only as a
// source for PNG export. Hoisted so the object identity is stable across
// renders instead of allocating a fresh style object each time.
const OFFSCREEN_STYLE = { position: 'absolute', left: '-9999px', top: '-9999px' } as const;

/**
 * U16. "GitHub" and "Open source" on a Keymaker page must lead to Keymaker's
 * source; they pointed at the upstream IttyBitz repo, so anyone looking for
 * this product's code or issue tracker landed on a different product.
 *
 * The fork attribution below is a *separate* link and deliberately still points
 * at IttyBitz. It is a GPL-3 credit, not a source link, and repointing it while
 * fixing this would trade a broken link for a licensing discourtesy.
 */
const KEYMAKER_REPO = "https://github.com/404SecNotFound/Keymaker-v2";

/**
 * 6.1. Injected from package.json by next.config.js, never written twice.
 *
 * The fallback is a visible placeholder rather than a plausible number: if the
 * injection ever breaks, the footer should say something obviously wrong rather
 * than confidently report a version that is not the one running.
 */
const APP_VERSION = process.env.KEYMAKER_APP_VERSION || "unknown";

/**
 * Whether this bundle is the tagged release of APP_VERSION or a rolling build.
 *
 * The footer said "Keymaker v2.0.0" for both, which made the version a claim
 * the artifact could not support: the deployed site ran commits past the tag
 * while naming the tag. The number is the one people quote in bug reports and
 * check signatures against, so it has to distinguish the two.
 */
const IS_RELEASE_BUILD = process.env.KEYMAKER_RELEASE_CHANNEL === "release";

/**
 * §4.6. One share per line, blanks and `#` comments dropped.
 *
 * Comments are stripped because the reference CLI prints share sets with
 * `# share 2 of 5` headers, and pasting that output back in unedited is the
 * obvious thing to do. Rejecting it would be a papercut aimed squarely at the
 * person recovering a container under stress.
 */
function parseShareLines(text: string): string[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));
}

/**
 * Bounds on the recovery-share textarea.
 *
 * The field took whatever was pasted straight into state, and two render-path
 * callers re-split and re-trimmed all of it on every keystroke. None of this is
 * a cryptographic boundary — the parser rejects anything that is not a share —
 * but "however much you like" is not a size for an input the UI rescans that
 * often.
 *
 * The numbers come from the format, generously. A `KMSHARE1:` line is about 95
 * characters and the UI issues at most 8 shares, so 16 lines is double any real
 * share set and 8 KiB is several times the text they occupy. Past that it is a
 * paste into the wrong box, which is what §7 is for.
 */
const MAX_SHARE_INPUT_CHARS = 8 * 1024;
const MAX_SHARE_LINES = 16;
const MAX_SHARE_LINE_CHARS = 200;

/**
 * Why this refuses instead of truncating, same as the U4 gate above it: keeping
 * the first N characters of someone's share set and silently dropping the rest
 * produces a reconstruction failure with no stated cause, aimed at the person
 * least able to diagnose it.
 */
function shareInputRejection(next: string): string | null {
  if (next.length > MAX_SHARE_INPUT_CHARS) {
    return (
      `That is ${Math.round(next.length / 1024).toLocaleString()} KB of text. ` +
      `A share set is a few hundred bytes — this box takes up to ` +
      `${MAX_SHARE_INPUT_CHARS / 1024} KB. If you meant to paste the encrypted ` +
      `container, it goes in the box above.`
    );
  }
  const lines = parseShareLines(next);
  if (lines.length > MAX_SHARE_LINES) {
    return (
      `That is ${lines.length} lines. A share set is at most 8 shares, one per ` +
      `line — this box takes up to ${MAX_SHARE_LINES}.`
    );
  }
  const overlong = lines.find((line) => line.length > MAX_SHARE_LINE_CHARS);
  if (overlong) {
    return (
      `One line is ${overlong.length} characters. A share is about 95, so that ` +
      `is not one — check for a line that did not wrap where you expected.`
    );
  }
  return null;
}

// Minimum password policy — deliberately NOT called a strength measurement.
//
// This check has been wrong twice, in the same way each time. First it accepted
// any six whitespace-separated tokens ("a a a a a a"). Tightened to distinct,
// substantial words, it still accepted "password qwerty letmein monkey dragon
// football" — six distinct dictionary words, every one of them in the first
// page of any cracking wordlist.
//
// The lesson is that no amount of morphology fixes this. Entropy is a property
// of *how a password was chosen*, and a string carries no evidence of its own
// provenance. A phrase drawn uniformly from a word list and a phrase a person
// picked because it was memorable are indistinguishable once typed.
//
// So this function no longer claims to identify strong passwords. It enforces
// a floor and says so. The only entropy figure Keymaker states is for passwords
// it generated itself, where it controls the sampling and the arithmetic is
// real — see PASSWORD_ENTROPY_BITS.
//
// Two ways to clear the floor:
//  1. Character-class rule: >= 24 chars with upper, lower, number and symbol.
//     The symbol class is kept in sync with the generatePassword charset, so a
//     generated password can never be rejected here.
//  2. Passphrase rule: enough distinct words of >= 3 characters, plus a length
//     floor. Repeats count once, so padding by repetition buys nothing.
//
// Advisory and UI-only. encryptData() has never consulted it, and must not —
// cryptographic behaviour cannot depend on a heuristic.
const PASSPHRASE_MIN_WORD_LEN = 3;

// The generator's alphabet and length. Kept here rather than inline so the
// entropy figure below is derived from the same values the generator uses,
// and cannot drift from them.
const PASSWORD_CHARSET =
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~`|}{[]:;?><,./-=";
const PASSWORD_LENGTH = 32;

// Exact, because the generator samples uniformly from PASSWORD_CHARSET with
// rejection sampling. This is the one entropy number Keymaker is entitled to
// state: it knows the alphabet, the length, and that the draw was unbiased.
const PASSWORD_ENTROPY_BITS = Math.floor(PASSWORD_LENGTH * Math.log2(PASSWORD_CHARSET.length));

// The passphrase generator's parameters, kept here for the same reason: the
// figure the UI prints is computed from the values the generator uses.
//
// Seven words rather than EFF's headline six. Six is 77.5 bits, which is sound
// behind Argon2id at RFC 9106's second profile — but the KDF settings are the
// user's to lower, and a seventh word buys 13 bits for one more word to
// remember. The list itself is fetched and checksummed rather than transcribed;
// see src/lib/eff-wordlist.ts and scripts/verify-wordlist.mjs.
const PASSPHRASE_WORDS = 7;
const PASSPHRASE_SEPARATOR = " ";

// Exact, for the same reason PASSWORD_ENTROPY_BITS is exact: uniform,
// independent draws from a list whose size is known. log2(7776) = 12.925 bits
// per word.
//
// "Independent" means with replacement, which is what makes this a plain
// multiplication and what diceware specifies. A repeated word in a generated
// phrase is therefore not a defect and does not reduce the count — drawing
// without replacement would be a different, slightly smaller number.
const PASSPHRASE_ENTROPY_BITS = Math.floor(
  PASSPHRASE_WORDS * Math.log2(EFF_LARGE_WORDLIST_SIZE)
);

/**
 * What the CSPRNG produced, when the current password is exactly that.
 *
 * A descriptor rather than a boolean beside a separate bit count: the claim
 * that there *is* an entropy figure and the figure itself have to travel
 * together, or they can drift apart.
 */
type GeneratedSecret =
  | { kind: "password"; bits: number }
  | { kind: "passphrase"; words: number; bits: number };

function meetsPasswordPolicy(pwd: string, wasGenerated = false): boolean {
  // Provenance settles it whenever provenance is known — which is the KM-02b
  // lesson pointed in the direction where it actually helps. A typed string
  // carries no evidence of how it was chosen, so morphology is all there is to
  // go on. A string this component drew from the CSPRNG a moment ago has a
  // known sampling process and an exact bit count, and needs no inference.
  //
  // This also removes a defect the rules below would otherwise introduce. A
  // uniform seven-word draw repeats a word about once in 370, and with
  // replacement that repetition costs nothing — the phrase is still 90 bits.
  // The distinct-word rule cannot tell that from padding, so without this it
  // would occasionally refuse to encrypt under a passphrase Keymaker had
  // itself just certified in the line above the field.
  if (wasGenerated) return true;

  const trimmed = pwd.trim();

  const distinctSubstantialWords = new Set(
    trimmed
      .split(/\s+/)
      .filter(Boolean)
      .map((w) => w.toLowerCase())
      .filter((w) => w.length >= PASSPHRASE_MIN_WORD_LEN)
  ).size;

  // A genuine diceware phrase clears one of these even with a repeated word,
  // because the length floor carries it.
  if (distinctSubstantialWords >= 6 && trimmed.length >= 20) return true;
  if (distinctSubstantialWords >= 4 && trimmed.length >= 24) return true;

  const hasUpperCase = /[A-Z]/.test(pwd);
  const hasLowerCase = /[a-z]/.test(pwd);
  const hasNumbers = /\d/.test(pwd);
  const hasSpecialChars = /[!@#$%^&*()_+~`|}{[\]:;?><,.\/=-]/.test(pwd);
  const hasMinLength = pwd.length >= 24;
  return hasMinLength && hasUpperCase && hasLowerCase && hasNumbers && hasSpecialChars;
}

// Shared download plumbing. Creating/clicking/removing a transient anchor is
// identical across every download path (key file, ciphertext, plaintext, QR
// PNGs), so it lives in one place.
function clickDownloadLink(href: string, filename: string) {
  const a = document.createElement("a");
  a.href = href;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  clickDownloadLink(url, filename);
  URL.revokeObjectURL(url);
}

// Export a canvas as a downloaded PNG. octet-stream forces a download rather
// than in-page navigation. .replace() only hits the MIME header, never the
// base64 body.
function exportCanvasPng(canvas: HTMLCanvasElement, filename: string) {
  const url = canvas.toDataURL("image/png").replace("image/png", "image/octet-stream");
  clickDownloadLink(url, filename);
}

const validateAndSanitizeFile = (file: File) => {
  if (file.name.includes('..') ||
      file.name.includes('/') ||
      file.name.includes('\\') ||
      file.name.length > 255) {
    throw new Error('Invalid filename. It may contain invalid characters or be too long.');
  }

  if (file.name.includes('\0')) {
    throw new Error('Invalid filename. It contains null bytes.');
  }

  // Reject C0 control characters and Unicode bidi-override characters
  // (U+202A–U+202E, U+2066–U+2069). A bidi override in a filename can
  // visually disguise the real extension of the decrypted download
  // (RTLO extension spoofing).
  if (/[\u0000-\u001f\u202a-\u202e\u2066-\u2069]/.test(file.name)) {
    throw new Error('Invalid filename. It contains control or bidirectional-override characters.');
  }

  return true;
};

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
const FileSelector = ({
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
      <div
        className={cn(
          "relative flex w-full cursor-pointer flex-col items-center justify-center rounded-xl border border-dashed border-white/15 bg-white/2 px-6 py-10 text-center transition-all duration-200 hover:border-accent/50 hover:bg-accent/3",
          { 'border-accent/60 bg-accent/5': isDragging }
        )}
        onClick={handleContainerClick}
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragEnter={handleDragEnter}
        onDragLeave={handleDragLeave}
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
        <div className="mb-3 grid h-12 w-12 place-items-center rounded-xl bg-white/5 text-accent">
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
          <h2 className="text-[15px] font-medium text-foreground">{label}</h2>
          <p className={cn(
            "mt-1 w-full overflow-hidden truncate text-[13px]",
            selectedFile ? "font-medium text-accent" : "text-muted-foreground"
          )}>
            {selectedFile ? selectedFile.name : description}
          </p>
        </div>
      </div>
      {dropRejected && (
        <p role="status" className="mt-2 text-[12px] leading-snug text-yellow-400">
          {dropRejected}
        </p>
      )}
      {selectedFile && (
        <div className="mt-2 text-right">
          <Button variant="link" size="sm" onClick={onClear} className="h-auto p-0 text-xs text-destructive hover:text-destructive/80">
            Clear
          </Button>
        </div>
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

function RevealableQr({
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
        <div className="flex h-[288px] w-[288px] items-center justify-center rounded-lg bg-white/6">
          <QrCode className="h-16 w-16 text-muted-foreground/40" />
        </div>
      )}
      {caption && (
        <p className="text-center text-xs text-muted-foreground">{caption}</p>
      )}
      <p className="rounded-md bg-yellow-900/20 px-3 py-2 text-center text-xs text-yellow-400">
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

// 100 MB. Note: encrypting a file of this size transiently holds several full
// copies in memory (the read ArrayBuffer, the Web Crypto ciphertext output,
// and the Blob for download), so peak usage is a multiple of this limit —
// the practical ceiling on low-RAM mobile devices.
const MAX_FILE_SIZE = 100 * 1024 * 1024;
// QR version 40, error-correction level L, byte mode. Every QRCodeCanvas below
// pins level="L" explicitly — raising the ECC level without lowering this
// limit would make qrcode.react throw for inputs above the new capacity
// (level M tops out at 2,331 bytes).
/**
 * Byte-mode capacity of a version-40 QR at error-correction level L.
 *
 * Bytes, not characters. Ciphertext is base64 so the two coincide there, but
 * decrypted plaintext is arbitrary Unicode: `"日本語".length` is 3 while its
 * UTF-8 encoding is 9 bytes. Sizing by string length therefore over-promised
 * for every non-ASCII script — Arabic, Urdu, CJK, emoji — and would hand the
 * encoder more data than the symbol can hold.
 */
const QR_MAX_BYTES = 2_953;

/** UTF-8 byte length, which is what the QR encoder actually consumes. */
function qrByteLength(text: string): number {
  return new TextEncoder().encode(text).byteLength;
}

// Self-identifying prefixes for encrypted TEXT blobs (files carry the binary
// "KEYM" magic instead). Decryption still accepts bare base64 IBTZ blobs.
//
// New text output is v2 armor. v1's prefix is *accepted* forever — it is what
// every text backup written before Phase 3 starts with — but nothing produces
// it any more.
//
// The two are matched differently on purpose, and FORMAT-V2-DESIGN §7 is the
// reason. `KEYM1:` shares all four of its first bytes with the binary magic,
// which is the bug v2's encoding exists to remove: lowercase `k` is 0x6B, the
// magic's `K` is 0x4B, so byte 0 alone separates them. That only holds if the
// v2 prefix is matched **case-sensitively** — accepting `KEYM2:` would put the
// collision straight back while looking like leniency.
const KEYM_V1_TEXT_PREFIX = "KEYM1:";
const KEYM_V2_TEXT_PREFIX = "keym2:";

/**
 * How long a copied secret is allowed to sit in the clipboard.
 *
 * The previous implementation read the clipboard back after 60 s and only
 * overwrote it if the contents still matched. That read is the problem:
 * `navigator.clipboard.readText()` needs both permission and document focus,
 * Firefox does not offer it to page script at all, and the whole thing sat
 * inside a `catch {}`. In practice the comparison threw and the seed phrase
 * stayed in the clipboard indefinitely — while the toast said it would be
 * cleared. A promise a security tool cannot keep is worse than no promise.
 *
 * So the overwrite is now unconditional. The cost is real and worth naming: if
 * the user copies something else in the meantime, that is what gets cleared.
 * The countdown is on screen for exactly that reason, with a control to clear
 * it early or dismiss it — a surprise is only a surprise if it was invisible.
 */
const CLIPBOARD_CLEAR_SECONDS = 60;

/**
 * Idle time before the tool wipes secrets from memory and the screen.
 *
 * The threat is mundane and the reason the feature exists: an unlocked laptop
 * with a decrypted seed phrase on it, in an office, a café, or a hotel room.
 *
 * Five minutes is a compromise. Someone transcribing a 24-word phrase onto
 * paper is doing the exact thing this could interrupt, so the last
 * LOCK_WARN_SECONDS are spent visibly counting down with a control to stay
 * open, rather than the screen simply going blank on them.
 */
const AUTO_LOCK_MS = 5 * 60_000;
const LOCK_WARN_SECONDS = 30;

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
function InfoTip({ label, children }: { label: string; children: ReactNode }) {
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
          className="-m-1.5 rounded-sm p-1.5 text-muted-foreground/60 transition-colors hover:text-muted-foreground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
        >
          <Info className="h-3.5 w-3.5" aria-hidden="true" />
        </button>
      </TooltipTrigger>
      <TooltipContent>{children}</TooltipContent>
    </Tooltip>
  );
}

/**
 * Subdirectory this build is served from, or "" at a domain root.
 *
 * Next rewrites its own asset URLs but not ones written by hand, so any link
 * authored here has to prefix itself — same reason crypto-client.ts does it for
 * the worker URL. Without it the recovery-kit links 404 on the Pages
 * deployment, which is the one place they matter most.
 */
const BASE_PATH = (process.env.KEYMAKER_BASE_PATH || '').replace(/\/$/, '');

/** Byte count for humans. Used by the verify-only result. */
function formatBytes(n: number): string {
  if (n < 1024) return `${n} byte${n === 1 ? '' : 's'}`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

// Filename privacy: when enabled, encrypted downloads are named
// keymaker-<random8 hex>.keym instead of <original name>.keym.
function randomFilenameSuffix(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(4));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

type KdfChoice = "pbkdf2" | "argon2id";

const CIPHER_OPTIONS = [
  {
    id: CipherId.AES_256_GCM,
    name: "AES-256-GCM",
    blurb: "Hardware-accelerated on most devices. The battle-tested default.",
  },
  {
    id: CipherId.CHACHA20_POLY1305,
    name: "ChaCha20-Poly1305",
    blurb: "Software-friendly stream cipher. Constant-time even without AES hardware.",
  },
  {
    id: CipherId.CHAINED,
    name: "AES → ChaCha (chained)",
    blurb: "Defence in depth: encrypts with AES-256-GCM, then ChaCha20-Poly1305 under an independently derived key.",
  },
] as const;

const FEATURE_CARDS = [
  {
    icon: Shield,
    title: "Argon2id + AES/ChaCha",
    description: "Memory-hard key derivation and chainable AEAD ciphers.",
  },
  {
    icon: Globe,
    title: "100% Client-Side",
    description: "Nothing leaves your browser. No servers, no uploads, no tracking.",
  },
  {
    icon: UserX,
    title: "No Accounts",
    description: "No sign-ups or logins. Just encrypt and go.",
  },
] as const;

export function EncryptorTool() {
  const [mode, setMode] = useState<Mode>("encrypt");
  const [inputType, setInputType] = useState<InputType>('file');
  const [file, setFile] = useState<File | null>(null);
  const [textSecret, setTextSecret] = useState('');
  const [outputText, setOutputText] = useState('');
  const [password, setPassword] = useState('');
  // Non-null only while `password` is exactly what a generator produced.
  // Gates the entropy figure, which is meaningless for a typed password.
  const [generated, setGenerated] = useState<GeneratedSecret | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const [showTextSecret, setShowTextSecret] = useState(false);
  // Advanced encryption options (Encrypt tab only — the KEYM container is
  // self-describing, so decryption needs no knobs).
  const [isAdvancedOpen, setIsAdvancedOpen] = useState(false);
  // Argon2id is the default: the user who never opens Advanced should get the
  // memory-hard KDF, not the weaker one. It needs WebAssembly, though, so
  // availability is probed on mount and we fall back visibly rather than
  // presenting a default that cannot run. Until the probe resolves the choice
  // is optimistic — the Encrypt button cannot be reached faster than a
  // microtask, and a failed probe corrects it before any derivation.
  const [kdfChoice, setKdfChoice] = useState<KdfChoice>("argon2id");
  const [argon2Available, setArgon2Available] = useState<boolean | null>(null);
  const [argonTimeCost, setArgonTimeCost] = useState(DEFAULT_ARGON2ID.timeCost);
  const [argonMemoryMiB, setArgonMemoryMiB] = useState(DEFAULT_ARGON2ID.memoryKiB / 1024);
  const [argonParallelism, setArgonParallelism] = useState(DEFAULT_ARGON2ID.parallelism);
  // Roadmap 2.5. `deviceFit` outlives the calibration itself on purpose: once
  // this device has been measured, every slider position can be priced against
  // it, not just the one calibration happened to pick.
  const [deviceFit, setDeviceFit] = useState<DeviceFit | null>(null);
  const [calibrating, setCalibrating] = useState(false);
  const [calibrationNote, setCalibrationNote] = useState<string | null>(null);

  /**
   * One second, and it is a judgement rather than a measurement.
   *
   * Long enough that brute force costs an attacker real money, short enough
   * that someone unlocking a backup on a phone does not think it has hung. The
   * fixed 64 MiB default was aiming at roughly this on a mid-range laptop;
   * calibration aims at the same target on whatever machine is actually here.
   */
  const CALIBRATION_BUDGET_MS = 1000;

  const runCalibration = useCallback(async () => {
    setCalibrating(true);
    setCalibrationNote(null);
    try {
      const result = await calibrateViaWorker(
        CALIBRATION_BUDGET_MS,
        argonTimeCost,
        argonParallelism
      );
      if (!result) {
        setDeviceFit(null);
        setCalibrationNote(
          "Calibration needs a Web Worker, and this browser did not provide one. Your current settings are unchanged."
        );
        return;
      }
      setDeviceFit(result.fit);
      // Only the memory slider moves. Time cost and parallelism are what the
      // user asked to solve *for*, and quietly overwriting a deliberate choice
      // is worse than a slightly-off answer.
      if (result.params.kdf === KdfId.ARGON2ID) {
        setArgonMemoryMiB(result.params.params.memoryKiB / 1024);
      }
      setCalibrationNote(describeCalibration(result, CALIBRATION_BUDGET_MS));
    } catch {
      setDeviceFit(null);
      setCalibrationNote("Calibration did not finish. Your current settings are unchanged.");
    } finally {
      setCalibrating(false);
    }
  }, [argonTimeCost, argonParallelism]);
  const [cipherChoice, setCipherChoice] = useState<CipherId>(CipherId.AES_256_GCM);
  const [obscureFilename, setObscureFilename] = useState(false);
  // Post-decrypt info line: which container format/params were detected.
  const [decryptInfo, setDecryptInfo] = useState<string | null>(null);
  /**
   * v3 §5.2. True when the container opened but its slot table did not
   * authenticate. Separate state rather than a clause on `decryptInfo` because
   * the two say different kinds of thing: that line describes the file, this
   * one reports that part of it has changed since it was written.
   */
  const [slotTableWarning, setSlotTableWarning] = useState(false);
  const [showDecryptedText, setShowDecryptedText] = useState(false);
  const [useKeyFile, setUseKeyFile] = useState(false);
  const [keyFile, setKeyFile] = useState<File | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  /** Set before the derivation starts when this container will be slow. */
  const [unlockCostNotice, setUnlockCostNotice] = useState<string | null>(null);
  const [isCryptoAvailable, setIsCryptoAvailable] = useState(true);
  const [isQrModalOpen, setIsQrModalOpen] = useState(false);

  /**
   * Verify-only decryption.
   *
   * "Does this backup still open with this password?" is the question people
   * actually have about a container they wrote two years ago, and answering it
   * today means decrypting it and looking at the seed phrase on screen — which
   * is the one thing a careful person does not want to do just to run a check.
   *
   * The AEAD tag *is* the answer: if it verifies, the container is intact and
   * the password is right. So run the identical decryption, then throw the
   * plaintext away without rendering it, writing it to disk, or letting the
   * BIP-39 detector near it.
   *
   * Being precise about what this does not do: authenticating an AEAD ciphertext
   * requires producing the plaintext — neither AES-GCM nor ChaCha20-Poly1305
   * exposes a verify-the-tag-only operation, and WebCrypto has no such API. The
   * plaintext exists in the worker's heap for the length of one call. What is
   * avoided is the part under the user's control: it never reaches the DOM, the
   * clipboard, a Blob, or a file.
   */
  const [verifyOnly, setVerifyOnly] = useState(false);
  type VerifyResult = { detail: string; bytes: number };
  const [verifyResult, setVerifyResult] = useState<VerifyResult | null>(null);

  // Recovery kit modal — see the footer.
  const [isRecoveryOpen, setIsRecoveryOpen] = useState(false);

  const clipboardTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  /**
   * Wall-clock instant the clipboard is due to be overwritten, or null.
   *
   * A deadline rather than a countdown integer, so the ticking effect owns the
   * display and nothing has to fire a side effect from inside a state updater.
   */
  const [clipboardDeadline, setClipboardDeadline] = useState<number | null>(null);
  const [clipboardSecondsLeft, setClipboardSecondsLeft] = useState<number | null>(null);

  // Auto-lock. lastActivityRef is a ref because it is written on every pointer
  // and key event: as state it would re-render the whole tool on mouse-down.
  const lastActivityRef = useRef<number>(0);
  const [lockSecondsLeft, setLockSecondsLeft] = useState<number | null>(null);

  /**
   * Monotonic id of the crypto operation that currently owns the UI.
   *
   * A ref, not state: it must be readable synchronously from inside an async
   * closure that started several renders ago, and bumping it must not itself
   * trigger a render.
   */
  const opSeqRef = useRef(0);

  // Decrypted-result QR modal state. This is purely a display-side concern —
  // the QR is generated from the already-decrypted `outputText`. It does not
  // touch the cryptography or the encrypted file format.
  // The SeedQR payload is intentionally NOT stored in state — it is derived
  // from `words` at render time, and only while the QR is revealed, to keep
  // the encoded secret out of long-lived component state.
  type DecryptedQrStatus =
    | { kind: "idle" }
    // seedShaped: the decrypted text failed BIP-39 validation but looks like
    // a seed phrase (valid word count, ≤1 unknown word) — the stored backup
    // itself likely contains a transcription error. Surfaced as a red border.
    | { kind: "plain"; seedShaped: boolean }
    | { kind: "seed"; words: string[] };
  const [isDecryptedQrModalOpen, setIsDecryptedQrModalOpen] = useState(false);
  // Default to blurred whenever the modal opens. Same shoulder-surfing
  // protection as the decrypted-text Textarea — the user must deliberately
  // click to reveal the QR before scanning.
  const [isDecryptedQrRevealed, setIsDecryptedQrRevealed] = useState(false);
  const [decryptedQrStatus, setDecryptedQrStatus] = useState<DecryptedQrStatus>({
    kind: "idle",
  });
  // Encrypt-side seed check for the subtle border tint on the secret text
  // field: 'valid' → green, 'invalid' → red (seed-shaped but failing
  // validation, i.e. a likely typo), 'none' → neutral (ordinary text).
  /**
   * Set when the text field refused an oversized input (U4).
   *
   * A separate piece of state rather than a toast: a toast is gone in a second
   * and the user is left looking at a field that silently did not take their
   * paste. This is a *state* of the field, so it renders next to the field and
   * stays until they act on it.
   */
  const [textInputRejected, setTextInputRejected] = useState<string | null>(null);

  const [textSecretSeedStatus, setTextSecretSeedStatus] = useState<
    "none" | "valid" | "invalid"
  >("none");
  const { toast } = useToast();

  /**
   * The armored output with its line breaks removed, for the QR code only.
   *
   * Armor is wrapped at 64 columns because that is what makes it survivable in
   * a textarea, an email and on paper. A QR code is none of those: capacity is
   * a hard cliff at QR_MAX_BYTES, and the newlines are pure overhead against
   * it. Measured on a container that just fits — 2 942 bytes compact becomes
   * 2 987 wrapped, over the 2 953 limit — so wrapping the QR payload would
   * take codes that scan today and turn them into "use the copy button
   * instead".
   *
   * Whitespace is not part of the encoding, so this scans to the same
   * container.
   */
  const outputTextForQr = outputText.replace(/\s+/g, "");


  // Derived, not stored — cheap (5 regex tests) and always consistent with
  // `password`, removing a state variable and its sync points.
  const passwordMeetsPolicy = meetsPasswordPolicy(password, generated !== null);

  /**
   * §4.6 recovery shares.
   *
   * Enrolment is a *write* option, so it lives with the cipher and KDF rather
   * than as a separate flow: the slot has to be added while a secret that opens
   * the container is in hand, and that moment is the encrypt itself.
   *
   * Defaults are 2-of-3, not 3-of-5. Three pieces of paper is a thing a person
   * will actually place — a lawyer, a sibling, a safe — and a scheme nobody
   * completes protects nothing. The picker goes to 8 either way.
   */
  const [shamirEnabled, setShamirEnabled] = useState(false);
  // §4.7. Encrypt side: enrol a passkey alongside the password. Never instead
  // of it — the container the writer produces always carries the passphrase
  // slot too, which is how the never-travels-alone rule is satisfied here.
  const [passkeyEnabled, setPasskeyEnabled] = useState(false);
  const [passkeySupported, setPasskeySupported] = useState(false);
  const [shamirThreshold, setShamirThreshold] = useState(2);
  const [shamirCount, setShamirCount] = useState(3);
  const [issuedShares, setIssuedShares] = useState<{ threshold: number; shares: string[] } | null>(null);
  /**
   * Read by the auto-lock interval, which closes over state from the render
   * that armed it. The effect depends on `hasSecretsOnScreen` only, so by the
   * time the interval fires `issuedShares` in its closure may be a tick old —
   * and this decides which of two toasts the user is told, so it has to be
   * current rather than nearly current.
   */
  const issuedSharesRef = useRef<{ threshold: number; shares: string[] } | null>(null);
  useEffect(() => {
    issuedSharesRef.current = issuedShares;
  }, [issuedShares]);
  /**
   * 4.2. What the paper vault sheet should render on the next print.
   *
   * Held in state rather than computed inside the print handler because the
   * sheet is React-rendered: `window.print()` snapshots whatever is in the DOM
   * at that instant, so the render has to have happened first. The print is
   * fired from an effect once this lands, not from the click.
   */
  const [paperVault, setPaperVault] = useState<{
    container: Uint8Array;
    shares?: string[];
    threshold?: number;
    printedOn: string;
  } | null>(null);
  /*
    4.2. Print after the sheet is in the DOM, not from the click handler.

    `window.print()` snapshots the document synchronously, so calling it in the
    same tick as setState prints the previous render — which is an empty sheet.
    The double rAF waits for React to commit and the browser to lay the QR
    canvases out; printing between those two produces a page of blank squares.

    The sheet is cleared afterwards so the container bytes do not sit in state
    for the rest of the session.
  */
  // §4.7. Whether to offer the control at all. Deliberately not a claim that
  // the *authenticator* can do PRF — there is no way to learn that without
  // prompting, and probing by prompting is what a capability check must not do.
  // A key that cannot derive is caught at enrolment, against an action the user
  // just took.
  useEffect(() => {
    let live = true;
    void (async () => {
      const { probePasskeySupport } = await import("@/lib/webauthn-prf");
      const support = await probePasskeySupport();
      if (live) setPasskeySupported(support.available);
    })();
    return () => {
      live = false;
    };
  }, []);

  useEffect(() => {
    if (!paperVault) return;
    let cancelled = false;
    const id = requestAnimationFrame(() =>
      requestAnimationFrame(() => {
        if (cancelled) return;
        window.print();
        setPaperVault(null);
      })
    );
    return () => {
      cancelled = true;
      cancelAnimationFrame(id);
    };
  }, [paperVault]);

  /**
   * Shares entered to unlock a container, one per line.
   *
   * Kept apart from the password field rather than overloading it. An heir has
   * no password at all, and a field labelled "Password" that also silently
   * accepts share text is the kind of cleverness that reads as a bug to the one
   * person who most needs it to be obvious.
   */
  const [useShares, setUseShares] = useState(false);
  /** §4.7. Decrypt side: unlock with an enrolled passkey instead of a password. */
  const [usePasskey, setUsePasskey] = useState(false);
  const [shareInput, setShareInput] = useState("");
  /** Set when a paste was refused, so the field can say why. Mirrors `textInputRejected`. */
  const [shareInputRejected, setShareInputRejected] = useState<string | null>(null);

  /**
   * The parse, once per change instead of twice per render.
   *
   * `parseShareLines(shareInput)` had three callers, two of them in the render
   * path — the submit-enabled predicate and the "n shares entered" hint — so
   * every keystroke re-split and re-trimmed the whole textarea twice over.
   */
  const shareLines = useMemo(() => parseShareLines(shareInput), [shareInput]);

  const handleShareInputChange = useCallback((next: string) => {
    const rejection = shareInputRejection(next);
    if (rejection) {
      // The text is not kept, unlike the wrong-box paste in the container
      // field. There the rejected content is what the user wants to act on;
      // here it is by definition not a share set, and holding several KB of
      // it in state is the thing being fixed.
      setShareInputRejected(rejection);
      return;
    }
    setShareInputRejected(null);
    setShareInput(next);
  }, []);

  // U25. The toggle can be on while the field is empty — the password is
  // cleared after every operation and the toggle is not — so "revealing" is
  // the conjunction, not the toggle alone. Nothing is being revealed when
  // there is nothing there.
  const revealingPassword = showPassword && password.length > 0;

  // Probe Argon2id support once, and demote the default if WebAssembly is
  // unavailable — a locked-down CSP, an exotic browser, or an embedded
  // webview. Silently leaving Argon2id selected in that case reproduces
  // exactly the failure this probe exists to prevent: a button that appears
  // to work and does nothing.
  useEffect(() => {
    let cancelled = false;
    isArgon2idAvailable().then((available) => {
      if (cancelled) return;
      setArgon2Available(available);
      if (!available) setKdfChoice("pbkdf2");
    });
    // Fetch every lazily-imported crypto dependency now, while the network is
    // presumably still there, so the service worker caches them. Without this
    // a user who loads the page, goes offline, and then picks a cipher they
    // have not used before would find the chunk missing — which would make the
    // README's "works air-gapped after first load" false in exactly the case
    // it matters.
    warmCryptoDependencies();
    // Spawn the crypto worker now too, for the same reason: its chunk should be
    // fetched and cached while the network is available, not at the moment
    // someone presses Encrypt.
    warmCryptoWorker();
    return () => {
      cancelled = true;
      // Leaving a worker running past unmount would keep burning CPU on a
      // derivation whose result nobody can receive.
      cancelAllCryptoWork();
    };
  }, []);

  // Clean up clipboard auto-clear timer on unmount
  useEffect(() => {
    return () => {
      if (clipboardTimeoutRef.current) {
        clearTimeout(clipboardTimeoutRef.current);
      }
    };
  }, []);

  /**
   * Drive the clipboard countdown, and overwrite when it reaches zero.
   *
   * Deliberately derived from a deadline and `Date.now()` rather than counting
   * ticks down: a background tab has its timers throttled to roughly once a
   * minute, so a tick-counter would still be showing "43 seconds" long after
   * the minute was up. The clipboard is exactly the thing that must not
   * silently outlive its stated lifetime.
   */
  useEffect(() => {
    if (clipboardDeadline === null) {
      setClipboardSecondsLeft(null);
      return;
    }
    let cancelled = false;
    const tick = () => {
      if (cancelled) return;
      const left = Math.ceil((clipboardDeadline - Date.now()) / 1000);
      if (left <= 0) {
        setClipboardDeadline(null);
        setClipboardSecondsLeft(null);
        // Unconditional. See CLIPBOARD_CLEAR_SECONDS for why the old
        // read-and-compare could not do this job.
        navigator.clipboard.writeText('').catch(() => {});
        return;
      }
      setClipboardSecondsLeft(left);
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [clipboardDeadline]);

  useEffect(() => {
    if (!window.crypto || !window.crypto.subtle || !window.crypto.getRandomValues) {
      setIsCryptoAvailable(false);
      toast({
        title: "Security Warning",
        description: "Web Crypto API is not available in this browser. This application cannot run securely.",
        variant: "destructive",
        duration: Infinity, // Keep it visible
      });
    }
  }, [toast]);

  // Warm the lazy BIP-39 chunk right after mount: it stays out of the
  // initial bundle, but fetching it now means the service worker caches it
  // while the user is still online, so offline seed detection keeps working.
  useEffect(() => {
    loadBip39().catch(() => {
      // Ignored — processData retries the import and degrades gracefully.
    });
  }, []);

  // Debounced BIP-39 check on the encrypt-side secret text, so a typo'd
  // seed phrase is caught BEFORE it gets encrypted into a long-term backup.
  // Deliberately color-only (border tint) — no text badge that would tell a
  // shoulder-surfer the blurred field holds a seed phrase.
  useEffect(() => {
    if (mode !== "encrypt" || inputType !== "text" || !textSecret.trim()) {
      setTextSecretSeedStatus("none");
      return;
    }
    let cancelled = false;
    const timer = setTimeout(async () => {
      try {
        const { validateBip39 } = await loadBip39();
        const result = await validateBip39(textSecret);
        if (cancelled) return;
        setTextSecretSeedStatus(
          result.valid ? "valid" : result.seedShaped ? "invalid" : "none"
        );
      } catch {
        if (!cancelled) setTextSecretSeedStatus("none");
      }
    }, 300);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [textSecret, mode, inputType]);

  /**
   * Gate the text field before its contents reach React state or the DOM.
   *
   * This runs on every input event, independently of the submit path — which is
   * the whole point of U4. The old size check lived only in `processData`, so a
   * paste was already in state, already laid out by the browser, and had
   * already blocked the main thread for seconds before anything looked at its
   * length. A check that runs after the damage is not a check.
   *
   * Refuses rather than truncates. Silently keeping the first 32 KiB of
   * someone's secret and encrypting *that* is the worst available outcome: it
   * succeeds, produces a container, and loses data without saying so.
   *
   * Byte length, not string length, on the encrypt side — the crypto core's cap
   * is on UTF-8 bytes, and a field measured in UTF-16 code units would disagree
   * with it for any non-ASCII secret.
   */
  const handleTextSecretChange = useCallback((next: string) => {
    const decrypting = mode === 'decrypt';
    if (decrypting) {
      if (next.length > MAX_TEXT_ARMOR_CHARS) {
        setTextInputRejected(
          `That is ${Math.round(next.length / 1024).toLocaleString()} KB of text. ` +
          `Encrypted text is accepted up to ${MAX_TEXT_ARMOR_CHARS / 1024} KB — ` +
          `for anything larger, decrypt the .keym file itself in File mode.`
        );
        return;
      }
    } else {
      const bytes = new Blob([next]).size;
      if (bytes > MAX_TEXT_PLAINTEXT_BYTES) {
        setTextInputRejected(
          `That is ${Math.round(bytes / 1024).toLocaleString()} KB. ` +
          `Text mode is for secrets up to ${MAX_TEXT_PLAINTEXT_BYTES / 1024} KB — ` +
          `switch to File mode to encrypt something this size.`
        );
        return;
      }
    }
    // §7 as amended by §4.6 — the wrong-box paste, with a real second encoding
    // to be wrong about for the first time.
    //
    // A share is not a container. Without this it reaches the parser, fails on
    // the magic, and reports a generic decryption failure: the exact baffling
    // outcome §7 exists to remove, aimed at the person least equipped to work
    // it out — someone recovering an inheritance from paper.
    //
    // The text is kept, not refused. Throwing away what they just pasted would
    // be the second unhelpful thing to do; the notice says where it belongs.
    if (decrypting && next.trimStart().toUpperCase().startsWith("KMSHARE1:")) {
      setTextInputRejected(
        'That is a recovery share, not an encrypted container. Put the container here, ' +
        'then choose "Use recovery shares" beside the password field to enter it.'
      );
      setTextSecret(next);
      return;
    }

    // §7.2. A self-extracting page pasted here is the wrong-box paste that
    // section calls the likeliest of all, because the artefact looks least like
    // a backup: it is a web page, and someone who opens it and sees a password
    // box has no reason to think the bytes they need are in the same file.
    //
    // The rule is different from the share above, and deliberately so. §7.2 says
    // a reader that recognises the sentinels MUST *extract and proceed* rather
    // than report — a share in this box cannot be used here, but a page can, so
    // refusing it would be pedantry aimed at someone recovering an inheritance.
    if (decrypting && looksLikeSelfExtract(next)) {
      try {
        const recovered = armorKeym2(extractSelfExtract(next));
        setTextInputRejected(null);
        setTextSecret(recovered);
        toast({
          title: "Backup found inside that page",
          description:
            "That was a self-extracting Keymaker page. The container has been taken " +
            "out of it — type the password to open it.",
        });
      } catch (e) {
        // Structural, never routed through the AEAD: a page problem reported as
        // a decryption failure sends someone to retype a password that was
        // never wrong.
        setTextInputRejected((e as Error).message);
        setTextSecret(next);
      }
      return;
    }

    // §7.1. A part is not a container either, and the section requires a reader
    // to report *which* part it is holding rather than failing it as corrupt.
    // The encoding shipped with 4.2 and this report is what it specifies.
    if (decrypting && looksLikePaperPart(next)) {
      const part = describePaperPart(next.trim().split(/\s+/)[0] ?? "");
      setTextInputRejected(
        part
          ? `That is part ${part.index} of ${part.total} of a paper backup. Every one ` +
            `of the ${part.total} parts is needed — scan them all into this box, one per line.`
          : "That is one part of a paper backup. Every part is needed — scan them " +
            "all into this box, one per line."
      );
      setTextSecret(next);
      return;
    }

    setTextInputRejected(null);
    setTextSecret(next);
  }, [mode, toast]);

  const handlePasswordChange = useCallback((pwd: string) => {
    setPassword(pwd);
    // Any edit invalidates the entropy claim — it only holds for the exact
    // string the CSPRNG produced. The generators re-set the descriptor after
    // calling this.
    setGenerated(null);
  }, []);

  /**
   * Drop every piece of state that is a secret, or stands in for one.
   *
   * One function, because there were two and they disagreed. `resetState` and
   * the old `wipeSensitiveState` cleared overlapping-but-different sets, and each new
   * kind of secret had to be remembered in both — which is exactly how the
   * recovery-share state came to survive a reset while being cleared by a
   * wipe, and how a selected key file survived both.
   *
   * The rule for this list: if holding it would let someone open a container,
   * or reveal what is in one, it belongs here. That includes the input-mode
   * toggles — leaving `useShares` on after clearing the shares is harmless,
   * but leaving it on *without* clearing them is the bug this replaces, and a
   * single list is the only way to stop that distinction mattering.
   *
   * Settings the user chose — cipher, KDF, Argon2id cost — are deliberately
   * absent. A wipe is not a reset: someone who has just had the tool lock
   * itself wants their configuration still there when they come back.
   */
  /**
   * Stop the running derivation, keeping everything the user typed.
   *
   * `clearSensitiveState` already terminates the worker, but it also wipes the
   * password, the key file and the chosen container — correct for an auto-lock
   * and wrong for "this is taking too long". Someone who stops a slow unlock
   * wants to not-wait, not to start over.
   *
   * Until now the only way to halt a derivation was to switch input type,
   * which terminates the worker as a side effect of disowning the operation.
   * That works and nobody would ever find it. A container can ask for minutes
   * of work — measured at 315 s for eight PBKDF2 slots at the §6 ceiling — so
   * the way out has to be a button.
   */
  const cancelOperation = useCallback(() => {
    // Same two steps clearSensitiveState uses: move the counter so the
    // in-flight completion path goes quiet, then actually kill the worker.
    opSeqRef.current++;
    cancelAllCryptoWork();
    setIsLoading(false);
    setUnlockCostNotice(null);
    toast({
      title: "Stopped",
      description: "The unlock was cancelled. Your password and file are still here.",
    });
  }, [toast]);

  const clearSensitiveState = useCallback((opts?: { sparingIssuedShares?: boolean }) => {
    // Disown any operation still running. A KDF cannot be cancelled from here —
    // that needs the Worker in Phase 2 — but it can be made harmless: once the
    // counter moves, the in-flight operation's completion path goes quiet
    // instead of writing its result, its toast, and a password wipe into a UI
    // that has moved on.
    opSeqRef.current++;
    // Now a real cancel, not just a disowning. Terminating the worker stops the
    // derivation; before it moved off the main thread there was no way to halt
    // a synchronous WASM call, so an abandoned operation ran to completion
    // regardless, burning CPU and battery for a result nobody would receive.
    cancelAllCryptoWork();
    setIsLoading(false);

    // Credentials and key material.
    setPassword('');
    setGenerated(null);
    setShowPassword(false);
    setKeyFile(null);
    setUseKeyFile(false);

    // Inputs and outputs. `file` is here because a chosen file is the
    // plaintext: the auto-lock treated a loaded document as nothing at all.
    setFile(null);
    setTextSecret('');
    setTextInputRejected(null);
    setShowTextSecret(false);
    setTextSecretSeedStatus("none");
    setOutputText('');
    setShowDecryptedText(false);
    setDecryptInfo(null);
    setSlotTableWarning(false);
    setVerifyResult(null);

    // Anything rendering a secret.
    setIsQrModalOpen(false);
    setIsDecryptedQrModalOpen(false);
    setIsDecryptedQrRevealed(false);
    setDecryptedQrStatus({ kind: "idle" });

    // §4.6 and §4.7. Each of these is password-equivalent: k shares open the
    // container with no password at all, and the paper vault holds the
    // container and the shares laid out together for printing.
    setUsePasskey(false);
    setUseShares(false);
    setShareInput('');
    setShareInputRejected(null);
    setPaperVault(null);

    // `issuedShares` is the one thing here that cannot be got back.
    //
    // Everything else on this list is recoverable: a password can be retyped, a
    // file reselected, a container re-downloaded, pasted shares pasted again.
    // Freshly issued shares exist exactly once — the dialog says so, and the
    // share secret was dropped inside the worker the moment they were made.
    // Destroying them does not lock an attacker out of anything either: the
    // container still has the passphrase slot they were enrolled beside, so the
    // only thing lost is the inheritance path the user just set up.
    //
    // So an *explicit* act may destroy them — Wipe now, a reset, a mode change —
    // and a *timer* may not. The dialog exists to be read slowly onto paper, and
    // `lastActivityRef` moves on pointerdown, keydown, wheel and touchstart:
    // transcription produces none of those. Wiping on a five-minute idle is
    // therefore aimed precisely at the user who is doing the right thing.
    if (!opts?.sparingIssuedShares) setIssuedShares(null);
  }, []);

  /**
   * Clear the secrets *and* return the form to its defaults.
   *
   * The only thing this adds is the input-type reset, which is a layout
   * choice rather than a secret — so it is the one line that does not belong
   * in `clearSensitiveState`.
   */
  const resetState = useCallback(() => {
    clearSensitiveState();
    setInputType('file');
  }, [clearSensitiveState]);

  /**
   * Is there anything on screen worth locking?
   *
   * Arming the timer unconditionally would mean a blank page quietly running a
   * five-minute countdown and firing a "wiped" toast at someone who has typed
   * nothing. The timer exists for the state that matters — a password, a
   * plaintext secret, a decrypted result — so it only runs when that exists.
   */
  const hasSecretsOnScreen =
    password.length > 0 ||
    textSecret.length > 0 ||
    outputText.length > 0 ||
    // KM-R03. Share-only decryption is the case this predicate missed: an heir
    // has no password and may have decrypted a *file*, so all three of the
    // above can be empty while the textarea holds enough shares to open the
    // container. The timer was not armed and the Wipe now button was not
    // rendered — on the one flow where the person at the keyboard is least
    // likely to be at their own desk.
    shareInput.length > 0 ||
    issuedShares !== null ||
    paperVault !== null ||
    // A chosen file *is* the secret, and this predicate did not think so. Load
    // a passport scan into Encrypt, walk away, and no timer was armed and no
    // Wipe now button was rendered — the two things that exist for exactly
    // that moment. `keyFile` is the same argument with less ambiguity: it is
    // half the key material, sitting in a file input.
    //
    // Kept in step with `clearSensitiveState` by construction: this predicate
    // asks "is any of it set", that function sets all of it to empty, and both
    // lists are the same list. Adding a secret to one without the other is the
    // bug class that produced every entry above.
    file !== null ||
    keyFile !== null;

  const keepOpen = useCallback(() => {
    lastActivityRef.current = Date.now();
    setLockSecondsLeft(null);
  }, []);

  /**
   * Auto-lock on inactivity.
   *
   * Activity is tracked in a ref and sampled once a second, rather than each
   * event resetting a timer in state: pointer and key events fire constantly,
   * and re-rendering the whole tool on every one of them to service a
   * five-minute clock would be a poor trade.
   *
   * Only the final LOCK_WARN_SECONDS are rendered. Before that the countdown
   * exists but says nothing, so the common case — someone actively using the
   * tool — sees no chrome at all.
   */
  useEffect(() => {
    if (!hasSecretsOnScreen) {
      setLockSecondsLeft(null);
      return;
    }

    lastActivityRef.current = Date.now();
    const bump = () => {
      lastActivityRef.current = Date.now();
    };
    const events = ["pointerdown", "keydown", "wheel", "touchstart"] as const;
    for (const event of events) {
      window.addEventListener(event, bump, { passive: true });
    }

    const id = setInterval(() => {
      const left = Math.ceil((AUTO_LOCK_MS - (Date.now() - lastActivityRef.current)) / 1000);
      if (left <= 0) {
        setLockSecondsLeft(null);
        const sparedShares = issuedSharesRef.current !== null;
        clearSensitiveState({ sparingIssuedShares: true });
        toast({
          title: "Locked — secrets cleared",
          description: sparedShares
            ? `Nothing was touched for ${AUTO_LOCK_MS / 60_000} minutes, so the password and any decrypted output were wiped from memory. Your recovery shares are still on screen — they cannot be shown again, so only you can dismiss them. Your settings are unchanged.`
            : `Nothing was touched for ${AUTO_LOCK_MS / 60_000} minutes, so the password and any decrypted output were wiped from memory. Your settings are unchanged.`,
        });
        return;
      }
      setLockSecondsLeft(left <= LOCK_WARN_SECONDS ? left : null);
    }, 1000);

    return () => {
      for (const event of events) window.removeEventListener(event, bump);
      clearInterval(id);
    };
  }, [hasSecretsOnScreen, clearSensitiveState, toast]);

  const handleModeChange = useCallback((newMode: string) => {
    setMode(newMode as Mode);
    // The Tools tab has no shared state with encrypt/decrypt — resetting
    // would only wipe an in-progress form when the user peeks at Tools.
    if (newMode !== "tools") {
      resetState();
    }
  }, [resetState]);
  
  const handleInputTypeChange = useCallback((newType: string) => {
      // Same reasoning as resetState: an operation started against File mode
      // must not deliver its result into Text mode. This was the reproducible
      // half of the bug — switch input type mid-derivation and the finished
      // operation announced "Success!" on a panel that had never run it.
      opSeqRef.current++;
      cancelAllCryptoWork();
      setIsLoading(false);
      setInputType(newType as InputType);
      // Clear any previous result when the input type changes. The blur and
      // reveal controls on the decrypted output are scoped to text mode, so
      // carrying outputText across the switch would render a decrypted
      // secret fully visible with no way to re-hide it.
      setOutputText('');
      setShowDecryptedText(false);
      setDecryptInfo(null);
      setSlotTableWarning(false);
      setIsDecryptedQrModalOpen(false);
      setIsDecryptedQrRevealed(false);
      setDecryptedQrStatus({ kind: "idle" });
  }, []);

  /**
   * @param maxBytes Ceiling for this particular picker. Encrypting caps the
   *   *plaintext*; decrypting has to allow the container, which is larger by
   *   the header, salt, nonces and tags. Sharing one limit meant a file of
   *   exactly the maximum size could be encrypted and then rejected on the way
   *   back in — the picker refused the container before the crypto core, which
   *   does allow the overhead, ever saw it.
   */
  const handleFileChange = useCallback((
    e: ChangeEvent<HTMLInputElement> | DragEvent<HTMLDivElement>,
    setter: (file: File | null) => void,
    maxBytes: number = MAX_PLAINTEXT_SIZE,
    /** What the file is, when it is refused for being too big. A key file or a
     *  plaintext can be swapped for a smaller one; a container cannot. */
    oversized: "plaintext" | "container" = "plaintext"
  ) => {
    let selectedFile: File | null = null;
    if ('dataTransfer' in e) { // DragEvent
      selectedFile = e.dataTransfer.files?.[0] || null;
    } else { // ChangeEvent
      selectedFile = e.target.files?.[0] || null;
      if (e.target) {
        e.target.value = "";
      }
    }

    if (!selectedFile) {
        setter(null);
        return;
    }

    try {
      validateAndSanitizeFile(selectedFile);
    } catch (error: any) {
        toast({
            title: "Invalid File",
            description: error.message,
            variant: "destructive",
        });
        setter(null);
        return;
    }
    
    if (selectedFile.size > maxBytes) {
      // "Pick a smaller file" is right for a file you are about to encrypt and
      // wrong for one you are trying to open: a backup has no smaller version,
      // and the reference decryptor has no size limit. Same rejection, two
      // completely different next steps.
      toast({
        title: oversized === "container" ? "Too large for this app" : "File Too Large",
        description:
          oversized === "container"
            ? oversizeRecoveryHelp()
            : `Please select a file smaller than ${Math.floor(maxBytes / 1024 / 1024)}MB.`,
        variant: "destructive",
      });
      setter(null);
      return;
    }

    setter(selectedFile);
  }, [toast]);
  

  const generatePassword = useCallback(() => {
    const charset = PASSWORD_CHARSET;
    const passwordLength = PASSWORD_LENGTH;
    const charsetLength = charset.length;
    // Rejection sampling: discard values that would cause modulo bias.
    // limit is the largest multiple of charsetLength that fits in a Uint32.
    // This is what makes the entropy figure below exact rather than
    // approximate — every character is uniform over the charset.
    const limit = Math.floor(0x100000000 / charsetLength) * charsetLength;
    let newPassword = "";
    while (newPassword.length < passwordLength) {
      const array = new Uint32Array(passwordLength - newPassword.length);
      window.crypto.getRandomValues(array);
      for (let i = 0; i < array.length && newPassword.length < passwordLength; i++) {
        if (array[i]! < limit) {
          newPassword += charset.charAt(array[i]! % charsetLength);
        }
      }
    }
    handlePasswordChange(newPassword);
    // Record that *this* password came from the CSPRNG. Any subsequent typing
    // clears the descriptor (see handlePasswordChange), because the entropy
    // claim only holds for the exact string we generated.
    setGenerated({ kind: "password", bits: PASSWORD_ENTROPY_BITS });
    toast({
      title: "Password generated",
      description: `${passwordLength} random characters — ${PASSWORD_ENTROPY_BITS} bits of entropy.`,
    });
  }, [toast, handlePasswordChange]);

  const generatePassphrase = useCallback(() => {
    const listSize = EFF_LARGE_WORDLIST_SIZE;
    // Rejection sampling, the same shape as generatePassword above and for the
    // same reason: 2^32 is not a multiple of 7,776, so a bare modulus would
    // make the first 4,096 words very slightly likelier than the rest and the
    // figure below would become an upper bound rather than the count.
    const limit = Math.floor(0x100000000 / listSize) * listSize;
    const words: string[] = [];
    while (words.length < PASSPHRASE_WORDS) {
      const array = new Uint32Array(PASSPHRASE_WORDS - words.length);
      window.crypto.getRandomValues(array);
      for (let i = 0; i < array.length && words.length < PASSPHRASE_WORDS; i++) {
        if (array[i]! < limit) {
          words.push(EFF_LARGE_WORDLIST[array[i]! % listSize]!);
        }
      }
    }
    handlePasswordChange(words.join(PASSPHRASE_SEPARATOR));
    setGenerated({
      kind: "passphrase",
      words: PASSPHRASE_WORDS,
      bits: PASSPHRASE_ENTROPY_BITS,
    });
    toast({
      title: "Passphrase generated",
      description: `${PASSPHRASE_WORDS} words from the EFF long list — ${PASSPHRASE_ENTROPY_BITS} bits of entropy.`,
    });
  }, [toast, handlePasswordChange]);


  /** Overwrite the clipboard now and stop the countdown. */
  const clearClipboardNow = useCallback(async () => {
    setClipboardDeadline(null);
    try {
      await navigator.clipboard.writeText('');
    } catch {
      // Writing needs document focus. Nothing useful to say here — the
      // countdown is already gone and the user asked for this explicitly.
    }
  }, []);

  const handleCopy = useCallback((textToCopy: string) => {
    if (!textToCopy) return;
    navigator.clipboard.writeText(textToCopy).then(() => {
      // Says what it can do, not what the user wants to hear.
      //
      // The timer overwrites the *current* clipboard entry, and that is the
      // whole of what a web page is able to reach. Windows Clipboard History
      // (Win+V), macOS clipboard managers, Gboard's history and cloud
      // clipboard sync all keep their own copy, and none of them is
      // addressable — or even detectable — from JavaScript. The previous
      // wording promised the secret would be "overwritten in 60 seconds", full
      // stop, which for anyone with history enabled is a promise the platform
      // breaks: one Win+V and one scroll recovers a seed phrase from a machine
      // its owner had been told was clean.
      toast({
        title: "Copied to clipboard",
        description:
          `This entry is overwritten in ${CLIPBOARD_CLEAR_SECONDS} seconds. If your ` +
          `system keeps clipboard history — Windows Win+V, a clipboard manager, ` +
          `phone keyboard history — it keeps its own copy, and no website can clear that.`,
      });
      setClipboardDeadline(Date.now() + CLIPBOARD_CLEAR_SECONDS * 1000);
    }).catch(() => {
       toast({ title: "Failed to copy", variant: "destructive" });
    });
  }, [toast]);

  const generateKeyFile = useCallback(() => {
    const keyData = new Uint8Array(64);
    window.crypto.getRandomValues(keyData);
    const blob = new Blob([keyData], { type: 'application/octet-stream' });
    triggerDownload(blob, 'keymaker-key.bin');
    toast({ title: "Key File Generated", description: "Your new key file has been downloaded." });
  }, [toast]);

  // High-res QR download: renders at 900px (≈3" at 300 DPI) with quiet zone padding
  const hiResQrRef = useRef<HTMLDivElement>(null);

  const handleDownloadQrCode = useCallback(() => {
    if (!hiResQrRef.current) return;
    const hiResCanvas = hiResQrRef.current.querySelector('canvas');
    if (!hiResCanvas) return;

    // Add a quiet zone (padding) around the QR — 4 modules is standard,
    // but we use a generous fixed margin for clean printing
    const PADDING = 60; // ~60px at 900px ≈ a comfortable quiet zone
    const exportCanvas = document.createElement('canvas');
    const ctx = exportCanvas.getContext('2d');
    if (!ctx) return;

    exportCanvas.width = hiResCanvas.width + PADDING * 2;
    exportCanvas.height = hiResCanvas.height + PADDING * 2;

    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, exportCanvas.width, exportCanvas.height);
    ctx.drawImage(hiResCanvas, PADDING, PADDING);

    exportCanvasPng(exportCanvas, "encrypted-qr.png");

    toast({ title: "QR Code downloaded", description: "High-resolution (300 DPI / 1020×1020px)" });
  }, [toast]);

  // Decrypted-QR download: exports a 1024×1024 PNG from a hidden hi-res
  // canvas. The hidden canvas is only mounted while the QR is revealed, and
  // it bakes in a spec-compliant 4-module quiet zone via marginSize={4}.
  const decryptedQrHiResRef = useRef<HTMLDivElement>(null);

  const handleDownloadDecryptedQr = useCallback(() => {
    const srcCanvas = decryptedQrHiResRef.current?.querySelector('canvas');
    if (!srcCanvas) return;

    // qrcode.react scales its canvas by devicePixelRatio, so the physical
    // pixel size varies by display. Normalize to exactly 1024×1024 by
    // drawing onto a fixed-size export canvas (integer downscale of a
    // binary image stays crisp).
    const exportCanvas = document.createElement('canvas');
    exportCanvas.width = 1024;
    exportCanvas.height = 1024;
    const ctx = exportCanvas.getContext('2d');
    if (!ctx) return;
    ctx.imageSmoothingEnabled = false;
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, 1024, 1024);
    ctx.drawImage(srcCanvas, 0, 0, 1024, 1024);

    const isSeed = decryptedQrStatus.kind === 'seed';
    exportCanvasPng(exportCanvas, isSeed ? 'keymaker-seedqr.png' : 'keymaker-qr.png');

    toast({
      title: isSeed ? 'SeedQR downloaded' : 'QR Code downloaded',
      description: '1024×1024 PNG. It encodes your decrypted secret — store it as carefully as the secret itself.',
    });
  }, [toast, decryptedQrStatus.kind]);

  const processData = useCallback(async () => {
    // Reentrancy guard.
    //
    // The Process button disables itself while `isLoading`, but that only
    // covers the button. Keyboard submit, a double-fire, or any future caller
    // reaches this function directly, and a second derivation racing the first
    // produces exactly the state corruption the sequence guard below exists to
    // prevent — so refuse at the door as well.
    if (isLoading) return;

    // Claim this operation's sequence number.
    //
    // Everything after an `await` here runs in a world that may have moved on:
    // the user can switch tab, switch File/Text, or start typing a new password
    // while Argon2id is grinding for several seconds. When that happened, the
    // stale operation still ran its completion path — writing output and firing
    // a "Success!" toast onto whichever tab was now showing, and, worst of all,
    // hitting the `setPassword('')` in its `finally` and wiping a password the
    // user had typed in the meantime.
    //
    // `resetState` and every mode/input switch bump this counter, so a stale
    // operation can detect that it no longer speaks for the UI and fall silent.
    const opId = ++opSeqRef.current;
    const isStale = () => opSeqRef.current !== opId;

    // This operation has not been priced yet. Without the reset, a previous
    // slow container's notice would still be in state, and the render gate is
    // only `isLoading` — so the next unlock, however cheap, would display the
    // last one's warning while it ran.
    setUnlockCostNotice(null);

    let mutablePassword = password;
    // Set when a legacy IttyBitz container is opened, so the completion toast
    // can mention it (see below).
    let legacyNotice = false;

    const hasInput = inputType === 'file' ? !!file : !!textSecret;
    if (!hasInput) {
      toast({
        title: `Missing ${inputType === 'file' ? 'File' : 'Text'}`,
        description: `Please provide a ${inputType} to process.`,
        variant: "destructive",
      });
      return;
    }
    // §4.6. Shares are a credential in their own right on the decrypt side —
    // an heir has no password, which is the entire point of the feature. This
    // guard predates share sets and would have made the inheritance path
    // unreachable while every control leading to it looked live.
    const suppliedShares =
      mode === "decrypt" && useShares ? shareLines : [];
    // §4.7 joins §4.6 in the same guard, for the same reason: someone unlocking
    // with a passkey has no password either, and the credential does not exist
    // yet at this point — it is produced by tapping the key further down.
    const unlockingWithPasskey = mode === "decrypt" && usePasskey;

    /**
     * The single exit for a successful operation.
     *
     * Every success path has to erase the plaintext buffer and drop the
     * credentials that opened it, and three paths were doing that three
     * different amounts. Verify-only zeroed the buffer and left the password
     * and the pasted shares sitting there. The non-UTF-8 path — added to stop
     * plaintext being mangled — returned before all of it, so the one branch
     * whose entire purpose is handling raw plaintext carefully was the branch
     * that left the plaintext un-zeroed.
     *
     * The buffer is a parameter rather than a captured variable so this can be
     * declared before `resultBuffer` is assigned, and so no path can call it
     * having forgotten which buffer it meant.
     */
    const finishOperation = (
      buffer: ArrayBuffer,
      notice: { title: string; description: string }
    ) => {
      // Best-effort erase now that the contents have been handed off: Blob
      // construction copies the bytes, and the decoded string and base64
      // output are separate allocations. Matters most on decrypt, where this
      // held the plaintext.
      new Uint8Array(buffer).fill(0);

      // B1: an operation the user has moved on from announces nothing and
      // wipes nothing. The erase above is unconditional because the buffer is
      // ours either way; everything below touches UI the user may have
      // refilled since.
      if (isStale()) return;
      toast(notice);

      // §4.6. Shares that have done their job are still password-equivalent,
      // and an heir who has just recovered a container has no reason to leave
      // k of them in a textarea.
      if (suppliedShares.length > 0) setShareInput('');

      // U13. Success only. A failed attempt keeps what was typed, because
      // retyping a 24-character password after a typo is the pressure that
      // pushes people towards shorter ones — and a wrong password is not the
      // secret anyway. The exposure window stays bounded by the auto-lock and
      // the panic wipe.
      setPassword('');
    };
    if (!mutablePassword && suppliedShares.length === 0 && !unlockingWithPasskey) {
        toast({
          title: mode === "decrypt" && useShares ? "Shares Required" : "Password Required",
          description:
            mode === "decrypt" && useShares
              ? "Paste at least the number of shares the container needs, one per line."
              : "Please provide a password.",
          variant: "destructive",
        });
        return;
    }


    if (mode === "encrypt" && !meetsPasswordPolicy(mutablePassword, generated !== null)) {
        toast({
          title: "Weak Password",
          description: "Use at least 24 characters with mixed character classes, or a 4+ word passphrase (diceware-style).",
          variant: "destructive",
        });
        return;
    }

    setIsLoading(true);
    setOutputText('');
    setShowDecryptedText(false);
    setDecryptInfo(null);
    setSlotTableWarning(false);
    setVerifyResult(null);
    setDecryptedQrStatus({ kind: "idle" });

    // Verify-only is a decrypt-side control; it must not silently apply to an
    // encrypt run if the user toggles it and then switches mode.
    const verifying = mode === 'decrypt' && verifyOnly;

    try {
      const keyFileBuffer = keyFile ? await keyFile.arrayBuffer() : null;

      let resultBuffer: ArrayBuffer;

      if (mode === 'encrypt') {
        const kdf: KdfParams =
          kdfChoice === "argon2id"
            ? {
                kdf: KdfId.ARGON2ID,
                params: {
                  timeCost: argonTimeCost,
                  memoryKiB: argonMemoryMiB * 1024,
                  parallelism: argonParallelism,
                },
              }
            : { kdf: KdfId.PBKDF2, params: { iterations: 1_000_000 } };

        const encoder = new TextEncoder();
        const inputBuffer = inputType === 'file' ? await file!.arrayBuffer() : (encoder.encode(textSecret).buffer as ArrayBuffer);
        // §4.7. The authenticator has to be asked *here*, on the main thread,
        // before any work is handed over: a Worker cannot reach
        // navigator.credentials. The slot salt is chosen first because the PRF
        // salt derives from it, so the question put to the key depends on a
        // value the container does not yet contain.
        let passkey: { prfOutput: Uint8Array; salt: Uint8Array } | undefined;
        if (passkeyEnabled) {
          const { derivePrfSalt } = await import("@/lib/keym-v2");
          const { enrolPasskey } = await import("@/lib/webauthn-prf");
          const slotSalt = crypto.getRandomValues(new Uint8Array(32));
          const prfOutput = await enrolPasskey(await derivePrfSalt(slotSalt));
          passkey = { prfOutput, salt: slotSalt };
        }

        // §4.6. Requested in the same call that writes the container, so the
        // share secret is generated and dropped inside the worker and the
        // password is not held past the operation that already needed it.
        const encrypted = await encryptViaWorker(
          inputBuffer,
          mutablePassword,
          keyFileBuffer,
          { kdf, cipher: cipherChoice },
          shamirEnabled ? { threshold: shamirThreshold, count: shamirCount } : undefined,
          passkey
        );
        resultBuffer = encrypted.data;
        if (encrypted.shares && !isStale()) {
          // Straight to the modal. These exist exactly once — nothing can
          // reissue them — so they must not be left to be noticed.
          setIssuedShares({ threshold: shamirThreshold, shares: encrypted.shares });
        }

        if (inputType === 'file') {
            const blob = new Blob([resultBuffer]);
            const outName = obscureFilename
              ? `keymaker-${randomFilenameSuffix()}.keym`
              : `${file!.name}.keym`;
            if (isStale()) return;
            triggerDownload(blob, outName);
            setFile(null);
        } else {
            if (isStale()) return;
            // §7's armor: base64url, unpadded, so the blob survives being
            // pasted into a URL, a filename or a QR code without escaping —
            // and so nobody has to strip `=` by hand from a backup they are
            // trying to recover. Dynamically imported for the same reason the
            // crypto core imports it that way.
            const { armorKeym2 } = await import("@/lib/keym-v2");
            setOutputText(armorKeym2(new Uint8Array(resultBuffer)));
            setTextSecret('');
        }

      } else { // Decrypt — the KEYM container is self-describing, and legacy
        // IttyBitz (IBTZ) blobs are auto-detected and handled transparently.
        let inputBuffer: ArrayBuffer;
        if (inputType === 'file') {
            inputBuffer = await file!.arrayBuffer();
        } else {
            let blobText = textSecret.trim();

            // Bound the *encoded* length before decoding, whichever encoding it
            // turns out to be. atob() plus the byte-copy allocates roughly 1.75x
            // the string before decryptData() has a buffer it can measure, so
            // the core size check cannot protect this step — only preceding it
            // can. This is checked before the prefix is stripped rather than
            // after, so it cannot be skipped by a paste that has no prefix.
            if (blobText.length > MAX_BASE64_INPUT_CHARS) {
              // Typed, so a size limit is reported as a size limit. As a plain
              // Error this fell through the catch below and told the user their
              // password might be wrong — about a paste they could see was huge.
              throw new KeymakerError("too-large", oversizeRecoveryHelp());
            }

            let bytes: Uint8Array;
            if (blobText.startsWith(KEYM_V2_TEXT_PREFIX)) {
              // Case-sensitive and byte-exact — see the note on the constants.
              // Also base64url rather than base64, so this cannot go through
              // base64ToUint8Array.
              const { dearmorKeym2 } = await import("@/lib/keym-v2");
              bytes = dearmorKeym2(blobText);
            } else {
              if (blobText.toUpperCase().startsWith(KEYM_V1_TEXT_PREFIX)) {
                blobText = blobText.slice(KEYM_V1_TEXT_PREFIX.length);
              }
              bytes = base64ToUint8Array(blobText);
            }
            inputBuffer = bytes.buffer as ArrayBuffer;
        }

        // Copy the header before the call. The buffer is transferred to the
        // worker, which detaches it here — reading it afterwards would yield
        // zero bytes and the format readback below would silently go blank.
        //
        // 1 KiB, not the 128 bytes this used to take. 128 covered the largest
        // KEYM v1 header (71) with room to spare, but a v2 slot table is
        // 9 + slot_count x 96 bytes and reaches 777 at the eight slots §6
        // allows. Pricing the unlock below needs all of them, and a peek that
        // stopped short would silently price only the slots it happened to
        // see — reporting a cheap unlock for the expensive container this is
        // for.
        const headerPeek = new Uint8Array(inputBuffer.slice(0, Math.min(1024, inputBuffer.byteLength)));

        // Say so before the wait, not after it.
        //
        // Everything below this line is the unlock: the worker call, the KDF
        // for every slot a password could match, and only then a result. A
        // container can honestly ask for minutes of that, and until now the
        // app gave no sign until it was over. This is the one moment the cost
        // is knowable — it is declared in the header — and not yet spent.
        // No format check: keym2UnlockCost parses a v2 core header and returns
        // null for anything else, so a v1 container or a stray blob is simply
        // priced at nothing. Checking `decryptResult.format` here would be
        // reading a variable the worker has not produced yet — the whole point
        // is that this runs first.
        {
          const { keym2UnlockCost, describeUnlockCost } = await import("@/lib/keym-v2");
          const notice = describeUnlockCost(keym2UnlockCost(headerPeek));
          if (notice && !isStale()) setUnlockCostNotice(notice);
        }

        // §4.7. A passkey unlock reads before it asks. The PRF salt derives
        // from the slot's own salt, so the container has to be parsed, the
        // passkey slot found and its salt turned into a question before the
        // authenticator has anything to answer — the reverse of every other
        // unlock, where the secret comes first.
        //
        // The *first* passkey slot is used, not all of them. Nothing in the
        // container says which key belongs to which slot (§4.7 stores no
        // identifier), so trying several would mean one authenticator tap per
        // slot, most of them wrong, with no way to explain why. One tap against
        // one slot fails the same way a wrong password does, which is at least
        // a failure the user already understands. Containers with more than one
        // enrolled passkey are the case this does not serve; enrol the second
        // key on its own copy until that changes.
        let prfOutput: Uint8Array | undefined;
        if (usePasskey) {
          const { passkeySlotSaltsKeym2, derivePrfSalt } = await import("@/lib/keym-v2");
          const { assertPasskeyPrf } = await import("@/lib/webauthn-prf");
          const salts = passkeySlotSaltsKeym2(new Uint8Array(inputBuffer));
          if (salts.length === 0) {
            throw new KeymakerError(
              "invalid-input",
              "This container has no passkey enrolled. Unlock it with its password."
            );
          }
          prfOutput = await assertPasskeyPrf(await derivePrfSalt(salts[0]!));
        }

        const decryptResult = await decryptViaWorker(
          inputBuffer,
          mutablePassword,
          keyFileBuffer,
          suppliedShares.length > 0 ? suppliedShares : undefined,
          prfOutput
        );
        resultBuffer = decryptResult.data;

        // Info line + legacy-format nudge.
        //
        // 6.1. These name a *container*, so they carry the format's name and
        // not the application's. "Keymaker v2" became ambiguous the moment the
        // app's own version reached 2.0.0: `Format: Keymaker v2` gives a reader
        // no way to tell whether it describes the file they just opened or the
        // program that opened it — and this line is exactly where someone looks
        // when a file will not open. The legacy labels below already carry
        // their own format's name, which is why they never had the problem.
        const formatLabels: Record<DetectedFormat, string> = {
          "keym-v1": "KEYM v1",
          "keym-v2": "KEYM v2",
          "keym-v3": "KEYM v3",
          "ibtz-v1": "IttyBitz v1 (legacy)",
          "ibtz-v0": "IttyBitz v0 (legacy)",
        };
        let info = `Format: ${formatLabels[decryptResult.format]}`;
        // Set when the container was written with derivation parameters weaker
        // than this version would use. It changes nothing about the decryption
        // that just succeeded — the file opened, on the terms it was written —
        // and is appended below purely so the owner knows to consider
        // re-encrypting rather than inheriting the weakness unaware.
        // Taken from the reader, which knows which slot answered. It used to be
        // taken from `inspect…(headerPeek)`, which reads slot 0 — correct for
        // the one-slot containers this app writes, and wrong for every other
        // shape: unlock a two-slot container with the heir's share set and the
        // advisory described the owner's passphrase slot. Worse, an attacker
        // who can reorder a table chooses which slot is at index 0, and so
        // chooses which KDF the owner is told about.
        //
        // The labels beside it still come from the header. Those describe the
        // *container* — its cipher, its slot count — which is a property of the
        // file rather than of the way in, and slot 0's KDF label is the
        // conventional summary of it.
        const weakKdf = decryptResult.weakKdf;
        if (decryptResult.format === "keym-v1") {
          const inspected = inspectKeym(headerPeek);
          if (inspected) info += ` · ${inspected.kdfLabel} · ${inspected.cipherLabel}`;
        } else if (
          decryptResult.format === "keym-v2" ||
          decryptResult.format === "keym-v3"
        ) {
          // One inspector for both: every field it reads sits at a
          // version-dependent offset it already resolves from the header.
          const { inspectKeym2 } = await import("@/lib/keym-v2");
          const inspected = inspectKeym2(headerPeek);
          if (inspected) {
            info += ` · ${inspected.kdfLabel} · ${inspected.cipherLabel}`;
            // Only worth saying when it is not the one-slot case every
            // container this version writes has.
            if (inspected.slots > 1) info += ` · ${inspected.slots} slots`;
          }
        }
        if (weakKdf) {
          info +=
            ` — Heads up: this backup was made with ${weakKdf}. It opened fine and ` +
            `its contents are intact. Re-encrypting it here would store the same ` +
            `secret behind today's stronger settings.`;
        }
        if (decryptResult.keyFileUsed) info += " · key file";
        if (isStale()) return;
        setDecryptInfo(info);
        // v3 §5.2. `false` only ever arrives after a slot has already opened
        // and the payload has already authenticated, so this reports on the
        // container's *recovery options*, never on the data. It deliberately
        // does not say which slot changed: the MAC covers the table as a whole
        // and the sealed table is not recoverable from the tampered one, so
        // "something changed" is the whole of what is known.
        setSlotTableWarning(decryptResult.slotTableAuthentic === false);

        if (verifying) {
          // Reaching this line *is* the result: decryptViaWorker throws unless
          // the AEAD tag verifies, so the container is intact and the password
          // and key file are right.
          //
          // Everything the non-verifying path does with the plaintext —
          // rendering it, encoding it to base64, building a Blob, downloading
          // it, running the BIP-39 detector over it — is skipped. The byte
          // count is reported because "it opens, and it is the size you
          // expect" catches a class of mistake that a bare tick does not: the
          // right password on the wrong backup.
          setVerifyResult({ detail: info, bytes: resultBuffer.byteLength });
          finishOperation(resultBuffer, {
            title: "Verified — the backup opens",
            description: "The contents were checked and discarded without being shown.",
          });
          return;
        }
        // Deliberately not a toast of its own. TOAST_LIMIT is 1, so the
        // unconditional "Success!" below replaced this one the instant it
        // appeared and nobody ever read the re-encryption nudge. One toast,
        // both facts.
        // Names the IttyBitz formats rather than "anything that is not v1",
        // because the toast this drives says "This was a legacy IttyBitz file".
        // The old condition was correct only while v1 was the sole KEYM version
        // in existence; the moment v2 containers appear it starts telling
        // people their brand-new file came from IttyBitz.
        legacyNotice = decryptResult.format === "ibtz-v1" || decryptResult.format === "ibtz-v0";

        if (inputType === 'file') {
             const stripped = file!.name.replace(/\.(keym|ibitz)$/i, '');
             const resultFilename = stripped !== file!.name
              ? stripped
              : `decrypted-${file!.name}`;
            const blob = new Blob([resultBuffer]);
            triggerDownload(blob, resultFilename);
        } else {
            // KM-R08. Fatal, because the default replaces every malformed byte
            // with U+FFFD and reports success. A container written by another
            // conforming implementation may hold arbitrary bytes; decoding
            // those leniently hands the user irreversibly mangled data under a
            // green tick, which is the worst failure this app can produce —
            // the plaintext authenticated, and then we broke it.
            let decryptedText: string;
            try {
              decryptedText = new TextDecoder("utf-8", { fatal: true }).decode(resultBuffer);
            } catch {
              // The bytes are verified and in hand. Making the user derive the
              // key a second time in File mode to get at them would be a
              // pointless second Argon2id run, so hand them over now and say
              // plainly what happened.
              if (isStale()) return;
              triggerDownload(new Blob([resultBuffer]), "decrypted.bin");
              finishOperation(resultBuffer, {
                title: "Decrypted, but not text",
                description:
                  "This container holds bytes that are not valid UTF-8, so there is nothing to show. " +
                  "It decrypted and authenticated correctly — the contents have been downloaded as decrypted.bin.",
              });
              return;
            }
            setOutputText(decryptedText);

            // Detect whether the decrypted text is a valid BIP-39 mnemonic —
            // this only labels the QR button and picks the SeedQR encoding.
            // Best-effort: if the lazy module can't load (e.g. offline before
            // the chunk was cached), treat the output as plain text rather
            // than failing the decryption.
            try {
              const { validateBip39 } = await loadBip39();
              const result = await validateBip39(decryptedText);
              if (isStale()) return;
              setDecryptedQrStatus(
                result.valid
                  ? { kind: "seed", words: result.words }
                  : { kind: "plain", seedShaped: result.seedShaped }
              );
            } catch {
              if (isStale()) return;
              setDecryptedQrStatus({ kind: "plain", seedShaped: false });
            }
        }
      }

      // The ordinary success path. Everything it used to do inline — erase the
      // buffer, announce, drop the shares, drop the password — now lives in
      // `finishOperation`, which the verify-only and non-text paths call too.
      // That is the point: three exits, one definition of "cleaned up".
      const done = `Your ${inputType} has been successfully ${mode === 'encrypt' ? 'encrypted' : 'decrypted'}.`;
      finishOperation(resultBuffer, {
        title: legacyNotice ? "Decrypted — legacy container" : "Success!",
        description: legacyNotice
          ? `${done} This was a legacy IttyBitz file; consider re-encrypting it in Keymaker format.`
          : done,
      });
    } catch (error: unknown) {
        // Which failures may be shown verbatim is decided by the crypto core's
        // error *type*, not by matching its message text here.
        //
        // The previous exact-match array could never match an interpolated
        // message, so "KDF parameter out of range: PBKDF2 iterations is
        // 10000001, expected 1..10000000" — a tampered container — fell through
        // to "the password may be incorrect". Same for an oversized paste. The
        // app told people their password was wrong when their file was broken.
        //
        // KeymakerError is only ever raised for structural or configuration
        // faults, which describe the file or the call rather than the secret.
        // A genuine authentication failure is a plain Error and still collapses
        // to one generic string, so wrong-password and corrupt-ciphertext stay
        // indistinguishable.
        const safeMessage = isUserFacingError(error)
          ? error.message
          : mode === 'decrypt'
            ? 'Decryption failed. The password or key file may be incorrect, or the data may be corrupted.'
            : 'Processing failed. Please try again.';

        if (!isStale()) {
          toast({
              title: "Processing Error",
              description: safeMessage,
              variant: "destructive",
          });
        }
    } finally {
      // Only the operation that still owns the UI may touch it — a stale one
      // writing here is the data-loss half of B1. The password clear moved to
      // the success path (U13); the spinner has to come down on every outcome,
      // so it stays.
      if (!isStale()) {
        setIsLoading(false);
      }
    }
    // §4.6 additions: useShares, shareInput, shamirEnabled, shamirThreshold and
    // shamirCount. Omitting them left processData closing over the values from
    // the render before the user touched any of them, so the share path took
    // the no-credential exit while every control leading to it looked live —
    // a click that did nothing at all, with no error to explain it.
  }, [file, mode, keyFile, toast, inputType, textSecret, password, generated, kdfChoice, argonTimeCost, argonMemoryMiB, argonParallelism, cipherChoice, obscureFilename, isLoading, verifyOnly, useShares, shareInput, shamirEnabled, shamirThreshold, shamirCount, passkeyEnabled, usePasskey]);
  
  const handleUseKeyFileChange = useCallback((checked: boolean) => {
      setUseKeyFile(checked);
      if (!checked) {
          setKeyFile(null);
      }
  }, []);

  const getPasswordStrengthColor = useCallback(() => {
    if (!password) return "border-input";
    if (meetsPasswordPolicy(password)) return "border-success";
    return "border-destructive";
  }, [password]);

  /**
   * U15. The button is disabled by policy and says nothing about why.
   *
   * The requirements are in the InfoTip beside the Password label, and the
   * toast that spells them out only fires from `processData` — which a disabled
   * button cannot reach. So the one moment the explanation is needed is the one
   * moment nothing offers it, and the user is left with a dead control.
   *
   * Gated on a non-empty password deliberately: before anything is typed the
   * button is disabled for the obvious reason, and saying so would be nagging
   * rather than explaining.
   */
  const blockedByPasswordPolicy = mode === "encrypt" && !!password && !passwordMeetsPolicy;

  const isProcessButtonDisabled = () => {
    if (isLoading || !isCryptoAvailable) return true;
    const hasInput = inputType === 'file' ? !!file : !!textSecret;
    // §4.6. An heir holds shares and no password, so shares are a credential
    // in their own right — requiring a password here would leave the one flow
    // this feature exists for permanently unreachable.
    const hasCredential =
      !!password ||
      (mode === 'decrypt' && useShares && shareLines.length > 0) ||
      // §4.7. The credential is a tap that has not happened yet, so the button
      // has to be live before it exists — otherwise the only control leading to
      // a passkey unlock is disabled by the absence of the thing it produces.
      (mode === 'decrypt' && usePasskey);
    if (!hasInput || !hasCredential) return true;

    if (mode === 'encrypt' && !passwordMeetsPolicy) {
        return true;
    }

    return false;
  }

  const inputTypePillClasses = (active: boolean) => cn(
    "flex-1 cursor-pointer rounded-lg px-3 py-2 text-center text-[13px] font-medium transition-all",
    active ? "bg-white/10 text-foreground shadow-xs" : "text-muted-foreground hover:text-foreground"
  );

  // Key-file toggle + picker/generator. Rendered in place on the Decrypt
  // tab and inside the Advanced section on the Encrypt tab.
  const keyFileControls = (
    <>
      <div className="flex items-center gap-3 py-1">
        <Switch
          id="use-keyfile"
          checked={useKeyFile}
          onCheckedChange={handleUseKeyFileChange}
          className="data-[state=checked]:bg-success"
        />
        <div className="flex items-center gap-1.5">
          <Label htmlFor="use-keyfile" className="cursor-pointer text-sm text-foreground">
            Use key file <span className="text-muted-foreground">(optional)</span>
          </Label>
          <InfoTip label="What is a key file?">
            <p>For additional security, you can use a key file. Use the generator to create a new, highly secure key file (recommended), or select an existing file. This file will be required along with your password to decrypt data.</p>
          </InfoTip>
        </div>
      </div>

      {useKeyFile && (
        <div className="animate-in fade-in-50 space-y-3">
          <FileSelector
            id={`${mode}-keyfile`}
            onFileChange={(e) => handleFileChange(e, setKeyFile)}
            onClear={() => setKeyFile(null)}
            selectedFile={keyFile}
            icon={<KeyRound size={22} />}
            label="Select key file"
            description="Drag & drop or click to select an existing file"
          />
          <div className="flex items-center gap-3">
            <hr className="grow border-t border-white/10" />
            <span className="text-[12px] font-medium uppercase tracking-wider text-muted-foreground">or</span>
            <hr className="grow border-t border-white/10" />
          </div>
          <Button
            variant="outline"
            className="w-full rounded-xl border-white/10 bg-white/4 py-2.5 text-sm font-medium text-foreground hover:bg-white/8"
            onClick={generateKeyFile}
          >
            <Download className="mr-2 h-4 w-4" />
            Generate & download new key file
          </Button>
        </div>
      )}
    </>
  );

  const renderContent = (currentMode: Mode) => (
    <div className="space-y-5">
      <div className="space-y-5">
        <div className="flex gap-0.5 rounded-xl bg-white/4 p-1">
          <button
            type="button"
            onClick={() => handleInputTypeChange('file')}
            className={inputTypePillClasses(inputType === 'file')}
          >
            File
          </button>
          <button
            type="button"
            onClick={() => handleInputTypeChange('text')}
            className={inputTypePillClasses(inputType === 'text')}
          >
            Text
          </button>
        </div>

        {inputType === 'file' ? (
          <FileSelector
            id={`${currentMode}-file`}
            onFileChange={(e) =>
              handleFileChange(
                e,
                setFile,
                // Decrypting accepts the container, which is larger than the
                // plaintext it holds by header + salt + nonces + tags.
                currentMode === 'decrypt' ? MAX_CONTAINER_SIZE : MAX_PLAINTEXT_SIZE,
                currentMode === 'decrypt' ? 'container' : 'plaintext'
              )
            }
            onClear={() => setFile(null)}
            selectedFile={file}
            icon={<FileText size={22} />}
            label="Drop a file here"
            description={`or click to browse · ${Math.floor(MAX_PLAINTEXT_SIZE / 1024 / 1024)} MB max`}
          />
        ) : (
          <div className="space-y-2">
            <div className="flex items-center justify-between gap-3">
              <Label htmlFor="text-secret" className="text-[13px] font-medium text-muted-foreground">
                Secret text
              </Label>
              {/*
                The recovery-phrase check, said out loud instead of only tinted.

                This was a border colour and nothing else: green for a valid
                BIP-39 phrase, red for one that is phrase-shaped but has a word
                the list does not contain. That red border is the warning that
                a word has been mistyped *before* it gets encrypted into a
                backup someone may not open for a decade — and roughly one man
                in twelve cannot distinguish it from the green one. A screen
                reader got nothing at all.

                It was colour-only on purpose: the original note reasoned that
                a text badge would tell someone reading over your shoulder that
                the blurred field holds a seed phrase. That concern is real but
                it does not bite here, because the indicator only appears for
                phrase-shaped input in the first place — an icon leaks exactly
                what the coloured border already leaked, no more. The wording
                is kept deliberately generic for the same reason: "a word isn't
                recognised" is a spellcheck result, not an announcement that
                this is a wallet seed.
              */}
              {currentMode === 'encrypt' && textSecretSeedStatus !== 'none' && (
                <span
                  id="text-secret-seed-status"
                  role="status"
                  className={cn(
                    "flex shrink-0 items-center gap-1 text-[12px] font-medium",
                    textSecretSeedStatus === 'valid' ? "text-success" : "text-destructive"
                  )}
                >
                  {textSecretSeedStatus === 'valid' ? (
                    <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
                  ) : (
                    <AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />
                  )}
                  {textSecretSeedStatus === 'valid'
                    ? 'All words recognised'
                    : "A word isn't recognised"}
                </span>
              )}
            </div>
            <div className="relative">
              <Textarea
                id="text-secret"
                value={textSecret}
                onChange={(e) => handleTextSecretChange(e.target.value)}
                placeholder={`Enter text to ${currentMode}...`}
                rows={5}
                // This field routinely holds BIP-39 seed phrases. Spellcheck can
                // ship its contents to a remote dictionary service, autocorrect
                // silently rewrites valid wordlist entries into near-miss words,
                // and autofill/autocapitalise let a mobile keyboard learn the
                // phrase. None of that is behaviour a secret input should
                // inherit by default.
                spellCheck={false}
                autoCorrect="off"
                autoCapitalize="none"
                autoComplete="off"
                data-1p-ignore
                data-lpignore="true"
                // Ties the field to the status above, so the check is part of
                // the field's description rather than a floating scrap of text
                // a screen reader user has to go looking for.
                aria-describedby={
                  [
                    currentMode === 'encrypt' && textSecretSeedStatus !== 'none'
                      ? "text-secret-seed-status"
                      : null,
                    textInputRejected ? "text-secret-size-error" : null,
                  ]
                    .filter(Boolean)
                    .join(" ") || undefined
                }
                aria-invalid={currentMode === 'encrypt' && textSecretSeedStatus === 'invalid'}
                className={cn(
                  "rounded-xl border-white/10 bg-white/4 pr-12 transition-[filter] duration-150 focus-visible:border-accent/50 focus-visible:ring-0",
                  currentMode === 'encrypt' && !showTextSecret && textSecret && "blur-xs",
                  // Subtle seed-phrase feedback: green border = valid BIP-39
                  // seed, red = seed-shaped but invalid (likely typo). The
                  // border also overrides the focus tint so the signal stays
                  // visible while typing.
                  currentMode === 'encrypt' && textSecretSeedStatus === 'valid' && "border-success focus-visible:border-success",
                  currentMode === 'encrypt' && textSecretSeedStatus === 'invalid' && "border-destructive focus-visible:border-destructive"
                )}
              />
              {currentMode === 'encrypt' && (
                <button
                  type="button"
                  onClick={() => setShowTextSecret(!showTextSecret)}
                  aria-pressed={showTextSecret}
                  aria-label={showTextSecret ? "Hide secret text" : "Show secret text"}
                  className="absolute right-2 top-2 rounded-lg border border-white/10 bg-white/5 p-1.5 text-muted-foreground transition-all hover:bg-white/10 hover:text-foreground"
                >
                  {showTextSecret ? <Eye className="h-4 w-4" /> : <EyeOff className="h-4 w-4" />}
                </button>
              )}
            </div>
            {textInputRejected && (
              <p
                id="text-secret-size-error"
                role="alert"
                className="animate-in fade-in-50 rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-[12px] leading-snug text-destructive"
              >
                {textInputRejected} Nothing was pasted, so what you already had is
                still here.
              </p>
            )}
          </div>
        )}

        <TooltipProvider>
          <div>
            <div className="mb-2 flex items-center gap-1.5">
              <Label htmlFor="password" className="text-[13px] font-medium text-muted-foreground">
                Password
              </Label>
              <InfoTip label="Password requirements">
                <p>
                  Minimum policy: 24+ characters with upper/lowercase, a number and a
                  symbol — or a passphrase of several distinct words. This is a floor,
                  not a strength measurement: Keymaker cannot tell how you chose a
                  password. For a figure it can actually stand behind, use Generate.
                </p>
                {/*
                  U24. The ceiling existed and was stated nowhere, so the first
                  time anyone met it was as a rejection *after* typing or pasting
                  something long.
                */}
                <p className="mt-2">
                  Maximum {MAX_PASSWORD_LENGTH.toLocaleString()} characters — far past
                  any useful passphrase. It bounds the KDF input rather than limiting
                  you.
                </p>
              </InfoTip>
              {/*
                §4.6. Offered only on decrypt, and only as an explicit switch.
                Someone recovering a container with shares has no password at
                all, so the way in has to be visible without one — but it must
                not be the default path either, since almost every unlock is
                still a password.
              */}
              {currentMode === "decrypt" && (
                <button
                  type="button"
                  onClick={() =>
                    setUseShares((v) => {
                      // KM-R03. Leaving them in state behind a hidden control
                      // is the worst of both: invisible to the user, and still
                      // there for the auto-lock to have to think about.
                      if (v) setShareInput('');
                      return !v;
                    })
                  }
                  aria-pressed={useShares}
                  className="ml-auto rounded-md px-2 py-1 text-[12px] text-accent transition-colors hover:bg-accent/10"
                >
                  {useShares ? "Use a password instead" : "Use recovery shares"}
                </button>
              )}

              {/*
                §4.7. Offered without knowing whether this container has a
                passkey slot: finding out means parsing a file the user may not
                have chosen yet, and a control that appears halfway through
                filling the form is worse than one that explains itself when
                pressed. Pressing it on a container with no passkey slot says
                so, in those words.
              */}
              {currentMode === "decrypt" && passkeySupported && !useShares && (
                <button
                  type="button"
                  onClick={() => setUsePasskey((v) => !v)}
                  aria-pressed={usePasskey}
                  className="rounded-md px-2 py-1 text-[12px] text-accent transition-colors hover:bg-accent/10"
                >
                  {usePasskey ? "Use a password instead" : "Use a passkey"}
                </button>
              )}
            </div>

            {currentMode === "decrypt" && useShares && (
              <div className="mb-3 space-y-2">
                <Textarea
                  id="share-input"
                  value={shareInput}
                  onChange={(e) => handleShareInputChange(e.target.value)}
                  placeholder={"KMSHARE1:...\nKMSHARE1:...\nOne share per line"}
                  rows={4}
                  spellCheck={false}
                  autoCorrect="off"
                  autoCapitalize="off"
                  aria-describedby={shareInputRejected ? "share-input-size-error" : undefined}
                  aria-invalid={shareInputRejected ? true : undefined}
                  className="min-h-[96px] rounded-xl border-white/10 bg-white/4 font-mono text-[12px]"
                />
                {shareInputRejected && (
                  <p
                    id="share-input-size-error"
                    role="alert"
                    className="text-[12px] leading-snug text-destructive"
                  >
                    {shareInputRejected} Nothing was pasted, so what you already had is
                    still there.
                  </p>
                )}
                <p className="text-[12px] leading-snug text-muted-foreground" role="status">
                  {(() => {
                    const n = shareLines.length;
                    if (n === 0) return "Paste the shares, one per line. Comment lines starting with # are ignored.";
                    // Deliberately does not say whether this is enough: the
                    // threshold lives on the shares, not in the container, and
                    // guessing it here would mean either reading it out of
                    // input the user might have mistyped or inventing a number.
                    return `${n} share${n === 1 ? "" : "s"} entered. If the container needs more, the attempt will simply fail.`;
                  })()}
                </p>
              </div>
            )}
            <div className="relative">
              <Input
                id="password"
                value={password}
                type={showPassword ? "text" : "password"}
                onChange={(e) => handlePasswordChange(e.target.value)}
                onKeyDown={(e) => {
                  // U23. Enter in a password field means submit, everywhere
                  // else on the web. Doing nothing is safe but it silently
                  // costs a keyboard user a Tab to a button they cannot see
                  // from the field.
                  //
                  // Routed through the same guard as the button rather than
                  // calling processData directly — otherwise Enter becomes a
                  // way to start an operation the button correctly refuses,
                  // including one blocked by the password policy.
                  if (e.key === "Enter" && !isProcessButtonDisabled()) {
                    e.preventDefault();
                    void processData();
                  }
                }}
                placeholder={currentMode === 'encrypt' ? "Enter a strong password" : "Enter decryption password"}
                // A password field reveals its contents whenever "Show" is
                // pressed, at which point spellcheck and autocorrect apply to
                // it like any other text. Off for the same reasons as above.
                spellCheck={false}
                autoCorrect="off"
                autoCapitalize="none"
                autoComplete={currentMode === 'encrypt' ? "new-password" : "current-password"}
                className={cn(
                  "h-11 rounded-xl border border-white/10 bg-white/4 pr-[74px] text-[15px] transition-colors focus-visible:border-accent/50 focus-visible:ring-0",
                  getPasswordStrengthColor()
                )}
              />
              {/*
                U25, two halves of one control.

                `aria-pressed` because this is a toggle, and without it a screen
                reader reads "Show, button" in both states — the one piece of
                information the label is carrying.

                The label follows `revealingPassword`, not `showPassword`. The
                password is cleared after an operation while the toggle stays
                on, which left the button reading "Hide" over an empty field:
                it claims something is concealed when nothing is.
              */}
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                aria-pressed={revealingPassword}
                aria-label={revealingPassword ? "Hide password" : "Show password"}
                className="absolute right-2 top-1/2 -translate-y-1/2 rounded-lg border border-white/10 bg-white/5 px-2.5 py-1 text-xs font-medium text-muted-foreground transition-all hover:bg-white/10 hover:text-foreground"
              >
                {revealingPassword ? 'Hide' : 'Show'}
              </button>
            </div>
            {/*
              Two columns on a phone, one row once there is room.

              These are four buttons — Copy, Clear, Random, Passphrase — and
              Button carries whitespace-nowrap, so flex-1 could not shrink them
              below their content: the row demanded ~470px and pushed the whole
              document sideways on every phone. min-w-0 lets a label ellipsise
              at the very narrowest widths rather than taking the page with it.
            */}
            <div className="mt-2.5 grid grid-cols-2 gap-2 sm:flex">
              <Button
                variant="outline"
                size="sm"
                onClick={() => handleCopy(password)}
                disabled={!password}
                className="min-w-0 flex-1 rounded-lg border-white/10 bg-white/4 text-[13px] font-medium text-muted-foreground hover:bg-white/8 hover:text-foreground"
              >
                <Copy className="mr-1.5 h-3.5 w-3.5" />Copy
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => handlePasswordChange("")}
                disabled={!password}
                className="min-w-0 flex-1 rounded-lg border-white/10 bg-white/4 text-[13px] font-medium text-muted-foreground hover:bg-white/8 hover:text-foreground"
              >
                <X className="mr-1.5 h-3.5 w-3.5" />Clear
              </Button>
              {currentMode === 'encrypt' && (
                <>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={generatePassword}
                    title={`${PASSWORD_LENGTH} random characters — ${PASSWORD_ENTROPY_BITS} bits`}
                    className="min-w-0 flex-1 rounded-lg border-white/10 bg-white/4 text-[13px] font-medium text-muted-foreground hover:bg-white/8 hover:text-foreground"
                  >
                    <RefreshCw className="mr-1.5 h-3.5 w-3.5" />Random
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={generatePassphrase}
                    title={`${PASSPHRASE_WORDS} words from the EFF long list — ${PASSPHRASE_ENTROPY_BITS} bits`}
                    className="min-w-0 flex-1 rounded-lg border-white/10 bg-white/4 text-[13px] font-medium text-muted-foreground hover:bg-white/8 hover:text-foreground"
                  >
                    <Dices className="mr-1.5 h-3.5 w-3.5" />Passphrase
                  </Button>
                </>
              )}
            </div>

            {/*
              Two different statements, deliberately worded differently.

              A generated secret gets a number, because the sampling is ours
              and the arithmetic is exact. A typed one gets "policy met" and an
              explicit disclaimer — Keymaker has no way to know whether a
              passphrase was drawn from a word list or picked because it was
              memorable, and the two look identical once typed. That is why the
              passphrase button states a bit count and typing the very same
              words does not.
            */}
            {currentMode === 'encrypt' && password && (
              generated ? (
                <p className="text-[12px] leading-snug text-success">
                  {generated.kind === 'passphrase' ? (
                    <>
                      Generated · {generated.words} words drawn uniformly from the{' '}
                      {EFF_LARGE_WORDLIST_SIZE.toLocaleString()}-word EFF long list ={' '}
                      <strong>{generated.bits} bits</strong> of entropy.
                    </>
                  ) : (
                    <>
                      Generated · {PASSWORD_LENGTH} random characters from a{' '}
                      {PASSWORD_CHARSET.length}-character set ≈{' '}
                      <strong>{generated.bits} bits</strong> of entropy.
                    </>
                  )}
                </p>
              ) : passwordMeetsPolicy ? (
                <p className="text-[12px] leading-snug text-muted-foreground">
                  Minimum policy met. This is a floor, not a strength rating — Keymaker
                  cannot tell how you chose this password. Use <strong>Random</strong> or{' '}
                  <strong>Passphrase</strong> for a figure it can stand behind.
                </p>
              ) : (
                <p className="text-[12px] leading-snug text-destructive">
                  Below the minimum policy: 24+ characters with mixed classes, or a
                  passphrase of several distinct words.
                </p>
              )
            )}
          </div>

          {currentMode === 'decrypt' && keyFileControls}

          {/*
            Verify-only. See the state declaration for why this exists and what
            it does not claim.
          */}
          {currentMode === 'decrypt' && (
            <div className="flex items-start gap-3 rounded-xl border border-white/8 bg-white/2 px-4 py-3">
              <Switch
                id="verify-only"
                checked={verifyOnly}
                onCheckedChange={setVerifyOnly}
                aria-describedby="verify-only-help"
              />
              <div className="min-w-0 space-y-0.5">
                <Label htmlFor="verify-only" className="cursor-pointer text-[13px] font-medium">
                  Verify only — don&apos;t reveal the contents
                </Label>
                <p id="verify-only-help" className="text-[12px] leading-snug text-muted-foreground">
                  Checks that the backup still opens with this password, then discards
                  what it found. Nothing is displayed, downloaded, or copied.
                </p>
              </div>
            </div>
          )}

          {currentMode === 'encrypt' && (
            <div className="overflow-hidden rounded-xl border border-white/8 bg-white/2">
              <button
                type="button"
                onClick={() => setIsAdvancedOpen((v) => !v)}
                aria-expanded={isAdvancedOpen}
                className="flex w-full items-center justify-between px-4 py-3 text-left transition-colors hover:bg-white/4"
              >
                <span className="text-[13px] font-medium text-foreground">
                  Advanced <span className="font-normal text-muted-foreground">— KDF, cipher, key file</span>
                </span>
                <ChevronDown
                  className={cn(
                    "h-4 w-4 text-muted-foreground transition-transform duration-200",
                    isAdvancedOpen && "rotate-180"
                  )}
                />
              </button>
              <div
                className={cn(
                  "grid transition-[grid-template-rows] duration-200 ease-out",
                  isAdvancedOpen ? "[grid-template-rows:1fr]" : "[grid-template-rows:0fr]"
                )}
              >
                {/*
                  U5. `grid-template-rows: 0fr` with `overflow-hidden` clips the
                  panel but leaves everything inside it focusable, so a keyboard
                  user tabbed through twelve controls they could not see — two
                  KDF buttons, three ciphers, four sliders, and the rest.

                  `inert` rather than unmounting, because unmounting would throw
                  away the user's chosen parameters every time the panel closes,
                  and because the collapse is animated: a `hidden` attribute
                  would make it disappear instantly instead of sliding.

                  React renders `inert` as a real attribute from 19 onwards, and
                  as the boolean-attribute string before that; `|| undefined`
                  keeps it absent rather than `inert="false"`, which browsers
                  treat as *inert*.
                */}
                <div className="min-h-0 overflow-hidden" inert={!isAdvancedOpen || undefined}>
                  <div className="space-y-4 border-t border-white/6 px-4 pb-4 pt-4">
                    {/* KDF choice */}
                    <div className="space-y-2">
                      <Label className="text-[13px] font-medium text-muted-foreground">Key derivation</Label>
                      <div className="grid grid-cols-2 gap-2">
                        <button
                          type="button"
                          onClick={() => setKdfChoice("pbkdf2")}
                          className={cn(
                            "rounded-lg border p-3 text-left transition-colors",
                            kdfChoice === "pbkdf2"
                              ? "border-accent/60 bg-accent/10"
                              : "border-white/10 bg-white/2 hover:border-white/20"
                          )}
                        >
                          <p className="text-[13px] font-semibold">PBKDF2</p>
                          <p className="mt-0.5 text-[12px] leading-snug text-muted-foreground">
                            Fastest and most compatible. 1M iterations of SHA-256.
                          </p>
                        </button>
                        <button
                          type="button"
                          onClick={() => argon2Available !== false && setKdfChoice("argon2id")}
                          disabled={argon2Available === false}
                          className={cn(
                            "rounded-lg border p-3 text-left transition-colors",
                            kdfChoice === "argon2id"
                              ? "border-accent/60 bg-accent/10"
                              : "border-white/10 bg-white/2 hover:border-white/20",
                            argon2Available === false && "cursor-not-allowed opacity-40 hover:border-white/10"
                          )}
                        >
                          <p className="text-[13px] font-semibold">
                            Argon2id{" "}
                            <span className="text-accent">
                              {argon2Available === false ? "· unavailable" : "· recommended · default"}
                            </span>
                          </p>
                          <p className="mt-0.5 text-[12px] leading-snug text-muted-foreground">
                            Memory-hard — resists GPU/ASIC password cracking.
                          </p>
                        </button>
                      </div>

                      {argon2Available === false && (
                        <p
                          role="status"
                          className="rounded-lg border border-yellow-500/40 bg-yellow-500/10 px-3 py-2 text-[12px] leading-snug text-yellow-400"
                        >
                          <AlertTriangle className="mr-1.5 inline h-3.5 w-3.5 align-[-2px]" />
                          WebAssembly is unavailable in this browser, so Argon2id cannot run.
                          Falling back to PBKDF2 at 1,000,000 iterations — still strong, but
                          not memory-hard. Files you encrypt here stay fully readable everywhere.
                        </p>
                      )}

                      {kdfChoice === "argon2id" && (
                        <div className="animate-in fade-in-50 space-y-3 rounded-lg border border-white/8 bg-white/2 p-3">
                          {(
                            [
                              { label: "Time cost", value: argonTimeCost, set: setArgonTimeCost, min: 1, max: 10, step: 1, hint: "passes over memory" },
                              { label: "Memory", value: argonMemoryMiB, set: setArgonMemoryMiB, min: 8, max: 256, step: 8, hint: "MiB" },
                              { label: "Parallelism", value: argonParallelism, set: setArgonParallelism, min: 1, max: 8, step: 1, hint: "threads" },
                            ] as const
                          ).map(({ label, value, set, min, max, step, hint }) => (
                            <div key={label}>
                              <div className="mb-1 flex items-center justify-between">
                                <Label className="text-[12px] text-muted-foreground">{label}</Label>
                                <span className="text-[12px] font-medium tabular-nums">
                                  {value} <span className="text-muted-foreground">{hint}</span>
                                </span>
                              </div>
                              <input
                                type="range"
                                min={min}
                                max={max}
                                step={step}
                                value={value}
                                onChange={(e) => set(Number(e.target.value))}
                                aria-label={`Argon2id ${label.toLowerCase()}`}
                                className="w-full accent-accent"
                              />
                            </div>
                          ))}
                          <div className="space-y-2 pt-1">
                            <button
                              type="button"
                              onClick={runCalibration}
                              disabled={calibrating || isLoading}
                              className={cn(
                                "w-full rounded-lg border px-3 py-2 text-[12px] font-medium transition-colors",
                                "border-white/10 bg-white/2 hover:border-white/20",
                                "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent",
                                "disabled:cursor-not-allowed disabled:opacity-50"
                              )}
                            >
                              {calibrating ? "Measuring this device…" : "Calibrate for this device"}
                            </button>
                            <p className="text-[12px] text-muted-foreground">
                              {deviceFit
                                ? `Derivation time: ≈${(predictArgon2Ms(deviceFit, argonTimeCost, argonMemoryMiB * 1024) / 1000).toFixed(1)}s per attempt, measured on this device.`
                                : `Estimated derivation time: ≈${Math.max(1, Math.round((argonTimeCost * argonMemoryMiB) / 64))}s per attempt on a typical laptop (varies by device).`}
                            </p>
                            {/* Announced, because the result is the whole point
                                of pressing the button and a sighted user sees
                                the memory slider jump. */}
                            <p className="text-[12px] text-muted-foreground" role="status" aria-live="polite">
                              {calibrationNote ?? ""}
                            </p>
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Cipher choice */}
                    <div className="space-y-2">
                      <Label className="text-[13px] font-medium text-muted-foreground">Cipher</Label>
                      <div className="space-y-2">
                        {CIPHER_OPTIONS.map(({ id, name, blurb }) => (
                          <button
                            key={id}
                            type="button"
                            onClick={() => setCipherChoice(id)}
                            className={cn(
                              "flex w-full items-start gap-2.5 rounded-lg border p-3 text-left transition-colors",
                              cipherChoice === id
                                ? "border-accent/60 bg-accent/10"
                                : "border-white/10 bg-white/2 hover:border-white/20"
                            )}
                          >
                            <span className="mt-0.5 flex-1">
                              <span className="block text-[13px] font-semibold">{name}</span>
                              <span className="mt-0.5 block text-[12px] leading-snug text-muted-foreground">{blurb}</span>
                            </span>
                          </button>
                        ))}
                      </div>
                    </div>

                    {/* Key file */}
                    {keyFileControls}

                    {/* Filename privacy */}
                    <div className="flex items-center gap-3">
                      <Switch
                        id="obscure-filename"
                        checked={obscureFilename}
                        onCheckedChange={setObscureFilename}
                        className="data-[state=checked]:bg-success"
                      />
                      <div className="flex items-center gap-1.5">
                        <Label htmlFor="obscure-filename" className="cursor-pointer text-sm text-foreground">
                          Obscure filename
                        </Label>
                        <InfoTip label="What does obscuring the filename do?">
                          <p>Encrypted downloads are named keymaker-&lt;random&gt;.keym so the original filename stays private.</p>
                        </InfoTip>
                      </div>
                    </div>

                    {/*
                      §4.7 passkey. Encrypt only, and additive by construction:
                      the container still gets the passphrase slot, so a passkey
                      is never the only way in. That is the format's rule, not a
                      UI preference — a passkey is hardware, and hardware is
                      lost.

                      Hidden rather than disabled where WebAuthn is missing. A
                      disabled control invites the question "why", and the
                      answer is about the browser rather than anything the user
                      can act on here.
                    */}
                    {currentMode === "encrypt" && passkeySupported && (
                      <div className="space-y-3 rounded-lg border border-white/8 p-3">
                        <div className="flex items-center gap-3">
                          <Switch
                            id="passkey-enabled"
                            checked={passkeyEnabled}
                            onCheckedChange={setPasskeyEnabled}
                            className="data-[state=checked]:bg-success"
                          />
                          <div className="flex items-center gap-1.5">
                            <Label htmlFor="passkey-enabled" className="cursor-pointer text-sm text-foreground">
                              Passkey quick access
                            </Label>
                            <InfoTip label="What does a passkey add?">
                              <p>
                                A quicker way in day to day, from a key you tap
                                rather than a phrase you remember — and one that
                                cannot be phished.
                              </p>
                              <p className="mt-2">
                                <strong>Your password is still the backup.</strong>{" "}
                                A passkey is not stronger — the password opens this
                                container either way, so it is exactly as strong as
                                the weaker of the two.
                              </p>
                              <p className="mt-2">
                                And it is <strong>not archival</strong>. A passkey
                                only answers at this website, so it will not open
                                anything from a copy of the app, from a different
                                address, or with the offline recovery script. Every
                                other way in survives all three. Keep the password.
                              </p>
                            </InfoTip>
                          </div>
                        </div>
                        {passkeyEnabled && (
                          <p className="text-[12px] leading-relaxed text-muted-foreground">
                            You will be asked to tap twice — once to create the
                            passkey, once to use it. Some keys only produce what
                            Keymaker needs on the second tap, so it asks for both
                            rather than enrolling a passkey that turns out not to
                            open anything.
                          </p>
                        )}
                      </div>
                    )}

                    {/*
                      §4.6 recovery shares. Encrypt only — a share set is
                      enrolled while writing, and the decrypt side has its own
                      entry path.
                    */}
                    {currentMode === "encrypt" && (
                      <div className="space-y-3 rounded-lg border border-white/8 p-3">
                        <div className="flex items-center gap-3">
                          <Switch
                            id="shamir-enabled"
                            checked={shamirEnabled}
                            onCheckedChange={setShamirEnabled}
                            className="data-[state=checked]:bg-success"
                          />
                          <div className="flex items-center gap-1.5">
                            <Label htmlFor="shamir-enabled" className="cursor-pointer text-sm text-foreground">
                              Recovery shares
                            </Label>
                            <InfoTip label="What are recovery shares?">
                              <p>
                                Splits a second way in across several printed codes. Any{" "}
                                {shamirThreshold} of the {shamirCount} open this container — without
                                the password. Fewer than {shamirThreshold} reveal nothing at all.
                              </p>
                            </InfoTip>
                          </div>
                        </div>

                        {shamirEnabled && (
                          <>
                            <div className="grid grid-cols-2 gap-3">
                              <div className="space-y-1.5">
                                <Label htmlFor="shamir-threshold" className="text-[12px] text-muted-foreground">
                                  Needed to open
                                </Label>
                                <Input
                                  id="shamir-threshold"
                                  type="number"
                                  min={2}
                                  max={shamirCount}
                                  value={shamirThreshold}
                                  onChange={(e) => {
                                    // Clamped here rather than trusting min/max, which are a
                                    // UI affordance: typing 9 into a number field sets 9.
                                    const n = Math.round(Number(e.target.value));
                                    if (!Number.isFinite(n)) return;
                                    setShamirThreshold(Math.min(Math.max(n, 2), shamirCount));
                                  }}
                                  className="h-10 rounded-lg border-white/10 bg-white/4"
                                />
                              </div>
                              <div className="space-y-1.5">
                                <Label htmlFor="shamir-count" className="text-[12px] text-muted-foreground">
                                  Shares to print
                                </Label>
                                <Input
                                  id="shamir-count"
                                  type="number"
                                  min={2}
                                  max={8}
                                  value={shamirCount}
                                  onChange={(e) => {
                                    const n = Math.round(Number(e.target.value));
                                    if (!Number.isFinite(n)) return;
                                    const next = Math.min(Math.max(n, 2), 8);
                                    setShamirCount(next);
                                    // The threshold cannot exceed the count, and silently
                                    // producing a set nobody can ever reach would be the
                                    // worst possible outcome for a backup feature.
                                    setShamirThreshold((t) => Math.min(t, next));
                                  }}
                                  className="h-10 rounded-lg border-white/10 bg-white/4"
                                />
                              </div>
                            </div>
                            {/*
                              Roadmap, "Honest framing to preserve": any k shares
                              open the container without the password, so each
                              share is as sensitive as the password itself. That
                              belongs on the screen, not only in the docs.
                            */}
                            <p className="rounded-md bg-yellow-900/20 px-3 py-2 text-[12px] leading-snug text-yellow-400">
                              Each share is as sensitive as your password. Anyone holding{" "}
                              {shamirThreshold} of them opens this container without knowing it.
                              Store them apart, with people who would not combine them casually.
                            </p>
                          </>
                        )}
                      </div>
                    )}

                    {/* Security summary */}
                    <p className="rounded-lg bg-accent/8 px-3 py-2 text-[12px] text-muted-foreground">
                      <span className="font-medium text-foreground">Effective configuration:</span>{" "}
                      {kdfChoice === "argon2id"
                        ? `Argon2id(${argonMemoryMiB} MiB, t=${argonTimeCost}, p=${argonParallelism})`
                        : "PBKDF2(1M iters)"}
                      {" · "}
                      {cipherChoice === CipherId.CHAINED
                        ? "AES+ChaCha"
                        : cipherChoice === CipherId.CHACHA20_POLY1305
                          ? "ChaCha20-Poly1305"
                          : "AES-256-GCM"}
                      {useKeyFile && " · key file"}
                      {obscureFilename && " · obscure filename"}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </TooltipProvider>
      </div>

      {/*
        A verified result subsumes the plain format line — verifyResult.detail
        is the same string — so only one of the two is ever rendered.
      */}
      {verifyResult && currentMode === 'decrypt' ? (
        <div
          role="status"
          className="animate-in fade-in-50 rounded-xl border border-success/40 bg-success/10 px-4 py-3"
        >
          <p className="flex items-center gap-2 text-[13px] font-semibold text-success">
            <ShieldCheck className="h-4 w-4 shrink-0" />
            The backup opens with this password
          </p>
          <p className="mt-1 text-[12px] leading-snug text-success/90">
            {verifyResult.detail} · {formatBytes(verifyResult.bytes)} of contents,
            authenticated and discarded without being shown.
          </p>
          <p className="mt-1.5 text-[12px] leading-snug text-muted-foreground">
            The size is worth a glance: the right password on the wrong backup still
            verifies.
          </p>
        </div>
      ) : decryptInfo && currentMode === 'decrypt' ? (
        <p className="animate-in fade-in-50 rounded-lg bg-white/4 px-3 py-2 text-[12px] text-muted-foreground">
          <Info className="mr-1.5 inline h-3.5 w-3.5 align-[-2px]" />
          {decryptInfo}
        </p>
      ) : null}

      {/* v3 §5.2. The container opened and the plaintext above is genuine —
          the payload authenticates on its own and did so before this rendered.
          What this reports is that the *slot table* has changed since the
          backup was written, which is a change to who can still open the file
          rather than to what is in it. Refusing to show the plaintext would
          have turned detectable tampering into a lost backup, which is the
          worse outcome; saying nothing would have wasted the detection. So:
          both. */}
      {slotTableWarning && currentMode === 'decrypt' && (
        <div
          role="alert"
          className="mt-2 animate-in fade-in-50 rounded-xl border border-amber-500/40 bg-amber-500/10 p-3 text-sm text-amber-200"
          data-testid="slot-table-warning"
        >
          <p className="flex items-start gap-2 font-semibold">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
            This backup&apos;s list of unlock methods has changed since it was created.
          </p>
          <p className="mt-1.5 leading-snug">
            Your data is intact — the contents are authenticated separately and
            verified before anything was shown. What changed is the set of ways
            back in: an unlock method may have been added or removed. It is not
            possible to say which one, only that the list is no longer the one
            sealed with the file. If you did not change it yourself, treat this
            copy as untrusted and recover from another one.
          </p>
        </div>
      )}

      {outputText && (
        <div className="animate-in fade-in-50 space-y-2">
          <div className="flex items-center justify-between gap-3">
            <Label htmlFor="output-text" className="text-[13px] font-medium text-muted-foreground">
              Result
            </Label>
            {/*
              Same colour-only problem as the encrypt side, and here it is the
              more consequential half: a red border on a *decrypted* backup
              means the phrase you stored years ago has a word the list does
              not contain, so it may not restore. That is not something to
              signal in hue alone.
            */}
            {currentMode === 'decrypt' && inputType === 'text' && decryptedQrStatus.kind !== 'idle' && (
              (decryptedQrStatus.kind === 'seed' || decryptedQrStatus.seedShaped) && (
                <span
                  id="output-seed-status"
                  role="status"
                  className={cn(
                    "flex shrink-0 items-center gap-1 text-[12px] font-medium",
                    decryptedQrStatus.kind === 'seed' ? "text-success" : "text-destructive"
                  )}
                >
                  {decryptedQrStatus.kind === 'seed' ? (
                    <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
                  ) : (
                    <AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />
                  )}
                  {decryptedQrStatus.kind === 'seed'
                    ? 'All words recognised'
                    : "A word isn't recognised"}
                </span>
              )
            )}
          </div>
          <div className="relative">
            <Textarea
              id="output-text"
              value={outputText}
              readOnly
              rows={5}
              className={cn(
                "rounded-xl border-white/10 bg-white/4 pr-12 focus-visible:ring-0",
                currentMode === 'decrypt' && inputType === 'text' && !showDecryptedText && "blur-xs",
                // Same border language as the encrypt-side secret field:
                // green = decrypted text is a valid BIP-39 seed, red = it is
                // seed-shaped but fails validation (the stored backup itself
                // likely holds a transcription error).
                currentMode === 'decrypt' && decryptedQrStatus.kind === 'seed' && "border-success",
                currentMode === 'decrypt' && decryptedQrStatus.kind === 'plain' && decryptedQrStatus.seedShaped && "border-destructive"
              )}
            />
            <div className="absolute right-1 top-1 flex flex-col items-center">
              {currentMode === 'decrypt' && inputType === 'text' && (
                <Button type="button" variant="ghost" size="icon" className="h-auto p-2" onClick={() => setShowDecryptedText(!showDecryptedText)}>
                  {showDecryptedText ? <EyeOff /> : <Eye />}
                </Button>
              )}
              <Button type="button" variant="ghost" size="icon" className="h-auto p-2" onClick={() => handleCopy(outputText)}>
                <Copy />
              </Button>
              {currentMode === 'encrypt' && inputType === 'text' && (
                <Dialog open={isQrModalOpen} onOpenChange={setIsQrModalOpen}>
                  <DialogTrigger asChild>
                    <Button type="button" variant="ghost" size="icon" className="h-auto p-2">
                      <QrCode />
                    </Button>
                  </DialogTrigger>
                  <DialogContent>
                    <DialogHeader>
                      <DialogTitle>Encrypted QR Code</DialogTitle>
                      <DialogDescription>
                        Scan this code to transfer the encrypted text.
                      </DialogDescription>
                    </DialogHeader>
                    <div className="flex flex-col items-center gap-4 py-4">
                      {qrByteLength(outputTextForQr) <= QR_MAX_BYTES ? (
                        <>
                          <div className="rounded-lg bg-white p-4">
                            <QRCodeCanvas value={outputTextForQr} size={256} level="L" marginSize={0} />
                          </div>
                          <div ref={hiResQrRef} style={OFFSCREEN_STYLE}>
                            <QRCodeCanvas value={outputTextForQr} size={900} level="L" />
                          </div>
                          <Button onClick={handleDownloadQrCode}>
                            <Download className="mr-2 h-4 w-4" />
                            Download PNG (300 DPI)
                          </Button>
                        </>
                      ) : (
                        <div className="rounded-md bg-yellow-900/20 p-3 text-center text-sm text-yellow-400">
                          <p className="font-medium">QR code unavailable</p>
                          <p className="mt-1">Output is {qrByteLength(outputTextForQr).toLocaleString()} bytes, which exceeds the QR code capacity of {QR_MAX_BYTES.toLocaleString()} bytes. Use the copy button instead.</p>
                        </div>
                      )}
                    </div>
                  </DialogContent>
                </Dialog>
              )}
              {currentMode === 'decrypt' && inputType === 'text' && decryptedQrStatus.kind !== 'idle' && (
                <Dialog
                  open={isDecryptedQrModalOpen}
                  onOpenChange={(open) => {
                    setIsDecryptedQrModalOpen(open);
                    // Reset to blurred whenever the modal opens or closes, so the
                    // user always has to deliberately click to reveal.
                    setIsDecryptedQrRevealed(false);
                  }}
                >
                  <DialogTrigger asChild>
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      className="h-auto p-2"
                      title={decryptedQrStatus.kind === 'seed' ? 'Show SeedQR' : 'Show QR'}
                    >
                      <QrCode />
                    </Button>
                  </DialogTrigger>
                  <DialogContent>
                    <DialogHeader>
                      <DialogTitle>
                        {decryptedQrStatus.kind === 'seed' ? 'Standard SeedQR' : 'QR Code'}
                      </DialogTitle>
                      <DialogDescription>
                        {decryptedQrStatus.kind === 'seed'
                          ? `BIP-39 ${decryptedQrStatus.words.length}-word seed phrase, encoded for hardware wallet import (Coldcard, SeedSigner, Sparrow, Specter, Krux, Keystone, Jade).`
                          : 'Scannable QR of the decrypted text. Nothing ever leaves your device.'}
                      </DialogDescription>
                    </DialogHeader>
                    <div className="flex flex-col items-center gap-4 py-4">
                      {decryptedQrStatus.kind === 'seed' ? (
                        <RevealableQr
                          // status can only be 'seed' after loadBip39()
                          // resolved in processData, so the sync handle is set.
                          getValue={() => bip39Module!.toStandardSeedQR(decryptedQrStatus.words)}
                          revealed={isDecryptedQrRevealed}
                          onToggleReveal={() => setIsDecryptedQrRevealed((v) => !v)}
                          onDownload={handleDownloadDecryptedQr}
                          hiResRef={decryptedQrHiResRef}
                          warning="Anyone who scans this QR can recover your seed. Show only on a trusted device and screen."
                          caption={`Standard SeedQR · ${decryptedQrStatus.words.length} words · ${decryptedQrStatus.words.length * 4} digits`}
                          // U28. Through handleCopy, so the digits inherit the
                          // 2.6 clipboard hardening — the countdown and the
                          // unconditional clear — rather than being written
                          // straight to a clipboard nothing then wipes.
                          onCopyDigits={() =>
                            handleCopy(bip39Module!.toStandardSeedQR(decryptedQrStatus.words))
                          }
                        />
                      ) : qrByteLength(outputText) <= QR_MAX_BYTES ? (
                        <RevealableQr
                          getValue={() => outputText}
                          revealed={isDecryptedQrRevealed}
                          onToggleReveal={() => setIsDecryptedQrRevealed((v) => !v)}
                          onDownload={handleDownloadDecryptedQr}
                          hiResRef={decryptedQrHiResRef}
                          warning="This QR contains your decrypted text. Show only on a trusted device and screen."
                        />
                      ) : (
                        <div className="rounded-md bg-yellow-900/20 p-3 text-center text-sm text-yellow-400">
                          <p className="font-medium">QR code unavailable</p>
                          <p className="mt-1">
                            Decrypted text is {qrByteLength(outputText).toLocaleString()} bytes,
                            which exceeds the QR code capacity of {QR_MAX_BYTES.toLocaleString()}{' '}
                            characters.
                          </p>
                        </div>
                      )}
                    </div>
                  </DialogContent>
                </Dialog>
              )}
            </div>
          </div>
        </div>
      )}

      {/*
        4.2. The paper route out of the app.

        Offered on the encrypt side only, and only for a v2 container, because
        that is the only thing §7.1's paper parts describe. Deliberately beside
        the result rather than buried in a menu: the moment someone is looking
        at a container they just made is the moment printing it is on their
        mind, and any later is a moment they have closed the tab.
      */}
      {currentMode === 'encrypt' && outputText.startsWith('keym2:') && (
        <button
          type="button"
          onClick={async () => {
            const { dearmorKeym2 } = await import("@/lib/keym-v2");
            setPaperVault({
              container: dearmorKeym2(outputText),
              printedOn: new Date().toISOString().slice(0, 10),
            });
          }}
          className="flex w-full cursor-pointer items-center justify-center gap-1.5 rounded-xl border border-white/10 bg-white/2 px-3 py-2 text-[12px] text-muted-foreground transition-colors hover:border-white/20 hover:text-foreground"
        >
          <Printer className="h-3.5 w-3.5" />
          Print paper vault — scannable backup and the procedure to open it
        </button>
      )}

      {/*
        4.3. The self-extracting page (§7.2).

        Beside the paper vault for the same reason it is: this is the moment
        someone is looking at a backup they just made and thinking about who
        else will ever open it.

        When the container is outside §7.2's subset the control does not
        disappear — it says what would have to change. Hiding it would make the
        feature invisible to exactly the users who chose Argon2id, which is the
        recommended default and therefore most of them. The trade has to be made
        before encrypting, because the page carries its own container and the
        plaintext is gone by the time this renders, so naming it here is the one
        place the choice can be taught at the moment it means anything.
      */}
      {currentMode === 'encrypt' && outputText.startsWith('keym2:') && (
        <SelfExtractExport armored={outputText} />
      )}

      {/*
        Clipboard countdown and the imminent-lock warning.

        Both are here rather than as toasts because both are *states*, not
        events: a toast that has already faded cannot tell you the clipboard
        still holds your seed phrase, and a lock warning you missed is not a
        warning. Each carries the control that answers it.
      */}
      {clipboardSecondsLeft !== null && (
        <div
          role="status"
          className="flex items-center justify-between gap-3 rounded-xl border border-white/10 bg-white/4 px-3 py-2 text-[12px]"
        >
          <span className="flex min-w-0 items-center gap-1.5 text-muted-foreground">
            <Timer className="h-3.5 w-3.5 shrink-0" />
            <span className="truncate">
              Clipboard clears in <span className="tabular-nums font-medium text-foreground">{clipboardSecondsLeft}s</span>
            </span>
          </span>
          <button
            type="button"
            onClick={clearClipboardNow}
            className="shrink-0 cursor-pointer rounded-lg border border-white/10 px-2.5 py-1 font-medium text-muted-foreground transition-colors hover:border-white/20 hover:text-foreground"
          >
            Clear now
          </button>
        </div>
      )}

      {lockSecondsLeft !== null && (
        <LockWarning secondsLeft={lockSecondsLeft} onKeepOpen={keepOpen} />
      )}

      {/* Shown while the derivation runs, with the way out beside it. A notice
          that explains a long wait but offers no way to end it is only half an
          answer. */}
      {isLoading && unlockCostNotice && (
        <div
          role="status"
          className="mt-2 rounded-xl border border-amber-500/40 bg-amber-500/10 p-3 text-sm text-amber-200"
          data-testid="unlock-cost-notice"
        >
          {unlockCostNotice}
        </div>
      )}

      <Button
        onClick={processData}
        disabled={isProcessButtonDisabled()}
        className="mt-2 h-auto w-full rounded-xl bg-linear-to-br from-[#e3a35c] via-[#c07f2e] to-[#8a5a1c] py-3.5 text-[15px] font-semibold text-black shadow-[0_8px_24px_-8px_rgba(192,127,46,0.5)] transition-all hover:-translate-y-px hover:shadow-[0_12px_32px_-8px_rgba(192,127,46,0.65)] disabled:opacity-40 disabled:hover:translate-y-0"
      >
        {isLoading ? (
          <Loader2 className="mr-2 h-5 w-5 animate-spin" />
        ) : currentMode === 'encrypt' ? (
          <Lock className="mr-2 h-5 w-5" />
        ) : verifyOnly ? (
          <ShieldCheck className="mr-2 h-5 w-5" />
        ) : (
          <Unlock className="mr-2 h-5 w-5" />
        )}
        {currentMode === 'encrypt'
          ? `Encrypt ${inputType === 'file' ? 'File' : 'Text'}`
          : verifyOnly
            ? `Verify ${inputType === 'file' ? 'File' : 'Text'}`
            : `Decrypt ${inputType === 'file' ? 'File' : 'Text'}`}
      </Button>

      {/* Only while something is running. Terminating the worker is a real
          stop, not a disowning — see cancelOperation. */}
      {isLoading && (
        <Button
          variant="ghost"
          onClick={cancelOperation}
          data-testid="cancel-operation"
          className="mt-1 h-auto w-full py-2 text-[13px] text-muted-foreground hover:text-foreground"
        >
          Stop
        </Button>
      )}

      {/*
        U15. `role="status"` rather than an alert: it is the explanation for a
        control the user is looking at, not an interruption, and it appears and
        disappears as they type.
      */}
      {blockedByPasswordPolicy && (
        <p
          role="status"
          className="mt-2 text-center text-[12px] leading-snug text-muted-foreground"
        >
          Encrypt stays disabled until the password meets the minimum policy —
          24+ characters with upper and lowercase, a number and a symbol, or a
          passphrase of several distinct words.
        </p>
      )}

      {/*
        Always available while there is something to wipe — the panic button
        for "someone just walked over", which is the case the five-minute timer
        is too slow for.
      */}
      {hasSecretsOnScreen && (
        <button
          type="button"
          onClick={() => {
            clearSensitiveState();
            toast({
              title: "Wiped",
              description: "Password, inputs and any decrypted output were cleared. Your settings are unchanged.",
            });
          }}
          className="mx-auto flex cursor-pointer items-center gap-1.5 text-[12px] text-muted-foreground underline underline-offset-2 transition-colors hover:text-destructive"
        >
          <Trash2 className="h-3.5 w-3.5" />
          Wipe now
        </button>
      )}
    </div>
  );

  // px-2.5 until there is room for px-4. The header is a wordmark and three
  // tabs on one row; at the tabs' full padding that row needs 412px, so every
  // phone narrower than an iPhone 14 Pro Max scrolled the whole page sideways —
  // which is what made the results grid look like it was overlapping.
  const tabTriggerClasses = "rounded-lg px-2.5 py-1.5 text-[13px] font-medium text-muted-foreground sm:px-4 data-[state=active]:bg-white/10 data-[state=active]:text-foreground data-[state=active]:shadow-xs";

  return (
    <Tabs value={mode} onValueChange={handleModeChange} className="flex min-h-screen flex-col">
      {/* ---- HEADER ---- */}
      <header className="sticky top-0 z-50 w-full border-b border-white/8 bg-black/70 backdrop-blur-xl backdrop-saturate-150">
        <div className="mx-auto flex max-w-5xl items-center justify-between gap-2 px-4 py-3 sm:px-6">
          <div className="flex min-w-0 items-center gap-2 sm:gap-2.5">
            <svg viewBox="0 0 512 512" width={28} height={28} aria-label="Keymaker Logo" role="img" xmlns="http://www.w3.org/2000/svg">
              <defs>
                <linearGradient id="kmHdrGrad" x1="0" y1="0" x2="1" y2="1">
                  <stop offset="0%" stopColor="#e3a35c" />
                  <stop offset="45%" stopColor="#c07f2e" />
                  <stop offset="100%" stopColor="#8a5a1c" />
                </linearGradient>
                <mask id="kmHdrKey">
                  <rect width="512" height="512" fill="white" />
                  <circle cx="256" cy="205" r="51" fill="black" />
                  <path d="M 230 205 L 282 205 L 297 369 L 215 369 Z" fill="black" />
                </mask>
              </defs>
              <rect width="512" height="512" rx="48" fill="url(#kmHdrGrad)" mask="url(#kmHdrKey)" />
            </svg>
            {/* The wordmark is what pushes the header row over on a small
                phone, so below the breakpoint only the logo remains — the
                brand is still present, and the tabs are the part a user cannot
                do without.

                The breakpoint is measured, not guessed, and deliberately has
                room to spare: text metrics differ between Chromium, Firefox
                and WebKit by a few pixels, and only Chromium can be checked
                locally. The overflow sweep in platform.spec.ts runs 375px and
                393px — either side of this line — in all three engines, so CI
                is what actually proves it. */}
            <span className="hidden text-[16px] font-semibold tracking-tight min-[390px]:inline sm:text-[17px]">
              Keymaker
            </span>
          </div>
          <TabsList className="h-auto bg-white/6 p-0.5">
            <TabsTrigger value="encrypt" className={tabTriggerClasses}>
              Encrypt
            </TabsTrigger>
            <TabsTrigger value="decrypt" className={tabTriggerClasses}>
              Decrypt
            </TabsTrigger>
            <TabsTrigger value="tools" className={tabTriggerClasses}>
              <Dices className="mr-1.5 h-3.5 w-3.5" />
              Tools
            </TabsTrigger>
          </TabsList>
        </div>
      </header>

      {/* ---- MAIN CONTENT ---- */}
      <div className="w-full flex-1">
        <div className="mx-auto max-w-[680px] px-4 pb-24 pt-12 sm:px-6 sm:pt-16">
          {/* Hero */}
          <div className="mb-10 text-center sm:mb-14">
            <h1 className="hero-gradient-text text-[44px] font-bold leading-[1.05] tracking-[-0.04em] sm:text-[56px]">
              Encrypt everything.<br />Trust nothing.
            </h1>
            <p className="mx-auto mt-4 max-w-md text-[17px] leading-snug text-muted-foreground sm:text-[19px]">
              Client-side encryption that never leaves your browser.{' '}
              <a href={KEYMAKER_REPO} target="_blank" rel="noopener noreferrer" className="text-accent hover:underline">
                Open source
              </a>
              , forked from IttyBitz. No accounts. No servers.
            </p>
          </div>

          {/* Card. 24px of padding either side of a 320px screen leaves 240px
              of usable width; p-5 buys back 16px where it is scarcest. */}
          <section className="glass-card rounded-[20px] p-5 sm:p-8">
            {/*
              U18. Radix gives every TabsContent `tabIndex={0}` so a scrollable
              panel is reachable by keyboard. Here the panels are not scrollable
              and every control inside is focusable on its own, so it is a tab
              stop that lands on a 566x533 div, shows no focus ring, and does
              nothing — a keyboard user presses Tab and appears to lose focus.

              -1 keeps the panel programmatically focusable (which Radix relies
              on when switching tabs) while removing it from the sequential
              order.
            */}
            <TabsContent value="encrypt" className="mt-0" tabIndex={-1}>
              {renderContent("encrypt")}
            </TabsContent>
            <TabsContent value="decrypt" className="mt-0" tabIndex={-1}>
              {renderContent("decrypt")}
            </TabsContent>
            {/*
              U2b. Radix unmounts an inactive tab panel, so switching away from
              Tools destroyed the dice roll log — a tally someone had physically
              rolled, gone because they glanced at the Encrypt tab. forceMount
              keeps it mounted, and the count survives.

              `hidden` has to be supplied here, though, and the reason is worth
              spelling out because the opposite is the natural assumption.
              Radix computes `hidden={!present}` with `present = forceMount ||
              isSelected`, so forceMount does not merely keep the panel mounted
              — it pins `hidden` to false for the panel's whole life. The
              inactive Tools panel was therefore rendered, 820px tall, in the
              document flow directly under the Encrypt button, with five
              controls a keyboard user could Tab into.

              Passing it explicitly works because Radix spreads the caller's
              props *after* its own `hidden`, so this wins. Same reason
              tabIndex={-1} above takes effect over the `tabIndex: 0` Radix
              sets.

              Only this panel gets forceMount. Encrypt and Decrypt deliberately
              reset on a mode change, and mounting both permanently would keep
              two sets of secret-bearing fields alive at once for no benefit.
            */}
            <TabsContent
              value="tools"
              className="mt-0"
              tabIndex={-1}
              forceMount
              hidden={mode !== "tools"}
            >
              <DiceEntropyTool />
            </TabsContent>
          </section>

          {/* Feature cards */}
          <div className="mt-8 grid gap-3 sm:mt-10 sm:grid-cols-3">
            {FEATURE_CARDS.map(({ icon: Icon, title, description }) => (
              <div key={title} className="rounded-2xl border border-white/6 bg-white/2 p-5">
                <div className="mb-2.5 grid h-8 w-8 place-items-center rounded-lg bg-accent/10 text-accent">
                  <Icon className="h-4 w-4" />
                </div>
                <p className="text-[14px] font-semibold">{title}</p>
                <p className="mt-1 text-[12px] leading-relaxed text-muted-foreground">
                  {description}
                </p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ---- FOOTER ---- */}
      <footer className="w-full border-t border-white/6">
        <div className="mx-auto flex max-w-5xl flex-col items-center gap-2 px-4 py-5 text-xs text-muted-foreground sm:flex-row sm:justify-between sm:px-6">
          <div className="flex items-center gap-1.5">
            <Heart className="h-3 w-3 text-red-500" />
            <span>
              Keymaker is a fork of{' '}
              <a href="https://github.com/seQRets/ittybitz" target="_blank" rel="noopener noreferrer" className="text-accent hover:underline">
                IttyBitz
              </a>{' '}
              by seQRets (GPL-3).
            </span>
          </div>
          {/*
            U8. These two are standalone footer controls, not links inside a
            sentence, so WCAG 2.5.8's inline exception does not cover them and
            16px tall is simply too small to hit. `py-1.5` takes both past 24px;
            the negative margin keeps the footer's own spacing where it was.
          */}
          <div className="-my-1.5 flex items-center gap-3">
            <button
              type="button"
              onClick={() => setIsRecoveryOpen(true)}
              className="flex cursor-pointer items-center gap-1.5 py-1.5 text-accent hover:underline"
            >
              <LifeBuoy className="h-3.5 w-3.5" />
              Recovery kit
            </button>
            <a href={KEYMAKER_REPO} target="_blank" rel="noopener noreferrer" className="py-1.5 hover:underline">GitHub</a>
            {/*
              6.3. The signed manifest and the reproducible build had existed
              for a while and were reachable only from a document in the repo —
              the one place someone worried about the *served* bundle has no
              particular reason to look.

              `.html` rather than a bare `/verify`: the export emits verify.html
              beside a verify/ directory of router payloads, so the
              extensionless path resolves to a directory with no index and 404s.
            */}
            <a href={`${BASE_PATH}/verify.html`} className="py-1.5 hover:underline">
              Verify this build
            </a>
            {/*
              6.1. Two numbers, stated separately and on purpose.

              The app version comes from package.json at build time, so there is
              no second literal to drift from it. The format version is what a
              *container* is, and moves only when the format does — §9 of the v2
              design says that is now frozen.

              Both appear because this is the line someone reads out when a file
              will not open, and "v2" alone does not say whether they mean the
              app or the file.
            */}
            <span>
              Keymaker v{APP_VERSION}
              {/*
                Only on a rolling build. A release says nothing extra, because
                there the version is the whole truth; a development build has
                to admit it is ahead of the tag it is naming. The verify page
                carries the commit, which is what turns this from a caveat into
                something actionable.
              */}
              {!IS_RELEASE_BUILD && (
                <span className="text-muted-foreground/60">-dev</span>
              )}
              {/* Read from the constant, not typed out. This said "writes KEYM
                  v2" for as long as the app had been writing v3 — a footer
                  whose whole purpose is to tell someone which format they are
                  holding, telling them the wrong one. A literal here is a
                  claim that has to be remembered; a constant is one that
                  cannot go stale. */}
              <span className="text-muted-foreground/60">
                {` · writes KEYM v${KEYM2_VERSION}`}
              </span>
            </span>
          </div>
        </div>
      </footer>

      {/*
        The recovery kit.

        Everything else in this app is about the container being safe. This is
        about it being *openable* — years from now, by someone who did not
        choose this tool, when the website is gone. Both files are served from
        this origin and precached by the service worker, so this dialog works
        offline and travels with the app rather than pointing at a repository
        the user may never find.
      */}
      {/*
        §4.6. The share set, shown exactly once.

        `onOpenChange` only ever closes — there is no reopening this, because
        there is nothing left to reopen it from: the share secret was discarded
        inside the worker the moment the slot was wrapped, so these strings are
        the only copies that will ever exist. That is a property of the format,
        not a limitation of this dialog, and the copy says so plainly rather
        than letting someone discover it by closing the window.
      */}
      <Dialog
        open={issuedShares !== null}
        onOpenChange={(open) => {
          if (!open) setIssuedShares(null);
        }}
      >
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-yellow-400" />
              Save these {issuedShares?.shares.length} shares now
            </DialogTitle>
            <DialogDescription>
              Any {issuedShares?.threshold} of them open this container without the
              password. They are shown once and cannot be reissued — closing this
              window loses them.
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
              <div key={share} className="rounded-lg border border-white/10 bg-white/4 p-2.5">
                <p className="mb-1 text-[12px] text-muted-foreground">
                  Share {i + 1} of {issuedShares.shares.length}
                </p>
                <p className="break-all font-mono text-[12px] leading-relaxed text-foreground">
                  {share}
                </p>
              </div>
            ))}
          </div>

          <p className="rounded-md bg-yellow-900/20 px-3 py-2 text-[12px] leading-snug text-yellow-400">
            Each share is as sensitive as your password. Store them in separate
            places, with people who would not casually combine them — anyone
            holding {issuedShares?.threshold} needs nothing else from you.
          </p>

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
                  const { dearmorKeym2 } = await import("@/lib/keym-v2");
                  setPaperVault({
                    container: dearmorKeym2(outputText),
                    shares: issuedShares.shares,
                    threshold: issuedShares.threshold,
                    printedOn: new Date().toISOString().slice(0, 10),
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
            {!outputText.startsWith("keym2:") && (
              <p className="w-full text-[12px] leading-snug text-muted-foreground">
                The paper vault prints the container beside the shares, and a file
                container is downloaded rather than kept on screen — so it is not
                here to print. Copy these shares now; to print a paper vault
                instead, encrypt in Text mode.
              </p>
            )}
          </div>
        </DialogContent>
      </Dialog>

      {/*
        4.2. The paper vault sheet. Hidden on screen by `.paper-vault` in
        globals.css and made the only visible element inside `@media print`, so
        it does not need to sit at the document root to print cleanly.
      */}
      {paperVault ? (
        <PaperVault
          container={paperVault.container}
          shares={paperVault.shares}
          threshold={paperVault.threshold}
          printedOn={paperVault.printedOn}
        />
      ) : null}

      <Dialog open={isRecoveryOpen} onOpenChange={setIsRecoveryOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <LifeBuoy className="h-4 w-4 text-accent" />
              Recovery kit
            </DialogTitle>
            <DialogDescription>
              A <code className="rounded bg-white/8 px-1 py-0.5 text-[12px]">.keym</code> file
              does not need this website. Save these next to your backups.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-2.5">
            {[
              {
                href: `${BASE_PATH}/recovery/keym.py`,
                name: 'keym.py',
                what: 'A standalone Python decryptor. Standard library plus one dependency for Argon2id; no browser, no npm, no network.',
              },
              {
                href: `${BASE_PATH}/recovery/RECOVERY.md`,
                name: 'RECOVERY.md',
                what: 'The procedure in writing, including how to decrypt by hand if even the script is gone. Worth printing and storing with the backup.',
              },
            ].map((item) => (
              <div
                key={item.name}
                className="rounded-xl border border-white/10 bg-white/2 p-3"
              >
                <div className="flex items-center justify-between gap-3">
                  <span className="font-mono text-[13px] font-medium">{item.name}</span>
                  <a
                    href={item.href}
                    download
                    className="shrink-0 rounded-lg border border-white/10 px-2.5 py-1 text-[12px] font-medium text-muted-foreground transition-colors hover:border-white/20 hover:text-foreground"
                  >
                    <Download className="mr-1 inline h-3 w-3 align-[-1px]" />
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
            data. The format itself is documented in{' '}
            <code className="rounded bg-white/8 px-1 py-0.5">FORMAT.md</code>, and{' '}
            <code className="rounded bg-white/8 px-1 py-0.5">keym.py</code> was written
            from that document independently of the code running here — which is how a
            specification bug got caught before it shipped.
          </p>
        </DialogContent>
      </Dialog>
    </Tabs>
  );
}

    