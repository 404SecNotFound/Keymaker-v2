
"use client";

import { useState, useRef, type ChangeEvent, type DragEvent, type RefObject, type ReactNode, useCallback, useEffect } from "react";
import { QRCodeCanvas } from "qrcode.react";
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
  KdfId,
  CipherId,
  DEFAULT_ARGON2ID,
  type KdfParams,
  type DetectedFormat,
} from "@/lib/keymaker-crypto";
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

// Chunked base64 encode/decode to avoid stack overflow on large buffers.
// The spread operator in btoa(String.fromCharCode(...arr)) exceeds the
// maximum call stack size for buffers larger than ~65KB.
function uint8ArrayToBase64(bytes: Uint8Array): string {
  const CHUNK_SIZE = 0x8000; // 32KB — well under any engine's argument limit
  let binary = '';
  for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
    const chunk = bytes.subarray(i, i + CHUNK_SIZE);
    binary += String.fromCharCode.apply(null, chunk as unknown as number[]);
  }
  return btoa(binary);
}

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

// Password strength gate, entropy-aware. Two paths count as strong:
//  1. The classic class rule: ≥24 chars with upper, lower, number, symbol.
//     The symbol class is kept in sync with the generatePassword charset so
//     a generated password can never be rejected by this check.
//  2. The diceware rule: a long passphrase of 4+ words (e.g. an all-lowercase
//     "correct horse battery staple"-style phrase) carries its entropy in
//     word count, not character classes. 6+ words is accepted regardless of
//     length (6 diceware words ≈ 77 bits minimum).
function isPasswordStrong(pwd: string): boolean {
  const wordCount = pwd.trim().split(/\s+/).filter(Boolean).length;
  if (wordCount >= 6) return true;
  if (wordCount >= 4 && pwd.length >= 24) return true;
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
      onFileChange(e);
    }
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
        onKeyDown={(e) => e.key === "Enter" && handleContainerClick()}
      >
        <div className="mb-3 grid h-12 w-12 place-items-center rounded-xl bg-white/5 text-accent">
          {icon}
        </div>
        <div className="w-full overflow-hidden">
          <h3 className="text-[15px] font-medium text-foreground">{label}</h3>
          <p className={cn(
            "mt-1 w-full overflow-hidden truncate text-[13px]",
            selectedFile ? "font-medium text-accent" : "text-muted-foreground"
          )}>
            {selectedFile ? selectedFile.name : description}
          </p>
        </div>
      </div>
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
        onChange={onFileChange}
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
}

function RevealableQr({
  getValue,
  revealed,
  onToggleReveal,
  onDownload,
  hiResRef,
  warning,
  caption,
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
const QR_MAX_CHARS = 2_953;

// Self-identifying prefix for encrypted TEXT blobs (files carry the binary
// "KEYM" magic instead). Decryption strips it if present and still accepts
// bare base64 IBTZ blobs.
const KEYM_TEXT_PREFIX = "KEYM1:";

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
    blurb: "Maximum: encrypts with AES-256-GCM, then ChaCha20-Poly1305 with an independent key. An attacker must break both.",
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
  const [showPassword, setShowPassword] = useState(false);
  const [showTextSecret, setShowTextSecret] = useState(false);
  // Advanced encryption options (Encrypt tab only — the KEYM container is
  // self-describing, so decryption needs no knobs).
  const [isAdvancedOpen, setIsAdvancedOpen] = useState(false);
  const [kdfChoice, setKdfChoice] = useState<KdfChoice>("pbkdf2");
  const [argonTimeCost, setArgonTimeCost] = useState(DEFAULT_ARGON2ID.timeCost);
  const [argonMemoryMiB, setArgonMemoryMiB] = useState(DEFAULT_ARGON2ID.memoryKiB / 1024);
  const [argonParallelism, setArgonParallelism] = useState(DEFAULT_ARGON2ID.parallelism);
  const [cipherChoice, setCipherChoice] = useState<CipherId>(CipherId.AES_256_GCM);
  const [obscureFilename, setObscureFilename] = useState(false);
  // Post-decrypt info line: which container format/params were detected.
  const [decryptInfo, setDecryptInfo] = useState<string | null>(null);
  const [showDecryptedText, setShowDecryptedText] = useState(false);
  const [useKeyFile, setUseKeyFile] = useState(false);
  const [keyFile, setKeyFile] = useState<File | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isCryptoAvailable, setIsCryptoAvailable] = useState(true);
  const [isQrModalOpen, setIsQrModalOpen] = useState(false);
  const clipboardTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

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
  const [textSecretSeedStatus, setTextSecretSeedStatus] = useState<
    "none" | "valid" | "invalid"
  >("none");
  const { toast } = useToast();

  // Derived, not stored — cheap (5 regex tests) and always consistent with
  // `password`, removing a state variable and its sync points.
  const passwordIsStrong = isPasswordStrong(password);

  // Clean up clipboard auto-clear timer on unmount
  useEffect(() => {
    return () => {
      if (clipboardTimeoutRef.current) {
        clearTimeout(clipboardTimeoutRef.current);
      }
    };
  }, []);

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

  const handlePasswordChange = useCallback((pwd: string) => {
    setPassword(pwd);
  }, []);

  const resetState = useCallback(() => {
    setFile(null);
    setPassword('');
    setShowPassword(false);
    setUseKeyFile(false);
    setKeyFile(null);
    setTextSecret('');
    setShowTextSecret(false);
    setOutputText('');
    setShowDecryptedText(false);
    setDecryptInfo(null);
    setInputType('file');
    setIsDecryptedQrModalOpen(false);
    setIsDecryptedQrRevealed(false);
    setDecryptedQrStatus({ kind: "idle" });
  }, []);

  const handleModeChange = useCallback((newMode: string) => {
    setMode(newMode as Mode);
    // The Tools tab has no shared state with encrypt/decrypt — resetting
    // would only wipe an in-progress form when the user peeks at Tools.
    if (newMode !== "tools") {
      resetState();
    }
  }, [resetState]);
  
  const handleInputTypeChange = useCallback((newType: string) => {
      setInputType(newType as InputType);
      // Clear any previous result when the input type changes. The blur and
      // reveal controls on the decrypted output are scoped to text mode, so
      // carrying outputText across the switch would render a decrypted
      // secret fully visible with no way to re-hide it.
      setOutputText('');
      setShowDecryptedText(false);
      setDecryptInfo(null);
      setIsDecryptedQrModalOpen(false);
      setIsDecryptedQrRevealed(false);
      setDecryptedQrStatus({ kind: "idle" });
  }, []);

  const handleFileChange = useCallback((
    e: ChangeEvent<HTMLInputElement> | DragEvent<HTMLDivElement>,
    setter: (file: File | null) => void
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
    
    if (selectedFile.size > MAX_FILE_SIZE) {
      toast({
        title: "File Too Large",
        description: `Please select a file smaller than ${MAX_FILE_SIZE / 1024 / 1024}MB.`,
        variant: "destructive",
      });
      setter(null);
      return;
    }

    setter(selectedFile);
  }, [toast]);
  

  const generatePassword = useCallback(() => {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~`|}{[]:;?><,./-=";
    const passwordLength = 32;
    const charsetLength = charset.length;
    // Rejection sampling: discard values that would cause modulo bias.
    // limit is the largest multiple of charsetLength that fits in a Uint32.
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
    toast({ title: "Password Generated", description: "A new secure password has been generated." });
  }, [toast, handlePasswordChange]);


  const handleCopy = useCallback((textToCopy: string) => {
    if (!textToCopy) return;
    navigator.clipboard.writeText(textToCopy).then(() => {
      toast({ title: "Copied to clipboard", description: "Auto-clear will be attempted in 60 seconds (may not work if tab loses focus)." });

      // Reset any existing auto-clear timer
      if (clipboardTimeoutRef.current) {
        clearTimeout(clipboardTimeoutRef.current);
      }

      // Auto-clear clipboard after 60 seconds (best-effort)
      clipboardTimeoutRef.current = setTimeout(async () => {
        try {
          const current = await navigator.clipboard.readText();
          if (current === textToCopy) {
            await navigator.clipboard.writeText('');
          }
        } catch {
          // Clipboard read may fail if tab is not focused — silently ignore
        }
        clipboardTimeoutRef.current = null;
      }, 60_000);
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
    let mutablePassword = password;

    const hasInput = inputType === 'file' ? !!file : !!textSecret;
    if (!hasInput) {
      toast({
        title: `Missing ${inputType === 'file' ? 'File' : 'Text'}`,
        description: `Please provide a ${inputType} to process.`,
        variant: "destructive",
      });
      return;
    }
    if (!mutablePassword) {
        toast({
          title: "Password Required",
          description: "Please provide a password.",
          variant: "destructive",
        });
        return;
    }
    
    if (mode === "encrypt" && !isPasswordStrong(mutablePassword)) {
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
    setDecryptedQrStatus({ kind: "idle" });

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
        resultBuffer = await encryptData(inputBuffer, mutablePassword, keyFileBuffer, { kdf, cipher: cipherChoice });

        if (inputType === 'file') {
            const blob = new Blob([resultBuffer]);
            const outName = obscureFilename
              ? `keymaker-${randomFilenameSuffix()}.keym`
              : `${file!.name}.keym`;
            triggerDownload(blob, outName);
            setFile(null);
        } else {
            const base64String = uint8ArrayToBase64(new Uint8Array(resultBuffer));
            setOutputText(KEYM_TEXT_PREFIX + base64String);
            setTextSecret('');
        }

      } else { // Decrypt — the KEYM container is self-describing, and legacy
        // IttyBitz (IBTZ) blobs are auto-detected and handled transparently.
        let inputBuffer: ArrayBuffer;
        if (inputType === 'file') {
            inputBuffer = await file!.arrayBuffer();
        } else {
            let blobText = textSecret.trim();
            if (blobText.toUpperCase().startsWith(KEYM_TEXT_PREFIX)) {
              blobText = blobText.slice(KEYM_TEXT_PREFIX.length);
            }
            const bytes = base64ToUint8Array(blobText);
            inputBuffer = bytes.buffer as ArrayBuffer;
        }

        const decryptResult = await decryptData(inputBuffer, mutablePassword, keyFileBuffer);
        resultBuffer = decryptResult.data;

        // Info line + legacy-format nudge.
        const formatLabels: Record<DetectedFormat, string> = {
          "keym-v1": "Keymaker v1",
          "ibtz-v1": "IttyBitz v1 (legacy)",
          "ibtz-v0": "IttyBitz v0 (legacy)",
        };
        let info = `Format: ${formatLabels[decryptResult.format]}`;
        if (decryptResult.format === "keym-v1") {
          const inspected = inspectKeym(new Uint8Array(inputBuffer));
          if (inspected) info += ` · ${inspected.kdfLabel} · ${inspected.cipherLabel}`;
        }
        if (decryptResult.keyFileUsed) info += " · key file";
        setDecryptInfo(info);
        if (decryptResult.format !== "keym-v1") {
          toast({
            title: "Imported from IttyBitz",
            description: "This is a legacy IttyBitz container. Consider re-encrypting in Keymaker format.",
          });
        }

        if (inputType === 'file') {
             const stripped = file!.name.replace(/\.(keym|ibitz)$/i, '');
             const resultFilename = stripped !== file!.name
              ? stripped
              : `decrypted-${file!.name}`;
            const blob = new Blob([resultBuffer]);
            triggerDownload(blob, resultFilename);
        } else {
            const decoder = new TextDecoder();
            const decryptedText = decoder.decode(resultBuffer);
            setOutputText(decryptedText);

            // Detect whether the decrypted text is a valid BIP-39 mnemonic —
            // this only labels the QR button and picks the SeedQR encoding.
            // Best-effort: if the lazy module can't load (e.g. offline before
            // the chunk was cached), treat the output as plain text rather
            // than failing the decryption.
            try {
              const { validateBip39 } = await loadBip39();
              const result = await validateBip39(decryptedText);
              setDecryptedQrStatus(
                result.valid
                  ? { kind: "seed", words: result.words }
                  : { kind: "plain", seedShaped: result.seedShaped }
              );
            } catch {
              setDecryptedQrStatus({ kind: "plain", seedShaped: false });
            }
        }
      }

      // Best-effort erase of the result buffer now that its contents have
      // been handed off (Blob construction copies the bytes; the decoded
      // string and base64 output are separate allocations). Matters most on
      // decrypt, where this buffer held the plaintext.
      new Uint8Array(resultBuffer).fill(0);

      toast({
        title: "Success!",
        description: `Your ${inputType} has been successfully ${mode === 'encrypt' ? 'encrypted' : 'decrypted'}.`,
      });
    } catch (error: any) {
        const knownSafeMessages = [
          'Invalid encrypted data format.',
          'Cannot process empty data.',
          'Password must be a string.',
          'Password is too long.',
          'Password contains invalid characters.',
          'A password is required for encryption.',
          'A password or key file is required for decryption.',
          'Web Crypto API not available.',
          'This file was encrypted with a newer version of IttyBitz. Please update the app.',
          'This file was encrypted with a newer KEYM version. Please update the app.',
        ];
        const raw = error.message || '';
        const safeMessage = knownSafeMessages.includes(raw)
          ? raw
          : mode === 'decrypt'
            ? 'Decryption failed. The password or key file may be incorrect, or the data may be corrupted.'
            : 'Processing failed. Please try again.';

        toast({
            title: "Processing Error",
            description: safeMessage,
            variant: "destructive",
        });
    } finally {
      // Clear sensitive data
      setPassword('');
      setIsLoading(false);
    }
  }, [file, mode, keyFile, toast, inputType, textSecret, password, kdfChoice, argonTimeCost, argonMemoryMiB, argonParallelism, cipherChoice, obscureFilename]);
  
  const handleUseKeyFileChange = useCallback((checked: boolean) => {
      setUseKeyFile(checked);
      if (!checked) {
          setKeyFile(null);
      }
  }, []);

  const getPasswordStrengthColor = useCallback(() => {
    if (!password) return "border-input";
    if (isPasswordStrong(password)) return "border-success";
    return "border-destructive";
  }, [password]);

  const isProcessButtonDisabled = () => {
    if (isLoading || !isCryptoAvailable) return true;
    const hasInput = inputType === 'file' ? !!file : !!textSecret;
    const hasPassword = !!password;
    if (!hasInput || !hasPassword) return true;
    
    if (mode === 'encrypt' && !passwordIsStrong) {
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
          <Tooltip>
            <TooltipTrigger asChild>
              <button type="button" className="focus:outline-hidden">
                <Info className="h-3.5 w-3.5 text-muted-foreground/60" />
              </button>
            </TooltipTrigger>
            <TooltipContent>
              <p>For additional security, you can use a key file. Use the generator to create a new, highly secure key file (recommended), or select an existing file. This file will be required along with your password to decrypt data.</p>
            </TooltipContent>
          </Tooltip>
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
            <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">or</span>
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
            onFileChange={(e) => handleFileChange(e, setFile)}
            onClear={() => setFile(null)}
            selectedFile={file}
            icon={<FileText size={22} />}
            label="Drop a file here"
            description={`or click to browse · 100 MB max`}
          />
        ) : (
          <div className="space-y-2">
            <Label htmlFor="text-secret" className="text-[13px] font-medium text-muted-foreground">
              Secret text
            </Label>
            <div className="relative">
              <Textarea
                id="text-secret"
                value={textSecret}
                onChange={(e) => setTextSecret(e.target.value)}
                placeholder={`Enter text to ${currentMode}...`}
                rows={5}
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
                  aria-label={showTextSecret ? "Hide secret text" : "Show secret text"}
                  className="absolute right-2 top-2 rounded-lg border border-white/10 bg-white/5 p-1.5 text-muted-foreground transition-all hover:bg-white/10 hover:text-foreground"
                >
                  {showTextSecret ? <Eye className="h-4 w-4" /> : <EyeOff className="h-4 w-4" />}
                </button>
              )}
            </div>
          </div>
        )}

        <TooltipProvider>
          <div>
            <div className="mb-2 flex items-center gap-1.5">
              <Label htmlFor="password" className="text-[13px] font-medium text-muted-foreground">
                Password
              </Label>
              <Tooltip>
                <TooltipTrigger asChild>
                  <button type="button" className="focus:outline-hidden">
                    <Info className="h-3.5 w-3.5 text-muted-foreground/60" />
                  </button>
                </TooltipTrigger>
                <TooltipContent>
                  <p>Min 24 chars with upper/lowercase, number &amp; symbol — or a 4+ word passphrase (diceware-style passphrases count as strong).</p>
                </TooltipContent>
              </Tooltip>
            </div>
            <div className="relative">
              <Input
                id="password"
                value={password}
                type={showPassword ? "text" : "password"}
                onChange={(e) => handlePasswordChange(e.target.value)}
                placeholder={currentMode === 'encrypt' ? "Enter a strong password" : "Enter decryption password"}
                className={cn(
                  "h-11 rounded-xl border border-white/10 bg-white/4 pr-[74px] text-[15px] transition-colors focus-visible:border-accent/50 focus-visible:ring-0",
                  getPasswordStrengthColor()
                )}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-2 top-1/2 -translate-y-1/2 rounded-lg border border-white/10 bg-white/5 px-2.5 py-1 text-xs font-medium text-muted-foreground transition-all hover:bg-white/10 hover:text-foreground"
              >
                {showPassword ? 'Hide' : 'Show'}
              </button>
            </div>
            <div className="mt-2.5 flex gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => handleCopy(password)}
                disabled={!password}
                className="flex-1 rounded-lg border-white/10 bg-white/4 text-[13px] font-medium text-muted-foreground hover:bg-white/8 hover:text-foreground"
              >
                <Copy className="mr-1.5 h-3.5 w-3.5" />Copy
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => handlePasswordChange("")}
                disabled={!password}
                className="flex-1 rounded-lg border-white/10 bg-white/4 text-[13px] font-medium text-muted-foreground hover:bg-white/8 hover:text-foreground"
              >
                <X className="mr-1.5 h-3.5 w-3.5" />Clear
              </Button>
              {currentMode === 'encrypt' && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={generatePassword}
                  className="flex-1 rounded-lg border-white/10 bg-white/4 text-[13px] font-medium text-muted-foreground hover:bg-white/8 hover:text-foreground"
                >
                  <RefreshCw className="mr-1.5 h-3.5 w-3.5" />Generate
                </Button>
              )}
            </div>
          </div>

          {currentMode === 'decrypt' && keyFileControls}

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
                <div className="min-h-0 overflow-hidden">
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
                          <p className="mt-0.5 text-[11px] leading-snug text-muted-foreground">
                            Fastest and most compatible. 1M iterations of SHA-256.
                          </p>
                        </button>
                        <button
                          type="button"
                          onClick={() => setKdfChoice("argon2id")}
                          className={cn(
                            "rounded-lg border p-3 text-left transition-colors",
                            kdfChoice === "argon2id"
                              ? "border-accent/60 bg-accent/10"
                              : "border-white/10 bg-white/2 hover:border-white/20"
                          )}
                        >
                          <p className="text-[13px] font-semibold">Argon2id <span className="text-accent">· recommended</span></p>
                          <p className="mt-0.5 text-[11px] leading-snug text-muted-foreground">
                            Memory-hard — resists GPU/ASIC password cracking.
                          </p>
                        </button>
                      </div>

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
                          <p className="text-[11px] text-muted-foreground">
                            Estimated derivation time: ≈{Math.max(1, Math.round((argonTimeCost * argonMemoryMiB) / 64))}s per attempt on a typical laptop (varies by device).
                          </p>
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
                              <span className="mt-0.5 block text-[11px] leading-snug text-muted-foreground">{blurb}</span>
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
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <button type="button" className="focus:outline-hidden">
                              <Info className="h-3.5 w-3.5 text-muted-foreground/60" />
                            </button>
                          </TooltipTrigger>
                          <TooltipContent>
                            <p>Encrypted downloads are named keymaker-&lt;random&gt;.keym so the original filename stays private.</p>
                          </TooltipContent>
                        </Tooltip>
                      </div>
                    </div>

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

      {decryptInfo && currentMode === 'decrypt' && (
        <p className="animate-in fade-in-50 rounded-lg bg-white/4 px-3 py-2 text-[12px] text-muted-foreground">
          <Info className="mr-1.5 inline h-3.5 w-3.5 align-[-2px]" />
          {decryptInfo}
        </p>
      )}

      {outputText && (
        <div className="animate-in fade-in-50 space-y-2">
          <Label htmlFor="output-text" className="text-[13px] font-medium text-muted-foreground">
            Result
          </Label>
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
                      {outputText.length <= QR_MAX_CHARS ? (
                        <>
                          <div className="rounded-lg bg-white p-4">
                            <QRCodeCanvas value={outputText} size={256} level="L" marginSize={0} />
                          </div>
                          <div ref={hiResQrRef} style={OFFSCREEN_STYLE}>
                            <QRCodeCanvas value={outputText} size={900} level="L" />
                          </div>
                          <Button onClick={handleDownloadQrCode}>
                            <Download className="mr-2 h-4 w-4" />
                            Download PNG (300 DPI)
                          </Button>
                        </>
                      ) : (
                        <div className="rounded-md bg-yellow-900/20 p-3 text-center text-sm text-yellow-400">
                          <p className="font-medium">QR code unavailable</p>
                          <p className="mt-1">Output is {outputText.length.toLocaleString()} characters, which exceeds the QR code capacity of {QR_MAX_CHARS.toLocaleString()} characters. Use the copy button instead.</p>
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
                        />
                      ) : outputText.length <= QR_MAX_CHARS ? (
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
                            Decrypted text is {outputText.length.toLocaleString()} characters,
                            which exceeds the QR code capacity of {QR_MAX_CHARS.toLocaleString()}{' '}
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

      <Button
        onClick={processData}
        disabled={isProcessButtonDisabled()}
        className="mt-2 h-auto w-full rounded-xl bg-linear-to-br from-[#e3a35c] via-[#c07f2e] to-[#8a5a1c] py-3.5 text-[15px] font-semibold text-black shadow-[0_8px_24px_-8px_rgba(192,127,46,0.5)] transition-all hover:-translate-y-px hover:shadow-[0_12px_32px_-8px_rgba(192,127,46,0.65)] disabled:opacity-40 disabled:hover:translate-y-0"
      >
        {isLoading ? (
          <Loader2 className="mr-2 h-5 w-5 animate-spin" />
        ) : (
          currentMode === 'encrypt' ? <Lock className="mr-2 h-5 w-5" /> : <Unlock className="mr-2 h-5 w-5" />
        )}
        {currentMode === 'encrypt' ? `Encrypt ${inputType === 'file' ? 'File' : 'Text'}` : `Decrypt ${inputType === 'file' ? 'File' : 'Text'}`}
      </Button>
    </div>
  );

  const tabTriggerClasses = "rounded-lg px-4 py-1.5 text-[13px] font-medium text-muted-foreground data-[state=active]:bg-white/10 data-[state=active]:text-foreground data-[state=active]:shadow-xs";

  return (
    <Tabs value={mode} onValueChange={handleModeChange} className="flex min-h-screen flex-col">
      {/* ---- HEADER ---- */}
      <header className="sticky top-0 z-50 w-full border-b border-white/8 bg-black/70 backdrop-blur-xl backdrop-saturate-150">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-3 sm:px-6">
          <div className="flex items-center gap-2.5">
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
            <span className="text-[17px] font-semibold tracking-tight">Keymaker</span>
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
              <a href="https://github.com/seQRets/ittybitz" target="_blank" rel="noopener noreferrer" className="text-accent hover:underline">
                Open source
              </a>
              , forked from IttyBitz. No accounts. No servers.
            </p>
          </div>

          {/* Card */}
          <section className="glass-card rounded-[20px] p-6 sm:p-8">
            <TabsContent value="encrypt" className="mt-0">
              {renderContent("encrypt")}
            </TabsContent>
            <TabsContent value="decrypt" className="mt-0">
              {renderContent("decrypt")}
            </TabsContent>
            <TabsContent value="tools" className="mt-0">
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
          <div className="flex items-center gap-3">
            <a href="https://github.com/seQRets/ittybitz" target="_blank" rel="noopener noreferrer" className="hover:underline">GitHub</a>
            <span>Keymaker v1.0.0</span>
          </div>
        </div>
      </footer>
    </Tabs>
  );
}

    