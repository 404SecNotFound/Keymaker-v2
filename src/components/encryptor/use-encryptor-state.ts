"use client";

/**
 * The Encryptor tool's shared state: every piece of it more than one tab
 * module reads or writes, plus the handlers that touch it. This is the
 * "brain" half of the split described in `encryptor-tool.tsx`'s header — the
 * "view" half is `secret-form.tsx`, `recovery-tab.tsx` and `shares-dialog.tsx`,
 * which all read this hook's return value through `EncryptorContext`.
 *
 * Moved verbatim out of the body of `EncryptorTool()` as part of the module
 * split. It stayed one hook rather than several smaller ones because the
 * state inside it is genuinely cross-referential — `processData` alone reads
 * or writes upward of thirty of the pieces below — and splitting it further
 * would mean threading that many values between hooks for no behavioural
 * gain, which is a worse trade than one large, cohesive file. See CLAUDE.md's
 * note on not chasing a line count at the cost of clarity.
 */
import {
  useState,
  useRef,
  useCallback,
  useEffect,
  useMemo,
  type ChangeEvent,
  type DragEvent,
} from "react";
import type { InspectorPlan } from "@/components/container-inspector";
import type { CommandBarItem } from "@/components/command-bar";
import { emptySeedWords, seedWordsFromText } from "@/components/seed-grid";
import { armorKeym2, KEYM2_HEADER_PEEK_BYTES } from "@/lib/keym-v2";
import { looksLikeSelfExtract, extractSelfExtract } from "@/lib/keym-v2-selfextract";
import { looksLikePaperPart, describePaperPart, decodePaperPartsAny, splitPaperParts } from "@/lib/keym-v2-paper";
import { decodeAllQrImage, decodeQrImages, QrDecodeError } from "@/lib/qr-decode";
import { meetsPasswordPolicy } from "@/lib/password-policy";
import {
  BookOpen,
  KeyRound,
  Lock,
  Unlock,
  RefreshCw,
  Globe,
  Dices,
  ShieldCheck,
  LifeBuoy,
  Trash2,
  Timer,
  FolderOpen,
  ScrollText,
  FileAudio,
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import {
  inspectKeym,
  isArgon2idAvailable,
  isUserFacingError,
  KeymakerError,
  warmCryptoDependencies,
  MAX_PLAINTEXT_SIZE,
  oversizeRecoveryHelp,
  MAX_BASE64_INPUT_CHARS,
  MAX_TEXT_PLAINTEXT_BYTES,
  MAX_TEXT_ARMOR_CHARS,
  KdfId,
  CipherId,
  DEFAULT_ARGON2ID,
  type KdfParams,
  type DetectedFormat,
  loadKeym2,
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
  type DeviceFit,
} from "@/lib/kdf-calibration";
import { EFF_LARGE_WORDLIST, EFF_LARGE_WORDLIST_SIZE } from "@/lib/eff-wordlist";
import {
  type Mode,
  type InputType,
  type InputChoice,
  type Bip39Module,
  type GeneratedSecret,
  type KdfChoice,
  type Door,
  type VerifyResult,
  type DecryptedQrStatus,
  type RehearsalState,
  type Receipt,
  loadBip39,
  parseShareLines,
  shareInputRejection,
  isShareText,
  mergeScannedShares,
  base64ToUint8Array,
  containerFromTextFile,
  validateAndSanitizeFile,
  triggerDownload,
  exportCanvasPng,
  paintedFrame,
  preparePaperParts,
  kdfLabelOf,
  cipherLabelOf,
  randomFilenameSuffix,
  DOORS,
  BASE_PATH,
  KEYMAKER_REPO,
  NOTHING_PASTED,
  KEYM_V1_TEXT_PREFIX,
  KEYM_V2_TEXT_PREFIX,
  CLIPBOARD_CLEAR_SECONDS,
  AUTO_LOCK_MS,
  LOCK_WARN_SECONDS,
  PASSWORD_CHARSET,
  PASSWORD_LENGTH,
  PASSWORD_ENTROPY_BITS,
  PASSPHRASE_WORDS,
  PASSPHRASE_SEPARATOR,
  PASSPHRASE_ENTROPY_BITS,
} from "./shared";

/**
 * Everything the Encryptor tool's tabs and dialogs share, in one hook. The
 * return value is provided to the tab modules through `EncryptorContext`;
 * see `context.tsx`.
 */
export function useEncryptorState() {
  const [mode, setMode] = useState<Mode>("encrypt");
  /** The last mode that owns a form (anything but Tools), so a return from a
   *  Tools peek can be told apart from a switch to a different form. */
  const formModeRef = useRef<Mode>("encrypt");
  const [workspacePage, setWorkspacePage] = useState<"workbench" | "workspace" | "recovery" | "docs">("workbench");
  const [compactNavigation, setCompactNavigation] = useState(false);
  useEffect(() => {
    const query = window.matchMedia("(max-width: 760px)");
    const sync = () => setCompactNavigation(query.matches);
    sync();
    query.addEventListener("change", sync);
    return () => query.removeEventListener("change", sync);
  }, []);
  const [inputType, setInputType] = useState<InputType>('file');
  /**
   * Seed Phrase mode — the grid editor for the text input.
   *
   * Not a third input type. `textSecret` stays the plaintext the crypto path
   * seals, and the grid is another editor for it: every change to the cells
   * writes the joined words back, so nothing downstream — the size gate, the
   * inspector's byte count, the encrypt call — has a second field to know
   * about. `seedWords` is the same secret in its own shape and is wiped with
   * it; its length is the phrase length, a layout choice that stays.
   */
  const [seedMode, setSeedMode] = useState(false);
  const [seedWords, setSeedWords] = useState<string[]>(() => emptySeedWords(12));
  /** The lazily loaded wordlist, held as state so the grid re-renders when it lands. */
  const [bip39, setBip39] = useState<Bip39Module | null>(null);
  const [file, setFile] = useState<File | null>(null);
  // True only while a QR image is being decoded, to disable the scan control
  // and show progress. Decoding is a few milliseconds for the app's own
  // exports but can be longer for a large phone photo.
  const [qrScanBusy, setQrScanBusy] = useState(false);
  const qrInputRef = useRef<HTMLInputElement>(null);
  const shareQrInputRef = useRef<HTMLInputElement>(null);
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
  /**
   * v4 §6: padding is the owner's choice, off until they make it. On, the
   * writer emits a KEYM v4 container whose length states only the bucket
   * the plaintext falls in; off, the usual v3.
   */
  const [hideSize, setHideSize] = useState(false);
  /**
   * The re-seal offer: the format of the backup just opened, when that
   * format is older than today's (v1, v2, IttyBitz), or null. v3 §6 says a
   * v2 backup moves to v3 only by decrypting and re-encrypting, and that it
   * is the owner's decision; this is where the decision is put in front of
   * them, with the backup open.
   */
  const [resealOffer, setResealOffer] = useState<DetectedFormat | null>(null);
  /** What a started re-seal carried to the Encrypt tab: the text, or nothing (a file). */
  const [resealNotice, setResealNotice] = useState<"text" | "file" | null>(null);
  const [showDecryptedText, setShowDecryptedText] = useState(false);
  const [useKeyFile, setUseKeyFile] = useState(false);
  const [keyFile, setKeyFile] = useState<File | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  /** Read by the idle-lock interval, which is not re-created on every change. */
  const isLoadingRef = useRef(false);
  useEffect(() => {
    isLoadingRef.current = isLoading;
  }, [isLoading]);
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
  const [verifyResult, setVerifyResult] = useState<VerifyResult | null>(null);

  // Recovery kit modal — see the footer.
  const [isRecoveryOpen, setIsRecoveryOpen] = useState(false);

  // Roadmap 4.5. The inheritance plan is a guided orientation on the encrypt
  // path, entered on purpose from the command bar or the link under the doors.
  // It is closed by any mode switch, because it belongs to a deliberate
  // encrypt-and-hand-on session, not to whatever the next tab is doing.
  const [inheritanceOpen, setInheritanceOpen] = useState(false);

  /**
   * The command bar (⌘K / Ctrl+K).
   *
   * Every entry calls a handler that already exists on the page — the bar adds
   * reach, never capability, which is what keeps it out of the security
   * argument entirely. The list itself is built beside the render, where the
   * handlers it names are in scope; see `commandBarCommands`.
   */
  const [isCommandBarOpen, setIsCommandBarOpen] = useState(false);
  /**
   * Which modifier the hint in the header advertises. Resolved after mount:
   * the export is static HTML, so the server render has no platform to ask,
   * and "Ctrl K" is the honest default for the first paint — it is also
   * accepted everywhere, ⌘ being the alias rather than the rule.
   */
  const [isApplePlatform, setIsApplePlatform] = useState(false);

  useEffect(() => {
    setIsApplePlatform(/Mac|iPhone|iPad/.test(navigator.platform));
  }, []);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && !e.altKey && !e.shiftKey && e.key.toLowerCase() === "k") {
        // Both browsers put something on Ctrl+K (search-from-address-bar);
        // while this page has focus the palette wins, which is the trade
        // every ⌘K app makes.
        e.preventDefault();
        setIsCommandBarOpen((open) => !open);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  const clipboardTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  /**
   * Wall-clock instant the clipboard is due to be overwritten, or null.
   *
   * A deadline rather than a countdown integer, so the ticking effect owns the
   * display and nothing has to fire a side effect from inside a state updater.
   */
  const [clipboardDeadline, setClipboardDeadline] = useState<number | null>(null);
  const [clipboardSecondsLeft, setClipboardSecondsLeft] = useState<number | null>(null);
  /**
   * The deadline passed but the browser refused the overwrite.
   *
   * Chromium rejects `navigator.clipboard.writeText` with
   * `NotAllowedError: Document is not focused` whenever the tab is not the
   * active one, and "copied the secret, switched to another app to paste it"
   * is the normal state of affairs at the sixty-second mark. Dropping the
   * countdown on that rejection left the secret in the clipboard with the UI
   * implying it had gone: the same promise-we-cannot-keep as the old
   * read-and-compare, one layer down. While this is set the clear stays armed
   * and is retried the moment the page is in a position to succeed.
   */
  const [clipboardClearPending, setClipboardClearPending] = useState(false);

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
  /**
   * §4.8. The strips open the backup only together with the password: one slot
   * that takes both, and nothing beside it. Off by default, because it makes a
   * forgotten password, or too few strips, the end of the backup.
   */
  const [sharesNeedPassword, setSharesNeedPassword] = useState(false);
  const [issuedShares, setIssuedShares] = useState<{
    threshold: number;
    shares: string[];
    /** §4.8: these strips open the backup only together with the password. */
    withPassword?: boolean;
  } | null>(null);
  /**
   * "Put the whole backup on every strip", for a backup small enough to fit
   * one printed symbol. Off by default and reset with every new share set: it
   * changes who can open the backup without the owner, so it is chosen each
   * time, never inherited.
   */
  const [stripsCarryBackup, setStripsCarryBackup] = useState(false);
  const [backupFitsOnStrip, setBackupFitsOnStrip] = useState(false);
  /**
   * The rehearsal — test the backup before you trust it.
   *
   * Shares are shown once with a strong warning, then gone, and the first
   * time anyone learns whether they work is the day they are needed. This
   * walks the owner through the heir's path while the strips are still on
   * screen: paste any k of them, exactly as an heir would, and the container
   * is opened with them alone — no password — through the same worker call
   * the verify-only unlock uses, and closed again without a byte reaching
   * the DOM, the clipboard, or a Blob. What is reported is that it opened,
   * how long it took, and which strips did it; the plaintext exists in the
   * worker for the length of one call and is zeroed on arrival.
   *
   * The pasted strips are secrets (any k of them are the password) and are
   * wiped with everything else. The outcome is not a secret, and it is not
   * kept either: it goes onto the next paper vault as ink and is discarded
   * with the rest, because the app stores nothing and the sheet in the
   * drawer is where a rehearsal record belongs.
   */
  const [rehearsalOpen, setRehearsalOpen] = useState(false);
  const [rehearsalInput, setRehearsalInput] = useState("");
  /** §4.8: the password, for rehearsing strips that open the backup only with it. */
  const [rehearsalPassword, setRehearsalPassword] = useState("");
  const [rehearsalInputRejected, setRehearsalInputRejected] = useState<string | null>(null);
  const [rehearsal, setRehearsal] = useState<RehearsalState>({ kind: "idle" });
  const rehearsalLines = useMemo(() => parseShareLines(rehearsalInput), [rehearsalInput]);
  /**
   * The workbench pane's copy of the opening bytes of the last container this
   * session wrote — captured before the download hands the only full copy to
   * the browser, because a file encrypt keeps nothing else around to parse.
   * Ciphertext header and slot table only, never key material, but it still
   * describes the user's backup, so it is wiped with everything else.
   */
  const [sealedPeek, setSealedPeek] = useState<Uint8Array | null>(null);
  /**
   * "Check this printout", on the Recovery page: one line per photo, saying
   * whether its code read back and whether it belongs to the backup this
   * session wrote. Null until a check has run. Never holds a decrypted byte:
   * the check derives no key and combines no shares.
   */
  const [printoutFindings, setPrintoutFindings] = useState<
    { file: string; text: string; problem: boolean }[] | null
  >(null);
  const [printoutBusy, setPrintoutBusy] = useState(false);
  const printoutInputRef = useRef<HTMLInputElement>(null);
  /** The live camera scanner, and whether this browser offers a camera at all. */
  const [cameraOpen, setCameraOpen] = useState(false);
  const [cameraAvailable, setCameraAvailable] = useState(false);
  useEffect(() => {
    setCameraAvailable(typeof navigator !== "undefined" && !!navigator.mediaDevices?.getUserMedia);
  }, []);
  /**
   * The receipt — the seal as a ceremony (10× plan, Bet 6).
   *
   * Press Encrypt, spinner, toast, output: correct and forgettable, and the
   * next steps — download, print, issue shares, rehearse — were scattered
   * across the form and the footer. The moment of completion is the one
   * moment the owner is certain to be paying attention, so it gets a receipt
   * instead of a toast: what was written, how it is protected (in the same
   * words the inspector uses, from the same function), the ways in, what left
   * this device (nothing), and the three real next steps as buttons. It is
   * state, not a secret — it names no key material — and it is cleared with
   * the output it describes.
   */
  const [receipt, setReceipt] = useState<Receipt | null>(null);
  // Whether the backup on screen fits one printed symbol, so the shares
  // dialog can offer to put it on every strip. Recomputed for each share set,
  // and the choice itself starts off again with each.
  useEffect(() => {
    setStripsCarryBackup(false);
    setBackupFitsOnStrip(false);
    if (!issuedShares || !outputText.startsWith("keym2:")) return;
    let live = true;
    (async () => {
      try {
        const { dearmorKeym2 } = await loadKeym2();
        const { encodePaperPartsForPrint } = await import("@/lib/keym-v2-paper");
        const parts = await encodePaperPartsForPrint(dearmorKeym2(outputText));
        if (live) setBackupFitsOnStrip(parts.length === 1);
      } catch {
        if (live) setBackupFitsOnStrip(false);
      }
    })();
    return () => {
      live = false;
    };
  }, [issuedShares, outputText]);

  // Printout findings describe one backup. A new seal or a wipe replaces or
  // clears it, and lines saying "belongs to this backup" must go with it.
  useEffect(() => {
    setPrintoutFindings(null);
  }, [receipt, sealedPeek]);
  /**
   * The wipe's acknowledgment, in place of a toast. A wipe is a deliberate
   * act, and a toast that fades in a few seconds is not an acknowledgment of
   * one; this stays until the next thing appears on screen.
   */
  const [wipeAck, setWipeAck] = useState(false);
  /** Decrypt-side twin: read live off the loaded input, before any unlock. */
  const [decryptPeek, setDecryptPeek] = useState<Uint8Array | null>(null);
  /**
   * Read by the auto-lock interval, which closes over state from the render
   * that armed it. The effect depends on `hasSecretsOnScreen` only, so by the
   * time the interval fires `issuedShares` in its closure may be a tick old —
   * and this decides which of two toasts the user is told, so it has to be
   * current rather than nearly current.
   */
  const issuedSharesRef = useRef<{ threshold: number; shares: string[]; withPassword?: boolean } | null>(null);
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
    /** §7.3 KMPART2 parts, encoded before this state is set so the sheet mounts ready. */
    parts: string[];
    /** The container needs too many symbols to be a paper backup. */
    tooLarge: boolean;
    shares?: string[];
    threshold?: number;
    /** §4.8: the strips open the backup only together with the password. */
    sharesNeedPassword?: boolean;
    /** §4.6 set codes of the container's share slots, for the owner's sheet. */
    setCodes: string[];
    /** The backup's one paper part, printed on every strip as well, when chosen. */
    stripBackupPart?: string | undefined;
    printedOn: string;
    /** A rehearsal that succeeded this session, to be written on the sheet. */
    rehearsal?: { on: string; strips: number[] } | undefined;
  } | null>(null);
  /*
    4.2. Print after the sheet is in the DOM, not from the click handler.

    `window.print()` snapshots the document synchronously, so calling it in the
    same tick as setState prints the previous render — which is an empty sheet.
    The double rAF waits for React to commit and the browser to lay the QR
    symbols out; printing between those two produces a page of blank squares.

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
        //
        // A refusal is not the end of it. The write needs document focus,
        // and a background tab does not have it, so the clear is kept armed
        // and retried on return rather than silently abandoned.
        navigator.clipboard.writeText('').catch(() => setClipboardClearPending(true));
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

  /**
   * Retry a refused clipboard clear as soon as the page can plausibly succeed.
   *
   * `focus` and `visibilitychange` are the events that mark a return to the
   * tab; `pointerdown` and `keydown` are belt and braces for a browser that
   * delivers neither (or delivers them before it considers the document
   * focused). A retry that is refused again costs nothing and keeps the
   * notice up; only a write that resolves stands the clear down.
   */
  useEffect(() => {
    if (!clipboardClearPending) return;
    let cancelled = false;
    const retry = () => {
      navigator.clipboard
        .writeText('')
        .then(() => {
          if (!cancelled) setClipboardClearPending(false);
        })
        .catch(() => {});
    };
    window.addEventListener("focus", retry);
    document.addEventListener("visibilitychange", retry);
    window.addEventListener("pointerdown", retry);
    window.addEventListener("keydown", retry);
    return () => {
      cancelled = true;
      window.removeEventListener("focus", retry);
      document.removeEventListener("visibilitychange", retry);
      window.removeEventListener("pointerdown", retry);
      window.removeEventListener("keydown", retry);
    };
  }, [clipboardClearPending]);

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
    loadBip39()
      .then((m) => setBip39(m))
      .catch(() => {
        // Ignored — processData retries the import and degrades gracefully.
      });
  }, []);

  // Debounced BIP-39 check on the encrypt-side secret text, so a typo'd
  // seed phrase is caught BEFORE it gets encrypted into a long-term backup.
  // Deliberately color-only (border tint) — no text badge that would tell a
  // shoulder-surfer the blurred field holds a seed phrase.
  useEffect(() => {
    // The grid reports per word and never needs this whole-phrase verdict.
    if (mode !== "encrypt" || inputType !== "text" || seedMode || !textSecret.trim()) {
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
  }, [textSecret, mode, inputType, seedMode]);

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
  const handleTextSecretChange = useCallback(async (next: string): Promise<boolean> => {
    const decrypting = mode === 'decrypt';
    if (decrypting) {
      if (next.length > MAX_TEXT_ARMOR_CHARS) {
        setTextInputRejected(
          `That is ${Math.round(next.length / 1024).toLocaleString()} KB of text. ` +
          `Encrypted text is accepted up to ${MAX_TEXT_ARMOR_CHARS / 1024} KB — ` +
          `for anything larger, decrypt the .keym file itself in File mode. ` +
          NOTHING_PASTED
        );
        return false;
      }
    } else {
      const bytes = new Blob([next]).size;
      if (bytes > MAX_TEXT_PLAINTEXT_BYTES) {
        setTextInputRejected(
          `That is ${Math.round(bytes / 1024).toLocaleString()} KB. ` +
          `Text mode is for secrets up to ${MAX_TEXT_PLAINTEXT_BYTES / 1024} KB — ` +
          `switch to File mode to encrypt something this size. ` +
          NOTHING_PASTED
        );
        return false;
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
    if (decrypting && isShareText(next)) {
      setTextInputRejected(
        'That is a recovery share, not an encrypted container. Put the container here, ' +
        'then choose "Use recovery shares" beside the password field to enter it.'
      );
      setTextSecret(next);
      return false;
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
        return true;
      } catch (e) {
        // Structural, never routed through the AEAD: a page problem reported as
        // a decryption failure sends someone to retype a password that was
        // never wrong.
        setTextInputRejected((e as Error).message);
        setTextSecret(next);
      }
      return false;
    }

    // §7.1/§7.3. Paper parts, and the same rule §7.2 sets for a self-extracting
    // page: a reader that recognises the encoding and *can* use it must use it.
    //
    // This branch used to only report. It told the reader "scan them all into
    // this box, one per line" — and then, when they did, told them the same
    // thing again, because nothing here ever reassembled anything.
    // `decodePaperParts` was written, exported and reachable from no caller in
    // the app; only `keym2.py join` ever used it. So the one instruction the
    // paper vault gives its own user could not be followed in the tool that
    // gave it.
    //
    // Version-aware: `decodePaperPartsAny` dispatches on the prefix, so a
    // KMPART2 set (what the vault now writes) and any older KMPART1 page both
    // reassemble here. It is async because §7.3's checksums are SHA-256.
    if (decrypting && looksLikePaperPart(next)) {
      const lines = splitPaperParts(next);
      try {
        // Structural, never routed through the AEAD, for the reason the
        // self-extract branch gives above: a missing page reported as a
        // decryption failure sends someone to retype a password that was
        // never wrong.
        const container = await decodePaperPartsAny(lines);
        setTextInputRejected(null);
        setTextSecret(armorKeym2(container));
        toast({
          title: `Paper backup reassembled from ${lines.length} ${lines.length === 1 ? "part" : "parts"}`,
          description: "Type the password to open it.",
        });
        return true;
      } catch (e) {
        // Every one of these names what is actually wrong — which part is
        // missing, which was scanned twice, which does not belong to this set.
        // The one-part case is the common one and gets the fuller sentence.
        const part =
          lines.length === 1 ? describePaperPart(lines[0] ?? "") : null;
        setTextInputRejected(
          part
            ? `That is part ${part.index} of ${part.total} of a paper backup. Every one ` +
              `of the ${part.total} parts is needed — scan them all into this box, one per line.`
            : (e as Error).message
        );
        setTextSecret(next);
      }
      return false;
    }

    setTextInputRejected(null);
    setTextSecret(next);
    return true;
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
    const stopped = cancelAllCryptoWork();
    setIsLoading(false);
    setUnlockCostNotice(null);
    // `stopped` is false when there was no worker to terminate — a browser
    // where the script could not load, running the derivation in this realm.
    // Moving opSeqRef still guarantees the result is discarded, but WebCrypto
    // will finish the work regardless, and saying "cancelled" there would be
    // claiming something the app did not do. Distinguishing the two costs one
    // sentence and keeps the button honest on the browsers least able to
    // afford the wait.
    toast({
      title: stopped ? "Stopped" : "Stopped waiting",
      description: stopped
        ? "The unlock was cancelled. Your password and file are still here."
        : "This browser could not start the background worker, so the derivation " +
          "already under way will run to completion — its result is discarded. " +
          "Your password and file are still here.",
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
    // The grid's cells are the same secret in another shape. The count is a
    // layout choice and stays.
    setSeedWords((w) => w.map(() => ""));
    setTextInputRejected(null);
    setShowTextSecret(false);
    setTextSecretSeedStatus("none");
    // Spared with the shares, and for the same reason. Issued shares exist
    // only on the encrypt side, where `outputText` is the sealed container,
    // ciphertext rather than a secret, and in Text mode the only copy of it.
    // The lock used to keep the shares and wipe this, so the dialog went on
    // showing strips that now opened nothing, its Print paper vault button
    // went dark, and the note under it blamed "a file container".
    if (!(opts?.sparingIssuedShares && issuedSharesRef.current !== null)) setOutputText('');
    setShowDecryptedText(false);
    setDecryptInfo(null);
    setSlotTableWarning(false);
    setResealOffer(null);
    setResealNotice(null);
    setVerifyResult(null);
    setSealedPeek(null);
    setReceipt(null);

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
    // The rehearsal's pasted strips are k shares in a textarea — the
    // password, in effect. Its outcome is discarded with them: the record
    // is the ink on the printed sheet, never state.
    setRehearsalOpen(false);
    setRehearsalInput("");
    setRehearsalPassword("");
    setRehearsalInputRejected(null);
    setRehearsal({ kind: "idle" });

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
    setSeedMode(false);
    setWipeAck(false);
    // 4.5. A tab click ends the inheritance session the plan was guiding, the
    // same way it resets the form beneath it.
    setInheritanceOpen(false);
  }, [clearSensitiveState]);

  /**
   * The panic wipe, as one named action. It had one caller (the "Wipe now"
   * link under the form); the command bar is the second, and the toast copy
   * must not fork between them — two surfaces describing the same wipe
   * differently is how someone comes to believe there are two wipes.
   */
  const wipeNow = useCallback(() => {
    clearSensitiveState();
    // Acknowledged where the wipe happened, and for as long as the screen
    // stays empty — not in a toast that is gone before it is read.
    setWipeAck(true);
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
    // Mirrored into `textSecret` on every change, so this clause is never the
    // one that fires — it is here so the list stays the same list as the one
    // in `clearSensitiveState`, by construction rather than by remembering.
    seedWords.some(Boolean) ||
    outputText.length > 0 ||
    // KM-R03. Share-only decryption is the case this predicate missed: an heir
    // has no password and may have decrypted a *file*, so all three of the
    // above can be empty while the textarea holds enough shares to open the
    // container. The timer was not armed and the Wipe now button was not
    // rendered — on the one flow where the person at the keyboard is least
    // likely to be at their own desk.
    shareInput.length > 0 ||
    rehearsalInput.length > 0 ||
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
      // An operation in progress is the user waiting on this tab, not a tab
      // left alone. A container may ask for minutes of derivation (the §6
      // ceiling measured at 315 s), and the lock used to fire in the middle:
      // it cancelled the unlock the user was sitting through and wiped the
      // password they had just typed. The idle clock starts when it finishes.
      if (isLoadingRef.current) {
        lastActivityRef.current = Date.now();
        setLockSecondsLeft(null);
        return;
      }
      const left = Math.ceil((AUTO_LOCK_MS - (Date.now() - lastActivityRef.current)) / 1000);
      if (left <= 0) {
        // Re-arm before wiping. When issued shares are spared the secrets stay
        // on screen, this effect does not re-run, and the interval keeps
        // sampling, so without this line every following tick was another
        // lock: a fresh toast, another cancelAllCryptoWork, another re-render,
        // once a second, aimed at the person copying one-time shares onto
        // paper. Moving the activity mark here makes the lock fire once per
        // idle period and re-arm naturally if a password is typed later while
        // the shares remain. Clearing the interval instead would leave that
        // later password unprotected, because nothing would restart the clock.
        lastActivityRef.current = Date.now();
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
    setWorkspacePage("workbench");
    if (newMode === mode) return;
    setMode(newMode as Mode);
    // The Tools tab has no shared state with encrypt/decrypt — resetting
    // would only wipe an in-progress form when the user peeks at Tools.
    if (newMode === "tools") return;
    // And the peek has two halves. Skipping the reset on the way *in* was
    // not enough: coming back out was an ordinary mode change, so Encrypt,
    // Tools, Encrypt still wiped the secret and password the first half had
    // just spared. Returning to the form Tools was opened from is not a mode
    // change; going anywhere else still is.
    const returning = mode === "tools" && newMode === formModeRef.current;
    formModeRef.current = newMode as Mode;
    if (!returning) resetState();
  }, [mode, resetState]);
  
  /**
   * Carry the recovered result to the Encrypt tab as its input, and let the
   * ordinary seal write today's format. Deliberately not a one-click
   * re-encrypt: the password was cleared on success (U13) and the plaintext
   * buffer erased, so a silent re-seal would have to keep both. Recovered
   * text is already on screen, so it travels; a recovered file was
   * downloaded and is not kept, so the owner is asked to choose it.
   *
   * The mode change resets the form (as every tab change does), so what is
   * carried is set after it; React applies the updates in order.
   */
  const startReseal = useCallback(() => {
    const kind = inputType;
    const carried = kind === "text" ? outputText : null;
    handleModeChange("encrypt");
    setInputType(kind);
    if (carried !== null) setTextSecret(carried);
    setResealNotice(kind);
  }, [inputType, outputText, handleModeChange]);

  const handleInputTypeChange = useCallback((newType: InputChoice) => {
      // Same reasoning as resetState: an operation started against File mode
      // must not deliver its result into Text mode. This was the reproducible
      // half of the bug — switch input type mid-derivation and the finished
      // operation announced "Success!" on a panel that had never run it.
      opSeqRef.current++;
      cancelAllCryptoWork();
      setIsLoading(false);
      setInputType(newType === 'file' ? 'file' : 'text');
      // Seed Phrase mode is the text input in another editor. Entering it
      // takes whatever the textarea held into the cells, and writes the
      // cleaned words back to `textSecret` at once, the same write the grid
      // makes on every edit. The cells are what the user sees and the status
      // line vouches for; `textSecret` is what gets sealed. Deriving one
      // without rewriting the other left a phrase pasted with stray
      // whitespace, newlines or numbering showing a clean grid and a matching
      // checksum while the raw string went into the container. An empty
      // textarea yields empty cells and an empty secret, so nothing is
      // invented. Leaving seed mode needs nothing: the cells wrote the joined
      // words back on every change.
      const seed = newType === 'seed';
      setSeedMode(seed);
      if (seed) {
        const words = seedWordsFromText(textSecret);
        setSeedWords(words);
        setTextSecret(words.filter(Boolean).join(' '));
      }
      // Clear any previous result when the input type changes. The blur and
      // reveal controls on the decrypted output are scoped to text mode, so
      // carrying outputText across the switch would render a decrypted
      // secret fully visible with no way to re-hide it.
      setOutputText('');
      setShowDecryptedText(false);
      setDecryptInfo(null);
      setSlotTableWarning(false);
      setSealedPeek(null);
      setIsDecryptedQrModalOpen(false);
      setIsDecryptedQrRevealed(false);
      setDecryptedQrStatus({ kind: "idle" });
      setReceipt(null);
      setWipeAck(false);
  }, [textSecret]);

  /**
   * Decrypt-side QR scan: turn one or more QR images into the encrypted text
   * they carry, then hand that text to the same routing a paste gets.
   *
   * A Keymaker QR encodes exactly what the Decrypt text box already accepts:
   * a `keym2:` armor string, a `KMPART2:`/`KMPART1:` paper part, or a
   * `KMSHARE2:`/`KMSHARE1:` share.
   * So this decodes image to string and lets `handleTextSecretChange` decide
   * what the string is. Several parts are joined with newlines, in the order
   * the files were given, which is the shape `decodePaperParts` reassembles.
   *
   * Switching to Text mode is deliberate: the recovered container has to be
   * visible above the password, and the reveal/blur controls the output uses
   * only exist in text mode.
   */
  /**
   * Route scanned QR text to the box that can use it. From image files, which
   * are decoded here, or from codes the camera already read (`fromCamera`),
   * which take exactly the same path from that point on.
   */
  const handleQrImageFiles = useCallback(async (files: readonly File[], fromCamera?: readonly string[]) => {
    if (files.length === 0 && !(fromCamera && fromCamera.length > 0)) return;
    setQrScanBusy(true);
    // The same staleness rule every other async path here follows. Decoding a
    // large photo takes a moment, and a tab switch or Wipe now in that moment
    // moves opSeqRef: the result then belongs to a form that no longer exists,
    // and writing it would put a container into the Encrypt field, or undo
    // the wipe the user just asked for.
    const seq = opSeqRef.current;
    try {
      const texts = fromCamera ? [...fromCamera] : await decodeQrImages(files);
      if (opSeqRef.current !== seq) return;
      // A printed backup opened without the password is container parts *and*
      // share strips, and the person opening it photographs all of it. Each
      // string goes to the box that can use it: shares to the shares box,
      // everything else to the container box. Joining them all into the
      // container box instead failed the whole set as one bad paste, and a
      // strip scanned on its own was only ever told it was in the wrong place.
      // The printed strips carry a QR precisely so this path exists.
      const shares = texts.filter(isShareText);
      // The same code read twice is one code. Strips that each carry the
      // backup put the same container symbol in every photo, and handing
      // the reassembler that symbol twice made it refuse the set as
      // "supplied twice". Shares are de-duplicated by mergeScannedShares.
      const rest = [...new Set(texts.filter((t) => !isShareText(t)))];
      // Checked before any state changes, so a refused set leaves the form
      // exactly as it was.
      const merged = shares.length > 0 ? mergeScannedShares(shareInput, shares) : null;
      const rejection = merged ? shareInputRejection(merged.text) : null;
      if (rejection) throw new QrDecodeError(rejection);

      // Only a container needs text mode. Shares scanned while a .keym file
      // is selected in File mode belong beside that file, and switching mode
      // would drop the very container they are meant to open.
      if (rest.length > 0 && inputType !== 'text') handleInputTypeChange('text');
      if (merged) {
        // Shares and a passkey are exclusive unlock paths; see the toggle.
        setUsePasskey(false);
        setUseShares(true);
        setShareInputRejected(null);
        setShareInput(merged.text);
      }
      // Whether the container box took what was scanned. A lone paper part,
      // or a set with a page missing, is kept in the box with a note naming
      // the problem, and the toast must not then say to type the password.
      const accepted = rest.length > 0 ? await handleTextSecretChange(rest.join("\n")) : true;

      const title = fromCamera
        ? `${texts.length} code${texts.length === 1 ? "" : "s"} read by the camera`
        : files.length === 1
          ? "QR image scanned"
          : `${files.length} QR images scanned`;
      if (!accepted) {
        toast({
          title,
          description: "It is not a complete backup yet. The note under the box says what is missing.",
          variant: "destructive",
        });
      } else if (!merged) {
        toast({
          title,
          description:
            "The encrypted text is in the box below. Type the password to open it.",
        });
      } else {
        const where =
          merged.added === 0
            ? "Every share scanned was already in the recovery-shares box."
            : `${merged.added} recovery ${merged.added === 1 ? "share is" : "shares are"} now in the recovery-shares box` +
              (merged.repeated > 0 ? ` (${merged.repeated} scanned twice, counted once).` : ".");
        const next =
          rest.length > 0 || (inputType === 'file' ? !!file : !!textSecret.trim())
            ? " With enough of them no password is needed. If the container needs more, the attempt will simply fail."
            : " The encrypted backup itself goes in the box above: scan or paste it too.";
        toast({ title, description: where + next });
      }
    } catch (e) {
      // A QR that will not read is a scanning problem, never an AEAD one, so it
      // is reported here and never allowed to reach the password path. That is
      // the same discipline the paper-part and self-extract branches keep, for
      // the same reason: a bad scan reported as a decryption failure sends
      // someone to retype a password that was never wrong.
      if (opSeqRef.current !== seq) return;
      const description =
        e instanceof QrDecodeError
          ? e.message
          : "That image could not be read as a QR code.";
      toast({ title: "Could not read QR", description, variant: "destructive" });
    } finally {
      setQrScanBusy(false);
    }
  }, [inputType, handleInputTypeChange, handleTextSecretChange, toast, shareInput, textSecret, file]);

  /** Is this file an image, and so a QR to scan rather than a container to open?
   *  MIME first, extension as the fallback for a drag that carried no type. */
  const isImageFile = useCallback((f: File) => {
    return /^image\//.test(f.type) || /\.(png|jpe?g|webp|gif|bmp)$/i.test(f.name);
  }, []);

  /**
   * The grid's one write path. The cells are the source of truth while the
   * grid is showing; `textSecret` follows them so the encrypt path never has
   * to know which editor was used.
   */
  const handleSeedWordsChange = useCallback((words: string[]) => {
    setSeedWords(words);
    setTextSecret(words.filter(Boolean).join(" "));
    setTextInputRejected(null);
  }, []);

  /**
   * Which door, if any, describes the form as it stands. Plain text mode is
   * behind no door — it is the power user's path, reached from the pills.
   */
  const currentDoor: Door | null =
    mode === "decrypt"
      ? "open"
      : mode === "encrypt" && inputType === "file"
        ? "file"
        : mode === "encrypt" && inputType === "text" && seedMode
          ? "seed"
          : null;

  /**
   * A door configures; it does not pre-render a form (the anticipation rule).
   * Where the mode changes it goes through `handleModeChange`, so the reset
   * is exactly the reset a tab click does; where only the input changes it
   * goes through `handleInputTypeChange`, likewise. The defaults are the
   * point: a seed phrase suggests shares, because it is the one thing people
   * seal for someone else; a file does not. Pressing the door already pressed
   * is a no-op, so a form in progress is never reset by a stray click.
   */
  const openDoor = useCallback((door: Door) => {
    setWorkspacePage("workbench");
    if (door === currentDoor) return;
    if (door === "open") {
      if (mode !== "decrypt") handleModeChange("decrypt");
      else if (inputType !== "file") handleInputTypeChange("file");
      return;
    }
    const changingMode = mode !== "encrypt";
    if (changingMode) handleModeChange("encrypt");
    if (door === "seed") {
      if (changingMode) {
        // resetState has just queued the file default; these land after it.
        setInputType("text");
        setSeedMode(true);
        setSeedWords(emptySeedWords(12));
      } else {
        handleInputTypeChange("seed");
      }
      setShamirEnabled(true);
    } else {
      if (!changingMode) handleInputTypeChange("file");
      setShamirEnabled(false);
    }
  }, [currentDoor, mode, inputType, handleModeChange, handleInputTypeChange]);

  /**
   * 4.5. Open the inheritance plan. Like a door, it configures the existing
   * form and adds no capability: encrypt mode, recovery shares on, and Advanced
   * open so the k-of-n controls the plan points at are in view. The plan flag is
   * set last, after `handleModeChange` may have queued a reset that clears it,
   * the same ordering `openDoor` relies on to keep its `setShamirEnabled(true)`.
   */
  const openInheritance = useCallback(() => {
    setWorkspacePage("workbench");
    if (mode !== "encrypt") handleModeChange("encrypt");
    // Text, because step 4 is the paper vault, and the paper vault prints a
    // container that is on screen: a sealed *file* is downloaded instead, so
    // the plan used to open on the one input where its own step 4 could not be
    // followed. Only switched when needed, since the switch clears a result.
    if (mode !== "encrypt" || inputType !== "text") handleInputTypeChange("text");
    setShamirEnabled(true);
    setIsAdvancedOpen(true);
    setInheritanceOpen(true);
  }, [mode, inputType, handleModeChange, handleInputTypeChange]);

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
        // Cancelling a replacement picker leaves the previous selection intact.
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
      setClipboardClearPending(false);
    } catch {
      // Writing needs document focus. A click normally brings that with it,
      // but if the write is refused anyway the clear stays armed and the
      // notice says so, rather than the button appearing to have worked.
      setClipboardClearPending(true);
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
      // A fresh copy supersedes any clear still pending from the last one:
      // otherwise the next keystroke would wipe the secret just copied.
      setClipboardClearPending(false);
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
      // null on the encrypt side: the receipt is the announcement there.
      notice: { title: string; description: string } | null
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
      if (notice) toast(notice);

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
    setResealOffer(null);
    setResealNotice(null);
    setVerifyResult(null);
    setSealedPeek(null);
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

        // A main-thread Argon2id derivation freezes the tab.
        //
        // hash-wasm derives synchronously, so with no Worker it blocks the
        // event loop for the whole run — the spinner does not animate and the
        // Stop button never renders, because React cannot paint. The work is
        // not lost and the container is identical; the tab is simply gone for
        // the duration, which at the §6 ceiling is minutes.
        //
        // Said beforehand rather than fixed by quietly lowering the cost. The
        // KDF and its parameters are the user's choice, and silently writing a
        // weaker backup than the one they asked for is the trade this project
        // does not make. PBKDF2 needs no warning: WebCrypto keeps it
        // off-thread even in the fallback.
        if (kdf.kdf === KdfId.ARGON2ID) {
          const { workerWillBeUsed } = await import("@/lib/crypto-client");
          if (!(await workerWillBeUsed()) && !isStale()) {
            setUnlockCostNotice(
              "This browser could not start the background worker, so Argon2id will run " +
                "on the page's own thread. The tab will stop responding until it finishes — " +
                "there is no Stop button while that happens. Nothing is wrong and nothing " +
                "is lost; it will come back on its own."
            );
            // Before, not during. The next few statements end in a synchronous
            // derivation that owns the event loop, so this is the last moment
            // the browser can draw anything at all.
            await paintedFrame();
          }
        }

        const encoder = new TextEncoder();
        const inputBuffer = inputType === 'file' ? await file!.arrayBuffer() : (encoder.encode(textSecret).buffer as ArrayBuffer);
        // Stop, a tab switch or the lock can land while a large file is still
        // being read. Every await from here to the worker is a point where the
        // operation may already be disowned, and going on would start a fresh
        // worker and a full derivation whose result is then thrown away (and,
        // after a Stop had terminated the worker, announce that the browser
        // could not start one).
        if (isStale()) return;
        // §4.7. The authenticator has to be asked *here*, on the main thread,
        // before any work is handed over: a Worker cannot reach
        // navigator.credentials. The slot salt is chosen first because the PRF
        // salt derives from it, so the question put to the key depends on a
        // value the container does not yet contain.
        let passkey: { prfOutput: Uint8Array; salt: Uint8Array } | undefined;
        // §4.8 rules a passkey out: it would open the backup on its own.
        if (passkeyEnabled && !(shamirEnabled && sharesNeedPassword)) {
          const { derivePrfSalt } = await loadKeym2();
          const { enrolPasskey } = await import("@/lib/webauthn-prf");
          const slotSalt = crypto.getRandomValues(new Uint8Array(32));
          const prfOutput = await enrolPasskey(await derivePrfSalt(slotSalt));
          passkey = { prfOutput, salt: slotSalt };
        }

        if (isStale()) return;
        // §4.6. Requested in the same call that writes the container, so the
        // share secret is generated and dropped inside the worker and the
        // password is not held past the operation that already needed it.
        const encrypted = await encryptViaWorker(
          inputBuffer,
          mutablePassword,
          keyFileBuffer,
          { kdf, cipher: cipherChoice, padded: hideSize },
          shamirEnabled
            ? { threshold: shamirThreshold, count: shamirCount, withPassword: sharesNeedPassword }
            : undefined,
          passkey
        );
        resultBuffer = encrypted.data;
        // The inspector's copy of what was just written: header and slot
        // table only, sliced synchronously — the note below forbids an await
        // in this window, and this needs none.
        if (!isStale()) {
          setSealedPeek(
            new Uint8Array(resultBuffer.slice(0, Math.min(KEYM2_HEADER_PEEK_BYTES, resultBuffer.byteLength)))
          );
        }
        if (!isStale()) {
          // A rehearsal describes the container it was run against. Only a
          // wipe used to clear it, so after rehearsing one backup and sealing
          // another, the new dialog showed the old result and the new paper
          // vault was stamped as rehearsed when it never had been.
          setRehearsal({ kind: "idle" });
          setRehearsalOpen(false);
          setRehearsalInput("");
          setRehearsalPassword("");
        }
        if (encrypted.shares && !isStale()) {
          // Straight to the modal. These exist exactly once — nothing can
          // reissue them — so they must not be left to be noticed.
          setIssuedShares({
            threshold: shamirThreshold,
            shares: encrypted.shares,
            withPassword: sharesNeedPassword,
          });
        }
        // **Do not put an `await` between here and the delivery below.**
        //
        // The auto-lock fires from a timer, so it can only interleave at a task
        // boundary. Today there is none between issuing the shares and writing
        // the container out, which is the only reason the bad interleaving is
        // unreachable: shares displayed, then the lock, then the container
        // silently not delivered — a set of one-time shares for a backup the
        // user never received, presented as if it were their recovery kit.
        //
        // A lock that fires during `encryptViaWorker` above is fine and is the
        // common case: `isStale()` is then true here, the shares are dropped
        // *and* so is the container, and the user redoes an operation that
        // produced nothing. Nothing is left half-issued.
        //
        // Anything added below that needs to await must re-check `isStale()`
        // after the await and before touching state, the way the text branch
        // does.

        // What the receipt says about protection comes from the same
        // functions the inspector's plan pane uses; the parsed pane says it
        // again from the bytes, and receipt.spec.ts holds the two together.
        const receiptOf = (from: string, to: string, onScreen: boolean): Receipt => ({
          from,
          to,
          kdf: kdfLabelOf(kdfChoice, argonMemoryMiB, argonTimeCost, argonParallelism),
          cipher: cipherLabelOf(cipherChoice),
          waysIn:
            shamirEnabled && sharesNeedPassword
              ? [
                  `${useKeyFile && keyFile ? "Passphrase + key file" : "Passphrase"} and ` +
                    `${shamirThreshold}-of-${shamirCount} recovery shares, both needed`,
                ]
              : [
                  useKeyFile && keyFile ? "Passphrase + key file" : "Passphrase",
                  ...(shamirEnabled ? [`${shamirThreshold}-of-${shamirCount} recovery shares`] : []),
                  ...(passkeyEnabled ? ["passkey"] : []),
                ],
          bytes: resultBuffer.byteLength,
          onScreen,
          shares: shamirEnabled ? { threshold: shamirThreshold, count: shamirCount } : null,
        });

        if (inputType === 'file') {
            const blob = new Blob([resultBuffer]);
            const outName = obscureFilename
              ? `keymaker-${randomFilenameSuffix()}.keym`
              : `${file!.name}.keym`;
            if (isStale()) return;
            triggerDownload(blob, outName);
            setReceipt(receiptOf(file!.name, outName, false));
            setFile(null);
        } else {
            if (isStale()) return;
            // §7's armor: base64url, unpadded, so the blob survives being
            // pasted into a URL, a filename or a QR code without escaping —
            // and so nobody has to strip `=` by hand from a backup they are
            // trying to recover. Dynamically imported for the same reason the
            // crypto core imports it that way.
            const { armorKeym2 } = await loadKeym2();
            setOutputText(armorKeym2(new Uint8Array(resultBuffer)));
            setReceipt(receiptOf("text", "keym2: container, on screen", true));
            setTextSecret('');
            // The grid's cells hold the same plaintext; sealed means gone.
            setSeedWords((w) => w.map(() => ""));
        }

      } else { // Decrypt — the KEYM container is self-describing, and legacy
        // IttyBitz (IBTZ) blobs are auto-detected and handled transparently.
        let inputBuffer: ArrayBuffer;
        if (inputType === 'file') {
            inputBuffer = await file!.arrayBuffer();
            const fromText = await containerFromTextFile(new Uint8Array(inputBuffer));
            // Copied rather than `.buffer`: a reader may hand back a view into
            // a larger buffer, and the container must be exactly its bytes.
            if (fromText) inputBuffer = new Uint8Array(fromText).buffer as ArrayBuffer;
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
              const { dearmorKeym2 } = await loadKeym2();
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
        // KEYM v1 header (71) with room to spare, but a slot table reaches 953
        // bytes at v3 + chained + the eight slots §6 allows. Pricing the unlock
        // below needs all of them, and a peek that stopped short would silently
        // price nothing at all — on exactly the expensive container this is
        // for. The size and its derivation live beside the format constants
        // they depend on; keym2-dispatch.mts asserts the relationship.
        const headerPeek = new Uint8Array(
          inputBuffer.slice(0, Math.min(KEYM2_HEADER_PEEK_BYTES, inputBuffer.byteLength))
        );

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
          const { keym2UnlockCost, describeUnlockCost } = await loadKeym2();
          const cost = keym2UnlockCost(headerPeek);
          const notice = describeUnlockCost(cost);
          // Same freeze, arriving from the other direction: here the KDF is the
          // container's choice rather than the user's, so the warning is driven
          // by what the header declares. A container can be cheap by the cost
          // ratio and still freeze the tab, so this is asked independently of
          // `notice` rather than folded into it.
          let freeze: string | null = null;
          if (cost !== null && cost.argon2Slots > 0) {
            const { workerWillBeUsed } = await import("@/lib/crypto-client");
            if (!(await workerWillBeUsed())) {
              freeze =
                "This browser could not start the background worker, so Argon2id will run " +
                "on the page's own thread. The tab will stop responding until it finishes — " +
                "there is no Stop button while that happens. Nothing is wrong and nothing " +
                "is lost; it will come back on its own.";
            }
          }
          const combined = [notice, freeze].filter(Boolean).join(" ");
          if (combined && !isStale()) {
            setUnlockCostNotice(combined);
            // Same reason as the encrypt side: if this one carries the freeze
            // warning, the unlock below is about to take the event loop.
            if (freeze) await paintedFrame();
          }
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
        // As on the encrypt side: the file read and the header peek above are
        // awaits, and a disowned operation must not ask for a passkey tap or
        // start a derivation.
        if (isStale()) return;
        let prfOutput: Uint8Array | undefined;
        if (usePasskey) {
          const { passkeySlotSaltsKeym2, derivePrfSalt } = await loadKeym2();
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

        // §4.8's MAY, taken: strips for a slot that also takes the password,
        // with no password typed, can never open it. Said before any work, in
        // the one sentence an heir needs, rather than after a derivation as
        // "decryption failed" about strips that were never wrong. From the slot
        // salts, which are in the clear, so it tells nobody anything new.
        if (suppliedShares.length > 0 && !mutablePassword) {
          const { sharesNeedPasswordKeym2 } = await loadKeym2();
          if (await sharesNeedPasswordKeym2(new Uint8Array(inputBuffer), suppliedShares)) {
            throw new KeymakerError(
              "credential-required",
              "These strips open this backup together with its password. Type the password as well, then try again."
            );
          }
        }

        if (isStale()) return;
        const decryptResult = await decryptViaWorker(
          inputBuffer,
          mutablePassword,
          keyFileBuffer,
          suppliedShares.length > 0 ? suppliedShares : undefined,
          prfOutput
        );
        resultBuffer = decryptResult.data;

        // A decrypt that goes stale mid-flight — a tab or mode switch, or the
        // auto-lock firing during one of the post-result awaits below
        // (inspectKeym2, loadBip39) — must not abandon the recovered plaintext
        // un-zeroed. finishOperation erases it on every success exit, but the
        // early returns that follow skip it, so they zero it here first. The
        // buffer is ours, and zeroing it a second time on a later path is
        // harmless.
        const abandonIfStale = (): boolean => {
          if (!isStale()) return false;
          new Uint8Array(resultBuffer).fill(0);
          return true;
        };

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
          "keym-v4": "KEYM v4",
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
          decryptResult.format === "keym-v3" ||
          decryptResult.format === "keym-v4"
        ) {
          // One inspector for both: every field it reads sits at a
          // version-dependent offset it already resolves from the header.
          const { inspectKeym2 } = await loadKeym2();
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
        if (abandonIfStale()) return;
        setDecryptInfo(info);
        // v3 §5.2. `false` only ever arrives after a slot has already opened
        // and the payload has already authenticated, so this reports on the
        // container's *recovery options*, never on the data. It deliberately
        // does not say which slot changed: the MAC covers the table as a whole
        // and the sealed table is not recoverable from the tampered one, so
        // "something changed" is the whole of what is known.
        setSlotTableWarning(decryptResult.slotTableAuthentic === false);
        // v3 §6 and §7: a v2 container is still strippable and there is no
        // in-place upgrade, so this is the moment to say so — with the backup
        // open, to the person holding its secret. v1 and IttyBitz files have
        // the same gap and more. Not on a verify-only run: nothing was kept
        // that could be carried over.
        setResealOffer(
          verifying || decryptResult.format === "keym-v3" || decryptResult.format === "keym-v4"
            ? null
            : decryptResult.format
        );

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
          setVerifyResult({ detail: info, bytes: resultBuffer.byteLength, method: suppliedShares.length > 0 ? "recovery shares" : usePasskey ? "passkey" : "password" });
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
              if (abandonIfStale()) return;
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
              if (abandonIfStale()) return;
              setDecryptedQrStatus(
                result.valid
                  ? { kind: "seed", words: result.words }
                  : { kind: "plain", seedShaped: result.seedShaped }
              );
            } catch {
              if (abandonIfStale()) return;
              setDecryptedQrStatus({ kind: "plain", seedShaped: false });
            }
        }
      }

      // The ordinary success path. Everything it used to do inline — erase the
      // buffer, announce, drop the shares, drop the password — now lives in
      // `finishOperation`, which the verify-only and non-text paths call too.
      // That is the point: three exits, one definition of "cleaned up".
      const done = `Your ${inputType} has been successfully ${mode === 'encrypt' ? 'encrypted' : 'decrypted'}.`;
      finishOperation(
        resultBuffer,
        // A seal is announced by its receipt, in the form, where the owner is
        // looking; a decrypt keeps the toast.
        mode === 'encrypt'
          ? null
          : {
              title: legacyNotice ? "Decrypted — legacy container" : "Success!",
              description: legacyNotice
                ? `${done} This was a legacy IttyBitz file; consider re-encrypting it in Keymaker format.`
                : done,
            }
      );
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
  }, [file, mode, keyFile, toast, inputType, textSecret, password, generated, kdfChoice, argonTimeCost, argonMemoryMiB, argonParallelism, cipherChoice, obscureFilename, isLoading, verifyOnly, useShares, shareInput, shamirEnabled, hideSize, shamirThreshold, shamirCount, sharesNeedPassword, passkeyEnabled, usePasskey]);
  
  const handleUseKeyFileChange = useCallback((checked: boolean) => {
      setUseKeyFile(checked);
      if (!checked) {
          setKeyFile(null);
      }
  }, []);

  // Encrypt only, and from the same verdict the button uses. On Decrypt the
  // policy does not apply: the right password is whatever the container was
  // sealed with, so a valid legacy password was painted red as if it were
  // wrong. And calling meetsPasswordPolicy without the generated flag
  // disagreed with the button about a generated passphrase.
  const getPasswordStrengthColor = useCallback(() => {
    if (!password || mode !== "encrypt") return "border-input";
    if (passwordMeetsPolicy) return "border-success";
    return "border-destructive";
  }, [password, mode, passwordMeetsPolicy]);

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
    // Seed Phrase mode seals only a phrase it has finished checking: every
    // cell holding a word the list knows. The checksum is reported, not
    // enforced — see the grid's header comment — so a mismatch does not
    // withhold the button.
    if (
      mode === 'encrypt' &&
      inputType === 'text' &&
      seedMode &&
      !(bip39 !== null && seedWords.every((w) => w !== "" && bip39.isBip39Word(w)))
    ) {
      return true;
    }
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

  // px-2.5 until there is room for px-4. The header is a wordmark and three
  // tabs on one row; at the tabs' full padding that row needs 412px, so every
  // phone narrower than an iPhone 14 Pro Max scrolled the whole page sideways —
  // which is what made the results grid look like it was overlapping.
  /**
   * Feed the workbench pane on the decrypt side: the same bounded header peek
   * the unlock-cost notice takes, but read as the input changes rather than
   * when the button is pressed — the whole point of the pane is that the file
   * explains itself before anything is spent. File reads stop at the peek
   * bound; armored pastes decode only a slice sized to cover it, so a
   * pathological paste costs the same as a healthy one (§ the paste gate
   * bounds the full decode separately).
   */
  useEffect(() => {
    if (mode !== "decrypt") {
      setDecryptPeek(null);
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        if (inputType === "file" && file) {
          const head = await file.slice(0, KEYM2_HEADER_PEEK_BYTES).arrayBuffer();
          if (!cancelled) setDecryptPeek(new Uint8Array(head));
          return;
        }
        if (inputType === "text") {
          const trimmed = textSecret.trim();
          if (
            trimmed.startsWith(KEYM_V2_TEXT_PREFIX) &&
            trimmed.length <= MAX_BASE64_INPUT_CHARS
          ) {
            const { dearmorKeym2 } = await loadKeym2();
            // 1392 armor characters cover the peek even if every 64-column
            // line break survived the paste; a slice that cuts mid-quantum
            // throws, is caught, and reads as "nothing loaded yet".
            const head = dearmorKeym2(
              trimmed.slice(0, KEYM_V2_TEXT_PREFIX.length + 1392)
            );
            if (!cancelled) setDecryptPeek(head.subarray(0, KEYM2_HEADER_PEEK_BYTES));
            return;
          }
        }
        if (!cancelled) setDecryptPeek(null);
      } catch {
        if (!cancelled) setDecryptPeek(null);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [mode, inputType, file, textSecret]);

  /**
   * The encrypt side of the pane restates the form, it does not predict the
   * worker: every string here names the same value processData will hand it.
   * The PBKDF2 literal is the one the operation uses — if that number moves,
   * this label is one of the two places it is written.
   */
  const inspectorPlan: InspectorPlan | null = useMemo(() => {
    if (mode !== "encrypt") return null;
    return {
      kdfLabel: kdfLabelOf(kdfChoice, argonMemoryMiB, argonTimeCost, argonParallelism),
      cipherLabel: cipherLabelOf(cipherChoice),
      cipherId: cipherChoice,
      keyFile: useKeyFile && keyFile !== null,
      shares: shamirEnabled ? { threshold: shamirThreshold, count: shamirCount } : null,
      // The encrypt-side enrol switch. `usePasskey` is the decrypt-side unlock
      // choice, false on this tab, so the plan used to omit the passkey slot
      // the worker was about to write: one way in and one byte-map segment
      // short.
      passkey: passkeyEnabled,
      inputBytes:
        inputType === "file"
          ? (file?.size ?? null)
          : textSecret.length > 0
            ? new TextEncoder().encode(textSecret).length
            : null,
    };
  }, [
    mode, kdfChoice, argonMemoryMiB, argonTimeCost, argonParallelism,
    cipherChoice, useKeyFile, keyFile, shamirEnabled, shamirThreshold,
    shamirCount, passkeyEnabled, inputType, file, textSecret,
  ]);

  /** What the next printed sheet says about rehearsal, or nothing yet. */
  const rehearsalStamp =
    rehearsal.kind === "ok" ? { on: rehearsal.on, strips: rehearsal.strips } : undefined;

  /**
   * The receipt's three buttons. Each calls what a control already called:
   * the paper vault's print path, the container's bytes to a download, and —
   * for a seal that issued strips — the heir's own route on the Decrypt tab
   * with the container filled in, verify-only on and the strip box open, so
   * the owner rehearses from the printed sheet exactly as an heir would. The
   * on-screen rehearsal in the shares dialog is the same exercise from the
   * strings; this is the one from paper.
   */
  const printPaperVault = useCallback(async () => {
    if (!outputText.startsWith("keym2:")) return;
    const { dearmorKeym2 } = await loadKeym2();
    const container = dearmorKeym2(outputText);
    const { parts, tooLarge, setCodes } = await preparePaperParts(container);
    setPaperVault({
      container,
      parts,
      tooLarge,
      setCodes,
      printedOn: new Date().toISOString().slice(0, 10),
      rehearsal: rehearsalStamp,
    });
  }, [outputText, rehearsalStamp]);

  const downloadContainer = useCallback(async () => {
    if (!outputText.startsWith("keym2:")) return;
    const { dearmorKeym2 } = await loadKeym2();
    triggerDownload(
      new Blob([dearmorKeym2(outputText).slice()]),
      `keymaker-${randomFilenameSuffix()}.keym`
    );
  }, [outputText]);

  const rehearseFromPaper = useCallback(() => {
    const armored = outputText;
    if (!armored.startsWith("keym2:")) return;
    // The mode change resets the form; everything below lands after it.
    handleModeChange("decrypt");
    setInputType("text");
    setTextSecret(armored);
    setUseShares(true);
    setVerifyOnly(true);
  }, [outputText, handleModeChange]);

  // The wipe's acknowledgment yields to the next thing on screen.
  useEffect(() => {
    if (hasSecretsOnScreen) setWipeAck(false);
  }, [hasSecretsOnScreen]);

  const handleRehearsalInputChange = useCallback((next: string) => {
    // The same bounds as the decrypt-side share box, for the same reason:
    // this is a share set or it is a paste into the wrong box.
    const rejection = shareInputRejection(next);
    if (rejection) {
      setRehearsalInputRejected(rejection);
      return;
    }
    setRehearsalInputRejected(null);
    setRehearsalInput(next);
    // A new paste is a new attempt; the last verdict no longer describes it.
    setRehearsal((r) => (r.kind === "failed" ? { kind: "idle" } : r));
  }, []);

  /**
   * The rehearsal itself. Identical to the heir's unlock — the worker, the
   * shares, no password — and different from every other decrypt in what
   * happens next: nothing. The buffer is zeroed on arrival and its length is
   * the only thing that survives. A result that lands after a wipe or a lock
   * has moved the operation counter is discarded, like any other.
   */
  const runRehearsal = useCallback(async () => {
    if (!issuedShares || !outputText.startsWith("keym2:")) return;
    const strips = parseShareLines(rehearsalInput);
    if (strips.length < issuedShares.threshold) return;
    const seq = opSeqRef.current;
    const isStale = () => opSeqRef.current !== seq;
    setRehearsal({ kind: "running" });
    const started = performance.now();
    try {
      const { dearmorKeym2 } = await loadKeym2();
      // A copy: the worker takes ownership of the buffer it is handed.
      const container = dearmorKeym2(outputText).slice();
      // §4.8. Strips that need the password are rehearsed with it, the way an
      // heir would have to open the backup.
      const result = await decryptViaWorker(
        container.buffer as ArrayBuffer,
        issuedShares.withPassword ? rehearsalPassword : "",
        null,
        strips
      );
      // The plaintext exists on this thread for exactly this long.
      const bytes = result.data.byteLength;
      new Uint8Array(result.data).fill(0);
      if (isStale()) return;
      const used = strips
        .map((s) => issuedShares.shares.indexOf(s) + 1)
        .filter((i) => i > 0)
        .sort((a, b) => a - b);
      setRehearsal({
        kind: "ok",
        on: new Date().toISOString().slice(0, 10),
        strips: used,
        seconds: (performance.now() - started) / 1000,
        bytes,
      });
      // The pasted strips have done their job; the ones above are still there.
      setRehearsalInput("");
      setRehearsalPassword("");
    } catch {
      if (isStale()) return;
      setRehearsal({
        kind: "failed",
        message:
          `These strips did not open the backup. Check each one against the sheet ` +
          `— a single wrong character is enough — and that at least ` +
          `${issuedShares.threshold} of the ${issuedShares.shares.length} are here` +
          (issuedShares.withPassword ? `, and that the password is the one you set.` : `.`),
      });
    }
  }, [issuedShares, outputText, rehearsalInput, rehearsalPassword]);

  /**
   * What the command bar offers, and when.
   *
   * Contextual on purpose, the way the page itself is: the generators exist
   * only where a password field does, and the wipe only while there is
   * something to wipe — a command that would do nothing is not listed rather
   * than listed grey. Mode switches go through `handleModeChange`, so they
   * reset state exactly as clicking the tab does; a switch to the mode
   * already showing is filtered out instead of resetting a form for nothing.
   */
  const commandBarCommands = useMemo<CommandBarItem[]>(() => {
    const items: CommandBarItem[] = [];
    if (mode !== "encrypt" || workspacePage !== "workbench") {
      items.push({
        id: "go-encrypt", group: "Go to", label: "Encrypt", icon: Lock,
        keywords: "seal file text mode tab",
        run: () => handleModeChange("encrypt"),
      });
    }
    if (mode !== "decrypt" || workspacePage !== "workbench") {
      items.push({
        id: "go-decrypt", group: "Go to", label: "Decrypt", icon: Unlock,
        keywords: "open unlock container mode tab",
        run: () => handleModeChange("decrypt"),
      });
    }
    if (mode !== "audio" || workspacePage !== "workbench") {
      items.push({
        id: "go-audio", group: "Go to", label: "Audio", icon: FileAudio,
        keywords: "steganography hide sound wav mp3 conceal mode tab",
        run: () => handleModeChange("audio"),
      });
    }
    if (mode !== "tools" || workspacePage !== "workbench") {
      items.push({
        id: "go-tools", group: "Go to", label: "Tools", icon: Dices,
        keywords: "dice entropy mode tab",
        run: () => handleModeChange("tools"),
      });
    }
    // The doors, reachable from the keyboard. After "Go to", so the list
    // still opens on the mode switches command-bar.spec.ts pins; the one
    // already pressed is left out for the same reason the current mode is.
    for (const door of DOORS) {
      if (door.id === currentDoor) continue;
      items.push({
        id: `door-${door.id}`, group: "Start", label: door.title, icon: door.icon,
        keywords: door.keywords,
        run: () => openDoor(door.id),
      });
    }
    // 4.5. In "Start" beside the doors, after them, so the "Go to" order
    // command-bar.spec.ts pins is untouched.
    items.push({
      id: "inheritance", group: "Start", label: "Set up an inheritance",
      icon: ScrollText,
      keywords: "heir estate legacy beneficiary will after death shares recovery",
      run: openInheritance,
    });
    if (mode === "encrypt") {
      items.push({
        id: "generate-password", group: "Encrypt", label: "Generate a random password",
        hint: `${PASSWORD_ENTROPY_BITS} bits`, icon: RefreshCw,
        keywords: "strong csprng",
        run: generatePassword,
      });
      items.push({
        id: "generate-passphrase", group: "Encrypt", label: "Generate a passphrase",
        hint: `${PASSPHRASE_ENTROPY_BITS} bits`, icon: Dices,
        keywords: "diceware words eff wordlist",
        run: generatePassphrase,
      });
      items.push({
        id: "generate-key-file", group: "Encrypt", label: "Generate a key file",
        hint: "64 bytes", icon: KeyRound,
        keywords: "second factor download",
        run: generateKeyFile,
      });
      items.push({
        id: "calibrate", group: "Encrypt", label: "Calibrate Argon2id for this device",
        hint: "~1s target", icon: Timer,
        keywords: "kdf memory benchmark measure advanced",
        // Open Advanced first: the calibration note renders there, and a
        // measurement whose result lands somewhere closed is a button that
        // appears to do nothing.
        run: () => {
          setIsAdvancedOpen(true);
          void runCalibration();
        },
      });
    }
    if (hasSecretsOnScreen) {
      items.push({
        id: "wipe-now", group: "Session", label: "Wipe now — clear secrets",
        icon: Trash2,
        keywords: "lock panic clear password",
        run: wipeNow,
      });
    }
    items.push({
      id: "recovery-kit", group: "Reference", label: "Open the recovery kit",
      icon: LifeBuoy,
      keywords: "offline python keym2.py heirs",
      run: () => setIsRecoveryOpen(true),
    });
    items.push({
      id: "verify-build", group: "Reference", label: "Verify this build",
      hint: "verify.html", icon: ShieldCheck,
      keywords: "manifest reproducible signature",
      // Same-tab, like the footer link it restates — and `.html` for the
      // reason the footer comment gives: the export has no /verify index.
      run: () => window.location.assign(`${BASE_PATH}/verify.html`),
    });
    items.push({
      id: "github", group: "Reference", label: "Open the source on GitHub",
      icon: Globe,
      keywords: "repository code issues",
      run: () => window.open(KEYMAKER_REPO, "_blank", "noopener,noreferrer"),
    });
    if (workspacePage !== "docs") {
      items.push({
        id: "docs", group: "Reference", label: "Read the docs",
        hint: "in the app", icon: BookOpen,
        keywords: "help guide manual documentation how to mistakes best practices",
        run: () => {
          // Same exit rule as the sidebar: Audio owns secret state.
          if (mode === "audio") handleModeChange("encrypt");
          setWorkspacePage("docs");
        },
      });
    }
    return items;
  }, [
    mode, workspacePage, currentDoor, openDoor, openInheritance, hasSecretsOnScreen, handleModeChange,
    generatePassword, generatePassphrase, generateKeyFile, runCalibration,
    wipeNow,
  ]);

  const activePage = workspacePage === "workbench" ? mode : workspacePage;
  const navigateWorkspace = (next: string) => {
    if (next === "workspace" || next === "recovery" || next === "docs") {
      // Audio owns local secret state. Leaving its view must unmount it.
      if (mode === "audio") handleModeChange("encrypt");
      setWorkspacePage(next);
    } else {
      handleModeChange(next);
    }
  };
  const pageCopy = {
    workspace: ["Secure workspace", "Choose what you want to protect, open, or recover."],
    encrypt: ["Encrypt", "Protect a file, a private note, or a recovery phrase."],
    decrypt: ["Decrypt", "Open an encrypted backup, or verify it without revealing its contents."],
    recovery: ["Recovery", "Prepare another way in. Test it before you need it."],
    audio: ["Audio", "Hide encrypted content inside a WAV file."],
    tools: ["Tools", "Generate entropy from physical dice rolls."],
    docs: ["Docs", "How Keymaker works, how to use it well, and what it does not protect against."],
  } as const;
  const navItems = [
    { id: "workspace", label: "Workspace", icon: FolderOpen },
    { id: "encrypt", label: "Encrypt", icon: Lock },
    { id: "decrypt", label: "Decrypt", icon: Unlock },
    { id: "recovery", label: "Recovery", icon: LifeBuoy },
    { id: "audio", label: "Audio", icon: FileAudio },
    { id: "tools", label: "Tools", icon: Dices },
    { id: "docs", label: "Docs", icon: BookOpen },
  ];
  /**
   * "Check this printout". Each photo is decoded on its own, so one blurred
   * picture is one line saying so rather than a failed batch, and each code is
   * compared with the backup this session wrote: the whole container when it
   * is on screen, otherwise the header and slot table the workbench kept,
   * which is enough for a strip but not for a container symbol.
   */
  const checkPrintout = async (files: readonly File[]) => {
    if (files.length === 0) return;
    setPrintoutBusy(true);
    const seq = opSeqRef.current;
    try {
      const { checkPrintoutCode, describePrintoutFinding, printoutFindingIsProblem } = await import(
        "@/lib/printout-check"
      );
      let container: Uint8Array | null = null;
      if (mode === "encrypt" && receipt?.onScreen && outputText.startsWith("keym2:")) {
        try {
          const { dearmorKeym2 } = await loadKeym2();
          container = dearmorKeym2(outputText);
        } catch {
          container = null;
        }
      }
      const backup = { container, header: mode === "encrypt" && receipt ? sealedPeek : null };
      const results: { file: string; text: string; problem: boolean }[] = [];
      for (const f of files) {
        try {
          // Every code in the photo, one line each: a whole sheet can be
          // checked in one picture.
          const texts = await decodeAllQrImage(f);
          for (const [i, text] of texts.entries()) {
            const finding = await checkPrintoutCode(text, backup);
            results.push({
              file: texts.length > 1 ? `${f.name} (${i + 1} of ${texts.length})` : f.name,
              text: describePrintoutFinding(finding),
              problem: printoutFindingIsProblem(finding),
            });
          }
        } catch (e) {
          results.push({
            file: f.name,
            text: e instanceof QrDecodeError ? e.message : "That image could not be read as a QR code.",
            problem: true,
          });
        }
      }
      // A wipe or a new seal while photos were decoding means these lines
      // describe a backup that is no longer the one on the page.
      if (opSeqRef.current !== seq) return;
      setPrintoutFindings(results);
    } finally {
      setPrintoutBusy(false);
    }
  };

  const returnToBackupTest = (withShares: boolean) => {
    const armored = mode === "encrypt" && receipt?.onScreen ? outputText : "";
    handleModeChange("decrypt");
    if (armored) {
      setInputType("text");
      setTextSecret(armored);
    }
    setUseShares(withShares);
    setVerifyOnly(true);
  };


  return {
    mode, setMode,
    formModeRef,
    workspacePage, setWorkspacePage,
    compactNavigation,
    inputType, setInputType,
    seedMode, setSeedMode,
    seedWords, setSeedWords,
    bip39, setBip39,
    file, setFile,
    qrScanBusy, setQrScanBusy,
    qrInputRef,
    shareQrInputRef,
    textSecret, setTextSecret,
    outputText, setOutputText,
    password, setPassword,
    generated, setGenerated,
    showPassword, setShowPassword,
    showTextSecret, setShowTextSecret,
    isAdvancedOpen, setIsAdvancedOpen,
    kdfChoice, setKdfChoice,
    argon2Available, setArgon2Available,
    argonTimeCost, setArgonTimeCost,
    argonMemoryMiB, setArgonMemoryMiB,
    argonParallelism, setArgonParallelism,
    deviceFit, setDeviceFit,
    calibrating, setCalibrating,
    calibrationNote, setCalibrationNote,
    runCalibration,
    cipherChoice, setCipherChoice,
    obscureFilename, setObscureFilename,
    decryptInfo, setDecryptInfo,
    slotTableWarning, setSlotTableWarning,
    hideSize, setHideSize,
    resealOffer, startReseal, resealNotice,
    showDecryptedText, setShowDecryptedText,
    useKeyFile, setUseKeyFile,
    keyFile, setKeyFile,
    isLoading, setIsLoading,
    isLoadingRef,
    unlockCostNotice, setUnlockCostNotice,
    isCryptoAvailable, setIsCryptoAvailable,
    isQrModalOpen, setIsQrModalOpen,
    verifyOnly, setVerifyOnly,
    verifyResult, setVerifyResult,
    isRecoveryOpen, setIsRecoveryOpen,
    inheritanceOpen, setInheritanceOpen,
    isCommandBarOpen, setIsCommandBarOpen,
    isApplePlatform,
    clipboardTimeoutRef,
    clipboardDeadline, setClipboardDeadline,
    clipboardSecondsLeft,
    clipboardClearPending,
    lastActivityRef,
    lockSecondsLeft,
    opSeqRef,
    isDecryptedQrModalOpen, setIsDecryptedQrModalOpen,
    isDecryptedQrRevealed, setIsDecryptedQrRevealed,
    decryptedQrStatus, setDecryptedQrStatus,
    textInputRejected, setTextInputRejected,
    textSecretSeedStatus,
    toast,
    outputTextForQr,
    passwordMeetsPolicy,
    shamirEnabled, setShamirEnabled,
    passkeyEnabled, setPasskeyEnabled,
    passkeySupported,
    shamirThreshold, setShamirThreshold,
    shamirCount, setShamirCount,
    sharesNeedPassword, setSharesNeedPassword,
    issuedShares, setIssuedShares,
    stripsCarryBackup, setStripsCarryBackup,
    backupFitsOnStrip,
    rehearsalOpen, setRehearsalOpen,
    rehearsalInput, setRehearsalInput,
    rehearsalPassword, setRehearsalPassword,
    rehearsalInputRejected, setRehearsalInputRejected,
    rehearsal,
    rehearsalLines,
    sealedPeek,
    printoutFindings,
    printoutBusy,
    printoutInputRef,
    cameraOpen, setCameraOpen,
    cameraAvailable,
    receipt,
    wipeAck,
    decryptPeek,
    issuedSharesRef,
    paperVault, setPaperVault,
    useShares, setUseShares,
    usePasskey, setUsePasskey,
    shareInput, setShareInput,
    shareInputRejected,
    shareLines,
    handleShareInputChange,
    revealingPassword,
    handleTextSecretChange,
    handlePasswordChange,
    cancelOperation,
    clearSensitiveState,
    resetState,
    wipeNow,
    hasSecretsOnScreen,
    keepOpen,
    handleModeChange,
    handleInputTypeChange,
    handleQrImageFiles,
    isImageFile,
    handleSeedWordsChange,
    currentDoor,
    openDoor,
    openInheritance,
    handleFileChange,
    generatePassword,
    generatePassphrase,
    clearClipboardNow,
    handleCopy,
    generateKeyFile,
    hiResQrRef,
    handleDownloadQrCode,
    decryptedQrHiResRef,
    handleDownloadDecryptedQr,
    processData,
    handleUseKeyFileChange,
    getPasswordStrengthColor,
    blockedByPasswordPolicy,
    isProcessButtonDisabled,
    inspectorPlan,
    rehearsalStamp,
    printPaperVault,
    downloadContainer,
    rehearseFromPaper,
    handleRehearsalInputChange,
    runRehearsal,
    commandBarCommands,
    activePage,
    navigateWorkspace,
    pageCopy,
    navItems,
    checkPrintout,
    returnToBackupTest,
  };
}
