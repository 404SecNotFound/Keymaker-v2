"use client";

/**
 * The Encrypt and Decrypt tabs' shared form. Both tabs render this same
 * component — `<SecretForm mode="encrypt" />` and `<SecretForm mode="decrypt" />`
 * — because that is what `encryptor-tool.tsx` actually contained: one render
 * function taking a `currentMode` parameter, branching on it throughout
 * rather than two separate trees. Splitting it into look-alike
 * `encrypt-tab.tsx`/`decrypt-tab.tsx` files would have meant duplicating this
 * whole form and letting the two copies drift; this module is that one form,
 * moved verbatim, renamed to say what it actually is.
 *
 * All state comes from `EncryptorContext` — see `use-encryptor-state.ts` for
 * where it lives and `context.tsx` for how it gets here.
 */
import { QRCodeCanvas } from "qrcode.react";
import {
  Camera,
  ChevronDown,
  Copy,
  Dices,
  Download,
  Eye,
  EyeOff,
  FileText,
  Info,
  KeyRound,
  Loader2,
  Lock,
  Printer,
  QrCode,
  RefreshCw,
  ScrollText,
  ShieldCheck,
  Sprout,
  Timer,
  Trash2,
  TriangleAlert,
  Unlock,
  X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { TooltipProvider } from "@/components/ui/tooltip";
import { SeedGrid } from "@/components/seed-grid";
import { InheritancePlan } from "@/components/inheritance-plan";
import { SelfExtractExport } from "@/components/self-extract-export";
import { cn } from "@/lib/utils";
import { PASSWORD_POLICY_HINT } from "@/lib/password-policy";
import { MAX_PASSWORD_LENGTH, MAX_CONTAINER_SIZE, MAX_PLAINTEXT_SIZE, CipherId } from "@/lib/keymaker-crypto";
import { predictArgon2Ms } from "@/lib/kdf-calibration";
import { EFF_LARGE_WORDLIST_SIZE } from "@/lib/eff-wordlist";
import { FileSelector, RevealableQr, InfoTip, LockWarning } from "./shared-ui";
import {
  type Mode,
  bip39Module,
  formatBytes,
  CIPHER_OPTIONS,
  SHARE_PRESETS,
  OFFSCREEN_STYLE,
  QR_MAX_BYTES,
  qrByteLength,
  PASSWORD_CHARSET,
  PASSWORD_LENGTH,
  PASSWORD_ENTROPY_BITS,
  PASSPHRASE_WORDS,
  PASSPHRASE_ENTROPY_BITS,
} from "./shared";
import { useEncryptorContext } from "./context";

export function SecretForm({ mode }: { mode: Mode }) {
  const {
    inputType, seedMode, seedWords, bip39, file, setFile, qrScanBusy,
    qrInputRef, shareQrInputRef, textSecret, outputText, password,
    generated, showPassword, setShowPassword, showTextSecret, setShowTextSecret,
    isAdvancedOpen, setIsAdvancedOpen,
    kdfChoice, setKdfChoice, argon2Available, argonTimeCost, setArgonTimeCost,
    argonMemoryMiB, setArgonMemoryMiB, argonParallelism, setArgonParallelism,
    deviceFit, calibrating, calibrationNote, runCalibration,
    cipherChoice, setCipherChoice, obscureFilename, setObscureFilename,
    decryptInfo, slotTableWarning, showDecryptedText, setShowDecryptedText,
    useKeyFile, keyFile, setKeyFile, isLoading, unlockCostNotice,
    isCryptoAvailable, isQrModalOpen, setIsQrModalOpen, verifyOnly, setVerifyOnly,
    verifyResult, inheritanceOpen, setInheritanceOpen,
    isDecryptedQrModalOpen, setIsDecryptedQrModalOpen,
    isDecryptedQrRevealed, setIsDecryptedQrRevealed, decryptedQrStatus,
    textInputRejected, textSecretSeedStatus, outputTextForQr,
    passwordMeetsPolicy, shamirEnabled, setShamirEnabled, passkeyEnabled,
    setPasskeyEnabled, passkeySupported, shamirThreshold, setShamirThreshold,
    shamirCount, setShamirCount, sharesNeedPassword, setSharesNeedPassword,
    rehearsalOpen, cameraAvailable, setCameraOpen, receipt,
    useShares, setUseShares, usePasskey, setUsePasskey, shareInput, setShareInput,
    shareInputRejected, shareLines, handleShareInputChange, revealingPassword,
    handleTextSecretChange, handlePasswordChange, cancelOperation,
    hasSecretsOnScreen, keepOpen, handleInputTypeChange, handleQrImageFiles,
    isImageFile, handleSeedWordsChange, handleFileChange, generatePassword,
    generatePassphrase, handleCopy, generateKeyFile, hiResQrRef,
    handleDownloadQrCode, decryptedQrHiResRef, handleDownloadDecryptedQr,
    processData, handleUseKeyFileChange, getPasswordStrengthColor,
    blockedByPasswordPolicy, isProcessButtonDisabled, printPaperVault,
    rehearseFromPaper, downloadContainer, clipboardSecondsLeft,
    clipboardClearPending, clearClipboardNow, lockSecondsLeft, wipeAck,
    wipeNow,
  } = useEncryptorContext();

  // Key-file toggle + picker/generator. Rendered in place on the Decrypt
  // tab and inside the Advanced section on the Encrypt tab.
  const keyFileControls = (
    <>
      <div className="flex items-center gap-3 py-1">
        <Switch
          id="use-keyfile"
          checked={useKeyFile}
          onCheckedChange={handleUseKeyFileChange}
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
            icon={<KeyRound className="h-5 w-5" />}
            label="Select key file"
            description="Drag & drop or click to select an existing file"
          />
          <div className="flex items-center gap-3">
            <hr className="grow border-t border-border" />
            <span className="text-[12px] font-medium uppercase tracking-wider text-muted-foreground">or</span>
            <hr className="grow border-t border-border" />
          </div>
          <Button
            variant="outline"
            className="w-full rounded-xl border-border bg-inset py-2.5 text-sm font-medium text-foreground hover:bg-raised"
            onClick={generateKeyFile}
          >
            <Download className="mr-2 h-4 w-4" />
            Generate & download new key file
          </Button>
        </div>
      )}
    </>
  );


  return (
    <div className="km-workform space-y-5">
      {mode === "encrypt" && inheritanceOpen && (
        <InheritancePlan
          threshold={shamirThreshold}
          count={shamirCount}
          onDismiss={() => setInheritanceOpen(false)}
        />
      )}
      <div className="space-y-5">
        <section className="km-form-section" aria-labelledby={`${mode}-content-title`}>
        <div className="km-section-heading">
          <span className="km-section-number">01</span>
          <h2 id={`${mode}-content-title`}>{mode === "encrypt" ? "Content" : "Encrypted content"}</h2>
          <span>{mode === "encrypt" ? "Choose what to protect" : "Choose a backup to open"}</span>
        </div>
        <div className="flex gap-0.5 rounded-xl bg-inset p-1">
          <button
            type="button"
            onClick={() => handleInputTypeChange('file')}
            aria-pressed={inputType === 'file'}
            className="km-input-choice km-choice"
          >
            <FileText className="h-4 w-4" aria-hidden="true" />
            File
          </button>
          <button
            type="button"
            onClick={() => handleInputTypeChange('text')}
            aria-pressed={inputType === 'text' && !(mode === 'encrypt' && seedMode)}
            className="km-input-choice km-choice"
          >
            <ScrollText className="h-4 w-4" aria-hidden="true" />
            Text
          </button>
          {/*
            Seed Phrase mode. Encrypt only: a phrase is something you seal,
            and what you open is a container. Pressing it while it is already
            showing does nothing — re-entering would re-seed the grid from
            `textSecret` and could resize it under a phrase in progress.
          */}
          {mode === 'encrypt' && (
            <button
              type="button"
              onClick={() => {
                if (!(inputType === 'text' && seedMode)) handleInputTypeChange('seed');
              }}
              aria-pressed={inputType === 'text' && seedMode}
              className="km-input-choice km-choice"
            >
              <Sprout className="h-4 w-4" aria-hidden="true" />
              Seed phrase
            </button>
          )}
        </div>

        {inputType === 'file' ? (
          <FileSelector
            id={`${mode}-file`}
            onFileChange={(e) => {
              // A QR PNG dropped on the Decrypt file box is the natural
              // instinct ("upload the picture"), but it is not a container.
              // Detect an image here and scan it instead of reading its bytes
              // as a container, which would fail on the magic and read as a
              // wrong password.
              if (mode === 'decrypt') {
                const dropped = 'dataTransfer' in e
                  ? e.dataTransfer.files?.[0]
                  : e.target.files?.[0];
                if (dropped && isImageFile(dropped)) {
                  if (!('dataTransfer' in e) && e.target) e.target.value = "";
                  void handleQrImageFiles([dropped]);
                  return;
                }
              }
              handleFileChange(
                e,
                setFile,
                // Decrypting accepts the container, which is larger than the
                // plaintext it holds by header + salt + nonces + tags.
                mode === 'decrypt' ? MAX_CONTAINER_SIZE : MAX_PLAINTEXT_SIZE,
                mode === 'decrypt' ? 'container' : 'plaintext'
              );
            }}
            onClear={() => setFile(null)}
            selectedFile={file}
            icon={<FileText className="h-5 w-5" />}
            label="Drop a file here"
            description={
              mode === 'decrypt'
                ? `a .keym container, or a QR image to scan · ${Math.floor(MAX_PLAINTEXT_SIZE / 1024 / 1024)} MB max`
                : `or click to browse · ${Math.floor(MAX_PLAINTEXT_SIZE / 1024 / 1024)} MB max`
            }
          />
        ) : mode === 'encrypt' && seedMode ? (
          <SeedGrid
            words={seedWords}
            onChange={handleSeedWordsChange}
            revealed={showTextSecret}
            onRevealedChange={setShowTextSecret}
            bip39={bip39}
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
              {mode === 'encrypt' && textSecretSeedStatus !== 'none' && (
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
                    <TriangleAlert className="h-3.5 w-3.5" aria-hidden="true" />
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
                placeholder={`Enter text to ${mode}...`}
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
                    mode === 'encrypt' && textSecretSeedStatus !== 'none'
                      ? "text-secret-seed-status"
                      : null,
                    textInputRejected ? "text-secret-size-error" : null,
                  ]
                    .filter(Boolean)
                    .join(" ") || undefined
                }
                aria-invalid={mode === 'encrypt' && textSecretSeedStatus === 'invalid'}
                className={cn(
                  "rounded-xl border-border bg-inset pr-12 transition-[filter] duration-150 focus-visible:border-border-strong focus-visible:ring-0",
                  mode === 'encrypt' && !showTextSecret && textSecret && "blur-xs",
                  // Subtle seed-phrase feedback: green border = valid BIP-39
                  // seed, red = seed-shaped but invalid (likely typo). The
                  // border also overrides the focus tint so the signal stays
                  // visible while typing.
                  mode === 'encrypt' && textSecretSeedStatus === 'valid' && "border-success focus-visible:border-success",
                  mode === 'encrypt' && textSecretSeedStatus === 'invalid' && "border-destructive focus-visible:border-destructive"
                )}
              />
              {mode === 'encrypt' && (
                <button
                  type="button"
                  onClick={() => setShowTextSecret(!showTextSecret)}
                  aria-pressed={showTextSecret}
                  aria-label={showTextSecret ? "Hide secret text" : "Show secret text"}
                  className="absolute right-2 top-2 rounded-lg border border-border bg-inset p-1.5 text-muted-foreground transition-all hover:bg-raised hover:text-foreground"
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
                {textInputRejected}
              </p>
            )}
            {/*
              QR scan, decrypt only. The encrypted text is often a QR (the
              encrypt-side output QR is one symbol, a paper vault is several),
              and typing a base64url container back by hand is not a thing
              anyone does. Scanning fills the box above with exactly the text a
              paste would carry, so from there it is the ordinary password
              unlock.
            */}
            {mode === 'decrypt' && (
              <div className="space-y-2 pt-1">
                <div className="flex items-center gap-3">
                  <hr className="grow border-t border-border" />
                  <span className="text-[12px] font-medium uppercase tracking-wider text-muted-foreground">
                    or scan a QR image
                  </span>
                  <hr className="grow border-t border-border" />
                </div>
                <input
                  ref={qrInputRef}
                  id="qr-scan-input"
                  type="file"
                  accept="image/png,image/jpeg,image/webp"
                  multiple
                  className="hidden"
                  onChange={(e) => {
                    const files = Array.from(e.target.files ?? []);
                    // Reset so re-selecting the same image fires onChange again.
                    e.target.value = "";
                    void handleQrImageFiles(files);
                  }}
                />
                <Button
                  type="button"
                  variant="outline"
                  disabled={qrScanBusy}
                  onClick={() => qrInputRef.current?.click()}
                  className="w-full rounded-xl border-border bg-inset py-2.5 text-sm font-medium text-foreground hover:bg-raised"
                >
                  <QrCode className="mr-2 h-4 w-4" />
                  {qrScanBusy ? "Reading QR…" : "Scan a QR image"}
                </Button>
                {cameraAvailable ? (
                  <Button
                    type="button"
                    variant="outline"
                    disabled={qrScanBusy}
                    onClick={() => setCameraOpen(true)}
                    className="w-full rounded-xl border-border bg-inset py-2.5 text-sm font-medium text-foreground hover:bg-raised"
                  >
                    <Camera className="mr-2 h-4 w-4" />
                    Use the camera
                  </Button>
                ) : null}
                <p className="text-[12px] leading-snug text-muted-foreground">
                  Upload a Keymaker QR PNG, or every part of a paper backup at
                  once, and its encrypted text fills the box above. Then type the
                  password. Recovery-share strips can go in the same batch: they
                  are moved to the recovery-shares box.
                </p>
              </div>
            )}
          </div>
        )}

        </section>
        <section className="km-form-section" aria-labelledby={`${mode}-protection-title`}>
        <div className="km-section-heading">
          <span className="km-section-number">02</span>
          <h2 id={`${mode}-protection-title`}>{mode === "encrypt" ? "Protection" : "Unlock method"}</h2>
        </div>
        <TooltipProvider>
          <div>
            <div className="mb-2 flex items-center gap-1.5">
              <Label htmlFor="password" className="text-[13px] font-medium text-muted-foreground">
                Password
              </Label>
              <InfoTip label="Password requirements">
                <p>
                  Minimum policy: {PASSWORD_POLICY_HINT} There is no upper/lower/number/symbol
                  rule, because that rejects strong lowercase secrets while passing predictable
                  ones. This is a floor, not a strength measurement: Keymaker cannot tell how you
                  chose a password. For a figure it can actually stand behind, use Generate.
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
              {mode === "decrypt" && (
                <button
                  type="button"
                  onClick={() => {
                    // One unlock path at a time. The passkey control is hidden
                    // while shares are on, so a passkey choice left set behind
                    // it would still win in processData: the heir pastes k
                    // shares and is asked to tap a key, and on a container
                    // with no passkey slot is told to use a password they do
                    // not have, with no visible control to undo it.
                    if (!useShares) setUsePasskey(false);
                    setUseShares((v) => {
                      // KM-R03. Leaving them in state behind a hidden control
                      // is the worst of both: invisible to the user, and still
                      // there for the auto-lock to have to think about.
                      if (v) setShareInput('');
                      return !v;
                    });
                  }}
                  aria-pressed={useShares}
                  className="km-action ml-auto rounded-md px-2 py-1 text-[12px] transition-colors hover:bg-inset"
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
              {mode === "decrypt" && passkeySupported && !useShares && (
                <button
                  type="button"
                  onClick={() => setUsePasskey((v) => !v)}
                  aria-pressed={usePasskey}
                  className="km-action rounded-md px-2 py-1 text-[12px] transition-colors hover:bg-inset"
                >
                  {usePasskey ? "Use a password instead" : "Use a passkey"}
                </button>
              )}
            </div>

            {mode === "decrypt" && useShares && (
              <div className="mb-3 space-y-2">
                <Textarea
                  id="share-input"
                  value={shareInput}
                  onChange={(e) => handleShareInputChange(e.target.value)}
                  placeholder={"KMSHARE2:...\nKMSHARE2:...\nOne share per line"}
                  rows={4}
                  spellCheck={false}
                  autoCorrect="off"
                  autoCapitalize="off"
                  aria-describedby={shareInputRejected ? "share-input-size-error" : undefined}
                  aria-invalid={shareInputRejected ? true : undefined}
                  className="min-h-[96px] rounded-xl border-border bg-inset font-mono text-[12px]"
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
                {/*
                  The printed strips each carry a QR. Without this the only way
                  in from paper was retyping a ~140-character code per strip,
                  by the person least equipped to get one character right. Same
                  handler as the container scan, which routes by prefix, so a
                  container photo picked here still lands in its own box.
                */}
                <input
                  ref={shareQrInputRef}
                  id="share-qr-scan-input"
                  type="file"
                  accept="image/png,image/jpeg,image/webp"
                  multiple
                  className="hidden"
                  onChange={(e) => {
                    const files = Array.from(e.target.files ?? []);
                    e.target.value = "";
                    void handleQrImageFiles(files);
                  }}
                />
                <Button
                  type="button"
                  variant="outline"
                  disabled={qrScanBusy}
                  onClick={() => shareQrInputRef.current?.click()}
                  className="w-full rounded-xl border-border bg-inset py-2 text-[13px] font-medium text-foreground hover:bg-raised"
                >
                  <QrCode className="mr-2 h-4 w-4" />
                  {qrScanBusy ? "Reading QR…" : "Scan share QR images"}
                </Button>
                {cameraAvailable ? (
                  <Button
                    type="button"
                    variant="outline"
                    disabled={qrScanBusy}
                    onClick={() => setCameraOpen(true)}
                    className="w-full rounded-xl border-border bg-inset py-2 text-[13px] font-medium text-foreground hover:bg-raised"
                  >
                    <Camera className="mr-2 h-4 w-4" />
                    Scan strips with the camera
                  </Button>
                ) : null}
                <p className="text-[12px] leading-snug text-muted-foreground" role="status">
                  {(() => {
                    const n = shareLines.length;
                    if (n === 0) return "Paste the shares, one per line, or scan the QR on each strip. Comment lines starting with # are ignored.";
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
                placeholder={mode === 'encrypt' ? "Enter a strong password" : "Enter decryption password"}
                aria-describedby={mode === "encrypt" && password ? "password-feedback" : undefined}
                // A password field reveals its contents whenever "Show" is
                // pressed, at which point spellcheck and autocorrect apply to
                // it like any other text. Off for the same reasons as above.
                spellCheck={false}
                autoCorrect="off"
                autoCapitalize="none"
                autoComplete={mode === 'encrypt' ? "new-password" : "current-password"}
                className={cn(
                  "h-11 rounded-xl border border-border bg-inset pr-[74px] text-[15px] transition-colors focus-visible:border-border-strong focus-visible:ring-0",
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
                className="absolute right-2 top-1/2 -translate-y-1/2 rounded-lg border border-border bg-inset px-2.5 py-1 text-xs font-medium text-muted-foreground transition-all hover:bg-raised hover:text-foreground"
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
                className="min-w-0 flex-1 rounded-lg border-border bg-inset text-[13px] font-medium text-muted-foreground hover:bg-raised hover:text-foreground"
              >
                <Copy className="mr-1.5 h-3.5 w-3.5" />Copy
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => handlePasswordChange("")}
                disabled={!password}
                className="min-w-0 flex-1 rounded-lg border-border bg-inset text-[13px] font-medium text-muted-foreground hover:bg-raised hover:text-foreground"
              >
                <X className="mr-1.5 h-3.5 w-3.5" />Clear
              </Button>
              {mode === 'encrypt' && (
                <>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={generatePassword}
                    title={`${PASSWORD_LENGTH} random characters — ${PASSWORD_ENTROPY_BITS} bits`}
                    className="km-action min-w-0 flex-1 rounded-lg border-border bg-inset text-[13px] font-medium hover:bg-raised"
                  >
                    <RefreshCw className="mr-1.5 h-3.5 w-3.5" />Random
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={generatePassphrase}
                    title={`${PASSPHRASE_WORDS} words from the EFF long list — ${PASSPHRASE_ENTROPY_BITS} bits`}
                    className="km-action min-w-0 flex-1 rounded-lg border-border bg-inset text-[13px] font-medium hover:bg-raised"
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
            {mode === 'encrypt' && password && (
              generated ? (
                <p id="password-feedback" className="text-[12px] leading-snug text-success">
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
                <p id="password-feedback" className="text-[12px] leading-snug text-muted-foreground">
                  <span className="text-success">Minimum policy met.</span>{" "}
                  This is a floor, not a strength rating — Keymaker
                  cannot tell how you chose this password. Use <strong>Random</strong> or{' '}
                  <strong>Passphrase</strong> for a figure it can stand behind.
                </p>
              ) : (
                <p id="password-feedback" className="text-[12px] leading-snug text-destructive">
                  Below the minimum policy: {PASSWORD_POLICY_HINT}
                </p>
              )
            )}
          </div>

          {mode === 'decrypt' && keyFileControls}

          {/*
            Verify-only. See the state declaration for why this exists and what
            it does not claim.
          */}
          {mode === 'decrypt' && (
            <div className="flex items-start gap-3 rounded-xl border border-border px-4 py-3">
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

          {mode === 'encrypt' && (
            <div className="overflow-hidden rounded-xl border border-border">
              <button
                type="button"
                onClick={() => setIsAdvancedOpen((v) => !v)}
                aria-expanded={isAdvancedOpen}
                className="flex w-full items-center justify-between px-4 py-3 text-left transition-colors hover:bg-inset"
              >
                <span className="text-[13px] font-medium text-action">
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
                  <div className="space-y-4 border-t border-border px-4 pb-4 pt-4">
                    {/*
                      Two columns from lg up, because expanded this was one vertical stack of
                      cards, sliders and toggles roughly a screen and a half long — everything
                      equally weighted and nothing to scan by.
                    
                      The split is by question, not by length: the left column is how the key is
                      derived from what you type, the right is what the sealed container ends up
                      carrying. `items-start` so the two columns size independently — the left
                      grows when Argon2id exposes its sliders, the right when a share set is
                      enabled, and neither should stretch the other.
                    
                      One column below lg. Two columns of this density on a phone would be worse
                      than the wall.
                    */}
                    <div className="grid gap-4 lg:grid-cols-2 lg:items-start lg:gap-x-6">
                      <section aria-labelledby="adv-derivation" className="space-y-4">
                        <h3
                          id="adv-derivation"
                          className="text-[12px] font-medium uppercase tracking-[0.08em] text-structural"
                        >
                          Key derivation
                        </h3>
                    {/* KDF choice */}
                    <div className="space-y-2">
                      <Label className="text-[13px] font-medium text-muted-foreground">Key derivation</Label>
                      <div className="km-kdf-choices">
                        <button
                          type="button"
                          onClick={() => setKdfChoice("pbkdf2")}
                          aria-pressed={kdfChoice === "pbkdf2"}
                          className={cn(
                            "km-choice rounded-lg border p-3 text-left transition-colors",
                            kdfChoice === "pbkdf2"
                              ? "border-border-strong bg-inset"
                              : "border-border hover:border-border-strong"
                          )}
                        >
                          <p className="text-[13px] font-medium">PBKDF2</p>
                          <p className="mt-0.5 text-[12px] leading-snug text-muted-foreground">
                            Fastest and most compatible. 1M iterations of SHA-256.
                          </p>
                        </button>
                        <button
                          type="button"
                          onClick={() => argon2Available !== false && setKdfChoice("argon2id")}
                          disabled={argon2Available === false}
                          aria-pressed={kdfChoice === "argon2id"}
                          className={cn(
                            "km-choice rounded-lg border p-3 text-left transition-colors",
                            kdfChoice === "argon2id"
                              ? "border-border-strong bg-inset"
                              : "border-border hover:border-border-strong",
                            argon2Available === false &&
                              "cursor-not-allowed border-border text-subtle-foreground hover:border-border"
                          )}
                        >
                          <p className="text-[13px] font-medium">
                            Argon2id{" "}
                            <span className="km-option-note text-muted-foreground">
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
                          className="rounded-lg border border-warning/40 bg-warning/10 px-3 py-2 text-[12px] leading-snug text-warning"
                        >
                          <TriangleAlert className="mr-1.5 inline h-3.5 w-3.5 align-[-2px]" />
                          WebAssembly is unavailable in this browser, so Argon2id cannot run.
                          Falling back to PBKDF2 at 1,000,000 iterations — still strong, but
                          not memory-hard. Files you encrypt here stay fully readable everywhere.
                        </p>
                      )}

                      {kdfChoice === "argon2id" && (
                        <div className="animate-in fade-in-50 space-y-3 rounded-lg border border-border p-3">
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
                                className="w-full accent-foreground"
                              />
                            </div>
                          ))}
                          <div className="space-y-2 pt-1">
                            <button
                              type="button"
                              onClick={runCalibration}
                              disabled={calibrating || isLoading}
                              className={cn(
                                "km-action w-full rounded-lg border px-3 py-2 text-[12px] font-medium transition-colors",
                                "border-border hover:border-border-strong",
                                "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                                "disabled:cursor-not-allowed disabled:border-border disabled:text-subtle-foreground"
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
                            <p
                              className="text-[12px] text-muted-foreground"
                              role="status"
                              aria-live="polite"
                              data-testid="calibration-note"
                            >
                              {calibrationNote ?? ""}
                            </p>
                          </div>
                        </div>
                      )}
                    </div>

                      </section>

                      <section aria-labelledby="adv-container" className="space-y-4">
                        <h3
                          id="adv-container"
                          className="text-[12px] font-medium uppercase tracking-[0.08em] text-structural"
                        >
                          What the container carries
                        </h3>
                    {/* Cipher choice */}
                    <div className="space-y-2">
                      <Label className="text-[13px] font-medium text-muted-foreground">Cipher</Label>
                      <div className="space-y-2">
                        {CIPHER_OPTIONS.map(({ id, name, blurb }) => (
                          <button
                            key={id}
                            type="button"
                            onClick={() => setCipherChoice(id)}
                            aria-pressed={cipherChoice === id}
                            className={cn(
                              "km-choice flex w-full items-start gap-2.5 rounded-lg border p-3 text-left transition-colors",
                              cipherChoice === id
                                ? "border-border-strong bg-inset"
                                : "border-border hover:border-border-strong"
                            )}
                          >
                            <span className="mt-0.5 flex-1">
                              <span className="block text-[13px] font-medium">{name}</span>
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
                    {mode === "encrypt" && passkeySupported && (
                      <div className="space-y-3 rounded-lg border border-border p-3">
                        <div className="flex items-center gap-3">
                          <Switch
                            id="passkey-enabled"
                            checked={passkeyEnabled && !(shamirEnabled && sharesNeedPassword)}
                            onCheckedChange={setPasskeyEnabled}
                            disabled={shamirEnabled && sharesNeedPassword}
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
                        {passkeyEnabled && !(shamirEnabled && sharesNeedPassword) && (
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
                    {mode === "encrypt" && (
                      <div className="space-y-3 rounded-lg border border-border p-3">
                        <div className="flex items-center gap-3">
                          <Switch
                            id="shamir-enabled"
                            checked={shamirEnabled}
                            onCheckedChange={setShamirEnabled}
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
                            {/*
                              The two sets most people want, one press each. The
                              fields below stay, and stay the source of truth:
                              a preset only fills them, so anything it sets can
                              be adjusted, and a preset is shown as chosen only
                              while both fields still match it.
                            */}
                            <div
                              role="group"
                              aria-label="Common share sets"
                              className="flex gap-0.5 rounded-xl bg-inset p-1"
                            >
                              {SHARE_PRESETS.map(([k, n]) => (
                                <button
                                  key={`${k}-of-${n}`}
                                  type="button"
                                  aria-pressed={shamirThreshold === k && shamirCount === n}
                                  onClick={() => {
                                    setShamirCount(n);
                                    setShamirThreshold(k);
                                  }}
                                  className="km-input-choice km-choice"
                                >
                                  {k} of {n}
                                </button>
                              ))}
                            </div>
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
                                  className="h-10 rounded-lg border-border bg-inset"
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
                                  className="h-10 rounded-lg border-border bg-inset"
                                />
                              </div>
                            </div>
                            {/*
                              Roadmap, "Honest framing to preserve": any k shares
                              open the container without the password, so each
                              share is as sensitive as the password itself. That
                              belongs on the screen, not only in the docs.
                            */}
                            {/*
                              §4.8. The other way to use strips: together with
                              the password rather than instead of it. The costs
                              §4.8 says a writer should state are stated here,
                              where the choice is made.
                            */}
                            <div className="space-y-2 rounded-md border border-border p-2.5">
                              <div className="flex items-center gap-3">
                                <Switch
                                  id="shares-need-password"
                                  checked={sharesNeedPassword}
                                  onCheckedChange={(v) => {
                                    setSharesNeedPassword(v);
                                    if (v) setPasskeyEnabled(false);
                                  }}
                                />
                                <Label htmlFor="shares-need-password" className="cursor-pointer text-sm text-foreground">
                                  The strips need the password too
                                </Label>
                              </div>
                              {sharesNeedPassword ? (
                                <p className="text-[12px] leading-snug text-muted-foreground" data-testid="shares-need-password-cost">
                                  Then neither opens it alone: it takes the password and{" "}
                                  {shamirThreshold} strips together. A forgotten password, or fewer than{" "}
                                  {shamirThreshold} strips, loses the backup for good, and nothing else can
                                  stand in for either. Versions of Keymaker and keym2.py from before this
                                  option cannot open it. No passkey can be added.
                                </p>
                              ) : null}
                            </div>
                            {sharesNeedPassword ? (
                              <p className="rounded-md bg-warning/10 px-3 py-2 text-[12px] leading-snug text-warning">
                                Keep the password and the strips in different hands. Anyone holding
                                the password and {shamirThreshold} strips opens this container.
                              </p>
                            ) : (
                              <p className="rounded-md bg-warning/10 px-3 py-2 text-[12px] leading-snug text-warning">
                                Each share is as sensitive as your password. Anyone holding{" "}
                                {shamirThreshold} of them opens this container without knowing it.
                                Store them apart, with people who would not combine them casually.
                              </p>
                            )}
                          </>
                        )}
                      </div>
                    )}

                      </section>
                    </div>

                    {/* Security summary */}
                    <p className="rounded-lg border border-border px-3 py-2 text-[12px] text-muted-foreground">
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
        </section>
      </div>

      {/*
        A verified result subsumes the plain format line — verifyResult.detail
        is the same string — so only one of the two is ever rendered.
      */}
      {verifyResult && mode === 'decrypt' ? (
        <div
          role="status"
          data-testid="verify-result"
          className="animate-in fade-in-50 rounded-xl border border-success/40 bg-success/10 px-4 py-3"
        >
          <p className="flex items-center gap-2 text-[13px] font-medium text-success">
            <ShieldCheck className="h-4 w-4 shrink-0" />
            The backup opens with {verifyResult.method === "password" ? "this password" : verifyResult.method === "passkey" ? "this passkey" : "these recovery shares"}
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
      ) : decryptInfo && mode === 'decrypt' ? (
        <p className="animate-in fade-in-50 rounded-lg bg-inset px-3 py-2 text-[12px] text-muted-foreground">
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
      {slotTableWarning && mode === 'decrypt' && (
        <div
          role="alert"
          className="mt-2 animate-in fade-in-50 rounded-xl border border-warning/40 bg-warning/10 p-3 text-sm text-warning"
          data-testid="slot-table-warning"
        >
          <p className="flex items-start gap-2 font-medium">
            <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
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

      {/*
        The receipt. 500ms in, not 200: DESIGN-SYSTEM.md § Motion's completion
        allowance, for the one moment the owner is certain to be watching.
        Opacity and transform only; the reduced-motion global flattens it.
      */}
      {mode === 'encrypt' && receipt && (
        <section
          role="status"
          aria-labelledby="receipt-title"
          data-testid="seal-receipt"
          className="animate-in fade-in-0 slide-in-from-bottom-2 space-y-3 rounded-xl border border-border p-4 duration-500"
        >
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-success" aria-hidden="true" />
            <h3 id="receipt-title" className="text-[15px] font-medium text-foreground">
              Sealed.
            </h3>
          </div>
          <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1.5 text-[12.5px] leading-snug">
            <dt className="text-muted-foreground">Written</dt>
            <dd data-testid="receipt-written" className="min-w-0 break-all font-mono text-[12px] text-foreground">
              {receipt.from} → {receipt.to}
            </dd>
            <dt className="text-muted-foreground">Protected by</dt>
            <dd className="min-w-0 font-mono text-[12px] text-foreground">
              <span data-testid="receipt-kdf">{receipt.kdf}</span>
              {" · "}
              <span data-testid="receipt-cipher">{receipt.cipher}</span>
            </dd>
            <dt className="text-muted-foreground">Ways in</dt>
            <dd data-testid="receipt-ways" className="min-w-0 text-foreground">
              {receipt.waysIn.join(" · ")}
            </dd>
            <dt className="text-muted-foreground">Left this device</dt>
            <dd data-testid="receipt-left" className="text-foreground">
              nothing
            </dd>
          </dl>
          {receipt.onScreen ? (
            <div className="flex flex-wrap gap-2">
              <Button type="button" variant="secondary" size="sm" onClick={() => void printPaperVault()} className="rounded-lg">
                <Printer className="mr-2 h-3.5 w-3.5" aria-hidden="true" />
                Print paper vault
              </Button>
              {receipt.shares && (
                <Button type="button" variant="secondary" size="sm" onClick={rehearseFromPaper} className="rounded-lg">
                  <Timer className="mr-2 h-3.5 w-3.5" aria-hidden="true" />
                  Rehearse recovery
                </Button>
              )}
              <Button type="button" variant="secondary" size="sm" onClick={() => void downloadContainer()} className="rounded-lg">
                <Download className="mr-2 h-3.5 w-3.5" aria-hidden="true" />
                Download .keym
              </Button>
            </div>
          ) : (
            <p className="text-[12px] leading-snug text-muted-foreground">
              The file was downloaded as it was sealed; nothing else of it is kept here.
              To print a paper vault or rehearse from paper, seal in Text mode.
            </p>
          )}
        </section>
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
            {mode === 'decrypt' && inputType === 'text' && decryptedQrStatus.kind !== 'idle' && (
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
                    <TriangleAlert className="h-3.5 w-3.5" aria-hidden="true" />
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
                "rounded-xl border-border bg-inset pr-12 focus-visible:ring-0",
                mode === 'decrypt' && inputType === 'text' && !showDecryptedText && "blur-xs",
                // Same border language as the encrypt-side secret field:
                // green = decrypted text is a valid BIP-39 seed, red = it is
                // seed-shaped but fails validation (the stored backup itself
                // likely holds a transcription error).
                mode === 'decrypt' && decryptedQrStatus.kind === 'seed' && "border-success",
                mode === 'decrypt' && decryptedQrStatus.kind === 'plain' && decryptedQrStatus.seedShaped && "border-destructive"
              )}
            />
            <div className="absolute right-1 top-1 flex flex-col items-center">
              {mode === 'decrypt' && inputType === 'text' && (
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="h-auto p-2"
                  onClick={() => setShowDecryptedText(!showDecryptedText)}
                  aria-label={showDecryptedText ? "Hide decrypted text" : "Show decrypted text"}
                  aria-pressed={showDecryptedText}
                >
                  {showDecryptedText ? <EyeOff /> : <Eye />}
                </Button>
              )}
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="h-auto p-2"
                onClick={() => handleCopy(outputText)}
                aria-label={mode === 'encrypt' ? "Copy encrypted text" : "Copy decrypted text"}
              >
                <Copy />
              </Button>
              {mode === 'encrypt' && inputType === 'text' && (
                <Dialog open={isQrModalOpen} onOpenChange={setIsQrModalOpen}>
                  <DialogTrigger asChild>
                    <Button type="button" variant="ghost" size="icon" className="h-auto p-2" aria-label="Show encrypted text as a QR code">
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
                        <div className="rounded-md bg-warning/10 p-3 text-center text-sm text-warning">
                          <p className="font-medium">QR code unavailable</p>
                          <p className="mt-1">Output is {qrByteLength(outputTextForQr).toLocaleString()} bytes, which exceeds the QR code capacity of {QR_MAX_BYTES.toLocaleString()} bytes. Use the copy button instead.</p>
                        </div>
                      )}
                    </div>
                  </DialogContent>
                </Dialog>
              )}
              {mode === 'decrypt' && inputType === 'text' && decryptedQrStatus.kind !== 'idle' && (
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
                        <div className="rounded-md bg-warning/10 p-3 text-center text-sm text-warning">
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
        4.2. The paper route out of the app lives on the receipt now — see
        it above the result — for the reason it used to sit here: the moment
        someone is looking at a container they just made is the moment
        printing it is on their mind.
      */}

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
      {mode === 'encrypt' && outputText.startsWith('keym2:') && (
        <SelfExtractExport armored={outputText} />
      )}

      {/*
        Clipboard countdown and the imminent-lock warning.

        Both are here rather than as toasts because both are *states*, not
        events: a toast that has already faded cannot tell you the clipboard
        still holds your seed phrase, and a lock warning you missed is not a
        warning. Each carries the control that answers it.
      */}
      {(clipboardSecondsLeft !== null || clipboardClearPending) && (
        <div
          className="flex items-center justify-between gap-3 rounded-xl border border-border bg-inset px-3 py-2 text-[12px]"
        >
          {/* Announced once, not once a second for a minute: the ticking
              count below is for sighted users and is not a live region. */}
          <span role="status" className="sr-only" data-testid="clipboard-announcement">
            {clipboardClearPending
              ? "Clipboard not cleared yet, because the tab was in the background. It will be cleared when you come back to this tab."
              : "The clipboard will be cleared in about a minute. Choose Clear now to clear it sooner."}
          </span>
          <span className="flex min-w-0 items-center gap-1.5 text-muted-foreground">
            {clipboardClearPending ? (
              // The countdown ran out while the tab was in the background and
              // the browser refused the overwrite. Saying so beats the banner
              // vanishing as though the secret had gone.
              <>
                <TriangleAlert className="h-3.5 w-3.5 shrink-0" />
                <span>
                  The clipboard could not be cleared while this tab was in the
                  background. It will be cleared when you return.
                </span>
              </>
            ) : (
              <>
                <Timer className="h-3.5 w-3.5 shrink-0" />
                <span className="truncate">
                  Clipboard clears in <span className="tabular-nums font-medium text-foreground">{clipboardSecondsLeft}s</span>
                </span>
              </>
            )}
          </span>
          <button
            type="button"
            onClick={clearClipboardNow}
            className="shrink-0 cursor-pointer rounded-lg border border-border px-2.5 py-1 font-medium text-muted-foreground transition-colors hover:border-border-strong hover:text-foreground"
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
          className="mt-2 rounded-xl border border-warning/40 bg-warning/10 p-3 text-sm text-warning"
          data-testid="unlock-cost-notice"
        >
          {unlockCostNotice}
        </div>
      )}

      {/* No disabled override here. The base button draws disabled as an
          unfilled pill; the `disabled:opacity-40` that used to be on this
          className made the app's primary action a mid grey block, reading as
          an ordinary button rather than an unavailable one. */}
      <Button
        onClick={processData}
        disabled={isProcessButtonDisabled()}
        className="mt-2 h-auto w-full py-3.5 text-[15px] font-medium"
      >
        {isLoading ? (
          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
        ) : mode === 'encrypt' ? (
          <Lock className="mr-2 h-4 w-4" />
        ) : verifyOnly ? (
          <ShieldCheck className="mr-2 h-4 w-4" />
        ) : (
          <Unlock className="mr-2 h-4 w-4" />
        )}
        {mode === 'encrypt'
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
          Encrypt stays disabled until the password meets the minimum policy:
          {' '}{PASSWORD_POLICY_HINT}
        </p>
      )}

      {/*
        Always available while there is something to wipe — the panic button
        for "someone just walked over", which is the case the five-minute timer
        is too slow for.
      */}
      {wipeAck && !hasSecretsOnScreen && (
        <section
          role="status"
          data-testid="wipe-ack"
          className="animate-in fade-in-0 slide-in-from-bottom-2 rounded-xl border border-border p-4 duration-500"
        >
          <p className="flex items-center gap-2 text-[15px] font-medium text-foreground">
            <Trash2 className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
            Wiped
          </p>
          <p className="mt-1 text-[12.5px] leading-snug text-muted-foreground">
            Password, inputs and any decrypted output were cleared. Your settings are
            unchanged.
          </p>
        </section>
      )}

      {hasSecretsOnScreen && (
        <button
          type="button"
          onClick={wipeNow}
          className="mx-auto flex cursor-pointer items-center gap-1.5 text-[12px] text-muted-foreground underline underline-offset-2 transition-colors hover:text-destructive"
        >
          <Trash2 className="h-3.5 w-3.5" />
          Wipe now
        </button>
      )}
    </div>
  );
}
