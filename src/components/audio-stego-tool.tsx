"use client";

/**
 * The Audio tab: an **encrypted audio carrier**. It packs a KEYM container into
 * an audio file's samples and recovers it. This is a carrier around the ordinary
 * encrypt/decrypt path, not a new cipher: the bytes packed into the audio are a
 * normal container produced by `encryptViaWorker`, so Argon2id + AES-256-GCM and
 * the independent decryptor apply unchanged. See docs/FORMAT-AUDIO-STEGO.md.
 *
 * Deliberately not called steganography in the UI. The `KAUD1` header sits in
 * the first sample LSBs and the container follows it sequentially, so the
 * presence of a payload is trivially detectable; this hides nothing from anyone
 * who looks. What protects the secret is the password, exactly as on the Encrypt
 * tab.
 *
 * Self-contained on purpose. It renders in its own tab like DiceEntropyTool, so
 * none of the 5,000-line encryptor's mode logic has to grow a fourth case.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import {
  Download,
  Eye,
  EyeOff,
  FileAudio,
  Lock,
  Unlock,
  TriangleAlert,
} from "lucide-react";
import { encryptViaWorker, decryptViaWorker } from "@/lib/crypto-client";
import { KdfId, CipherId, DEFAULT_ARGON2ID, MAX_PLAINTEXT_SIZE, isUserFacingError } from "@/lib/keymaker-crypto";
import { meetsPasswordPolicy, PASSWORD_POLICY_HINT } from "@/lib/password-policy";
import {
  AudioStegoError,
  parseWavToPcm16,
  decodeToPcm16,
  writePcm16Wav,
  embedContainer,
  extractContainer,
  audioCapacityBytes,
  type Pcm16,
} from "@/lib/audio-stego";

/** Phase 1 seals with the recommended defaults. The Audio tab does not expose
 *  KDF/cipher choice yet; the container is still a full KEYM container. */
const OPTIONS = {
  kdf: { kdf: KdfId.ARGON2ID as const, params: DEFAULT_ARGON2ID },
  cipher: CipherId.AES_256_GCM as const,
};

type Sub = "hide" | "reveal";
type SecretType = "text" | "file";

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function download(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function looksLikeWav(file: File): boolean {
  return /audio\/(wav|x-wav|wave|vnd\.wave)/i.test(file.type) || /\.wav$/i.test(file.name);
}

/** Decode any carrier to 16-bit PCM. WAV is parsed exactly so its samples (and
 *  therefore any embedded LSBs) survive; everything else goes through Web Audio. */
async function decodeCarrier(file: File): Promise<Pcm16> {
  const buffer = await file.arrayBuffer();
  if (looksLikeWav(file)) {
    return parseWavToPcm16(new Uint8Array(buffer));
  }
  return decodeToPcm16(buffer);
}

export function AudioStegoTool() {
  const { toast } = useToast();
  const [sub, setSub] = useState<Sub>("hide");
  const [busy, setBusy] = useState(false);

  // Carrier, decoded once on selection so capacity can be shown and the embed
  // does not decode twice.
  const [carrierName, setCarrierName] = useState<string | null>(null);
  const [carrierPcm, setCarrierPcm] = useState<Pcm16 | null>(null);
  const [carrierError, setCarrierError] = useState<string | null>(null);
  const carrierInputRef = useRef<HTMLInputElement>(null);

  // Hide inputs.
  const [secretType, setSecretType] = useState<SecretType>("text");
  const [secretText, setSecretText] = useState("");
  const [secretFile, setSecretFile] = useState<File | null>(null);
  const secretFileInputRef = useRef<HTMLInputElement>(null);

  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  // Reveal output.
  const [revealedText, setRevealedText] = useState<string | null>(null);
  const [revealedBytes, setRevealedBytes] = useState<Uint8Array | null>(null);
  const [showRevealed, setShowRevealed] = useState(false);

  const capacity = carrierPcm ? audioCapacityBytes(carrierPcm.samples.length, 1) : 0;

  const resetOutputs = useCallback(() => {
    setRevealedText(null);
    setRevealedBytes(null);
    setShowRevealed(false);
  }, []);

  // Drop every secret this tab holds. JavaScript cannot guarantee zeroization,
  // but the recovered bytes are one buffer this code owns, so it is overwritten
  // rather than merely dereferenced; the strings are released to the collector.
  const clearSecrets = useCallback(() => {
    setPassword("");
    setSecretText("");
    setRevealedText((prev) => (prev === null ? prev : null));
    setRevealedBytes((prev) => {
      if (prev) prev.fill(0);
      return null;
    });
    setShowRevealed(false);
    setShowPassword(false);
  }, []);

  // Auto-lock, matching the main tool's posture: a tab that is hidden or being
  // navigated away from should not keep a password and a decrypted secret in
  // memory, and neither should one that unmounts (which is what a tab switch
  // does here, since this panel is not force-mounted).
  useEffect(() => {
    const onHide = () => {
      if (document.visibilityState === "hidden") clearSecrets();
    };
    document.addEventListener("visibilitychange", onHide);
    window.addEventListener("pagehide", clearSecrets);
    return () => {
      document.removeEventListener("visibilitychange", onHide);
      window.removeEventListener("pagehide", clearSecrets);
      clearSecrets();
    };
  }, [clearSecrets]);

  const switchSub = useCallback(
    (next: Sub) => {
      setSub(next);
      resetOutputs();
    },
    [resetOutputs]
  );

  const onCarrierChange = useCallback(
    async (file: File | null) => {
      resetOutputs();
      setCarrierPcm(null);
      setCarrierError(null);
      setCarrierName(file?.name ?? null);
      if (!file) return;
      if (file.size > MAX_PLAINTEXT_SIZE) {
        setCarrierError(
          `That file is ${formatBytes(file.size)}. Audio carriers are accepted up to ` +
            `${Math.floor(MAX_PLAINTEXT_SIZE / 1024 / 1024)} MB.`
        );
        return;
      }
      setBusy(true);
      try {
        const pcm = await decodeCarrier(file);
        setCarrierPcm(pcm);
      } catch (e) {
        setCarrierError(
          e instanceof AudioStegoError ? e.message : "This audio file could not be read."
        );
      } finally {
        setBusy(false);
      }
    },
    [resetOutputs]
  );

  const runHide = useCallback(async () => {
    if (!carrierPcm) {
      toast({ title: "Add a carrier", description: "Choose an audio file to pack the secret into.", variant: "destructive" });
      return;
    }
    const haveSecret = secretType === "text" ? secretText.length > 0 : secretFile !== null;
    if (!haveSecret) {
      toast({ title: "Nothing to hide", description: "Enter text or choose a file to pack in.", variant: "destructive" });
      return;
    }
    if (!meetsPasswordPolicy(password)) {
      toast({
        title: "Stronger password needed",
        description: `Use ${PASSWORD_POLICY_HINT}`,
        variant: "destructive",
      });
      return;
    }

    setBusy(true);
    try {
      const secretBytes =
        secretType === "text"
          ? new TextEncoder().encode(secretText)
          : new Uint8Array(await secretFile!.arrayBuffer());
      // exact-length ArrayBuffer, since encryptViaWorker takes ownership.
      const input = secretBytes.slice().buffer;
      const enc = await encryptViaWorker(input, password, null, OPTIONS);
      const container = new Uint8Array(enc.data);

      // Capacity is re-checked inside embedContainer, but checking here lets the
      // message name the container size the carrier actually has to hold, which
      // is larger than the secret by the header, salt, nonces and tags.
      if (container.length > capacity) {
        toast({
          title: "Carrier too small",
          description:
            `The sealed secret is ${formatBytes(container.length)} but this audio holds ` +
            `${formatBytes(capacity)}. Use a longer track, or hide less.`,
          variant: "destructive",
        });
        return;
      }

      const stego = embedContainer(carrierPcm, container, 1);
      const wav = writePcm16Wav(stego);
      download(new Blob([wav as BlobPart], { type: "audio/wav" }), "keymaker-audio.wav");
      toast({
        title: "Secret packed into audio",
        description: "Downloaded as a WAV. It plays normally; open it here on the Reveal side with the password.",
      });
    } catch (e) {
      const description =
        e instanceof AudioStegoError
          ? e.message
          : isUserFacingError(e)
            ? e.message
            : "Something went wrong sealing the secret into the audio.";
      toast({ title: "Could not pack the secret", description, variant: "destructive" });
    } finally {
      setBusy(false);
    }
  }, [carrierPcm, capacity, secretType, secretText, secretFile, password, toast]);

  const runReveal = useCallback(async () => {
    if (!carrierPcm) {
      toast({ title: "Add the audio", description: "Choose the audio file that carries the secret.", variant: "destructive" });
      return;
    }
    if (password.length === 0) {
      toast({ title: "Password needed", description: "Enter the password the secret was hidden with.", variant: "destructive" });
      return;
    }

    setBusy(true);
    resetOutputs();
    try {
      // Structural failure first: a file with no KAUD1 header is reported as
      // carrying nothing, never routed to the AEAD where it would read as a
      // wrong password.
      const container = extractContainer(carrierPcm);
      const res = await decryptViaWorker(container.slice().buffer, password, null);
      const data = new Uint8Array(res.data);

      let asText: string | null = null;
      try {
        asText = new TextDecoder("utf-8", { fatal: true }).decode(data);
      } catch {
        asText = null;
      }
      setRevealedBytes(data);
      setRevealedText(asText);
      toast({
        title: "Secret recovered",
        description: asText !== null ? "Recovered as text below." : "Recovered a file. Download it below.",
      });
    } catch (e) {
      if (e instanceof AudioStegoError) {
        toast({ title: "No hidden data", description: e.message, variant: "destructive" });
      } else if (isUserFacingError(e)) {
        toast({ title: "Could not open", description: e.message, variant: "destructive" });
      } else {
        toast({
          title: "Wrong password or damaged carrier",
          description: "The hidden container did not open. Check the password, and that this is the exact file that was produced.",
          variant: "destructive",
        });
      }
    } finally {
      setBusy(false);
    }
  }, [carrierPcm, password, resetOutputs, toast]);

  const pillClasses = (active: boolean) =>
    cn(
      "flex-1 cursor-pointer rounded-full border px-3 py-2 text-center text-[13px] font-medium transition-colors",
      active ? "border-border-strong bg-inset text-foreground" : "border-transparent text-muted-foreground hover:text-foreground"
    );

  return (
    <div className="space-y-5">
      <div className="space-y-1">
        <h2 className="text-[15px] font-semibold text-foreground">Encrypted audio carrier</h2>
        <p className="text-[13px] leading-snug text-muted-foreground">
          Pack an encrypted secret into an audio file, and take it back out with the password.
        </p>
      </div>

      {/* Honest framing: this is a carrier, not deniable hiding; lossless out. */}
      <div className="flex items-start gap-2.5 rounded-xl border border-warning/40 bg-warning/10 px-3.5 py-3 text-[12px] leading-snug text-warning">
        <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
        <p>
          This is a carrier, not a hiding place: the payload sits in a known place in the samples
          and is easy to detect, so do not rely on it to conceal that a secret exists. What protects
          the secret is the password: the same Argon2id and AES-256-GCM the Encrypt tab uses. Output
          is a lossless WAV, because an MP3 cannot hold the data.
        </p>
      </div>

      <div className="flex gap-0.5 rounded-xl bg-inset p-1">
        <button type="button" onClick={() => switchSub("hide")} className={pillClasses(sub === "hide")}>
          Pack into audio
        </button>
        <button type="button" onClick={() => switchSub("reveal")} className={pillClasses(sub === "reveal")}>
          Unpack from audio
        </button>
      </div>

      {/* Carrier picker, shared by both sub-modes. */}
      <div className="space-y-2">
        <Label className="text-[13px] font-medium text-muted-foreground">
          {sub === "hide" ? "Carrier audio" : "Audio to read"}
        </Label>
        <input
          ref={carrierInputRef}
          id="audio-carrier-input"
          type="file"
          accept="audio/*,.wav,.mp3,.flac,.ogg"
          className="hidden"
          onChange={(e) => {
            const f = e.target.files?.[0] ?? null;
            e.target.value = "";
            void onCarrierChange(f);
          }}
        />
        <button
          type="button"
          onClick={() => carrierInputRef.current?.click()}
          className="flex w-full items-center gap-3 rounded-xl border border-dashed border-border bg-inset px-4 py-4 text-left transition-colors hover:bg-raised"
        >
          <FileAudio className="h-5 w-5 shrink-0 text-muted-foreground" />
          <span className="min-w-0 flex-1">
            <span className="block truncate text-sm text-foreground">
              {carrierName ?? "Choose an audio file"}
            </span>
            <span className="block text-[12px] text-muted-foreground">
              {carrierPcm
                ? `${carrierPcm.channels === 1 ? "mono" : `${carrierPcm.channels}ch`} · ${carrierPcm.sampleRate.toLocaleString()} Hz · holds ${formatBytes(capacity)}`
                : sub === "hide"
                  ? "MP3, WAV, FLAC or Ogg in · lossless WAV out"
                  : "the WAV this tab produced"}
            </span>
          </span>
        </button>
        {carrierError && (
          <p role="alert" className="rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-[12px] leading-snug text-destructive">
            {carrierError}
          </p>
        )}
      </div>

      {sub === "hide" ? (
        <>
          {/* Secret input: text or file. */}
          <div className="space-y-2">
            <div className="flex gap-0.5 rounded-xl bg-inset p-1">
              <button type="button" onClick={() => setSecretType("text")} className={pillClasses(secretType === "text")}>
                Text
              </button>
              <button type="button" onClick={() => setSecretType("file")} className={pillClasses(secretType === "file")}>
                File
              </button>
            </div>
            {secretType === "text" ? (
              <Textarea
                id="audio-secret-text"
                value={secretText}
                onChange={(e) => setSecretText(e.target.value)}
                placeholder="Enter the secret text to pack in…"
                rows={4}
                spellCheck={false}
                autoCorrect="off"
                autoCapitalize="none"
                autoComplete="off"
                data-1p-ignore
                data-lpignore="true"
                className="rounded-xl border-border bg-inset focus-visible:border-border-strong focus-visible:ring-0"
              />
            ) : (
              <>
                <input
                  ref={secretFileInputRef}
                  id="audio-secret-file-input"
                  type="file"
                  className="hidden"
                  onChange={(e) => setSecretFile(e.target.files?.[0] ?? null)}
                />
                <button
                  type="button"
                  onClick={() => secretFileInputRef.current?.click()}
                  className="flex w-full items-center gap-3 rounded-xl border border-dashed border-border bg-inset px-4 py-4 text-left transition-colors hover:bg-raised"
                >
                  <Lock className="h-5 w-5 shrink-0 text-muted-foreground" />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm text-foreground">{secretFile?.name ?? "Choose a file to hide"}</span>
                    <span className="block text-[12px] text-muted-foreground">
                      {secretFile ? formatBytes(secretFile.size) : "any file the carrier is large enough to hold"}
                    </span>
                  </span>
                </button>
              </>
            )}
          </div>

          <PasswordField
            id="audio-hide-password"
            value={password}
            onChange={setPassword}
            show={showPassword}
            onToggle={() => setShowPassword((v) => !v)}
            placeholder="Password to lock the secret"
          />

          <Button
            type="button"
            disabled={busy}
            onClick={() => void runHide()}
            className="w-full rounded-xl py-6 text-sm font-semibold"
          >
            <Lock className="mr-2 h-4 w-4" />
            {busy ? "Working…" : "Pack into audio & download WAV"}
          </Button>
        </>
      ) : (
        <>
          <PasswordField
            id="audio-reveal-password"
            value={password}
            onChange={setPassword}
            show={showPassword}
            onToggle={() => setShowPassword((v) => !v)}
            placeholder="Password the secret was packed with"
          />

          <Button
            type="button"
            disabled={busy}
            onClick={() => void runReveal()}
            className="w-full rounded-xl py-6 text-sm font-semibold"
          >
            <Unlock className="mr-2 h-4 w-4" />
            {busy ? "Working…" : "Reveal secret"}
          </Button>

          {revealedBytes && (
            <div className="animate-in fade-in-50 space-y-2">
              <div className="flex items-center justify-between">
                <Label className="text-[13px] font-medium text-muted-foreground">Recovered</Label>
                {revealedText !== null && (
                  <button
                    type="button"
                    onClick={() => setShowRevealed((v) => !v)}
                    aria-pressed={showRevealed}
                    className="rounded-lg border border-border bg-inset p-1.5 text-muted-foreground transition-colors hover:bg-raised hover:text-foreground"
                    aria-label={showRevealed ? "Hide recovered text" : "Show recovered text"}
                  >
                    {showRevealed ? <Eye className="h-4 w-4" /> : <EyeOff className="h-4 w-4" />}
                  </button>
                )}
              </div>
              {revealedText !== null ? (
                <Textarea
                  data-testid="audio-recovered-text"
                  readOnly
                  value={revealedText}
                  rows={5}
                  className={cn(
                    "rounded-xl border-border bg-inset focus-visible:ring-0",
                    !showRevealed && "blur-sm"
                  )}
                />
              ) : (
                <p className="text-[12px] leading-snug text-muted-foreground">
                  The hidden secret is a {formatBytes(revealedBytes.length)} file, not text.
                </p>
              )}
              <Button
                type="button"
                variant="outline"
                onClick={() =>
                  download(
                    new Blob([revealedBytes.slice() as BlobPart], { type: "application/octet-stream" }),
                    revealedText !== null ? "recovered.txt" : "recovered.bin"
                  )
                }
                className="w-full rounded-xl"
              >
                <Download className="mr-2 h-4 w-4" />
                Download recovered {revealedText !== null ? "text" : "file"}
              </Button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function PasswordField({
  id,
  value,
  onChange,
  show,
  onToggle,
  placeholder,
}: {
  id: string;
  value: string;
  onChange: (v: string) => void;
  show: boolean;
  onToggle: () => void;
  placeholder: string;
}) {
  return (
    <div className="space-y-2">
      <Label htmlFor={id} className="text-[13px] font-medium text-muted-foreground">
        Password
      </Label>
      <div className="relative">
        <Input
          id={id}
          type={show ? "text" : "password"}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          autoComplete="off"
          data-1p-ignore
          data-lpignore="true"
          className="rounded-xl border-border bg-inset pr-12 focus-visible:border-border-strong focus-visible:ring-0"
        />
        <button
          type="button"
          onClick={onToggle}
          aria-pressed={show}
          aria-label={show ? "Hide password" : "Show password"}
          className="absolute right-2 top-1/2 -translate-y-1/2 rounded-lg border border-border bg-inset p-1.5 text-muted-foreground transition-colors hover:bg-raised hover:text-foreground"
        >
          {show ? <Eye className="h-4 w-4" /> : <EyeOff className="h-4 w-4" />}
        </button>
      </div>
    </div>
  );
}
