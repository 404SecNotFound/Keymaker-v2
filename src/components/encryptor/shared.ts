/**
 * Types, constants and pure helper functions shared by more than one
 * Encryptor tab module. Nothing here holds React state or renders JSX — see
 * `shared-ui.tsx` for the presentational components that used to live beside
 * these in the single `encryptor-tool.tsx` file.
 *
 * Moved verbatim out of `encryptor-tool.tsx` as part of the module split; see
 * that file's own header for why the split happened. Behaviour is
 * unchanged — every function and constant here is byte-for-byte what it was.
 */
import {
  KeymakerError,
  loadKeym2,
  CipherId,
} from "@/lib/keymaker-crypto";
import { loadShamir } from "@/lib/keym-v2";
import { looksLikeSelfExtract, extractSelfExtract } from "@/lib/keym-v2-selfextract";
import { looksLikePaperPart, decodePaperPartsAny, splitPaperParts } from "@/lib/keym-v2-paper";
import { EFF_LARGE_WORDLIST_SIZE } from "@/lib/eff-wordlist";
import {
  Sprout,
  FileLock,
  FolderOpen,
  Shield,
  Globe,
  UserX,
} from "lucide-react";

export type Mode = "encrypt" | "decrypt" | "tools" | "audio";
export type InputType = "file" | "text";
/**
 * What the input pills offer. "seed" is not a third InputType: it is the text
 * input with the grid as its editor, and everything downstream still sees
 * `inputType === "text"` and one `textSecret`.
 */
export type InputChoice = InputType | "seed";

// The BIP-39 module embeds the full English wordlist (~13 KB), so it is
// loaded lazily to keep it out of the initial bundle. It is warmed in the
// background right after mount (see the effect in EncryptorTool) so the
// service worker caches the chunk for offline use, and awaited on the
// decrypt path before seed detection. `bip39Module` is the synchronous
// handle for render-time use; it is guaranteed non-null once any
// `loadBip39()` call has resolved.
export type Bip39Module = typeof import("@/lib/bip39");
export let bip39Module: Bip39Module | null = null;
let bip39ModulePromise: Promise<Bip39Module> | null = null;
export function loadBip39(): Promise<Bip39Module> {
  bip39ModulePromise ??= import("@/lib/bip39").then((m) => {
    bip39Module = m;
    return m;
  });
  return bip39ModulePromise;
}

// Chunked base64 decode to avoid stack overflow on large buffers.
//
// The encoding half of this pair used to live here and is gone: text output is
// v2 armor now, which is base64url and comes from `armorKeym2`. B9's fix — the
// array-and-join instead of `+=` — moved with it, and is called out there
// rather than dropped.
export function base64ToUint8Array(base64: string): Uint8Array {
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
export const OFFSCREEN_STYLE = { position: 'absolute', left: '-9999px', top: '-9999px' } as const;

/**
 * U16. "GitHub" and "Open source" on a Keymaker page must lead to Keymaker's
 * source; they pointed at the upstream IttyBitz repo, so anyone looking for
 * this product's code or issue tracker landed on a different product.
 *
 * The fork attribution below is a *separate* link and deliberately still points
 * at IttyBitz. It is a GPL-3 credit, not a source link, and repointing it while
 * fixing this would trade a broken link for a licensing discourtesy.
 */
export const KEYMAKER_REPO = "https://github.com/404SecNotFound/Keymaker-v2";

/**
 * 6.1. Injected from package.json by next.config.js, never written twice.
 *
 * The fallback is a visible placeholder rather than a plausible number: if the
 * injection ever breaks, the footer should say something obviously wrong rather
 * than confidently report a version that is not the one running.
 */
export const APP_VERSION = process.env.KEYMAKER_APP_VERSION || "unknown";

/**
 * Whether this bundle is the tagged release of APP_VERSION or a rolling build.
 *
 * The footer said "Keymaker v2.0.0" for both, which made the version a claim
 * the artifact could not support: the deployed site ran commits past the tag
 * while naming the tag. The number is the one people quote in bug reports and
 * check signatures against, so it has to distinguish the two.
 */
export const IS_RELEASE_BUILD = process.env.KEYMAKER_RELEASE_CHANNEL === "release";

/**
 * §4.6. One share per line, blanks and `#` comments dropped.
 *
 * Comments are stripped because the reference CLI prints share sets with
 * `# share 2 of 5` headers, and pasting that output back in unedited is the
 * obvious thing to do. Rejecting it would be a papercut aimed squarely at the
 * person recovering a container under stress.
 */
export function parseShareLines(text: string): string[] {
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
 * The numbers come from the format, generously. A `KMSHARE2:` line is about 140
 * characters (the wider v2 set id and checksum; a legacy `KMSHARE1:` is ~95) and
 * the UI issues at most 8 shares, so 16 lines is double any real share set and
 * 8 KiB is several times the text they occupy. Past that it is a paste into the
 * wrong box, which is what §7 is for.
 */
/**
 * Said only when a paste was refused. The container box also shows notices
 * for pastes it keeps (a share, a paper part, a damaged page), and appending
 * this to every notice told someone looking at their own paste that nothing
 * had been pasted.
 */
/**
 * One-press share sets, as `[needed, printed]`. 2 of 3 survives one lost or
 * destroyed strip; 3 of 5 survives two, and no two holders can open it
 * together. Both fit §4.6's bounds (at most 8 shares, a threshold of at least
 * 2), and the custom fields below them reach every other legal pair.
 */
export const SHARE_PRESETS: ReadonlyArray<readonly [number, number]> = [
  [2, 3],
  [3, 5],
];

export const NOTHING_PASTED = "Nothing was pasted, so what you already had is still here.";

export const MAX_SHARE_INPUT_CHARS = 8 * 1024;
export const MAX_SHARE_LINES = 16;
export const MAX_SHARE_LINE_CHARS = 200;

/**
 * Why this refuses instead of truncating, same as the U4 gate above it: keeping
 * the first N characters of someone's share set and silently dropping the rest
 * produces a reconstruction failure with no stated cause, aimed at the person
 * least able to diagnose it.
 */
export function shareInputRejection(next: string): string | null {
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

/** §4.6 share text, either version. A prefix test, not a parse: the parser is
 *  the authority, this only decides which box a string belongs in. */
export function isShareText(text: string): boolean {
  return /^KMSHARE[12]:/.test(text.trimStart().toUpperCase());
}

/**
 * Append scanned shares to what is already in the shares box, skipping any
 * that are already there.
 *
 * Scanning the same strip twice is the ordinary mistake with a stack of
 * photos, and a duplicate is not harmless: `combineShares` refuses a repeated
 * index outright (§4.6), so k-1 strips plus one scanned twice would fail with
 * nothing to say which photo was the repeat. Case-insensitive because the
 * share alphabet is, and a phone's QR reader may hand back either.
 */
export function mergeScannedShares(
  existing: string,
  scanned: readonly string[]
): { text: string; added: number; repeated: number } {
  const seen = new Set(parseShareLines(existing).map((line) => line.toUpperCase()));
  const fresh: string[] = [];
  let repeated = 0;
  for (const raw of scanned) {
    const line = raw.trim();
    const key = line.toUpperCase();
    if (seen.has(key)) {
      repeated++;
      continue;
    }
    seen.add(key);
    fresh.push(line);
  }
  if (fresh.length === 0) return { text: existing, added: 0, repeated };
  const base = existing.replace(/\s+$/, "");
  return {
    text: `${base ? `${base}\n` : ""}${fresh.join("\n")}\n`,
    added: fresh.length,
    repeated,
  };
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
// The generator's alphabet and length. Kept here rather than inline so the
// entropy figure below is derived from the same values the generator uses,
// and cannot drift from them.
export const PASSWORD_CHARSET =
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~`|}{[]:;?><,./-=";
export const PASSWORD_LENGTH = 32;

// Exact, because the generator samples uniformly from PASSWORD_CHARSET with
// rejection sampling. This is the one entropy number Keymaker is entitled to
// state: it knows the alphabet, the length, and that the draw was unbiased.
export const PASSWORD_ENTROPY_BITS = Math.floor(PASSWORD_LENGTH * Math.log2(PASSWORD_CHARSET.length));

// The passphrase generator's parameters, kept here for the same reason: the
// figure the UI prints is computed from the values the generator uses.
//
// Seven words rather than EFF's headline six. Six is 77.5 bits, which is sound
// behind Argon2id at RFC 9106's second profile — but the KDF settings are the
// user's to lower, and a seventh word buys 13 bits for one more word to
// remember. The list itself is fetched and checksummed rather than transcribed;
// see src/lib/eff-wordlist.ts and scripts/verify-wordlist.mjs.
export const PASSPHRASE_WORDS = 7;
export const PASSPHRASE_SEPARATOR = " ";

// Exact, for the same reason PASSWORD_ENTROPY_BITS is exact: uniform,
// independent draws from a list whose size is known. log2(7776) = 12.925 bits
// per word.
//
// "Independent" means with replacement, which is what makes this a plain
// multiplication and what diceware specifies. A repeated word in a generated
// phrase is therefore not a defect and does not reduce the count — drawing
// without replacement would be a different, slightly smaller number.
export const PASSPHRASE_ENTROPY_BITS = Math.floor(
  PASSPHRASE_WORDS * Math.log2(EFF_LARGE_WORDLIST_SIZE)
);

/**
 * What the CSPRNG produced, when the current password is exactly that.
 *
 * A descriptor rather than a boolean beside a separate bit count: the claim
 * that there *is* an entropy figure and the figure itself have to travel
 * together, or they can drift apart.
 */
export type GeneratedSecret =
  | { kind: "password"; bits: number }
  | { kind: "passphrase"; words: number; bits: number };

// Shared download plumbing. Creating/clicking/removing a transient anchor is
// identical across every download path (key file, ciphertext, plaintext, QR
// PNGs), so it lives in one place.
export function clickDownloadLink(href: string, filename: string) {
  const a = document.createElement("a");
  a.href = href;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

/**
 * Wait until the browser has actually painted.
 *
 * A warning that a derivation is about to freeze the tab is only useful if it
 * is on screen *before* the freeze. Setting React state does not achieve that:
 * the update is scheduled, and the paint happens when the browser next gets a
 * turn — which it never does if the calling code goes straight on into a
 * synchronous, main-thread KDF. `await` yields a microtask, and a microtask is
 * not a frame.
 *
 * Two frames rather than one: the first is when React commits the update, the
 * second is after the browser has drawn it. Raced against a short timer so a
 * page that never animates — a background tab, a headless browser with frames
 * throttled — cannot hang the operation instead of merely not painting it. The
 * cost is at most one quarter-second, and only on the path where the
 * alternative is a tab that stops responding for minutes.
 */
export function paintedFrame(): Promise<void> {
  return new Promise<void>((resolve) => {
    const timer = setTimeout(resolve, 250);
    requestAnimationFrame(() =>
      requestAnimationFrame(() => {
        clearTimeout(timer);
        resolve();
      })
    );
  });
}

export function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  clickDownloadLink(url, filename);
  URL.revokeObjectURL(url);
}

// Export a canvas as a downloaded PNG. octet-stream forces a download rather
// than in-page navigation. .replace() only hits the MIME header, never the
// base64 body.
export function exportCanvasPng(canvas: HTMLCanvasElement, filename: string) {
  const url = canvas.toDataURL("image/png").replace("image/png", "image/octet-stream");
  clickDownloadLink(url, filename);
}

export const validateAndSanitizeFile = (file: File) => {
  // A browser's File.name is a leaf name and never carries a path, so `..`
  // inside it is only punctuation: "Notes... draft.txt" was refused as an
  // invalid filename. What would still mean a directory is a name that is
  // nothing but dots, and the separators below.
  if (/^\.+$/.test(file.name) ||
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
  if (/[\u0000-\u001f‪-‮⁦-⁩]/.test(file.name)) {
    throw new Error('Invalid filename. It contains control or bidirectional-override characters.');
  }

  return true;
};

// 100 MB. Note: encrypting a file of this size transiently holds several full
// copies in memory (the read ArrayBuffer, the Web Crypto ciphertext output,
// and the Blob for download), so peak usage is a multiple of this limit —
// the practical ceiling on low-RAM mobile devices.
export const MAX_FILE_SIZE = 100 * 1024 * 1024;
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
export const QR_MAX_BYTES = 2_953;

/** UTF-8 byte length, which is what the QR encoder actually consumes. */
export function qrByteLength(text: string): number {
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
export const KEYM_V1_TEXT_PREFIX = "KEYM1:";
export const KEYM_V2_TEXT_PREFIX = "keym2:";

/**
 * A file chosen on Decrypt that holds a backup as *text*: `keym2:` or
 * `KEYM1:` armor saved to a .txt, a self-extracting page, or a set of paper
 * parts. Returns the container bytes, or null when the file is not one of
 * these (a binary container, a legacy blob, or anything else), in which case
 * it goes to the container reader as it is.
 *
 * File mode used to hand every file to the reader as raw bytes. None of these
 * starts with the binary magic, so each fell through to the headerless legacy
 * path, ran a million PBKDF2 iterations, and was reported as a wrong password:
 * the heir holding a saved .txt or the page itself was told to retype a
 * password that was right. The text box already reads all of these; this is
 * the same set of readers, reached from the other input.
 */
export async function containerFromTextFile(bytes: Uint8Array): Promise<Uint8Array | null> {
  const ascii = (at: number, n: number) => String.fromCharCode(...bytes.subarray(at, at + n));
  // Binary containers: KEYM magic with a version byte (not the "1:" of v1
  // armor, which shares the first four bytes), and legacy IBTZ.
  if (ascii(0, 4) === "IBTZ") return null;
  if (ascii(0, 4) === "KEYM" && ascii(4, 2) !== "1:") return null;
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
  text = text.replace(/^﻿/, "").trim();
  const unreadable = (what: string) =>
    new KeymakerError(
      "invalid-input",
      `That file holds ${what}, but it is not intact, so it cannot be opened. ` +
        "Nothing was tried against your password. Recover from another copy."
    );
  if (text.startsWith(KEYM_V2_TEXT_PREFIX)) {
    const { dearmorKeym2 } = await loadKeym2();
    try {
      return dearmorKeym2(text);
    } catch {
      throw unreadable("keym2: text");
    }
  }
  if (text.toUpperCase().startsWith(KEYM_V1_TEXT_PREFIX)) {
    try {
      return base64ToUint8Array(text.slice(KEYM_V1_TEXT_PREFIX.length).replace(/\s+/g, ""));
    } catch {
      throw unreadable("KEYM1: text");
    }
  }
  if (looksLikeSelfExtract(text)) {
    try {
      return extractSelfExtract(text);
    } catch (e) {
      throw new KeymakerError("invalid-input", (e as Error).message);
    }
  }
  if (looksLikePaperPart(text)) {
    try {
      return await decodePaperPartsAny(splitPaperParts(text));
    } catch (e) {
      throw new KeymakerError("invalid-input", (e as Error).message);
    }
  }
  // Shares files usually open with a comment ("# strips 1 and 2"), so the
  // test is on the first line that is not one.
  const firstLine = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .find((line) => line !== "" && !line.startsWith("#"));
  if (firstLine !== undefined && isShareText(firstLine)) {
    throw new KeymakerError(
      "invalid-input",
      "That file holds recovery shares, not an encrypted backup. Choose the backup " +
        'here, then choose "Use recovery shares" beside the password field and put ' +
        "the shares there."
    );
  }
  return null;
}

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
export const CLIPBOARD_CLEAR_SECONDS = 60;

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
export const AUTO_LOCK_MS = 5 * 60_000;
export const LOCK_WARN_SECONDS = 30;

/**
 * Subdirectory this build is served from, or "" at a domain root.
 *
 * Next rewrites its own asset URLs but not ones written by hand, so any link
 * authored here has to prefix itself — same reason crypto-client.ts does it for
 * the worker URL. Without it the recovery-kit links 404 on the Pages
 * deployment, which is the one place they matter most.
 */
export const BASE_PATH = (process.env.KEYMAKER_BASE_PATH || '').replace(/\/$/, '');

/** Byte count for humans. Used by the verify-only result. */
export function formatBytes(n: number): string {
  if (n < 1024) return `${n} byte${n === 1 ? '' : 's'}`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

// Filename privacy: when enabled, encrypted downloads are named
// keymaker-<random8 hex>.keym instead of <original name>.keym.
export function randomFilenameSuffix(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(4));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export type KdfChoice = "pbkdf2" | "argon2id";

/**
 * The KDF and cipher as the inspector names them — one function each, used
 * by the plan pane *and* the receipt, so the two cannot drift. The parsed
 * pane derives the same strings from the bytes, which is what the receipt
 * spec compares them to.
 */
export function kdfLabelOf(
  choice: KdfChoice,
  memoryMiB: number,
  timeCost: number,
  parallelism: number
): string {
  return choice === "argon2id"
    ? `Argon2id · ${memoryMiB} MiB · t=${timeCost} · p=${parallelism}`
    : "PBKDF2 · 1,000,000 iterations";
}
export function cipherLabelOf(cipher: CipherId): string {
  return cipher === CipherId.AES_256_GCM
    ? "AES-256-GCM"
    : cipher === CipherId.CHACHA20_POLY1305
      ? "ChaCha20-Poly1305"
      : "AES-256-GCM + ChaCha20-Poly1305";
}

export const CIPHER_OPTIONS = [
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

/**
 * The doors under the hero.
 *
 * The first decision the page used to ask was the system's — Encrypt, Decrypt,
 * Tools — and the user's own question ("I have a seed phrase to put
 * somewhere safe") had to be translated into it. A door is that question,
 * answered: it sets the mode, the input, and the defaults a passport scan and
 * a 24-word phrase should never have shared. It configures and nothing more —
 * the form is the same form, arriving with the right things already set. The
 * tabs stay for anyone who thinks in the system's terms.
 */
export const DOORS = [
  {
    id: "seed",
    icon: Sprout,
    title: "Back up a seed phrase",
    blurb: "Each word checked as you type. Recovery shares suggested.",
    keywords: "bip39 wallet mnemonic recovery words",
  },
  {
    id: "file",
    icon: FileLock,
    title: "Encrypt a file",
    blurb: "Any file, sealed into a .keym you keep.",
    keywords: "document scan photo seal",
  },
  {
    id: "open",
    icon: FolderOpen,
    title: "Open a backup",
    blurb: "A .keym file, pasted text, or paper shares.",
    keywords: "decrypt unlock heir recover restore",
  },
] as const;
export type Door = (typeof DOORS)[number]["id"];

export const FEATURE_CARDS = [
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

/**
 * §7.3. Encode a container into KMPART2 paper parts, each sized to fit one QR
 * symbol, and decide whether it is simply too large to be a paper backup.
 *
 * Async because the container fingerprint and per-part checksums are SHA-256, so
 * this runs in the print handler before the sheet mounts rather than in the
 * sheet's render: a QR whose value arrives a tick after layout prints blank, and
 * a page must never go to paper half-formed. The sheet is handed a finished
 * array. `paperCapacityV2` reserves the v2 metadata so no part overflows its
 * symbol — the trap a naive swap of the v1 writer would have hit.
 */
export async function preparePaperParts(
  container: Uint8Array
): Promise<{ parts: string[]; tooLarge: boolean; setCodes: string[] }> {
  const { encodePaperPartsForPrint } = await import("@/lib/keym-v2-paper");
  const setCodes = await containerSetCodes(container);
  try {
    const parts = await encodePaperPartsForPrint(container);
    // 300 symbols is ~200 kB of container at §7.3's version-25 size, and a
    // ream of paper. Past that the honest answer is "this is not a paper
    // backup", not pages no one will scan.
    return { parts, tooLarge: parts.length > 300, setCodes };
  } catch {
    return { parts: [], tooLarge: true, setCodes };
  }
}

/**
 * §4.6 "The set code" of each share set this container carries, from its slot
 * salts, so the owner's sheet can say which strips belong to it. Derived from
 * the container rather than from strips, because the sheet is also printed
 * later, from the receipt, when the strips are no longer on screen. Empty for a
 * container with no share slot or one this build cannot parse: a sheet with no
 * set code is honest, one with an invented code is not.
 */
export async function containerSetCodes(container: Uint8Array): Promise<string[]> {
  try {
    const { shamirSlotSaltsKeym2 } = await loadKeym2();
    const { shareSetCode } = await loadShamir();
    return await Promise.all(shamirSlotSaltsKeym2(container).map((salt) => shareSetCode(salt)));
  } catch {
    return [];
  }
}

/** Verify-only decrypt result — see the `verifyOnly` state in the hook. */
export type VerifyResult = { detail: string; bytes: number; method: "password" | "recovery shares" | "passkey" };

// Decrypted-result QR modal state. This is purely a display-side concern —
// the QR is generated from the already-decrypted `outputText`. It does not
// touch the cryptography or the encrypted file format.
// The SeedQR payload is intentionally NOT stored in state — it is derived
// from `words` at render time, and only while the QR is revealed, to keep
// the encoded secret out of long-lived component state.
export type DecryptedQrStatus =
  | { kind: "idle" }
  // seedShaped: the decrypted text failed BIP-39 validation but looks like
  // a seed phrase (valid word count, ≤1 unknown word) — the stored backup
  // itself likely contains a transcription error. Surfaced as a red border.
  | { kind: "plain"; seedShaped: boolean }
  | { kind: "seed"; words: string[] };

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
export type RehearsalState =
  | { kind: "idle" }
  | { kind: "running" }
  | { kind: "ok"; on: string; strips: number[]; seconds: number; bytes: number }
  | { kind: "failed"; message: string };

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
export type Receipt = {
  from: string;
  to: string;
  kdf: string;
  cipher: string;
  waysIn: string[];
  bytes: number;
  /** The container is on screen as armored text: printable, downloadable, rehearsable. */
  onScreen: boolean;
  shares: { threshold: number; count: number } | null;
};
