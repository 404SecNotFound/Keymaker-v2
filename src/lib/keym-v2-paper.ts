/**
 * Paper parts for KEYM v2 — `docs/FORMAT-V2-DESIGN.md` §7.1.
 *
 * A container of any interesting size does not fit in one QR code, so a paper
 * backup spans several symbols and the format has to say how they split and how
 * they go back together. This is that encoding, and it has a counterpart in
 * `reference/keym2.py` that must agree byte for byte — the conformance suite
 * compares the emitted strings, not just the reassembled container, because
 * transposing a slice boundary leaves the reassembly correct and the printed
 * pages mutually unusable.
 *
 * The reason this exists at all rather than "print the armor in a small font":
 * a page of base64 is retyped by hand at 4 kB an hour with a typo rate that
 * makes an AEAD failure near-certain. A QR is scanned in a second and the
 * error-correction is arithmetic rather than eyesight.
 */

/** §7.1. `KMS` is a share, `KMP` is a paper part; the family splits at byte 2. */
export const KEYM2_PART_PREFIX = "KMPART1:";

/** Anchored, and the counts are bounded — see the Python regex for the reason. */
const PART_RE = /^KMPART1:(\d{1,4})\/(\d{1,4}):([A-Za-z0-9_-]+)$/;

/**
 * Byte-mode capacity of a version-40 QR at error-correction level **M**.
 *
 * Deliberately not level L, which the on-screen QR uses. L recovers 7% of a
 * damaged symbol and is the right trade when the "paper" is a phone screen two
 * feet away. This code is going in a drawer for a decade, where it will be
 * folded, stained, photocopied and sun-bleached, and 15% recovery for a third
 * fewer bytes is the trade that actually matches the medium.
 */
export const PAPER_QR_MAX_BYTES = 2_331;

function b64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(text: string): Uint8Array {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/**
 * Raw container bytes that fit one symbol of `qrByteCapacity`.
 *
 * Subtracts the widest prefix this run can emit, then reverses base64's 4/3
 * inflation. `totalHint` stops a small backup being charged for four-digit
 * counts it will never print.
 */
export function paperCapacity(qrByteCapacity: number, totalHint = 9999): number {
  const prefix = KEYM2_PART_PREFIX.length + 2 * String(totalHint).length + 2;
  const usable = qrByteCapacity - prefix;
  if (usable < 4) throw new Error("symbol too small to hold a part");
  return Math.floor(usable / 4) * 3;
}

/**
 * §7.1. Split a container into paper parts of at most `capacity` raw bytes.
 *
 * A one-part backup is still written `1/1`. Special-casing it would leave an
 * untested branch on the path that only the smallest backups take, and the page
 * saying "part 1 of 1" is what stops someone hunting a drawer for pages that
 * were never printed.
 */
export function encodePaperParts(container: Uint8Array, capacity: number): string[] {
  if (capacity < 1) throw new Error("capacity must be at least one byte");
  if (container.length === 0) {
    throw new Error("refusing to write paper parts for an empty container");
  }
  const slices: Uint8Array[] = [];
  for (let i = 0; i < container.length; i += capacity) {
    slices.push(container.subarray(i, i + capacity));
  }
  if (slices.length > 9999) {
    throw new Error(`${slices.length} parts is not a paper backup anyone will reassemble`);
  }
  return slices.map(
    (s, i) => `${KEYM2_PART_PREFIX}${i + 1}/${slices.length}:${b64urlEncode(s)}`
  );
}

/**
 * §7.1. Reassemble paper parts, byte for byte.
 *
 * Every failure this function *can* see is reported as a reassembly failure.
 * Letting a short or misordered set through to the AEAD would surface as
 * "decryption failed", which a user reads as a wrong password — and acts on by
 * retyping a password they already know is right, while the actual problem is
 * a page still in the scanner.
 *
 * What it cannot see, stated because the sentence above used to imply
 * otherwise: a part is structure plus base64url, and §7.1 gives it **no
 * checksum** — unlike a Shamir share, which carries one (§4.6). A character
 * misread as another character *in the alphabet* encodes different data and
 * nothing here can tell. Whitespace is the same case by a different route:
 * §7.1 strips it so a printed part can wrap, so a space landing on a character
 * deletes it, and only the three-in-four that break the body's length mod 4
 * are caught by the decoder below.
 *
 * That residual is the AEAD's, which is the right place for it — the container
 * authenticates every byte, so damage never yields wrong plaintext, only a
 * refusal. The cost is the refusal's *wording*, and the fix for that is not a
 * format change: adding a checksum to §7.1 would invalidate every page already
 * printed, which is a worse trade than a misleading error message. Measured by
 * `scripts/keym2-fuzz.mts`, which reports the count rather than asserting it
 * away.
 */
export function decodePaperParts(parts: readonly string[]): Uint8Array {
  const seen = new Map<number, Uint8Array>();
  const totals = new Set<number>();

  for (const raw of parts) {
    const text = raw.replace(/\s+/g, "");
    if (!text) continue;
    const m = PART_RE.exec(text);
    if (!m) {
      throw new Error(
        `Not a paper part: "${text.slice(0, 24)}". Parts look like ` +
          `${KEYM2_PART_PREFIX}1/4:… — check the whole symbol scanned.`
      );
    }
    const index = Number(m[1]);
    const total = Number(m[2]);
    if (total < 1) throw new Error("A part claims to be one of zero parts.");
    if (index < 1 || index > total) {
      throw new Error(`Part ${index} of ${total} is out of range.`);
    }
    if (seen.has(index)) throw new Error(`Part ${index} was supplied twice.`);
    totals.add(total);
    seen.set(index, b64urlDecode(m[3] as string));
  }

  if (seen.size === 0) throw new Error("No parts supplied.");
  if (totals.size !== 1) {
    throw new Error(
      `These parts disagree about how many there are (${[...totals].sort().join(", ")}) — ` +
        "they are from different backups."
    );
  }

  const total = [...totals][0] as number;
  const missing: number[] = [];
  for (let i = 1; i <= total; i++) if (!seen.has(i)) missing.push(i);
  if (missing.length) {
    throw new Error(
      `Missing part ${missing.join(", ")} of ${total}. Every part is needed — ` +
        "this is not a k-of-n share set."
    );
  }

  let length = 0;
  for (const slice of seen.values()) length += slice.length;
  const out = new Uint8Array(length);
  let offset = 0;
  for (let i = 1; i <= total; i++) {
    const slice = seen.get(i) as Uint8Array;
    out.set(slice, offset);
    offset += slice.length;
  }
  return out;
}

/** §7.1. Whether some pasted text is a paper part, for the wrong-box report. */
/**
 * Pasted text split into the lines `decodePaperParts` expects.
 *
 * Blank lines and `#` comments are dropped, because `keym2.py split` writes
 * `# part 1 of 4` above each part and an heir pastes the file it produced, not
 * a hand-cleaned version of it.
 *
 * This lives here because it existed three times and agreed twice. The Python
 * CLI dropped comments, `bridge.mts`'s `join` dropped comments, and the app —
 * the only one of the three a person actually uses — did not. The conformance
 * suite could not see the difference: its own harness filtered the comments out
 * before handing anything to the decoder, so it was testing text no user ever
 * produces. One definition, used by all of them, is what stops that recurring.
 */
export function splitPaperParts(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line !== "" && !line.startsWith("#"));
}

/**
 * §7.1. Does this paste look like paper parts?
 *
 * Answered on the first *part* line rather than the first line, so the CLI's
 * own output routes here. Before, a leading `# part 1 of 4` made this false and
 * the paste fell through to the container reader, which reported that the text
 * was not a container — true, unhelpful, and not what went wrong.
 *
 * Total by contract: this is called on whatever was pasted.
 */
export function looksLikePaperPart(text: string): boolean {
  const first = splitPaperParts(text)[0];
  return first !== undefined && first.startsWith(KEYM2_PART_PREFIX);
}

/**
 * The `i of n` a wrong-box paste should be told, without committing to the
 * whole part being valid — the point is to name what they pasted, not to
 * validate it.
 */
export function describePaperPart(text: string): { index: number; total: number } | null {
  const m = PART_RE.exec(text.replace(/\s+/g, ""));
  if (!m) return null;
  return { index: Number(m[1]), total: Number(m[2]) };
}
