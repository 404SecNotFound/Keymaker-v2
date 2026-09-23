/**
 * When the camera scanner has read enough, and what to tell the person holding
 * the paper while it has not. Pure, so the rule that decides when the camera
 * stops is tested without a camera (scripts/camera-progress-test.mjs).
 *
 * "Enough" is judged from the codes themselves, never from the container: a
 * strip says how many strips open its backup (§4.6 `threshold`), and a
 * container symbol says how many symbols there are (§7.1/§7.3 `total`). Each
 * kind that has been started must be complete, and a whole backup in one code
 * (`keym2:` armor) is complete on its own. A strip is counted by its index
 * within the first set seen, so the same strip held up twice counts once, and
 * a strip from a different set is named rather than counted.
 */

import { shareTextSetCode } from "./keym-v2-shamir";
import { describePaperPart } from "./keym-v2-paper";

export interface CameraProgress {
  strips: { indices: number[]; threshold: number | null; setCode: string | null; otherSet: number };
  parts: { indices: number[]; total: number | null };
  wholeBackup: boolean;
  complete: boolean;
}

function isStrip(text: string): boolean {
  return /^\s*KMSHARE[12]:/i.test(text);
}

/**
 * Where a set of scanned codes stands. Pure, so the rule that decides when the
 * camera stops is testable without one.
 */
export function cameraProgress(codes: readonly string[]): CameraProgress {
  const stripIndices = new Map<string, Set<number>>();
  let threshold: number | null = null;
  let setCode: string | null = null;
  let otherSet = 0;
  const partIndices = new Set<number>();
  let total: number | null = null;
  let wholeBackup = false;

  for (const code of codes) {
    if (isStrip(code)) {
      const info = stripHeader(code);
      if (!info) continue;
      // The first strip fixes the set; a strip from another set is counted
      // apart, so it cannot make up the number.
      setCode ??= info.setCode;
      threshold ??= info.threshold;
      if (info.setCode !== setCode) {
        otherSet++;
        continue;
      }
      const set = stripIndices.get(info.setCode) ?? new Set<number>();
      set.add(info.index);
      stripIndices.set(info.setCode, set);
      continue;
    }
    const part = describePaperPart(code);
    if (part) {
      total ??= part.total;
      if (part.total === total) partIndices.add(part.index);
      continue;
    }
    if (code.trim().startsWith("keym2:")) wholeBackup = true;
  }

  const indices = setCode ? [...(stripIndices.get(setCode) ?? [])].sort((a, b) => a - b) : [];
  const parts = [...partIndices].sort((a, b) => a - b);
  const stripsDone = setCode === null || (threshold !== null && indices.length >= threshold);
  const partsDone = total === null || parts.length === total;
  const anything = setCode !== null || total !== null || wholeBackup;
  return {
    strips: { indices, threshold, setCode, otherSet },
    parts: { indices: parts, total },
    wholeBackup,
    complete: anything && stripsDone && partsDone,
  };
}

/**
 * A strip's index, threshold and set code, read from its text alone. The
 * record's layout is §4.6's: after the set id (16 bytes for KMSHARE2, 4 for
 * KMSHARE1) come the threshold and the index, one byte each. Decoding the base32
 * here rather than calling the full decoder keeps this synchronous; the
 * checksum is verified where the strip is used, in the shares box.
 */
function stripHeader(text: string): { index: number; threshold: number; setCode: string } | null {
  const upper = text.trim().toUpperCase();
  const v2 = upper.startsWith("KMSHARE2:");
  const body = upper
    .slice(9)
    .replace(/[-\s]/g, "")
    .replace(/[IL]/g, "1")
    .replace(/O/g, "0");
  const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  const idLen = v2 ? 16 : 4;
  const need = Math.ceil(((idLen + 2) * 8) / 5);
  if (body.length < need) return null;
  let bits = "";
  for (const ch of body.slice(0, need)) {
    const v = alphabet.indexOf(ch);
    if (v < 0) return null;
    bits += v.toString(2).padStart(5, "0");
  }
  const byteAt = (i: number) => parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  const setCode = v2 ? shareTextSetCode(text) : body.slice(0, 6);
  if (!setCode) return null;
  return { threshold: byteAt(idLen), index: byteAt(idLen + 1), setCode };
}

/** One sentence per started kind, saying what is in and what is still needed. */
export function describeCameraProgress(p: CameraProgress): string[] {
  const lines: string[] = [];
  if (p.strips.setCode !== null && p.strips.threshold !== null) {
    const have = p.strips.indices.length;
    const need = p.strips.threshold;
    lines.push(
      have >= need
        ? `Recovery strips: ${p.strips.indices.join(", ")}. That is ${need}, which is enough.`
        : `Recovery strips: ${p.strips.indices.join(", ")}. ${have} of the ${need} needed. Show the next strip.`
    );
    if (p.strips.otherSet > 0) {
      lines.push(
        `${p.strips.otherSet === 1 ? "One strip" : `${p.strips.otherSet} strips`} from a different set ` +
          `(not ${p.strips.setCode}) ${p.strips.otherSet === 1 ? "was" : "were"} left out.`
      );
    }
  }
  if (p.parts.total !== null) {
    const missing: number[] = [];
    for (let i = 1; i <= p.parts.total; i++) if (!p.parts.indices.includes(i)) missing.push(i);
    lines.push(
      missing.length === 0
        ? `Container symbols: all ${p.parts.total}.`
        : `Container symbols: ${p.parts.indices.length} of ${p.parts.total}. Still needed: ${missing.join(", ")}.`
    );
  }
  if (p.wholeBackup) lines.push("The whole backup, in one code.");
  if (lines.length === 0) lines.push("Hold a recovery strip or a container symbol up to the camera.");
  return lines;
}
