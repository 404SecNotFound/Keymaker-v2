/**
 * "Check this printout": does a printed strip or symbol read back, and does it
 * belong to this backup?
 *
 * A paper backup that has never been scanned is a hope, and the rehearsal that
 * proves it opens needs the password or enough strips. This is the smaller,
 * safer step before that: photograph what came out of the printer and learn,
 * for each code, whether it decodes intact and whether it is from the backup on
 * screen. Nothing here joins, combines or decrypts anything. A strip's value is
 * never used, and no key is derived, so a check can be run with nothing but
 * the paper and the container this session wrote.
 *
 * What "belongs" means, per kind, and what each can and cannot say:
 *
 * - **A strip** (`KMSHARE2`/`KMSHARE1`) belongs when its set id equals the set
 *   id of a share slot in the container, all sixteen bytes for `KMSHARE2` and
 *   the four a `KMSHARE1` carries (FORMAT-V2-DESIGN §6). That needs only the
 *   header and slot table, which the workbench keeps even for a container it
 *   wrote straight to a file.
 * - **A paper part** (`KMPART2`) belongs when its `cid` and `length` equal the
 *   container's fingerprint and length (§7.3). That needs the whole container,
 *   so it is only answered when the container is on screen.
 * - **A `KMPART1` part** carries no fingerprint, so which backup it is from is
 *   not knowable from the part, and the check says so rather than guessing.
 * - **A whole backup in one code** (`keym2:` armor) belongs when its bytes are
 *   the container's.
 *
 * With no backup to compare against, each code is still reported as reading
 * or not, which is the half of the question paper can answer by itself.
 */

import { dearmorKeym2, shamirSlotSaltsKeym2 } from "./keym-v2";
import {
  decodeShareAny,
  shareSetIdV2,
  shareTextSetCode,
  SHARE2_PREFIX,
  SHARE_PREFIX,
} from "./keym-v2-shamir";
import {
  containerFingerprint,
  describePaperPart,
  inspectPaperPartV2,
  KEYM2_PART2_PREFIX,
  KEYM2_PART_PREFIX,
} from "./keym-v2-paper";
import { asciiUpper, stripIgnorable } from "./keym-text";

/** Whether a code is from the backup being checked, or cannot be told. */
export type Belongs = "yes" | "no" | "unknown";

export type PrintoutFinding =
  | { kind: "strip"; index: number; threshold: number; setCode: string | null; belongs: Belongs }
  | { kind: "strip-damaged" }
  | { kind: "part"; index: number; total: number; belongs: Belongs }
  | { kind: "part-damaged"; index: number; total: number }
  | { kind: "part-v1"; index: number; total: number }
  | { kind: "backup"; belongs: Belongs }
  | { kind: "other" };

/**
 * The backup a printout is checked against. `container` is the whole thing,
 * when it is on screen; `header` is at least its header and slot table. Either,
 * both or neither may be known.
 */
export interface PrintoutBackup {
  container: Uint8Array | null;
  header: Uint8Array | null;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}

/** The set ids of every share slot the backup carries, or null if unknown. */
async function backupSetIds(backup: PrintoutBackup): Promise<Uint8Array[] | null> {
  const source = backup.container ?? backup.header;
  if (!source) return null;
  try {
    return await Promise.all(shamirSlotSaltsKeym2(source).map((salt) => shareSetIdV2(salt)));
  } catch {
    return null;
  }
}

/**
 * Check one decoded QR string against the backup. Never throws: a string that
 * is not a Keymaker code is a finding (`other`), not an error.
 */
export async function checkPrintoutCode(
  text: string,
  backup: PrintoutBackup
): Promise<PrintoutFinding> {
  const folded = asciiUpper(stripIgnorable(text));

  if (folded.startsWith(SHARE2_PREFIX) || folded.startsWith(SHARE_PREFIX)) {
    let share;
    try {
      share = await decodeShareAny(text);
    } catch {
      return { kind: "strip-damaged" };
    }
    const ids = await backupSetIds(backup);
    const belongs: Belongs =
      ids === null
        ? "unknown"
        : ids.some((id) => bytesEqual(id.subarray(0, share.setId.length), share.setId))
          ? "yes"
          : "no";
    return {
      kind: "strip",
      index: share.index,
      threshold: share.threshold,
      setCode: shareTextSetCode(text),
      belongs,
    };
  }

  const trimmed = stripIgnorable(text);
  if (trimmed.startsWith(KEYM2_PART2_PREFIX)) {
    const part = await inspectPaperPartV2(trimmed);
    if (part === null) return { kind: "other" };
    if (!part.checksumOk) return { kind: "part-damaged", index: part.index, total: part.total };
    let belongs: Belongs = "unknown";
    if (backup.container) {
      belongs =
        part.length === backup.container.length &&
        part.cid === (await containerFingerprint(backup.container))
          ? "yes"
          : "no";
    }
    return { kind: "part", index: part.index, total: part.total, belongs };
  }

  if (trimmed.startsWith(KEYM2_PART_PREFIX)) {
    const part = describePaperPart(trimmed);
    return part ? { kind: "part-v1", index: part.index, total: part.total } : { kind: "other" };
  }

  if (trimmed.startsWith("keym2:")) {
    let bytes: Uint8Array;
    try {
      bytes = dearmorKeym2(trimmed);
    } catch {
      return { kind: "other" };
    }
    return {
      kind: "backup",
      belongs: backup.container ? (bytesEqual(bytes, backup.container) ? "yes" : "no") : "unknown",
    };
  }

  return { kind: "other" };
}

/** One plain sentence per finding, for the list the Recovery page shows. */
export function describePrintoutFinding(f: PrintoutFinding): string {
  const verdict = (b: Belongs, what: string): string =>
    b === "yes"
      ? `reads correctly and belongs to this backup.`
      : b === "no"
        ? `reads correctly, but it is from a different backup. Keep it with the ${what} it belongs to.`
        : `reads correctly. There is no backup on screen to compare it with.`;
  switch (f.kind) {
    case "strip":
      return (
        `Recovery strip ${f.index}${f.setCode ? `, set ${f.setCode}` : ""}, any ${f.threshold} open it: ` +
        verdict(f.belongs, "backup")
      );
    case "strip-damaged":
      return "A recovery strip, but its code does not check out. Scan it again, and reprint it if it still fails.";
    case "part":
      return `Container symbol ${f.index} of ${f.total}: ` + verdict(f.belongs, "sheet");
    case "part-damaged":
      return (
        `Container symbol ${f.index} of ${f.total}: its checksum does not match, so it did not ` +
        "read back intact. Scan it again, and reprint the sheet if it still fails."
      );
    case "part-v1":
      return (
        `Container symbol ${f.index} of ${f.total} (an older KMPART1 part): it reads, but this ` +
        "kind of part carries no fingerprint, so which backup it is from cannot be checked."
      );
    case "backup":
      return "The whole backup in one code: " + verdict(f.belongs, "file");
    case "other":
      return "A QR code, but not a Keymaker strip or container symbol.";
  }
}

/** True when a finding is a problem the person should act on. */
export function printoutFindingIsProblem(f: PrintoutFinding): boolean {
  switch (f.kind) {
    case "strip":
    case "part":
    case "backup":
      return f.belongs === "no";
    case "part-v1":
      return false;
    default:
      return true;
  }
}
