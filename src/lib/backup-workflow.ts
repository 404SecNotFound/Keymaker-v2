/**
 * Where a new backup is in its life on this page, and what is known about it
 * (roadmap Section 06).
 *
 * Pure, so the rules can be tested without a browser. The page holds one of
 * these, feeds it events, and reads two things back: which phase it is in,
 * and whether the backup on screen still matches the form above it.
 *
 * ## Phases
 *
 * - `editing`: nothing has been written, or what was written has been cleared.
 * - `working`: a job is running. It is identified by the page's operation
 *   number, the same one its stale-job guard uses.
 * - `created`: that job wrote a backup. What it was written with is recorded,
 *   and so is every export started from it.
 *
 * ## Why the job number matters
 *
 * An encrypt that the user has moved on from (by stopping it, switching tab
 * or input type, or starting another) must never put the page back into a
 * success state. The page already checks for that before it writes anything;
 * this checks again. A `sealed` or `job-ended` event is accepted only from the
 * job the workflow is currently waiting on, so a late answer from an old job
 * cannot produce a receipt or end a newer job's wait.
 *
 * ## Exports are "started", not "saved"
 *
 * A page can ask the browser to download a file or open the print dialog. It
 * cannot see whether the file was kept or the sheet printed. So an export
 * records only that it was started, and when, and the page says so.
 */
import type { WayIn } from "./access-policy";

/** What a backup was written with, as far as the form describes it. */
export interface CreationSettings {
  inputType: "file" | "text";
  /** The receipt's KDF label, e.g. "Argon2id · 64 MiB · t=3 · p=4". */
  kdf: string;
  /** The receipt's cipher label. */
  cipher: string;
  /** KEYM v4 padding ("hide the size"). */
  padded: boolean;
  /** The ways in the access policy describes. */
  waysIn: WayIn[];
}

/** A part of the form that no longer matches the backup it wrote. */
export type SettingsChange = "access rule" | "key derivation" | "cipher" | "size hiding" | "input type";

/**
 * Which parts of the form differ from what the backup was written with.
 * Empty when the form still describes it.
 */
export function settingsChanges(sealed: CreationSettings, now: CreationSettings): SettingsChange[] {
  const changes: SettingsChange[] = [];
  if (sealed.inputType !== now.inputType) changes.push("input type");
  if (JSON.stringify(sealed.waysIn) !== JSON.stringify(now.waysIn)) changes.push("access rule");
  if (sealed.kdf !== now.kdf) changes.push("key derivation");
  if (sealed.cipher !== now.cipher) changes.push("cipher");
  if (sealed.padded !== now.padded) changes.push("size hiding");
  return changes;
}

export interface ExportStarted {
  how: "download" | "print";
  /** ISO 8601, when the page asked the browser. */
  at: string;
}

export type Workflow =
  | { phase: "editing" }
  | { phase: "working"; job: number }
  | { phase: "created"; job: number; sealed: CreationSettings; exports: ExportStarted[] };

export type WorkflowEvent =
  | { type: "job-started"; job: number }
  | { type: "sealed"; job: number; settings: CreationSettings }
  /** The job failed or was stopped. Ignored unless it is the job being waited on. */
  | { type: "job-ended"; job: number }
  | { type: "export-started"; how: ExportStarted["how"]; at: string }
  /** The page cleared the backup: a wipe, a lock, a mode or input switch. */
  | { type: "cleared" };

export const initialWorkflow: Workflow = { phase: "editing" };

export function workflowReducer(state: Workflow, event: WorkflowEvent): Workflow {
  switch (event.type) {
    case "job-started":
      // A new job replaces whatever was on screen: the page clears the old
      // output when it starts, so evidence about it cannot stay.
      return { phase: "working", job: event.job };
    case "sealed":
      if (state.phase !== "working" || state.job !== event.job) return state;
      return { phase: "created", job: event.job, sealed: event.settings, exports: [] };
    case "job-ended":
      if (state.phase !== "working" || state.job !== event.job) return state;
      return initialWorkflow;
    case "export-started":
      if (state.phase !== "created") return state;
      return { ...state, exports: [...state.exports, { how: event.how, at: event.at }] };
    case "cleared":
      return initialWorkflow;
  }
}

/** The most recent export of each kind, for the page to describe. */
export function latestExports(state: Workflow): Partial<Record<ExportStarted["how"], string>> {
  if (state.phase !== "created") return {};
  const out: Partial<Record<ExportStarted["how"], string>> = {};
  for (const e of state.exports) out[e.how] = e.at;
  return out;
}

/**
 * The access rule as one sentence, for display before creation.
 *
 * Built from the same `describeWayIn` wording the receipt uses, joined with
 * "or" because each way in opens the backup on its own. A §4.8 way in already
 * says "both needed" inside its own wording.
 */
export function describeAccessRule(waysIn: string[]): string {
  if (waysIn.length === 0) return "";
  if (waysIn.length === 1) return waysIn[0]!;
  return `${waysIn.slice(0, -1).join(", ")} or ${waysIn[waysIn.length - 1]}`;
}
