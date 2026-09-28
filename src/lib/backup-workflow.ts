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

// ---------------------------------------------------------------------------
// The visible step order (Section 06, part b)
// ---------------------------------------------------------------------------

/**
 * How much of the backup's paper copy has been photographed back and matched
 * to it on the Recovery page. `checked` counts distinct container symbols; a
 * backup that fits one symbol has a total of 1.
 */
export interface PrintoutCoverage {
  checked: number[];
  total: number;
}

/** The part of a printout finding this needs: container symbols only. */
export type CoverageFinding =
  | { kind: "part"; index: number; total: number; belongs: "yes" | "no" | "unknown" }
  | { kind: "backup"; belongs: "yes" | "no" | "unknown" }
  | { kind: string };

/**
 * Add one check's findings to what earlier checks of the same backup found.
 *
 * Only container symbols that read back intact *and* were matched to this
 * backup count. Recovery strips are not the saved copy, a symbol from another
 * backup proves nothing about this one, and "unknown" is not a match. Symbols
 * can be photographed one at a time, so checks accumulate; the page resets
 * the coverage whenever the backup it describes goes.
 */
export function mergePrintoutCoverage(
  prev: PrintoutCoverage | null,
  findings: readonly CoverageFinding[]
): PrintoutCoverage | null {
  let out = prev;
  for (const f of findings) {
    if (f.kind === "backup" && "belongs" in f && f.belongs === "yes") {
      out = { checked: [1], total: 1 };
    } else if (f.kind === "part" && "belongs" in f && f.belongs === "yes" && "index" in f && "total" in f) {
      // A different total is a different sheet layout; start again from it.
      const base = out && out.total === f.total ? out.checked : [];
      const checked = base.includes(f.index) ? base : [...base, f.index].sort((a, b) => a - b);
      out = { checked, total: f.total };
    }
  }
  return out;
}

export type StepId = "content" | "access" | "review" | "create" | "saved-copy" | "recovery";

/**
 * - `todo`: not reached yet.
 * - `current`: the one step to act on now. At most one step is current.
 * - `working`: the encrypt is running.
 * - `done`: finished, on evidence the page has.
 * - `started`: the page asked the browser for something it cannot confirm
 *   (a download, a print). Not done, and never shown as done.
 * - `changed`: the backup was made, and the form has moved on since.
 */
export type StepState = "todo" | "current" | "working" | "done" | "started" | "changed";

export interface Step {
  id: StepId;
  label: string;
  state: StepState;
  /** One plain sentence: what this step is waiting on, or what is known. */
  detail: string;
}

/** What the page knows, read from its own state. Nothing here is a secret. */
export interface StepInputs {
  workflow: Workflow;
  /** Content is present and complete enough to encrypt. */
  hasContent: boolean;
  /** A password is set and meets the policy. */
  credentialReady: boolean;
  /** What changed since the backup was made, or null. */
  changed: string[] | null;
  /**
   * Whether the backup is still on screen (text mode), or was downloaded when
   * it was written and not kept (file mode). Null before a backup exists.
   */
  keptOnScreen: boolean | null;
  exports: Partial<Record<ExportStarted["how"], string>>;
  printout: PrintoutCoverage | null;
  /** The backup has recovery shares, so it can be rehearsed from them here. */
  hasShares: boolean;
  /** A rehearsal from the shares opened this backup. */
  rehearsed: boolean;
}

export const STEP_LABELS: Record<StepId, string> = {
  content: "Content",
  access: "Access rule",
  review: "Review",
  create: "Create",
  "saved-copy": "Check saved copy",
  recovery: "Prepare recovery",
};

/**
 * The six steps of making a backup, each in the state the page's evidence
 * supports.
 *
 * Status, not a wizard: every control stays where it is, and nothing here
 * gates anything. It never claims more than the page knows. A download or a
 * print is "started", because the browser does not say whether the file was
 * kept. A saved copy is "done" only when every container symbol of the
 * printout has been photographed back and matched to this backup. Recovery
 * is "done" only when a rehearsal opened it.
 */
export function workflowSteps(i: StepInputs): Step[] {
  const s = (id: StepId, state: StepState, detail: string): Step => ({
    id,
    label: STEP_LABELS[id],
    state,
    detail,
  });

  if (i.workflow.phase !== "created") {
    const working = i.workflow.phase === "working";
    const steps = [
      s("content", working || i.hasContent ? "done" : "todo", "Choose a file or enter the text to protect."),
      s(
        "access",
        working || i.credentialReady ? "done" : "todo",
        "Set a password that meets the policy, and any shares or passkey."
      ),
      s("review", working ? "done" : "todo", "Read the rule above Encrypt, then encrypt."),
      s("create", working ? "working" : "todo", working ? "Encrypting." : "Nothing has been written yet."),
      s("saved-copy", "todo", "Save a copy once the backup exists."),
      s("recovery", "todo", "Test a way back in once a copy is saved."),
    ];
    return markCurrent(steps);
  }

  const done = (id: StepId, detail: string) => s(id, "done", detail);
  const steps: Step[] = [
    done("content", "In the backup."),
    done("access", "In the backup."),
    done("review", "Done before it was written."),
    i.changed
      ? s(
          "create",
          "changed",
          `Changed since this backup was made: ${i.changed.join(", ")}. Encrypt again to include it.`
        )
      : done("create", "Written on this device. Nothing left it."),
  ];

  const p = i.printout;
  if (p && p.checked.length >= p.total) {
    steps.push(done("saved-copy", "Every printed container symbol was read back and matches this backup."));
  } else {
    const said: string[] = [];
    if (i.keptOnScreen === false) said.push("Downloaded when it was written");
    if (i.exports.download) said.push("Download started");
    if (i.exports.print) said.push("Paper vault sent to print");
    if (p) said.push(`${p.checked.length} of ${p.total} printed symbols matched`);
    steps.push(
      said.length > 0
        ? s(
            "saved-copy",
            "started",
            `${said.join(". ")}. The page cannot see whether a copy was kept; photograph the printout on the Recovery tab to check it.`
          )
        : s("saved-copy", "todo", "Download it or print the paper vault, then check the copy.")
    );
  }

  if (i.rehearsed) {
    steps.push(done("recovery", "A rehearsal from the recovery shares opened this backup."));
  } else if (i.hasShares && i.keptOnScreen) {
    steps.push(s("recovery", "todo", "Rehearse recovery from the shares, the way an heir would."));
  } else {
    steps.push(
      s(
        "recovery",
        "todo",
        i.hasShares
          ? "Rehearse from the shares by loading the saved file on the Decrypt tab."
          : "Test the password against the saved copy, on the Decrypt tab with verify only."
      )
    );
  }
  return markCurrent(steps);
}

/** The first step still to do becomes the current one. */
function markCurrent(steps: Step[]): Step[] {
  const first = steps.findIndex((st) => st.state === "todo");
  if (first < 0) return steps;
  // Nothing is current while the encrypt runs or the backup no longer
  // matches the form: the step to act on is the one already flagged.
  if (steps.some((st) => st.state === "working" || st.state === "changed")) return steps;
  return steps.map((st, idx) => (idx === first ? { ...st, state: "current" } : st));
}
