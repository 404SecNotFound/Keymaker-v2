"use client";

/**
 * The visible step order for making a backup (roadmap Section 06, part b).
 *
 * Status, not a wizard: BAR.md keeps one form with no Next buttons, so this
 * only says where the backup is. Every state comes from `workflowSteps`, which
 * marks a step done only on evidence the page has. A download or a print is
 * "Started", never "Done", because the browser does not say whether anything
 * was kept. Each state is a word as well as a colour.
 */
import type { Step, StepState } from "@/lib/backup-workflow";

const STATE_WORD: Record<StepState, string> = {
  todo: "To do",
  current: "Next",
  working: "Working",
  done: "Done",
  started: "Started",
  changed: "Changed",
};

/**
 * The steps the sentences under the list describe: the one to act on now, and
 * any step that was started but cannot be confirmed, since that is unfinished
 * too and its sentence says what is still missing.
 */
function describedSteps(steps: Step[]): Step[] {
  let focus: Step | undefined;
  for (const state of ["changed", "working", "current"] as const) {
    focus = steps.find((st) => st.state === state);
    if (focus) break;
  }
  const started = steps.filter((st) => st.state === "started");
  const out = [...(focus ? [focus] : []), ...started].sort((a, b) => steps.indexOf(a) - steps.indexOf(b));
  return out.length > 0 ? out : steps.slice(-1);
}

export function WorkflowSteps({ steps }: { steps: Step[] }) {
  const described = describedSteps(steps);
  return (
    <div role="group" aria-labelledby="workflow-steps-title" data-testid="workflow-steps" className="km-steps">
      <h2 id="workflow-steps-title" className="sr-only">Steps to make a backup</h2>
      <ol>
        {steps.map((st, i) => (
          <li
            key={st.id}
            data-step={st.id}
            data-state={st.state}
            aria-current={st.state === "current" ? "step" : undefined}
          >
            <span className="km-step-number" aria-hidden="true">{i + 1}</span>
            <span className="km-step-label">{st.label}</span>
            <span className="km-step-state">{STATE_WORD[st.state]}</span>
          </li>
        ))}
      </ol>
      {/* No aria-live here. It would re-announce on every keystroke, and
          Radix's modal hiding (the aria-hidden package) keeps every live
          region and its ancestors exposed, so a live region here left
          controls mounted later behind the shares dialog reachable. The
          step to act on is marked with aria-current instead. */}
      <div data-testid="workflow-step-detail" className="km-steps-detail">
        {described.map((st) => (
          <p key={st.id} data-step={st.id}>
            <span className="text-foreground">{st.label}.</span> {st.detail}
          </p>
        ))}
      </div>
    </div>
  );
}
