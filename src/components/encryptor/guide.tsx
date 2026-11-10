"use client";

/**
 * Guided mode: the Encrypt form, one step at a time.
 *
 * Nothing here is a second form. The fields, the Encrypt button and the
 * receipt are the ones the single-page view shows; `secret-form.tsx` marks
 * each with `data-guide`, and a stylesheet rule hides the parts that are not
 * the current screen. This file adds what a walk-through needs around them:
 * a heading that says what to do now, and Back and Next.
 *
 * Next follows the same evidence the step list does (`workflowSteps`), so the
 * guide never lets someone past a step the page cannot see is done. The one
 * rule of its own is on the password step: a generated password must have
 * been shown, because the field is masked and the password is cleared once
 * the backup is sealed.
 */
import { useEffect, useRef } from "react";
import { ArrowLeft, ArrowRight, KeyRound, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useEncryptorContext } from "./context";
import { GUIDE_SCREENS, type GuideScreen } from "./use-encryptor-state";

const TITLE: Record<GuideScreen, string> = {
  content: "Choose what to protect",
  access: "Set the password",
  review: "Check it, then encrypt",
  "saved-copy": "Save your backup",
  recovery: "Test that it opens",
};

const HELP: Record<GuideScreen, string> = {
  content: "Pick a file, type a note, or enter a seed phrase. It is encrypted in this tab and is not uploaded.",
  access: "This password opens the backup later. Nobody can recover it for you, so keep it somewhere safe.",
  review: "Read how the backup will open. If it is right, encrypt.",
  "saved-copy": "The backup exists only in this tab until you save it. Download it or print the paper vault now.",
  recovery: "A backup is only useful if it opens. Check the copy you saved before you rely on it.",
};

/** The heading above the current screen's part of the form. */
export function GuideHeading() {
  const { guideScreen } = useEncryptorContext();
  const position = GUIDE_SCREENS.indexOf(guideScreen) + 1;
  // A new screen starts at its heading. The step before may have left the
  // page scrolled down to a button, and the next task would open off screen.
  // Focus moves with it, so a screen reader announces the new step.
  const ref = useRef<HTMLDivElement>(null);
  const first = useRef(true);
  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    ref.current?.scrollIntoView({ block: "center" });
    ref.current?.focus({ preventScroll: true });
  }, [guideScreen]);
  return (
    <div ref={ref} tabIndex={-1} className="km-guide-heading outline-hidden" data-testid="guide-heading">
      <p className="km-guide-count">
        Step {position} of {GUIDE_SCREENS.length}
      </p>
      <h2>{TITLE[guideScreen]}</h2>
      <p>{HELP[guideScreen]}</p>
    </div>
  );
}

/** What the review screen shows above the Encrypt button. */
export function GuideReview() {
  const { inputType, file, textSecret } = useEncryptorContext();
  const what =
    inputType === "file"
      ? file
        ? file.name
        : "No file chosen yet"
      : textSecret
        ? "The text you entered"
        : "Nothing entered yet";
  return (
    <p data-testid="guide-review" className="rounded-xl border border-border px-4 py-3 text-[12.5px] leading-snug text-muted-foreground">
      Protecting: <span className="text-foreground">{what}</span>
    </p>
  );
}

/** The last screen: the two ways to prove the saved copy opens. */
export function GuideRecovery() {
  const { receipt, returnToBackupTest, steps } = useEncryptorContext();
  const recovery = steps.find((st) => st.id === "recovery");
  return (
    <section className="km-form-section space-y-3" data-testid="guide-recovery">
      {recovery && <p className="text-[12.5px] leading-snug text-muted-foreground">{recovery.detail}</p>}
      <div className="flex flex-wrap gap-2">
        <Button variant="outline" onClick={() => returnToBackupTest(false)}>
          <ShieldCheck className="h-4 w-4" />
          Verify with the password
        </Button>
        {receipt?.shares && (
          <Button variant="outline" onClick={() => returnToBackupTest(true)}>
            <KeyRound className="h-4 w-4" />
            Verify with recovery shares
          </Button>
        )}
      </div>
    </section>
  );
}

/** Back and Next, and the reason when Next is not available yet. */
export function GuideNav() {
  const { guideScreen, setGuideScreen, steps, generated, generatedSeen, isLoading } = useEncryptorContext();
  const index = GUIDE_SCREENS.indexOf(guideScreen);
  const state = (id: string) => steps.find((st) => st.id === id)?.state;

  let blocked: string | null = null;
  if (guideScreen === "content" && state("content") !== "done") {
    blocked = "Choose a file or enter something to protect first.";
  } else if (guideScreen === "access" && state("access") !== "done") {
    blocked = "Set a password that meets the policy first.";
  } else if (guideScreen === "access" && generated && !generatedSeen) {
    blocked = "Press Show and write the generated password down first. It cannot be shown again after the backup is sealed.";
  } else if (guideScreen === "saved-copy" && !["started", "done"].includes(state("saved-copy") ?? "")) {
    blocked = "Download the backup or print the paper vault first.";
  }

  // Encrypt is the way forward from the review screen, and the last screen
  // has nowhere further to go.
  const hasNext = guideScreen !== "review" && index < GUIDE_SCREENS.length - 1;

  return (
    <div className="km-guide-nav" data-testid="guide-nav">
      <div className="flex flex-wrap items-center gap-2">
        {index > 0 && (
          <Button
            type="button"
            variant="outline"
            disabled={isLoading}
            onClick={() => setGuideScreen(GUIDE_SCREENS[index - 1]!)}
          >
            <ArrowLeft className="h-4 w-4" />
            Back
          </Button>
        )}
        {hasNext && (
          <Button
            type="button"
            disabled={blocked !== null}
            aria-describedby={blocked ? "guide-blocked" : undefined}
            onClick={() => setGuideScreen(GUIDE_SCREENS[index + 1]!)}
          >
            Next
            <ArrowRight className="h-4 w-4" />
          </Button>
        )}
      </div>
      {hasNext && blocked && (
        <p id="guide-blocked" data-testid="guide-blocked" className="text-[12.5px] leading-snug text-muted-foreground">
          {blocked}
        </p>
      )}
    </div>
  );
}
