"use client";

/**
 * Dice Entropy Calculator — ported from the Morpheus project (entropy.py).
 *
 * Answers one question: "how many physical dice rolls do I need for N bits
 * of entropy?" Bits per roll = log2(sides); total = rolls × bits per roll.
 * The 128-bit value is treated as a floor and 256-bit as the target, matching
 * the Morpheus framing.
 *
 * This tool computes bits — it does NOT generate seeds. Roll real dice, on
 * an air-gapped device, and record the results yourself.
 */

import { useMemo, useState } from "react";
import { Dices, Info, AlertTriangle, CheckCircle2, ShieldAlert } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";

const FLOOR_BITS = 128;
const TARGET_BITS = 256;

// Bounds on the die itself. HTML min/max attributes are a UI affordance, not
// validation — the value still has to be checked here.
const MIN_SIDES = 2;
const MAX_SIDES = 1000;

type Verdict = "below" | "floor" | "target";

export function DiceEntropyTool() {
  const [sides, setSides] = useState(6);
  const [targetBits, setTargetBits] = useState<number>(TARGET_BITS);
  const [rollLog, setRollLog] = useState("");
  const [manualRolls, setManualRolls] = useState("");

  const calc = useMemo(() => {
    const validSides =
      Number.isInteger(sides) && sides >= MIN_SIDES && sides <= MAX_SIDES ? sides : 6;
    const bitsPerRoll = Math.log2(validSides);

    // Count rolls from the log (whitespace/comma/semicolon separated).
    //
    // Every entry must be a physically possible outcome for this die. An
    // earlier version incremented the count for any token it could not parse,
    // so "hello", "0", a 9 on a d6, or a 25 on a d20 each contributed a full
    // roll's worth of entropy to the total. For a tool whose entire output is
    // an entropy estimate, silently counting impossible observations is the
    // one bug that matters most: it inflates the number the user is trusting.
    const tokens = rollLog.split(/[\s,;]+/).filter(Boolean);
    let rolls = 0;
    const invalidEntries: string[] = [];

    for (const token of tokens) {
      // Run-together digits like "46231" mean five rolls — but only for dice
      // whose faces are all single digits, otherwise "12" is ambiguous.
      if (validSides <= 9 && /^\d+$/.test(token) && token.length > 1) {
        const digits = token.split("").map(Number);
        if (digits.every((d) => d >= 1 && d <= validSides)) {
          rolls += digits.length;
        } else {
          invalidEntries.push(token);
        }
        continue;
      }

      // Otherwise the token must be a single face value within range.
      if (/^\d+$/.test(token)) {
        const value = Number(token);
        if (value >= 1 && value <= validSides) {
          rolls += 1;
          continue;
        }
      }
      invalidEntries.push(token);
    }

    // The manual count is a fallback for people who tallied on paper. It only
    // applies when no rolls were logged, and must itself be a positive integer.
    const manual = Number(manualRolls.trim());
    if (rolls === 0 && invalidEntries.length === 0 && Number.isInteger(manual) && manual > 0) {
      rolls = manual;
    }

    const totalBits = rolls * bitsPerRoll;
    const rollsFor128 = Math.ceil(FLOOR_BITS / bitsPerRoll);
    const rollsFor256 = Math.ceil(TARGET_BITS / bitsPerRoll);
    const rollsNeeded = Math.ceil(targetBits / bitsPerRoll);
    const progress = Math.min(1, totalBits / targetBits);

    const verdict: Verdict =
      totalBits >= TARGET_BITS ? "target" : totalBits >= FLOOR_BITS ? "floor" : "below";

    return {
      validSides,
      bitsPerRoll,
      rolls,
      totalBits,
      rollsFor128,
      rollsFor256,
      rollsNeeded,
      progress,
      verdict,
      invalidEntries,
    };
  }, [sides, targetBits, rollLog, manualRolls]);

  const verdictUI = {
    below: {
      icon: ShieldAlert,
      classes: "border-destructive/40 bg-destructive/10 text-destructive",
      title: "Below the 128-bit floor",
      body: `Keep rolling — ${calc.rollsNeeded - calc.rolls} more ${calc.validSides}-sided rolls to reach your ${targetBits}-bit target.`,
    },
    floor: {
      icon: CheckCircle2,
      classes: "border-yellow-500/40 bg-yellow-500/10 text-yellow-400",
      title: "128-bit floor cleared",
      body:
        targetBits === TARGET_BITS
          ? `You have a secure minimum. ${calc.rollsNeeded - calc.rolls} more rolls to reach the 256-bit target.`
          : "You have reached your selected target.",
    },
    target: {
      icon: CheckCircle2,
      classes: "border-success/40 bg-success/10 text-success",
      title: "256-bit target reached",
      body: "Full target entropy achieved. More rolls add margin but are not required.",
    },
  }[calc.verdict];

  const VerdictIcon = verdictUI.icon;

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-2.5">
        <div className="grid h-9 w-9 place-items-center rounded-lg bg-accent/10 text-accent">
          <Dices className="h-4.5 w-4.5" />
        </div>
        <div>
          <h2 className="text-[15px] font-semibold">Dice Entropy Calculator</h2>
          <p className="text-[12px] text-muted-foreground">
            How many physical dice rolls for 128 / 256 bits of entropy?
          </p>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1.5">
          <Label htmlFor="dice-sides" className="text-[13px] font-medium text-muted-foreground">
            Dice sides
          </Label>
          <Input
            id="dice-sides"
            type="number"
            min={2}
            max={1000}
            value={sides}
            onChange={(e) => setSides(Number(e.target.value))}
            className="h-11 rounded-xl border-white/10 bg-white/4 text-[15px] focus-visible:border-accent/50 focus-visible:ring-0"
          />
        </div>
        <div className="space-y-1.5">
          <Label className="text-[13px] font-medium text-muted-foreground">Target</Label>
          <div className="flex gap-0.5 rounded-xl bg-white/4 p-1">
            {[FLOOR_BITS, TARGET_BITS].map((bits) => (
              <button
                key={bits}
                type="button"
                onClick={() => setTargetBits(bits)}
                className={cn(
                  "flex-1 cursor-pointer rounded-lg px-2 py-2 text-center text-[12px] font-medium transition-all",
                  targetBits === bits
                    ? "bg-white/10 text-foreground shadow-xs"
                    : "text-muted-foreground hover:text-foreground"
                )}
              >
                {bits}-bit{bits === FLOOR_BITS ? " floor" : " target"}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="space-y-1.5">
        <Label htmlFor="roll-log" className="text-[13px] font-medium text-muted-foreground">
          Roll log <span className="font-normal">(type your rolls — entries are counted automatically)</span>
        </Label>
        <Textarea
          id="roll-log"
          value={rollLog}
          onChange={(e) => setRollLog(e.target.value)}
          placeholder={`e.g. 4 6 2 3 1 … or run together: 46231`}
          rows={3}
          className="rounded-xl border-white/10 bg-white/4 focus-visible:border-accent/50 focus-visible:ring-0"
        />
      </div>

      <div className="space-y-1.5">
        <Label htmlFor="manual-rolls" className="text-[13px] font-medium text-muted-foreground">
          …or enter rolls so far manually
        </Label>
        <Input
          id="manual-rolls"
          type="number"
          min={0}
          value={manualRolls}
          onChange={(e) => setManualRolls(e.target.value)}
          placeholder="0"
          disabled={rollLog.trim().length > 0}
          className="h-11 rounded-xl border-white/10 bg-white/4 text-[15px] focus-visible:border-accent/50 focus-visible:ring-0 disabled:opacity-40"
        />
      </div>

      {/* Results */}
      <div className="space-y-3 rounded-xl border border-white/8 bg-white/2 p-4">
        <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-[13px] sm:grid-cols-4">
          <div>
            <p className="text-[11px] uppercase tracking-wide text-muted-foreground">Bits / roll</p>
            <p className="font-semibold tabular-nums">{calc.bitsPerRoll.toFixed(2)}</p>
          </div>
          <div>
            <p className="text-[11px] uppercase tracking-wide text-muted-foreground">Rolls counted</p>
            <p className="font-semibold tabular-nums">{calc.rolls}</p>
          </div>
          <div>
            <p className="text-[11px] uppercase tracking-wide text-muted-foreground">Total entropy</p>
            <p className="font-semibold tabular-nums">{calc.totalBits.toFixed(1)} bits</p>
          </div>
          <div>
            <p className="text-[11px] uppercase tracking-wide text-muted-foreground">Rolls needed</p>
            <p className="font-semibold tabular-nums">
              {calc.rollsFor128} <span className="text-muted-foreground">/128</span>
              {" · "}
              {calc.rollsFor256} <span className="text-muted-foreground">/256</span>
            </p>
          </div>
        </div>

        {calc.invalidEntries.length > 0 && (
          <div
            role="alert"
            className="animate-in fade-in-50 rounded-lg border border-destructive/40 bg-destructive/10 p-3 text-[12px] text-destructive"
          >
            <p className="font-semibold">
              {calc.invalidEntries.length} entr{calc.invalidEntries.length === 1 ? "y" : "ies"} ignored —
              not a possible result for a {calc.validSides}-sided die
            </p>
            <p className="mt-1 break-all font-mono text-[11px] opacity-80">
              {calc.invalidEntries.slice(0, 12).join("  ")}
              {calc.invalidEntries.length > 12 && ` … +${calc.invalidEntries.length - 12} more`}
            </p>
            <p className="mt-1.5 opacity-80">
              These contribute no entropy. Correct or remove them so the total reflects
              only real rolls.
            </p>
          </div>
        )}

        <div>
          <div className="mb-1 flex justify-between text-[11px] text-muted-foreground">
            <span>0</span>
            <span>{targetBits}-bit target</span>
          </div>
          <div className="h-2.5 w-full overflow-hidden rounded-full bg-white/8">
            <div
              className={cn(
                "h-full rounded-full transition-all duration-300",
                calc.verdict === "target"
                  ? "bg-success"
                  : calc.verdict === "floor"
                    ? "bg-yellow-500"
                    : "bg-accent"
              )}
              style={{ width: `${(calc.progress * 100).toFixed(1)}%` }}
            />
          </div>
          <div className="mt-1 flex justify-between text-[11px] text-muted-foreground">
            <span className={cn(calc.totalBits >= FLOOR_BITS && "text-yellow-400")}>128-bit floor @ {calc.rollsFor128} rolls</span>
            <span>{calc.progress >= 1 ? "100%" : `${Math.floor(calc.progress * 100)}%`}</span>
          </div>
        </div>

        <div className={cn("flex items-start gap-2.5 rounded-lg border px-3 py-2.5", verdictUI.classes)}>
          <VerdictIcon className="mt-0.5 h-4 w-4 shrink-0" />
          <div>
            <p className="text-[13px] font-semibold">{verdictUI.title}</p>
            <p className="mt-0.5 text-[12px] opacity-90">{verdictUI.body}</p>
          </div>
        </div>
      </div>

      {/* Educational context (from Morpheus) */}
      <div className="space-y-2.5 rounded-xl border border-white/6 bg-white/2 p-4 text-[12px] leading-relaxed text-muted-foreground">
        <p className="flex items-start gap-2">
          <Info className="mt-0.5 h-3.5 w-3.5 shrink-0 text-accent" />
          <span>
            <span className="font-medium text-foreground">Why physical dice?</span> Hardware and
            software random-number generators have failed in the real world — the COLDCARD hardware
            wallet lesson showed that a vendor RNG can be subtly broken or compromised. Physical dice
            survive vendor RNG failures: their entropy comes from physics you can watch, not from a
            chip you must trust.
          </span>
        </p>
        <p className="flex items-start gap-2">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-yellow-400" />
          <span>
            Rolls only count if they are <span className="font-medium text-foreground">fair</span> (no
            loaded dice), <span className="font-medium text-foreground">independent</span> (shake well,
            one roll at a time or well-mixed), <span className="font-medium text-foreground">ordered</span> (record
            them in the exact order rolled), and <span className="font-medium text-foreground">private</span> (no
            cameras, no observers).
          </span>
        </p>
        <p className="flex items-start gap-2">
          <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-destructive" />
          <span>
            This calculator computes bits of entropy — it does{" "}
            <span className="font-medium text-foreground">not</span> generate seeds or keys. Perform
            actual seed generation with your recorded rolls on an air-gapped device using dedicated,
            audited software.
          </span>
        </p>
      </div>
    </div>
  );
}
