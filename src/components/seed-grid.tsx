"use client";

/**
 * The seed grid — Seed Phrase mode's editor for the text input.
 *
 * A recovery phrase typed into a textarea is checked afterwards, as a whole,
 * and the verdict is one line: a word is not on the list. Which word, and
 * what it was probably meant to be, the textarea cannot say. This grid gives
 * each word its own cell, so the check runs per word as it is typed and the
 * report can name a position — "Word 7 is not on the list — did you mean
 * absorb?" — always in words, never only in a colour. The border tint is
 * kept, as the second channel.
 *
 * What it does not do is decide. Repeated words are legal in a phrase and are
 * not flagged. A checksum that does not match is reported in a sentence and
 * left to the person who typed it: a phrase from a wallet that never followed
 * the standard is theirs to seal. The one thing the encrypt button waits for
 * is every cell holding a word the list knows — an unknown word can be part
 * of no BIP-39 phrase, so sealing one in *Seed Phrase* mode is always a
 * transcription error, and the plain text input is one click away for
 * anything that is not a phrase.
 *
 * Hand-rolled on the pattern the command bar set: each cell is a combobox
 * driving a listbox through aria-activedescendant, the arrow keys move the
 * highlight, and the input keeps focus for the whole interaction. The
 * completion rule is deliberately unadventurous: Enter takes the highlighted
 * word, Space and Tab take it only when it is the sole candidate or the user
 * moved the highlight themselves, and nothing is ever completed from a prefix
 * that could be several words. Four letters identify every word on the list,
 * so the honest case is also the common one.
 *
 * The wordlist arrives lazily — it is 13 KB the landing page does not need —
 * and the grid takes input before it lands, saying so in the status line.
 *
 * Secrecy: the cells are blurred like the textarea is, except the one being
 * typed into, so at most one word is ever readable — the one under the user's
 * own fingers — and the reveal toggle lifts all of them at once. Nothing here
 * is stored, copied or sent. The parent owns the words and wipes them with
 * everything else.
 */

import {
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type ClipboardEvent,
  type KeyboardEvent,
} from "react";
import { Eye, EyeOff, ShieldCheck, TriangleAlert } from "lucide-react";
import { cn } from "@/lib/utils";

type Bip39Module = typeof import("@/lib/bip39");

/**
 * The lengths BIP-39 allows. Written here as well as in bip39.ts on purpose:
 * importing a value from that module would pull the wordlist into the initial
 * bundle, and the length pills have to render before the list arrives.
 */
export const SEED_WORD_COUNTS = [12, 15, 18, 21, 24] as const;
export type SeedWordCount = (typeof SEED_WORD_COUNTS)[number];

export function emptySeedWords(count: SeedWordCount = 12): string[] {
  return Array.from({ length: count }, () => "");
}

/** A word array at a valid length, keeping whatever fits. */
export function resizeSeedWords(words: readonly string[], count: SeedWordCount): string[] {
  return Array.from({ length: count }, (_, i) => words[i] ?? "");
}

/** The smallest valid length that holds `n` words; 24 when nothing does. */
export function seedCountFor(n: number): SeedWordCount {
  return SEED_WORD_COUNTS.find((c) => c >= n) ?? 24;
}

/** NFKD, lowercase, letters only. The list is a–z; everything else is noise. */
export function cleanSeedWord(raw: string): string {
  return raw.normalize("NFKD").toLowerCase().replace(/[^a-z]/g, "");
}

/**
 * Free text as grid words: split on whitespace, cleaned, sized to a valid
 * length. Numbering ("1." / "7)") falls away with the other non-letters, so a
 * phrase copied from a numbered list lands in the right cells.
 */
export function seedWordsFromText(text: string): string[] {
  const parts = text.split(/\s+/).map(cleanSeedWord).filter(Boolean).slice(0, 24);
  return resizeSeedWords(parts, seedCountFor(Math.max(parts.length, 12)));
}

type Tone = "muted" | "danger" | "success";

/** "a", "a or b", "a, b or c". */
const listOf = (items: readonly string[]) =>
  items.length <= 1
    ? (items[0] ?? "")
    : `${items.slice(0, -1).join(", ")} or ${items[items.length - 1]}`;

export interface SeedGridProps {
  /** One entry per cell. The length is the phrase length, always one of SEED_WORD_COUNTS. */
  words: string[];
  onChange: (words: string[]) => void;
  /** Whether every cell is readable. Off, only the focused one is. */
  revealed: boolean;
  onRevealedChange: (revealed: boolean) => void;
  /** The lazily loaded wordlist; null until it lands, during which the cells take input and the status says so. */
  bip39: Bip39Module | null;
}

export function SeedGrid({ words, onChange, revealed, onRevealedChange, bip39 }: SeedGridProps) {
  const uid = useId();
  const labelId = `${uid}-label`;
  const statusId = `${uid}-status`;
  const count = words.length as SeedWordCount;

  const inputs = useRef<(HTMLInputElement | null)[]>([]);
  /** A cell to focus once the next render has created it — after a paste grows the grid. */
  const pendingFocus = useRef<number | null>(null);
  useEffect(() => {
    if (pendingFocus.current === null) return;
    inputs.current[pendingFocus.current]?.focus();
    pendingFocus.current = null;
  });

  const [focused, setFocused] = useState<number | null>(null);
  const [active, setActive] = useState(0);
  /** True once the arrow keys have moved the highlight — an explicit choice, honoured by Space and Tab. */
  const [navigated, setNavigated] = useState(false);
  /** Escape closes the list until the word changes. */
  const [dismissed, setDismissed] = useState(false);
  const [checksum, setChecksum] = useState<{ phrase: string; valid: boolean } | null>(null);

  const focusedWord = focused === null ? "" : (words[focused] ?? "");
  useEffect(() => {
    setActive(0);
    setNavigated(false);
    setDismissed(false);
  }, [focused, focusedWord]);

  const completions = useMemo(() => {
    if (focused === null || !bip39 || focusedWord.length < 2) return [];
    return bip39.bip39Completions(focusedWord, 8);
  }, [focused, focusedWord, bip39]);
  const listOpen =
    focused !== null &&
    !dismissed &&
    completions.length > 0 &&
    !(completions.length === 1 && completions[0] === focusedWord);
  const activeIndex = Math.min(active, Math.max(completions.length - 1, 0));
  const listId = `${uid}-list`;
  const optionId = (k: number) => `${uid}-option-${k}`;

  /**
   * What each cell is, from the grid's point of view. A word that is not on
   * the list is "partial" while it is being typed and "flagged" once it is
   * left — the difference between a word half-written and a word wrong.
   */
  const cells = useMemo(
    () =>
      words.map((w, i): "empty" | "unchecked" | "ok" | "partial" | "flagged" => {
        if (!w) return "empty";
        if (!bip39) return "unchecked";
        if (bip39.isBip39Word(w)) return "ok";
        return i === focused ? "partial" : "flagged";
      }),
    [words, bip39, focused]
  );
  const flagged = cells.flatMap((s, i) => (s === "flagged" ? [i] : []));
  const entered = cells.filter((s) => s === "ok").length;
  const phrase = bip39 && entered === count ? words.join(" ") : null;

  // The checksum needs SHA-256, which is async; the result is cached against
  // the phrase it was computed for, so a stale answer is never shown for a
  // phrase that has since changed.
  useEffect(() => {
    if (!phrase || !bip39) return;
    let live = true;
    bip39
      .validateBip39(phrase)
      .then((r) => {
        if (live) setChecksum({ phrase, valid: r.valid });
      })
      .catch(() => {
        // Leave the status on "checking": a verdict this could not reach is
        // not one to invent.
      });
    return () => {
      live = false;
    };
  }, [phrase, bip39]);

  const status: { text: string; tone: Tone } = (() => {
    if (!bip39) return { text: "Loading the word list…", tone: "muted" };
    if (flagged.length > 0) {
      const i = flagged[0]!;
      const w = words[i]!;
      const more = flagged.length - 1;
      const tail = more > 0 ? ` ${more} more ${more === 1 ? "word is" : "words are"} flagged.` : "";
      const heads = bip39.bip39Completions(w, 4);
      if (heads.length > 0) {
        const shown =
          heads.length > 3
            ? `${heads.slice(0, 3).join(", ")} or another word starting “${w}”`
            : listOf(heads);
        return { text: `Word ${i + 1} isn't complete — did you mean ${shown}?${tail}`, tone: "danger" };
      }
      const suggestion = bip39.suggestBip39Word(w);
      return {
        text: suggestion
          ? `Word ${i + 1} is not on the list — did you mean ${suggestion}?${tail}`
          : `Word ${i + 1} is not on the list.${tail}`,
        tone: "danger",
      };
    }
    if (!words.some(Boolean)) {
      return { text: "Type the words in order, or paste the whole phrase into any box.", tone: "muted" };
    }
    if (entered < count) return { text: `${entered} of ${count} words entered.`, tone: "muted" };
    if (!checksum || checksum.phrase !== phrase) return { text: "Checking the checksum…", tone: "muted" };
    return checksum.valid
      ? { text: `Checksum matches — a valid ${count}-word phrase.`, tone: "success" }
      : {
          text: `All ${count} words are on the list, but the checksum does not match — one of them is probably wrong.`,
          tone: "danger",
        };
  })();

  const setWord = (i: number, value: string) => {
    const next = words.slice();
    next[i] = value;
    onChange(next);
  };

  const focusCell = (i: number) => inputs.current[i]?.focus();
  const advance = (i: number) => {
    if (i < count - 1) focusCell(i + 1);
  };
  const accept = (i: number, word: string) => {
    setWord(i, word);
    advance(i);
  };

  /**
   * Several words at once — a paste, or a phrase typed with spaces faster
   * than the key handler saw them. Filled from this cell on, growing the grid
   * to the next valid length when they do not fit and dropping what would not
   * fit in 24. Focus lands after the last word placed.
   */
  const distribute = (i: number, parts: string[]) => {
    const needed = i + parts.length;
    const nextCount = needed > count ? seedCountFor(Math.min(needed, 24)) : count;
    const next = resizeSeedWords(words, nextCount);
    parts.slice(0, nextCount - i).forEach((p, k) => {
      next[i + k] = p;
    });
    onChange(next);
    pendingFocus.current = Math.min(needed, nextCount - 1);
  };

  const handleInput = (i: number, raw: string) => {
    if (/\s/.test(raw)) {
      const parts = raw.split(/\s+/).map(cleanSeedWord).filter(Boolean);
      if (parts.length === 0) setWord(i, "");
      else if (parts.length === 1) commit(i, parts[0]!);
      else distribute(i, parts);
      return;
    }
    setWord(i, cleanSeedWord(raw));
  };

  /** A word followed by a space: the only completion is taken, anything else stays as typed. */
  const commit = (i: number, word: string) => {
    if (bip39?.isBip39Word(word)) {
      accept(i, word);
      return;
    }
    const heads = bip39 && word.length >= 2 ? bip39.bip39Completions(word, 2) : [];
    if (heads.length === 1) accept(i, heads[0]!);
    else setWord(i, word);
  };

  const handlePaste = (i: number, e: ClipboardEvent<HTMLInputElement>) => {
    const text = e.clipboardData.getData("text");
    if (!/\s/.test(text.trim())) return;
    e.preventDefault();
    const parts = text.split(/\s+/).map(cleanSeedWord).filter(Boolean);
    if (parts.length > 0) distribute(i, parts);
  };

  const handleKeyDown = (i: number, e: KeyboardEvent<HTMLInputElement>) => {
    const w = words[i] ?? "";
    const exact = !!bip39 && bip39.isBip39Word(w);
    const highlighted = listOpen ? completions[activeIndex] : undefined;
    // The highlight is an offer until the user moves it or it is the only one.
    const deliberate = highlighted !== undefined && (navigated || completions.length === 1);

    switch (e.key) {
      case "ArrowDown":
        if (completions.length > 0) {
          e.preventDefault();
          if (!listOpen) setDismissed(false);
          else setActive((a) => Math.min(a + 1, completions.length - 1));
          setNavigated(true);
        }
        break;
      case "ArrowUp":
        if (listOpen) {
          e.preventDefault();
          setActive((a) => Math.max(a - 1, 0));
          setNavigated(true);
        }
        break;
      case "Home":
        if (listOpen) {
          e.preventDefault();
          setActive(0);
          setNavigated(true);
        }
        break;
      case "End":
        if (listOpen) {
          e.preventDefault();
          setActive(completions.length - 1);
          setNavigated(true);
        }
        break;
      case "Escape":
        if (listOpen) {
          e.preventDefault();
          setDismissed(true);
        }
        break;
      case "Enter":
        e.preventDefault();
        if (exact) advance(i);
        else if (highlighted !== undefined) accept(i, highlighted);
        else advance(i);
        break;
      case " ":
        e.preventDefault();
        if (exact) advance(i);
        else if (deliberate) accept(i, highlighted!);
        break;
      case "Tab":
        if (!e.shiftKey && w && !exact && deliberate) setWord(i, highlighted!);
        break;
      case "Backspace":
        if (w === "" && i > 0) {
          e.preventDefault();
          focusCell(i - 1);
        }
        break;
    }
  };

  return (
    <div className="space-y-2" data-testid="seed-mode">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span id={labelId} className="text-[13px] font-medium text-muted-foreground">
          Seed phrase
        </span>
        <div className="flex items-center gap-2">
          <div role="group" aria-label="Phrase length" className="flex gap-0.5 rounded-lg bg-inset p-0.5">
            {SEED_WORD_COUNTS.map((n) => (
              <button
                key={n}
                type="button"
                aria-pressed={n === count}
                onClick={() => onChange(resizeSeedWords(words, n))}
                className={cn(
                  "min-w-8 cursor-pointer rounded-md border px-1.5 py-1 font-mono text-[12px] leading-none transition-colors",
                  n === count
                    ? "border-border-strong bg-inset text-foreground"
                    : "border-transparent text-muted-foreground hover:text-foreground"
                )}
              >
                {n}
              </button>
            ))}
          </div>
          <button
            type="button"
            onClick={() => onRevealedChange(!revealed)}
            aria-pressed={revealed}
            aria-label={revealed ? "Hide secret text" : "Show secret text"}
            className="rounded-lg border border-border bg-inset p-1.5 text-muted-foreground transition-all hover:bg-raised hover:text-foreground"
          >
            {revealed ? (
              <Eye className="h-4 w-4" aria-hidden="true" />
            ) : (
              <EyeOff className="h-4 w-4" aria-hidden="true" />
            )}
          </button>
        </div>
      </div>

      <div
        role="group"
        aria-labelledby={labelId}
        aria-describedby={statusId}
        data-testid="seed-grid"
        className="grid grid-cols-2 gap-2 min-[420px]:grid-cols-3 sm:grid-cols-4"
      >
        {words.map((w, i) => {
          const state = cells[i]!;
          const isFocused = focused === i;
          const open = isFocused && listOpen;
          return (
            <div key={i} className="relative">
              <span
                aria-hidden="true"
                className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 font-mono text-[12px] tabular-nums text-subtle-foreground"
              >
                {i + 1}
              </span>
              <input
                ref={(el) => {
                  inputs.current[i] = el;
                }}
                id={`seed-word-${i + 1}`}
                role="combobox"
                aria-label={`Word ${i + 1}`}
                aria-autocomplete="list"
                aria-expanded={open}
                aria-controls={open ? listId : undefined}
                aria-activedescendant={open ? optionId(activeIndex) : undefined}
                aria-invalid={state === "flagged" || undefined}
                value={w}
                onChange={(e) => handleInput(i, e.target.value)}
                onPaste={(e) => handlePaste(i, e)}
                onKeyDown={(e) => handleKeyDown(i, e)}
                onFocus={() => setFocused(i)}
                onBlur={() => setFocused((f) => (f === i ? null : f))}
                // The same protections the textarea carries, for the same
                // reason: these cells hold a wallet's recovery phrase, and
                // a keyboard that learns them or a service that spell-checks
                // them is a leak by default.
                autoComplete="off"
                autoCorrect="off"
                autoCapitalize="none"
                spellCheck={false}
                enterKeyHint="next"
                data-1p-ignore
                data-lpignore="true"
                className={cn(
                  "h-10 w-full min-w-0 rounded-xl border bg-inset pl-8 pr-2.5 font-mono text-[13px] text-foreground transition-[filter,border-color] duration-150 focus-visible:outline-hidden focus-visible:ring-0",
                  state === "flagged"
                    ? "border-destructive focus-visible:border-destructive"
                    : "border-border focus-visible:border-border-strong",
                  !revealed && w && !isFocused && "blur-xs"
                )}
              />
              {open && (
                <ul
                  id={listId}
                  role="listbox"
                  aria-label={`Completions for word ${i + 1}`}
                  className="absolute left-0 top-full z-20 mt-1 w-full min-w-36 overflow-hidden rounded-xl border border-border bg-card p-1"
                >
                  {completions.map((c, k) => (
                    <li
                      key={c}
                      id={optionId(k)}
                      role="option"
                      aria-selected={k === activeIndex}
                      // mousedown would blur the input and close this list
                      // before the click arrives.
                      onMouseDown={(e) => e.preventDefault()}
                      onClick={() => accept(i, c)}
                      onPointerMove={() => {
                        if (k !== activeIndex) {
                          setActive(k);
                          setNavigated(true);
                        }
                      }}
                      className={cn(
                        "cursor-pointer rounded-lg px-2.5 py-1.5 font-mono text-[13px] text-foreground",
                        k === activeIndex && "bg-inset"
                      )}
                    >
                      {c}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          );
        })}
      </div>

      <p
        id={statusId}
        role="status"
        data-testid="seed-grid-status"
        data-tone={status.tone}
        className={cn(
          "flex items-start gap-1.5 rounded-lg border px-3 py-2 text-[12px] leading-snug",
          status.tone === "danger"
            ? "border-destructive/40 bg-destructive/10 text-destructive"
            : status.tone === "success"
              ? "border-success/40 bg-success/10 text-success"
              : "border-border text-muted-foreground"
        )}
      >
        {status.tone === "danger" && (
          <TriangleAlert className="mt-px h-3.5 w-3.5 shrink-0" aria-hidden="true" />
        )}
        {status.tone === "success" && (
          <ShieldCheck className="mt-px h-3.5 w-3.5 shrink-0" aria-hidden="true" />
        )}
        <span>{status.text}</span>
      </p>
    </div>
  );
}
