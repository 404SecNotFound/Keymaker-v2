"use client";

/**
 * The command bar — the keyboard-first layer, opened with ⌘K / Ctrl+K.
 *
 * Wayfinding in this app is deliberately neutral: no accent colour, no badge,
 * nothing that shouts. A command bar is how capability grows inside that
 * constraint — every action it offers already exists somewhere on the page,
 * and this surface only makes them reachable without hunting. It never holds
 * an action of its own, which is also the security posture: nothing here
 * touches key material, it only calls the same handlers the buttons do.
 *
 * Hand-rolled on the Radix dialog primitives rather than pulling in `cmdk`.
 * The project keeps its supply chain small on purpose, and the part a library
 * would add — fuzzy scoring — is the part deliberately not wanted: a filter
 * that is a plain case-insensitive substring match is one whose misses a user
 * can predict. Radix contributes the parts that are genuinely hard to get
 * right: focus containment, escape, the portal, and the scrim.
 *
 * The list is a `listbox` driven by `aria-activedescendant` from the input,
 * which stays focused for the whole interaction — the pattern for a filtering
 * combobox. Options carry `tabIndex={-1}` so Tab cannot wander into them; the
 * arrow keys are the way down.
 */

import {
  useEffect,
  useMemo,
  useState,
  type ComponentType,
  type KeyboardEvent,
} from "react";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { Search } from "lucide-react";
import { Dialog, DialogPortal, DialogOverlay } from "@/components/ui/dialog";
import { cn } from "@/lib/utils";

export interface CommandBarItem {
  /** Stable id; also the DOM id the active-descendant wiring points at. */
  id: string;
  /** Section heading this renders under. Groups keep first-seen order. */
  group: string;
  label: string;
  /** Right-aligned mono annotation — an entropy figure, a destination. */
  hint?: string;
  /** Extra text the filter matches that the label does not say. */
  keywords?: string;
  icon: ComponentType<{ className?: string; "aria-hidden"?: boolean }>;
  run: () => void;
}

const optionDomId = (id: string) => `command-bar-option-${id}`;

export function CommandBar({
  open,
  onOpenChange,
  commands,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  commands: CommandBarItem[];
}) {
  const [query, setQuery] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);

  // A fresh open starts blank. Reset on open rather than on close so the
  // closing animation never flashes an emptied list on the way out.
  useEffect(() => {
    if (open) {
      setQuery("");
      setActiveIndex(0);
    }
  }, [open]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return commands;
    return commands.filter((c) =>
      `${c.label} ${c.keywords ?? ""} ${c.group}`.toLowerCase().includes(q)
    );
  }, [commands, query]);

  // The selection follows the list, not the other way round: any change to
  // what is visible puts it back on the first row, which is the row Enter
  // should mean after typing.
  useEffect(() => {
    setActiveIndex(0);
  }, [query]);

  const active = filtered[Math.min(activeIndex, filtered.length - 1)];

  // Keep the keyboard selection on screen. `nearest` is a no-op for a row the
  // pointer chose (it is already visible), so this can run unconditionally.
  useEffect(() => {
    if (!active) return;
    document
      .getElementById(optionDomId(active.id))
      ?.scrollIntoView({ block: "nearest" });
  }, [active]);

  const groups = useMemo(() => {
    const order: string[] = [];
    const byGroup = new Map<string, CommandBarItem[]>();
    for (const item of filtered) {
      if (!byGroup.has(item.group)) {
        byGroup.set(item.group, []);
        order.push(item.group);
      }
      byGroup.get(item.group)!.push(item);
    }
    return order.map((name) => ({ name, items: byGroup.get(name)! }));
  }, [filtered]);

  const runItem = (item: CommandBarItem) => {
    // Close first: a command that opens another dialog (the recovery kit)
    // must not race two Radix portals for focus on the way in.
    onOpenChange(false);
    item.run();
  };

  const onInputKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActiveIndex((i) => Math.min(i + 1, filtered.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActiveIndex((i) => Math.max(i - 1, 0));
    } else if (e.key === "Home" && filtered.length > 0) {
      e.preventDefault();
      setActiveIndex(0);
    } else if (e.key === "End" && filtered.length > 0) {
      e.preventDefault();
      setActiveIndex(filtered.length - 1);
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (active) runItem(active);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogPortal>
        <DialogOverlay />
        {/*
          Not the shared DialogContent: that one centres itself, carries a
          visible close button and 24px of padding — right for a form, wrong
          for a palette. This content sits high (the list grows downward and
          must not reflow around the viewport centre), has no chrome of its
          own, and animates in the sanctioned register: opacity and transform,
          200ms, nothing else. Elevation is the card fill plus a hairline —
          no shadow, per DESIGN-SYSTEM.md.
        */}
        <DialogPrimitive.Content
          aria-label="Command menu"
          className="fixed left-1/2 top-[16%] z-50 w-[min(560px,calc(100vw-2rem))] -translate-x-1/2 overflow-hidden rounded-[20px] border border-border bg-card duration-200 data-[state=open]:animate-in data-[state=open]:fade-in-0 data-[state=open]:zoom-in-95 data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=closed]:zoom-out-95"
        >
          <DialogPrimitive.Title className="sr-only">
            Command menu
          </DialogPrimitive.Title>
          <DialogPrimitive.Description className="sr-only">
            Type to filter commands. Arrow keys move the selection, Enter runs
            it, Escape closes.
          </DialogPrimitive.Description>

          <div className="flex items-center gap-2.5 border-b border-border px-4">
            <Search
              className="h-4 w-4 shrink-0 text-subtle-foreground"
              aria-hidden="true"
            />
            <input
              // eslint-disable-next-line jsx-a11y/no-autofocus -- the input is
              // the whole point of a freshly opened palette; Radix would focus
              // it anyway as the first focusable, this only makes it explicit.
              autoFocus
              role="combobox"
              aria-expanded="true"
              aria-controls="command-bar-list"
              aria-activedescendant={active ? optionDomId(active.id) : undefined}
              aria-label="Filter commands"
              autoComplete="off"
              autoCorrect="off"
              spellCheck={false}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={onInputKeyDown}
              placeholder="Type a command…"
              className="h-12 w-full bg-transparent text-[15px] text-foreground placeholder:text-subtle-foreground focus-visible:outline-hidden"
            />
            <kbd className="shrink-0 rounded-md border border-border px-1.5 py-0.5 font-mono text-[12px] text-subtle-foreground">
              esc
            </kbd>
          </div>

          <div
            id="command-bar-list"
            role="listbox"
            aria-label="Commands"
            className="max-h-[min(348px,50vh)] overflow-y-auto p-2"
          >
            {groups.map((group) => (
              <div key={group.name} role="group" aria-label={group.name}>
                <p
                  aria-hidden="true"
                  className="px-2.5 pb-1 pt-2.5 font-mono text-[12px] uppercase tracking-[0.1em] text-subtle-foreground"
                >
                  {group.name}
                </p>
                {group.items.map((item) => {
                  const isActive = active?.id === item.id;
                  return (
                    <button
                      key={item.id}
                      id={optionDomId(item.id)}
                      type="button"
                      role="option"
                      aria-selected={isActive}
                      tabIndex={-1}
                      // pointermove rather than pointerenter: a list that
                      // scrolls under a resting cursor must not steal the
                      // selection from the keyboard.
                      onPointerMove={() => {
                        if (!isActive) {
                          setActiveIndex(filtered.indexOf(item));
                        }
                      }}
                      onClick={() => runItem(item)}
                      className={cn(
                        "flex w-full cursor-pointer items-center gap-2.5 rounded-xl px-2.5 py-2 text-left text-[14px] text-foreground",
                        isActive && "bg-inset"
                      )}
                    >
                      <item.icon
                        className="h-4 w-4 shrink-0 text-muted-foreground"
                        aria-hidden={true}
                      />
                      <span className="min-w-0 flex-1 truncate">
                        {item.label}
                      </span>
                      {item.hint && (
                        <span className="shrink-0 font-mono text-[12px] text-subtle-foreground">
                          {item.hint}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            ))}
            {filtered.length === 0 && (
              <p
                role="status"
                className="px-2.5 py-8 text-center text-[13px] text-muted-foreground"
              >
                No command matches &ldquo;{query}&rdquo;.
              </p>
            )}
          </div>

          <div className="flex items-center gap-3 border-t border-border px-4 py-2 font-mono text-[12px] text-subtle-foreground">
            <span>↑↓ navigate</span>
            <span>↵ run</span>
            <span className="ml-auto">esc closes</span>
          </div>
        </DialogPrimitive.Content>
      </DialogPortal>
    </Dialog>
  );
}
