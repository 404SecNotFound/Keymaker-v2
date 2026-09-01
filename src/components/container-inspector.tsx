"use client";

/**
 * The container inspector — the right pane of the workbench split.
 *
 * The format is the product, so show the file. Encrypting, this renders what
 * the form is about to write; once something real exists — the sealed output
 * on the encrypt side, a loaded container on the decrypt side — it renders
 * what the bytes actually say, parsed with the same functions the unlock
 * path trusts. Nothing here is invented: every number is either read out of
 * a header peek or restated from the control the user just set, and the two
 * states are labelled differently ("will be written" / "was written") so a
 * plan is never dressed up as a fact.
 *
 * Read-only by construction. The peek this receives is a bounded slice
 * (KEYM2_HEADER_PEEK_BYTES), which covers the largest slot table §6 allows —
 * the same derivation the unlock-cost notice relies on — so a truncated walk
 * here would mean that constant is wrong, and keym2-dispatch.mts pins it.
 */

import { useMemo, useState } from "react";
import { CheckCircle2, TriangleAlert } from "lucide-react";
import { CipherId, KdfId } from "@/lib/keymaker-crypto";
import {
  KEYM2_KDF_HKDF,
  KEYM2_SLOT_TYPE_PASSKEY,
  KEYM2_SLOT_TYPE_SHAMIR,
  KEYM2_VERSION,
  KEYM2_VERSION_V2,
  KEYM2_VERSION_V3,
  keym2SlotCountOffset,
  keym2SlotTableOffset,
  keym2SlotLen,
  parseKeym2CoreHeader,
  parseKeym2Slot,
  keym2UnlockCost,
  describeUnlockCost,
} from "@/lib/keym-v2";
import { cn } from "@/lib/utils";

/** What the encrypt form has declared, restated — not predicted. */
export interface InspectorPlan {
  kdfLabel: string;
  cipherLabel: string;
  /** The cipher as an id, so the byte map can size slots the way §6 does. */
  cipherId: CipherId;
  keyFile: boolean;
  shares: { threshold: number; count: number } | null;
  passkey: boolean;
  inputBytes: number | null;
}

/* ── The byte map ─────────────────────────────────────────────────────────
 *
 * The one place the sparks are spent. § "The sparks — quarantined" permits
 * the lifted cuts #5C7FFF / #FF7A47 in data visualisation and nowhere else,
 * and this strip is data, not decoration: each segment's width is the byte
 * extent it describes, computed from the same offsets the parser (or the
 * plan) uses, so more slots draw a longer table and a chained cipher draws
 * wider slots. Nothing here is invented, which is this pane's standing rule.
 *
 * Marks only — the type rule stands: a byte in a spark colour is a defect,
 * so the sparks live in the segments and the legend dots while every glyph
 * stays in the warm text scale. The whole block is aria-hidden because it
 * restates what the annotation line and the slot rows already say in text;
 * a screen reader loses nothing.
 *
 * `flexBasis: 3` is the honesty floor: the 5-byte stamp against a 300-byte
 * header would otherwise round to nothing, and a map whose first landmark
 * is invisible explains nothing. Below 3px the strip is schematic and the
 * caption's byte count is the exact figure.
 */
interface ByteSpan {
  key: string;
  kind: "stamp" | "fields" | "slot";
  bytes: number;
}

const SPAN_FILL: Record<ByteSpan["kind"], string> = {
  stamp: "bg-[#FF7A47]",
  fields: "bg-border-strong",
  slot: "bg-[#5C7FFF]",
};

function byteMapSpans(version: number, cipher: number, slotCount: number): ByteSpan[] {
  const table = keym2SlotTableOffset(version);
  const width = keym2SlotLen(cipher);
  return [
    { key: "stamp", kind: "stamp", bytes: 5 },
    { key: "fields", kind: "fields", bytes: table - 5 },
    ...Array.from({ length: slotCount }, (_, i): ByteSpan => ({
      key: `slot-${i}`,
      kind: "slot",
      bytes: width,
    })),
  ];
}

function ByteMap({ spans }: { spans: ByteSpan[] }) {
  const total = spans.reduce((sum, s) => sum + s.bytes, 0);
  const slots = spans.filter((s) => s.kind === "slot").length;
  return (
    <div aria-hidden="true" data-testid="inspector-byte-map" className="px-4 pt-3">
      <div className="flex h-1.5 gap-px overflow-hidden rounded-full">
        {spans.map((span) => (
          <span
            key={span.key}
            data-kind={span.kind}
            className={cn("h-full", SPAN_FILL[span.kind])}
            style={{ flexGrow: span.bytes, flexBasis: 3 }}
          />
        ))}
      </div>
      <p className="flex flex-wrap items-center gap-x-3 gap-y-1 pt-1.5 font-mono text-[12px] text-subtle-foreground">
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-[#FF7A47]" />
          magic+ver
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-border-strong" />
          header fields
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-[#5C7FFF]" />
          {slots === 1 ? "1 slot" : `${slots} slots`}
        </span>
        <span className="ml-auto">{total} B → payload</span>
      </p>
    </div>
  );
}

interface SlotRow {
  index: number;
  label: string;
  detail: string;
}

interface ParsedPeek {
  version: number;
  /** Kept as the id beside the label: the byte map sizes slots from it. */
  cipher: number;
  cipherLabel: string;
  slotCount: number;
  slots: SlotRow[];
  costNote: string | null;
  headHex: string[];
  slotCountOffset: number;
}

const cipherLabelOf = (cipher: number): string =>
  cipher === CipherId.AES_256_GCM
    ? "AES-256-GCM"
    : cipher === CipherId.CHACHA20_POLY1305
      ? "ChaCha20-Poly1305"
      : "AES-256-GCM + ChaCha20-Poly1305";

/**
 * Parse a header peek into rows, or classify it.
 *
 * "legacy" is KEYM v1 or IttyBitz — real containers this app opens, whose
 * headers this inspector does not itemise; the unlock path explains them.
 * null is anything else, including a paste that is not a container at all.
 */
function parsePeek(peek: Uint8Array): ParsedPeek | "legacy" | null {
  if (peek.length >= 5) {
    const magic = String.fromCharCode(...peek.subarray(0, 4));
    if (magic === "IBTZ") return "legacy";
    if (magic === "KEYM" && peek[4] === 0x01) return "legacy";
  }
  try {
    const core = parseKeym2CoreHeader(peek);
    const countOffset = keym2SlotCountOffset(core.version);
    const table = keym2SlotTableOffset(core.version);
    const slotCount = peek[countOffset] as number;
    const width = keym2SlotLen(core.cipher);

    const slots: SlotRow[] = [];
    for (let i = 0; i < slotCount; i++) {
      const start = table + i * width;
      if (start + width > peek.length) break;
      const slot = parseKeym2Slot(peek.subarray(start, start + width));
      if (slot === null) {
        slots.push({ index: i, label: "Unrecognised slot", detail: "" });
      } else if (slot.slotType === KEYM2_SLOT_TYPE_PASSKEY) {
        slots.push({ index: i, label: "Passkey", detail: "WebAuthn PRF · HKDF-SHA-256" });
      } else if (slot.slotType === KEYM2_SLOT_TYPE_SHAMIR) {
        // No k or n: §4.6 stores neither, and this pane never invents.
        slots.push({ index: i, label: "Share set", detail: "Shamir · HKDF-SHA-256" });
      } else if (slot.kdf.kdf === KEYM2_KDF_HKDF) {
        slots.push({ index: i, label: "HKDF slot", detail: "HKDF-SHA-256" });
      } else if (slot.kdf.kdf === KdfId.PBKDF2) {
        slots.push({
          index: i,
          label: "Passphrase",
          detail: `PBKDF2 · ${slot.kdf.params.iterations.toLocaleString("en-US")} iterations`,
        });
      } else {
        slots.push({
          index: i,
          label: "Passphrase",
          detail: `Argon2id · ${Math.round(slot.kdf.params.memoryKiB / 1024)} MiB · t=${slot.kdf.params.timeCost} · p=${slot.kdf.params.parallelism}`,
        });
      }
    }

    return {
      version: core.version,
      cipher: core.cipher,
      cipherLabel: cipherLabelOf(core.cipher),
      slotCount,
      slots,
      costNote: describeUnlockCost(keym2UnlockCost(peek)),
      headHex: Array.from(peek.subarray(0, 10), (b) =>
        b.toString(16).padStart(2, "0").toUpperCase()
      ),
      slotCountOffset: countOffset,
    };
  } catch {
    return null;
  }
}

const rowClasses =
  "flex items-baseline gap-2.5 border-t border-border px-4 py-2 text-[12.5px]";

function SlotList({ slots }: { slots: SlotRow[] }) {
  return (
    <div>
      {slots.map((slot) => (
        <div key={slot.index} className={rowClasses} data-testid="inspector-slot-row">
          <span className="w-4 shrink-0 font-mono text-[12px] text-subtle-foreground">
            {slot.index}
          </span>
          <span className="font-medium text-foreground">{slot.label}</span>
          <span className="ml-auto text-right font-mono text-[12px] text-muted-foreground">
            {slot.detail}
          </span>
        </div>
      ))}
    </div>
  );
}

function Check({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2 text-[12px] text-muted-foreground">
      <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-success" aria-hidden="true" />
      <span>{children}</span>
    </div>
  );
}

export function ContainerInspector({
  mode,
  plan,
  peek,
  className,
}: {
  mode: "encrypt" | "decrypt";
  plan: InspectorPlan | null;
  peek: Uint8Array | null;
  className?: string;
}) {
  const parsed = useMemo(() => (peek ? parsePeek(peek) : null), [peek]);

  /**
   * §"Anticipation": before there is input, the encrypt side is describing a
   * file nobody has made yet, so it summarises instead of itemising. Real
   * input opens the detail on its own — having just supplied the thing, the
   * user should not have to ask to see it described. `asked` only survives
   * the empty state; once `hasInput` is true it stops being consulted.
   */
  const hasInput = plan !== null && plan.inputBytes !== null && plan.inputBytes > 0;
  const [asked, setAsked] = useState(false);
  const showPlanDetail = hasInput || asked;

  /** Slot 0 is always the passphrase; §6 appends the optional ones in this order. */
  const waysIn = plan ? 1 + (plan.shares ? 1 : 0) + (plan.passkey ? 1 : 0) : 0;

  const title =
    parsed && parsed !== "legacy"
      ? mode === "encrypt"
        ? "What was written"
        : "What you loaded"
      : mode === "encrypt"
        ? "What will be written"
        : "What you loaded";

  const versionShown =
    parsed && parsed !== "legacy" ? parsed.version : mode === "encrypt" ? KEYM2_VERSION : null;

  return (
    <aside
      aria-label="Container details"
      data-testid="container-inspector"
      className={cn(
        "panel flex flex-col overflow-hidden rounded-[20px]",
        className
      )}
    >
      <header className="flex items-center gap-2.5 px-4 py-3">
        <h2 className="text-[13px] font-medium">{title}</h2>
        {versionShown !== null && (
          <span className="ml-auto inline-flex items-center gap-1.5 rounded-full border border-border px-2.5 py-0.5 font-mono text-[12px] font-medium tracking-wide text-muted-foreground">
            <span
              className={cn(
                "inline-block h-1.5 w-1.5 rounded-full",
                versionShown === KEYM2_VERSION_V3 ? "bg-success" : "bg-warning"
              )}
              aria-hidden="true"
            />
            KEYM v{versionShown}
          </span>
        )}
      </header>

      {/* ── The bytes ─────────────────────────────────────────────── */}
      {parsed && parsed !== "legacy" ? (
        <>
          <div className="mx-4 overflow-x-auto rounded-md border border-border bg-background px-3 py-2 font-mono text-[12px] leading-relaxed">
            <span className="mr-2 text-subtle-foreground">0000</span>
            {parsed.headHex.map((hex, i) => (
              <span
                key={i}
                className={cn(
                  "mr-1.5",
                  i < 4 && "font-medium text-muted-foreground",
                  i === 4 && "font-medium text-foreground",
                  i > 4 && "text-subtle-foreground"
                )}
              >
                {hex}
              </span>
            ))}
            <span className="text-subtle-foreground">…</span>
          </div>
          <div className="flex flex-wrap gap-x-4 gap-y-1 px-4 pb-1 pt-2 font-mono text-[12px] text-subtle-foreground">
            <span>&quot;KEYM&quot; magic</span>
            <span className="text-foreground">version {parsed.version}</span>
            <span>
              slot count @ 0x{parsed.slotCountOffset.toString(16).toUpperCase().padStart(2, "0")}
            </span>
          </div>

          {/* Widths from the parsed offsets, so the map cannot disagree with
              the rows below it. `slots.length` rather than the count byte: a
              truncated peek itemises fewer rows, and the map draws what the
              pane actually shows. */}
          <ByteMap spans={byteMapSpans(parsed.version, parsed.cipher, parsed.slots.length)} />

          {/* ── The slot table, as parsed ───────────────────────── */}
          <p className="px-4 pb-1 pt-3 font-mono text-[12px] uppercase tracking-[0.1em] text-subtle-foreground">
            {parsed.slotCount === 1 ? "1 slot" : `${parsed.slotCount} slots`} · ways in
          </p>
          <SlotList slots={parsed.slots} />

          <div className="mt-auto space-y-1.5 border-t border-border px-4 py-3">
            <Check>Payload sealed with {parsed.cipherLabel}</Check>
            {parsed.version === KEYM2_VERSION_V3 ? (
              <Check>Slot table authenticated — a removed slot can&apos;t hide</Check>
            ) : (
              <div className="flex items-center gap-2 text-[12px] text-warning/90">
                <TriangleAlert className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                <span>v2 slot table is not authenticated — v3 added that</span>
              </div>
            )}
            <Check>
              Opens without this app —{" "}
              <span className="font-mono text-[12px]">keym2.py</span>
            </Check>
            {parsed.costNote && (
              <p className="pt-1 text-[12px] leading-snug text-muted-foreground">
                {parsed.costNote}
              </p>
            )}
          </div>
        </>
      ) : parsed === "legacy" ? (
        <p className="px-4 pb-3 text-[12.5px] leading-relaxed text-muted-foreground">
          A first-generation container (KEYM v1 or IttyBitz). It opens the same
          way — the unlock explains what it finds. This pane itemises only
          KEYM v2 and v3 headers.
        </p>
      ) : mode === "encrypt" && plan && !showPlanDetail ? (
        <div className="px-4 pb-3" data-testid="inspector-plan-summary">
          <p className="text-[12.5px] leading-relaxed text-muted-foreground">
            Type or drop something in and this pane itemises the container it
            will write, header byte by header byte.
          </p>
          <p className="pt-2 font-mono text-[12px] text-subtle-foreground">
            {plan.cipherLabel} · {waysIn === 1 ? "1 way in" : `${waysIn} ways in`}
          </p>
          <button
            type="button"
            onClick={() => setAsked(true)}
            aria-expanded={false}
            className="mt-3 rounded-full border border-border px-3 py-1 font-mono text-[12px] text-muted-foreground transition-colors hover:bg-inset hover:text-foreground focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
          >
            Show the header it will write
          </button>
        </div>
      ) : mode === "encrypt" && plan ? (
        <>
          <div className="mx-4 overflow-x-auto rounded-md border border-border bg-background px-3 py-2 font-mono text-[12px] leading-relaxed">
            <span className="mr-2 text-subtle-foreground">0000</span>
            {["4B", "45", "59", "4D"].map((hex) => (
              <span key={hex} className="mr-1.5 font-medium text-foreground">
                {hex}
              </span>
            ))}
            <span className="mr-1.5 font-medium text-foreground">
              {KEYM2_VERSION.toString(16).padStart(2, "0").toUpperCase()}
            </span>
            <span className="text-subtle-foreground">…</span>
          </div>
          <p className="px-4 pb-1 pt-2 font-mono text-[12px] text-subtle-foreground">
            salts and nonces are drawn fresh at seal time
          </p>

          {/* The plan side of the same map: version is what this app writes,
              slot count is the ways-in the form has declared. Restated, not
              predicted — every input comes from a control on screen. */}
          <ByteMap spans={byteMapSpans(KEYM2_VERSION, plan.cipherId, waysIn)} />

          <p className="px-4 pb-1 pt-3 font-mono text-[12px] uppercase tracking-[0.1em] text-subtle-foreground">
            ways in · as configured
          </p>
          <div>
            <div className={rowClasses}>
              <span className="w-4 shrink-0 font-mono text-[12px] text-subtle-foreground">0</span>
              <span className="font-medium text-foreground">
                {plan.keyFile ? "Passphrase + key file" : "Passphrase"}
              </span>
              <span className="ml-auto text-right font-mono text-[12px] text-muted-foreground">
                {plan.kdfLabel}
              </span>
            </div>
            {plan.shares && (
              <div className={rowClasses}>
                <span className="w-4 shrink-0 font-mono text-[12px] text-subtle-foreground">1</span>
                <span className="font-medium text-foreground">Share set</span>
                <span className="ml-auto text-right font-mono text-[12px] text-muted-foreground">
                  any {plan.shares.threshold} of {plan.shares.count}
                </span>
              </div>
            )}
            {plan.passkey && (
              <div className={rowClasses}>
                <span className="w-4 shrink-0 font-mono text-[12px] text-subtle-foreground">
                  {plan.shares ? 2 : 1}
                </span>
                <span className="font-medium text-foreground">Passkey</span>
                <span className="ml-auto text-right font-mono text-[12px] text-muted-foreground">
                  WebAuthn PRF · HKDF-SHA-256
                </span>
              </div>
            )}
          </div>

          <div className="mt-auto space-y-1.5 border-t border-border px-4 py-3">
            <Check>Payload sealed with {plan.cipherLabel}</Check>
            <Check>Slot table authenticated — a removed slot can&apos;t hide</Check>
            <Check>
              Opens without this app —{" "}
              <span className="font-mono text-[12px]">keym2.py</span>
            </Check>
            {plan.inputBytes !== null && plan.inputBytes > 0 && (
              <p className="pt-1 font-mono text-[12px] text-subtle-foreground">
                input · {plan.inputBytes.toLocaleString("en-US")} bytes
              </p>
            )}
          </div>
        </>
      ) : (
        <p className="px-4 pb-3 text-[12.5px] leading-relaxed text-muted-foreground">
          Load a <span className="font-mono text-[12px]">.keym</span> file or
          paste a <span className="font-mono text-[12px]">keym2:</span> blob
          and this pane reads its header before anything is unlocked: which
          format generation it is, and every way in that its slot table holds.
        </p>
      )}

      {/* Claims here are structural facts about the app, not live telemetry:
          the export has connect-src 'none', so "nothing leaves" is enforced
          by CSP rather than asserted by a status light. */}
      <footer className="flex items-center gap-3 border-t border-border px-4 py-2.5 font-mono text-[12px] text-subtle-foreground">
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-success" aria-hidden="true" />
          runs in this tab
        </span>
        <span>nothing is uploaded</span>
        <span className="ml-auto">writes KEYM v{KEYM2_VERSION}</span>
      </footer>
    </aside>
  );
}
