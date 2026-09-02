"use client";

import { QRCodeCanvas } from "qrcode.react";
import {
  encodePaperParts,
  paperCapacity,
  PAPER_QR_MAX_BYTES,
} from "@/lib/keym-v2-paper";
import { parseKeym2CoreHeader, keym2SlotCountOffset } from "@/lib/keym-v2";
import { byteMapSpans } from "@/components/container-inspector";

/**
 * Roadmap 4.2 — the paper vault print kit.
 *
 * ## The debt this pays
 *
 * The share modal's Print button was `window.print()` against the app's own
 * dark, screen-shaped layout. What came out was a screenshot of a dialog: dark
 * background burning through a printer's toner, share strings in a proportional
 * face at whatever size the viewport happened to be, and no indication of what
 * the pages were or how to use them. A share set printed from a dark dialog is
 * not a paper backup, and calling the button "Print" implied it was.
 *
 * ## What a paper backup has to survive
 *
 * A drawer or a safe-deposit box for a decade, then being used *once*, in a
 * hurry, by someone who did not choose this tool and may not know what it is.
 * That shapes every decision here:
 *
 * - **QR, not base64 text.** A page of base64 gets retyped at about 4 kB an
 *   hour with a typo rate that makes an AEAD failure near-certain. The failure
 *   then looks identical to a wrong password. A symbol is scanned in a second
 *   and its error correction is arithmetic rather than eyesight.
 * - **Error-correction level M, not L.** The on-screen QR uses L, which is
 *   right for a phone two feet away. Paper gets folded, stained, photocopied
 *   and sun-bleached: 15% recovery for a third fewer bytes is the trade that
 *   matches the medium. §7.1 of the format design records this.
 * - **The procedure travels with it.** A page of unreadable squares and no
 *   instructions is a puzzle, not a backup. The condensed procedure is on the
 *   sheet, and it names `keym2.py` and `docs/RECOVERY.md` so the full version is
 *   findable.
 * - **Nothing secret is printed automatically.** The password is a blank line
 *   to write on, or not. See below.
 *
 * ## The sheet as a procedure
 *
 * One document was doing three jobs: the owner's copy of the backup, the
 * envelopes for three different people, and the instructions for a fourth
 * person years later. It now reads in the order that person meets it.
 *
 * - **A cover before a single square** — *What this is · What you need · Do
 *   this* — in the words of someone who did not choose this tool. The
 *   detailed procedure stays at the end; the cover is what gets read in a
 *   hurry.
 * - **The byte map under the symbols**, the same strip the container inspector
 *   draws and from the same function, so the sheet says how many ways in the
 *   container holds without anyone decoding a square. The two spark cuts are
 *   the one exception to a monochrome page, and they are data.
 * - **A rehearsal box.** A backup that has never been opened is a hope. The
 *   box is a line to be filled in ink — date, which strips, when to do it
 *   again — because the paper is where that record belongs: the app stores
 *   nothing, and a stamp on the sheet survives every device the owner will
 *   ever replace.
 * - **Strips, not a list.** Each share is a strip with a cut line and a
 *   *Held by* line, one per envelope, on a page of its own: the owner's copy
 *   keeps the symbols, the holders get a key and nothing else, and a strip
 *   says what it is to whoever finds it in a drawer.
 *
 * ## Why the hint is a blank line and not a container field
 *
 * The roadmap asks for a "password hint field". It is a line ruled on the paper,
 * deliberately *not* a value stored in the container: a hint inside the
 * ciphertext is a hint handed to whoever steals the ciphertext, and it travels
 * everywhere the file goes. On paper it is only as exposed as the paper, which
 * is a risk the person holding it can actually see and reason about.
 */

export interface PaperVaultProps {
  /** The container to print, raw bytes. */
  container: Uint8Array;
  /** §4.6 share strings, if a set was enrolled in the same operation. */
  shares?: readonly string[] | undefined;
  /** The k of k-of-n, needed to say what a share is worth. */
  threshold?: number | undefined;
  /** Shown as the label on the sheet; never the secret itself. */
  label?: string | undefined;
  /** Fixed by the caller so a re-render cannot change what "printed on" says. */
  printedOn: string;
  /**
   * A rehearsal that succeeded this session: the date and the strips it used.
   * Written into the box as ink would be. Absent, the box prints blank.
   */
  rehearsal?: { on: string; strips: readonly number[] } | undefined;
}

const CAPACITY = paperCapacity(PAPER_QR_MAX_BYTES);

/**
 * The header's shape, read from the bytes the sheet is printing. Null for
 * anything the v2 parser refuses — the sheet then prints without a map rather
 * than with an invented one, which is the inspector's standing rule too.
 */
function containerLayout(
  bytes: Uint8Array
): { version: number; cipher: number; slotCount: number } | null {
  try {
    const core = parseKeym2CoreHeader(bytes);
    const slotCount = bytes[keym2SlotCountOffset(core.version)];
    if (slotCount === undefined) return null;
    return { version: core.version, cipher: core.cipher, slotCount };
  } catch {
    return null;
  }
}

/** "a", "a and b", "a, b and c". */
const listOf = (items: readonly string[]): string =>
  items.length <= 1
    ? (items[0] ?? "")
    : `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;

/** "____", "____ and ____", "____, ____ and ____" — one blank per strip a rehearsal needs. */
const stripBlanks = (k: number): string => listOf(Array.from({ length: k }, () => "______"));

/** The same day next year, the honest default for "rehearse again by". */
function aYearAfter(isoDate: string): string {
  const d = new Date(`${isoDate}T00:00:00Z`);
  if (Number.isNaN(d.getTime())) return "______________";
  d.setUTCFullYear(d.getUTCFullYear() + 1);
  return d.toISOString().slice(0, 10);
}

export function PaperVault({
  container,
  shares,
  threshold,
  label,
  printedOn,
  rehearsal,
}: PaperVaultProps) {
  let parts: string[] = [];
  let tooLarge = false;
  try {
    parts = encodePaperParts(container, CAPACITY);
  } catch {
    tooLarge = true;
  }

  // 300 symbols is ~500 kB of container and a ream of paper. Past that the
  // honest answer is "this is not a paper backup", not 300 pages someone will
  // never scan.
  if (parts.length > 300) tooLarge = true;

  const hasStrips = !!shares && shares.length > 0;
  const k = threshold ?? 0;
  const n = shares?.length ?? 0;
  const layout = containerLayout(container);
  const spans = layout ? byteMapSpans(layout.version, layout.cipher, layout.slotCount) : [];
  const headerBytes = spans.reduce((sum, s) => sum + s.bytes, 0);

  return (
    <div className="paper-vault" aria-hidden="true">
      <header className="pv-head">
        <h1>Keymaker paper vault</h1>
        <p className="pv-sub">
          An encrypted backup, and how to open it without this website.
          {label ? <> Label: <strong>{label}</strong>.</> : null} Printed {printedOn}.
        </p>
      </header>

      {/*
        The cover. Three cells, read before a single square, in the voice of
        the person who finds this in a drawer: what it is, what they need,
        what to do. The full procedure with the commands is at the end.
      */}
      <section className="pv-cover" data-testid="pv-cover">
        <div className="pv-cover-cell">
          <h2>What this is</h2>
          <p>
            An encrypted backup, made with Keymaker on {printedOn}
            {label ? <> and labelled &ldquo;{label}&rdquo;</> : null}. The squares on
            this page are the backup itself, printed so a phone camera can read
            them. Without the password
            {hasStrips ? <> &mdash; or {k} of its {n} recovery strips &mdash;</> : null}{" "}
            they reveal nothing, so this page is safe to keep and useless to
            steal.
          </p>
        </div>
        <div className="pv-cover-cell">
          <h2>What you need</h2>
          <ul>
            <li>This page, whole, with every square readable.</li>
            <li>
              The password its owner set
              {hasStrips ? (
                <>, or {k} of the {n} recovery strips held by the people named on them</>
              ) : null}
              .
            </li>
            <li>
              A phone that scans QR codes, and a computer with Python 3. The
              Keymaker website is not required &mdash; nothing here depends on it
              still existing.
            </li>
          </ul>
        </div>
        <div className="pv-cover-cell">
          <h2>Do this</h2>
          <ol>
            <li>
              Scan every square in the block below. Each reads as a line beginning{" "}
              <code>KMPART1:</code>.
            </li>
            <li>
              Save all the lines in one text file, <code>parts.txt</code>.
            </li>
            <li>
              Follow &ldquo;How to open this without Keymaker&rdquo; at the end
              &mdash; three commands.
            </li>
            <li>
              If it fails, the password or a strip is wrong, not the squares. Try
              again before you worry.
            </li>
          </ol>
        </div>
      </section>

      {tooLarge ? (
        <section className="pv-block">
          <h2>This backup is too large to print</h2>
          <p>
            It would take {parts.length || "hundreds of"} QR symbols. Keep the
            container as a file instead, and print this page&rsquo;s procedure
            alongside it — the recovery steps below still apply.
          </p>
        </section>
      ) : (
        <section className="pv-block">
          <h2>
            The encrypted data — {parts.length} symbol{parts.length === 1 ? "" : "s"}
          </h2>
          <p className="pv-note">
            Scan <strong>all {parts.length}</strong> and join them in order. Every
            one is needed; these are not k-of-n shares. Each symbol also prints
            its own <code>i/n</code>, so they can be scanned in any order.
          </p>
          <div className="pv-grid">
            {parts.map((part, i) => (
              <figure key={part.slice(0, 32)} className="pv-qr">
                {/* Level M, and 300px so a 600dpi printer has real modules to
                    work with rather than resampling a screen-sized bitmap. */}
                <QRCodeCanvas value={part} size={300} level="M" marginSize={2} />
                <figcaption>
                  part {i + 1} of {parts.length}
                </figcaption>
              </figure>
            ))}
          </div>

          {/*
            The byte map, from the inspector's own function: segment widths
            are the byte extents of the header these squares encode, so the
            sheet reports how many ways in exist without decoding anything.
            The two spark cuts are the page's only colour, and they are data.
          */}
          {layout ? (
            <div className="pv-bytemap" data-testid="pv-bytemap">
              <div className="pv-bytemap-strip">
                {spans.map((span) => (
                  <span
                    key={span.key}
                    data-kind={span.kind}
                    className={`pv-seg pv-seg-${span.kind}`}
                    style={{ flexGrow: span.bytes, flexBasis: "3pt" }}
                  />
                ))}
              </div>
              <p className="pv-bytemap-legend">
                <span>
                  <i className="pv-swatch pv-seg-stamp" /> magic + version
                </span>
                <span>
                  <i className="pv-swatch pv-seg-fields" /> header fields
                </span>
                <span>
                  <i className="pv-swatch pv-seg-slot" />{" "}
                  {layout.slotCount === 1 ? "1 slot" : `${layout.slotCount} slots`} &mdash;
                  the ways in
                </span>
                <span>
                  {headerBytes} bytes of header, then the sealed payload
                </span>
              </p>
            </div>
          ) : null}
        </section>
      )}

      <section className="pv-block pv-hint">
        <h2>Password reminder</h2>
        <p className="pv-note">
          Write a <em>reminder</em> here, or leave it blank. Not the password —
          anyone holding this page would then hold the backup as well. This line
          is on paper rather than inside the file on purpose: a hint stored in the
          container travels everywhere the container goes.
        </p>
        <div className="pv-rule" />
        <div className="pv-rule" />
      </section>

      {/*
        The rehearsal box. Ink, not state: the app stores nothing, so the
        record of whether this backup was ever opened lives here, on the copy
        that will be in the drawer when it matters.
      */}
      <section className="pv-block pv-rehearsal" data-testid="pv-rehearsal">
        <h2>Rehearsal</h2>
        <p className="pv-note">
          A backup that has never been opened is a hope. Open it once before you
          trust it{hasStrips ? <> &mdash; with the strips, not the password</> : null},
          and write the date here. Do it again after any move, and at least once a
          year.
        </p>
        {rehearsal ? (
          <p className="pv-rehearsal-line">
            &#9745; Rehearsed on {rehearsal.on}
            {rehearsal.strips.length > 0 ? (
              <> with strips {listOf(rehearsal.strips.map(String))}</>
            ) : null}{" "}
            &middot; rehearse again by {aYearAfter(rehearsal.on)}
          </p>
        ) : (
          <p className="pv-rehearsal-line">
            &#9744; Rehearsed on ______________
            {hasStrips ? <> with strips {stripBlanks(k)}</> : null} &middot; rehearse again
            by ______________
          </p>
        )}
      </section>

      {hasStrips ? (
        <section className="pv-block pv-break pv-strips" data-testid="pv-strips">
          <h2>Recovery strips — cut apart, one per envelope</h2>
          <p className="pv-note">
            Any <strong>{k}</strong> of these {n} open the backup on the owner&rsquo;s
            sheet <em>without the password</em>, so each strip is as sensitive as
            the password itself. Cut along the lines, write each holder&rsquo;s
            name on their strip, and give them to people who would not casually
            combine them. Keep this page no longer than it takes to cut it up.
          </p>
          {shares!.map((share, i) => (
            <div key={share} className="pv-strip" data-testid="pv-strip">
              <p className="pv-cut">&#9986; cut here</p>
              <div className="pv-strip-head">
                <span>
                  Recovery strip {i + 1} of {n}
                </span>
                <span className="pv-holder">Held by ______________________</span>
              </div>
              <div className="pv-strip-body">
                <QRCodeCanvas value={share} size={190} level="M" marginSize={2} />
                <code>{share}</code>
              </div>
              <p className="pv-strip-note">
                One of {n} strips for a Keymaker backup. Any {k} of them open it
                without the password; alone, this one reveals nothing. Keep it
                sealed. When the backup has to be opened, bring it, or read the
                code above to the person opening it &mdash;{" "}
                <code>keym2.py decrypt --share</code> takes it.
              </p>
            </div>
          ))}
        </section>
      ) : null}

      <section className="pv-block pv-break">
        <h2>How to open this without Keymaker</h2>
        <ol className="pv-steps">
          <li>
            Install Python 3.10 or newer, then{" "}
            <code>pip install cryptography argon2-cffi</code>.
          </li>
          <li>
            Get <code>keym2.py</code> — from{" "}
            <code>github.com/404SecNotFound/Keymaker-v2</code> under{" "}
            <code>reference/</code>, or from any copy saved with this page.
          </li>
          <li>
            Scan every symbol above. Each decodes to a line starting{" "}
            <code>KMPART1:</code>. Save them all into one file,{" "}
            <code>parts.txt</code>, one per line.
          </li>
          <li>
            <code>python3 keym2.py join --in parts.txt --out vault.keym</code>
          </li>
          <li>
            <code>python3 keym2.py inspect --in vault.keym</code> — says what the
            backup is, and needs no password.
          </li>
          <li>
            <code>python3 keym2.py decrypt --in vault.keym --out recovered</code>{" "}
            — asks for the password, or use{" "}
            <code>--share</code> once per strip if you have {threshold ?? "k"} of
            them.
          </li>
        </ol>
        <p className="pv-note">
          The full procedure, including what to do when it fails, is{" "}
          <code>docs/RECOVERY.md</code> in that repository. If an error appears,
          it will not say which input was wrong — that is deliberate, and it means
          check the password, the strips, and whether every symbol scanned.
        </p>
      </section>

      <footer className="pv-foot">
        Format KEYM v2 · specified in <code>docs/FORMAT-V2-DESIGN.md</code> ·
        paper parts are §7.1 · this page prints no secret except what you write
        on it.
      </footer>
    </div>
  );
}
