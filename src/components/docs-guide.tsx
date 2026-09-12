"use client";

/**
 * The Docs view: the sidebar's seventh destination.
 *
 * Everything the app can do, explained in the app, in the order a person meets
 * it: what a container is, how to make one, how to open one, the extra ways in,
 * seed phrases, recovery, the audio carrier, the bytes, then habits, mistakes
 * and the limits. Each chapter is a numbered panel like the Recovery view, so
 * the page reads as part of the workspace rather than as a pasted manual.
 *
 * Two rules from the rest of the app hold here too. Every claim is one the code
 * or `docs/` backs, and the honesty rules in DESIGN-SYSTEM.md are repeated where
 * they bite: a download is a request, not a saved copy; shares configured are
 * not shares issued; parsed metadata is not verification. The diagrams are
 * HTML, not images, so they inherit the palette, scale with the text, and add
 * nothing to the precache manifest. The two spark colours the design system
 * quarantines for diagrams (#5C7FFF, #FF7A47) appear only inside `<figure>`.
 */

import type { ReactNode } from "react";
import {
  ArrowRight,
  Info,
  Lightbulb,
  OctagonAlert,
  TriangleAlert,
  UserRound,
} from "lucide-react";

export type DocsTarget = "encrypt" | "decrypt" | "recovery" | "audio" | "tools";

type Chapter = { id: string; number: string; title: string; blurb: string };

const CHAPTERS: Chapter[] = [
  { id: "start", number: "01", title: "Start here", blurb: "What a Keymaker backup is, in two minutes." },
  { id: "encrypt", number: "02", title: "Encrypting", blurb: "A file, a note or a seed phrase, sealed into a container you keep." },
  { id: "decrypt", number: "03", title: "Opening and verifying", blurb: "Getting data back, and proving a backup opens without revealing it." },
  { id: "ways-in", number: "04", title: "Ways in", blurb: "Password, key file, passkey, recovery shares: what each adds and costs." },
  { id: "seeds", number: "05", title: "Seed phrases and dice", blurb: "Word-by-word checking, SeedQR export, and counting dice rolls." },
  { id: "recovery", number: "06", title: "Recovery and inheritance", blurb: "Paper, a Python script, a self-opening page, and a plan for someone else." },
  { id: "audio", number: "07", title: "The audio carrier", blurb: "A container inside a WAV file, and what that does not hide." },
  { id: "internals", number: "08", title: "Under the hood", blurb: "The bytes, the authenticated header, and what the page can prove about itself." },
  { id: "practices", number: "09", title: "Best practices", blurb: "Ten habits, ranked by how much each one saves." },
  { id: "mistakes", number: "10", title: "Mistakes to avoid", blurb: "Ten ways people lose or leak a backup, and the fix for each." },
  { id: "limits", number: "11", title: "What it does not protect against", blurb: "Stated plainly, because a vague disclaimer says nothing." },
];

/** Indexed access is `Chapter | undefined` under the strict config; the list is fixed, so a miss is a bug. */
function ch(index: number): Chapter {
  const chapter = CHAPTERS[index];
  if (!chapter) throw new Error(`docs: no chapter ${index}`);
  return chapter;
}

// ---------------------------------------------------------------------------
// Building blocks
// ---------------------------------------------------------------------------

function ChapterPanel({ chapter, children }: { chapter: Chapter; children: ReactNode }) {
  const titleId = `docs-${chapter.id}-title`;
  return (
    <section id={`docs-${chapter.id}`} className="km-form-section km-docs-chapter" aria-labelledby={titleId}>
      <div className="km-section-heading">
        <span className="km-section-number">{chapter.number}</span>
        <h2 id={titleId}>{chapter.title}</h2>
      </div>
      <p className="km-docs-blurb">{chapter.blurb}</p>
      {children}
    </section>
  );
}

function H3({ children }: { children: ReactNode }) {
  return <h3 className="km-docs-h3">{children}</h3>;
}

function Steps({ items }: { items: ReactNode[] }) {
  return (
    <ol className="km-docs-steps">
      {items.map((item, i) => (
        <li key={i}>
          <span className="km-docs-step-number" aria-hidden="true">{i + 1}</span>
          <div>{item}</div>
        </li>
      ))}
    </ol>
  );
}

function Bullets({ items }: { items: ReactNode[] }) {
  return (
    <ul className="km-docs-bullets">
      {items.map((item, i) => <li key={i}>{item}</li>)}
    </ul>
  );
}

type CalloutKind = "tip" | "note" | "warning" | "danger";
const CALLOUT_LABEL: Record<CalloutKind, string> = { tip: "Tip", note: "Note", warning: "Warning", danger: "No recovery" };

function Callout({ kind, title, children }: { kind: CalloutKind; title: string; children: ReactNode }) {
  const Icon = kind === "tip" ? Lightbulb : kind === "note" ? Info : kind === "warning" ? TriangleAlert : OctagonAlert;
  return (
    <aside className={`km-docs-callout km-docs-callout-${kind}`} aria-label={`${CALLOUT_LABEL[kind]}: ${title}`}>
      <div className="km-docs-callout-head">
        <Icon className="h-3.5 w-3.5" aria-hidden="true" />
        <span className="km-docs-callout-kind">{CALLOUT_LABEL[kind]}</span>
        <strong>{title}</strong>
      </div>
      <div className="km-docs-callout-body">{children}</div>
    </aside>
  );
}

function Scenario({ title, story, lesson }: { title: string; story: ReactNode; lesson: ReactNode }) {
  return (
    <div className="km-docs-scenario">
      <p className="km-docs-eyebrow"><UserRound className="h-3.5 w-3.5" aria-hidden="true" />In practice</p>
      <strong>{title}</strong>
      <p>{story}</p>
      <p className="km-docs-lesson"><span className="km-docs-lesson-label">Lesson</span><span className="km-docs-lesson-text">{lesson}</span></p>
    </div>
  );
}

function Table({ columns, rows }: { columns: string[]; rows: ReactNode[][] }) {
  return (
    <div className="km-docs-table-wrap">
      <table className="km-docs-table">
        <thead>
          <tr>{columns.map((c) => <th key={c} scope="col">{c}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i}>
              {row.map((cell, j) => j === 0 ? <th key={j} scope="row">{cell}</th> : <td key={j}>{cell}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Ranked({ items }: { items: { title: string; body: ReactNode }[] }) {
  return (
    <ol className="km-docs-ranked">
      {items.map((item, i) => (
        <li key={i}>
          <span className="km-docs-rank" aria-hidden="true">{i + 1}</span>
          <div>
            <strong>{item.title}</strong>
            <p>{item.body}</p>
          </div>
        </li>
      ))}
    </ol>
  );
}

/** A box in a flow diagram. `mark` uses one of the two quarantined spark colours. */
function Box({ title, detail, mark }: { title: ReactNode; detail?: ReactNode; mark?: "blue" | "ember" }) {
  return (
    <div className={`km-docs-box${mark ? ` km-docs-box-${mark}` : ""}`}>
      <span>{title}</span>
      {detail ? <small>{detail}</small> : null}
    </div>
  );
}

function Arrow() {
  return <ArrowRight className="km-docs-arrow h-3.5 w-3.5" aria-hidden="true" />;
}

function Figure({ caption, children }: { caption: string; children: ReactNode }) {
  return (
    <figure className="km-docs-figure">
      <div className="km-docs-figure-body">{children}</div>
      <figcaption>{caption}</figcaption>
    </figure>
  );
}

function GoTo({ target, onNavigate, children }: { target: DocsTarget; onNavigate?: ((t: DocsTarget) => void) | undefined; children: ReactNode }) {
  if (!onNavigate) return <strong>{children}</strong>;
  return (
    <button type="button" className="km-docs-goto" onClick={() => onNavigate(target)}>
      {children}<ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
    </button>
  );
}

// ---------------------------------------------------------------------------
// Diagrams
// ---------------------------------------------------------------------------

function PipelineDiagram() {
  return (
    <Figure caption="One pass from password to container. The header travels inside the file and is authenticated by every layer, so whoever opens it needs no settings, only the password, and cannot be handed a weakened header.">
      <div className="km-docs-flow">
        <Box title="Password" detail="+ key file, optional" />
        <Arrow />
        <Box title="NFC normalise" detail="same key on every OS" />
        <Arrow />
        <Box title="Argon2id" detail="or PBKDF2, slow on purpose" mark="blue" />
        <Arrow />
        <Box title="Master key" detail="32 bytes" />
        <Arrow />
        <Box title="AES-256-GCM" detail="or ChaCha20, or both" />
        <Arrow />
        <Box title="keym2: text" detail="or a .keym file" mark="ember" />
      </div>
      <div className="km-docs-flow km-docs-flow-note">
        <Box title="Header" detail="fed in as authenticated data, never encrypted" />
        <Arrow />
        <span className="km-docs-flow-text">into every AEAD layer</span>
      </div>
    </Figure>
  );
}

function SlotsDiagram() {
  return (
    <Figure caption="A container has one master key and up to eight slots, each holding that key sealed under a different way in. Any single slot opens the file. The password slot is the one that survives everything; the rest are conveniences and safety nets.">
      <div className="km-docs-stack">
        <Box title="Core header" detail="24 bytes, authenticated everywhere" />
        <div className="km-docs-slots">
          <Box title="Slot: passphrase" detail="+ key file if used" mark="blue" />
          <Box title="Slot: passkey" detail="optional, this site only" />
          <Box title="Slot: recovery shares" detail="optional, k of n strips" />
          <Box title="…up to 8" detail="each 96 or 112 bytes" />
        </div>
        <Box title="Payload" detail="1 MiB chunks, each with its own tag" mark="ember" />
      </div>
    </Figure>
  );
}

function SharesDiagram() {
  return (
    <Figure caption="Recovery shares with the default 2 of 3. Any two strips open the container without the password. One strip on its own reveals nothing about the key, which is the property that lets you hand them to different people.">
      <div className="km-docs-flow">
        <Box title="Strip 1" detail="KMSHARE1:…" mark="blue" />
        <Box title="Strip 2" detail="KMSHARE1:…" mark="blue" />
        <Box title="Strip 3" detail="KMSHARE1:…" />
        <Arrow />
        <Box title="Any 2 of 3" detail="opens the container" mark="ember" />
      </div>
      <div className="km-docs-flow km-docs-flow-note">
        <Box title="1 strip alone" />
        <Arrow />
        <span className="km-docs-flow-text">reveals nothing, mathematically</span>
      </div>
    </Figure>
  );
}

function WireDiagram() {
  const cells: { label: string; bytes: string; mark?: "blue" | "ember"; grow?: boolean }[] = [
    { label: "KEYM", bytes: "4" },
    { label: "v3", bytes: "1" },
    { label: "cipher", bytes: "1" },
    { label: "flags", bytes: "1" },
    { label: "0", bytes: "1" },
    { label: "container_id", bytes: "16" },
    { label: "slots", bytes: "1" },
    { label: "slot_table_mac", bytes: "32", mark: "blue" },
    { label: "slot table", bytes: "n × 96 / 112" },
    { label: "payload chunks", bytes: "1 MiB + tag each", mark: "ember", grow: true },
  ];
  return (
    <Figure caption="The KEYM v3 container, in order. The first 24 bytes are the core header, authenticated by the payload and by every slot. The slot table MAC lets the app say whether the list of ways in has been edited. The payload is the data in 1 MiB chunks, each carrying its own 16-byte tag, or 32 when chained.">
      <div className="km-docs-wire" role="img" aria-label="Byte layout of a KEYM v3 container: magic, version, cipher, flags, reserved byte, 16-byte container id, slot count, 32-byte slot table MAC, the slot table, then the payload chunks">
        {cells.map((c) => (
          <div key={c.label} className={`km-docs-cell${c.mark ? ` km-docs-cell-${c.mark}` : ""}${c.grow ? " km-docs-cell-grow" : ""}`}>
            <span>{c.label}</span>
            <small>{c.bytes}</small>
          </div>
        ))}
      </div>
    </Figure>
  );
}

function DowngradeDiagram() {
  return (
    <Figure caption="Why the header is authenticated. An attacker who could rewrite the stored parameters would turn a memory-hard derivation into a cheap one and brute-force the password offline, with the file still opening normally. Because every header byte is under the tag, the edit is detected and the file refused.">
      <div className="km-docs-flow">
        <Box title="Attacker edits the header" detail="Argon2id → PBKDF2, 1 iteration" />
        <Arrow />
        <Box title="Tag check" detail="header is authenticated data" mark="blue" />
        <Arrow />
        <Box title="Refused" detail="no downgrade, no oracle" mark="ember" />
      </div>
    </Figure>
  );
}

function VerifyDiagram() {
  return (
    <Figure caption="Verify only. The container is decrypted and authenticated in the worker, the plaintext is discarded, and the result names the method that worked and the size. Nothing reaches the screen, the clipboard, or a file.">
      <div className="km-docs-flow">
        <Box title="Container + a way in" />
        <Arrow />
        <Box title="Decrypt in the worker" detail="authenticate every layer" mark="blue" />
        <Arrow />
        <Box title="Discard plaintext" />
        <Arrow />
        <Box title="Opens · 2.1 KB · password" detail="the whole report" mark="ember" />
      </div>
    </Figure>
  );
}

function AudioDiagram() {
  return (
    <Figure caption="The audio carrier. The same container the Encrypt view writes is packed into the least significant bit of each sample, after a KAUD1 header at a fixed place. The output is always WAV: lossy re-encoding rewrites those bits and the container is gone.">
      <div className="km-docs-flow">
        <Box title="KEYM container" detail="Argon2id + AES, as usual" mark="blue" />
        <Arrow />
        <Box title="KAUD1 header" detail="fixed position, findable" />
        <Arrow />
        <Box title="Sample LSBs" detail="one bit per sample" />
        <Arrow />
        <Box title="WAV out" detail="lossless only" mark="ember" />
      </div>
      <div className="km-docs-flow km-docs-flow-note">
        <Box title="Convert to MP3" />
        <Arrow />
        <span className="km-docs-flow-text">the low bits are rewritten; the secret is destroyed</span>
      </div>
    </Figure>
  );
}

function RecoveryLadderDiagram() {
  return (
    <Figure caption="Four ways to open a backup, from most convenient to most durable. Each one needs less of Keymaker than the one before it. The bottom rung needs none of it.">
      <div className="km-docs-ladder">
        <Box title="This app" detail="any browser, online or installed offline" mark="blue" />
        <Box title="A self-opening page" detail="one .html holding the container and a decryptor" />
        <Box title="keym2.py" detail="the recovery kit: Python and two libraries, no website" />
        <Box title="Paper" detail="printed shares and the printed procedure" mark="ember" />
      </div>
    </Figure>
  );
}

function SeedCheckDiagram() {
  return (
    <Figure caption="Seed Phrase mode checks each word against the BIP-39 list as it is typed and reports the checksum in a sentence once the phrase is whole. A wrong word is named by position and by what it was probably meant to be, never by colour alone.">
      <div className="km-docs-flow">
        <Box title="Word 7: wroth" detail="not on the list" mark="ember" />
        <Arrow />
        <Box title="Did you mean worth?" detail="named in words" mark="blue" />
        <Arrow />
        <Box title="Checksum" detail="reported before you seal" />
      </div>
    </Figure>
  );
}

// ---------------------------------------------------------------------------
// The guide
// ---------------------------------------------------------------------------

export function DocsGuide({ onNavigate }: { onNavigate?: ((target: DocsTarget) => void) | undefined }) {
  return (
    <div className="km-docs" data-testid="docs-guide">
      <nav className="km-docs-toc" aria-label="Chapters">
        <p className="km-nav-label">CHAPTERS</p>
        <ol>
          {CHAPTERS.map((c) => (
            <li key={c.id}>
              <a href={`#docs-${c.id}`}><span className="km-docs-toc-number">{c.number}</span>{c.title}</a>
            </li>
          ))}
        </ol>
      </nav>

      <div className="km-docs-body">
        {/* 01 ------------------------------------------------------------ */}
        <ChapterPanel chapter={ch(0)}>
          <p>
            Keymaker turns a file, a note or a seed phrase plus a password into a <strong>container</strong>: a
            line of text beginning <code>keym2:</code>, or a <code>.keym</code> file, that only the password opens.
            Everything runs in this tab. Nothing is uploaded, there is no account, and the app keeps no library of
            your backups. You save each container somewhere you control.
          </p>
          <p>
            The container describes itself. It carries which key derivation and which cipher were used, so opening
            it years from now needs no settings, and the whole header is authenticated so nobody can quietly swap
            those settings for weaker ones. The format is written down, an independent Python implementation ships
            with the app, and a printed procedure opens a backup with no Keymaker software at all.
          </p>
          <PipelineDiagram />
          <H3>The two-minute tour</H3>
          <Steps items={[
            <>Pick a door on the <strong>Workspace</strong> view: back up a seed phrase, encrypt a file, or open a backup. Or go straight to <GoTo target="encrypt" onNavigate={onNavigate}>Encrypt</GoTo>.</>,
            <>Choose <strong>File</strong>, <strong>Text</strong> or <strong>Seed phrase</strong> and put in what you are protecting. Secret fields blur themselves.</>,
            <>Set a password, or press <strong>Random</strong> or <strong>Passphrase</strong> to have one generated. Leave <strong>Advanced</strong> alone the first time.</>,
            <>Press <strong>Encrypt</strong>. The result is a <code>keym2:</code> line you can copy, or <strong>Download</strong> gives the same bytes as a <code>.keym</code> file.</>,
            <>Go to <GoTo target="decrypt" onNavigate={onNavigate}>Decrypt</GoTo>, paste it back, turn on <strong>Verify only</strong>, and prove it opens. A backup you have never opened is a hypothesis.</>,
          ]} />
          <Callout kind="tip" title="The password is the only secret">
            The container can be emailed, printed, or left on a USB stick. Argon2id makes every guess at the password cost real memory and time, so a long passphrase is the whole defence. A short one undoes everything else on this page.
          </Callout>
          <Callout kind="note" title="Where the keyboard shortcuts are">
            <kbd>⌘K</kbd> or <kbd>Ctrl K</kbd> opens the command menu. Every action on the page is reachable from it, including these chapters, and it never holds an action of its own.
          </Callout>
        </ChapterPanel>

        {/* 02 ------------------------------------------------------------ */}
        <ChapterPanel chapter={ch(1)}>
          <Steps items={[
            <>On <GoTo target="encrypt" onNavigate={onNavigate}>Encrypt</GoTo>, choose the input type. <strong>File</strong> takes anything up to 100 MB. <strong>Text</strong> takes a note. <strong>Seed phrase</strong> gives each word its own cell.</>,
            <>Set the password. A typed one gets <em>Minimum policy met</em> and nothing more, because a string carries no evidence of how it was chosen. <strong>Random</strong> gives 32 characters (208 bits) and <strong>Passphrase</strong> seven words from the EFF long list (90 bits). Those two the app can vouch for exactly.</>,
            <>Open <strong>Advanced</strong> only if you have a reason. The defaults are the right ones for new data.</>,
            <>Press <strong>Encrypt</strong>. Read the receipt: what was written, how it is protected, and the ways in. The <strong>container inspector</strong> beside the form shows the header the file actually carries, labelled <em>was written</em>.</>,
            <>Keep the container. <strong>Download</strong> is a request to the browser, not proof of a saved copy. Check your downloads folder before you rely on it.</>,
          ]} />
          <Callout kind="danger" title="There is no reset">
            No recovery email, no support desk, nobody to call. If the password is lost, and every other way in with it, the data is gone. Decide where the password will live before you press Encrypt, not after.
          </Callout>
          <H3>The Advanced panel, and when to touch it</H3>
          <Table columns={["Setting", "Default", "Change it when"]} rows={[
            ["Key derivation", "Argon2id, 64 MiB, 3 passes, 4 lanes", <>You accept a slower decryption in exchange for a costlier attack. <strong>Calibrate for this device</strong> measures your machine and picks the strongest settings that fit a time budget. <strong>PBKDF2</strong> at 1,000,000 iterations exists for browsers that forbid WebAssembly and for compatibility.</>],
            ["Cipher", "AES-256-GCM", <>You have a policy reason to prefer <strong>ChaCha20-Poly1305</strong>, or you want <strong>AES then ChaCha</strong> chained under independent subkeys. Chaining is defence in depth against a break in one cipher. It does nothing for a guessable password.</>],
            ["Key file", "Off", <>You want a second thing an attacker must have. Generate one in the app or pick any file. It counts as a second password: lose it and the container is gone.</>],
            ["Obscure filename", "Off", <>The file's name is itself sensitive. The download becomes <code>keymaker-&lt;random&gt;.keym</code>.</>],
            ["Passkey quick access", "Off", <>You will open this backup often, here, and want a tap instead of a phrase. Read chapter 04 first: it is a convenience, not strength, and not archival.</>],
            ["Recovery shares", "Off", <>Someone other than you may need to open this, or you want a way in that is not a memory. Chapter 04 and 06.</>],
          ]} />
          <Scenario
            title="The right password on the wrong backup"
            story={<>A freelancer keeps monthly copies of an accounts file, each encrypted with the same passphrase. In a hurry they verify the newest container, see <em>opens</em>, and delete the plaintext. The container they verified was last month's copy, pasted from the wrong note.</>}
            lesson={<>Read the size on the verify result. The panel says so for a reason: the right password on the wrong backup still verifies. Compare the byte count with the file you meant to protect.</>}
          />
        </ChapterPanel>

        {/* 03 ------------------------------------------------------------ */}
        <ChapterPanel chapter={ch(2)}>
          <Steps items={[
            <>On <GoTo target="decrypt" onNavigate={onNavigate}>Decrypt</GoTo>, paste the <code>keym2:</code> text, drop the <code>.keym</code> file, or scan a QR image. Legacy IttyBitz files and blobs open too.</>,
            <>The inspector reads the header back before you type anything: format version, cipher, key derivation and cost, and the ways in. That is parsed metadata, not proof it will open.</>,
            <>Choose the way in: the password (with its key file, if one was used), <strong>Use recovery shares</strong> pasted one per line, or <strong>Use a passkey</strong> if one was enrolled here.</>,
            <>Turn on <strong>Verify only</strong> when you want proof without exposure. Otherwise press <strong>Decrypt</strong>. Recovered text is blurred until you reveal it; a recovered file is offered as a download.</>,
          ]} />
          <VerifyDiagram />
          <H3>What the messages mean</H3>
          <Table columns={["You see", "What happened", "What to do"]} rows={[
            [<>A generic failure, whether the password was wrong or the file damaged</>, <>By design. A message that told the two apart would be an oracle: an attacker probing a container could learn which guesses were structurally valid.</>, <>Check caps lock, keyboard layout, leading and trailing spaces, and that you pasted the whole line from <code>keym2:</code> to the end. Then obtain a fresh copy of the container by another route.</>],
            [<>A notice that unlocking will take longer than usual, with a <strong>Stop</strong> button</>, <>The container asks for expensive key derivation, priced from its own header. Up to eight slots are derived in turn before anything is authenticated.</>, <>Wait if you expect it. Stop if you do not: a hostile file cannot burn your CPU unannounced, but it can ask.</>],
            [<>The list of ways in has changed</>, <>The slot table MAC did not match. Someone edited or removed a slot without holding a secret. You still get your data; the app refuses to make further changes to that list.</>, <>Treat the copy as tampered. Re-encrypt from the recovered plaintext into a fresh container.</>],
            [<>This container is too large for the app</>, <>The app holds the container and the recovered file in memory at once, so it stops at 100 MB. The format has no such limit.</>, <>The message gives the command. <code>keym2.py</code> opens it with no size limit.</>],
            [<>This container has no passkey enrolled</>, <>You chose the passkey way in on a file that was never given one.</>, <>Use the password.</>],
          ]} />
          <Callout kind="note" title="Slow is a feature">
            Argon2id at the default settings allocates 64 MiB and makes three passes over it, per guess. That is the cost you are imposing on anyone brute-forcing the password. The window stays responsive, the derivation runs in a worker, and Stop is always there.
          </Callout>
          <Scenario
            title="The chat that reflowed the text"
            story={<>A container is pasted into a messaging app that wraps long lines and turns straight quotes into curly ones. Pasted back months later, it fails every time. The password is right. The bytes are not the bytes that were sent.</>}
            lesson={<>Send containers as a <code>.keym</code> file, or inside a code block, and copy from the very start of <code>keym2:</code>. A container is one line; anything that prettifies it can break it.</>}
          />
        </ChapterPanel>

        {/* 04 ------------------------------------------------------------ */}
        <ChapterPanel chapter={ch(3)}>
          <p>
            A container holds one master key and up to eight <strong>slots</strong>. Each slot is that key sealed under a
            different way in, and any single slot opens the file. This is what lets one backup have a password, a
            passkey and a set of paper shares at the same time.
          </p>
          <SlotsDiagram />
          <Table columns={["Way in", "What it is", "Honest framing"]} rows={[
            ["Password", <>Something you know. Normalised to NFC before derivation, so the same characters typed on a Mac and on Windows derive the same key.</>, <>The one that survives everything: a copy of the app, a different address, the offline script. Keep it even when you add the others.</>],
            ["Key file", <>Something you have, appended to the password bytes before derivation. Generate one in the app or use any file.</>, <>A second password. If the file changes by one byte, or is lost, the container is gone. Photo libraries re-encode and sync clients rewrite.</>],
            ["Passkey", <>A WebAuthn PRF slot: a tap on a hardware key or a platform authenticator, phishing-resistant.</>, <>Not extra strength. The password still opens the container, so it is exactly as strong as the weaker of the two. And not archival: it answers only at this website.</>],
            ["Recovery shares", <>The master key split with Shamir's scheme into n printed strips, any k of which reconstruct it.</>, <>Any k strips open the container <em>without the password</em>, so each strip is as sensitive as the password itself. Fewer than k reveal nothing.</>],
          ]} />
          <SharesDiagram />
          <Callout kind="warning" title="Shares configured is not shares issued">
            Turning the switch on and setting 2 of 3 is a plan. The strips exist only after you encrypt and the shares dialog shows them. Print them from the paper vault, then <strong>Rehearse now</strong>: paste the strips back and open the container with them before you rely on them.
          </Callout>
          <Scenario
            title="Three strips in one drawer"
            story={<>A couple splits a backup 2 of 3 and, for tidiness, keeps all three printed strips in the same folder in the same desk. The desk is what the burglar takes.</>}
            lesson={<>The whole point of a threshold is separation. Different places, different people. Two of three in one location is one location.</>}
          />
        </ChapterPanel>

        {/* 05 ------------------------------------------------------------ */}
        <ChapterPanel chapter={ch(4)}>
          <p>
            <strong>Seed Phrase mode</strong> is the first door on the Workspace view and the third pill above the text
            box. Each of the 12 to 24 words gets its own cell. A prefix completes from the BIP-39 list, since four
            letters name every word on it, and only the cell being typed into is readable; the rest stay blurred
            until you reveal them.
          </p>
          <SeedCheckDiagram />
          <Bullets items={[
            <><strong>Mistakes are named, not coloured.</strong> <em>Word 7 is not on the list, did you mean worth?</em> The border tint is a second channel, never the only one.</>,
            <><strong>The checksum is reported before you seal.</strong> A phrase that is seed-shaped but fails its checksum is caught while the mistake is still fixable, not after a bad backup has been stored for a decade.</>,
            <><strong>Repeated words are legal</strong> and are not flagged. A phrase from a wallet that never followed the standard is yours to seal; the app tells you and leaves the decision with you.</>,
            <><strong>On the way back out</strong>, a recovered seed can be exported as a <strong>Standard SeedQR</strong> for Coldcard, SeedSigner, Sparrow, Specter, Krux, Keystone or Jade. The QR is not drawn until you press <strong>Reveal</strong>. Ciphertext QR codes show at once; plaintext ones are gated, because a pattern that is your seed is a different category of risk.</>,
          ]} />
          <H3>The dice calculator</H3>
          <p>
            Under <GoTo target="tools" onNavigate={onNavigate}>Tools</GoTo>. It answers one question: how many physical
            dice rolls do you need for 128 or 256 bits of entropy? Bits per roll is log2 of the number of sides, so
            a six-sided die gives about 2.58 bits and 99 rolls clear 256. It computes bits. It does not generate a
            seed. Roll real dice and turn the rolls into a seed on an air-gapped device with dedicated software.
          </p>
          <Callout kind="note" title="Why dice at all">
            Hardware random number generators have failed in the field. Dice derive their randomness from mechanics you can watch rather than silicon you have to trust, which is why the calculator exists and why it refuses to do the seed step for you.
          </Callout>
        </ChapterPanel>

        {/* 06 ------------------------------------------------------------ */}
        <ChapterPanel chapter={ch(5)}>
          <p>
            The <GoTo target="recovery" onNavigate={onNavigate}>Recovery</GoTo> view exists for the day the app,
            the website or you are not available. It distinguishes a configured share set from an issued one, a
            download request from a saved copy, and a test instruction from a passed test, on purpose.
          </p>
          <RecoveryLadderDiagram />
          <Table columns={["Tool", "What it gives you", "Its limit"]} rows={[
            ["Verify a way in", <>Proof that the backup opens with the password, or with the shares, without revealing the contents.</>, <>A passing password test says nothing about the shares. Test each method you plan to rely on.</>],
            ["Paper backup", <>A print kit designed for a drawer: the container as QR with instructions, and the share strips in a monospace face at a readable size.</>, <>Paper burns and fades. Two copies, two places.</>],
            ["Recovery kit", <><code>keym2.py</code> and the printed procedure, bundled with the app under <code>/recovery/</code>. Python plus two mainstream libraries opens any container with no browser and no website.</>, <>Getting the two libraries onto a machine normally reaches a package index. Download the wheels now and store them beside the backup for a genuinely offline kit.</>],
            ["Self-opening page", <>One <code>.html</code> holding the container and a WebCrypto-only decryptor, for the person who inherits the backup and not the toolchain.</>, <>Only for AES-256-GCM with a PBKDF2 password slot. The app's default is Argon2id, so most containers cannot become a page, and the export says which change would allow it rather than hiding the option.</>],
            ["Inheritance plan", <>A guided order of the steps above for leaving a backup someone can open after you. It adds no cryptography; it tells you which existing controls to use and in what order.</>, <>It repeats the shares warning where you decide: any k strips open the container without the password.</>],
          ]} />
          <H3>What to keep, and where</H3>
          <Table columns={["Keep", "Why", "Where"]} rows={[
            ["The container", "The encrypted data itself.", "Anywhere. It is designed to be seen."],
            ["The password", "Without it, nothing else matters.", "Separately from the container. Two places, or it is one lost envelope from gone."],
            ["The key file, if any", "It counts as a second password.", "Backed up like the password. Not in a photo library or a folder that syncs."],
            ["The share strips, if any", "Any k open the container.", "Different places, different people."],
            [<>A copy of <code>keym2.py</code></>, "So recovery works with no network and no site.", "Beside the backup, with the two library wheels."],
            ["The printed procedure", "For when there is no working computer to read a repository on.", "With the paper backup."],
          ]} />
          <Scenario
            title="Six months later"
            story={<>Someone encrypts a password-manager export with a passphrase they are certain they will never forget. The receipt says <em>opens</em>. The following spring, three near misses are refused, then a fourth. The archive is exactly as safe from its owner as from anyone else.</>}
            lesson={<>Store the password durably in the same minute you create it, and set up a second way in while the plaintext still exists. The confirm step catches typos, not memory.</>}
          />
        </ChapterPanel>

        {/* 07 ------------------------------------------------------------ */}
        <ChapterPanel chapter={ch(6)}>
          <p>
            The <GoTo target="audio" onNavigate={onNavigate}>Audio</GoTo> view packs an encrypted secret into an
            audio file that plays like ordinary music. The bytes packed in are the same KEYM container the Encrypt
            view writes, so Argon2id, the cipher and the independent Python decryptor all apply unchanged. This is a
            carrier, not a new cipher.
          </p>
          <AudioDiagram />
          <Steps items={[
            <><strong>Pack:</strong> choose an audio carrier (MP3, WAV, FLAC or Ogg), the secret as text or a file, and a password. Download the WAV.</>,
            <><strong>Unpack:</strong> open that WAV here with the password to recover the secret.</>,
          ]} />
          <Callout kind="warning" title="A carrier, not a hiding place">
            This is deliberately not called steganography. The <code>KAUD1</code> header sits at a fixed place in the samples and the payload follows it sequentially, so the presence of a payload is trivially detectable. It hides nothing from anyone who looks. What protects the secret is the password, exactly as on the Encrypt view.
          </Callout>
          <Scenario
            title="The MP3 that lost the secret"
            story={<>A user packs a backup into a WAV, then runs it through a converter to save space and keeps only the MP3. The music sounds identical. The low bit of every sample has been rewritten by the encoder, and the container is gone.</>}
            lesson={<>Keep the WAV. There is deliberately no MP3 output, because the bit does not survive lossy encoding. If space matters, encrypt to a <code>.keym</code> file instead; it is smaller than any carrier.</>}
          />
        </ChapterPanel>

        {/* 08 ------------------------------------------------------------ */}
        <ChapterPanel chapter={ch(7)}>
          <p>
            For readers who want to know what is in the file, not only what it does. Everything here is specified
            in the format documents that ship with the source, and pinned by fixtures and by the Python reference
            implementation reading the same bytes.
          </p>
          <WireDiagram />
          <H3>Key derivation</H3>
          <p>
            The password, normalised to NFC and encoded as UTF-8, with the key file's bytes appended if there is one,
            goes through <strong>Argon2id</strong> (default 64 MiB, 3 passes, 4 lanes) or <strong>PBKDF2-HMAC-SHA-256</strong>
            at 1,000,000 iterations, with a 32-byte salt stored in the slot. The result unwraps the master key in
            that slot. Argon2id is memory-hard, so an attacker's parallelism is capped by memory bandwidth rather than
            by core count, and raising the memory setting raises their cost far more than yours: you pay it once, they
            pay it per guess.
          </p>
          <H3>Why the header is authenticated</H3>
          <DowngradeDiagram />
          <p>
            Every AEAD layer is fed the core header as additional authenticated data, and each slot's wrap is fed
            the core header plus its own 48-byte prefix. Readable before you hold the key, unforgeable once you do.
            The slot count is deliberately outside both, so a slot table stays editable by someone holding exactly
            one slot's secret; a separate <code>slot_table_mac</code> keyed from the master key covers the table as a
            whole, so an edit made without any secret is detected and reported.
          </p>
          <H3>Ciphers</H3>
          <p>
            AES-256-GCM or ChaCha20-Poly1305, both 256-bit authenticated ciphers, or the two chained: AES first, then
            ChaCha over its output, under independent subkeys from HKDF. Chaining costs one extra pass and 16 more
            bytes of tag per chunk. Decryption runs the chain in reverse and each layer authenticates before it
            decrypts, so tampered data is rejected at the outer layer without the inner key ever being applied.
          </p>
          <H3>What this page can prove about itself</H3>
          <Bullets items={[
            <><strong>The sealed status</strong> under the inspector shows three facts the page establishes locally, never telemetry: the served policy forbids every network destination (<code>default-src</code>, <code>connect-src</code> and <code>form-action</code> all <code>'none'</code>, read from the document rather than typed), whether the browser is online, and whether the running build's files hash to the manifest it shipped with.</>,
            <><strong>The verify page</strong> states the commit this build claims to be and prints the commands that check the served files against a signed manifest, on your machine. It never says <em>verified</em>, because only you can run the check.</>,
            <><strong>No asymmetric cryptography</strong> anywhere in the container path, enforced by a test. No RSA, no elliptic curves, no key exchange. Harvest-now-decrypt-later does not apply: there is no key exchange to record. Grover's algorithm halves the effective strength of a 256-bit key to about 128 bits, which is comfortable, and halves the effective entropy of your passphrase, which is the existing weakness restated.</>,
            <><strong>Old files keep opening.</strong> KEYM v1 and v2 containers and legacy IttyBitz files are covered by a fixture corpus of real ciphertexts from earlier releases, gated in CI.</>,
          ]} />
          <Callout kind="note" title="Updates never install themselves over a live page">
            The app is installable and works offline after the first load; every file the build emits is precached. A new version waits and asks before reloading, because a page may be mid-derivation holding key material.
          </Callout>
        </ChapterPanel>

        {/* 09 ------------------------------------------------------------ */}
        <ChapterPanel chapter={ch(8)}>
          <p>Ranked by how often ignoring one causes real loss. The first three cover most of it.</p>
          <Ranked items={[
            { title: "Store the password before you press Encrypt", body: <>In a password manager, or on paper in a safe place. There is no reset, and <em>I will remember it</em> is the sentence that precedes most lost data.</> },
            { title: "Verify before you delete the original", body: <>Turn on <strong>Verify only</strong>, open what you just made, and read the size. Thirty seconds now against an unrecoverable mistake later.</> },
            { title: "Set up a second way in while the plaintext exists", body: <>Recovery shares in different places, or a key file backed up like a password. A single memory is a single point of failure.</> },
            { title: "Use a generated password when you can", body: <><strong>Passphrase</strong> gives seven words and 90 bits you can copy off a card without a transcription error. It is not the weaker option. A typed password gets no strength figure because none would be honest.</> },
            { title: "Keep the defaults unless you can say why", body: <>Argon2id and AES-256-GCM are the reference settings. Every option in Advanced exists for a stated reason, and the table in chapter 02 names it.</> },
            { title: "Send the password by a different route than the container", body: <>The container can travel anywhere. If the password travels with it, the encryption protected nothing.</> },
            { title: "Keep the container on one line, or as a file", body: <>It is a single <code>keym2:</code> line by design. Chat clients and word processors that wrap or prettify text can make it unreadable. A <code>.keym</code> file has no such problem.</> },
            { title: "Print the recovery kit while the site is up", body: <>The procedure, <code>keym2.py</code>, and the two library wheels, beside the backup. The day you need them is the day you may not have a network.</> },
            { title: "Rehearse the shares", body: <>The shares dialog has <strong>Rehearse now</strong> for a reason. A share set you have never reconstructed from is a hypothesis, and a passing password test says nothing about it.</> },
            { title: "Treat the clipboard as public", body: <>Keymaker clears its own copy after 60 seconds, best effort. Clipboard history, clipboard managers and cloud clipboard sync keep theirs, and no web page can see or clear those.</> },
          ]} />
        </ChapterPanel>

        {/* 10 ------------------------------------------------------------ */}
        <ChapterPanel chapter={ch(9)}>
          <p>Each one has happened to someone. Ranked by cost.</p>
          <Ranked items={[
            { title: "Losing the password with no other way in", body: <><strong>Cost:</strong> the data, permanently. <strong>Avoid it:</strong> store the password durably in the same minute you create it, and add shares or a key file while the plaintext still exists.</> },
            { title: "Trusting a download that was never saved", body: <><strong>Cost:</strong> a backup that exists only in a receipt. <strong>Avoid it:</strong> Download is a request to the browser. Open your downloads folder and look, then verify from the saved file.</> },
            { title: "Sending the password with the container", body: <><strong>Cost:</strong> the encryption did nothing, and the pair is now archived and indexed. <strong>Avoid it:</strong> a different channel, always.</> },
            { title: "Keeping all the share strips together", body: <><strong>Cost:</strong> a threshold that protects against nothing. <strong>Avoid it:</strong> different places, different people. Any k strips open the container without the password.</> },
            { title: "Relying on a passkey as the only way in", body: <><strong>Cost:</strong> a backup that opens only at this website, in this browser profile. <strong>Avoid it:</strong> the format will not let you drop the password slot, and the docs will not let you forget why: a passkey is convenience, not an archive.</> },
            { title: "Choosing a cloud photo as a key file", body: <><strong>Cost:</strong> the data, the first time the library re-encodes the photo. <strong>Avoid it:</strong> generate the key file in the app, keep it where nothing syncs or optimises, and back it up like a password.</> },
            { title: "Converting the audio carrier to MP3", body: <><strong>Cost:</strong> the container inside it. <strong>Avoid it:</strong> keep the WAV. Lossy encoders rewrite the very bits that carry the secret.</> },
            { title: "Reading a generic failure as a corrupted file, or as a wrong password", body: <><strong>Cost:</strong> an afternoon, or a wrongly discarded backup. <strong>Avoid it:</strong> the app cannot tell the two apart on purpose. Check the password carefully, then get a fresh copy of the container by another route before concluding anything.</> },
            { title: "Copying a seed phrase on a machine with clipboard history", body: <><strong>Cost:</strong> the seed is still in the history after the 60-second clear. <strong>Avoid it:</strong> use the SeedQR export or type it into the wallet. Treat anything copied as still there.</> },
            { title: "Backing up something you have not read the size of", body: <><strong>Cost:</strong> the wrong month's file, verified and trusted. <strong>Avoid it:</strong> the verify result names the size. Compare it with what you meant to protect.</> },
          ]} />
        </ChapterPanel>

        {/* 11 ------------------------------------------------------------ */}
        <ChapterPanel chapter={ch(10)}>
          <p>Keymaker protects data at rest. Named plainly, because a vague disclaimer is a way of not saying anything.</p>
          <Bullets items={[
            <><strong>A compromised device.</strong> Malware, a keylogger or a hostile operating system sees the plaintext and the password as you type them. No web app can fix this, and one that implied otherwise would be lying.</>,
            <><strong>A malicious browser extension.</strong> Extensions run inside the page's origin with permission to read the DOM. The content security policy does not apply to them. One with access to this tab can read a secret before it is ever encrypted.</>,
            <><strong>The clipboard.</strong> Copying a container or a password puts it where every other app on the machine can read it, and on some platforms where it syncs to other devices. Keymaker clears its own copies on a timer; anything that read them in the meantime already has them.</>,
            <><strong>Someone looking at your screen.</strong> Secret fields blur by default and reveal toggles exist for that reason. A shoulder, a webcam and a screen recorder all defeat it.</>,
            <><strong>How long your plaintext is.</strong> The container is not padded, so its length reveals the plaintext's length exactly, byte for byte. If the mere size of what you are protecting is sensitive, that leaks regardless of the cipher.</>,
            <><strong>A weak password.</strong> Argon2id makes guessing expensive. It cannot make a guessable password unguessable.</>,
            <><strong>Forgetting the password.</strong> There is no reset, no recovery email and nobody to call. This is the failure that actually happens.</>,
          ]} />
          <H3>The trust anchor</H3>
          <p>
            A web app has the weakest trust anchor of any encryption tool: code delivered fresh on every visit by
            whoever controls the host. Keymaker's answer is not to deny it but to make it checkable. Every deployment
            ships a signed manifest, the build is byte-for-byte reproducible from a commit you can read, and the verify
            page tells you how to check the copy you were served. That narrows the gap. It does not close it. For the
            highest-value secrets, run a verified download offline, on a machine that never rejoins a network.
          </p>
          <H3>Known limits of this build</H3>
          <Table columns={["Limit", "Detail"]} rows={[
            ["Memory hygiene is best effort", "Buffers are zero-filled after use, but the JavaScript garbage collector may already have copied them. This cannot be fully solved in a browser."],
            ["100 MB per file", <>The tab holds the container and the recovered file at once. The format has no limit and <code>keym2.py</code> has none; a 150 MiB backup round-trips through it in about two seconds.</>],
            ["Argon2id needs WebAssembly", "Browsers that forbid it fall back to PBKDF2."],
            ["Passkeys are bound to this origin", "A copy of the app at another address, or the offline script, cannot use them. Every other way in survives both."],
            ["A deleted slot is silent to everyone but its owner", "Anyone holding the file can remove a way in. v3 detects and reports an edit made without a secret; it cannot prevent one."],
          ]} />
        </ChapterPanel>
      </div>
    </div>
  );
}
