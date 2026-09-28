/**
 * The backup workflow's rules (roadmap Section 06), without a browser.
 *
 * `src/lib/backup-workflow.ts` decides what the page may say about the backup
 * on screen. The rule that matters most is that a job the user has moved on
 * from cannot put the page back into a success state: its result, its
 * failure and its end are ignored once another job has started or the page
 * has been cleared. The page checks for staleness before it writes anything;
 * this is the second check, and these are its cases.
 *
 * The negative control is to drop the job comparison from the reducer; the
 * "stale" checks below must fail.
 *
 * Part b adds the visible step order. Its rule is that no step is shown as
 * done on evidence the page does not have: a started download or print is
 * never a checked copy, a partial printout check is never a whole one, and a
 * rehearsal that has not run is never a prepared recovery.
 *
 * Part c adds the "Format detail" switch. Off, KDF parameters go and
 * everything else stays: the KDF and cipher names, the version, and every
 * warning, including one that quotes a number.
 *
 * Part d holds a verify result to what it checked: another backup, key file,
 * unlock method or newly typed credentials each make it stop applying.
 *
 * Part e counts a verify of this exact backup as evidence: a recovery test,
 * and a saved-copy check when the bytes came from a file on disk.
 */
import {
  describeAccessRule,
  initialWorkflow,
  latestExports,
  mergePrintoutCoverage,
  settingsChanges,
  workflowReducer,
  workflowSteps,
  type CreationSettings,
  type StepInputs,
  type StepState,
  type Workflow,
  type WorkflowEvent,
} from "../src/lib/backup-workflow.ts";
import { atDetail, withoutKdfParameters } from "../src/lib/detail-level.ts";
import { verifyChanges, type VerifiedInput } from "../src/lib/verify-evidence.ts";

let passed = 0;
let failed = 0;
function check(name: string, ok: boolean, detail = "") {
  if (ok) {
    passed++;
    console.log(`ok    ${name}`);
  } else {
    failed++;
    console.log(`FAIL  ${name}${detail ? ` (${detail})` : ""}`);
  }
}

const run = (events: WorkflowEvent[], from: Workflow = initialWorkflow) => events.reduce(workflowReducer, from);

const SETTINGS: CreationSettings = {
  inputType: "text",
  kdf: "Argon2id · 64 MiB · t=3 · p=4",
  cipher: "AES-256-GCM",
  padded: false,
  waysIn: [{ kind: "password", keyFile: false }],
};

// ---------------------------------------------------------------------------
// The ordinary path.
// ---------------------------------------------------------------------------
{
  const s = run([{ type: "job-started", job: 1 }]);
  check("a started job is working", s.phase === "working" && s.job === 1);
  const done = run([{ type: "sealed", job: 1, settings: SETTINGS }], s);
  check("its own result creates the backup", done.phase === "created" && done.job === 1);
  const ended = run([{ type: "job-ended", job: 1 }], done);
  check("the job's end after its result changes nothing", ended === done);
  check("a failed or stopped job returns to editing",
    run([{ type: "job-started", job: 2 }, { type: "job-ended", job: 2 }]).phase === "editing");
}

// ---------------------------------------------------------------------------
// Stale jobs.
// ---------------------------------------------------------------------------
{
  // Job 1 started, the user started job 2, then job 1's result arrived.
  const s = run([{ type: "job-started", job: 1 }, { type: "job-started", job: 2 }, { type: "sealed", job: 1, settings: SETTINGS }]);
  check("stale: an old job's result does not create a backup while a newer job runs",
    s.phase === "working" && s.job === 2, JSON.stringify(s));

  const t = run([{ type: "job-started", job: 1 }, { type: "job-started", job: 2 }, { type: "job-ended", job: 1 }]);
  check("stale: an old job's end does not end the newer job's wait",
    t.phase === "working" && t.job === 2, JSON.stringify(t));

  // Job 1 started, the page was cleared (a wipe or a switch), then its result arrived.
  const u = run([{ type: "job-started", job: 1 }, { type: "cleared" }, { type: "sealed", job: 1, settings: SETTINGS }]);
  check("stale: a result arriving after the page was cleared does not create a backup",
    u.phase === "editing", JSON.stringify(u));

  // Backup from job 1 on screen; job 2 started and failed; job 1's duplicate result arrives.
  const v = run([
    { type: "job-started", job: 1 },
    { type: "sealed", job: 1, settings: SETTINGS },
    { type: "job-started", job: 2 },
    { type: "job-ended", job: 2 },
    { type: "sealed", job: 1, settings: SETTINGS },
  ]);
  check("stale: a failed new job does not bring back the previous backup",
    v.phase === "editing", JSON.stringify(v));
}

// ---------------------------------------------------------------------------
// Exports.
// ---------------------------------------------------------------------------
{
  const created = run([{ type: "job-started", job: 1 }, { type: "sealed", job: 1, settings: SETTINGS }]);
  const exported = run([
    { type: "export-started", how: "download", at: "2026-01-01T10:00:00.000Z" },
    { type: "export-started", how: "print", at: "2026-01-01T10:05:00.000Z" },
    { type: "export-started", how: "download", at: "2026-01-01T10:09:00.000Z" },
  ], created);
  const latest = latestExports(exported);
  check("exports are recorded against the backup, latest of each kind",
    latest.download === "2026-01-01T10:09:00.000Z" && latest.print === "2026-01-01T10:05:00.000Z");
  check("an export with no backup is not recorded",
    Object.keys(latestExports(run([{ type: "export-started", how: "download", at: "x" }]))).length === 0);
  check("a new job forgets the previous backup's exports",
    Object.keys(latestExports(run([{ type: "job-started", job: 2 }], exported))).length === 0);
  check("clearing the page forgets them",
    Object.keys(latestExports(run([{ type: "cleared" }], exported))).length === 0);
}

// ---------------------------------------------------------------------------
// What changed since the backup was made.
// ---------------------------------------------------------------------------
{
  check("the same settings are no change", settingsChanges(SETTINGS, { ...SETTINGS }).length === 0);
  const cases: [string, Partial<CreationSettings>][] = [
    ["access rule", { waysIn: [{ kind: "password", keyFile: false }, { kind: "shares", threshold: 2, count: 3 }] }],
    ["access rule", { waysIn: [{ kind: "password", keyFile: true }] }],
    ["key derivation", { kdf: "PBKDF2 · 1,000,000 iterations" }],
    ["cipher", { cipher: "ChaCha20-Poly1305" }],
    ["size hiding", { padded: true }],
    ["input type", { inputType: "file" }],
  ];
  for (const [aspect, change] of cases) {
    const got = settingsChanges(SETTINGS, { ...SETTINGS, ...change });
    check(`changing ${JSON.stringify(change)} is reported as "${aspect}" and nothing else`,
      got.length === 1 && got[0] === aspect, got.join(", "));
  }
  // §4.8 versus OR is an access-rule change even with the same k and n.
  const or = [{ kind: "password", keyFile: false }, { kind: "shares", threshold: 2, count: 3 }] as const;
  const and = [{ kind: "password-and-shares", keyFile: false, threshold: 2, count: 3 }] as const;
  check("switching shares from OR to AND is an access-rule change",
    settingsChanges({ ...SETTINGS, waysIn: [...or] }, { ...SETTINGS, waysIn: [...and] }).includes("access rule"));
}

// ---------------------------------------------------------------------------
// The rule shown before creation.
// ---------------------------------------------------------------------------
check("one way in is said as itself", describeAccessRule(["Passphrase"]) === "Passphrase");
check("two ways in are joined with or",
  describeAccessRule(["Passphrase", "2-of-3 recovery shares"]) === "Passphrase or 2-of-3 recovery shares");
check("three ways in are listed, then or",
  describeAccessRule(["Passphrase", "2-of-3 recovery shares", "passkey"]) ===
    "Passphrase, 2-of-3 recovery shares or passkey");
check("an AND way in keeps its own wording",
  describeAccessRule(["Passphrase and 2-of-3 recovery shares, both needed"]) ===
    "Passphrase and 2-of-3 recovery shares, both needed");

// ---------------------------------------------------------------------------
// Part b: the visible step order.
// ---------------------------------------------------------------------------
{
  const created = run([{ type: "job-started", job: 1 }, { type: "sealed", job: 1, settings: SETTINGS }]);
  const base: StepInputs = {
    workflow: initialWorkflow,
    hasContent: false,
    credentialReady: false,
    changed: null,
    keptOnScreen: null,
    exports: {},
    printout: null,
    hasShares: false,
    rehearsed: false,
  };
  const states = (i: StepInputs) => workflowSteps(i).map((s) => s.state);
  const stateOf = (i: StepInputs, id: string): StepState | undefined =>
    workflowSteps(i).find((s) => s.id === id)?.state;
  const eq = (a: unknown[], b: unknown[]) => JSON.stringify(a) === JSON.stringify(b);

  check("there are six steps, in the order the roadmap names",
    eq(workflowSteps(base).map((s) => s.id), ["content", "access", "review", "create", "saved-copy", "recovery"]));
  check("an empty form: content is next, nothing is done",
    eq(states(base), ["current", "todo", "todo", "todo", "todo", "todo"]), states(base).join(","));
  check("content alone makes the access rule next",
    eq(states({ ...base, hasContent: true }), ["done", "current", "todo", "todo", "todo", "todo"]));
  check("a password alone does not mark content done",
    stateOf({ ...base, credentialReady: true }, "content") === "current");
  check("content and a password make review next",
    eq(states({ ...base, hasContent: true, credentialReady: true }), ["done", "done", "current", "todo", "todo", "todo"]));
  const working = run([{ type: "job-started", job: 1 }]);
  check("while encrypting, creation is working and nothing is next",
    eq(states({ ...base, workflow: working }), ["done", "done", "done", "working", "todo", "todo"]),
    states({ ...base, workflow: working }).join(","));

  const made: StepInputs = { ...base, workflow: created, keptOnScreen: true };
  check("a new backup: created, and the saved copy is next",
    eq(states(made), ["done", "done", "done", "done", "current", "todo"]), states(made).join(","));
  check("a started download is started, not done",
    stateOf({ ...made, exports: { download: "2026-09-28T10:00:00Z" } }, "saved-copy") === "started");
  check("a started print is started, not done",
    stateOf({ ...made, exports: { print: "2026-09-28T10:00:00Z" } }, "saved-copy") === "started");
  check("a file-mode backup, downloaded when written, is started, not done",
    stateOf({ ...made, keptOnScreen: false }, "saved-copy") === "started");
  check("once a copy is started, recovery becomes next",
    stateOf({ ...made, exports: { download: "x" } }, "recovery") === "current");
  check("a partial printout check is started, not done",
    stateOf({ ...made, printout: { checked: [1], total: 3 } }, "saved-copy") === "started");
  check("every printed symbol matched is done",
    stateOf({ ...made, printout: { checked: [1, 2, 3], total: 3 } }, "saved-copy") === "done");
  check("recovery is not done until a rehearsal opens the backup",
    stateOf({ ...made, hasShares: true, printout: { checked: [1], total: 1 } }, "recovery") === "current");
  check("a rehearsal that opened it makes recovery done",
    stateOf({ ...made, hasShares: true, rehearsed: true }, "recovery") === "done");
  const changed = states({ ...made, changed: ["cipher"] });
  check("a changed form flags creation and makes nothing else next",
    eq(changed, ["done", "done", "done", "changed", "todo", "todo"]), changed.join(","));
  check("the change notice names what changed",
    workflowSteps({ ...made, changed: ["content", "cipher"] })[3]!.detail.includes("content, cipher"));
  check("at most one step is next, in every combination tried", (() => {
    for (const wf of [initialWorkflow, working, created])
      for (const hasContent of [false, true])
        for (const credentialReady of [false, true])
          for (const rehearsed of [false, true])
            for (const exports of [{}, { download: "x" }]) {
              const n = states({ ...base, workflow: wf, hasContent, credentialReady, rehearsed, exports,
                keptOnScreen: wf.phase === "created" ? true : null }).filter((s) => s === "current").length;
              if (n > 1) return false;
            }
    return true;
  })());
  check("a cleared page goes back to content being next",
    stateOf({ ...base, workflow: run([{ type: "cleared" }], created) }, "content") === "current");

  // The printout coverage behind "Check saved copy".
  const part = (index: number, total: number, belongs: "yes" | "no" | "unknown") =>
    ({ kind: "part", index, total, belongs }) as const;
  check("a matched symbol counts",
    eq(mergePrintoutCoverage(null, [part(2, 3, "yes")])?.checked ?? [], [2]));
  check("a symbol from another backup does not count",
    mergePrintoutCoverage(null, [part(1, 3, "no")]) === null);
  check("a symbol that cannot be matched does not count",
    mergePrintoutCoverage(null, [part(1, 3, "unknown")]) === null);
  check("a recovery strip is not the saved copy",
    mergePrintoutCoverage(null, [{ kind: "strip", index: 1, threshold: 2, setCode: null, belongs: "yes" }]) === null);
  check("a damaged symbol does not count",
    mergePrintoutCoverage(null, [{ kind: "part-damaged", index: 1, total: 3 }]) === null);
  const one = mergePrintoutCoverage(null, [part(1, 3, "yes")]);
  const two = mergePrintoutCoverage(one, [part(3, 3, "yes"), part(3, 3, "yes")]);
  check("checks accumulate, and a symbol seen twice counts once", eq(two?.checked ?? [], [1, 3]), JSON.stringify(two));
  check("the whole backup in one code covers it",
    eq(mergePrintoutCoverage(null, [{ kind: "backup", belongs: "yes" }]) ?? {}, { checked: [1], total: 1 }));
}

// ---------------------------------------------------------------------------
// Part c: the format detail switch.
// ---------------------------------------------------------------------------
{
  const trim = withoutKdfParameters;
  check("Argon2id keeps its name and loses its parameters",
    trim("Argon2id · 64 MiB · t=3 · p=4") === "Argon2id", trim("Argon2id · 64 MiB · t=3 · p=4"));
  check("PBKDF2 keeps its name and loses its iterations",
    trim("PBKDF2 · 1,000,000 iterations") === "PBKDF2");
  check("a passkey slot keeps both algorithm names",
    trim("WebAuthn PRF · HKDF-SHA-256") === "WebAuthn PRF · HKDF-SHA-256");
  check("a password-and-shares slot keeps \"both needed\"",
    trim("both needed · Argon2id · 64 MiB") === "both needed · Argon2id");
  const unlocked =
    "Format: KEYM v3 · PBKDF2 · 1,000,000 iterations · AES-256-GCM · 2 slots (read from the file, not authenticated)" +
    " · key file";
  check("the unlock line keeps the version, the cipher, the slot note and the key file",
    trim(unlocked) === "Format: KEYM v3 · PBKDF2 · AES-256-GCM · 2 slots (read from the file, not authenticated) · key file",
    trim(unlocked));
  const warned =
    "Format: KEYM v3 · PBKDF2 · 100,000 iterations · AES-256-GCM — Heads up: this backup was made with " +
    "100,000 PBKDF2 iterations, below the 1,000,000 this version writes. It opened fine.";
  check("a weak-KDF warning keeps the numbers it quotes",
    trim(warned).includes("made with 100,000 PBKDF2 iterations, below the 1,000,000 this version writes"), trim(warned));
  check("a label with no parameters is unchanged", trim("AES-256-GCM") === "AES-256-GCM");
  // The readers' shape, which the unlock line uses: parameters in brackets.
  check("the reader's PBKDF2 label loses its bracketed iterations",
    trim("Format: KEYM v3 · PBKDF2 (1,000,000 iters) · AES-256-GCM") === "Format: KEYM v3 · PBKDF2 · AES-256-GCM",
    trim("Format: KEYM v3 · PBKDF2 (1,000,000 iters) · AES-256-GCM"));
  check("the reader's Argon2id label loses its bracketed parameters",
    trim("Argon2id (64 MiB, t=3, p=4)") === "Argon2id", trim("Argon2id (64 MiB, t=3, p=4)"));
  check("a both-needed slot keeps the KDF name inside its bracket",
    trim("password and share set, both needed (PBKDF2 1,000,000 iters)") ===
      "password and share set, both needed (PBKDF2)",
    trim("password and share set, both needed (PBKDF2 1,000,000 iters)"));
  check("a bracket naming an algorithm is kept",
    trim("passkey / WebAuthn PRF (HKDF-SHA-256)") === "passkey / WebAuthn PRF (HKDF-SHA-256)");
  const readerWarned =
    "Format: KEYM v3 · PBKDF2 (100,000 iters) · AES-256-GCM — Heads up: this backup was made with " +
    "100,000 PBKDF2 iterations, below the 1,000,000 this version writes. It opened fine.";
  check("the reader's shape keeps a weak-KDF warning's numbers too",
    trim(readerWarned).includes("made with 100,000 PBKDF2 iterations, below the 1,000,000 this version writes") &&
      !trim(readerWarned).includes("(100,000 iters)"),
    trim(readerWarned));
  check("with format detail on, nothing is trimmed",
    atDetail("Argon2id · 64 MiB · t=3 · p=4", true) === "Argon2id · 64 MiB · t=3 · p=4");
}

// ---------------------------------------------------------------------------
// Part d: a verify result belongs to what it checked.
// ---------------------------------------------------------------------------
{
  // Files are compared by identity, as the page compares File objects.
  const fileA = { name: "a.keym" };
  const fileB = { name: "a.keym" };
  const key = { name: "key" };
  const text: VerifiedInput<object> = {
    inputType: "text", file: null, text: "keym2:AAAA", keyFile: null, useShares: false, usePasskey: false,
  };
  const inFile: VerifiedInput<object> = { ...text, inputType: "file", file: fileA, text: "" };
  const eq = (a: unknown[], b: unknown[]) => JSON.stringify(a) === JSON.stringify(b);

  check("the same input, nothing typed since: the result applies", verifyChanges(text, { ...text }, false).length === 0);
  check("another pasted container is another backup",
    eq(verifyChanges(text, { ...text, text: "keym2:BBBB" }, false), ["backup"]));
  check("a file picked again is another backup, even with the same name",
    eq(verifyChanges(inFile, { ...inFile, file: fileB }, false), ["backup"]));
  check("the same file object still applies", verifyChanges(inFile, { ...inFile }, false).length === 0);
  check("switching between file and text is another backup",
    verifyChanges(text, { ...inFile }, false).includes("backup"));
  check("in file mode, leftover text in the other box does not count",
    verifyChanges(inFile, { ...inFile, text: "keym2:CCCC" }, false).length === 0);
  check("adding a key file is reported", eq(verifyChanges(text, { ...text, keyFile: key }, false), ["key file"]));
  check("switching to shares is a change of unlock method",
    eq(verifyChanges(text, { ...text, useShares: true }, false), ["unlock method"]));
  check("switching to a passkey is a change of unlock method",
    eq(verifyChanges(text, { ...text, usePasskey: true }, false), ["unlock method"]));
  check("a password typed since is reported as credentials", eq(verifyChanges(text, { ...text }, true), ["credentials"]));
  check("several changes are all named, in order",
    eq(verifyChanges(text, { ...text, text: "x", keyFile: key, useShares: true }, true),
      ["backup", "key file", "unlock method", "credentials"]));
}

// ---------------------------------------------------------------------------
// Part e: a verify of this exact backup is evidence.
// ---------------------------------------------------------------------------
{
  const made = run([{ type: "job-started", job: 7 }, { type: "sealed", job: 7, settings: SETTINGS }]);
  const pasted = { how: "passphrase" as const, fromFile: false, at: "2026-09-28T16:00:00Z" };
  const loaded = { how: "passphrase" as const, fromFile: true, at: "2026-09-28T16:05:00Z" };
  const stepsOf = (wf: Workflow) =>
    workflowSteps({
      workflow: wf, hasContent: false, credentialReady: false, changed: null, keptOnScreen: true,
      exports: {}, printout: null, hasShares: false, rehearsed: false,
    });
  const stateOf = (wf: Workflow, id: string) => stepsOf(wf).find((st) => st.id === id)?.state;

  check("a verify is ignored before a backup exists",
    JSON.stringify(run([{ type: "verified", check: pasted }])) === JSON.stringify(initialWorkflow));
  check("a verify is ignored while a job is running",
    JSON.stringify(run([{ type: "job-started", job: 8 }, { type: "verified", check: pasted }])) ===
      JSON.stringify({ phase: "working", job: 8 }));
  const afterPaste = run([{ type: "verified", check: pasted }], made);
  check("a verify is recorded on the backup it opened",
    afterPaste.phase === "created" && afterPaste.verified.length === 1);
  check("a pasted verify makes recovery done", stateOf(afterPaste, "recovery") === "done");
  check("a pasted verify is not a saved copy: the page pasted its own copy",
    stateOf(afterPaste, "saved-copy") !== "done", String(stateOf(afterPaste, "saved-copy")));
  const afterLoad = run([{ type: "verified", check: loaded }], made);
  check("a verify of a loaded file makes the saved copy done", stateOf(afterLoad, "saved-copy") === "done");
  check("and recovery done", stateOf(afterLoad, "recovery") === "done");
  check("the recovery sentence names what opened it",
    stepsOf(run([{ type: "verified", check: { ...pasted, how: "shares" } }], made))
      .find((st) => st.id === "recovery")!.detail.includes("the recovery shares"));
  check("a new job drops the evidence of the old backup",
    run([{ type: "verified", check: loaded }, { type: "job-started", job: 9 }], made).phase === "working");
  check("a wipe drops it", run([{ type: "verified", check: loaded }, { type: "cleared" }], made).phase === "editing");
}

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
