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
  check("with format detail on, nothing is trimmed",
    atDetail("Argon2id · 64 MiB · t=3 · p=4", true) === "Argon2id · 64 MiB · t=3 · p=4");
}

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
