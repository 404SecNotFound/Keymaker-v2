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
 */
import {
  describeAccessRule,
  initialWorkflow,
  latestExports,
  settingsChanges,
  workflowReducer,
  type CreationSettings,
  type Workflow,
  type WorkflowEvent,
} from "../src/lib/backup-workflow.ts";

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

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
