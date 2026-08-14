/**
 * Argon2id auto-calibration — the solver, against synthetic devices.
 *
 * Roadmap 2.5. The measuring half is a stopwatch and needs no test; the
 * judgement half decides what parameters a user's backup is written with, and
 * it is only testable at all because `calibrateArgon2` takes measurements as
 * data rather than taking them itself.
 *
 * That buys the thing real hardware cannot give: devices that do not exist. A
 * machine fast enough to exhaust the ceiling, one too slow to reach the floor,
 * and one whose measurements are incoherent are all one object literal each,
 * and every CI runner sees the same three.
 *
 * The model is checked against its own closed form rather than against
 * remembered numbers. Each synthetic device is generated *from* a known
 * intercept and slope, so the expected answer can be computed independently
 * and a solver that quietly dropped the intercept would not match it.
 */
import { KdfId, validateKdfParams } from "../src/lib/keymaker-crypto.ts";
import {
  calibrateArgon2,
  describeCalibration,
  CALIBRATION_MEMORY_FLOOR_KIB,
  CALIBRATION_MEMORY_CEILING_KIB,
  FORMAT_MEMORY_MAX_KIB,
  type Argon2Sample,
} from "../src/lib/kdf-calibration.ts";

let passed = 0;
const failures: string[] = [];

function check(ok: boolean, label: string, detail = ""): void {
  if (ok) {
    passed++;
    console.log(`  ok   ${label}`);
  } else {
    failures.push(label);
    console.log(`  FAIL ${label}${detail ? `   ${detail}` : ""}`);
  }
}

const LOW_KIB = 8 * 1024;
const HIGH_KIB = 32 * 1024;

/**
 * A device is entirely described by a fixed per-call overhead and a per-KiB
 * cost. Sampling it is the same arithmetic the solver has to invert.
 */
function device(interceptMs: number, slopeMsPerKiB: number, timeCost = 1) {
  const at = (memoryKiB: number): Argon2Sample => ({
    timeCost,
    memoryKiB,
    elapsedMs: timeCost * (interceptMs + slopeMsPerKiB * memoryKiB),
  });
  return { low: at(LOW_KIB), high: at(HIGH_KIB), interceptMs, slopeMsPerKiB };
}

function memoryOf(params: { kdf: KdfId; params: Record<string, number> }): number {
  return params.kdf === KdfId.ARGON2ID ? (params.params.memoryKiB as number) : -1;
}

console.log("\nArgon2id calibration solver\n");

const BUDGET = 1000;
const T = 3;
const P = 4;

// --- the model is inverted correctly -----------------------------------------
console.log("The solver inverts its own cost model:");
{
  // A deliberately large intercept, because that is the term a one-point model
  // cannot see. 40 ms of fixed overhead on an 8 MiB sample is most of the
  // measurement, and attributing it to memory would make this device look
  // roughly three times slower than it is.
  const d = device(40, 0.0015);
  const c = calibrateArgon2({
    low: d.low,
    high: d.high,
    budgetMs: BUDGET,
    timeCost: T,
    parallelism: P,
    maxMemoryKiB: FORMAT_MEMORY_MAX_KIB,
  });

  const analytic = (BUDGET / T - d.interceptMs) / d.slopeMsPerKiB;
  const expected = Math.floor(analytic / 1024) * 1024;
  check(memoryOf(c.params) === expected, "memory matches the closed form",
    `got ${memoryOf(c.params)}, expected ${expected}`);
  check(c.limitedBy === "budget", "reports the budget as the binding constraint");

  // A solver that ignored the intercept would attribute all 56 ms of the low
  // sample to 8 MiB of memory and hand back roughly a third of this.
  const naive = Math.floor((BUDGET / T / (d.low.elapsedMs / LOW_KIB)) / 1024) * 1024;
  check(memoryOf(c.params) > naive * 1.5,
    "two-point fit beats the one-point model it replaces",
    `two-point ${memoryOf(c.params)} vs one-point ${naive}`);
}

// --- the three constraints ----------------------------------------------------
console.log("\nEach constraint is reported as the one that bound the answer:");
{
  // Absurdly fast: microseconds per MiB. Nothing real, which is the point.
  const fast = device(0.5, 0.000002);
  const c = calibrateArgon2({
    low: fast.low, high: fast.high, budgetMs: BUDGET, timeCost: T, parallelism: P,
  });
  check(c.limitedBy === "memory-ceiling", "a device faster than the ceiling says so");
  check(memoryOf(c.params) === CALIBRATION_MEMORY_CEILING_KIB,
    "and stops at the ceiling", String(memoryOf(c.params)));
  // The honest consequence: it will unlock *faster* than asked.
  check(c.predictedMs < BUDGET, "predicts under budget when ceiling-bound",
    `${c.predictedMs.toFixed(0)}ms`);

  const slow = device(400, 0.05);
  const s = calibrateArgon2({
    low: slow.low, high: slow.high, budgetMs: BUDGET, timeCost: T, parallelism: P,
  });
  check(s.limitedBy === "memory-floor", "a device slower than the floor says so");
  check(memoryOf(s.params) === CALIBRATION_MEMORY_FLOOR_KIB,
    "and stops at the floor", String(memoryOf(s.params)));
  // This is the case a bare number would misrepresent: the user asked for 1 s
  // and is going to wait longer, and the result has to admit it.
  check(s.predictedMs > BUDGET, "predicts over budget when floor-bound",
    `${s.predictedMs.toFixed(0)}ms`);
  check(describeCalibration(s, BUDGET).includes("over the"),
    "and the description says so rather than printing the target",
    describeCalibration(s, BUDGET));
}

// --- rounding never overshoots the budget -------------------------------------
console.log("\nRounding is downward, so a budget-bound answer never exceeds it:");
{
  let worst = 0;
  let overshoots = 0;
  for (let i = 0; i < 500; i++) {
    const d = device(5 + (i % 97), 0.00002 + (i % 31) * 0.00003);
    const c = calibrateArgon2({
      low: d.low, high: d.high, budgetMs: BUDGET, timeCost: T, parallelism: P,
      maxMemoryKiB: FORMAT_MEMORY_MAX_KIB,
    });
    if (c.limitedBy !== "budget") continue;
    if (c.predictedMs > BUDGET) {
      overshoots++;
      worst = Math.max(worst, c.predictedMs);
    }
  }
  check(overshoots === 0, "no budget-bound result predicts over budget",
    `${overshoots} overshoot(s), worst ${worst.toFixed(0)}ms`);
}

// --- every result is writable ------------------------------------------------
console.log("\nEvery result is a set of parameters the writer will accept:");
{
  // Tied to validateKdfParams rather than to a copy of §6's numbers here. If
  // the bounds ever move, this fails instead of quietly diverging.
  let rejected = 0;
  let outOfRange = 0;
  for (let i = 0; i < 500; i++) {
    const d = device(i * 0.9, 1e-7 * Math.pow(1.02, i));
    const c = calibrateArgon2({
      low: d.low, high: d.high, budgetMs: BUDGET, timeCost: T, parallelism: P,
    });
    const m = memoryOf(c.params);
    if (m < CALIBRATION_MEMORY_FLOOR_KIB || m > FORMAT_MEMORY_MAX_KIB) outOfRange++;
    try {
      validateKdfParams(c.params, "encrypt");
    } catch {
      rejected++;
    }
  }
  check(rejected === 0, "500 synthetic devices all produce writable parameters",
    `${rejected} rejected by validateKdfParams`);
  check(outOfRange === 0, "and all land inside the format's own bounds",
    `${outOfRange} out of range`);
}

// --- the format's ceiling outranks the caller's --------------------------------
console.log("\nA caller cannot raise the ceiling past what the format allows:");
{
  // The portability ceiling is the caller's to move — a caller who knows the
  // recovery device can reasonably ask for more than 128 MiB. §6's maximum is
  // not theirs to move, and a solver that took `maxMemoryKiB` at face value
  // would emit parameters no reader will accept. A control confirmed nothing
  // else in this file exercises that path.
  const fast = device(0.5, 0.000002);
  for (const asked of [FORMAT_MEMORY_MAX_KIB * 2, 1024 * 1024, Infinity]) {
    const c = calibrateArgon2({
      low: fast.low, high: fast.high, budgetMs: BUDGET, timeCost: T, parallelism: P,
      maxMemoryKiB: asked,
    });
    const m = memoryOf(c.params);
    check(m === FORMAT_MEMORY_MAX_KIB, `asking for ${asked} KiB is capped at the format maximum`,
      `got ${m}`);
    let writable = true;
    try {
      validateKdfParams(c.params, "encrypt");
    } catch {
      writable = false;
    }
    check(writable, `and the capped result is still writable`);
  }
}

// --- monotonicity -------------------------------------------------------------
console.log("\nA faster device never gets weaker parameters:");
{
  let inversions = 0;
  let previous = 0;
  for (let i = 20; i >= 1; i--) {
    // Strictly decreasing cost as i falls: strictly faster device each step.
    const d = device(10, 0.00001 * i);
    const c = calibrateArgon2({
      low: d.low, high: d.high, budgetMs: BUDGET, timeCost: T, parallelism: P,
      maxMemoryKiB: FORMAT_MEMORY_MAX_KIB,
    });
    const m = memoryOf(c.params);
    if (m < previous) inversions++;
    previous = m;
  }
  check(inversions === 0, "memory rises monotonically with device speed",
    `${inversions} inversion(s)`);
}

// --- incoherent measurements fall back ----------------------------------------
console.log("\nA measurement that does not describe a device is refused:");
{
  const good = device(20, 0.0001);
  const cases: Array<[string, Parameters<typeof calibrateArgon2>[0]]> = [
    ["zero elapsed time", {
      low: { ...good.low, elapsedMs: 0 }, high: good.high,
      budgetMs: BUDGET, timeCost: T, parallelism: P,
    }],
    ["negative elapsed time", {
      low: { ...good.low, elapsedMs: -5 }, high: good.high,
      budgetMs: BUDGET, timeCost: T, parallelism: P,
    }],
    ["samples at the same memory size", {
      low: good.low, high: { ...good.high, memoryKiB: good.low.memoryKiB },
      budgetMs: BUDGET, timeCost: T, parallelism: P,
    }],
    // More memory measured as no slower. Real devices do not do this; noisy
    // measurements of real devices do, and extrapolating from a flat or
    // negative slope produces a nonsense memory size rather than a wrong one.
    ["more memory measured as faster", {
      low: good.low, high: { ...good.high, elapsedMs: good.low.elapsedMs - 1 },
      budgetMs: BUDGET, timeCost: T, parallelism: P,
    }],
    ["identical timings at different sizes", {
      low: good.low, high: { ...good.high, elapsedMs: good.low.elapsedMs },
      budgetMs: BUDGET, timeCost: T, parallelism: P,
    }],
    ["NaN in a sample", {
      low: { ...good.low, elapsedMs: NaN }, high: good.high,
      budgetMs: BUDGET, timeCost: T, parallelism: P,
    }],
    ["a budget of zero", {
      low: good.low, high: good.high, budgetMs: 0, timeCost: T, parallelism: P,
    }],
  ];

  let wrong = 0;
  for (const [label, req] of cases) {
    const c = calibrateArgon2(req);
    const ok =
      c.limitedBy === "unusable-measurement" &&
      memoryOf(c.params) === 64 * 1024 &&
      (c.params.kdf === KdfId.ARGON2ID ? c.params.params.timeCost === 3 : false);
    if (!ok) wrong++;
    check(ok, `${label} falls back to the shipped default`,
      `limitedBy=${c.limitedBy} memory=${memoryOf(c.params)}`);
  }
  check(wrong === 0, "a failed calibration leaves the user where they started");
}

console.log(`\n${passed} passed, ${failures.length} failed`);
if (failures.length) {
  console.log("Calibration solver FAILED.");
  process.exit(1);
}
console.log("Calibration verified against synthetic devices, including impossible ones.");
