/**
 * Argon2id auto-calibration — pick the strongest parameters that fit an unlock
 * budget on *this* device.
 *
 * Roadmap 2.5. KeePass does this; no browser tool does. The fixed 64 MiB
 * default is sound but it is a guess made once, for everyone: too slow on a
 * budget phone, and far weaker than a desktop could afford for the same wait.
 *
 * ## The measurement is not the interesting part
 *
 * Timing one Argon2id call is easy. Turning that into a parameter choice
 * involves three judgements, and all three are here rather than in the caller:
 *
 * 1. **A cost model.** Argon2id's running time is close to linear in
 *    `time_cost x memory`, but not through the origin — there is a fixed
 *    overhead per call (wasm instantiation, allocation, thread setup) that a
 *    single measurement cannot separate from the per-byte cost. Attributing
 *    that overhead to memory makes the device look slower than it is, so a
 *    one-point model always under-provisions. Two points at different memory
 *    sizes separate the intercept from the slope.
 *
 * 2. **A ceiling below the format's.** §6 permits up to 256 MiB. Calibration
 *    should not go there, and the reason has nothing to do with cryptography:
 *    **the device you encrypt on is not the device you recover on.** A
 *    container calibrated to a desktop's memory can be painful or impossible
 *    to open on the phone someone reaches for in ten years. The default
 *    ceiling here is deliberately half the format maximum.
 *
 * 3. **Honesty about which limit bound the answer.** "8 MiB" means something
 *    very different when it is the floor the device could not beat than when
 *    it is what the budget bought. `limitedBy` carries that so the UI can say
 *    which happened instead of just printing a number.
 *
 * This module is pure and has no dependency on the Worker, WebCrypto or
 * hash-wasm — the measuring is the caller's job. That is what makes the
 * judgements above testable against synthetic devices, including ones no
 * hardware in this room could impersonate.
 */

import { KdfId, validateKdfParams, type KdfParams } from "./keymaker-crypto";

/** One timed Argon2id run. `parallelism` is not modelled — see `calibrateArgon2`. */
export interface Argon2Sample {
  timeCost: number;
  memoryKiB: number;
  elapsedMs: number;
}

export interface CalibrationRequest {
  /** Two runs at the same parallelism and different memory sizes. */
  low: Argon2Sample;
  high: Argon2Sample;
  /** Unlock time to aim for, in milliseconds. */
  budgetMs: number;
  /** The `time_cost` the answer should use. Memory is what gets solved for. */
  timeCost: number;
  parallelism: number;
  /** Defaults to `CALIBRATION_MEMORY_CEILING_KIB`. */
  maxMemoryKiB?: number;
}

/** The two coefficients of the fitted cost model, per unit of `time_cost`. */
export interface DeviceFit {
  interceptMs: number;
  slopeMsPerKiB: number;
}

export interface Calibration {
  params: KdfParams;
  /**
   * The fitted model, so a caller can price parameters the solver did not
   * choose. This is what turns the settings panel's "≈Ns on a typical laptop"
   * guess into a number about the machine actually in front of the user, for
   * every slider position rather than only the calibrated one.
   *
   * Null when the measurement was rejected.
   */
  fit: DeviceFit | null;
  /** What the model expects an unlock to cost, in milliseconds. */
  predictedMs: number;
  /**
   * Which constraint decided the answer.
   *
   * - `budget` — the honest case: memory landed inside the range.
   * - `memory-ceiling` — the device is fast enough to exhaust the ceiling, so
   *   the real unlock will be *faster* than the budget.
   * - `memory-floor` — the device cannot reach the budget even at the minimum,
   *   so the real unlock will be *slower*. The number to show the user is
   *   `predictedMs`, not the budget they asked for.
   * - `unusable-measurement` — the samples did not describe a coherent device
   *   and the fixed default was returned untouched.
   */
  limitedBy: "budget" | "memory-ceiling" | "memory-floor" | "unusable-measurement";
}

/**
 * §6's bounds, restated for the solver. `validateKdfParams` remains the
 * authority — `kdf-calibration-test.mts` pushes every result through it rather
 * than trusting that these two lists agree.
 */
export const CALIBRATION_MEMORY_FLOOR_KIB = 8 * 1024; // §6 write policy minimum
export const FORMAT_MEMORY_MAX_KIB = 256 * 1024; // §6 read maximum

/**
 * Half the format maximum, and not for a cryptographic reason — see the note
 * on portability at the top of this file. Callers who know the recovery device
 * can raise it.
 */
export const CALIBRATION_MEMORY_CEILING_KIB = 128 * 1024;

/** Memory is reported in whole MiB, so the number a user sees is a round one. */
const MEMORY_GRANULARITY_KIB = 1024;

/**
 * The answer when the measurement cannot be trusted. Deliberately the shipped
 * default rather than something clever: a calibration that failed should leave
 * the user exactly where they would have been without it.
 */
const FALLBACK: KdfParams = {
  kdf: KdfId.ARGON2ID,
  params: { timeCost: 3, memoryKiB: 64 * 1024, parallelism: 4 },
};

function usable(s: Argon2Sample): boolean {
  return (
    Number.isFinite(s.elapsedMs) &&
    s.elapsedMs > 0 &&
    Number.isFinite(s.memoryKiB) &&
    s.memoryKiB > 0 &&
    Number.isFinite(s.timeCost) &&
    s.timeCost > 0
  );
}

/**
 * Fit `elapsed ≈ timeCost * (intercept + slope * memoryKiB)` through two
 * samples, normalising each by its own `timeCost` first so the two can be
 * compared even if they were measured at different ones.
 *
 * Null when the samples do not describe a device — see `calibrateArgon2` for
 * why a non-positive slope is treated as noise rather than extrapolated from.
 */
export function fitDevice(low: Argon2Sample, high: Argon2Sample): DeviceFit | null {
  if (!usable(low) || !usable(high) || high.memoryKiB <= low.memoryKiB) return null;

  const unitLow = low.elapsedMs / low.timeCost;
  const unitHigh = high.elapsedMs / high.timeCost;
  const slopeMsPerKiB = (unitHigh - unitLow) / (high.memoryKiB - low.memoryKiB);
  const interceptMs = unitLow - slopeMsPerKiB * low.memoryKiB;

  if (!(slopeMsPerKiB > 0) || !Number.isFinite(interceptMs)) return null;
  return { interceptMs, slopeMsPerKiB };
}

/** Price any parameter pair against a fitted device. */
export function predictArgon2Ms(fit: DeviceFit, timeCost: number, memoryKiB: number): number {
  return timeCost * (fit.interceptMs + fit.slopeMsPerKiB * memoryKiB);
}

/**
 * Solve for the largest memory size whose predicted unlock fits `budgetMs`.
 */
export function calibrateArgon2(req: CalibrationRequest): Calibration {
  const { low, high, budgetMs, timeCost, parallelism } = req;
  const ceiling = Math.min(
    req.maxMemoryKiB ?? CALIBRATION_MEMORY_CEILING_KIB,
    FORMAT_MEMORY_MAX_KIB
  );

  const budgetOk =
    Number.isFinite(budgetMs) &&
    budgetMs > 0 &&
    Number.isFinite(timeCost) &&
    timeCost >= 1 &&
    ceiling >= CALIBRATION_MEMORY_FLOOR_KIB;

  // A non-positive slope means more memory measured as no slower, which no real
  // device does. It is noise — a scheduler hiccup, a throttled core waking up —
  // and extrapolating from it produces either a negative memory size or an
  // absurd one. `fitDevice` returns null rather than letting that through.
  const fit = budgetOk ? fitDevice(low, high) : null;
  if (!fit) {
    return { params: FALLBACK, fit: null, predictedMs: NaN, limitedBy: "unusable-measurement" };
  }

  const { interceptMs: intercept, slopeMsPerKiB: slope } = fit;
  const solved = (budgetMs / timeCost - intercept) / slope;

  // Round *down* to whole MiB. Rounding to nearest would let the result exceed
  // the budget it was asked to fit, which is the one direction that matters:
  // an unlock slower than promised is the complaint, a faster one is not.
  let memoryKiB = Math.floor(solved / MEMORY_GRANULARITY_KIB) * MEMORY_GRANULARITY_KIB;

  let limitedBy: Calibration["limitedBy"] = "budget";
  if (!Number.isFinite(memoryKiB) || memoryKiB < CALIBRATION_MEMORY_FLOOR_KIB) {
    memoryKiB = CALIBRATION_MEMORY_FLOOR_KIB;
    limitedBy = "memory-floor";
  } else if (memoryKiB > ceiling) {
    memoryKiB = ceiling;
    limitedBy = "memory-ceiling";
  }

  const params: KdfParams = {
    kdf: KdfId.ARGON2ID,
    params: { timeCost, memoryKiB, parallelism },
  };

  // Every result must be a set of parameters the writer will accept, and this
  // asks the writer rather than restating its bounds.
  //
  // The bounds were being restated, and incompletely: `budgetOk` above checks
  // budgetMs, timeCost and the memory ceiling, and `parallelism` was
  // destructured from the request and returned untouched. A caller passing 0,
  // NaN or 4.5 got a Calibration whose params no encrypt would accept — from a
  // function whose contract is that they always are. `timeCost` was half
  // checked too: finite and >= 1, with no ceiling and no integer requirement.
  //
  // Duplicating the ranges here would just move the drift. Asking the
  // authoritative validator cannot drift, and it covers fields added later
  // without this function being touched.
  try {
    validateKdfParams(params, "encrypt");
  } catch {
    return { params: FALLBACK, fit, predictedMs: NaN, limitedBy: "unusable-measurement" };
  }

  return {
    params,
    fit,
    predictedMs: predictArgon2Ms(fit, timeCost, memoryKiB),
    limitedBy,
  };
}

/**
 * A one-line summary for the UI, phrased so that a clamped result does not read
 * as if the budget was met.
 */
export function describeCalibration(c: Calibration, budgetMs: number): string {
  const mib = Math.round(
    (c.params.kdf === KdfId.ARGON2ID ? c.params.params.memoryKiB : 0) / 1024
  );
  const secs = (ms: number) => `${(ms / 1000).toFixed(1)} s`;

  switch (c.limitedBy) {
    case "budget":
      return `${mib} MiB — about ${secs(c.predictedMs)} to unlock on this device.`;
    case "memory-ceiling":
      return (
        `${mib} MiB — this device could go faster still, but ${mib} MiB is the ` +
        `ceiling, so a phone can also open the file. About ${secs(c.predictedMs)} here.`
      );
    case "memory-floor":
      return (
        `${mib} MiB — the minimum. This device needs about ${secs(c.predictedMs)}, ` +
        `which is over the ${secs(budgetMs)} target; lowering it further would ` +
        `weaken the file rather than speed it up much.`
      );
    case "unusable-measurement":
      return "Measurement was inconsistent — the standard settings were kept.";
  }
}
