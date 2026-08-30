/**
 * When to retry a worker readiness probe, and when to stop paying for it.
 *
 * Extracted from `crypto-client.ts` so it can be tested at all. The wiring in
 * `ready()` resisted every browser test attempted — `page.route` never sees the
 * request the second `new Worker()` makes, the fix terminates the stalled worker
 * before its script lands so no worker event fires, and the later construction
 * is served from cache so no fetch happens. A responsiveness test written
 * against it passed with the fix reverted and was deleted. See `ready()` for the
 * full account.
 *
 * **So this pins the policy, not the wiring.** That is a real gap and is stated
 * rather than papered over: these tests cannot tell you `ready()` calls this
 * correctly. What they can tell you is that the decision itself — the part with
 * an off-by-one in it, and the part whose reset rule is easy to forget — is what
 * it is supposed to be.
 *
 * ## The decision
 *
 * Two failures are indistinguishable from the page's side and want opposite
 * answers. A cold cache fetching the worker script over a slow link is
 * transient, and treating it as permanent costs every later Argon2id derivation
 * a frozen tab. A worker that will never answer is permanent, and re-probing it
 * costs 10 s of every operation forever.
 *
 * Retrying once separates them for a bounded worst case. A probe that *answers*
 * clears the count, because the earlier timeout was then the slow link it was
 * assumed to be and should not be held against a later, unrelated hiccup.
 */

/** Timeouts tolerated before the worker is abandoned for the session. */
export const MAX_PROBE_TIMEOUTS = 2;

export type ProbeDecision = "retry" | "give-up";

/**
 * The probe outcome tally for one page session.
 *
 * Deliberately a tiny object rather than two module-level variables: module
 * state cannot be reset between test cases, and a policy that cannot be
 * exercised twice in one process is a policy nobody tests.
 */
export class ProbePolicy {
  private timeouts = 0;

  /** A probe timed out. Returns whether the next call should try again. */
  onTimeout(): ProbeDecision {
    this.timeouts += 1;
    return this.timeouts >= MAX_PROBE_TIMEOUTS ? "give-up" : "retry";
  }

  /** A probe answered. The slate is clean. */
  onAnswer(): void {
    this.timeouts = 0;
  }

  /** How many timeouts have gone unanswered. Exposed for assertions only. */
  get unanswered(): number {
    return this.timeouts;
  }
}
