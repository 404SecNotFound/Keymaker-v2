/**
 * The build-time egress gate: which CSP directives must be `'none'` for the
 * zero-network claim to hold, and a check the post-build step and its test both
 * call.
 *
 * `connect-src 'none'` has been gated since KM-07, but it stops only the
 * scripted network APIs (fetch/XHR/WebSocket/EventSource/sendBeacon). A `<form>`
 * POST is governed by `form-action`, which does not fall back to `default-src`,
 * and `default-src 'none'` refuses the rest. So the guarantee rests on all
 * three, and the build must fail if a future edit drops any of them from a
 * shipped page's CSP — the build-time counterpart of the runtime sealed verdict
 * in `src/lib/seal-verdict.ts`. This lives in Node, and duplicates that tiny
 * predicate, because the build script cannot import the browser TypeScript.
 */

/** Every directive that must be exactly `<name> 'none'` in a shipped CSP. */
export const EGRESS_DIRECTIVES = ["default-src", "connect-src", "form-action"];

/**
 * The full text of one directive from a decoded CSP string, trimmed and with
 * internal whitespace collapsed, or null if absent. Matches the name exactly so
 * `connect-src` never picks up a longer directive.
 */
export function pickDirective(policy, name) {
  return (
    policy
      .split(";")
      .map((d) => d.trim().replace(/\s+/g, " "))
      .find((d) => d === name || d.startsWith(`${name} `)) ?? null
  );
}

/**
 * The egress directives that are not exactly `'none'` in `policy`, each as
 * `{ name, value }` with `value` the directive as written or null when missing.
 * An empty array means the policy is sealed against egress.
 */
export function egressViolations(policy) {
  return EGRESS_DIRECTIVES.map((name) => ({ name, value: pickDirective(policy, name) })).filter(
    ({ name, value }) => value !== `${name} 'none'`
  );
}
