/**
 * The "sealed" verdict: does this page's own CSP forbid egress the way the
 * sealed panel claims it does?
 *
 * The panel's claim is total — "forbidden to talk to any server, for every
 * request to anywhere". `connect-src 'none'` alone does not earn that: it stops
 * the scripted network APIs (fetch, XHR, WebSocket, EventSource, sendBeacon)
 * and nothing else. A `<form>` posting to an attacker is governed by
 * `form-action`, which does **not** fall back to `default-src`, so a build that
 * kept `connect-src 'none'` but dropped `form-action 'none'` could still
 * exfiltrate while the old verdict — keyed on `connect-src` alone — went on
 * calling it sealed. `default-src 'none'` is the fallback that refuses the rest
 * (media, object, script, …).
 *
 * So the verdict the panel is allowed to make requires all three, each read
 * from the served document, never typed here. This module is deliberately free
 * of React and the DOM so the decision is a pure function the parser test can
 * drive directly.
 */

/**
 * The directives the total-egress claim actually rests on. Every one must be
 * exactly `<name> 'none'` for the page to count as sealed:
 *  - default-src: the fallback that refuses media, object, script and the rest;
 *  - connect-src: fetch / XHR / WebSocket / EventSource / sendBeacon;
 *  - form-action: a form POST, which no `default-src` fallback covers.
 */
export const SEAL_REQUIRED_DIRECTIVES = ["default-src", "connect-src", "form-action"] as const;

/**
 * The full text of one directive from a CSP string, trimmed and with internal
 * whitespace collapsed, or null if the policy does not carry it. Matches the
 * directive name exactly so `connect-src` never picks up a longer name.
 */
export function pickDirective(csp: string, name: string): string | null {
  return (
    csp
      .split(";")
      .map((d) => d.trim().replace(/\s+/g, " "))
      .find((d) => d === name || d.startsWith(`${name} `)) ?? null
  );
}

/**
 * True only when the policy sets every egress-relevant directive to `'none'`.
 * A missing policy (`null`/`undefined`), a missing directive, or one set to
 * anything other than `'none'` is not sealed.
 */
export function isSealed(csp: string | null | undefined): boolean {
  if (!csp) return false;
  return SEAL_REQUIRED_DIRECTIVES.every((name) => pickDirective(csp, name) === `${name} 'none'`);
}
