/**
 * The "sealed" verdict: does this page's own CSP forbid egress the way the
 * sealed panel claims it does?
 *
 * The panel's claim used to be total ("forbidden to talk to any server, for
 * every request to anywhere"), and no page policy earns that. It is now the
 * narrower one in SEALED_CLAIM below. `connect-src 'none'` alone does not earn
 * even that: it stops
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

/**
 * What the panel says about a sealed page, and the whole of it.
 *
 * The three directives above stop the scripted connection APIs, a form post and
 * any load from another server. They do not govern moving the tab to another
 * address (`location.href = "https://elsewhere/?" + secret`), WebRTC's ICE
 * traffic, requests for this site's own files (`img-src 'self'` with data in the
 * query string), or the page's workers, which a `<meta>` policy does not reach.
 * docs/HOW-IT-WORKS.md ("What the CSP does not do") measures the image and
 * worker channels against the production export. So the
 * claim names those limits in the same breath, and scripts/seal-verdict-test.mjs
 * fails if it stops naming them or goes back to claiming every request.
 */
export const SEALED_CLAIM = {
  title: "Blocked from opening connections",
  text:
    "Enforced by the browser before a request starts. This page cannot fetch, open " +
    "a socket or send a beacon, post a form, or load anything from another server. " +
    "That is not every way out. A page's policy does not cover sending the tab to " +
    "another address, WebRTC, requests for this site's own files, or the page's " +
    "workers. For those the guarantee is that no code here does it, and the " +
    "reproducible build lets you check that. The lines the browser enforces are " +
    "below, read from this page as it was served and not typed here.",
} as const;
