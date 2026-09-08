#!/usr/bin/env node
/**
 * The build's egress gate requires the whole directive set, not connect-src
 * alone.
 *
 * apply-csp-hashes.mjs fails the build unless every shipped page's CSP sets
 * default-src, connect-src AND form-action to 'none'. connect-src has been
 * gated since KM-07, but on its own it stops only the scripted network APIs; a
 * <form> POST is governed by form-action (no default-src fallback). This drives
 * the shared gate helper (scripts/csp-egress-gate.mjs) so a regression that
 * dropped form-action or default-src from the gate is caught here rather than
 * shipping a CSP the build no longer checks.
 *
 * Control shown to bite: removing "form-action" (or "default-src") from
 * EGRESS_DIRECTIVES makes the corresponding case below report no violation, and
 * its assertion fails.
 */
import { egressViolations, pickDirective, EGRESS_DIRECTIVES } from "./csp-egress-gate.mjs";

let failed = 0;
const ok = (cond, msg) => {
  if (!cond) { console.error("FAIL:", msg); failed++; }
  else console.log("ok   ", msg);
};
const names = (policy) => egressViolations(policy).map((d) => d.name);

// The production policy, verbatim from src/app/layout.tsx.
const PROD =
  "default-src 'none'; script-src 'self' 'wasm-unsafe-eval' 'unsafe-inline'; " +
  "style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; " +
  "connect-src 'none'; worker-src 'self'; manifest-src 'self'; object-src 'none'; " +
  "base-uri 'none'; form-action 'none'";

// Positive: the real export has no egress violations.
ok(egressViolations(PROD).length === 0, "the production CSP passes the egress gate");

// Each egress directive is load-bearing. The form-action and default-src cases
// are the ones a connect-src-only gate would wave through — the bite.
ok(names(PROD.replace("; form-action 'none'", "")).includes("form-action"),
   "dropping form-action is a violation (a form POST could still leave)");
ok(names(PROD.replace("default-src 'none'; ", "")).includes("default-src"),
   "dropping default-src is a violation");
ok(names(PROD.replace("connect-src 'none'", "connect-src 'self'")).includes("connect-src"),
   "connect-src 'self' is a violation");
ok(names(PROD.replace("form-action 'none'", "form-action 'self'")).includes("form-action"),
   "form-action 'self' is a violation");

// A policy carrying none of them is all three violations.
ok(egressViolations("script-src 'self'").length === EGRESS_DIRECTIVES.length,
   "a policy with no egress directives violates on every one");

// pickDirective reads exact text, collapses whitespace, and does not match a
// longer directive name.
ok(pickDirective(PROD, "form-action") === "form-action 'none'", "pickDirective finds form-action");
ok(pickDirective("default-src  'none' ", "default-src") === "default-src 'none'", "pickDirective collapses whitespace");
ok(pickDirective("connect-src-elem 'self'", "connect-src") === null, "pickDirective does not match a longer name");

console.log(failed === 0 ? "\nAll csp-egress-gate checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
