#!/usr/bin/env node
/**
 * The service worker's install step fetches the un-hashed app shell past the
 * HTTP cache, and the shell includes the whole recovery kit.
 *
 * `cache.addAll(urls)` fetches with the default cache mode, so a URL the
 * browser's HTTP cache still holds from the previous deploy is stored as it
 * was: the new version's cache gets the old `/`, which disagrees with the new
 * SHA256SUMS (the sealed status reads that as tampering) and, offline, asks
 * for chunks the activate step has deleted. The shell URLs are not
 * content-hashed, so they must be fetched with `cache: 'reload'`.
 *
 * This runs public/sw.js itself in a stub worker scope and records what the
 * install handler hands to Cache Storage, rather than reading the source.
 *
 * It also dispatches offline fetches through the worker's fetch handler and
 * checks they are answered from the worker's own cache. `caches.match()`
 * searches every cache on the origin, and on GitHub Pages that includes other
 * project sites' caches; the stub answers such a lookup with "FOREIGN".
 *
 * Controls shown to bite: passing APP_SHELL to addAll as plain strings fails
 * the reload check; dropping requirements.txt from APP_SHELL fails the kit
 * check; dropping verify.html fails the verify checks; going back to
 * `caches.match` fails the three offline lookups.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import vm from "node:vm";

const HERE = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(HERE, "..", "public", "sw.js"), "utf8")
  .replace("__BUILD_ID__", "test")
  .replace("__PRECACHE_ASSETS__", JSON.stringify(["/Keymaker-v2/_next/static/chunks/app-0123abcd.js"]));

let failed = 0;
const ok = (cond, msg) => {
  if (!cond) { console.error("FAIL:", msg); failed++; }
  else console.log("ok   ", msg);
};

class StubRequest {
  constructor(url, init = {}) {
    this.url = url;
    this.cache = init.cache ?? "default";
  }
}

const added = [];
const handlers = {};
/** What this worker's own cache holds, by URL path, for the fetch checks. */
const owned = new Map();
let openedNames = [];
const scope = {
  location: new URL("https://example.test/Keymaker-v2/sw.js"),
  addEventListener: (type, fn) => { handlers[type] = fn; },
  registration: { scope: "https://example.test/Keymaker-v2/" },
  clients: { claim: async () => {} },
  skipWaiting: () => {},
};
const context = vm.createContext({
  self: scope,
  URL,
  Request: StubRequest,
  Response: class {},
  console,
  caches: {
    open: async (name) => {
      openedNames.push(name);
      return {
        addAll: async (items) => { added.push(...items); },
        put: async () => {},
        match: async (req) => {
          const path = new URL(typeof req === "string" ? req : req.url, "https://example.test").pathname;
          return owned.get(path);
        },
      };
    },
    keys: async () => [],
    // Cache Storage as a whole, which on a shared origin includes other apps'
    // caches. A correct worker never asks it.
    match: async () => "FOREIGN",
    delete: async () => true,
  },
  fetch: async () => { throw new Error("no network in this test"); },
});
vm.runInContext(source, context, { filename: "sw.js" });

let pending;
handlers.install({ waitUntil: (p) => { pending = p; } });
await pending;

const asUrl = (item) => (typeof item === "string" ? item : item.url);
const shell = added.filter((item) => !asUrl(item).includes("/_next/static/"));
ok(shell.length > 0, `the install step precached a shell (${shell.length} entries)`);
const stale = shell.filter((item) => typeof item === "string" || item.cache !== "reload");
ok(
  stale.length === 0,
  "every un-hashed shell URL is fetched with cache: 'reload'" +
    (stale.length ? ` (not: ${stale.map(asUrl).join(", ")})` : "")
);
const urls = added.map(asUrl);
for (const file of ["RECOVERY.md", "keym2.py", "keym.py", "requirements.txt"]) {
  ok(urls.includes(`/Keymaker-v2/recovery/${file}`), `the recovery kit's ${file} is precached`);
}
ok(urls.includes("/Keymaker-v2/_next/static/chunks/app-0123abcd.js"), "the hashed chunks are still precached");
ok(urls.includes("/Keymaker-v2/verify.html"), "the verify page is precached, so it opens offline");

// Offline lookups: a navigation with the network down, and a cacheable asset.
// Both must be answered from this worker's own cache, never Cache Storage as a
// whole, which on GitHub Pages holds every project site's caches.
owned.set("/Keymaker-v2/verify.html", "OWN verify");
owned.set("/Keymaker-v2/", "OWN shell");
owned.set("/Keymaker-v2/logo.svg", "OWN logo");
async function respond(url, mode) {
  let responded;
  handlers.fetch({
    request: { url, mode, method: "GET" },
    respondWith: (p) => { responded = p; },
  });
  return responded === undefined ? undefined : await responded;
}
openedNames = [];
ok((await respond("https://example.test/Keymaker-v2/verify.html", "navigate")) === "OWN verify",
  "offline, /verify.html is served as itself, from this worker's cache");
ok((await respond("https://example.test/Keymaker-v2/some/deep/link", "navigate")) === "OWN shell",
  "offline, an unknown navigation falls back to this worker's own shell");
ok((await respond("https://example.test/Keymaker-v2/logo.svg", "no-cors")) === "OWN logo",
  "a cacheable asset is answered from this worker's own cache");
ok(openedNames.every((n) => n === "keymaker-test"), "every lookup opened this worker's own cache by name");

if (failed) {
  console.error(`\n${failed} check(s) failed`);
  process.exit(1);
}
console.log("\nThe service worker precaches a fresh shell and the whole kit.");
