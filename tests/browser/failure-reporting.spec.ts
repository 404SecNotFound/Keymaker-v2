import { test, expect, type Page } from "@playwright/test";
import { readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { visible, useTextMode, selectCrypto, encryptText, STRONG_PASSWORD } from "./helpers";

/**
 * A failure that never looked at the secret must not blame it.
 *
 * Phase 1 established the rule for structural faults: a truncated or
 * tampered file says so, rather than "the password may be incorrect". Two
 * failures were still falling through to that sentence, and both describe
 * the page rather than the file:
 *
 *  - a lazily imported component (the ChaCha20 cipher, the Argon2id library)
 *    that could not be loaded. The loaders rejected with whatever the browser
 *    said about the import, and the v2 slot walk caught that beside a wrong
 *    key: every ChaCha slot or every Argon2id slot was silently skipped, the
 *    walk exhausted, and the user was told to check a password that was never
 *    tried;
 *  - the crypto worker dying with an operation in flight. Every pending
 *    request was failed with a plain Error, and the decrypt path renders any
 *    untyped error as the wrong-password sentence.
 *
 * Both now surface as typed errors with their own message. The first is only
 * reachable in-thread: the worker bundle inlines both libraries, so the chunk
 * only matters when the page derives for itself, which is why that test blocks
 * the Worker constructor the way worker.spec.ts does. Service workers are
 * blocked in these contexts so `page.route` sees every request.
 */

const OUT = resolve(__dirname, "../../out");
const WRONG_PASSWORD = /password or key file may be incorrect/i;

/** The chunk carrying @noble/ciphers, found by the ChaCha20 sigma constant. */
function nobleChunk(): string {
  const dir = join(OUT, "_next", "static", "chunks");
  const hits = readdirSync(dir).filter(
    (f) => f.endsWith(".js") && readFileSync(join(dir, f), "utf8").includes("expand 32-byte k")
  );
  expect(hits, "exactly one chunk should carry the ChaCha20 constant; is out/ a build?").toHaveLength(1);
  return hits[0]!;
}

async function attemptDecrypt(page: Page, armor: string, password: string) {
  await visible(page.getByRole("tab", { name: "Decrypt" })).click();
  await useTextMode(page);
  await visible(page.getByPlaceholder("Enter text to decrypt")).fill(armor);
  await visible(page.getByPlaceholder("Enter decryption password")).fill(password);
  await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();
}

test("a cipher that cannot be loaded is named, and the password is not blamed", async ({ browser }) => {
  const chunk = nobleChunk();
  const context = await browser.newContext({ serviceWorkers: "block" });
  const page = await context.newPage();
  try {
    // No worker, so the page derives for itself and the lazy chunk is what
    // carries the cipher. The premise is asserted below.
    const workers: string[] = [];
    page.on("worker", (w) => workers.push(w.url()));
    await page.addInitScript(() => {
      class BlockedWorker {
        constructor() {
          throw new Error("Worker construction blocked by the test");
        }
      }
      Object.defineProperty(window, "Worker", { value: BlockedWorker, configurable: true });
    });

    await page.goto("/");
    await useTextMode(page);
    await selectCrypto(page, "pbkdf2", "chacha");
    const armor = await encryptText(page, "unreachable cipher", STRONG_PASSWORD);
    expect(workers, "the worker was supposed to be unavailable").toHaveLength(0);

    // From here the cipher's chunk is unreachable: the deploy moved under the
    // page, or the network went before the precache had it.
    await page.route(`**/_next/static/chunks/${chunk}`, (route) => route.abort());
    await page.goto("/");
    await attemptDecrypt(page, armor, STRONG_PASSWORD);

    await expect(
      visible(page.getByText(/could not be loaded/i)).first(),
      "the missing cipher was not named"
    ).toBeVisible({ timeout: 30_000 });
    await expect(page.getByText(WRONG_PASSWORD)).toHaveCount(0);
  } finally {
    await context.close();
  }
});

test("a worker that dies mid-operation is named, and the password is not blamed", async ({ browser }) => {
  const fixture = JSON.parse(
    readFileSync(join(process.cwd(), "tests/browser/fixtures/expensive-pbkdf2.json"), "utf8")
  ) as { password: string; armor: string };
  const context = await browser.newContext({ serviceWorkers: "block" });
  const page = await context.newPage();
  try {
    // A worker that passes the readiness probe and dies on the first real
    // request. An uncaught throw in a worker fires `error` on the page's
    // Worker object, which is the event the client handles.
    await page.route("**/crypto-worker.js", (route) =>
      route.fulfill({
        contentType: "application/javascript",
        body:
          'self.onmessage = (e) => { const r = e.data;' +
          ' if (r.op === "ping") { self.postMessage({ id: r.id, ok: true, op: "ping" }); return; }' +
          ' throw new Error("simulated worker crash"); };',
      })
    );
    await page.goto("/");
    await page.waitForTimeout(1_500); // let the probe be answered by the stub
    await attemptDecrypt(page, fixture.armor, fixture.password);

    await expect(
      visible(page.getByText(/background worker stopped/i)).first(),
      "the dead worker was not named"
    ).toBeVisible({ timeout: 30_000 });
    await expect(page.getByText(WRONG_PASSWORD)).toHaveCount(0);
  } finally {
    await context.close();
  }
});
