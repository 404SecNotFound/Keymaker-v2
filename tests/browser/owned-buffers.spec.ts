import { test, expect, type Page } from "@playwright/test";
import { visible, useTextMode, STRONG_PASSWORD } from "./helpers";

/**
 * The buffers an operation owns are erased on the exits the worker never saw.
 *
 * `processData` reads the key file, then the plaintext (or the container),
 * then may ask a passkey for its PRF output, and only then hands everything to
 * the worker — which transfers the buffers and so empties this side's copies.
 * Between the reads and the hand-over sit a stale-return, an await that throws
 * when the passkey prompt is dismissed, and a paste that fails to decode. Each
 * of those left the plaintext and the key file in the page heap until GC,
 * while the toast said the operation had failed cleanly. The fix erases all of
 * them in the operation's `finally`.
 *
 * Both tests watch the buffers from outside: `Blob.prototype.arrayBuffer` is
 * wrapped before the app loads so the exact ArrayBuffer the hook received for
 * a named file is kept on `window`, where the test can read its bytes after
 * the failure. A buffer that is still full-length (not detached) proves the
 * worker never took it, so the only thing that could have zeroed it is the
 * exit path under test. The controls bite: with the three `secureErase` calls
 * removed from the `finally`, both buffers keep their bytes.
 */

const KEY_BYTES = Uint8Array.from({ length: 64 }, (_, i) => (i * 13 + 7) & 0xff || 0x5a);
const SECRET_BYTES = Uint8Array.from({ length: 96 }, (_, i) => (i * 11 + 3) & 0xff || 0x3c);

type Caught = { name: string; bytes: number[] };

/** Keep the ArrayBuffer every read of `names` returns, so its bytes can be read later. */
async function watchFileReads(page: Page, names: string[]) {
  await page.addInitScript((watched: string[]) => {
    const w = window as unknown as { __reads: { name: string; buffer: ArrayBuffer }[] };
    w.__reads = [];
    const original = Blob.prototype.arrayBuffer;
    Blob.prototype.arrayBuffer = async function (this: Blob) {
      const buffer = await original.call(this);
      if (this instanceof File && watched.includes(this.name)) w.__reads.push({ name: this.name, buffer });
      return buffer;
    };
  }, names);
}

async function caughtReads(page: Page): Promise<Caught[]> {
  return page.evaluate(() => {
    const w = window as unknown as { __reads: { name: string; buffer: ArrayBuffer }[] };
    return w.__reads.map((r) => ({ name: r.name, bytes: Array.from(new Uint8Array(r.buffer)) }));
  });
}

function expectErased(reads: Caught[], name: string, length: number) {
  const mine = reads.filter((r) => r.name === name);
  expect(mine.length, `${name} was read ${mine.length} times; expected at least once`).toBeGreaterThan(0);
  for (const read of mine) {
    // Full length: the worker never took this buffer, so nothing detached it.
    expect(read.bytes.length, `${name} was transferred, so this exit was not the one under test`).toBe(length);
    const live = read.bytes.filter((b) => b !== 0).length;
    expect(live, `${name}: ${live} of ${length} bytes still hold the file after the failure`).toBe(0);
  }
}

test.describe("owned buffers are erased on every exit", () => {
  test("a key file read for a decrypt whose paste fails to decode is erased", async ({ page }) => {
    await watchFileReads(page, ["key.bin"]);
    await page.goto("/");
    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);

    await visible(page.getByLabel(/use key file/i)).click();
    await page.locator("#decrypt-keyfile").setInputFiles({
      name: "key.bin",
      mimeType: "application/octet-stream",
      buffer: Buffer.from(KEY_BYTES),
    });
    // The armor prefix with a body that is not base64url: the key file has
    // been read by the time dearmor throws, and the worker is never called.
    await visible(page.getByPlaceholder("Enter text to decrypt")).fill("keym2:!!!!not-armor!!!!");
    await visible(page.getByPlaceholder("Enter decryption password")).fill(STRONG_PASSWORD);
    await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();

    // The toast and its live-region announcement both carry the title.
    await expect(page.getByText("Processing Error").first()).toBeVisible({ timeout: 30_000 });
    expectErased(await caughtReads(page), "key.bin", KEY_BYTES.length);
  });

  test("a plaintext read for an encrypt whose passkey prompt is dismissed is erased", async ({ page }) => {
    // WebAuthn refuses an IP address as a relying-party id; localhost resolves
    // to the same server. See passkey.spec.ts.
    const ORIGIN = "http://localhost:4321";
    await watchFileReads(page, ["secret.txt"]);
    // The passkey control only appears when the browser offers WebAuthn with
    // PRF, so a virtual authenticator is attached — and then the enrolment
    // itself is made to fail the way a dismissed prompt fails, so the
    // operation throws after the plaintext was read and before the worker.
    await page.addInitScript(() => {
      navigator.credentials.create = () =>
        Promise.reject(new DOMException("The operation either timed out or was not allowed.", "NotAllowedError"));
    });
    const cdp = await page.context().newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    await cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2",
        ctap2Version: "ctap2_1",
        transport: "internal",
        hasResidentKey: true,
        hasUserVerification: true,
        hasPrf: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    });
    try {
      await page.goto(`${ORIGIN}/`);
      await useTextMode(page);
      const advanced = visible(page.getByRole("button", { name: /^Advanced/ }));
      if ((await advanced.getAttribute("aria-expanded")) !== "true") await advanced.click();
      await visible(page.getByRole("button").filter({ hasText: "PBKDF2" })).click();
      const toggle = visible(page.getByRole("switch", { name: /Passkey quick access/i }));
      await expect(toggle, "no passkey control: WebAuthn with PRF was not detected").toBeVisible();
      await expect
        .poll(async () => {
          if ((await toggle.getAttribute("aria-checked")) !== "true") await toggle.click();
          return toggle.getAttribute("aria-checked");
        }, { timeout: 5_000 })
        .toBe("true");

      await visible(page.getByRole("button", { name: "File", exact: true })).first().click();
      await page.setInputFiles('input[type="file"]', {
        name: "secret.txt",
        mimeType: "text/plain",
        buffer: Buffer.from(SECRET_BYTES),
      });
      await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
      let downloaded = false;
      page.on("download", () => {
        downloaded = true;
      });
      await visible(page.getByRole("button", { name: /^Encrypt File$/i })).click();

      await expect(page.getByText("Processing Error").first()).toBeVisible({ timeout: 30_000 });
      expect(downloaded, "the dismissed enrolment still produced a container").toBe(false);
      expectErased(await caughtReads(page), "secret.txt", SECRET_BYTES.length);
    } finally {
      await cdp.detach();
    }
  });
});
