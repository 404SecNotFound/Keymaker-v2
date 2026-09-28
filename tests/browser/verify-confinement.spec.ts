import { test, expect, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { visible, useTextMode, selectCrypto, STRONG_PASSWORD } from "./helpers";

/**
 * Verify-only and the rehearsal keep the plaintext in the worker (roadmap 9.2).
 *
 * Both used to take the ordinary decrypt response and zero the plaintext on
 * arrival. Nothing was rendered, so every test that read the page passed, and
 * yet a whole copy of the secret crossed into the page's heap each time. The
 * page cannot see that from the DOM; the transport can. So the worker is
 * wrapped before the app loads and every message it posts to the page is kept,
 * alongside every Blob built and every object URL made, and the tests inspect
 * those rather than what is on screen.
 *
 * `scripts/verify-transport-test.mts` holds the worker itself to the same rule
 * for every format in the corpus. This file holds the page to it: that the
 * verify and the rehearsal really ask for a verify, that a cancel or a switch
 * mid-verify leaves nothing behind, and that with no worker at all the page
 * says the check ran in the page instead of implying it did not.
 *
 * The first test's positive control is the ordinary decrypt, run through the
 * same instrument: it must be seen carrying the secret, or a clean verify
 * result would mean only that the instrument sees nothing.
 */

const SECRET = "verify-confinement marker 5b1e: the spare key is taped under the drawer.";

/** Record what the crypto worker sends the page, and what the page turns into Blobs and URLs. */
async function instrument(page: Page) {
  await page.addInitScript(() => {
    const w = window as unknown as {
      __inbound: unknown[];
      __blobParts: unknown[][];
      __objectUrls: number;
    };
    w.__inbound = [];
    w.__blobParts = [];
    w.__objectUrls = 0;
    const NativeWorker = window.Worker;
    class RecordingWorker extends NativeWorker {
      constructor(url: string | URL, options?: WorkerOptions) {
        super(url, options);
        // Cloned on arrival. This listener runs before the app's, which zeroes
        // a decrypt's buffer in place once it has used it; reading the
        // original later would find zeros and call a leak clean.
        this.addEventListener("message", (e) => w.__inbound.push(structuredClone((e as MessageEvent).data)));
      }
    }
    Object.defineProperty(window, "Worker", { value: RecordingWorker, configurable: true });
    const NativeBlob = window.Blob;
    class RecordingBlob extends NativeBlob {
      constructor(parts?: BlobPart[], options?: BlobPropertyBag) {
        super(parts, options);
        w.__blobParts.push(structuredClone(parts ?? []));
      }
    }
    Object.defineProperty(window, "Blob", { value: RecordingBlob, configurable: true });
    const createObjectURL = URL.createObjectURL.bind(URL);
    URL.createObjectURL = (obj: Blob | MediaSource) => {
      w.__objectUrls++;
      return createObjectURL(obj);
    };
  });
}

/** Forget everything recorded so far: what follows is the operation under test. */
async function resetRecord(page: Page) {
  await page.evaluate(() => {
    const w = window as unknown as { __inbound: unknown[]; __blobParts: unknown[][]; __objectUrls: number };
    w.__inbound.length = 0;
    w.__blobParts.length = 0;
    w.__objectUrls = 0;
  });
}

interface Record_ {
  ops: string[];
  leaks: string[];
  buffers: number;
  objectUrls: number;
}

/** What crossed since the last reset, and where the secret was seen in it. */
async function readRecord(page: Page, secret: string): Promise<Record_> {
  return page.evaluate((marker) => {
    const w = window as unknown as { __inbound: unknown[]; __blobParts: unknown[][]; __objectUrls: number };
    const dec = new TextDecoder("utf-8", { fatal: false });
    const leaks: string[] = [];
    let buffers = 0;
    const walk = (v: unknown, path: string) => {
      if (v instanceof ArrayBuffer || ArrayBuffer.isView(v)) {
        buffers++;
        const view = v instanceof ArrayBuffer ? new Uint8Array(v) : new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
        if (dec.decode(view).includes(marker)) leaks.push(`${path}: buffer holding the secret`);
      } else if (v instanceof Blob) {
        leaks.push(`${path}: a Blob`);
      } else if (typeof v === "string") {
        if (v.includes(marker)) leaks.push(`${path}: string holding the secret`);
        if (v.startsWith("blob:")) leaks.push(`${path}: an object URL`);
      } else if (v && typeof v === "object") {
        for (const [k, x] of Object.entries(v)) walk(x, `${path}.${k}`);
      }
    };
    w.__inbound.forEach((m, i) => walk(m, `message[${i}]`));
    w.__blobParts.forEach((parts, i) => parts.forEach((p, j) => walk(p, `blob[${i}].part[${j}]`)));
    return {
      ops: w.__inbound.map((m) => String((m as { op?: unknown }).op ?? (m as { ok?: unknown }).ok)),
      leaks,
      buffers,
      objectUrls: w.__objectUrls,
    };
  }, secret);
}

/** Seal SECRET with PBKDF2 (the KDF is not under test) and return the armoured container. */
async function seal(page: Page): Promise<string> {
  await page.goto("/");
  await useTextMode(page);
  await selectCrypto(page, "pbkdf2", "aes");
  await visible(page.getByPlaceholder("Enter text to encrypt")).fill(SECRET);
  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
  await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();
  const output = visible(page.locator("#output-text"));
  await expect(output).toHaveValue(/^keym2:/, { timeout: 60_000 });
  return output.inputValue();
}

async function stageVerify(page: Page, blob: string, password: string) {
  await visible(page.getByRole("tab", { name: "Decrypt" })).click();
  await useTextMode(page);
  await visible(page.getByPlaceholder("Enter text to decrypt")).fill(blob);
  await visible(page.getByPlaceholder("Enter decryption password")).fill(password);
  const toggle = visible(page.getByLabel(/Verify only/i));
  if (!(await toggle.isChecked())) await toggle.click();
  await expect(toggle).toBeChecked();
}

const verifyButton = (page: Page) => visible(page.getByRole("button", { name: /^Verify Text$/i }));
const verifyResult = (page: Page) => page.getByTestId("verify-result");

test("verify-only receives a byte count from the worker and never the plaintext", async ({ page }) => {
  await instrument(page);
  const blob = await seal(page);
  await stageVerify(page, blob, STRONG_PASSWORD);

  await resetRecord(page);
  await verifyButton(page).click();
  await expect(visible(verifyResult(page))).toContainText("The backup opens with this password", {
    timeout: 60_000,
  });
  await expect(visible(verifyResult(page))).toContainText(
    `${new TextEncoder().encode(SECRET).length} bytes`
  );
  // It ran in the worker, so there is nothing to disclose.
  await expect(page.getByTestId("verify-in-page")).toHaveCount(0);

  // The boundary first: this is the claim, and the op names below only say
  // which route the page took to keep it.
  const record = await readRecord(page, SECRET);
  expect(record.leaks, "the secret crossed into the page").toEqual([]);
  expect(record.buffers, "a buffer crossed into the page during a verify").toBe(0);
  expect(record.objectUrls, "a verify made an object URL").toBe(0);
  expect(record.ops, "the page did not ask the worker for a verify").toContain("verify");
  expect(record.ops, "the page asked the worker for a decrypt").not.toContain("decrypt");

  // Positive control: the same instrument, the ordinary decrypt. It has to be
  // seen carrying the secret, or the clean record above proves nothing.
  await visible(page.getByLabel(/Verify only/i)).click();
  await visible(page.getByPlaceholder("Enter decryption password")).fill(STRONG_PASSWORD);
  await resetRecord(page);
  await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();
  await expect(visible(page.locator("#output-text"))).toHaveValue(SECRET, { timeout: 60_000 });
  const control = await readRecord(page, SECRET);
  expect(control.ops).toContain("decrypt");
  expect(control.leaks.length, "the instrument did not see the plaintext an ordinary decrypt returns").toBeGreaterThan(0);
});

test("a wrong password fails the verify, and nothing secret crosses", async ({ page }) => {
  await instrument(page);
  const blob = await seal(page);
  const wrong = `${STRONG_PASSWORD}-wrong`;
  await stageVerify(page, blob, wrong);

  await resetRecord(page);
  await verifyButton(page).click();
  await expect(page.getByText(/Decryption failed/i).first()).toBeVisible({ timeout: 60_000 });
  await expect(verifyResult(page)).toHaveCount(0);

  const record = await readRecord(page, SECRET);
  const credentials = await readRecord(page, wrong);
  expect(record.ops).toContain("false");
  expect(record.leaks).toEqual([]);
  expect(credentials.leaks, "the error carried the password back").toEqual([]);
  expect(record.buffers).toBe(0);
});

test("a truncated backup fails the verify with nothing crossing", async ({ page }) => {
  await instrument(page);
  const blob = await seal(page);
  await stageVerify(page, blob.slice(0, blob.length - 12), STRONG_PASSWORD);

  await resetRecord(page);
  await verifyButton(page).click();
  await expect(page.getByText(/Processing Error/i).first()).toBeVisible({ timeout: 60_000 });
  await expect(verifyResult(page)).toHaveCount(0);
  const record = await readRecord(page, SECRET);
  expect(record.leaks).toEqual([]);
  expect(record.buffers).toBe(0);
});

test("the rehearsal asks for a verify, and the plaintext never reaches the page", async ({ page }) => {
  await instrument(page);
  await page.goto("/");
  await useTextMode(page);
  await selectCrypto(page, "pbkdf2", "aes");
  const advanced = visible(page.getByRole("button", { name: /^Advanced/ }));
  if ((await advanced.getAttribute("aria-expanded")) !== "true") await advanced.click();
  const sharesSwitch = visible(page.getByRole("switch", { name: "Recovery shares" }));
  await expect(async () => {
    if ((await sharesSwitch.getAttribute("aria-checked")) !== "true") await sharesSwitch.click();
    await expect(sharesSwitch).toHaveAttribute("aria-checked", "true", { timeout: 1_000 });
  }).toPass({ timeout: 20_000 });
  await visible(page.getByLabel("Shares to print")).fill("3");
  await visible(page.getByLabel("Needed to open")).fill("2");
  await visible(page.getByPlaceholder("Enter text to encrypt")).fill(SECRET);
  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
  await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();

  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText(/Save these 3 shares now/)).toBeVisible({ timeout: 90_000 });
  const shares = (await dialog.getByText(/^KMSHARE2:/).allTextContents()).map((s) => s.trim());
  await dialog.getByRole("button", { name: /Rehearse now/ }).click();
  await dialog.getByLabel("Strips to rehearse with").fill(`${shares[0]}\n${shares[1]}`);

  await resetRecord(page);
  await dialog.getByRole("button", { name: /^Open with these strips$/ }).click();
  const result = dialog.getByTestId("rehearsal-result");
  await expect(result).toContainText(/Opened in/, { timeout: 60_000 });
  await expect(result).not.toContainText("Checked on this page");

  const record = await readRecord(page, SECRET);
  expect(record.leaks, "the secret crossed into the page").toEqual([]);
  expect(record.buffers, "a buffer crossed into the page during the rehearsal").toBe(0);
  expect(record.objectUrls).toBe(0);
  expect(record.ops, "the rehearsal did not ask the worker for a verify").toContain("verify");
  expect(record.ops, "the rehearsal asked the worker for a decrypt").not.toContain("decrypt");
});

/** A container whose one slot costs 9,000,000 PBKDF2 iterations: long enough to interrupt. */
function expensive(): { password: string; armor: string } {
  return JSON.parse(
    readFileSync(join(process.cwd(), "tests/browser/fixtures/expensive-pbkdf2.json"), "utf8")
  ) as { password: string; armor: string };
}

test("Stop during a verify ends it, and nothing arrives afterwards", async ({ page }) => {
  await instrument(page);
  const closed: string[] = [];
  page.on("worker", (w) => w.on("close", () => closed.push(w.url())));
  const fixture = expensive();
  await page.goto("/");
  await stageVerify(page, fixture.armor, fixture.password);

  await resetRecord(page);
  await verifyButton(page).click();
  await expect(page.locator(".animate-spin").first(), "the verify never started").toBeVisible({ timeout: 20_000 });
  // Only closes from here on count. Staging the form already closed the
  // warm-up worker (choosing Text mode disowns and terminates), so without
  // this the check below passed before Stop was ever pressed.
  closed.length = 0;
  const stop = visible(page.getByTestId("cancel-operation"));
  await stop.click();
  await expect(stop).toBeHidden({ timeout: 15_000 });
  await expect.poll(() => closed.some((u) => u.endsWith("/crypto-worker.js")), {
    message: "Stop did not terminate the worker running the verify",
    timeout: 10_000,
  }).toBe(true);

  // Longer than the derivation would take to fail on its own is not needed:
  // the worker that held the job is gone. What is checked is that nothing
  // claims a result, and that no message for the job ever lands.
  await page.waitForTimeout(3_000);
  await expect(verifyResult(page)).toHaveCount(0);
  await expect(page.getByText(/Verified — the backup opens/)).toHaveCount(0);
  const record = await readRecord(page, fixture.password);
  expect(record.ops.filter((o) => o === "verify" || o === "false"), "a response for the stopped job arrived").toEqual([]);

  // And the next verify, on a fresh worker, works.
  const blob = await seal(page);
  await stageVerify(page, blob, STRONG_PASSWORD);
  await verifyButton(page).click();
  await expect(visible(verifyResult(page))).toContainText("The backup opens with this password", {
    timeout: 60_000,
  });
});

test("switching to Encrypt mid-verify disowns it: no result and no toast, then or later", async ({ page }) => {
  await instrument(page);
  const closed: string[] = [];
  page.on("worker", (w) => w.on("close", () => closed.push(w.url())));
  const fixture = expensive();
  await page.goto("/");
  await stageVerify(page, fixture.armor, fixture.password);

  await verifyButton(page).click();
  await expect(page.locator(".animate-spin").first(), "the verify never started").toBeVisible({ timeout: 20_000 });
  // As in the Stop test: only a close caused by the switch counts.
  closed.length = 0;
  await visible(page.getByRole("tab", { name: "Encrypt" })).click();
  await expect(page.locator(".animate-spin"), "the switch left the verify running").toHaveCount(0, { timeout: 5_000 });
  await expect.poll(() => closed.some((u) => u.endsWith("/crypto-worker.js")), {
    message: "the switch did not terminate the worker running the verify",
    timeout: 10_000,
  }).toBe(true);

  await page.waitForTimeout(3_000);
  await visible(page.getByRole("tab", { name: "Decrypt" })).click();
  await expect(verifyResult(page)).toHaveCount(0);
  await expect(page.getByText(/Verified — the backup opens/)).toHaveCount(0);
  await expect(page.getByText(/Processing Error/)).toHaveCount(0);
});

test("with no worker, the verify still runs and says it ran in the page", async ({ page }) => {
  await page.addInitScript(() => {
    class BlockedWorker {
      constructor() {
        throw new Error("Worker construction blocked by the test");
      }
    }
    Object.defineProperty(window, "Worker", { value: BlockedWorker, configurable: true });
  });
  const blob = await seal(page);
  await stageVerify(page, blob, STRONG_PASSWORD);
  await verifyButton(page).click();
  await expect(visible(verifyResult(page))).toContainText("The backup opens with this password", {
    timeout: 60_000,
  });
  await expect(
    visible(page.getByTestId("verify-in-page")),
    "a verify that ran on the page's thread did not say so"
  ).toContainText("Checked on this page");
  const body = (await page.locator("body").textContent()) ?? "";
  expect(body).not.toContain(SECRET);
});
