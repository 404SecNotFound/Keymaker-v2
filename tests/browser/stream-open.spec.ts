import { test, expect, type Page } from "@playwright/test";
import { createHash } from "node:crypto";
import {
  closeSync,
  copyFileSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readSync,
  rmSync,
  statSync,
  truncateSync,
  writeSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { visible, STRONG_PASSWORD } from "./helpers";
import { MAX_CONTAINER_SIZE } from "../../src/lib/keymaker-crypto";
import {
  MIB,
  bridgeContainerAt,
  chosenFile,
  hasDialog,
  instrument,
  picker,
  toast,
  verifyLoadedFile,
  workerOps,
  writePlaintextAt,
} from "./stream-helpers";

/**
 * Stage C2: a backup above the 100 MB in-memory cap, opened in two phases and
 * saved to a file the user chooses (format §5.5).
 *
 * Phase 1, the Decrypt click, derives the key and opens the slot and chunk 0
 * in the worker, asks for no file, and shows a pending panel that says the
 * password is right and nothing is checked past the first part or saved.
 * Phase 2, "Save decrypted file…", opens the save dialog on its own click and
 * drains the backup to the chosen file, which is closed (committed) only after
 * the worker's final answer. The save dialog is `stream-helpers.ts`'s OPFS
 * stand-in, whose commit-on-close `stream-save.spec.ts` proves first.
 *
 * ## Cost
 *
 * One 103 MiB plaintext and one container of it from the bridge, made once
 * per worker process and shared by every test here; a flipped and a truncated
 * copy are made from it on demand. PBKDF2 at 600,000 iterations, so each phase
 * 1 costs well under a second of derivation; each phase 2 drains 103 MiB.
 *
 * Negative controls, each applied to the source, built and seen to fail here:
 * - the page committing once the drain's chunks stop, whatever the drain's
 *   outcome, rather than on its success answer: the flipped and the cut
 *   backups leave bytes in the chosen file. (Committing when "the last chunk
 *   arrives" cannot be written as a control: the core never hands over the
 *   chunk that fails, so for these backups no last chunk arrives.)
 * - the commit moved into the `finally`: Stop leaves the file closed.
 * - the dialog opened in phase 1: a wrong password opens it.
 * - the pending state cleared when the dialog is cancelled: no second click.
 * - the worker not terminated by Wipe and the lock: it drains on request.
 * - the success panel rendered at phase 1: the wording test sees it.
 * - the decrypt label read without the dialog: the no-dialog label is wrong.
 */

/**
 * 104 MiB, one more than the encrypt suite, so that the container with its
 * last chunk cut off is still above the in-memory container limit (about
 * 102 MiB) and takes the streamed path too.
 */
const PLAIN_BYTES = 104 * MIB;
/** Every file here must be above it, or the page takes the in-memory path and the test proves nothing. */
const CONTAINER_LIMIT = MAX_CONTAINER_SIZE;

/** Built once per worker process: the plaintext, its digest and the container. */
let corpus: { dir: string; plain: string; plainSha256: string; container: string } | null = null;
function large(): NonNullable<typeof corpus> {
  if (corpus) return corpus;
  const dir = mkdtempSync(join(tmpdir(), "keymaker-stream-open-"));
  const plain = writePlaintextAt(join(dir, "large-plain.bin"), PLAIN_BYTES);
  const plainSha256 = createHash("sha256").update(readFileSync(plain)).digest("hex");
  const container = bridgeContainerAt(plain, join(dir, "large-backup.keym"));
  expect(statSync(container).size, "tripwire: the container is not above the in-memory limit").toBeGreaterThan(CONTAINER_LIMIT);
  corpus = { dir, plain, plainSha256, container };
  return corpus;
}
test.afterAll(() => {
  if (corpus) rmSync(corpus.dir, { recursive: true, force: true });
  corpus = null;
});

/** The container with its very last byte (the last chunk's tag) flipped. */
function flippedContainer(): string {
  const { dir, container } = large();
  const out = join(dir, "flipped-backup.keym");
  copyFileSync(container, out);
  const size = statSync(out).size;
  const fd = openSync(out, "r+");
  try {
    const last = Buffer.alloc(1);
    readSync(fd, last, 0, 1, size - 1);
    last[0] = last[0]! ^ 0x01;
    writeSync(fd, last, 0, 1, size - 1);
  } finally {
    closeSync(fd);
  }
  return out;
}

/**
 * The container with its last chunk removed exactly. The plaintext is a whole
 * number of mebibytes, so every chunk on the wire is 1 MiB of ciphertext and a
 * 16-byte AES-GCM tag; what is left is a valid length of 102 chunks whose last
 * was sealed with final_flag 0.
 */
function truncatedContainer(): string {
  const { dir, container } = large();
  const out = join(dir, "truncated-backup.keym");
  copyFileSync(container, out);
  truncateSync(out, statSync(container).size - (MIB + 16));
  expect(statSync(out).size, "tripwire: the cut container fell under the in-memory limit").toBeGreaterThan(CONTAINER_LIMIT);
  return out;
}

const decryptTab = (page: Page) => visible(page.getByRole("tab", { name: "Decrypt", exact: true }));
const decryptButton = (page: Page) => visible(page.getByRole("button", { name: /^Decrypt File$/i }));
const pending = (page: Page) => visible(page.getByTestId("pending-save"));
const saveButton = (page: Page) => visible(page.getByRole("button", { name: "Save decrypted file…" }));

/** Load the app on Decrypt, pick a backup by path, type a password, and run phase 1. */
async function phaseOne(page: Page, containerPath: string, password = STRONG_PASSWORD): Promise<void> {
  await page.goto("/");
  await decryptTab(page).click();
  await page.locator("#decrypt-file").setInputFiles(containerPath);
  await visible(page.getByPlaceholder("Enter decryption password")).fill(password);
  await decryptButton(page).click();
}

/** Post a drain straight to the worker that ran the open, and report what comes back within a second and a half. */
async function drainAttempt(page: Page): Promise<{ terminated: boolean; replies: { op?: string; ok?: boolean }[] }> {
  return page.evaluate(async () => {
    const w = window as unknown as { __openWorker: Worker | null; __terminated: Worker[] };
    const wk = w.__openWorker!;
    const replies: { op?: string; ok?: boolean }[] = [];
    const listen = (e: MessageEvent) => {
      if ((e.data as { id?: number }).id === 987_654) replies.push({ op: e.data.op, ok: e.data.ok });
    };
    wk.addEventListener("message", listen);
    wk.postMessage({ id: 987_654, op: "drain" });
    await new Promise((r) => setTimeout(r, 1500));
    wk.removeEventListener("message", listen);
    return { terminated: w.__terminated.includes(wk), replies };
  });
}

test.describe("with a save dialog", () => {
  test.beforeEach(async ({ page }) => {
    await instrument(page);
    await page.goto("/");
    test.skip(!(await hasDialog(page)), "this browser has no showSaveFilePicker; see the tests without one");
  });

  test("round trip: a backup above 100 MB is opened, then saved, byte for byte", async ({ page }) => {
    const { container, plainSha256 } = large();
    await page.goto("/");
    await decryptTab(page).click();
    await expect(
      visible(page.getByText("a .keym container, or a QR image to scan · 1 GB max, saved where you choose"))
    ).toBeVisible();
    await phaseOne(page, container);
    await expect(pending(page)).toBeVisible({ timeout: 60_000 });
    expect((await picker(page)).calls, "phase 1 asked for a file").toHaveLength(0);
    expect(await workerOps(page)).toContain("open-stream");
    expect(await workerOps(page)).not.toContain("decrypt");

    await saveButton(page).click();
    const saved = visible(page.getByTestId("decrypt-saved"));
    await expect(saved).toBeVisible({ timeout: 90_000 });
    const record = await picker(page);
    expect(record.calls).toHaveLength(1);
    expect(record.calls[0]!.suggestedName).toBe("large-backup");
    expect(record.calls[0]!.activation, "the dialog was not opened inside the click's activation").toBe(true);
    expect(record.calls[0]!.opsBefore, "the drain started before the dialog").not.toContain("drain");
    expect(record.settled).toBe("closed");
    expect(await workerOps(page)).toContain("drain");

    const file = await chosenFile(page);
    expect(file.size).toBe(PLAIN_BYTES);
    expect(file.sha256, "the saved file is not the original plaintext").toBe(plainSha256);
    await expect(saved).toContainText("Every part of the backup checked out");
    await expect(saved).toContainText("large-backup");
    await expect(page.getByTestId("pending-save")).toHaveCount(0);
    await expect(page.getByTestId("save-progress")).toHaveCount(0);
    // U13: the password goes once the file is saved.
    await expect(visible(page.getByPlaceholder("Enter decryption password"))).toHaveValue("");
  });

  test("phase 1 says the password is right and nothing is checked or saved yet, and claims no more", async ({ page }) => {
    await phaseOne(page, large().container);
    const panel = pending(page);
    await expect(panel).toBeVisible({ timeout: 60_000 });
    await expect(panel).toContainText("The password is right.");
    await expect(panel).toContainText("Nothing is saved yet.");
    await expect(panel).toContainText("The first part of this backup has opened.");
    await expect(panel).toContainText("The rest of it is not checked yet, and nothing has been saved.");
    await expect(visible(page.getByRole("button", { name: "Discard" }))).toBeVisible();
    const text = (await panel.innerText()).replace("Save decrypted file…", "");
    expect(text, "the pending panel claims success").not.toMatch(/Success|Decrypted|Verified|intact/);
    expect(await panel.locator("svg.lucide-shield-check, svg.lucide-circle-check, svg.lucide-check").count(),
      "the pending panel shows a tick").toBe(0);
    await expect(page.getByTestId("decrypt-saved")).toHaveCount(0);
    await expect(page.getByTestId("verify-result")).toHaveCount(0);
    // The info line is there, without the advisory that says the contents are intact.
    await expect(visible(page.getByText(/^Format: KEYM v3/))).toBeVisible();
    await expect(page.getByText(/contents are intact/)).toHaveCount(0);
    await expect(toast(page, /Success|Decrypted/)).toHaveCount(0);
  });

  test("a backup whose last chunk is flipped opens in phase 1 and saves nothing", async ({ page }) => {
    await phaseOne(page, flippedContainer());
    await expect(pending(page)).toBeVisible({ timeout: 60_000 });
    await saveButton(page).click();
    // The file first: closed is saved, whatever the page then says.
    await expect.poll(async () => (await picker(page)).settled, { timeout: 90_000 }).not.toBeNull();
    expect((await chosenFile(page)).size, "a failed decrypt left bytes in the chosen file").toBe(0);
    expect((await picker(page)).settled, "the file was closed, which saves it").toBe("aborted");
    await expect(toast(page, "Decryption failed, so nothing was saved. An empty or partial temporary file may be left where you chose to save it."))
      .toBeVisible();
    await expect(page.getByTestId("decrypt-saved")).toHaveCount(0);
    await expect(page.getByTestId("pending-save")).toHaveCount(0);
  });

  test("a backup cut off exactly at a chunk boundary opens in phase 1 and saves nothing", async ({ page }) => {
    await phaseOne(page, truncatedContainer());
    await expect(pending(page)).toBeVisible({ timeout: 60_000 });
    await saveButton(page).click();
    await expect.poll(async () => (await picker(page)).settled, { timeout: 90_000 }).not.toBeNull();
    expect((await chosenFile(page)).size, "a failed decrypt left bytes in the chosen file").toBe(0);
    expect((await picker(page)).settled, "the file was closed, which saves it").toBe("aborted");
    await expect(toast(page, /^Decryption failed, so nothing was saved\./)).toBeVisible();
    await expect(page.getByTestId("decrypt-saved")).toHaveCount(0);
  });

  test("Stop during the save saves nothing", async ({ page }) => {
    await phaseOne(page, large().container);
    await expect(pending(page)).toBeVisible({ timeout: 60_000 });
    await page.evaluate(() => ((window as unknown as { __picker: { writeDelayMs: number } }).__picker.writeDelayMs = 60));
    await saveButton(page).click();
    await expect(visible(page.getByTestId("save-progress"))).toContainText("Nothing is saved until every part has been checked", {
      timeout: 60_000,
    });
    await expect.poll(async () => (await picker(page)).writes, { timeout: 60_000 }).toBeGreaterThan(4);
    await visible(page.getByTestId("cancel-operation")).click();
    await expect(toast(page, /The decryption was stopped and nothing was saved\./)).toBeVisible();
    await expect.poll(async () => (await picker(page)).settled, { timeout: 30_000 }).not.toBeNull();
    expect((await picker(page)).settled, "the stopped file was closed, which saves it").toBe("aborted");
    expect((await chosenFile(page)).size, "a stopped save left bytes in the chosen file").toBe(0);
    await expect(page.getByTestId("decrypt-saved")).toHaveCount(0);
  });

  test("a wrong password never opens the save dialog", async ({ page }) => {
    await phaseOne(page, large().container, `${STRONG_PASSWORD} but wrong`);
    await expect(toast(page, /Decryption failed/)).toBeVisible({ timeout: 60_000 });
    await page.waitForTimeout(500);
    expect((await picker(page)).calls, "the save dialog was opened for a wrong password").toHaveLength(0);
    await expect(page.getByTestId("pending-save")).toHaveCount(0);
    expect(await workerOps(page)).not.toContain("drain");
  });

  test("cancelling the dialog keeps the backup open, and a second click saves it", async ({ page }) => {
    const { plainSha256 } = large();
    await phaseOne(page, large().container);
    await expect(pending(page)).toBeVisible({ timeout: 60_000 });
    await page.evaluate(() => ((window as unknown as { __picker: { mode: string } }).__picker.mode = "cancel"));
    await saveButton(page).click();
    await expect(toast(page, /No file was chosen, so nothing was saved\./)).toBeVisible();
    await expect(pending(page)).toBeVisible();
    expect(await workerOps(page), "a drain started although the dialog was cancelled").not.toContain("drain");

    await page.evaluate(() => ((window as unknown as { __picker: { mode: string } }).__picker.mode = "ok"));
    await saveButton(page).click();
    await expect(visible(page.getByTestId("decrypt-saved"))).toBeVisible({ timeout: 90_000 });
    expect((await picker(page)).calls).toHaveLength(2);
    expect((await chosenFile(page)).sha256).toBe(plainSha256);
  });

  test("Wipe while a save is pending ends it here and in the worker", async ({ page }) => {
    await phaseOne(page, large().container);
    await expect(pending(page)).toBeVisible({ timeout: 60_000 });
    await visible(page.getByRole("button", { name: "Wipe now" })).click();
    await expect(page.getByTestId("pending-save")).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Save decrypted file…" })).toHaveCount(0);
    const attempt = await drainAttempt(page);
    expect(attempt.replies.filter((r) => r.ok === true || r.op === "chunk"), "the worker still drained the backup").toHaveLength(0);
    expect(attempt.terminated, "the worker holding the backup was not terminated").toBe(true);
  });

  test("the auto-lock while a save is pending ends it here and in the worker", async ({ page }) => {
    await phaseOne(page, large().container);
    await expect(pending(page)).toBeVisible({ timeout: 60_000 });
    // The lock fires on pagehide when nothing is running; see hidden-tab-lock.spec.ts.
    await page.evaluate(() => window.dispatchEvent(new Event("pagehide")));
    await expect(toast(page, /Locked/)).toBeVisible();
    await expect(page.getByTestId("pending-save")).toHaveCount(0);
    const attempt = await drainAttempt(page);
    expect(attempt.replies.filter((r) => r.ok === true || r.op === "chunk"), "the worker still drained the backup").toHaveLength(0);
    expect(attempt.terminated).toBe(true);
  });

  test("Discard ends it, and the worker refuses a drain", async ({ page }) => {
    await phaseOne(page, large().container);
    await expect(pending(page)).toBeVisible({ timeout: 60_000 });
    await visible(page.getByRole("button", { name: "Discard" })).click();
    await expect(page.getByTestId("pending-save")).toHaveCount(0);
    expect(await workerOps(page)).toContain("close-stream");
    const attempt = await drainAttempt(page);
    expect(attempt.replies, "the worker did not refuse the drain").toEqual([{ op: undefined, ok: false }]);
    expect((await picker(page)).calls).toHaveLength(0);
  });

  test("a KEYM v1 file above the limit is refused by name, before any work", async ({ page }, testInfo) => {
    // A v1 header and 103 MiB after it, above the container limit: only the head is read.
    // The frozen corpus's KEYM v1 fixtures carry no version prefix in their names.
    const v1 = readFileSync(resolve(__dirname, "../../scripts/fixtures/keymaker/pbkdf2-aes256gcm.keym"));
    expect(v1.subarray(0, 5).toString("latin1"), "tripwire: the fixture is not KEYM v1").toBe("KEYM\x01");
    const path = testInfo.outputPath("big-v1.keym");
    const fd = openSync(path, "w");
    try {
      writeSync(fd, v1);
      const zeros = Buffer.alloc(MIB);
      for (let i = 0; i < 103; i++) writeSync(fd, zeros);
    } finally {
      closeSync(fd);
    }
    expect(statSync(path).size).toBeGreaterThan(CONTAINER_LIMIT);
    await phaseOne(page, path);
    const refusal = toast(page, /This is a KEYM v1 backup, which seals the whole file as one block\./);
    await expect(refusal).toBeVisible();
    await expect(refusal).toContainText("keym2.py decrypt");
    expect(await workerOps(page)).not.toContain("open-stream");
    expect((await picker(page)).calls).toHaveLength(0);
  });
});

test.describe("without a save dialog", () => {
  // Firefox and WebKit as they are; Chromium with the dialog deleted.
  test.beforeEach(async ({ page }) => {
    await instrument(page, { removeDialog: true });
  });

  test("a backup above 100 MB is refused for opening, with the recovery help, and still verifies", async ({ page }) => {
    await page.goto("/");
    await decryptTab(page).click();
    await expect(
      visible(page.getByText("a .keym container, or a QR image to scan · 100 MB to open here · 1 GB to verify"))
    ).toBeVisible();
    await page.locator("#decrypt-file").setInputFiles(large().container);
    await visible(page.getByPlaceholder("Enter decryption password")).fill(STRONG_PASSWORD);
    await decryptButton(page).click();
    const refusal = toast(page, /This backup is larger than the 100 MB this app can open in a browser tab/);
    await expect(refusal).toBeVisible();
    await expect(refusal).toContainText("keym2.py decrypt");
    await expect(refusal).toContainText("turn on Verify only");
    await expect(refusal).toContainText("Chrome or Edge, can open backups up to 1 GB");
    expect(await workerOps(page)).not.toContain("open-stream");
    await expect(page.getByTestId("pending-save")).toHaveCount(0);

    await verifyLoadedFile(page);
    expect(await workerOps(page), "the verify was not streamed").toContain("open-stream");
    expect(await workerOps(page)).not.toContain("drain");
  });
});
