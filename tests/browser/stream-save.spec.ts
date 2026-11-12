import { test, expect, type Page } from "@playwright/test";
import { visible, selectCrypto, STRONG_PASSWORD } from "./helpers";
import {
  PLAIN_BYTES,
  type PickerRecord,
  bridgeContainer,
  chosenFile,
  hasDialog,
  instrument,
  picker,
  toast,
  verifyLoadedFile,
  workerOps,
  writePlaintext,
} from "./stream-helpers";

/**
 * Stage C1: a file above the 100 MB in-memory cap, encrypted straight to a
 * file the user chooses, and a backup above it verified a chunk at a time.
 *
 * ## The save dialog is a stand-in
 *
 * Headless Chromium's real `showSaveFilePicker` rejects at once with
 * AbortError. `stream-helpers.ts` replaces it with a stand-in over an OPFS
 * file whose writable is the browser's own; the precondition test below
 * proves it commits only on close before anything relies on it, so the suite
 * cannot pass on a stand-in that writes straight through. What it cannot show
 * is what the real dialog does on disk, and the page's wording claims nothing
 * about that. `stream-open.spec.ts` uses the same stand-in for decrypt.
 *
 * ## Browsers without the dialog
 *
 * Firefox and WebKit have no `showSaveFilePicker`. Every test that needs one
 * is guarded by that capability, not by the project's name, and the tests for
 * a browser without it also run in Chromium, with the dialog deleted by an
 * init script, so they are exercised on every engine.
 *
 * ## Cost
 *
 * Each test writes a 103 MiB plaintext to disk (`testInfo.outputPath`) and
 * hands the picker its path, never a buffer. 103 MiB, not 101, so the
 * container it becomes is also above the in-memory container limit and its
 * verify is streamed too. Every encrypt uses PBKDF2, the fastest key
 * derivation the form offers.
 *
 * Negative controls, each applied to the source, built and seen to fail here:
 * the recorded digest taken over something else; `commit()` moved into the
 * `finally`; the dialog opened after the derivation has started; shares shown
 * before the commit; the dropzone label read from the streaming limit
 * regardless of the dialog.
 */

/** Load the app, choose PBKDF2, pick the large file by path, type the password. */
async function readyToEncrypt(page: Page, plainPath: string): Promise<void> {
  await page.goto("/");
  // The label is replaced by the file's name once one is chosen.
  await expect(visible(page.getByText("or click to browse · 1 GB max, saved where you choose"))).toBeVisible();
  await selectCrypto(page, "pbkdf2", "aes");
  await page.locator("#encrypt-file").setInputFiles(plainPath);
  await expect(visible(page.getByText("large-plain.bin"))).toBeVisible();
  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
}

const encryptButton = (page: Page) => visible(page.getByRole("button", { name: /^Encrypt File$/ }));
const step = (page: Page, id: string) => page.getByTestId("workflow-steps").locator(`li[data-step="${id}"]`);

test.describe("with a save dialog", () => {
  test.beforeEach(async ({ page }) => {
    await instrument(page);
    await page.goto("/");
    test.skip(!(await hasDialog(page)), "this browser has no showSaveFilePicker; see the tests without one");
  });

  test("precondition: the stand-in commits on close and needs a click", async ({ page }) => {
    const result = await page.evaluate(async () => {
      const w = window as unknown as {
        __makeHandle: (name: string) => Promise<{ createWritable(): Promise<{ write(b: BufferSource): Promise<void>; close(): Promise<void>; abort(): Promise<void> }> }>;
        __picker: PickerRecord;
        showSaveFilePicker: () => Promise<unknown>;
      };
      const root = await navigator.storage.getDirectory();
      const sizeOf = async (name: string) => (await (await root.getFileHandle(name)).getFile()).size;

      const handle = await w.__makeHandle("pre.keym");
      const name = w.__picker.lastName!;
      const writable = await handle.createWritable();
      await writable.write(new Uint8Array(4096));
      const beforeClose = await sizeOf(name);
      await writable.close();
      const afterClose = await sizeOf(name);

      const other = await w.__makeHandle("pre2.keym");
      const otherName = w.__picker.lastName!;
      const discarded = await other.createWritable();
      await discarded.write(new Uint8Array(4096));
      await discarded.abort();
      const afterAbort = await sizeOf(otherName);

      // Without a click. Playwright's evaluate carries a user gesture of its
      // own, so wait out the activation it grants (Chromium keeps it for five
      // seconds) before asking.
      await new Promise((r) => setTimeout(r, 6000));
      const stillActive = (navigator as { userActivation?: { isActive: boolean } }).userActivation?.isActive ?? null;
      let withoutClick = "resolved";
      try {
        await w.showSaveFilePicker();
      } catch (e) {
        withoutClick = (e as Error).name;
      }
      return { beforeClose, afterClose, afterAbort, stillActive, withoutClick };
    });
    expect(result.beforeClose, "written bytes were visible before close(): the stand-in does not model the commit").toBe(0);
    expect(result.afterClose).toBe(4096);
    expect(result.afterAbort, "an aborted write left bytes behind").toBe(0);
    expect(result.stillActive, "activation outlived the wait, so the next check proves nothing").toBe(false);
    expect(result.withoutClick, "the stand-in opened without user activation").toBe("SecurityError");
  });

  test("a file above 100 MB is encrypted to the chosen file, and the page records its digest", async ({ page }, testInfo) => {
    const plain = writePlaintext(testInfo);
    await readyToEncrypt(page, plain);
    await encryptButton(page).click();
    const receipt = visible(page.getByTestId("seal-receipt"));
    await expect(receipt).toBeVisible({ timeout: 90_000 });

    const record = await picker(page);
    expect(record.calls).toHaveLength(1);
    expect(record.calls[0]!.suggestedName).toBe("large-plain.bin.keym");
    expect(record.calls[0]!.activation, "the dialog was not opened inside the click's activation").toBe(true);
    expect(record.calls[0]!.opsBefore, "the encrypt started before the dialog").not.toContain("encrypt-stream");
    expect(record.settled).toBe("closed");
    expect(await workerOps(page)).toContain("encrypt-stream");

    const saved = await chosenFile(page);
    const bytes = Number(await receipt.getAttribute("data-container-bytes"));
    const recorded = await receipt.getAttribute("data-container-sha256");
    expect(saved.size, "the chosen file is not the size the receipt reports").toBe(bytes);
    expect(saved.size).toBeGreaterThan(PLAIN_BYTES);
    expect(saved.sha256, "the digest the page recorded is not the digest of the file it saved").toBe(recorded);

    await expect(visible(page.getByTestId("receipt-written"))).toHaveText("large-plain.bin → large-plain.bin.keym");
    await expect(receipt).toContainText("The file was saved where you chose");
    await expect(step(page, "saved-copy")).toHaveAttribute("data-state", "started");
    await expect(page.getByTestId("save-progress")).toHaveCount(0);
  });

  test("Stop during the stream saves nothing", async ({ page }, testInfo) => {
    const plain = writePlaintext(testInfo);
    await readyToEncrypt(page, plain);
    // Slow the writes so Stop lands mid-stream.
    await page.evaluate(() => ((window as unknown as { __picker: PickerRecord }).__picker.writeDelayMs = 60));
    await encryptButton(page).click();
    await expect(visible(page.getByTestId("save-progress"))).toContainText("Nothing is saved until the file is complete", {
      timeout: 60_000,
    });
    await expect.poll(async () => (await picker(page)).writes, { timeout: 60_000 }).toBeGreaterThan(4);
    await visible(page.getByTestId("cancel-operation")).click();
    await expect(toast(page, /The encryption was stopped and nothing was saved\./)).toBeVisible();

    // Wait for the operation to let go of the file, then look at it.
    await expect.poll(async () => (await picker(page)).settled, { timeout: 30_000 }).not.toBeNull();
    expect((await picker(page)).settled, "the stopped file was closed, which saves it").toBe("aborted");
    expect((await chosenFile(page)).size, "a stopped save left bytes in the chosen file").toBe(0);
    await expect(page.getByTestId("seal-receipt")).toHaveCount(0);
    await expect(visible(page.getByPlaceholder("Enter a strong password"))).toHaveValue(STRONG_PASSWORD);
  });

  test("cancelling the dialog derives nothing and keeps the password", async ({ page }, testInfo) => {
    const plain = writePlaintext(testInfo);
    await readyToEncrypt(page, plain);
    await page.evaluate(() => ((window as unknown as { __picker: PickerRecord }).__picker.mode = "cancel"));
    await encryptButton(page).click();
    await expect(toast(page, /No file was chosen, so nothing was encrypted\./)).toBeVisible();
    // Give a wrongly ordered encrypt time to reach the worker.
    await page.waitForTimeout(1500);
    const record = await picker(page);
    expect(record.calls).toHaveLength(1);
    expect(record.calls[0]!.opsBefore, "the encrypt started before the dialog").not.toContain("encrypt-stream");
    expect(await workerOps(page), "an encrypt reached the worker although the dialog was cancelled").not.toContain("encrypt-stream");
    await expect(visible(page.getByPlaceholder("Enter a strong password"))).toHaveValue(STRONG_PASSWORD);
    await expect(encryptButton(page)).toBeEnabled();
  });

  test("shares appear only once the file is committed", async ({ page }, testInfo) => {
    const plain = writePlaintext(testInfo);
    await readyToEncrypt(page, plain);
    const sharesSwitch = visible(page.getByRole("switch", { name: "Recovery shares" }));
    await sharesSwitch.click();
    await expect(sharesSwitch).toHaveAttribute("aria-checked", "true");
    await page.evaluate(() => ((window as unknown as { __picker: PickerRecord }).__picker.mode = "close-rejects"));
    await encryptButton(page).click();
    await expect(toast(page, /The browser could not finish saving the encrypted file, so nothing was saved\./)).toBeVisible({
      timeout: 90_000,
    });
    await expect(page.getByRole("dialog"), "shares were shown for a file that was not saved").toHaveCount(0);
    await expect(page.getByTestId("seal-receipt")).toHaveCount(0);
    expect((await chosenFile(page)).size).toBe(0);
    await expect(visible(page.getByPlaceholder("Enter a strong password"))).toHaveValue(STRONG_PASSWORD);
  });

  test("verifying the saved file counts as evidence for the backup", async ({ page }, testInfo) => {
    const plain = writePlaintext(testInfo);
    await readyToEncrypt(page, plain);
    await encryptButton(page).click();
    await expect(visible(page.getByTestId("seal-receipt"))).toBeVisible({ timeout: 90_000 });

    // Copy the saved file out of OPFS to a real path, as a user's file on disk.
    const download = page.waitForEvent("download");
    await page.evaluate(async () => {
      const name = (window as unknown as { __picker: PickerRecord }).__picker.lastName!;
      const root = await navigator.storage.getDirectory();
      const file = await (await root.getFileHandle(name)).getFile();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(file);
      a.download = "saved.keym";
      document.body.appendChild(a);
      a.click();
      a.remove();
    });
    const savedPath = testInfo.outputPath("saved.keym");
    await (await download).saveAs(savedPath);

    await visible(page.getByRole("tab", { name: "Decrypt", exact: true })).click();
    await page.locator("#decrypt-file").setInputFiles(savedPath);
    await verifyLoadedFile(page);
    expect(await workerOps(page), "the verify was not streamed").toContain("open-stream");

    await visible(page.getByRole("tab", { name: "Encrypt", exact: true })).click();
    await expect(step(page, "saved-copy")).toHaveAttribute("data-state", "done");
    await expect(step(page, "recovery")).toHaveAttribute("data-state", "done");
    await visible(page.getByRole("tab", { name: "Recovery", exact: true })).click();
    await expect(visible(page.getByTestId("recovery-saved-copy"))).toContainText("matched this backup byte for byte");
  });
});

test.describe("without a save dialog", () => {
  // Firefox and WebKit as they are; Chromium with the dialog deleted.
  test.beforeEach(async ({ page }) => {
    await instrument(page, { removeDialog: true });
  });

  test("the labels state the limits that apply here", async ({ page }) => {
    await page.goto("/");
    await expect(visible(page.getByText("or click to browse · 100 MB max in this browser"))).toBeVisible();
    await visible(page.getByRole("tab", { name: "Decrypt", exact: true })).click();
    await expect(
      visible(page.getByText("a .keym container, or a QR image to scan · 100 MB to open here · 1 GB to verify"))
    ).toBeVisible();
  });

  test("a file above 100 MB is refused for encrypt, with the alternatives", async ({ page }, testInfo) => {
    const plain = writePlaintext(testInfo);
    await page.goto("/");
    await page.locator("#encrypt-file").setInputFiles(plain);
    const refusal = toast(page, /This browser encrypts files up to 100 MB, because it cannot save straight to a file you choose\./);
    await expect(refusal).toBeVisible();
    await expect(refusal).toContainText("Chrome or Edge");
    await expect(refusal).toContainText("up to 1 GB");
    await expect(refusal).toContainText("keym2.py");
    await expect(page.getByText("large-plain.bin")).toHaveCount(0);
    expect(await workerOps(page)).not.toContain("encrypt-stream");
  });

  test("a backup above 100 MB still verifies", async ({ page }, testInfo) => {
    const plain = writePlaintext(testInfo);
    const container = bridgeContainer(testInfo, plain);
    await page.goto("/");
    await visible(page.getByRole("tab", { name: "Decrypt", exact: true })).click();
    await page.locator("#decrypt-file").setInputFiles(container);
    await verifyLoadedFile(page);
    expect(await workerOps(page), "the verify was not streamed").toContain("open-stream");
  });

  test("a backup above 100 MB is not opened here", async ({ page }, testInfo) => {
    const plain = writePlaintext(testInfo);
    const container = bridgeContainer(testInfo, plain);
    await page.goto("/");
    await visible(page.getByRole("tab", { name: "Decrypt", exact: true })).click();
    await page.locator("#decrypt-file").setInputFiles(container);
    await visible(page.getByPlaceholder("Enter decryption password")).fill(STRONG_PASSWORD);
    await visible(page.getByRole("button", { name: /^Decrypt File$/i })).click();
    await expect(toast(page, /turn on Verify only/)).toBeVisible();
    const ops = await workerOps(page);
    expect(ops).not.toContain("decrypt");
    expect(ops).not.toContain("open-stream");
  });
});
