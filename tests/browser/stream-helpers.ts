import { expect, type Page, type TestInfo } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { closeSync, openSync, writeSync } from "node:fs";
import { resolve } from "node:path";
import { visible, STRONG_PASSWORD } from "./helpers";

/**
 * What the streamed-save suites share: a large plaintext on disk, a container
 * of it from the bridge, and the save-dialog stand-in.
 *
 * ## The save dialog is a stand-in
 *
 * Headless Chromium's real `showSaveFilePicker` rejects at once with
 * AbortError, as if the user had cancelled. So, where the browser has the
 * dialog, an init script replaces it with one that "chooses" a file in the
 * origin-private file system (OPFS) and hands back a handle whose
 * `createWritable()` is the browser's own. That is the same writable the real
 * dialog returns, with the same commit-on-close behaviour;
 * `stream-save.spec.ts`'s precondition test proves that before anything relies
 * on it. The stand-in also refuses without transient user activation, as the
 * real dialog does, and records every call, every operation the page posts to
 * the crypto worker, which worker got an `open-stream`, and every worker the
 * page terminated.
 *
 * What it cannot show is what the real dialog does on disk: whether it creates
 * or empties the chosen file on confirm, and what a crash leaves behind. The
 * page's wording claims neither.
 */

export const MIB = 1024 * 1024;
/**
 * 103 MiB, not 101, so the container it becomes is also above the in-memory
 * container limit, and a whole number of mebibytes, so its last chunk is full.
 */
export const PLAIN_BYTES = 103 * MIB;
const REPO_ROOT = resolve(__dirname, "../..");
const BRIDGE = resolve(REPO_ROOT, "reference/bridge.mjs");

/** A file of `bytes` (a whole number of mebibytes, 103 by default) at `path`, in a pattern that is not all zeros. */
export function writePlaintextAt(path: string, bytes = PLAIN_BYTES): string {
  const block = Buffer.alloc(MIB);
  const fd = openSync(path, "w");
  try {
    for (let i = 0; i < bytes / MIB; i++) {
      for (let j = 0; j < MIB; j += 4) block.writeUInt32LE((i * 2654435761 + j) >>> 0, j);
      writeSync(fd, block);
    }
  } finally {
    closeSync(fd);
  }
  return path;
}

/** `writePlaintextAt` under the test's own output directory. */
export function writePlaintext(testInfo: TestInfo, name = "large-plain.bin"): string {
  return writePlaintextAt(testInfo.outputPath(name));
}

/**
 * A container of `plainPath` at `out`, written by the TypeScript streaming
 * writer through the conformance bridge, for browsers that cannot write one
 * this large themselves. PBKDF2 at 600,000 iterations, the fastest the format
 * writes, and a pinned salt and master key: a test fixture, the one case §4.5
 * allows them.
 */
export function bridgeContainerAt(plainPath: string, out: string): string {
  execFileSync("node", [
    BRIDGE, "encrypt2stream",
    "--password", STRONG_PASSWORD,
    "--in", plainPath,
    "--out", out,
    "--cipher", "aes",
    "--kdf", "pbkdf2", "--iterations", "600000",
    "--salt", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "--master-key", "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    "--container-id", "404142434445464748494a4b4c4d4e4f",
  ], { cwd: REPO_ROOT, encoding: "utf8" });
  return out;
}

/** `bridgeContainerAt` under the test's own output directory. */
export function bridgeContainer(testInfo: TestInfo, plainPath: string): string {
  return bridgeContainerAt(plainPath, testInfo.outputPath("large-bridge.keym"));
}

export interface PickerRecord {
  calls: { suggestedName: string | undefined; activation: boolean | null; opsBefore: string[] }[];
  mode: "ok" | "cancel" | "close-rejects";
  writeDelayMs: number;
  writes: number;
  lastName: string | null;
  settled: "closed" | "aborted" | null;
}

/**
 * Record what the page posts to the crypto worker, and, where the browser has
 * a save dialog, replace it with the OPFS stand-in described above.
 */
export async function instrument(page: Page, opts: { removeDialog?: boolean } = {}): Promise<void> {
  await page.addInitScript((removeDialog: boolean) => {
    const w = window as unknown as Record<string, unknown> & {
      __workerOps: string[];
      __picker: PickerRecord;
      __openWorker: Worker | null;
      __terminated: Worker[];
    };
    w.__workerOps = [];
    w.__openWorker = null;
    w.__terminated = [];
    const post = Worker.prototype.postMessage as (this: Worker, message: unknown, ...rest: unknown[]) => void;
    Worker.prototype.postMessage = function (this: Worker, message: unknown, ...rest: unknown[]) {
      const op = (message as { op?: unknown } | null)?.op;
      if (typeof op === "string") w.__workerOps.push(op);
      if (op === "open-stream") w.__openWorker = this;
      return post.call(this, message, ...rest);
    } as typeof Worker.prototype.postMessage;
    const terminate = Worker.prototype.terminate as (this: Worker) => void;
    Worker.prototype.terminate = function (this: Worker) {
      w.__terminated.push(this);
      return terminate.call(this);
    };

    if (removeDialog) {
      Object.defineProperty(window, "showSaveFilePicker", { value: undefined, configurable: true, writable: true });
    }
    w.__nativePicker = typeof (window as { showSaveFilePicker?: unknown }).showSaveFilePicker === "function";
    if (!w.__nativePicker) return;

    const record: PickerRecord = { calls: [], mode: "ok", writeDelayMs: 0, writes: 0, lastName: null, settled: null };
    w.__picker = record;
    let n = 0;
    /** A handle over a fresh OPFS file, reporting `shownName` as the browser would report the chosen name. */
    const makeHandle = async (shownName: string) => {
      const root = await navigator.storage.getDirectory();
      const opfsName = `chosen-${++n}.bin`;
      const real = await root.getFileHandle(opfsName, { create: true });
      record.lastName = opfsName;
      record.settled = null;
      return {
        kind: "file",
        name: shownName,
        createWritable: async (options?: FileSystemCreateWritableOptions) => {
          const ws = await real.createWritable(options);
          return {
            write: async (bytes: BufferSource) => {
              record.writes++;
              if (record.writeDelayMs) await new Promise((r) => setTimeout(r, record.writeDelayMs));
              return ws.write(bytes);
            },
            close: async () => {
              if (record.mode === "close-rejects") {
                await ws.abort();
                record.settled = "aborted";
                throw new DOMException("There is not enough space on the disk.", "QuotaExceededError");
              }
              await ws.close();
              record.settled = "closed";
            },
            abort: async (reason?: unknown) => {
              await ws.abort(reason);
              record.settled = "aborted";
            },
          };
        },
      };
    };
    w.__makeHandle = makeHandle;
    (window as { showSaveFilePicker?: unknown }).showSaveFilePicker = async (options?: { suggestedName?: string }) => {
      const activation = (navigator as { userActivation?: { isActive: boolean } }).userActivation?.isActive ?? null;
      record.calls.push({ suggestedName: options?.suggestedName, activation, opsBefore: [...w.__workerOps] });
      // The real dialog needs the click's transient activation.
      if (activation === false) {
        throw new DOMException("Must be handling a user gesture to show a file picker.", "SecurityError");
      }
      if (record.mode === "cancel") throw new DOMException("The user aborted a request.", "AbortError");
      return makeHandle(options?.suggestedName ?? "untitled");
    };
  }, opts.removeDialog === true);
}

export const hasDialog = (page: Page) =>
  page.evaluate(() => (window as unknown as { __nativePicker: boolean }).__nativePicker);
export const picker = (page: Page) => page.evaluate(() => (window as unknown as { __picker: PickerRecord }).__picker);
export const workerOps = (page: Page) => page.evaluate(() => (window as unknown as { __workerOps: string[] }).__workerOps);

/** The size and SHA-256 of the last OPFS file the stand-in handed out, read in the page. */
export async function chosenFile(page: Page): Promise<{ size: number; sha256: string }> {
  return page.evaluate(async () => {
    const name = (window as unknown as { __picker: PickerRecord }).__picker.lastName!;
    const root = await navigator.storage.getDirectory();
    const file = await (await root.getFileHandle(name)).getFile();
    const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
    return {
      size: file.size,
      sha256: Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join(""),
    };
  });
}

/** A toast, by its text. The live region repeats every toast, so this reads the visible one. */
export const toast = (page: Page, text: string | RegExp) => page.getByLabel(/^Notifications/).getByText(text);

/** Turn on Verify only for the loaded file and verify it with the shared password. */
export async function verifyLoadedFile(page: Page): Promise<void> {
  await visible(page.getByPlaceholder("Enter decryption password")).fill(STRONG_PASSWORD);
  const toggle = visible(page.getByLabel(/Verify only/i));
  if (!(await toggle.isChecked())) await toggle.click();
  await expect(toggle).toBeChecked();
  await visible(page.getByRole("button", { name: /^Verify File$/i })).click();
  await expect(visible(page.getByTestId("verify-result"))).toContainText("The backup opens with this password", {
    timeout: 90_000,
  });
}
