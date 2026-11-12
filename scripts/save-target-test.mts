/**
 * The per-browser file limits, and the save target's state machine, without a
 * browser.
 *
 * `fileLimits` decides how large a file each action takes in this browser:
 * encrypt, and opening a backup, stream to a file the user chooses only where
 * there is a save dialog and a worker, and stay at the in-memory cap everywhere
 * else; verify reads a chunk at a time wherever there is a worker. The
 * dropzone's label and the refusals are built from the same answer, so they
 * are held to it here too.
 *
 * `saveTargetOver` is the file the page writes a streamed backup to. Its rules
 * are the ones that keep a backup from being reported as saved when it was
 * not: nothing can be committed once aborted, an abort after the commit does
 * nothing, a commit whose close() rejects is not committed, and nothing can be
 * written once the target is no longer open.
 *
 * Negative controls (each was applied by hand, built, and seen to fail here):
 * - make `abort()` call through after a commit: "abort after commit is a
 *   no-op" fails.
 * - return the streaming limit when `toDisk` is false: the "no save dialog"
 *   checks fail.
 * - keep `decryptOpen` at the in-memory cap with a dialog and a worker: the
 *   "opening streams to a chosen file" check fails.
 */
import {
  MAX_CONTAINER_SIZE,
  MAX_PLAINTEXT_SIZE,
  MAX_STREAM_CONTAINER_SIZE,
  MAX_STREAM_PLAINTEXT_SIZE,
} from "../src/lib/keymaker-crypto.ts";
import {
  canSaveToDisk,
  chooseSaveTarget,
  saveTargetOver,
  SaveFailed,
  SAVE_COMMIT_FAILED,
  SAVE_NOT_OPEN,
  SAVE_OPEN_FAILED,
  SAVE_PICKER_FAILED,
  SAVE_WRITE_FAILED,
  SAVE_MAY_REMAIN,
  DECRYPT_SAVE_COMMIT_FAILED,
  DECRYPT_SAVE_OPEN_FAILED,
  DECRYPT_SAVE_PICKER_FAILED,
  DECRYPT_SAVE_WRITE_FAILED,
  type WritableLike,
} from "../src/lib/save-target.ts";
import {
  dropzoneLabel,
  decryptOpenTooLarge,
  encryptTooLarge,
  fileLimits,
  notStreamableRefusal,
  pickerLimit,
  DECRYPT_SAVE_FAILED,
  NOTHING_DECRYPTED_SAVED_ON_STOP,
} from "../src/components/encryptor/shared.ts";
import { oversizeRecoveryHelp } from "../src/lib/keymaker-crypto.ts";

let passed = 0;
let failed = 0;
function check(name: string, ok: boolean, detail = "") {
  if (ok) {
    passed++;
    console.log(`ok    ${name}`);
  } else {
    failed++;
    console.log(`FAIL  ${name}${detail ? ` (${detail})` : ""}`);
  }
}

/** Run `fn`, returning what it threw, or null if it did not. */
async function thrown(fn: () => Promise<unknown>): Promise<unknown> {
  try {
    await fn();
    return null;
  } catch (error) {
    return error;
  }
}

// ---------------------------------------------------------------------------
// fileLimits
// ---------------------------------------------------------------------------
{
  const chromium = fileLimits({ toDisk: true, worker: true });
  check("save dialog and worker: encrypt streams up to 1 GiB", chromium.encrypt === MAX_STREAM_PLAINTEXT_SIZE);
  check("save dialog and worker: verify streams", chromium.verify === MAX_STREAM_CONTAINER_SIZE);
  check("save dialog and worker: opening streams to a chosen file, as far as verify reads",
    chromium.decryptOpen === MAX_STREAM_CONTAINER_SIZE && chromium.decryptOpen === chromium.verify, `got ${chromium.decryptOpen}`);

  const noDialog = fileLimits({ toDisk: false, worker: true });
  check("no save dialog: encrypt stays at the in-memory cap", noDialog.encrypt === MAX_PLAINTEXT_SIZE,
    `got ${noDialog.encrypt}`);
  check("no save dialog: verify still streams", noDialog.verify === MAX_STREAM_CONTAINER_SIZE);
  check("no save dialog: opening stays in memory", noDialog.decryptOpen === MAX_CONTAINER_SIZE);

  const noWorker = fileLimits({ toDisk: true, worker: false });
  check("no worker: encrypt stays at the in-memory cap, dialog or not", noWorker.encrypt === MAX_PLAINTEXT_SIZE);
  check("no worker: verify stays at the in-memory cap", noWorker.verify === MAX_CONTAINER_SIZE);
  check("no worker: opening stays in memory, dialog or not", noWorker.decryptOpen === MAX_CONTAINER_SIZE,
    `got ${noWorker.decryptOpen}`);

  const neither = fileLimits({ toDisk: false, worker: false });
  check("neither: every action at the in-memory cap",
    neither.encrypt === MAX_PLAINTEXT_SIZE && neither.verify === MAX_CONTAINER_SIZE && neither.decryptOpen === MAX_CONTAINER_SIZE);

  check("the encrypt picker takes what encrypt takes", pickerLimit("encrypt", chromium) === chromium.encrypt
    && pickerLimit("encrypt", noDialog) === MAX_PLAINTEXT_SIZE);
  check("the decrypt picker takes the larger of open and verify",
    pickerLimit("decrypt", noDialog) === MAX_STREAM_CONTAINER_SIZE && pickerLimit("decrypt", neither) === MAX_CONTAINER_SIZE);
}

// ---------------------------------------------------------------------------
// The words built from those limits
// ---------------------------------------------------------------------------
{
  const label = (mode: "encrypt" | "decrypt", toDisk: boolean, worker: boolean) => dropzoneLabel(mode, { toDisk, worker });
  check("encrypt label with a save dialog", label("encrypt", true, true) === "or click to browse · 1 GB max, saved where you choose",
    label("encrypt", true, true));
  check("encrypt label without a save dialog", label("encrypt", false, true) === "or click to browse · 100 MB max in this browser",
    label("encrypt", false, true));
  check("encrypt label without a worker", label("encrypt", true, false) === "or click to browse · 100 MB max in this browser");
  check("decrypt label with a save dialog and a worker",
    label("decrypt", true, true) === "a .keym container, or a QR image to scan · 1 GB max, saved where you choose",
    label("decrypt", true, true));
  check("decrypt label with a worker and no save dialog",
    label("decrypt", false, true) === "a .keym container, or a QR image to scan · 100 MB to open here · 1 GB to verify",
    label("decrypt", false, true));
  check("decrypt label without a worker", label("decrypt", false, false) === "a .keym container, or a QR image to scan · 100 MB max"
    && label("decrypt", true, false) === label("decrypt", false, false), label("decrypt", true, false));

  const openNoDialog = decryptOpenTooLarge({ toDisk: false, worker: true });
  check("the no-dialog open refusal keeps the recovery help, offers Verify only, and names where it can be opened",
    openNoDialog.description.includes("keym2.py decrypt") && /turn on Verify only/.test(openNoDialog.description)
      && /Chrome or Edge, can open backups up to 1 GB/.test(openNoDialog.description),
    openNoDialog.description);
  const openNoWorker = decryptOpenTooLarge({ toDisk: true, worker: false });
  check("the no-worker open refusal keeps the recovery help and offers nothing it cannot do",
    openNoWorker.description.includes("keym2.py decrypt") && !/Verify only|Chrome/.test(openNoWorker.description),
    openNoWorker.description);
  const openOver = decryptOpenTooLarge({ toDisk: true, worker: true });
  check("above the streaming ceiling the open refusal names 1 GiB and the reference",
    openOver.description.includes("1 GiB") && openOver.description.includes("keym2.py decrypt") && !/Verify only/.test(openOver.description),
    openOver.description);
  for (const [format, name] of [["keym-v1", "KEYM v1 backup"], ["ibtz-v1", "IttyBitz v1 backup"], ["ibtz-v0", "not a binary KEYM v2"]] as const) {
    const text = notStreamableRefusal(format, false);
    check(`a ${format} file above the limit is refused by name, with the recovery help`,
      text.includes(name) && text.includes("keym2.py decrypt") && /this app opens only/.test(text), text);
  }
  check("the verify form of that refusal says Verify only", /Verify only reads only/.test(notStreamableRefusal("keym-v1", true)));
  check("no open refusal, nor the stop and failure words, uses an em-dash",
    ![openNoDialog, openNoWorker, openOver].some((r) => /—/.test(r.title + r.description.replace(oversizeRecoveryHelp(), "")
      .replace(oversizeRecoveryHelp("streaming"), "")))
      && ![NOTHING_DECRYPTED_SAVED_ON_STOP, DECRYPT_SAVE_FAILED, notStreamableRefusal("keym-v1", false).replace(oversizeRecoveryHelp(), "")]
        .some((m) => /—/.test(m)));
  check("a failed decrypt save says decryption failed, nothing was saved, and what may be left",
    DECRYPT_SAVE_FAILED.startsWith("Decryption failed, so nothing was saved.") && DECRYPT_SAVE_FAILED.endsWith(SAVE_MAY_REMAIN));

  const noDialog = encryptTooLarge({ toDisk: false, worker: true });
  check("the no-dialog refusal names this browser's limit and both alternatives",
    noDialog.description.includes("up to 100 MB") && /Chrome or Edge/.test(noDialog.description)
      && noDialog.description.includes("1 GB") && noDialog.description.includes("keym2.py"),
    noDialog.description);
  const noWorker = encryptTooLarge({ toDisk: true, worker: false });
  check("the no-worker refusal says why, and names the limit",
    /background worker/.test(noWorker.description) && noWorker.description.includes("up to 100 MB")
      && !/Chrome or Edge/.test(noWorker.description),
    noWorker.description);
  const over = encryptTooLarge({ toDisk: true, worker: true });
  check("the over-the-ceiling refusal names 1 GB", over.description.includes("1 GB") && over.description.includes("keym2.py"),
    over.description);
  check("no refusal uses an em-dash", ![noDialog, noWorker, over].some((r) => /—/.test(r.title + r.description)));
}

// ---------------------------------------------------------------------------
// The save target's state machine
// ---------------------------------------------------------------------------

/** A writable that records what it was asked to do. */
function fakeWritable(opts: { closeRejects?: boolean; writeRejects?: boolean; abortRejects?: boolean; closeGate?: Promise<void> } = {}) {
  const calls: string[] = [];
  const written: number[] = [];
  const w: WritableLike = {
    async write(bytes) {
      calls.push("write");
      if (opts.writeRejects) throw new Error("disk full");
      written.push(bytes.length);
    },
    async close() {
      calls.push("close");
      if (opts.closeGate) await opts.closeGate;
      if (opts.closeRejects) throw new Error("close failed");
    },
    async abort() {
      calls.push("abort");
      if (opts.abortRejects) throw new Error("abort failed");
    },
  };
  return { w, calls, written };
}

{
  const f = fakeWritable();
  const t = saveTargetOver("backup.keym", f.w);
  check("a new target is open and named", t.state === "open" && t.name === "backup.keym");
  await t.write(new Uint8Array(3));
  await t.write(new Uint8Array(5));
  await t.commit();
  check("write, write, commit: committed, closed once", t.state === "committed" && f.calls.join(",") === "write,write,close",
    f.calls.join(","));
  await t.abort();
  check("abort after commit is a no-op", t.state === "committed" && !f.calls.includes("abort"), f.calls.join(","));
  const again = await thrown(() => t.commit());
  check("a second commit is refused", again instanceof SaveFailed && (again as Error).message === SAVE_NOT_OPEN);
  const late = await thrown(() => t.write(new Uint8Array(1)));
  check("a write after commit is refused, and never reaches the file",
    late instanceof SaveFailed && f.calls.filter((c) => c === "write").length === 2);
}

{
  const f = fakeWritable();
  const t = saveTargetOver("b.keym", f.w);
  await t.write(new Uint8Array(1));
  await t.abort();
  check("abort discards: aborted, the writable aborted", t.state === "aborted" && f.calls.join(",") === "write,abort");
  const commit = await thrown(() => t.commit());
  check("commit after abort is impossible",
    commit instanceof SaveFailed && t.state === "aborted" && !f.calls.includes("close"), f.calls.join(","));
  const write = await thrown(() => t.write(new Uint8Array(1)));
  check("write after abort rejects, and never reaches the file",
    write instanceof SaveFailed && f.calls.filter((c) => c === "write").length === 1);
  await t.abort();
  check("a second abort does nothing", f.calls.filter((c) => c === "abort").length === 1);
}

{
  const f = fakeWritable({ closeRejects: true });
  const t = saveTargetOver("c.keym", f.w);
  await t.write(new Uint8Array(1));
  const error = await thrown(() => t.commit());
  check("a rejected close() leaves the target not committed", t.state !== "committed", t.state);
  check("a rejected close() is reported as not saved",
    error instanceof SaveFailed && (error as Error).message === SAVE_COMMIT_FAILED);
  await t.abort();
  check("abort after a rejected close does not touch the errored stream", !f.calls.includes("abort"));
}

{
  const f = fakeWritable({ writeRejects: true });
  const t = saveTargetOver("d.keym", f.w);
  const error = await thrown(() => t.write(new Uint8Array(1)));
  check("a failed write is reported as not saved", error instanceof SaveFailed && (error as Error).message === SAVE_WRITE_FAILED);
  check("a failed write leaves the target open, so it can still be discarded", t.state === "open");
  await t.abort();
  check("and the abort reaches the writable", f.calls.includes("abort") && t.state === "aborted");
}

{
  // A decrypt's target: the same rules, its failures in its own words.
  const w = fakeWritable({ writeRejects: true });
  const t = saveTargetOver("photo.jpg", w.w, "decrypt");
  const error = await thrown(() => t.write(new Uint8Array(1)));
  check("a decrypt's failed write says the decrypted file was not saved, and what may be left",
    error instanceof SaveFailed && (error as Error).message === DECRYPT_SAVE_WRITE_FAILED
      && DECRYPT_SAVE_WRITE_FAILED.endsWith(SAVE_MAY_REMAIN));
  const c = fakeWritable({ closeRejects: true });
  const tc = saveTargetOver("photo.jpg", c.w, "decrypt");
  const closeError = await thrown(() => tc.commit());
  check("a decrypt's rejected close is not a save, in its own words",
    closeError instanceof SaveFailed && (closeError as Error).message === DECRYPT_SAVE_COMMIT_FAILED && tc.state !== "committed");
  check("no save message uses an em-dash or claims a file was encrypted on decrypt",
    ![DECRYPT_SAVE_WRITE_FAILED, DECRYPT_SAVE_COMMIT_FAILED, DECRYPT_SAVE_OPEN_FAILED, DECRYPT_SAVE_PICKER_FAILED]
      .some((m) => /—|encrypt/.test(m)));
}

{
  const f = fakeWritable({ abortRejects: true });
  const t = saveTargetOver("e.keym", f.w);
  const error = await thrown(() => t.abort());
  check("abort swallows the writable's own failure", error === null && t.state === "aborted");
}

{
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  const f = fakeWritable({ closeGate: gate });
  const t = saveTargetOver("f.keym", f.w);
  const committing = t.commit();
  check("while close() runs the target is committing", t.state === "committing");
  await t.abort();
  check("abort while committing is a no-op", !f.calls.includes("abort") && t.state === "committing");
  const write = await thrown(() => t.write(new Uint8Array(1)));
  check("a write while committing is refused", write instanceof SaveFailed && !f.calls.includes("write"));
  release();
  await committing;
  check("and the commit then completes", t.state === "committed");
}

// ---------------------------------------------------------------------------
// canSaveToDisk and chooseSaveTarget, against a stand-in window
// ---------------------------------------------------------------------------
{
  check("no window: cannot save to disk", canSaveToDisk() === false);
  const g = globalThis as unknown as { window?: unknown };
  const fakeWindow: Record<string, unknown> = { isSecureContext: true };
  fakeWindow.top = fakeWindow;
  g.window = fakeWindow;
  try {
    check("no save dialog: cannot save to disk", canSaveToDisk() === false);
    let picks = 0;
    let pickResult: () => Promise<unknown> = async () => {
      throw Object.assign(new Error("The user aborted a request."), { name: "AbortError" });
    };
    fakeWindow.showSaveFilePicker = () => {
      picks++;
      return pickResult();
    };
    check("a top-level secure page with the dialog can", canSaveToDisk() === true);
    fakeWindow.isSecureContext = false;
    check("an insecure page cannot", canSaveToDisk() === false);
    fakeWindow.isSecureContext = true;
    fakeWindow.top = {};
    check("a framed page cannot", canSaveToDisk() === false);
    const framed = await thrown(() => chooseSaveTarget("x.keym"));
    check("a framed page is refused before the dialog opens",
      framed instanceof SaveFailed && (framed as Error).message === SAVE_PICKER_FAILED && picks === 0);
    fakeWindow.top = fakeWindow;

    check("a cancelled dialog is null, not an error", (await chooseSaveTarget("x.keym")) === null && picks === 1);
    pickResult = async () => {
      throw Object.assign(new Error("Must be handling a user gesture"), { name: "SecurityError" });
    };
    const refused = await thrown(() => chooseSaveTarget("x.keym"));
    check("any other dialog failure is a typed refusal",
      refused instanceof SaveFailed && (refused as Error).message === SAVE_PICKER_FAILED);
    pickResult = async () => ({ name: "y.keym", createWritable: async () => { throw new Error("locked"); } });
    const unopened = await thrown(() => chooseSaveTarget("x.keym"));
    check("a file that will not open is a typed refusal",
      unopened instanceof SaveFailed && (unopened as Error).message === SAVE_OPEN_FAILED);
    const f = fakeWritable();
    pickResult = async () => ({ name: "chosen.keym", createWritable: async () => f.w });
    const t = await chooseSaveTarget("x.keym");
    check("a chosen file opens as an open target named as the browser reports it",
      t !== null && t.state === "open" && t.name === "chosen.keym");

    // A decrypt's dialog: no .keym type offered, the name passed through,
    // and its failures in its own words.
    let options: unknown = null;
    fakeWindow.showSaveFilePicker = (o: unknown) => {
      options = o;
      return pickResult();
    };
    const plain = await chooseSaveTarget("photo.jpg", "decrypt");
    check("a decrypt's dialog suggests the name it is given and offers no file type",
      plain !== null && JSON.stringify(options) === JSON.stringify({ suggestedName: "photo.jpg" }), JSON.stringify(options));
    pickResult = async () => {
      throw Object.assign(new Error("Must be handling a user gesture"), { name: "SecurityError" });
    };
    const refusedDecrypt = await thrown(() => chooseSaveTarget("photo.jpg", "decrypt"));
    check("a decrypt's dialog failure says nothing was saved, not that nothing was encrypted",
      refusedDecrypt instanceof SaveFailed && (refusedDecrypt as Error).message === DECRYPT_SAVE_PICKER_FAILED);
    pickResult = async () => ({ name: "y", createWritable: async () => { throw new Error("locked"); } });
    const unopenedDecrypt = await thrown(() => chooseSaveTarget("photo.jpg", "decrypt"));
    check("a decrypt's file that will not open says nothing was saved",
      unopenedDecrypt instanceof SaveFailed && (unopenedDecrypt as Error).message === DECRYPT_SAVE_OPEN_FAILED);
  } finally {
    delete g.window;
  }
}

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
