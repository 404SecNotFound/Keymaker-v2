/**
 * A one-shot save target: the file the user chose in the browser's save
 * dialog, written once, in order, and committed at the end.
 *
 * This is what lets a file above the in-memory cap be encrypted at all. The
 * container is too large to assemble into a Blob and download, so it is
 * written a chunk at a time to a file the user picked, and nothing else.
 * Nothing is stored between visits, no handle is kept, nothing is read back:
 * the ciphertext lands only where the user chose to save it, as a download
 * would. The roadmap records why this much of the File System Access API is
 * admitted and a workspace or a vault is not.
 *
 * ## Commit on close
 *
 * `createWritable()` writes to a temporary file and makes it the chosen file
 * only on `close()`. Observed in Chromium on an OPFS handle: the file's size
 * is 0 until `close()` resolves, and after `abort()` a file that already
 * existed keeps its old bytes. So `commit()` is the moment the backup exists,
 * and a rejected `commit()` means it does not. What the real save dialog does
 * on disk before that (whether it creates or empties the chosen file when the
 * user confirms, and what a crash leaves) has not been observed, so the page
 * says no more than: nothing is saved until the file is complete, and a
 * stopped or failed save may leave an empty or partial temporary file where
 * the user chose to save.
 *
 * ## Not removing what was left
 *
 * After a failed or stopped save this does not call the non-standard
 * `handle.remove()`. If the user chose to overwrite an existing file, removing
 * the handle could delete that file, which is worse than leaving a temporary
 * one behind.
 *
 * The state machine is `saveTargetOver`, over any object with the three calls
 * it uses, so it can be tested without a browser.
 */

/** A save that did not complete, with a message the page shows as it is. */
export class SaveFailed extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "SaveFailed";
  }
}

const MAY_REMAIN = "An empty or partial temporary file may be left where you chose to save it.";

export const SAVE_WRITE_FAILED =
  `The encrypted file could not be written where you chose to save it, so nothing was saved. ${MAY_REMAIN}`;
export const SAVE_COMMIT_FAILED =
  `The browser could not finish saving the encrypted file, so nothing was saved. ${MAY_REMAIN}`;
export const SAVE_OPEN_FAILED =
  "The browser could not open the file you chose for writing, so nothing was encrypted or saved.";
export const SAVE_PICKER_FAILED =
  "The browser could not show the save dialog, so nothing was encrypted or saved.";
export const SAVE_NOT_OPEN = "This save has already finished or been stopped.";

/**
 * Can this page save straight to a file the user chooses?
 *
 * Only in a top-level, secure page with the save dialog: Chromium on the
 * desktop. Firefox and Safari have no `showSaveFilePicker`, a worker has none,
 * and a framed page is refused by the browser, so each of those keeps the
 * in-memory path and its cap.
 */
export function canSaveToDisk(): boolean {
  if (typeof window === "undefined") return false;
  try {
    return typeof window.showSaveFilePicker === "function" && window.isSecureContext === true && window.top === window;
  } catch {
    // A cross-origin parent can make reading `top` throw in some embeddings.
    return false;
  }
}

export type SaveTargetState = "open" | "committing" | "committed" | "aborted";

export interface SaveTarget {
  /** The name of the file the user chose, as the browser reports it. */
  readonly name: string;
  readonly state: SaveTargetState;
  /** Append bytes. Rejects unless the target is open. */
  write(bytes: Uint8Array): Promise<void>;
  /** Close the file, which is what saves it. A rejection means it was NOT saved. */
  commit(): Promise<void>;
  /** Discard what was written. A no-op once committing or committed; never rejects. */
  abort(): Promise<void>;
}

/** The three calls a target needs from `FileSystemWritableFileStream`. */
export interface WritableLike {
  write(bytes: Uint8Array): Promise<void>;
  close(): Promise<void>;
  abort(reason?: unknown): Promise<void>;
}

/** The state machine, over any writable. `chooseSaveTarget` wraps the real one. */
export function saveTargetOver(name: string, writable: WritableLike): SaveTarget {
  let state: SaveTargetState = "open";
  return {
    name,
    get state() {
      return state;
    },
    async write(bytes: Uint8Array): Promise<void> {
      if (state !== "open") throw new SaveFailed(SAVE_NOT_OPEN);
      try {
        await writable.write(bytes);
      } catch (cause) {
        // The target stays open so the caller's `abort()` still discards the
        // temporary file; nothing here can be committed after a failed write
        // because the caller stops at the first rejection.
        throw new SaveFailed(SAVE_WRITE_FAILED, { cause });
      }
    },
    async commit(): Promise<void> {
      if (state !== "open") throw new SaveFailed(SAVE_NOT_OPEN);
      state = "committing";
      try {
        await writable.close();
      } catch (cause) {
        // Not committed, and it cannot be: a stream whose close rejected is
        // errored. Marked aborted so a later `abort()` does not touch it.
        state = "aborted";
        throw new SaveFailed(SAVE_COMMIT_FAILED, { cause });
      }
      state = "committed";
    },
    async abort(): Promise<void> {
      if (state !== "open") return;
      state = "aborted";
      try {
        await writable.abort();
      } catch {
        // Already errored or closed by the browser. Nothing more to discard.
      }
    },
  };
}

/**
 * Ask the user where to save, and open that file for writing.
 *
 * Must be the first thing awaited after the click that asked for it: the
 * dialog needs the click's transient activation, which Chromium was observed
 * to keep for about three seconds and lose by six. Resolves null when the user
 * cancels the dialog.
 */
export async function chooseSaveTarget(suggestedName: string): Promise<SaveTarget | null> {
  if (!canSaveToDisk()) throw new SaveFailed(SAVE_PICKER_FAILED);
  let handle: FileSystemFileHandle;
  try {
    handle = await window.showSaveFilePicker!({
      suggestedName,
      types: [{ description: "Keymaker backup", accept: { "application/octet-stream": [".keym"] } }],
    });
  } catch (error) {
    if ((error as { name?: unknown } | null)?.name === "AbortError") return null;
    throw new SaveFailed(SAVE_PICKER_FAILED, { cause: error });
  }
  let writable: FileSystemWritableFileStream;
  try {
    writable = await handle.createWritable();
  } catch (error) {
    throw new SaveFailed(SAVE_OPEN_FAILED, { cause: error });
  }
  return saveTargetOver(handle.name, {
    write: (bytes) => writable.write(bytes as Uint8Array<ArrayBuffer>),
    close: () => writable.close(),
    abort: (reason) => writable.abort(reason),
  });
}
