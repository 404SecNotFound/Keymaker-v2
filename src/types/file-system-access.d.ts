/**
 * The one part of the File System Access API this app uses that TypeScript's
 * DOM library does not declare: the save dialog. `FileSystemFileHandle`,
 * `createWritable()` and `FileSystemWritableFileStream` are in the DOM lib
 * already.
 *
 * Declared optional, because it is: Chromium on the desktop has it, Firefox
 * and Safari do not, and it is undefined inside a worker. `canSaveToDisk()` in
 * `src/lib/save-target.ts` is the only place that asks.
 */
interface SaveFilePickerAcceptType {
  description?: string;
  accept: Record<string, string | string[]>;
}

interface SaveFilePickerOptions {
  suggestedName?: string;
  types?: SaveFilePickerAcceptType[];
  excludeAcceptAllOption?: boolean;
  id?: string;
}

interface Window {
  showSaveFilePicker?: (options?: SaveFilePickerOptions) => Promise<FileSystemFileHandle>;
}
