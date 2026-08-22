"use client";

/**
 * Main-thread client for the crypto worker.
 *
 * Presents the same shape as calling `encryptContainer`/`decryptData` directly,
 * so the UI does not have to know which side of the boundary the work happened on,
 * and adds the one thing the in-thread version could never offer: a cancel that
 * actually stops the derivation.
 *
 * ## Falling back is not optional
 *
 * If a Worker cannot be constructed — an unusual embedding, a policy that
 * blocks it, a browser we have not met — the app must keep working rather than
 * lose encryption entirely. Every call therefore falls back to the in-thread
 * implementation. That path is slower and freezes the tab, which is exactly
 * what we are trying to escape, but a frozen tab beats a broken tool.
 *
 * The fallback is deliberately *silent* in the crypto sense: same functions,
 * same bytes, same errors. Only the responsiveness differs.
 */

import {
  encryptContainer,
  decryptData,
  secureErase,
  KeymakerError,
  type KeymakerErrorCode,
  type KeymakerOptions,
  type DetectedFormat,
} from "./keymaker-crypto";
import type { CryptoRequest, CryptoResponse } from "./crypto-worker";
import { calibrateArgon2, type Calibration } from "./kdf-calibration";

export interface DecryptOutcome {
  data: ArrayBuffer;
  format: DetectedFormat;
  keyFileUsed: boolean;
}

interface Pending {
  resolve: (value: never) => void;
  reject: (reason: unknown) => void;
}

let worker: Worker | null = null;
/** Set once the worker has proven unusable, so we stop retrying on every call. */
let workerUnavailable = false;
/**
 * Resolves true once the worker has answered a probe, false if it cannot.
 *
 * This exists because of an ordering hazard. Buffers are *transferred* to the
 * worker, which detaches them on this side — so if the worker turns out to be
 * broken after we have already posted, there is nothing left to retry with and
 * the operation is simply lost. Proving the worker answers *before* handing it
 * the only copy of a user's plaintext removes that failure mode entirely.
 *
 * The probe costs one round-trip at warm-up, off the critical path.
 */
let readiness: Promise<boolean> | null = null;
let nextId = 1;
const pending = new Map<number, Pending>();

/** True when the last operation ran off the main thread. Exposed for tests. */
export let lastRunUsedWorker = false;

function spawn(): Worker | null {
  if (workerUnavailable) return null;
  if (worker) return worker;

  try {
    // Served from the origin root, like sw.js, and bundled by
    // scripts/build-crypto-worker.mjs rather than by Turbopack — see that file
    // for why the idiomatic `new Worker(new URL(...))` does not survive a
    // static export here.
    //
    // BASE is the deployment subdirectory ("" at a domain root,
    // "/Keymaker-v2" on a GitHub Pages project site). Without it the worker
    // would be requested from the domain root and 404.
    const base = (process.env.KEYMAKER_BASE_PATH || "").replace(/\/$/, "");
    worker = new Worker(`${base}/crypto-worker.js`, { name: "keymaker-crypto" });

    worker.addEventListener("message", (event: MessageEvent<CryptoResponse>) => {
      const res = event.data;
      const entry = pending.get(res.id);
      if (!entry) return;
      pending.delete(res.id);

      if (res.ok === false) {
        // Rebuild the typed error. Without this the Phase 1 distinction is lost
        // in transit and every structural fault reads as a wrong password.
        entry.reject(
          res.code
            ? new KeymakerError(res.code as KeymakerErrorCode, res.message)
            : new Error(res.message)
        );
        return;
      }
      entry.resolve(res as never);
    });

    // A worker that dies takes every in-flight operation with it. Reject them
    // rather than leaving the UI waiting on a promise that can never settle.
    //
    // A script that fails to load reaches here too, and in that case retrying
    // would fail identically every time — so the worker is marked unusable and
    // everything afterwards runs in-thread.
    worker.addEventListener("error", () => {
      workerUnavailable = true;
      readiness = Promise.resolve(false);
      failAllPending(new Error("Processing failed. Please try again."));
      terminate();
    });

    return worker;
  } catch {
    workerUnavailable = true;
    worker = null;
    return null;
  }
}

/**
 * Has the worker answered a probe?
 *
 * Deliberately not cached as "unavailable" on timeout alone: a slow first paint
 * on a cold cache can delay the reply without meaning anything is wrong. It is
 * cached as unavailable only when construction throws or the script errors.
 */
function ready(): Promise<boolean> {
  if (readiness) return readiness;
  const w = spawn();
  if (!w) {
    readiness = Promise.resolve(false);
    return readiness;
  }
  const id = nextId++;
  readiness = new Promise<boolean>((resolve) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      resolve(false);
    }, 10_000);
    pending.set(id, {
      resolve: (() => {
        clearTimeout(timer);
        resolve(true);
      }) as unknown as (v: never) => void,
      reject: () => {
        clearTimeout(timer);
        resolve(false);
      },
    });
    w.postMessage({ id, op: "ping" } satisfies CryptoRequest);
  });
  return readiness;
}

function failAllPending(reason: unknown) {
  for (const [, entry] of pending) entry.reject(reason);
  pending.clear();
}

function terminate() {
  if (worker) {
    worker.terminate();
    worker = null;
  }
}

/**
 * Abandon every in-flight operation and stop the work.
 *
 * Terminating is the only way to actually halt a synchronous WASM derivation,
 * so the worker is thrown away and a fresh one spawned on the next call. That
 * is cheap relative to an Argon2id run, and it is the difference between a
 * cancel that stops burning the user's battery and one that merely stops
 * listening.
 */
export function cancelAllCryptoWork(): void {
  if (!worker) return;
  failAllPending(new Error("Cancelled."));
  terminate();
  // The next call spawns a fresh worker, which has to prove itself again.
  readiness = null;
}

function post<T extends CryptoResponse>(
  w: Worker,
  request: CryptoRequest,
  transfer: Transferable[]
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    pending.set(request.id, { resolve: resolve as (v: never) => void, reject });
    w.postMessage(request, transfer);
  });
}

export interface EncryptOutcome {
  data: ArrayBuffer;
  /** §4.6, present only when `shamir` was requested. Produced once, never again. */
  shares?: string[] | undefined;
}

export async function encryptViaWorker(
  data: ArrayBuffer,
  password: string,
  keyFile: ArrayBuffer | null,
  options: KeymakerOptions,
  shamir?: { threshold: number; count: number },
  passkey?: { prfOutput: Uint8Array; salt: Uint8Array }
): Promise<EncryptOutcome> {
  const w = (await ready()) ? spawn() : null;
  if (!w) {
    lastRunUsedWorker = false;
    // encryptContainer zeroes the caller's key-file buffer in its `finally` —
    // that is its documented contract. Anything enrolled *after* it therefore
    // needs its own copy, taken before the call. Reading `keyFile` afterwards
    // yields zeros, the slot key derives from the wrong material, and the
    // enrolment fails with "Decryption failed." in the middle of an encryption.
    const keyFileForSlots =
      keyFile && (shamir || passkey) ? new Uint8Array(keyFile.slice(0)) : null;
    let out = await encryptContainer(data, password, keyFile, options);
    // §4.7, and the same argument the share fallback makes below: a browser
    // where the Worker failed to start must not quietly produce a container
    // with no passkey slot, reported as success.
    if (passkey) {
      const { addPasskeySlotKeym2 } = await import("./keym-v2");
      const enrolled = await addPasskeySlotKeym2(
        new Uint8Array(out),
        { password, keyFile: keyFileForSlots },
        passkey.prfOutput,
        passkey.salt
      );
      out = enrolled.buffer.slice(
        enrolled.byteOffset,
        enrolled.byteOffset + enrolled.byteLength
      ) as ArrayBuffer;
    }
    if (!shamir) {
      secureErase(keyFileForSlots);
      return { data: out };
    }
    // The no-worker fallback has to do the same work, or enabling shares would
    // silently produce a container with no share slot on a browser where the
    // Worker failed to start — a backup the heirs cannot open, reported as
    // success.
    const { addShamirSlotKeym2 } = await import("./keym-v2");
    const enrolled = await addShamirSlotKeym2(
      new Uint8Array(out),
      { password, keyFile: keyFileForSlots },
      shamir.threshold,
      shamir.count
    );
    const result = {
      data: enrolled.container.buffer.slice(
        enrolled.container.byteOffset,
        enrolled.container.byteOffset + enrolled.container.byteLength
      ) as ArrayBuffer,
      shares: enrolled.shares,
    };
    secureErase(keyFileForSlots);
    return result;
  }
  lastRunUsedWorker = true;

  const id = nextId++;
  // Transferring detaches these buffers on this side, which is the point: one
  // copy of the plaintext, in the realm doing the work.
  //
  // The key file is *not* transferred when a share set is being enrolled: the
  // worker needs it twice, once for the container and once to unwrap the slot
  // it is about to add, and a detached buffer cannot be read a second time.
  const transfer: Transferable[] = [data];
  // A transferred buffer is detached on this side, so it can only be handed
  // over when nothing here needs it afterwards. Both enrolment paths re-derive
  // from the key file inside the worker, so neither may transfer it.
  if (keyFile && !shamir && !passkey) transfer.push(keyFile);

  const res = await post<Extract<CryptoResponse, { op: "encrypt"; ok: true }>>(
    w,
    { id, op: "encrypt", data, password, keyFile, options, shamir, passkey },
    transfer
  );
  return { data: res.data, shares: res.shares };
}

/**
 * Measure this device and choose Argon2id parameters for an unlock budget.
 *
 * Returns `null` when there is no Worker to measure in. That is deliberately
 * not a silent fallback to a main-thread measurement: every other operation
 * here degrades to the in-thread path because losing encryption entirely would
 * be worse than a frozen tab, and none of that reasoning applies to a
 * convenience that the user can simply decline. A second timing path, running
 * under conditions the solver was never given, is a worse answer than "not
 * available here" — so the caller is told, and the existing settings stand.
 */
export async function calibrateViaWorker(
  budgetMs: number,
  timeCost: number,
  parallelism: number
): Promise<Calibration | null> {
  const w = (await ready()) ? spawn() : null;
  if (!w) {
    lastRunUsedWorker = false;
    return null;
  }
  lastRunUsedWorker = true;

  const id = nextId++;
  const res = await post<Extract<CryptoResponse, { op: "calibrate"; ok: true }>>(
    w,
    { id, op: "calibrate", parallelism },
    []
  );
  return calibrateArgon2({ low: res.low, high: res.high, budgetMs, timeCost, parallelism });
}

export async function decryptViaWorker(
  data: ArrayBuffer,
  password: string,
  keyFile: ArrayBuffer | null,
  shares?: string[],
  prfOutput?: Uint8Array
): Promise<DecryptOutcome> {
  const w = (await ready()) ? spawn() : null;
  if (!w) {
    lastRunUsedWorker = false;
    return decryptData(data, password, keyFile, shares, prfOutput);
  }
  lastRunUsedWorker = true;

  const id = nextId++;
  const transfer: Transferable[] = [data];
  if (keyFile) transfer.push(keyFile);

  const res = await post<Extract<CryptoResponse, { op: "decrypt"; ok: true }>>(
    w,
    { id, op: "decrypt", data, password, keyFile, shares, prfOutput },
    transfer
  );
  return { data: res.data, format: res.format, keyFileUsed: res.keyFileUsed };
}

/**
 * Start the worker and let it pull in its lazy dependencies early.
 *
 * Same reasoning as the existing dependency warm-up: the first Argon2id call
 * would otherwise pay for fetching hash-wasm, and if that first call happens
 * offline the chunk has to already be cached. Spawning here means the worker
 * chunk is fetched during idle time rather than at the moment someone presses
 * Encrypt.
 */
export function warmCryptoWorker(): void {
  void ready();
}
