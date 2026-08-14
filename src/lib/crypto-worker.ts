/// <reference lib="webworker" />

/**
 * Crypto worker: runs key derivation and AEAD off the main thread.
 *
 * ## Why this exists
 *
 * Argon2id runs through hash-wasm, which is synchronous and CPU-bound. On the
 * main thread that means the tab is frozen for the whole derivation — measured
 * on a fast machine at maximum settings, an interrupting click issued 200 ms
 * into a 22-second derivation did not resolve until 22.5 s. Nothing renders,
 * nothing responds, and the user cannot even cancel. The default settings are
 * shorter but the same shape: seconds of a dead tab on a mid-range phone.
 *
 * Moving the work here fixes that directly, and buys three more things:
 *
 *  - **Cancellation becomes real.** The page can terminate the worker and the
 *    derivation actually stops, rather than running to completion invisibly
 *    while the UI pretends it was abandoned.
 *  - **Key material gets its own heap.** Passwords, derived keys and plaintext
 *    live in a separate JS realm from React state, the DOM, and any future
 *    third-party script on the page. Not a hard boundary — a compromised page
 *    can still postMessage — but the accidental exposure surface shrinks a lot.
 *  - **Transferable buffers.** Results move to the main thread by transfer
 *    rather than structured-clone copy.
 *
 * ## What it deliberately is not
 *
 * It is a transport, not a second implementation. It calls exactly the same
 * `encryptContainer`/`decryptData` the in-thread path uses, so there is no way
 * for the two to disagree about the wire format. Everything the conformance and
 * fixture suites prove about the core still applies unchanged.
 */

import {
  encryptContainer,
  decryptData,
  isUserFacingError,
  type KeymakerOptions,
  type DetectedFormat,
} from "./keymaker-crypto";

export type CryptoRequest =
  /**
   * Readiness probe. The client sends one before trusting the worker with real
   * work — see crypto-client.ts for why that ordering matters.
   */
  | { id: number; op: "ping" }
  | {
      id: number;
      op: "encrypt";
      data: ArrayBuffer;
      password: string;
      keyFile: ArrayBuffer | null;
      options: KeymakerOptions;
    }
  | {
      id: number;
      op: "decrypt";
      data: ArrayBuffer;
      password: string;
      keyFile: ArrayBuffer | null;
    };

export type CryptoResponse =
  | { id: number; ok: true; op: "ping" }
  | { id: number; ok: true; op: "encrypt"; data: ArrayBuffer }
  | {
      id: number;
      ok: true;
      op: "decrypt";
      data: ArrayBuffer;
      format: DetectedFormat;
      keyFileUsed: boolean;
    }
  /**
   * Errors cross the boundary as plain data.
   *
   * An Error instance survives structured clone, but its *subclass* does not —
   * a KeymakerError arrives on the other side as a bare Error and
   * `isUserFacingError` returns false for it. That would silently undo the
   * Phase 1 fix: every structural fault would collapse back into "the password
   * may be incorrect". So the code travels explicitly and the client
   * reconstructs the typed error from it.
   */
  | { id: number; ok: false; code: string | null; message: string };

const ctx = self as unknown as DedicatedWorkerGlobalScope;

ctx.addEventListener("message", async (event: MessageEvent<CryptoRequest>) => {
  const req = event.data;

  try {
    if (req.op === "ping") {
      ctx.postMessage({ id: req.id, ok: true, op: "ping" } satisfies CryptoResponse);
      return;
    }

    if (req.op === "encrypt") {
      const out = await encryptContainer(req.data, req.password, req.keyFile, req.options);
      const response: CryptoResponse = { id: req.id, ok: true, op: "encrypt", data: out };
      ctx.postMessage(response, [out]);
      return;
    }

    const result = await decryptData(req.data, req.password, req.keyFile);
    const response: CryptoResponse = {
      id: req.id,
      ok: true,
      op: "decrypt",
      data: result.data,
      format: result.format,
      keyFileUsed: result.keyFileUsed,
    };
    ctx.postMessage(response, [result.data]);
  } catch (error) {
    const response: CryptoResponse = {
      id: req.id,
      ok: false,
      code: isUserFacingError(error) ? error.code : null,
      message: error instanceof Error ? error.message : "Processing failed. Please try again.",
    };
    ctx.postMessage(response);
  }
});
