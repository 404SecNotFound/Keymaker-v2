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
  secureErase,
  decryptData,
  isUserFacingError,
  loadHashWasm,
  type KeymakerOptions,
  type DetectedFormat,
} from "./keymaker-crypto";
import type { Argon2Sample } from "./kdf-calibration";

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
      /**
       * KEYM v2 §4.6. Enrol a k-of-n share set in the same operation that
       * writes the container.
       *
       * One op rather than two, because enrolling a slot needs a secret that
       * already opens the container and the password is the one we have. A
       * separate "add shares" call would mean either keeping the password
       * alive in the page past the encrypt that should have cleared it, or
       * asking the user to type it a second time.
       */
      shamir?: { threshold: number; count: number } | undefined;
      /**
       * §4.7. Obtained on the main thread, because `navigator.credentials` does
       * not exist here — a Worker cannot tap a security key. The 32 bytes and
       * the salt they were derived for come in together; everything after that
       * is ordinary slot arithmetic.
       */
      passkey?: { prfOutput: Uint8Array; salt: Uint8Array } | undefined;
    }
  | {
      id: number;
      op: "decrypt";
      data: ArrayBuffer;
      password: string;
      keyFile: ArrayBuffer | null;
      /** §4.6. Enough of these and no password is needed at all. */
      shares?: string[] | undefined;
      /** §4.7. Obtained on the main thread; a Worker cannot tap a security key. */
      prfOutput?: Uint8Array | undefined;
    }
  /**
   * Time Argon2id at two memory sizes so the caller can solve for parameters
   * that fit an unlock budget (roadmap 2.5).
   *
   * The worker measures and returns raw samples; it does not choose. Choosing
   * is `kdf-calibration.ts`, which is pure and therefore testable against
   * devices that do not exist. Keeping the judgement out of here preserves what
   * this file claims to be — a transport, not a second implementation.
   */
  | { id: number; op: "calibrate"; parallelism: number };

export type CryptoResponse =
  | { id: number; ok: true; op: "ping" }
  /**
   * `shares` is present only when the request asked for them, and this is the
   * only moment they will ever exist: §4.6 discards the share secret once the
   * slot is wrapped, so nothing — not this app, not the reference — can reissue
   * them afterwards.
   */
  | { id: number; ok: true; op: "encrypt"; data: ArrayBuffer; shares?: string[] | undefined }
  | { id: number; ok: true; op: "calibrate"; low: Argon2Sample; high: Argon2Sample }
  | {
      id: number;
      ok: true;
      op: "decrypt";
      data: ArrayBuffer;
      format: DetectedFormat;
      keyFileUsed: boolean;
      /**
       * v3 §5.2. Crosses the worker boundary because the report is owed to the
       * person doing the recovery, and they are on the other side of it. A
       * boolean and a null both survive structured clone unchanged, so unlike
       * the error path below this needs no reconstruction.
       */
      slotTableAuthentic: boolean | null;
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

/** Memory sizes for the two calibration points, in KiB. */
const CALIBRATE_LOW_KIB = 8 * 1024;
const CALIBRATE_HIGH_KIB = 32 * 1024;

/**
 * Time one Argon2id derivation. Random password and salt, discarded output —
 * nothing here touches the user's secret.
 */
async function timeArgon2(memoryKiB: number, parallelism: number): Promise<number> {
  const { argon2id } = await loadHashWasm();
  const password = crypto.getRandomValues(new Uint8Array(32));
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const started = performance.now();
  await argon2id({
    password,
    salt,
    iterations: 1,
    memorySize: memoryKiB,
    parallelism,
    hashLength: 32,
    outputType: "binary",
  });
  return performance.now() - started;
}

/**
 * Two timed points, plus a discarded warm-up.
 *
 * The warm-up is not politeness, it is correctness. The first Argon2id call in
 * a worker pays for instantiating the wasm module, and that cost lands entirely
 * in whichever sample happens to be first — inflating the low point, which is
 * exactly the one the model uses to estimate fixed overhead. Left in, it makes
 * a fast device look slow, and can invert the slope badly enough that
 * `calibrateArgon2` rejects the whole measurement and falls back.
 *
 * Each point is the *minimum* of two runs. Scheduling noise only ever adds
 * time, so the minimum is the better estimate of what the device can do; an
 * average would drag every measurement toward whatever else the machine was
 * doing.
 */
async function calibrate(parallelism: number): Promise<{ low: Argon2Sample; high: Argon2Sample }> {
  await timeArgon2(CALIBRATE_LOW_KIB, parallelism);

  const sample = async (memoryKiB: number): Promise<Argon2Sample> => ({
    timeCost: 1,
    memoryKiB,
    elapsedMs: Math.min(
      await timeArgon2(memoryKiB, parallelism),
      await timeArgon2(memoryKiB, parallelism)
    ),
  });

  return { low: await sample(CALIBRATE_LOW_KIB), high: await sample(CALIBRATE_HIGH_KIB) };
}

ctx.addEventListener("message", async (event: MessageEvent<CryptoRequest>) => {
  const req = event.data;

  try {
    if (req.op === "ping") {
      ctx.postMessage({ id: req.id, ok: true, op: "ping" } satisfies CryptoResponse);
      return;
    }

    if (req.op === "calibrate") {
      const { low, high } = await calibrate(req.parallelism);
      ctx.postMessage({ id: req.id, ok: true, op: "calibrate", low, high } satisfies CryptoResponse);
      return;
    }

    if (req.op === "encrypt") {
      // encryptContainer zeroes the caller's key-file buffer in its `finally` —
      // that is its documented contract. Anything enrolled *after* it therefore
      // has to hold its own copy, taken before the call. Reading `keyFile`
      // afterwards yields zeros, the slot key derives from the wrong material,
      // and the enrolment fails with "Decryption failed." in the middle of an
      // encryption.
      const keyFileForSlots =
        req.keyFile && (req.shamir || req.passkey)
          ? new Uint8Array(req.keyFile.slice(0))
          : null;
      let out = await encryptContainer(req.data, req.password, req.keyFile, req.options);
      let shares: string[] | undefined;

      if (req.shamir) {
        // §4.6. Enrolled here rather than in the page so the share secret and
        // the coefficients are generated, used and dropped inside the worker's
        // heap — the same reason the derivation lives here.
        const { addShamirSlotKeym2 } = await import("./keym-v2");
        const enrolled = await addShamirSlotKeym2(
          new Uint8Array(out),
          { password: req.password, keyFile: keyFileForSlots },
          req.shamir.threshold,
          req.shamir.count
        );
        out = enrolled.container.buffer.slice(
          enrolled.container.byteOffset,
          enrolled.container.byteOffset + enrolled.container.byteLength
        ) as ArrayBuffer;
        shares = enrolled.shares;
      }

      if (req.passkey) {
        // §4.7. Added after encryption for the same reason a share set is: the
        // container has to exist before a slot can be added to it. The rule
        // that a passkey never travels alone is satisfied structurally here —
        // `out` already carries the passphrase slot encryptContainer wrote.
        const { addPasskeySlotKeym2 } = await import("./keym-v2");
        const enrolled = await addPasskeySlotKeym2(
          new Uint8Array(out),
          { password: req.password, keyFile: keyFileForSlots },
          req.passkey.prfOutput,
          req.passkey.salt
        );
        out = enrolled.buffer.slice(
          enrolled.byteOffset,
          enrolled.byteOffset + enrolled.byteLength
        ) as ArrayBuffer;
      }

      // The copy taken above so the enrolments could still read it. Same
      // standard encryptContainer applies to the original.
      if (keyFileForSlots) secureErase(keyFileForSlots);

      const response: CryptoResponse = { id: req.id, ok: true, op: "encrypt", data: out, shares };
      ctx.postMessage(response, [out]);
      return;
    }

    const result = await decryptData(req.data, req.password, req.keyFile, req.shares, req.prfOutput);
    const response: CryptoResponse = {
      id: req.id,
      ok: true,
      op: "decrypt",
      data: result.data,
      format: result.format,
      keyFileUsed: result.keyFileUsed,
      slotTableAuthentic: result.slotTableAuthentic,
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
