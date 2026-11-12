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
  encryptContainerWithSharesRequired,
  encryptContainerWithSlots,
  encryptContainerToSink,
  openContainerStream,
  KeymakerError,
  secureErase,
  decryptData,
  isUserFacingError,
  loadHashWasm,
  type KeymakerOptions,
  type DetectedFormat,
  type OpenedBy,
} from "./keymaker-crypto";
import type { Keym2ByteSink } from "./keym-v2";
import type { Argon2Sample } from "./kdf-calibration";

/**
 * At most this many chunk messages are in flight to the page, un-acknowledged.
 *
 * The worker can seal faster than the page can write, and every chunk posted
 * and not yet written is a mebibyte held in the page's heap. Four bounds that
 * at a few mebibytes whatever the file's size, and is enough to keep a write
 * queued behind the one in progress.
 */
export const STREAM_WINDOW = 4;

/**
 * What an `open-stream` request is for. Only `verify` exists: the plaintext is
 * counted and erased here, and nothing but the count crosses (roadmap 9.2). A
 * streamed decrypt, whose chunks do cross, is a later addition to this union;
 * the worker refuses any purpose it does not list.
 */
export type OpenStreamPurpose = "verify";

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
      shamir?: { threshold: number; count: number; withPassword?: boolean } | undefined;
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
      /**
       * `verify` is `decrypt` that keeps the plaintext here (roadmap 9.2).
       *
       * Same inputs, same reader, a different answer: the byte count and what
       * the reader established, never the bytes. Verify-only and the rehearsal
       * used to take the full decrypt response and zero the plaintext on
       * arrival, which put a whole copy of it in the page's heap to prove a
       * backup opens — the one operation whose point is not to show it.
       */
      op: "decrypt" | "verify";
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
  | { id: number; op: "calibrate"; parallelism: number }
  /**
   * `encrypt`, reading the plaintext from a `File` a chunk at a time and
   * posting the container back as `chunk` messages, under the streaming
   * ceiling. The fields are `encrypt`'s with `file` for `data`.
   *
   * The file is read here, by slicing it: a `File` posted to a worker can be
   * sliced in the worker. The output is written by the page, because the
   * writable it goes to cannot be posted here.
   */
  | {
      id: number;
      op: "encrypt-stream";
      file: Blob;
      password: string;
      keyFile: ArrayBuffer | null;
      options: KeymakerOptions;
      shamir?: { threshold: number; count: number; withPassword?: boolean } | undefined;
      passkey?: { prfOutput: Uint8Array; salt: Uint8Array } | undefined;
    }
  /**
   * Open a container in a `File` without reading it whole. `purpose` says what
   * happens to the plaintext; see `OpenStreamPurpose`. `digest` asks for the
   * SHA-256 of the container bytes the reader read.
   */
  | {
      id: number;
      op: "open-stream";
      file: Blob;
      password: string;
      keyFile: ArrayBuffer | null;
      shares?: string[] | undefined;
      prfOutput?: Uint8Array | undefined;
      purpose: OpenStreamPurpose;
      digest: boolean;
    }
  /**
   * The page has written chunk `seq` of stream `stream` (the id of the request
   * that started it), and every chunk before it. A valid ack gets no response.
   */
  | { id: number; op: "ack"; stream: number; seq: number };

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
      weakKdf: string | null;
    }
  /**
   * Everything a verify is allowed to tell the page. No field here is, or is
   * derived from, a byte of the plaintext except its length.
   */
  | {
      id: number;
      ok: true;
      op: "verify";
      format: DetectedFormat;
      /** The authenticated plaintext's length. */
      bytes: number;
      /** Which kind of slot the reader settled on. */
      openedBy: OpenedBy;
      keyFileUsed: boolean;
      /**
       * v3 §5.2, named rather than a nullable boolean so a caller cannot read
       * "no MAC to check" as "checked and fine". `not_available` is every
       * format without a `slot_table_mac`: v1, v2 and both IttyBitz formats.
       */
      slotTable: "authentic" | "changed" | "not_available";
      weakKdf: string | null;
      /**
       * Lowercase hex SHA-256 of exactly the container bytes the reader read,
       * when a streamed verify asked for it; null otherwise, and always null
       * for the in-memory `verify`. A digest of ciphertext says nothing about
       * the plaintext.
       */
      digest: string | null;
    }
  /**
   * One piece of a stream's output, in order from `seq` 0, its buffer
   * transferred. `id` is the stream's: the id of the request that started it.
   * Not a settlement: the request's own response comes after the last chunk.
   */
  | { id: number; ok: true; op: "chunk"; seq: number; data: ArrayBuffer }
  /**
   * An `encrypt-stream` finished: every chunk has been posted and acknowledged.
   * `bytes` is the container's length, `head` its bytes before the first chunk
   * (the first `chunk` message, again), and `digest` the lowercase hex SHA-256
   * of every byte posted. `shares` as for `encrypt`.
   */
  | {
      id: number;
      ok: true;
      op: "encrypt-stream";
      bytes: number;
      head: ArrayBuffer;
      digest: string;
      shares?: string[] | undefined;
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

// ---------------------------------------------------------------------------
// Streams: chunk messages under flow control
// ---------------------------------------------------------------------------

/** One stream's flow-control state, keyed by the id of the request that started it. */
interface StreamState {
  /** Chunks posted. The next chunk's `seq`. */
  sent: number;
  /** Chunks the page has acknowledged: every `seq` below this. */
  acked: number;
  /** The stream's writer, parked until an ack arrives. */
  wake: (() => void) | null;
}

const streams = new Map<number, StreamState>();

/** Park until the page has acknowledged enough that `ready(state)` holds. */
async function until(state: StreamState, ready: (s: StreamState) => boolean): Promise<void> {
  while (!ready(state)) await new Promise<void>((resolve) => (state.wake = resolve));
}

/**
 * The sink a streamed encrypt writes to: each write becomes one `chunk`
 * message, posted only while fewer than `STREAM_WINDOW` are unacknowledged,
 * and hashed first, because the transfer detaches it.
 */
function chunkSink(id: number, state: StreamState, hasher: { update(data: Uint8Array): unknown }): Keym2ByteSink {
  return {
    async write(bytes: Uint8Array): Promise<void> {
      await until(state, (s) => s.sent - s.acked < STREAM_WINDOW);
      hasher.update(bytes);
      // The core hands the sink ownership of `bytes`. A view that does not
      // span its buffer would transfer bytes that are not this chunk's.
      const data =
        bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength && bytes.buffer instanceof ArrayBuffer
          ? bytes.buffer
          : (bytes.slice().buffer as ArrayBuffer);
      const seq = state.sent++;
      ctx.postMessage({ id, ok: true, op: "chunk", seq, data } satisfies CryptoResponse, [data]);
    },
  };
}

/**
 * Answer an `ack`. A valid one moves the window and gets no response; one that
 * is malformed, names a stream that is not running, or acknowledges a chunk
 * that was never posted gets `ok: false`, because each is a page bug that
 * would otherwise stall a stream with nothing said.
 */
function acknowledge(req: { id: number; stream?: unknown; seq?: unknown }): void {
  const { stream, seq } = req;
  if (!Number.isSafeInteger(stream) || !Number.isSafeInteger(seq) || (seq as number) < 0) {
    ctx.postMessage({ id: req.id, ok: false, code: "invalid-input", message: "Malformed acknowledgement." } satisfies CryptoResponse);
    return;
  }
  const state = streams.get(stream as number);
  if (!state) {
    ctx.postMessage({
      id: req.id,
      ok: false,
      code: "invalid-input",
      message: "Acknowledgement for a stream that is not running.",
    } satisfies CryptoResponse);
    return;
  }
  if ((seq as number) >= state.sent) {
    ctx.postMessage({
      id: req.id,
      ok: false,
      code: "invalid-input",
      message: "Acknowledgement for a chunk that was not sent.",
    } satisfies CryptoResponse);
    return;
  }
  state.acked = Math.max(state.acked, (seq as number) + 1);
  const wake = state.wake;
  state.wake = null;
  wake?.();
}

/**
 * Hash exactly the container bytes a streamed reader reads, once each, in
 * order. The reader's ranges overlap (the head read runs into the first
 * chunk) and are otherwise contiguous; a range that skipped ahead would leave
 * bytes out of the digest, so it marks the digest unusable rather than wrong.
 */
function containerHasher(hasher: { update(data: Uint8Array): unknown; digest(f: "hex"): string }) {
  let upTo = 0;
  let gap = false;
  return {
    onRead(offset: number, bytes: Uint8Array): void {
      if (offset > upTo) gap = true;
      const end = offset + bytes.length;
      if (gap || end <= upTo) return;
      hasher.update(bytes.subarray(upTo - offset));
      upTo = end;
    },
    /** The digest, once the reader has read all `total` bytes of the container. */
    digest(total: number): string {
      if (gap || upTo !== total) {
        throw new KeymakerError(
          "invalid-input",
          "The file's digest could not be taken over every byte that was read, so the check was not completed."
        );
      }
      return hasher.digest("hex");
    },
  };
}

ctx.addEventListener("message", async (event: MessageEvent<CryptoRequest>) => {
  const req = event.data;

  // Only the page can post here, but a message it did not mean to send still
  // has to be answered, or the client's pending promise waits for ever. A
  // null message used to throw inside this async listener — a rejected
  // promise nobody held, no `error` event, no response — and an op this
  // worker does not know fell through to the decrypt branch with undefined
  // arguments. Both now get a response that names the problem.
  if (
    typeof req !== "object" ||
    req === null ||
    typeof (req as { id?: unknown }).id !== "number" ||
    typeof (req as { op?: unknown }).op !== "string"
  ) {
    const id = typeof (req as { id?: unknown } | null)?.id === "number" ? (req as { id: number }).id : -1;
    ctx.postMessage({ id, ok: false, code: null, message: "Malformed request." } satisfies CryptoResponse);
    return;
  }

  // Handled before the `try`, so its `finally` (which erases the secrets an
  // operation carried) is not reached by a message that carries none.
  if (req.op === "ack") {
    acknowledge(req);
    return;
  }

  try {
    if (req.op === "ping") {
      ctx.postMessage({ id: req.id, ok: true, op: "ping" } satisfies CryptoResponse);
      return;
    }

    if (req.op === "encrypt-stream") {
      const state: StreamState = { sent: 0, acked: 0, wake: null };
      streams.set(req.id, state);
      const { createSHA256 } = await loadHashWasm();
      const hasher = await createSHA256();
      hasher.init();
      const written = await encryptContainerToSink(
        req.file,
        req.password,
        req.keyFile,
        req.options,
        { shamir: req.shamir, passkey: req.passkey },
        chunkSink(req.id, state, hasher)
      );
      // The response is the page's signal that the container is complete, so
      // it waits until the page has written every chunk: nothing it says can
      // overtake a chunk still in flight, and no acknowledgement can arrive
      // for a stream that has already ended.
      await until(state, (s) => s.acked === s.sent);
      const head = written.head.slice().buffer as ArrayBuffer;
      const response: CryptoResponse = {
        id: req.id,
        ok: true,
        op: "encrypt-stream",
        bytes: written.bytes,
        head,
        digest: hasher.digest("hex"),
        shares: written.shares,
      };
      ctx.postMessage(response, [head]);
      return;
    }

    if (req.op === "open-stream") {
      // Checked before anything is read or derived. Only `verify` exists, and
      // a purpose this worker does not list must not fall through to it.
      if (req.purpose !== "verify") {
        throw new KeymakerError(
          "invalid-input",
          `Unknown open-stream purpose: ${String((req as { purpose?: unknown }).purpose).slice(0, 32)}`
        );
      }
      let hash: ReturnType<typeof containerHasher> | null = null;
      if (req.digest === true) {
        const { createSHA256 } = await loadHashWasm();
        const hasher = await createSHA256();
        hasher.init();
        hash = containerHasher(hasher);
      }
      const opened = await openContainerStream(
        req.file,
        req.password,
        req.keyFile,
        req.shares,
        req.prfOutput,
        hash ? { onRead: hash.onRead } : undefined
      );
      let bytes = 0;
      try {
        // Counted and erased here; nothing is posted until the last chunk
        // has verified, and then only the count (roadmap 9.2).
        await opened.drain({
          async write(chunk: Uint8Array): Promise<void> {
            bytes += chunk.length;
            secureErase(chunk);
          },
        });
      } finally {
        opened.discard();
      }
      const response: CryptoResponse = {
        id: req.id,
        ok: true,
        op: "verify",
        format: opened.format,
        bytes,
        openedBy: opened.openedBy,
        keyFileUsed: opened.keyFileUsed,
        slotTable:
          opened.slotTableAuthentic === null
            ? "not_available"
            : opened.slotTableAuthentic
              ? "authentic"
              : "changed",
        weakKdf: opened.weakKdf,
        // `file` is a Blob by now: openContainerStream refuses anything else.
        digest: hash ? hash.digest(req.file.size) : null,
      };
      ctx.postMessage(response);
      return;
    }

    if (req.op === "calibrate") {
      const { low, high } = await calibrate(req.parallelism);
      ctx.postMessage({ id: req.id, ok: true, op: "calibrate", low, high } satisfies CryptoResponse);
      return;
    }

    if (req.op === "encrypt") {
      let out: ArrayBuffer;
      let shares: string[] | undefined;
      if (req.shamir?.withPassword) {
        // §4.8. One slot that takes the password and the shares together, and
        // nothing else: a passphrase or passkey slot beside it would open the
        // backup with one half, which is what this choice rules out.
        if (req.passkey) {
          throw new KeymakerError(
            "invalid-input",
            "A passkey would open this backup on its own, and it was set to need the password and the strips together."
          );
        }
        const written = await encryptContainerWithSharesRequired(
          req.data, req.password, req.keyFile, req.options, req.shamir.threshold, req.shamir.count
        );
        out = written.data;
        shares = written.shares;
      } else if (req.shamir || req.passkey) {
        // Roadmap 9.3. Every way in, in one write: the password is derived
        // once and the share and passkey slots wrap the master key that write
        // is still holding. This used to be encryptContainer followed by one
        // enrolment per extra way in, and each enrolment opened the container
        // again, which meant deriving the password again. The share secret and
        // the coefficients are still generated, used and dropped in this heap.
        const written = await encryptContainerWithSlots(req.data, req.password, req.keyFile, req.options, {
          shamir: req.shamir ? { threshold: req.shamir.threshold, count: req.shamir.count } : undefined,
          passkey: req.passkey,
        });
        out = written.data;
        shares = written.shares;
      } else {
        out = await encryptContainer(req.data, req.password, req.keyFile, req.options);
      }

      const response: CryptoResponse = { id: req.id, ok: true, op: "encrypt", data: out, shares };
      ctx.postMessage(response, [out]);
      return;
    }

    if (req.op === "verify") {
      const result = await decryptData(req.data, req.password, req.keyFile, req.shares, req.prfOutput);
      // The length is read before the erase, and the erase is unconditional:
      // nothing between the two can throw, and nothing after it needs the bytes.
      const bytes = result.data.byteLength;
      secureErase(result.data);
      const response: CryptoResponse = {
        id: req.id,
        ok: true,
        op: "verify",
        format: result.format,
        bytes,
        openedBy: result.openedBy,
        keyFileUsed: result.keyFileUsed,
        slotTable:
          result.slotTableAuthentic === null
            ? "not_available"
            : result.slotTableAuthentic
              ? "authentic"
              : "changed",
        weakKdf: result.weakKdf,
        digest: null,
      };
      // Nothing to transfer: the response carries no buffer at all.
      ctx.postMessage(response);
      return;
    }

    if (req.op !== "decrypt") {
      throw new KeymakerError("invalid-input", `Unknown operation: ${String((req as { op: string }).op).slice(0, 32)}`);
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
      weakKdf: result.weakKdf,
    };
    ctx.postMessage(response, [result.data]);
  } catch (error) {
    const response: CryptoResponse = {
      id: req.id,
      ok: false,
      code: isUserFacingError(error) ? error.code : null,
      // Only messages the core has typed as safe to show cross the boundary.
      // The page already shows nothing else, but an untyped message is text
      // nobody here wrote — a library's, a browser's — and this worker holds
      // the key material. Verify made this promise first; it costs nothing
      // to keep it for every op.
      message: isUserFacingError(error)
        ? error.message
        : req.op === "encrypt" || req.op === "encrypt-stream"
          ? "Processing failed. Please try again."
          : "Decryption failed.",
    };
    ctx.postMessage(response);
  } finally {
    // A PRF output is a 32-byte secret that unwraps a slot on its own — the
    // same asset class as the master key, and worth as much to anyone who
    // finds it in a heap snapshot. Unlike the plaintext it is
    // structured-cloned into this realm rather than transferred, because the
    // page still needs its own copy; that makes this copy the worker's, and
    // this the only code that can destroy it.
    //
    // In the `finally` rather than after each use because the branches above
    // return from several places and the `catch` turns a throw into a
    // response — a trailing call would be skipped on most exits, including
    // every failed unlock, which is the case an attacker gets to repeat.
    if (req.op === "encrypt") secureErase(req.passkey?.prfOutput);
    // The plaintext is transferred in, so this realm holds the only copy, and
    // nothing downstream erases its plaintext input. Without this the secret
    // stays in the worker's heap for as long as the worker lives, which is
    // the life of the page. Same reasoning as above for doing it here: every
    // exit, including a refused or failed encrypt, passes through.
    if (req.op === "encrypt") secureErase(req.data);
    if (req.op === "decrypt" || req.op === "verify") secureErase(req.prfOutput);
    // The streaming ops: the same two secrets. The key file is transferred in
    // and the core zeroes it on every exit already; this is the backstop for
    // a request that failed before reaching the core. The plaintext of an
    // `encrypt-stream` is a File, read and erased a chunk at a time by the
    // writer, so there is no whole buffer of it here to erase.
    if (req.op === "encrypt-stream") {
      secureErase(req.passkey?.prfOutput);
      if (req.keyFile instanceof ArrayBuffer) secureErase(req.keyFile);
      streams.delete(req.id);
    }
    if (req.op === "open-stream") {
      secureErase(req.prfOutput);
      if (req.keyFile instanceof ArrayBuffer) secureErase(req.keyFile);
    }
  }
});
