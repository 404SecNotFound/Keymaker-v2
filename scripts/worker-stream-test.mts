/**
 * The worker's streaming protocol: `encrypt-stream`, `open-stream` and `ack`.
 *
 * The page will hand the worker a `File`; the worker slices it, seals it a
 * chunk at a time and posts each piece of the container back, and the page
 * writes the pieces and acknowledges them. This loads the shipping worker
 * module as-is with a stand-in `self` (as verify-transport-test.mts does),
 * models `postMessage`'s transfer with `structuredClone`, and checks:
 *
 *  a. The chunk messages, concatenated in `seq` order, are a container the
 *     in-memory reader opens to the original file.
 *  b. `digest` is the SHA-256 of exactly that concatenation.
 *  c. `head` is the container's bytes before the first payload chunk.
 *  d. With acknowledgements withheld, at most `STREAM_WINDOW` (4) chunks are
 *     posted; acknowledging them lets the stream finish.
 *  e. No chunk message carries a recognisable plaintext.
 *  f. A file whose read fails part-way yields one typed error and no success.
 *  g. A share set and a passkey requested through `encrypt-stream` produce a
 *     container that opens every way, byte-identical to the in-memory
 *     writer's under the same pinned randomness (`crypto.getRandomValues`
 *     replaced by a seeded generator for both runs); likewise §4.8's
 *     password-and-shares slot.
 *
 * And the protocol's edges: a malformed or unknown ack is answered `ok:false`
 * while a valid one is not answered at all; a streamed verify of a
 * multi-chunk container posts no chunk and reports the container's digest;
 * an `open-stream` purpose the worker does not list is refused.
 *
 * Negative controls, each run against a patched worker that was confirmed to
 * build: drop one chunk (a fails), hash without the head (b fails), remove the
 * credit wait (d fails), post the plaintext as a chunk (e fails).
 */
import { createHash, webcrypto } from "node:crypto";
import {
  CipherId,
  KdfId,
  decryptData,
  encryptContainerWithSlots,
  encryptContainerWithSharesRequired,
  type KeymakerOptions,
} from "../src/lib/keymaker-crypto.ts";
import { KEYM2_VERSION_V3, keym2ContainerLength, keym2SlotLen, keym2SlotTableOffset } from "../src/lib/keym-v2.ts";

if (!globalThis.crypto) (globalThis as { crypto?: Crypto }).crypto = webcrypto as unknown as Crypto;

let passed = 0;
let failed = 0;
function check(ok: boolean, name: string, detail = "") {
  if (typeof ok !== "boolean") throw new Error(`check(${JSON.stringify(name)}) was handed a non-boolean condition`);
  if (ok) {
    passed++;
    console.log(`ok    ${name}`);
  } else {
    failed++;
    console.log(`FAIL  ${name}${detail ? ` (${detail})` : ""}`);
  }
}

// ---------------------------------------------------------------------------
// The shipping worker, with a stand-in `self` whose postMessage transfers.
// ---------------------------------------------------------------------------
type Handler = (e: { data: unknown }) => Promise<void>;
let handler: Handler | null = null;
/** Every message the worker posted, as the page would receive it. */
const inbox: any[] = [];
let onPost: ((message: any) => void) | null = null;
(globalThis as any).self = {
  addEventListener: (_type: string, h: Handler) => {
    handler = h;
  },
  postMessage: (message: any, transfer?: Transferable[]) => {
    // A real postMessage detaches what it transfers on the sending side and
    // delivers a copy; structuredClone with `transfer` does exactly that.
    const received = transfer && transfer.length ? structuredClone(message, { transfer }) : structuredClone(message);
    inbox.push(received);
    onPost?.(received);
  },
};
const workerModule = (await import("../src/lib/crypto-worker.ts")) as { STREAM_WINDOW: number };

let nextId = 1000;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const sha256 = (u: Uint8Array) => createHash("sha256").update(u).digest("hex");
const concat = (parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
};
const ab = (u: Uint8Array) => u.slice().buffer as ArrayBuffer;

interface Run {
  id: number;
  /** Chunk messages for this stream, in arrival order. */
  chunks: { seq: number; data: Uint8Array }[];
  /** This stream's non-chunk messages: its final answer, or its error. */
  finals: any[];
  /** Responses to acks this run sent; a valid ack gets none. */
  ackResponses: any[];
  /** The largest number of chunks posted and not yet acknowledged, seen at any arrival. */
  maxOutstanding: number;
  acksSent: number;
  /** Settles when the worker's handler for the request returns. */
  done: Promise<void>;
  ack(seq: number): Promise<void>;
}

/**
 * Start one request. With `autoAck`, each chunk is acknowledged on a later
 * task, as a page that writes it first would.
 */
function start(req: Record<string, unknown>, autoAck: boolean): Run {
  const id = ++nextId;
  const ackIds = new Set<number>();
  const run: Run = {
    id,
    chunks: [],
    finals: [],
    ackResponses: [],
    maxOutstanding: 0,
    acksSent: 0,
    done: Promise.resolve(),
    async ack(seq: number) {
      const ackId = ++nextId;
      ackIds.add(ackId);
      run.acksSent = Math.max(run.acksSent, seq + 1);
      await handler!({ data: { id: ackId, op: "ack", stream: id, seq } });
    },
  };
  const previous = onPost;
  onPost = (m) => {
    previous?.(m);
    if (ackIds.has(m.id)) run.ackResponses.push(m);
    if (m.id !== id) return;
    if (m.ok === true && m.op === "chunk") {
      run.chunks.push({ seq: m.seq, data: new Uint8Array(m.data) });
      run.maxOutstanding = Math.max(run.maxOutstanding, run.chunks.length - run.acksSent);
      if (autoAck) setImmediate(() => void run.ack(m.seq));
    } else {
      run.finals.push(m);
    }
  };
  run.done = handler!({ data: { id, ...req } });
  return run;
}

/** Wait until `cond` holds, or `ms` passes. */
async function waitFor(cond: () => boolean, ms: number): Promise<boolean> {
  const until = Date.now() + ms;
  while (!cond() && Date.now() < until) await sleep(10);
  return cond();
}

/**
 * Wait for the worker's handler to return, but not for ever: a worker that
 * stalls (a broken window, a dropped chunk the test keeps waiting on) is a
 * failure to report, not a suite that never ends.
 */
async function finish(run: Run, label: string, ms = 60_000): Promise<void> {
  const ended = await Promise.race([run.done.then(() => true), sleep(ms).then(() => false)]);
  if (!ended) check(false, `${label}: the request finished within ${ms / 1000} s`, "the worker stalled");
}

function containerOf(run: Run): Uint8Array {
  return concat([...run.chunks].sort((x, y) => x.seq - y.seq).map((c) => c.data));
}

const PASSWORD = "correct horse battery staple — streaming";
const OPTIONS: KeymakerOptions = { kdf: { kdf: KdfId.PBKDF2, params: { iterations: 600_000 } }, cipher: CipherId.AES_256_GCM };
const MiB = 1024 * 1024;
/** Recognisable on sight, and long enough that ciphertext cannot contain it by chance. */
const CANARY = "KEYMAKER-STREAM-CANARY-PLAINTEXT|";
const plaintext = (() => {
  const unit = new TextEncoder().encode(CANARY);
  const out = new Uint8Array(6 * MiB + 12345);
  for (let i = 0; i < out.length; i++) out[i] = unit[i % unit.length]!;
  return out;
})();
const canaryBytes = Buffer.from(CANARY);
const fileOf = (u: Uint8Array, name = "plain.bin") => new File([u as Uint8Array<ArrayBuffer>], name);

check(workerModule.STREAM_WINDOW === 4, "the stream window is 4", `${workerModule.STREAM_WINDOW}`);

// ---------------------------------------------------------------------------
// a, b, c, e: one streamed encrypt, acknowledged as it goes.
// ---------------------------------------------------------------------------
console.log("\nEncrypt a 6 MiB file through encrypt-stream:");
const main = start(
  { op: "encrypt-stream", file: fileOf(plaintext), password: PASSWORD, keyFile: null, options: OPTIONS },
  true
);
await finish(main, "the main encrypt");
const final = main.finals[0];
const container = containerOf(main);
const expectedChunks = 1 + Math.ceil(plaintext.length / MiB); // the head, then one write per payload chunk
check(
  main.finals.length === 1 && final?.ok === true && final.op === "encrypt-stream",
  "the stream ends with one encrypt-stream success",
  JSON.stringify(main.finals.map((f) => ({ ok: f.ok, op: f.op, message: f.message })))
);
check(
  main.chunks.length === expectedChunks && main.chunks.every((c, i) => c.seq === i),
  `it posted ${expectedChunks} chunk messages, seq 0..${expectedChunks - 1} in order`,
  `${main.chunks.length} chunks, seqs ${main.chunks.map((c) => c.seq).join(",")}`
);
check(
  container.length === final?.bytes &&
    container.length === keym2ContainerLength(KEYM2_VERSION_V3, CipherId.AES_256_GCM, 1, plaintext.length),
  "the chunks add up to the reported and the predicted container length",
  `${container.length} vs reported ${final?.bytes}`
);
{
  // a.
  let opened: Uint8Array | null = null;
  let why = "";
  try {
    opened = new Uint8Array((await decryptData(ab(container), PASSWORD, null)).data);
  } catch (e) {
    why = e instanceof Error ? e.message : String(e);
  }
  check(
    opened !== null && Buffer.compare(opened, plaintext) === 0,
    "(a) the concatenated chunks open with the in-memory reader to the original file",
    why || `opened ${opened?.length} bytes`
  );
}
// b.
check(
  typeof final?.digest === "string" && final.digest === sha256(container) && /^[0-9a-f]{64}$/.test(final.digest),
  "(b) digest is the lowercase hex SHA-256 of the concatenated chunks",
  `${final?.digest} vs ${sha256(container)}`
);
// c.
{
  const head = final?.head instanceof ArrayBuffer ? new Uint8Array(final.head) : null;
  const payloadOffset = keym2SlotTableOffset(KEYM2_VERSION_V3) + keym2SlotLen(CipherId.AES_256_GCM);
  check(
    head !== null && head.length === payloadOffset && Buffer.compare(head, container.subarray(0, payloadOffset)) === 0,
    "(c) head is the container's bytes before its first payload chunk",
    `head ${head?.length} bytes, payload offset ${payloadOffset}`
  );
  check(
    head !== null && main.chunks[0] !== undefined && Buffer.compare(head, main.chunks[0].data) === 0,
    "(c) and it is the first chunk message, again"
  );
}
// e.
{
  const carrying = main.chunks.filter((c) => Buffer.from(c.data).indexOf(canaryBytes) !== -1).map((c) => c.seq);
  check(carrying.length === 0, "(e) no chunk message carries the plaintext", `chunks ${carrying.join(",")}`);
  check(
    !JSON.stringify({ ...final, head: undefined }).includes(CANARY),
    "(e) nor does the final message"
  );
}
check(main.maxOutstanding <= 4, "never more than 4 chunks un-acknowledged while acks flowed", `${main.maxOutstanding}`);
check(main.ackResponses.length === 0, "a valid ack gets no response", JSON.stringify(main.ackResponses));

// ---------------------------------------------------------------------------
// d. Withhold acknowledgements.
// ---------------------------------------------------------------------------
console.log("\nWithhold acknowledgements:");
{
  const held = start(
    { op: "encrypt-stream", file: fileOf(plaintext), password: PASSWORD, keyFile: null, options: OPTIONS },
    false
  );
  await waitFor(() => held.chunks.length >= 4 || held.finals.length > 0, 30_000);
  // Long enough for a worker that ignores the window to have posted the rest:
  // sealing a mebibyte takes milliseconds.
  await sleep(1500);
  check(
    held.chunks.length === 4 && held.finals.length === 0,
    "(d) with no acknowledgement the worker posts exactly 4 chunks and stops",
    `${held.chunks.length} chunks, ${held.finals.length} final messages`
  );
  // An ack for a chunk the worker has not posted is refused, and does not open
  // the window: otherwise a page could acknowledge ahead and defeat it.
  {
    const before = inbox.length;
    await handler!({ data: { id: ++nextId, op: "ack", stream: held.id, seq: 99 } });
    const out = inbox.slice(before).filter((m) => m.id !== held.id);
    await sleep(300);
    check(
      out.length === 1 && out[0].ok === false && held.chunks.length === 4,
      "(d) an ack for a chunk that was not posted is answered ok:false and releases nothing",
      `${JSON.stringify(out)}; ${held.chunks.length} chunks`
    );
  }
  // Release them, acknowledging each chunk that arrives in turn, and let it
  // finish. Bounded: a worker that never finishes is reported, not waited on.
  const deadline = Date.now() + 60_000;
  let acked = 0;
  while (held.finals.length === 0 && Date.now() < deadline) {
    const arrived = held.chunks.filter((c) => c.seq >= acked).map((c) => c.seq);
    for (const seq of arrived.sort((x, y) => x - y)) {
      await held.ack(seq);
      acked = seq + 1;
    }
    await waitFor(() => held.chunks.some((c) => c.seq >= acked) || held.finals.length > 0, 5_000);
  }
  await finish(held, "(d)");
  check(
    held.finals[0]?.ok === true && held.chunks.length === expectedChunks,
    "(d) acknowledging them lets the stream finish",
    `${held.chunks.length} chunks, final ${JSON.stringify(held.finals[0]?.op ?? held.finals[0]?.message)}`
  );
}

// ---------------------------------------------------------------------------
// f. A file whose read fails part-way.
// ---------------------------------------------------------------------------
console.log("\nA file that stops being readable:");
{
  /** Readable for its first 2 MiB, then every read fails as a moved file's does. */
  class FailingFile extends File {
    override slice(start?: number, end?: number, type?: string): Blob {
      if ((start ?? 0) >= 2 * MiB) {
        return {
          arrayBuffer: () => Promise.reject(new DOMException("The file could not be read.", "NotReadableError")),
        } as unknown as Blob;
      }
      return super.slice(start, end, type);
    }
  }
  const bad = start(
    { op: "encrypt-stream", file: new FailingFile([plaintext], "moved.bin"), password: PASSWORD, keyFile: null, options: OPTIONS },
    true
  );
  await finish(bad, "(f)");
  await sleep(50);
  const errors = bad.finals.filter((f) => f.ok === false);
  const successes = bad.finals.filter((f) => f.ok === true);
  check(
    errors.length === 1 && successes.length === 0,
    "(f) a read that fails part-way yields one error and no success",
    JSON.stringify(bad.finals)
  );
  check(
    errors[0]?.code === "invalid-input" && /could not be read/i.test(errors[0]?.message ?? ""),
    "(f) and the error is the typed could-not-be-read error, not a generic failure",
    JSON.stringify(errors[0])
  );
}

// ---------------------------------------------------------------------------
// The ack protocol's edges, and the open-stream purposes.
// ---------------------------------------------------------------------------
console.log("\nAcknowledgements and open-stream:");
{
  const answers = async (data: Record<string, unknown>) => {
    const before = inbox.length;
    await handler!({ data });
    return inbox.slice(before);
  };
  for (const [label, msg] of [
    ["an ack with no stream or seq", { id: 1, op: "ack" }],
    ["an ack whose seq is not a number", { id: 2, op: "ack", stream: 5, seq: "0" }],
    ["an ack with a negative seq", { id: 3, op: "ack", stream: 5, seq: -1 }],
    ["an ack for a stream that is not running", { id: 4, op: "ack", stream: 987654, seq: 0 }],
  ] as const) {
    const out = await answers(msg);
    check(
      out.length === 1 && out[0].ok === false && out[0].id === msg.id && typeof out[0].message === "string",
      `${label} is answered ok:false`,
      JSON.stringify(out)
    );
  }

  // A streamed verify of the multi-chunk container from (a): no chunk crosses,
  // and the digest covers every container byte once, though the reader's head
  // read and its first chunk read overlap.
  const verify = start(
    { op: "open-stream", file: fileOf(container, "backup.keym"), password: PASSWORD, keyFile: null, purpose: "verify", digest: true },
    true
  );
  await finish(verify, "the streamed verify");
  const v = verify.finals[0];
  check(
    verify.chunks.length === 0 && verify.finals.length === 1 && v?.ok === true && v.op === "verify",
    "a streamed verify of a 7-chunk container posts no chunk and one verify answer",
    `${verify.chunks.length} chunks; ${JSON.stringify(v)}`
  );
  check(
    v?.bytes === plaintext.length && v?.format === "keym-v3" && v?.openedBy === "passphrase" && v?.slotTable === "authentic",
    "it reports the plaintext's length, the format, the slot and the slot table",
    JSON.stringify(v)
  );
  check(v?.digest === sha256(container), "its digest is the container's SHA-256", `${v?.digest}`);

  const noDigest = start(
    { op: "open-stream", file: fileOf(container), password: PASSWORD, keyFile: null, purpose: "verify", digest: false },
    true
  );
  await finish(noDigest, "the verify without digest");
  check(noDigest.finals[0]?.ok === true && noDigest.finals[0].digest === null, "without digest, the digest is null");

  for (const purpose of ["bogus", "Decrypt", undefined]) {
    const refused = start(
      { op: "open-stream", file: fileOf(container), password: PASSWORD, keyFile: null, purpose, digest: false },
      true
    );
    await finish(refused, `purpose ${String(purpose)}`);
    check(
      refused.chunks.length === 0 && refused.finals.length === 1 && refused.finals[0].ok === false &&
        /purpose/i.test(refused.finals[0].message),
      `open-stream with purpose ${JSON.stringify(purpose)} is refused, and nothing is posted`,
      JSON.stringify(refused.finals)
    );
  }
}

// ---------------------------------------------------------------------------
// g. Share set and passkey, byte for byte against the in-memory writer.
// ---------------------------------------------------------------------------
console.log("\nShare sets and passkeys through encrypt-stream:");
{
  // A seeded generator in place of crypto.getRandomValues, reset before each
  // writer, so both draw the same salts, container id, master key, share
  // secret and coefficients in the same order.
  const realCrypto = globalThis.crypto;
  const pin = (seed: number) => {
    let s = seed >>> 0 || 1;
    Object.defineProperty(realCrypto, "getRandomValues", {
      configurable: true,
      writable: true,
      value: <T extends ArrayBufferView | null>(array: T): T => {
        const bytes = new Uint8Array(array!.buffer, array!.byteOffset, array!.byteLength);
        for (let i = 0; i < bytes.length; i++) {
          s ^= s << 13;
          s ^= s >>> 17;
          s ^= s << 5;
          bytes[i] = s & 0xff;
        }
        return array;
      },
    });
  };
  const unpin = () => {
    delete (realCrypto as unknown as Record<string, unknown>).getRandomValues;
  };

  const small = new TextEncoder().encode(`${CANARY} a smaller file, two chunks `.repeat(40_000));
  const prf = Uint8Array.from({ length: 32 }, (_, i) => (i * 29 + 3) & 0xff);
  const passkeySalt = Uint8Array.from({ length: 32 }, (_, i) => (i * 11 + 1) & 0xff);
  const shamir = { threshold: 2, count: 3 };

  pin(0x5eed);
  const streamed = start(
    {
      op: "encrypt-stream",
      file: fileOf(small),
      password: PASSWORD,
      keyFile: null,
      options: OPTIONS,
      shamir,
      passkey: { prfOutput: prf.slice(), salt: passkeySalt.slice() },
    },
    true
  );
  await finish(streamed, "(g) shares and passkey");
  unpin();
  const s = streamed.finals[0];
  const streamedContainer = containerOf(streamed);

  pin(0x5eed);
  const inMemory = await encryptContainerWithSlots(ab(small), PASSWORD, null, OPTIONS, {
    shamir,
    passkey: { prfOutput: prf.slice(), salt: passkeySalt.slice() },
  });
  unpin();

  check(s?.ok === true && Array.isArray(s.shares) && s.shares.length === 3, "a share set and a passkey stream", JSON.stringify(s?.message));
  check(
    Buffer.compare(streamedContainer, new Uint8Array(inMemory.data)) === 0 &&
      JSON.stringify(s?.shares) === JSON.stringify(inMemory.shares),
    "(g) the streamed container and shares are byte-identical to the in-memory writer's under the same randomness",
    `${streamedContainer.length} vs ${inMemory.data.byteLength} bytes`
  );
  check(s?.digest === sha256(streamedContainer), "(g) and its digest is the container's");
  const opens = async (label: string, password: string, shares?: string[], prfOutput?: Uint8Array) => {
    let why = "";
    try {
      const r = await decryptData(ab(streamedContainer), password, null, shares, prfOutput);
      if (Buffer.compare(new Uint8Array(r.data), small) === 0) {
        check(true, `(g) it opens with ${label} (opened by ${r.openedBy})`);
        return;
      }
      why = "plaintext differs";
    } catch (e) {
      why = e instanceof Error ? e.message : String(e);
    }
    check(false, `(g) it opens with ${label}`, why);
  };
  await opens("the password", PASSWORD);
  await opens("two of the three strips alone", "", s?.shares?.slice(1));
  await opens("the passkey alone", "", undefined, prf.slice());

  // §4.8: one slot, the password and the strips together.
  pin(0xb07);
  const both = start(
    {
      op: "encrypt-stream",
      file: fileOf(small),
      password: PASSWORD,
      keyFile: null,
      options: OPTIONS,
      shamir: { ...shamir, withPassword: true },
    },
    true
  );
  await finish(both, "(g) password and strips");
  unpin();
  pin(0xb07);
  const bothInMemory = await encryptContainerWithSharesRequired(ab(small), PASSWORD, null, OPTIONS, 2, 3);
  unpin();
  const b = both.finals[0];
  const bothContainer = containerOf(both);
  check(
    b?.ok === true &&
      Buffer.compare(bothContainer, new Uint8Array(bothInMemory.data)) === 0 &&
      JSON.stringify(b.shares) === JSON.stringify(bothInMemory.shares),
    "(g) a password-and-strips backup streams byte-identical to the in-memory writer's",
    JSON.stringify(b?.message)
  );
  {
    let ok = false;
    try {
      const r = await decryptData(ab(bothContainer), PASSWORD, null, b?.shares?.slice(0, 2));
      ok = Buffer.compare(new Uint8Array(r.data), small) === 0 && r.openedBy === "passphrase-and-shares";
    } catch {
      ok = false;
    }
    check(ok, "(g) and it opens with the password and two strips");
  }

  // A passkey beside a password-and-strips slot is refused before anything is
  // read, exactly as the in-memory encrypt refuses it.
  const contradictory = start(
    {
      op: "encrypt-stream",
      file: fileOf(small),
      password: PASSWORD,
      keyFile: null,
      options: OPTIONS,
      shamir: { ...shamir, withPassword: true },
      passkey: { prfOutput: prf.slice(), salt: passkeySalt.slice() },
    },
    true
  );
  await finish(contradictory, "the contradictory request");
  check(
    contradictory.chunks.length === 0 && contradictory.finals[0]?.ok === false &&
      contradictory.finals[0]?.code === "invalid-input",
    "a passkey beside a password-and-strips slot is refused, and nothing is posted",
    JSON.stringify(contradictory.finals)
  );
}

// ---------------------------------------------------------------------------
// Streamed decrypt: `open-stream` with purpose "decrypt", then `drain`.
// ---------------------------------------------------------------------------
//
// Phase 1 opens the container and keeps it as the worker's one session; its
// answer carries no plaintext. Phase 2 drains the session to the page under
// the ack window, and its final answer is the page's commit signal (§5.5), so
// it must come only after the last chunk opened under final_flag and every
// chunk was acknowledged, and never for a container that does not verify to
// the end. Negative controls, each built and run: post chunk 0 with the
// `opened` answer (h fails); post the final answer before the last ack (i
// fails); open the last chunk under final_flag 0 in the core (the truncation
// check in j fails); post the final answer however the drain ended (both
// checks in j fail); skip the session discard on a new request (k fails).
console.log("\nStreamed decrypt:");
{
  const OPENED_FIELDS = new Set(["id", "ok", "op", "format", "bytes", "openedBy", "keyFileUsed", "slotTable", "weakKdf"]);
  /** Every buffer, typed array or Blob anywhere in a message, by path. */
  const buffersIn = (value: unknown, path = "message"): string[] => {
    if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) return [`${path} is a buffer`];
    if (value instanceof Blob) return [`${path} is a Blob`];
    if (value && typeof value === "object") {
      return Object.entries(value).flatMap(([k, v]) => buffersIn(v, `${path}.${k}`));
    }
    return [];
  };
  const openReq = (file: Blob, password = PASSWORD) => ({
    op: "open-stream",
    file,
    password,
    keyFile: null,
    purpose: "decrypt",
    digest: false,
  });
  const MiBTag = MiB + 16; // one full AES-GCM chunk on the wire
  const lastChunkWire = (plaintext.length % MiB) + 16;

  // h. Phase 1 posts one `opened` answer, with no buffer and no plaintext.
  const opened = start(openReq(fileOf(container, "backup.keym")), true);
  await finish(opened, "(h) the open");
  const o = opened.finals[0];
  const extra = o ? Object.keys(o).filter((k) => !OPENED_FIELDS.has(k)) : ["no message"];
  check(
    opened.chunks.length === 0 && opened.finals.length === 1 && o?.ok === true && o.op === "opened",
    "(h) open-stream for decrypt posts exactly one opened answer and no chunk",
    `${opened.chunks.length} chunks; ${JSON.stringify(opened.finals.map((f) => f.op ?? f.message))}`
  );
  check(
    extra.length === 0 && buffersIn(o).length === 0 && !JSON.stringify(o ?? {}).includes(CANARY),
    "(h) the opened answer holds no buffer, no plaintext and nothing off its allow-list",
    [...extra, ...buffersIn(o)].join("; ")
  );
  check(
    o?.bytes === plaintext.length && o?.format === "keym-v3" && o?.openedBy === "passphrase" &&
      o?.slotTable === "authentic" && o?.keyFileUsed === false,
    "(h) it reports the plaintext's length, the format, the slot and the slot table",
    JSON.stringify(o)
  );

  // i. The drain yields the plaintext, and its final answer waits for the last ack.
  const drain = start({ op: "drain" }, false);
  const expectedDrainChunks = Math.ceil(plaintext.length / MiB);
  {
    const deadline = Date.now() + 60_000;
    let acked = 0;
    while (Date.now() < deadline) {
      const ready = drain.chunks.filter((c) => c.seq >= acked && c.seq < expectedDrainChunks - 1).map((c) => c.seq);
      for (const seq of ready.sort((x, y) => x - y)) {
        await drain.ack(seq);
        acked = seq + 1;
      }
      if (drain.chunks.length >= expectedDrainChunks || drain.finals.length > 0) break;
      await waitFor(() => drain.chunks.some((c) => c.seq >= acked) || drain.finals.length > 0, 5_000);
    }
  }
  // Every chunk is posted and all but the last acknowledged. A worker that
  // answered on `drain()` resolving, rather than on the last ack, has answered.
  await sleep(500);
  check(
    drain.chunks.length === expectedDrainChunks && drain.finals.length === 0,
    "(i) with every chunk posted and the last not yet acknowledged, no final answer has been sent",
    `${drain.chunks.length} chunks, finals ${JSON.stringify(drain.finals)}`
  );
  await drain.ack(expectedDrainChunks - 1);
  await finish(drain, "(i) the drain");
  const d = drain.finals[0];
  check(
    drain.finals.length === 1 && d?.ok === true && d.op === "drain" && d.bytes === plaintext.length,
    "(i) acknowledging the last chunk brings the one final drain answer, with the plaintext's length",
    JSON.stringify(drain.finals)
  );
  check(
    Buffer.compare(containerOf(drain), plaintext) === 0,
    "(i) the drained chunks, in seq order, are the original plaintext",
    `${containerOf(drain).length} bytes vs ${plaintext.length}`
  );
  check(drain.chunks.every((c, i) => c.seq === i), "(i) the chunks arrive in order");
  check(
    drain.maxOutstanding <= workerModule.STREAM_WINDOW,
    "(i) never more than 4 chunks un-acknowledged",
    `${drain.maxOutstanding}`
  );
  {
    const again = start({ op: "drain" }, true);
    await finish(again, "(i) a second drain");
    check(
      again.chunks.length === 0 && again.finals[0]?.ok === false && /no opened backup/i.test(again.finals[0]?.message ?? ""),
      "(i) the session is single use: a second drain is refused and posts nothing",
      JSON.stringify(again.finals)
    );
  }

  // j. A container that does not verify to the end: never a final success.
  const flipped = container.slice();
  flipped[flipped.length - 1]! ^= 0x01;
  // Exactly the last chunk removed: a payload of whole chunks, valid by length,
  // whose new last chunk was sealed with final_flag 0.
  const truncated = container.slice(0, container.length - lastChunkWire);
  {
    const payloadOffset = keym2SlotTableOffset(KEYM2_VERSION_V3) + keym2SlotLen(CipherId.AES_256_GCM);
    check(
      container.length === payloadOffset + 6 * MiBTag + lastChunkWire && truncated.length === payloadOffset + 6 * MiBTag,
      "(j) tripwire: the truncated container is six whole chunks, ending exactly on a chunk boundary",
      `${container.length}, ${truncated.length}, payload at ${payloadOffset}`
    );
  }
  for (const [label, bad] of [
    ["its last chunk flipped", flipped],
    ["truncated exactly at a chunk boundary", truncated],
  ] as const) {
    const op = start(openReq(fileOf(bad)), true);
    await finish(op, `(j) open, ${label}`);
    check(
      op.finals[0]?.ok === true && op.finals[0].op === "opened",
      `(j) a container with ${label} opens in phase 1 (only chunk 0 is checked there)`,
      JSON.stringify(op.finals)
    );
    const dr = start({ op: "drain" }, true);
    await finish(dr, `(j) drain, ${label}`);
    await sleep(100);
    const successes = dr.finals.filter((f) => f.ok === true);
    const errors = dr.finals.filter((f) => f.ok === false);
    check(
      successes.length === 0 && errors.length === 1,
      `(j) draining a container with ${label} sends an error and never a final success`,
      `${dr.chunks.length} chunks; ${JSON.stringify(dr.finals)}`
    );
    check(
      errors[0]?.message === "Decryption failed." && errors[0]?.code === null,
      `(j) and the error is the generic one, saying nothing about which check failed`,
      JSON.stringify(errors[0])
    );
    check(dr.chunks.length > 0, `(j) chunks before the bad one did reach the page (the check is not vacuous)`,
      `${dr.chunks.length} chunks`);
  }

  // k. Every way a session ends: a later drain is refused.
  const refusedDrain = async (label: string) => {
    const dr = start({ op: "drain" }, true);
    await finish(dr, label);
    check(
      dr.chunks.length === 0 && dr.finals.length === 1 && dr.finals[0]?.ok === false &&
        /no opened backup/i.test(dr.finals[0]?.message ?? ""),
      `(k) after ${label}, a drain is refused and posts nothing`,
      `${dr.chunks.length} chunks; ${JSON.stringify(dr.finals)}`
    );
  };
  const openOk = async (label: string, file: Blob = fileOf(container)) => {
    const op = start(openReq(file), true);
    await finish(op, label);
    if (op.finals[0]?.op !== "opened") check(false, `${label}: the open succeeded`, JSON.stringify(op.finals));
  };
  await openOk("(k) open before close-stream");
  {
    const cs = start({ op: "close-stream" }, true);
    await finish(cs, "(k) close-stream");
    check(cs.finals[0]?.ok === true && cs.finals[0].op === "close-stream", "(k) close-stream is answered", JSON.stringify(cs.finals));
  }
  await refusedDrain("close-stream");
  await openOk("(k) open before a ping");
  {
    const p = start({ op: "ping" }, true);
    await finish(p, "(k) ping");
  }
  await refusedDrain("a new request (a ping)");
  await openOk("(k) open before a verify");
  {
    const v = start({ op: "open-stream", file: fileOf(container), password: PASSWORD, keyFile: null, purpose: "verify", digest: false }, true);
    await finish(v, "(k) verify");
    check(v.finals[0]?.ok === true, "(k) the verify in between succeeds");
  }
  await refusedDrain("a new request (a streamed verify)");
  await openOk("(k) open before a wrong-password open");
  {
    const wrong = start(openReq(fileOf(container), `${PASSWORD} but wrong`), true);
    await finish(wrong, "(k) the wrong-password open");
    check(
      wrong.finals.length === 1 && wrong.finals[0]?.ok === false && wrong.chunks.length === 0,
      "(k) a wrong password gets no opened answer, only an error",
      JSON.stringify(wrong.finals)
    );
  }
  await refusedDrain("a second open that failed");
  {
    // A second open that succeeds replaces the first: the drain is the second's.
    const other = new TextEncoder().encode(`${CANARY} the second backup `.repeat(100));
    const secondContainer = await encryptContainerWithSlots(ab(other), PASSWORD, null, OPTIONS, {});
    await openOk("(k) the first open");
    await openOk("(k) the second open", fileOf(new Uint8Array(secondContainer.data)));
    const dr = start({ op: "drain" }, true);
    await finish(dr, "(k) the drain after two opens");
    check(
      dr.finals[0]?.ok === true && Buffer.compare(containerOf(dr), other) === 0,
      "(k) after a second open, the drain is the second backup's",
      JSON.stringify(dr.finals)
    );
  }
  await refusedDrain("a drain that finished");
  {
    // A request that arrives while an open is still deriving ends the session
    // that open is about to make.
    const slow = start(openReq(fileOf(container)), true);
    const cs = start({ op: "close-stream" }, true);
    await finish(slow, "(k) the overtaken open");
    await finish(cs, "(k) the overtaking close-stream");
    check(
      slow.finals[0]?.ok === false,
      "(k) an open overtaken by close-stream while deriving does not answer opened",
      JSON.stringify(slow.finals)
    );
    await refusedDrain("an open overtaken while deriving");
  }
  {
    // A drain overtaken by a new request mid-stream ends with an error.
    await openOk("(k) open before an overtaken drain");
    const dr = start({ op: "drain" }, false);
    await waitFor(() => dr.chunks.length >= 1, 30_000);
    const p = start({ op: "ping" }, true);
    await finish(p, "(k) the ping that overtakes the drain");
    await finish(dr, "(k) the overtaken drain");
    check(
      dr.finals.length === 1 && dr.finals[0]?.ok === false,
      "(k) a drain overtaken by a new request ends with an error, not a success",
      JSON.stringify(dr.finals)
    );
  }

  // l. Formats that cannot be read a chunk at a time, refused by name.
  {
    const refusedByName = async (label: string, file: Blob, name: RegExp) => {
      const op = start(openReq(file), true);
      await finish(op, label);
      const f = op.finals[0];
      check(
        op.finals.length === 1 && f?.ok === false && f.code === "unsupported-config" && name.test(f.message ?? ""),
        `(l) ${label} is refused by name`,
        JSON.stringify(op.finals)
      );
      await refusedDrain(`a refused ${label}`);
    };
    const { readFileSync } = await import("node:fs");
    const { dirname, join } = await import("node:path");
    const { fileURLToPath } = await import("node:url");
    const here = dirname(fileURLToPath(import.meta.url));
    const meta = JSON.parse(readFileSync(join(here, "fixtures", "keymaker", "fixtures.json"), "utf8"));
    const v1 = meta.fixtures.find((f: { version?: number; file: string; audio?: boolean; selfextract?: boolean }) =>
      (f.version ?? 1) === 1 && !f.audio && !f.selfextract);
    const v1Bytes = new Uint8Array(readFileSync(join(here, "fixtures", "keymaker", v1.file)));
    await refusedByName("a KEYM v1 backup", fileOf(v1Bytes), /This is a KEYM v1 backup/);
    // Above the in-memory limit: the header decides, before anything is read past it.
    const bigV1 = new Blob([v1Bytes as Uint8Array<ArrayBuffer>, new Uint8Array(101 * MiB)]);
    await refusedByName("a KEYM v1 backup above 100 MB", bigV1, /This is a KEYM v1 backup/);
    const legacy = JSON.parse(readFileSync(join(here, "crypto-fixtures.json"), "utf8"));
    const ibtz1 = legacy.fixtures.find((f: { format: string }) => f.format === "v1");
    const ibtzBytes = Uint8Array.from(Buffer.from(ibtz1.base64, "base64"));
    await refusedByName("an IttyBitz v1 backup", fileOf(ibtzBytes), /This is an IttyBitz v1 backup/);
    await refusedByName(
      "a file with no header (IttyBitz v0, or not a backup)",
      new Blob([new Uint8Array(101 * MiB).fill(0x61)]),
      /not a KEYM v2, v3 or v4 backup/
    );
  }
}

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
