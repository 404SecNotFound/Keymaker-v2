/**
 * The streaming core of KEYM v2/v3/v4: the writer's sink contract, buffer
 * ownership, §5.5's commit-on-resolve rule, `blobSource`'s typed read
 * failure, v4's emission window, and `discard`.
 *
 * Byte equality with the reference is not tested here. The in-memory API is
 * the streaming core over a memory source and a collecting sink, so
 * crosstest2, the published vectors, the frozen corpus and the slot
 * transaction suite already hold the core to the bytes; crosstest2 also drives
 * the streaming entry points through the bridge (`encrypt2stream`,
 * `decrypt2stream`). What is here is the part of the contract those suites
 * cannot see: what a sink receives, in what order, and when.
 *
 *   node scripts/keymaker-test.mjs keym2-stream
 *
 * Each section names the control that was shown to make it fail.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { webcrypto } from "node:crypto";
import { CipherId, KdfId, isUserFacingError, type KdfParams } from "../src/lib/keymaker-crypto.ts";
import {
  KEYM2_CHUNK_SIZE,
  KEYM2_VERSION_V2,
  KEYM2_VERSION_V3,
  KEYM2_VERSION_V4,
  blobSource,
  bytesSource,
  decryptKeym2,
  encryptKeym2ToSink,
  encryptKeym2WithExplicitSecrets,
  encryptKeym2WithExplicitSecretsToSink,
  keym2ContainerLength,
  keym2PaddedLen,
  keym2SlotLen,
  keym2SlotTableOffset,
  openKeym2Stream,
  type Keym2ByteSink,
  type Keym2ByteSource,
} from "../src/lib/keym-v2.ts";

if (!globalThis.crypto) {
  (globalThis as { crypto?: Crypto }).crypto = webcrypto as unknown as Crypto;
}

let passed = 0;
const failures: string[] = [];
function check(ok: boolean, label: string, detail = ""): void {
  if (ok) {
    passed++;
    console.log(`  ok   ${label}`);
  } else {
    failures.push(label);
    console.log(`  FAIL ${label}${detail ? `   ${detail}` : ""}`);
  }
}

const C = KEYM2_CHUNK_SIZE;
const PASSWORD = "stream core: correct horse battery staple 51e0";
const FAST: KdfParams = { kdf: KdfId.PBKDF2, params: { iterations: 600_000 } };
const SALT = Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff);
const MASTER = Uint8Array.from({ length: 32 }, (_, i) => (i * 17 + 9) & 0xff);
const CID = Uint8Array.from({ length: 16 }, (_, i) => (i * 13 + 1) & 0xff);
const GENERIC = "Decryption failed.";
const TAG: Record<number, number> = {
  [CipherId.AES_256_GCM]: 16,
  [CipherId.CHACHA20_POLY1305]: 16,
  [CipherId.CHAINED]: 32,
};

/** Deterministic, non-repeating enough that a misplaced chunk cannot match. */
function pattern(n: number, seed = 1): Uint8Array {
  const out = new Uint8Array(n);
  let x = seed * 2654435761 >>> 0;
  for (let i = 0; i < n; i++) {
    x = (x * 1103515245 + 12345) >>> 0;
    out[i] = x >>> 24;
  }
  return out;
}

function concatAll(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

const same = (a: Uint8Array | null, b: Uint8Array | null): boolean =>
  a !== null && b !== null && Buffer.from(a).equals(Buffer.from(b));

/** A sink that keeps the buffers it is handed, by reference, in order. */
function retainingSink(): { sink: Keym2ByteSink; writes: Uint8Array[] } {
  const writes: Uint8Array[] = [];
  return { sink: { write: async (bytes) => void writes.push(bytes) }, writes };
}

function versionLabel(v: number): string {
  return `v${v}`;
}

async function writeStreamed(
  plaintext: Uint8Array,
  version: number,
  cipher: CipherId,
  sink: Keym2ByteSink
): Promise<{ bytes: number; head: Uint8Array }> {
  return encryptKeym2WithExplicitSecretsToSink(
    bytesSource(plaintext),
    PASSWORD,
    null,
    { kdf: FAST, cipher },
    SALT,
    MASTER,
    sink,
    version,
    version === KEYM2_VERSION_V2 ? new Uint8Array(0) : CID
  );
}

/** §5.5 as a caller must apply it: write to a temporary place, commit only when drain resolves. */
async function commitOnResolve(
  source: Keym2ByteSource,
  password = PASSWORD
): Promise<{ committed: Uint8Array | null; error: unknown; writes: Uint8Array[]; opened: boolean }> {
  const temporary: Uint8Array[] = [];
  let committed: Uint8Array | null = null;
  let error: unknown = null;
  let opened = false;
  try {
    const stream = await openKeym2Stream(source, password, null);
    opened = true;
    try {
      await stream.drain({ write: async (bytes) => void temporary.push(bytes) });
      committed = concatAll(temporary); // the commit
    } finally {
      stream.discard();
    }
  } catch (e) {
    error = e;
  }
  return { committed, error, writes: temporary, opened };
}

const message = (e: unknown): string => (e instanceof Error ? e.message : String(e));

/**
 * Run one section. An exception the section did not expect fails it by name
 * rather than ending the run: a control that breaks the writer must show up
 * as the checks it breaks, not as a traceback that hides every later section.
 */
async function guarded(name: string, body: () => Promise<void>): Promise<void> {
  try {
    await body();
  } catch (e) {
    check(false, `${name}: ran to the end without an unexpected exception`, message(e));
  }
}

// ---------------------------------------------------------------------------
// (a) The writer's sink contract: the head as one write, then exactly one
//     write per chunk, each of its exact length, totalling
//     keym2ContainerLength. The chunk count is computed here, from §5.1 and
//     v4 §4.1, not taken from the library.
//
// Control: a writer that emits an empty trailing chunk on an exact multiple
// of the chunk size (count = floor(n / C) + 1) fails every exact multiple
// here — C and 2C of plaintext, and v4's one-chunk stream at C - 8 — on both
// the write count and the total.
// ---------------------------------------------------------------------------
console.log("\n(a) Sink contract: head, then one write per chunk:");
await guarded("(a)", async () => {
  for (const version of [KEYM2_VERSION_V2, KEYM2_VERSION_V3, KEYM2_VERSION_V4]) {
    for (const cipher of [CipherId.AES_256_GCM, CipherId.CHAINED]) {
      const sizes =
        version === KEYM2_VERSION_V4
          ? [0, 248, 249, C - 8, C - 7, C]
          : [0, 1, C - 1, C, C + 1, 2 * C];
      for (const n of sizes) {
        const label = `${versionLabel(version)} ${cipher === CipherId.CHAINED ? "chained" : "aes"} ${n} B`;
        const plaintext = pattern(n, n + version);
        const { sink, writes } = retainingSink();
        let summary: { bytes: number; head: Uint8Array } | null = null;
        try {
          summary = await writeStreamed(plaintext, version, cipher, sink);
        } catch (e) {
          check(false, `${label}: the streaming writer completes`, message(e));
          continue;
        }
        const tag = TAG[cipher] as number;
        const headLen = keym2SlotTableOffset(version) + keym2SlotLen(cipher);
        const stream = version === KEYM2_VERSION_V4 ? keym2PaddedLen(8 + n) : n;
        const count = Math.max(1, Math.ceil(stream / C));
        const wantLens = [headLen];
        for (let i = 0; i < count; i++) wantLens.push(Math.min(C, stream - i * C) + tag);
        const gotLens = writes.map((w) => w.length);
        check(
          gotLens.length === wantLens.length && gotLens.every((l, i) => l === wantLens[i]),
          `${label}: the head (${headLen} B), then ${count} chunk write(s) of exactly their length`,
          `got [${gotLens.join(", ")}], want [${wantLens.join(", ")}]`
        );
        const total = gotLens.reduce((a, b) => a + b, 0);
        const want = keym2ContainerLength(version, cipher, 1, n);
        check(total === want && summary.bytes === want,
          `${label}: total equals keym2ContainerLength (${want} B), and the summary says so`,
          `wrote ${total}, summary ${summary.bytes}`);
        check(same(summary.head, writes[0] ?? null), `${label}: summary.head is the head the sink received`);
      }
    }
  }
});

// ---------------------------------------------------------------------------
// (b) Ownership. The sink keeps every buffer it is handed by reference and
//     erases all of them once the write is done; the concatenation it made
//     first must still decrypt, and summary.head must survive the erase.
//
// Control: a writer that seals into one scratch buffer and hands the sink a
// view of it each time makes every retained write alias the last chunk, and
// the container no longer opens.
// ---------------------------------------------------------------------------
console.log("\n(b) Ownership: the sink may keep or erase what it is handed:");
await guarded("(b)", async () => {
  for (const version of [KEYM2_VERSION_V3, KEYM2_VERSION_V4]) {
    for (const cipher of [CipherId.AES_256_GCM, CipherId.CHACHA20_POLY1305]) {
      const label = `${versionLabel(version)} ${cipher === CipherId.AES_256_GCM ? "aes" : "chacha"}`;
      const plaintext = pattern(2 * C + 77, 5);
      const { sink, writes } = retainingSink();
      let summary: { bytes: number; head: Uint8Array } | null = null;
      try {
        summary = await writeStreamed(plaintext, version, cipher, sink);
      } catch (e) {
        check(false, `${label}: the streaming writer completes`, message(e));
        continue;
      }
      const collected = concatAll(writes);
      const distinct = new Set(writes.map((w) => w.buffer)).size;
      check(distinct === writes.length, `${label}: every write is its own buffer`, `${distinct} buffers for ${writes.length} writes`);
      for (const w of writes) w.fill(0);
      check(!summary.head.every((b) => b === 0) && same(summary.head, collected.subarray(0, summary.head.length)),
        `${label}: summary.head is the writer's own copy, untouched by the sink erasing its head`);
      try {
        const got = await decryptKeym2(collected, PASSWORD, null);
        check(same(got.data, plaintext), `${label}: what the sink collected decrypts to the plaintext after the sink erased every buffer`);
      } catch (e) {
        check(false, `${label}: what the sink collected decrypts to the plaintext after the sink erased every buffer`, message(e));
      }
    }
  }
});

// ---------------------------------------------------------------------------
// (c) §5.5: drain hands chunks over as they verify, and resolves only once
//     the final chunk has opened under final_flag 1. A caller that commits
//     on resolve therefore never commits a truncated or tampered container.
//
// Control: opening the last chunk in drain with final_flag 0 makes the
// boundary truncation resolve, and the wrapper commits a two-chunk prefix.
// ---------------------------------------------------------------------------
console.log("\n(c) §5.5: commit only when drain resolves:");
await guarded("(c)", async () => {
  const plaintext = pattern(2 * C + 100, 9);
  const container = await encryptKeym2WithExplicitSecrets(
    plaintext, PASSWORD, null, { kdf: FAST, cipher: CipherId.AES_256_GCM }, SALT, MASTER, KEYM2_VERSION_V3, CID);
  const off = keym2SlotTableOffset(KEYM2_VERSION_V3) + keym2SlotLen(CipherId.AES_256_GCM);
  const stride = C + 16;

  const good = await commitOnResolve(bytesSource(container));
  check(same(good.committed, plaintext), "the untouched three-chunk container commits its plaintext (the wrapper can commit)",
    message(good.error));

  const flip = (at: number): Uint8Array => {
    const c = container.slice();
    c[at] = (c[at] as number) ^ 0x01;
    return c;
  };
  const cases: [string, Uint8Array, (r: Awaited<ReturnType<typeof commitOnResolve>>) => void][] = [
    ["truncated exactly at a chunk boundary (two whole chunks left)", container.slice(0, off + 2 * stride), (r) => {
      check(r.opened && r.writes.length >= 1, "boundary truncation: chunk 0 had already reached the sink when drain refused");
    }],
    ["the last chunk flipped", flip(container.length - 5), () => {}],
    ["a middle chunk flipped", flip(off + stride + 100), (r) => {
      check(r.opened && r.writes.length === 1 && (r.writes[0]?.length ?? 0) === C && same(r.writes[0] ?? null, plaintext.subarray(0, C)),
        "middle chunk: the sink DID receive chunk 0 (this is about commit, not emission)",
        `${r.writes.length} write(s)`);
    }],
  ];
  for (const [why, bad, extra] of cases) {
    const r = await commitOnResolve(bytesSource(bad));
    check(r.committed === null && message(r.error) === GENERIC,
      `${why}: drain rejects with the generic error and nothing is committed`,
      r.committed ? `committed ${r.committed.length} B` : message(r.error));
    extra(r);
  }

  // docs/vectors/reject.json: the published must-reject rows that are about
  // the payload. Rows refused at open hand the sink nothing at all.
  const pack = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "docs", "vectors", "reject.json"), "utf8")) as {
    vectors: { id: string; input: string; password?: string }[];
  };
  const rows = new Map(pack.vectors.map((v) => [v.id, v]));
  for (const [id, atOpen] of [
    ["reject-container-final-flag", true],
    ["reject-container-payload-cut", true],
    ["reject-container-v4-too-short", true],
    ["reject-container-v4-length-overrun", true],
    ["reject-container-v4-wrong-bucket", true],
    ["reject-container-v4-padding-nonzero", false],
  ] as const) {
    const row = rows.get(id);
    if (!row || row.password === undefined) {
      check(false, `reject.json still carries ${id}`);
      continue;
    }
    const r = await commitOnResolve(bytesSource(Uint8Array.from(Buffer.from(row.input, "hex"))), row.password);
    check(r.committed === null && message(r.error) === GENERIC,
      `${id}: refused with the generic error, nothing committed`,
      r.committed ? `committed ${r.committed.length} B` : message(r.error));
    if (atOpen) {
      check(r.writes.length === 0, `${id}: the sink was handed nothing`, `${r.writes.length} write(s)`);
    }
  }
  // The non-zero padding row is refused by drain, not open: its chunk opens
  // and its prefix is sound. It is a one-chunk stream with L = 14 and the
  // padding in the same chunk, so step 5 runs before the chunk's plaintext
  // is handed on and the sink sees none of it.
  {
    const row = rows.get("reject-container-v4-padding-nonzero");
    if (row?.password !== undefined) {
      const r = await commitOnResolve(bytesSource(Uint8Array.from(Buffer.from(row.input, "hex"))), row.password);
      check(r.opened && r.writes.length === 0,
        "v4 non-zero padding: the zero check runs before that chunk's plaintext is handed on", `${r.writes.length} write(s)`);
    }
  }
});

// ---------------------------------------------------------------------------
// (d) blobSource: a read that fails or comes back short is a typed
//     invalid-input error saying the file could not be read to the end, not
//     the generic decryption failure, on the read path and the write path.
//
// Control: without the typed wrap the DOMException reaches the caller as
// itself, which isUserFacingError rejects.
// ---------------------------------------------------------------------------
console.log("\n(d) blobSource: an unreadable file is a typed error:");
await guarded("(d)", async () => {
  const plaintext = pattern(C + 300, 11);
  const container = await encryptKeym2WithExplicitSecrets(
    plaintext, PASSWORD, null, { kdf: FAST, cipher: CipherId.AES_256_GCM }, SALT, MASTER, KEYM2_VERSION_V3, CID);
  const real = new Blob([container as BlobPart]);
  const off = keym2SlotTableOffset(KEYM2_VERSION_V3) + keym2SlotLen(CipherId.AES_256_GCM);

  const ok = await commitOnResolve(blobSource(real));
  check(same(ok.committed, plaintext), "a real Blob opens and drains to the plaintext", message(ok.error));

  /** A Blob whose reads at or past `failAt` throw (or, with `short`, come back one byte short). */
  const flaky = (blob: Blob, failAt: number, short = false): Blob =>
    ({
      size: blob.size,
      slice(start?: number, end?: number) {
        const part = blob.slice(start, end);
        return {
          arrayBuffer: async () => {
            if ((start ?? 0) < failAt) return part.arrayBuffer();
            if (short) return (await part.arrayBuffer()).slice(1);
            throw new DOMException("The requested file could not be read.", "NotReadableError");
          },
        } as Blob;
      },
    }) as Blob;

  const typed = (e: unknown): boolean =>
    isUserFacingError(e) && e.code === "invalid-input" && /could not be read to the end/.test(e.message) &&
    /nothing was saved/.test(e.message) && e.message !== GENERIC;

  for (const [why, blob] of [
    ["the head read throws", flaky(real, 0)],
    ["a chunk read mid-drain throws", flaky(real, off + 1)],
    ["a chunk read mid-drain comes back short", flaky(real, off + 1, true)],
  ] as const) {
    const r = await commitOnResolve(blobSource(blob));
    check(r.committed === null && typed(r.error),
      `read: ${why}: a typed invalid-input error saying the file could not be read, not "${GENERIC}"`,
      r.error instanceof Error ? `${(r.error as { code?: string }).code ?? r.error.name}: ${r.error.message}` : String(r.error));
  }

  // The write path reads its plaintext through the same source.
  const plainBlob = new Blob([plaintext as BlobPart]);
  for (const [why, blob] of [
    ["the first plaintext read throws", flaky(plainBlob, 0)],
    ["a later plaintext read throws", flaky(plainBlob, 1)],
  ] as const) {
    let error: unknown = null;
    try {
      await encryptKeym2ToSink(blobSource(blob), PASSWORD, null, { kdf: FAST, cipher: CipherId.AES_256_GCM },
        { write: async () => {} }, KEYM2_VERSION_V3);
    } catch (e) {
      error = e;
    }
    check(typed(error), `write: ${why}: the same typed error`,
      error instanceof Error ? `${(error as { code?: string }).code ?? error.name}: ${error.message}` : String(error));
  }
});

// ---------------------------------------------------------------------------
// (e) v4 emission: the sink receives exactly L bytes, the plaintext, and
//     never the prefix or a padding byte.
//
// Control: a drain that hands on each chunk's whole window of the stream
// emits the 8-byte prefix and the padding, and every size here fails.
// ---------------------------------------------------------------------------
console.log("\n(e) v4: the sink receives stream bytes [8, 8 + L) only:");
await guarded("(e)", async () => {
  for (const cipher of [CipherId.AES_256_GCM, CipherId.CHAINED]) {
    for (const n of [0, 1, 200, 249, C - 8, C - 7, C + 5]) {
      const label = `v4 ${cipher === CipherId.CHAINED ? "chained" : "aes"} ${n} B`;
      const plaintext = pattern(n, n + 3);
      const container = await encryptKeym2WithExplicitSecrets(
        plaintext, PASSWORD, null, { kdf: FAST, cipher }, SALT, MASTER, KEYM2_VERSION_V4, CID);
      let lengthSeen = -1;
      const temporary: Uint8Array[] = [];
      let error: unknown = null;
      try {
        const stream = await openKeym2Stream(bytesSource(container), PASSWORD, null);
        lengthSeen = stream.plaintextLength;
        await stream.drain({ write: async (b) => void temporary.push(b) });
      } catch (e) {
        error = e;
      }
      const emitted = concatAll(temporary);
      check(error === null && lengthSeen === n, `${label}: plaintextLength is L`, error ? message(error) : `${lengthSeen}`);
      check(emitted.length === n && same(emitted, plaintext),
        `${label}: the sink received exactly L bytes, and they are the plaintext`, `${emitted.length} B emitted`);
    }
  }
});

// ---------------------------------------------------------------------------
// (f) discard erases the payload keys. A census of every Uint8Array the core
//     allocates during openKeym2Stream: before discard, a buffer holding the
//     ChaCha payload key (and chunk 0's plaintext) exists, which proves the
//     census can see it; after discard, none does. AES keys are
//     non-extractable CryptoKeys with no bytes to erase, so ChaCha and
//     chained are the ciphers this can check.
//
// Control: a discard that drops the key without erasing it leaves the key
// in the census.
// ---------------------------------------------------------------------------
console.log("\n(f) discard erases the payload keys:");
await guarded("(f)", async () => {
  const U8 = globalThis.Uint8Array;
  let census: Uint8Array[] | null = null;
  const Recording = new Proxy(U8, {
    construct(target, args, newTarget) {
      const view = Reflect.construct(target, args, newTarget === Recording ? target : newTarget) as Uint8Array;
      if (census) census.push(view);
      return view;
    },
  });
  const nativeSlice = U8.prototype.slice;
  const holders = (seen: Uint8Array[], needle: Uint8Array): number => {
    const want = Buffer.from(needle.buffer, needle.byteOffset, needle.byteLength);
    const visited = new Set<ArrayBufferLike>();
    let found = 0;
    for (const view of seen) {
      if (visited.has(view.buffer)) continue;
      visited.add(view.buffer);
      if (view.buffer.byteLength === 0) continue;
      if (Buffer.from(view.buffer as ArrayBuffer).indexOf(want) !== -1) found++;
    }
    return found;
  };

  /** §4.3, the chained ChaCha subkey: HKDF-SHA-256(master, 32 zero bytes, "keymaker-v2-chacha"). */
  const chainedChachaKey = async (master: Uint8Array): Promise<Uint8Array> => {
    const k = await crypto.subtle.importKey("raw", master as BufferSource, "HKDF", false, ["deriveBits"]);
    return new Uint8Array(await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: new TextEncoder().encode("keymaker-v2-chacha") },
      k, 256));
  };

  for (const cipher of [CipherId.CHACHA20_POLY1305, CipherId.CHAINED]) {
    const label = cipher === CipherId.CHAINED ? "chained" : "chacha";
    const plaintext = pattern(C + 40, 21);
    const container = await encryptKeym2WithExplicitSecrets(
      plaintext, PASSWORD, null, { kdf: FAST, cipher }, SALT, MASTER, KEYM2_VERSION_V3, CID);
    const payloadKey = cipher === CipherId.CHAINED ? await chainedChachaKey(MASTER) : MASTER;
    const chunk0Sample = plaintext.slice(1000, 1064);

    census = [];
    (globalThis as { Uint8Array: unknown }).Uint8Array = Recording;
    U8.prototype.slice = function (this: Uint8Array, ...args: [number?, number?]) {
      const view = nativeSlice.apply(this, args);
      if (census) census.push(view);
      return view;
    } as typeof U8.prototype.slice;
    let stream: Awaited<ReturnType<typeof openKeym2Stream>> | null = null;
    try {
      stream = await openKeym2Stream(bytesSource(container), PASSWORD, null);
    } catch (e) {
      check(false, `${label}: opens`, message(e));
    } finally {
      (globalThis as { Uint8Array: unknown }).Uint8Array = U8;
      U8.prototype.slice = nativeSlice;
    }
    const seen = census;
    census = null;
    if (stream === null) continue;
    check(holders(seen, payloadKey) > 0,
      `${label}: before discard the census sees the held payload key (the check below is not vacuous)`);
    check(holders(seen, chunk0Sample) > 0, `${label}: before discard the census sees chunk 0's held plaintext`);
    stream.discard();
    check(holders(seen, payloadKey) === 0, `${label}: after discard no buffer the core made holds the payload key`,
      `${holders(seen, payloadKey)} buffer(s)`);
    check(holders(seen, chunk0Sample) === 0, `${label}: after discard chunk 0's plaintext is erased`,
      `${holders(seen, chunk0Sample)} buffer(s)`);
    stream.discard();
    check(true, `${label}: discard is idempotent`);
    let refused = false;
    try {
      await stream.drain({ write: async () => {} });
    } catch {
      refused = true;
    }
    check(refused, `${label}: drain after discard is refused`);
  }

  // Single use.
  const container = await encryptKeym2WithExplicitSecrets(
    pattern(10), PASSWORD, null, { kdf: FAST, cipher: CipherId.AES_256_GCM }, SALT, MASTER, KEYM2_VERSION_V3, CID);
  const stream = await openKeym2Stream(bytesSource(container), PASSWORD, null);
  await stream.drain({ write: async () => {} });
  let again = false;
  try {
    await stream.drain({ write: async () => {} });
  } catch {
    again = true;
  }
  check(again, "drain is single use");
});

console.log(`\n${passed} passed, ${failures.length} failed`);
if (failures.length) {
  console.log("KEYM streaming core checks FAILED.");
  process.exit(1);
}
console.log("All KEYM streaming core checks passed.");
