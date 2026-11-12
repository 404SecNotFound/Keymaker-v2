/**
 * What a verify sends back across the worker boundary (roadmap 9.2).
 *
 * Verify-only and the rehearsal prove a backup opens without showing it. They
 * used to take the ordinary decrypt response, which carries the plaintext, and
 * zero it on arrival — so a whole copy of the secret crossed into the page's
 * heap for an operation that never needed it. The worker's `verify` op keeps
 * the plaintext on its own side and answers with the length and what the
 * reader established.
 *
 * This loads the shipping worker as-is with a stand-in `self`, sends it real
 * containers from every format it reads, and inspects every message it posts:
 *
 *  1. Each field of a success is on an allow-list, and nothing in it is a
 *     buffer, a typed array, a Blob, an object URL, or a string holding the
 *     plaintext. Nothing is in the transfer list.
 *  2. The fields are right: the byte count is the plaintext's, the format and
 *     the slot table verdict match the corpus, and `openedBy` names the kind
 *     of slot the credentials were for.
 *  3. Failures (a wrong password, wrong strips, a truncated file, noise) cross
 *     as an error that holds none of the credentials or the plaintext.
 *  4. The same scanner run over the ordinary decrypt response *does* find the
 *     plaintext. That is the check that the scanner can see a leak at all: a
 *     scanner that found nothing anywhere would pass (1) against any worker.
 *
 *  5. The same containers as Blobs through `open-stream` with `purpose:
 *     "verify"` cross with the same allow-listed fields plus the container's
 *     digest, in one message: no `chunk` message, no buffer. KEYM v1 and the
 *     IttyBitz formats are refused by type. The failures in (3) fail the same
 *     way.
 *
 *  6. Phase 1 of a streamed decrypt (`open-stream` with `purpose: "decrypt"`)
 *     crosses with one `opened` answer on the same allow-list, no digest,
 *     and nothing else; the failures in (3) never get one; KEYM v1 and
 *     IttyBitz v1 are refused by name. The drain, where the plaintext is
 *     meant to cross, is scanned too, and the scanner must find it there.
 *
 * The negative control is to make `verify` answer with the decrypt response;
 * (1) must fail. The PR records the run. For (5) it is to have `open-stream`
 * post its chunks whatever the purpose. For (6), post chunk 0 with `opened`.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { extractContainer, parseWavToPcm16 } from "../src/lib/audio-stego.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const CORPUS = join(HERE, "fixtures", "keymaker");
const META = JSON.parse(readFileSync(join(CORPUS, "fixtures.json"), "utf8"));
const LEGACY = JSON.parse(readFileSync(join(HERE, "crypto-fixtures.json"), "utf8"));

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

// ---------------------------------------------------------------------------
// The shipping worker, loaded as-is with a stand-in `self`.
// ---------------------------------------------------------------------------
let handler: ((e: { data: unknown }) => Promise<void>) | null = null;
const posted: { message: any; transfer: unknown[] }[] = [];
(globalThis as any).self = {
  addEventListener: (_type: string, h: any) => {
    handler = h;
  },
  postMessage: (message: any, transfer?: unknown[]) => {
    posted.push({ message, transfer: transfer ?? [] });
  },
};
await import("../src/lib/crypto-worker.ts");

let nextId = 0;
/** Send one request and return everything the worker posted for it. */
async function send(req: Record<string, unknown>): Promise<{ message: any; transfer: unknown[] }[]> {
  posted.length = 0;
  await handler!({ data: { id: ++nextId, ...req } });
  return posted.splice(0);
}

// ---------------------------------------------------------------------------
// The scanner.
// ---------------------------------------------------------------------------
// `digest` is the SHA-256 of the container, not of the plaintext: null for an
// in-memory verify, and hex of ciphertext for a streamed one.
const VERIFY_FIELDS = new Set([
  "id", "ok", "op", "format", "bytes", "openedBy", "keyFileUsed", "slotTable", "weakKdf", "digest",
]);
const ERROR_FIELDS = new Set(["id", "ok", "code", "message"]);

/**
 * Every way a secret could be in `value`, by path. `secrets` are strings that
 * must not appear anywhere in any string: the plaintext, and on a failure the
 * credentials too.
 */
function leaks(value: unknown, secrets: string[], path = "response"): string[] {
  const found: string[] = [];
  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
    found.push(`${path} is a buffer (${(value as ArrayBuffer).byteLength} bytes)`);
  } else if (typeof Blob !== "undefined" && value instanceof Blob) {
    found.push(`${path} is a Blob`);
  } else if (typeof value === "string") {
    if (value.startsWith("blob:")) found.push(`${path} is an object URL`);
    for (const s of secrets) {
      if (s && value.includes(s)) found.push(`${path} contains ${JSON.stringify(s.slice(0, 24))}…`);
    }
  } else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) found.push(...leaks(v, secrets, `${path}.${k}`));
  }
  return found;
}

const enc = new TextEncoder();
const hex = (h: string) => Uint8Array.from(h.match(/../g)!.map((b) => parseInt(b, 16)));
const b64 = (s: string) => Uint8Array.from(Buffer.from(s, "base64"));
/** A fresh, owned ArrayBuffer — the worker takes whatever it is handed. */
const owned = (u: Uint8Array) => u.slice().buffer as ArrayBuffer;

interface Case {
  label: string;
  container: Uint8Array;
  plaintext: string;
  password: string;
  keyFile: Uint8Array | null;
  shares?: string[];
  prfOutput?: Uint8Array;
  format: string;
  openedBy: string;
  slotTable: string;
}

const cases: Case[] = [];
const PASSWORD: string = META.password;
const KEY_FILE = hex(META.keyFileHex);

for (const fx of META.fixtures) {
  if (fx.selfextract) continue; // an HTML page, not a container; its decryptor is tested in the browser
  // A carrier WAV holds an ordinary container; unwrap it with the app's reader
  // and it takes the same verify-only path as every other vector.
  const container = fx.audio
    ? extractContainer(parseWavToPcm16(new Uint8Array(readFileSync(join(CORPUS, fx.file)))))
    : new Uint8Array(readFileSync(join(CORPUS, fx.file)));
  const version = fx.version ?? 1;
  const format = `keym-v${version}`;
  const slotTable =
    fx.slotTableAuthentic === undefined ? "not_available" : fx.slotTableAuthentic ? "authentic" : "changed";
  const base = { container, plaintext: fx.plaintext, format, slotTable };
  if (fx.shamir) {
    cases.push({
      ...base,
      label: `${fx.name} with its strips`,
      password: "",
      keyFile: null,
      shares: fx.shamir.shares.slice(0, fx.shamir.threshold),
      openedBy: "shares",
    });
  }
  if (fx.passkey) {
    cases.push({
      ...base,
      label: `${fx.name} with its passkey`,
      password: "",
      keyFile: null,
      prfOutput: hex(fx.passkey.prfOutputHex),
      openedBy: "passkey",
    });
  }
  if (fx.both) {
    cases.push({
      ...base,
      label: `${fx.name} with the password and its strips`,
      password: PASSWORD,
      keyFile: null,
      shares: fx.both.shares.slice(0, fx.both.threshold),
      openedBy: "passphrase-and-shares",
    });
  } else {
    cases.push({
      ...base,
      label: `${fx.name} with the password`,
      password: PASSWORD,
      keyFile: fx.keyFile ? KEY_FILE : null,
      openedBy: "passphrase",
    });
  }
}
for (const fx of LEGACY.fixtures) {
  cases.push({
    label: `IttyBitz ${fx.version} [${fx.format}] ${fx.payload}${fx.keyFile ? " +keyfile" : ""}`,
    container: b64(fx.base64),
    plaintext: fx.plaintext,
    password: LEGACY.password,
    keyFile: fx.keyFile ? hex(LEGACY.keyFileHex) : null,
    format: fx.format === "v1" ? "ibtz-v1" : "ibtz-v0",
    openedBy: "passphrase",
    slotTable: "not_available",
  });
}

function request(op: "verify" | "decrypt", c: Case, override: Partial<Case> = {}) {
  const x = { ...c, ...override };
  return {
    op,
    data: owned(x.container),
    password: x.password,
    keyFile: x.keyFile ? owned(x.keyFile) : null,
    shares: x.shares,
    prfOutput: x.prfOutput ? x.prfOutput.slice() : undefined,
  };
}

// ---------------------------------------------------------------------------
// 1 and 2. Every container the reader opens: what the verify sends back.
// ---------------------------------------------------------------------------
console.log(`\nVerify, success (${cases.length} containers):`);
for (const c of cases) {
  const out = await send(request("verify", c));
  const msg = out[0]?.message;
  const found = out.flatMap((o, i) => leaks(o.message, [c.plaintext], `message[${i}]`));
  const transferred = out.flatMap((o) => o.transfer);
  const extra = msg ? Object.keys(msg).filter((k) => !VERIFY_FIELDS.has(k)) : [];
  check(
    `${c.label}: nothing but the allowed fields crosses, and none holds the plaintext`,
    out.length === 1 && msg?.ok === true && found.length === 0 && transferred.length === 0 && extra.length === 0,
    [
      out.length !== 1 ? `${out.length} messages` : "",
      msg?.ok !== true ? `ok=${msg?.ok} ${msg?.message ?? ""}` : "",
      ...found,
      transferred.length ? `${transferred.length} transferred` : "",
      extra.length ? `unexpected fields ${extra.join(", ")}` : "",
    ].filter(Boolean).join("; ")
  );
  const bytes = enc.encode(c.plaintext).byteLength;
  check(
    `${c.label}: reports ${bytes} bytes, ${c.format}, opened by ${c.openedBy}, slot table ${c.slotTable}`,
    msg?.op === "verify" &&
      msg.bytes === bytes &&
      msg.format === c.format &&
      msg.openedBy === c.openedBy &&
      msg.slotTable === c.slotTable,
    msg ? `got ${msg.bytes} bytes, ${msg.format}, ${msg.openedBy}, ${msg.slotTable}` : "no message"
  );
}

// ---------------------------------------------------------------------------
// 3. Failures cross as an error holding no secret.
// ---------------------------------------------------------------------------
console.log("\nVerify, failure:");
const v3 = cases.find((c) => c.label.startsWith("v3-pbkdf2-aes256gcm with the password"))!;
const shamir = cases.find((c) => c.label.startsWith("v3-shamir-aes256gcm"))!;
const passkey = cases.find((c) => c.label.startsWith("v3-passkey-aes256gcm"))!;
const legacy = cases.find((c) => c.format === "ibtz-v1")!;
const wrongStrip = (s: string) => s.slice(0, -3) + (s.at(-3) === "A" ? "B" : "A") + s.slice(-2);

const failures: { label: string; make: () => ReturnType<typeof request>; secrets: string[] }[] = [
  {
    label: "a wrong password",
    make: () => request("verify", v3, { password: `${PASSWORD} but wrong` }),
    secrets: [v3.plaintext, `${PASSWORD} but wrong`, PASSWORD],
  },
  {
    label: "a wrong strip among the right ones",
    make: () => request("verify", shamir, { shares: [wrongStrip(shamir.shares![0]!), ...shamir.shares!.slice(1)] }),
    secrets: [shamir.plaintext, ...shamir.shares!],
  },
  {
    label: "fewer strips than the threshold",
    make: () => request("verify", shamir, { shares: shamir.shares!.slice(0, 1) }),
    secrets: [shamir.plaintext, ...shamir.shares!],
  },
  {
    label: "the wrong passkey",
    make: () => request("verify", passkey, { prfOutput: new Uint8Array(32).fill(0x5a) }),
    secrets: [passkey.plaintext],
  },
  {
    label: "a container cut off mid-payload",
    make: () => request("verify", v3, { container: v3.container.slice(0, v3.container.length - 20) }),
    secrets: [v3.plaintext, PASSWORD],
  },
  {
    label: "a container cut off inside its header",
    make: () => request("verify", v3, { container: v3.container.slice(0, 12) }),
    secrets: [v3.plaintext, PASSWORD],
  },
  {
    label: "one flipped payload byte",
    make: () => request("verify", v3, {
      container: (() => {
        const t = v3.container.slice();
        t[t.length - 1]! ^= 0x01;
        return t;
      })(),
    }),
    secrets: [v3.plaintext, PASSWORD],
  },
  {
    label: "random bytes",
    make: () => request("verify", v3, { container: new Uint8Array(200).fill(0x61) }),
    secrets: [v3.plaintext, PASSWORD],
  },
  {
    label: "a wrong password on a legacy IttyBitz file",
    make: () => request("verify", legacy, { password: "not the IttyBitz password" }),
    secrets: [legacy.plaintext, "not the IttyBitz password", LEGACY.password],
  },
];
for (const f of failures) {
  const out = await send(f.make());
  const msg = out[0]?.message;
  const found = out.flatMap((o, i) => leaks(o.message, f.secrets, `message[${i}]`));
  const extra = msg ? Object.keys(msg).filter((k) => !ERROR_FIELDS.has(k)) : [];
  check(
    `${f.label}: an error, and nothing secret in it`,
    out.length === 1 && msg?.ok === false && found.length === 0 && extra.length === 0 &&
      out[0]!.transfer.length === 0,
    [msg?.ok !== false ? `ok=${msg?.ok}` : "", ...found, extra.length ? `fields ${extra.join(", ")}` : ""]
      .filter(Boolean).join("; ")
  );
}

// ---------------------------------------------------------------------------
// 5. The streamed verify: the same containers as Blobs, through `open-stream`.
// ---------------------------------------------------------------------------
//
// `open-stream` with `purpose: "verify"` reads the container a chunk at a time
// in the worker and must cross with exactly what the in-memory verify crosses
// with, plus the container's digest: one message, on the same allow-list,
// holding no buffer and nothing transferred — in particular no `chunk`
// message, which is how a streamed decrypt would hand over plaintext. KEYM v1
// and the IttyBitz formats cannot be read a chunk at a time and are refused
// by type, with nothing secret in the refusal.
//
// The negative control is to have `open-stream` post its chunks whatever the
// purpose; the first check below must fail.
const STREAMABLE = new Set(["keym-v2", "keym-v3", "keym-v4"]);
const sha256Hex = (u: Uint8Array) => createHash("sha256").update(u).digest("hex");

function streamRequest(c: Case, override: Partial<Case> = {}) {
  const x = { ...c, ...override };
  return {
    op: "open-stream",
    file: new Blob([x.container as Uint8Array<ArrayBuffer>]),
    password: x.password,
    keyFile: x.keyFile ? owned(x.keyFile) : null,
    shares: x.shares,
    prfOutput: x.prfOutput ? x.prfOutput.slice() : undefined,
    purpose: "verify",
    digest: true,
  };
}

/** `send`, bounded: a worker that waits for an ack nobody sends must fail here, not hang. */
async function sendBounded(req: Record<string, unknown>, ms = 30_000) {
  posted.length = 0;
  const finished = await Promise.race([
    handler!({ data: { id: ++nextId, ...req } }).then(() => true),
    new Promise<boolean>((r) => setTimeout(() => r(false), ms)),
  ]);
  return { finished, out: posted.splice(0) };
}

console.log(`\nStreamed verify (${cases.length} containers as Blobs):`);
for (const c of cases) {
  const { finished, out } = await sendBounded(streamRequest(c));
  const msg = out.at(-1)?.message;
  const found = out.flatMap((o, i) => leaks(o.message, [c.plaintext], `message[${i}]`));
  const transferred = out.flatMap((o) => o.transfer);
  const chunkMessages = out.filter((o) => o.message?.op === "chunk").length;
  if (!STREAMABLE.has(c.format)) {
    const extra = msg ? Object.keys(msg).filter((k) => !ERROR_FIELDS.has(k)) : [];
    check(
      `${c.label}: refused by type as not streamable, and nothing secret crosses`,
      finished && out.length === 1 && msg?.ok === false && msg.code === "unsupported-config" &&
        found.length === 0 && transferred.length === 0 && extra.length === 0,
      [
        !finished ? "the worker did not finish" : "",
        out.length !== 1 ? `${out.length} messages` : "",
        `${msg?.ok} ${msg?.code} ${String(msg?.message ?? "").slice(0, 60)}`,
        ...found,
      ].filter(Boolean).join("; ")
    );
    continue;
  }
  const extra = msg ? Object.keys(msg).filter((k) => !VERIFY_FIELDS.has(k)) : [];
  check(
    `${c.label}: one message, on the allow-list, no chunk, no buffer, nothing transferred`,
    finished && out.length === 1 && chunkMessages === 0 && msg?.ok === true && found.length === 0 &&
      transferred.length === 0 && extra.length === 0,
    [
      !finished ? "the worker did not finish" : "",
      out.length !== 1 ? `${out.length} messages` : "",
      chunkMessages ? `${chunkMessages} chunk messages` : "",
      msg?.ok !== true ? `ok=${msg?.ok} ${msg?.message ?? ""}` : "",
      ...found,
      transferred.length ? `${transferred.length} transferred` : "",
      extra.length ? `unexpected fields ${extra.join(", ")}` : "",
    ].filter(Boolean).join("; ")
  );
  const bytes = enc.encode(c.plaintext).byteLength;
  check(
    `${c.label}: reports what the in-memory verify reports, and the container's digest`,
    msg?.op === "verify" &&
      msg.bytes === bytes &&
      msg.format === c.format &&
      msg.openedBy === c.openedBy &&
      msg.slotTable === c.slotTable &&
      msg.digest === sha256Hex(c.container),
    msg ? `got ${msg.bytes} bytes, ${msg.format}, ${msg.openedBy}, ${msg.slotTable}, ${msg.digest}` : "no message"
  );
}

console.log("\nStreamed verify, failure:");
for (const f of failures) {
  // The same failures, built afresh (the worker zeroes the key file and PRF
  // output it was handed) and re-sent with the container as a Blob.
  const r = f.make();
  const { finished, out } = await sendBounded({
    op: "open-stream",
    file: new Blob([r.data]),
    password: r.password,
    keyFile: r.keyFile,
    shares: r.shares,
    prfOutput: r.prfOutput,
    purpose: "verify",
    digest: true,
  });
  const msg = out[0]?.message;
  const found = out.flatMap((o, i) => leaks(o.message, f.secrets, `message[${i}]`));
  const extra = msg ? Object.keys(msg).filter((k) => !ERROR_FIELDS.has(k)) : [];
  check(
    `${f.label}: an error, and nothing secret in it`,
    finished && out.length === 1 && msg?.ok === false && found.length === 0 && extra.length === 0 &&
      out[0]!.transfer.length === 0,
    [msg?.ok !== false ? `ok=${msg?.ok}` : "", `${out.length} messages`, ...found].filter(Boolean).join("; ")
  );
}

// ---------------------------------------------------------------------------
// 6. Phase 1 of a streamed decrypt: `open-stream` with `purpose: "decrypt"`.
// ---------------------------------------------------------------------------
//
// The open keeps the container in the worker for a later `drain`, and its
// answer must cross with no more than a verify's: the same allow-list minus
// the digest, one message, no buffer, nothing transferred, no chunk. The
// plaintext crosses only in the drain, which the scanner is shown to see.
// Every open is followed by a `close-stream`, which must be answered and
// carry nothing either.
//
// The negative control is to post chunk 0 with the `opened` answer; the
// first check below must fail.
const OPENED_FIELDS = new Set(["id", "ok", "op", "format", "bytes", "openedBy", "keyFileUsed", "slotTable", "weakKdf"]);

console.log(`\nStreamed decrypt, phase 1 (${cases.length} containers as Blobs):`);
for (const c of cases) {
  const { finished, out } = await sendBounded({ ...streamRequest(c), purpose: "decrypt", digest: false });
  const msg = out.at(-1)?.message;
  const found = out.flatMap((o, i) => leaks(o.message, [c.plaintext], `message[${i}]`));
  const transferred = out.flatMap((o) => o.transfer);
  if (!STREAMABLE.has(c.format)) {
    const name = c.format === "keym-v1" ? /KEYM v1 backup/ : c.format === "ibtz-v1" ? /IttyBitz v1 backup/ : /not a KEYM v2, v3 or v4 backup/;
    check(
      `${c.label}: refused by type and by name, and nothing secret crosses`,
      finished && out.length === 1 && msg?.ok === false && msg.code === "unsupported-config" && name.test(msg.message) &&
        found.length === 0 && transferred.length === 0,
      [!finished ? "the worker did not finish" : "", `${msg?.ok} ${msg?.code} ${String(msg?.message ?? "").slice(0, 60)}`, ...found]
        .filter(Boolean).join("; ")
    );
    continue;
  }
  const extra = msg ? Object.keys(msg).filter((k) => !OPENED_FIELDS.has(k)) : [];
  check(
    `${c.label}: one opened answer, on the allow-list, no chunk, no buffer, nothing transferred`,
    finished && out.length === 1 && msg?.ok === true && msg.op === "opened" && found.length === 0 &&
      transferred.length === 0 && extra.length === 0,
    [
      !finished ? "the worker did not finish" : "",
      out.length !== 1 ? `${out.length} messages (${out.map((o) => o.message?.op).join(",")})` : "",
      msg?.ok !== true ? `ok=${msg?.ok} ${msg?.message ?? ""}` : "",
      ...found,
      transferred.length ? `${transferred.length} transferred` : "",
      extra.length ? `unexpected fields ${extra.join(", ")}` : "",
    ].filter(Boolean).join("; ")
  );
  check(
    `${c.label}: reports what the verify reports`,
    msg?.bytes === enc.encode(c.plaintext).byteLength && msg?.format === c.format &&
      msg?.openedBy === c.openedBy && msg?.slotTable === c.slotTable,
    msg ? `got ${msg.bytes} bytes, ${msg.format}, ${msg.openedBy}, ${msg.slotTable}` : "no message"
  );
  const closed = await sendBounded({ op: "close-stream" });
  check(
    `${c.label}: close-stream is answered with nothing in it`,
    closed.finished && closed.out.length === 1 && closed.out[0]!.message?.ok === true &&
      leaks(closed.out[0]!.message, [c.plaintext]).length === 0 && closed.out[0]!.transfer.length === 0,
    JSON.stringify(closed.out.map((o) => o.message))
  );
}

console.log("\nStreamed decrypt, phase 1, failure:");
for (const f of failures) {
  const r = f.make();
  const { finished, out } = await sendBounded({
    op: "open-stream",
    file: new Blob([r.data]),
    password: r.password,
    keyFile: r.keyFile,
    shares: r.shares,
    prfOutput: r.prfOutput,
    purpose: "decrypt",
    digest: false,
  });
  const msg = out[0]?.message;
  const found = out.flatMap((o, i) => leaks(o.message, f.secrets, `message[${i}]`));
  const extra = msg ? Object.keys(msg).filter((k) => !ERROR_FIELDS.has(k)) : [];
  check(
    `${f.label}: an error, no opened answer, and nothing secret in it`,
    finished && out.length === 1 && msg?.ok === false && found.length === 0 && extra.length === 0 &&
      out[0]!.transfer.length === 0,
    [msg?.ok !== false ? `ok=${msg?.ok} op=${msg?.op}` : "", `${out.length} messages`, ...found].filter(Boolean).join("; ")
  );
}

console.log("\nThe scanner, against the drain:");
{
  // The drain is where the plaintext is meant to cross, a chunk at a time.
  // The scanner must see it there, or the checks above prove nothing.
  await sendBounded({ ...streamRequest(v3), purpose: "decrypt", digest: false });
  posted.length = 0;
  const id = ++nextId;
  const done = handler!({ data: { id, op: "drain" } });
  // Acknowledge each chunk as it is posted, as the page does once written.
  for (let seen = 0; ; ) {
    const chunks = posted.filter((p) => p.message?.op === "chunk");
    for (; seen < chunks.length; seen++) {
      await handler!({ data: { id: ++nextId, op: "ack", stream: id, seq: chunks[seen]!.message.seq } });
    }
    if (posted.some((p) => p.message?.id === id && p.message?.op !== "chunk")) break;
    await new Promise((r) => setTimeout(r, 10));
  }
  await done;
  const out = posted.splice(0);
  const chunkFound = out.filter((o) => o.message?.op === "chunk").flatMap((o) =>
    o.message.data instanceof ArrayBuffer && new TextDecoder().decode(o.message.data).includes(v3.plaintext) ? ["chunk"] : []);
  const final = out.find((o) => o.message?.id === id && o.message?.op === "drain")?.message;
  check(
    `${v3.label}: the drain's chunk carries the plaintext, and the scanner reports it`,
    chunkFound.length === 1 && out.some((o) => leaks(o.message, [v3.plaintext]).length > 0),
    `${chunkFound.length} chunk(s) with the plaintext`
  );
  check(
    `${v3.label}: the drain's final answer is on its own allow-list and holds no buffer`,
    final?.ok === true && Object.keys(final).every((k) => ["id", "ok", "op", "bytes"].includes(k)) &&
      leaks(final, [v3.plaintext]).length === 0,
    JSON.stringify(final)
  );
}

// ---------------------------------------------------------------------------
// 4. The scanner sees a leak when there is one.
// ---------------------------------------------------------------------------
console.log("\nThe scanner, against the ordinary decrypt:");
for (const c of [v3, shamir, legacy]) {
  const out = await send(request("decrypt", c));
  const found = out.flatMap((o) => leaks(o.message, [c.plaintext]));
  check(
    `${c.label}: the decrypt response is reported as carrying the plaintext`,
    out[0]?.message?.ok === true && found.length > 0,
    `found ${found.length}`
  );
  // A decrypt's buffer is the plaintext; decode it so a mismatch is visible.
  const data = out[0]?.message?.data;
  check(
    `${c.label}: and that buffer is the plaintext, so decrypt is unchanged`,
    data instanceof ArrayBuffer && new TextDecoder().decode(data) === c.plaintext
  );
}

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
