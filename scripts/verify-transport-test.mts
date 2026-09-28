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
 * The negative control is to make `verify` answer with the decrypt response;
 * (1) must fail. The PR records the run.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

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
const VERIFY_FIELDS = new Set([
  "id", "ok", "op", "format", "bytes", "openedBy", "keyFileUsed", "slotTable", "weakKdf",
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
  const container = new Uint8Array(readFileSync(join(CORPUS, fx.file)));
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

const failures: { label: string; req: ReturnType<typeof request>; secrets: string[] }[] = [
  {
    label: "a wrong password",
    req: request("verify", v3, { password: `${PASSWORD} but wrong` }),
    secrets: [v3.plaintext, `${PASSWORD} but wrong`, PASSWORD],
  },
  {
    label: "a wrong strip among the right ones",
    req: request("verify", shamir, { shares: [wrongStrip(shamir.shares![0]!), ...shamir.shares!.slice(1)] }),
    secrets: [shamir.plaintext, ...shamir.shares!],
  },
  {
    label: "fewer strips than the threshold",
    req: request("verify", shamir, { shares: shamir.shares!.slice(0, 1) }),
    secrets: [shamir.plaintext, ...shamir.shares!],
  },
  {
    label: "the wrong passkey",
    req: request("verify", passkey, { prfOutput: new Uint8Array(32).fill(0x5a) }),
    secrets: [passkey.plaintext],
  },
  {
    label: "a container cut off mid-payload",
    req: request("verify", v3, { container: v3.container.slice(0, v3.container.length - 20) }),
    secrets: [v3.plaintext, PASSWORD],
  },
  {
    label: "a container cut off inside its header",
    req: request("verify", v3, { container: v3.container.slice(0, 12) }),
    secrets: [v3.plaintext, PASSWORD],
  },
  {
    label: "one flipped payload byte",
    req: request("verify", v3, {
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
    req: request("verify", v3, { container: new Uint8Array(200).fill(0x61) }),
    secrets: [v3.plaintext, PASSWORD],
  },
  {
    label: "a wrong password on a legacy IttyBitz file",
    req: request("verify", legacy, { password: "not the IttyBitz password" }),
    secrets: [legacy.plaintext, "not the IttyBitz password", LEGACY.password],
  },
];
for (const f of failures) {
  const out = await send(f.req);
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
