#!/usr/bin/env node
/**
 * A WAV carrier at any common depth is read, at its own sample rate, and a
 * 16-bit carrier re-saved losslessly at a greater depth keeps its payload.
 *
 * parseWavToPcm16 used to refuse everything but 16-bit PCM ("Only 16-bit PCM
 * WAV is supported"), while docs/FORMAT-AUDIO-STEGO.md promised Hide any WAV.
 * A 24-bit or float recording, which is what most audio tools export, could not
 * be used as a carrier at all. Handing those to Web Audio instead is not a fix:
 * it resamples to the device rate, and the low bit the payload lives in does
 * not survive that.
 *
 * What is pinned:
 *   - 8, 24 and 32-bit integer PCM and 32/64-bit float are read and scaled to
 *     16 bits, plain and as WAVE_FORMAT_EXTENSIBLE, with the sample rate kept;
 *   - a 16-bit sample widened by a power of two comes back exactly, so a stego
 *     WAV re-saved at 24-bit or float still reveals its container;
 *   - an EXTENSIBLE header with a foreign SubFormat GUID, or one too short to
 *     hold it, is refused as a typed AudioStegoError.
 *
 * The control: restore the "Only 16-bit PCM" refusal and every conversion case
 * here fails with that message.
 */
import esbuild from "esbuild";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
const src = join(HERE, "..", "src", "lib", "audio-stego.ts");
const out = join(mkdtempSync(join(tmpdir(), "kaud-depth-")), "audio-stego.mjs");
await esbuild.build({ entryPoints: [src], bundle: true, format: "esm", platform: "node", outfile: out });

const { parseWavToPcm16, writePcm16Wav, embedContainer, extractContainer, AudioStegoError } =
  await import(pathToFileURL(out).href);

let failed = 0;
const ok = (cond, msg) => {
  if (!cond) { console.error("FAIL:", msg); failed++; }
  else console.log("ok   ", msg);
};
const parses = (bytes, msg) => {
  try {
    return parseWavToPcm16(bytes);
  } catch (e) {
    ok(false, `${msg} (threw ${e?.constructor?.name}: ${e?.message})`);
    return null;
  }
};
const rejectsAudioStego = (fn, msg) => {
  try {
    fn();
    ok(false, msg + " (did not throw)");
  } catch (e) {
    ok(e instanceof AudioStegoError, msg + (e instanceof AudioStegoError ? "" : ` (threw ${e?.constructor?.name})`));
  }
};

const ascii = (s) => Uint8Array.from(s, (c) => c.charCodeAt(0));
const u16 = (n) => Uint8Array.of(n & 0xff, (n >> 8) & 0xff);
const u32 = (n) => Uint8Array.of(n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff);
const cat = (...parts) => {
  const a = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { a.set(p, o); o += p.length; }
  return a;
};

const RATE = 44100;
/** KSDATAFORMAT_SUBTYPE_* for a given format code: the code, then a fixed suffix. */
const subFormat = (code, suffix = [0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71]) =>
  cat(u16(code), Uint8Array.from(suffix));

function wav({ format, bits, channels = 1, data, extensible = false, guid = null, fmtSize = null }) {
  const align = channels * (bits / 8);
  const base = cat(u16(extensible ? 0xfffe : format), u16(channels), u32(RATE), u32(RATE * align), u16(align), u16(bits));
  const ext = extensible ? cat(u16(22), u16(bits), u32(0), guid ?? subFormat(format)) : new Uint8Array(0);
  const body = cat(base, ext);
  const size = fmtSize ?? body.length;
  const fmt = cat(ascii("fmt "), u32(size), body.subarray(0, size));
  const dataChunk = cat(ascii("data"), u32(data.length), data, data.length & 1 ? new Uint8Array(1) : new Uint8Array(0));
  const all = cat(fmt, dataChunk);
  return cat(ascii("RIFF"), u32(4 + all.length), ascii("WAVE"), all);
}

/** Widen 16-bit samples to another encoding by a power of two, as a lossless re-save does. */
function widen(samples, kind) {
  const n = samples.length;
  if (kind === "pcm24") {
    const b = new Uint8Array(n * 3);
    for (let i = 0; i < n; i++) {
      const v = (samples[i] * 256) & 0xffffff;
      b[i * 3] = v & 0xff; b[i * 3 + 1] = (v >> 8) & 0xff; b[i * 3 + 2] = (v >> 16) & 0xff;
    }
    return b;
  }
  const b = new Uint8Array(n * (kind === "float64" ? 8 : 4));
  const v = new DataView(b.buffer);
  for (let i = 0; i < n; i++) {
    if (kind === "pcm32") v.setInt32(i * 4, samples[i] * 65536, true);
    else if (kind === "float32") v.setFloat32(i * 4, samples[i] / 32768, true);
    else v.setFloat64(i * 8, samples[i] / 32768, true);
  }
  return b;
}

const S = Int16Array.of(0, 1, -1, 2, -2, 32767, -32768, 12345, -12345, 257, -257, 16385);
const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

// --- Each depth, plain and extensible ---
const CASES = [
  ["24-bit PCM", 1, 24, "pcm24"],
  ["32-bit PCM", 1, 32, "pcm32"],
  ["32-bit float", 3, 32, "float32"],
  ["64-bit float", 3, 64, "float64"],
];
for (const [name, format, bits, kind] of CASES) {
  for (const extensible of [false, true]) {
    const label = `${name}${extensible ? " (WAVE_FORMAT_EXTENSIBLE)" : ""}`;
    const got = parses(wav({ format, bits, data: widen(S, kind), extensible }), `${label} is read`);
    if (!got) continue;
    ok(got.sampleRate === RATE, `${label} keeps its sample rate (got ${got.sampleRate})`);
    ok(same(got.samples, S), `${label} widened from 16-bit comes back to the same samples`);
  }
}

// 8-bit is unsigned and narrower, so only its scaling is checked.
{
  const got = parses(wav({ format: 1, bits: 8, data: Uint8Array.of(0, 128, 255, 129) }), "8-bit PCM is read");
  if (got) ok(same(got.samples, Int16Array.of(-32768, 0, 32512, 256)), "8-bit PCM is centred on 128 and scaled by 256");
}

// Stereo keeps its interleave.
{
  const got = parses(wav({ format: 1, bits: 24, channels: 2, data: widen(S, "pcm24") }), "stereo 24-bit PCM is read");
  if (got) ok(got.channels === 2 && same(got.samples, S), "stereo 24-bit PCM keeps its channels and order");
}

// Out-of-range float clamps rather than wrapping.
{
  const b = new Uint8Array(8);
  const v = new DataView(b.buffer);
  v.setFloat32(0, 1.0, true);
  v.setFloat32(4, -1.5, true);
  const got = parses(wav({ format: 3, bits: 32, data: b }), "full-scale float is read");
  if (got) ok(same(got.samples, Int16Array.of(32767, -32768)), "full-scale float clamps to the 16-bit range");
}

// --- A payload survives a lossless re-save at a greater depth ---
{
  const carrier = new Int16Array(6000);
  let seed = 7;
  for (let i = 0; i < carrier.length; i++) { seed = (seed * 1103515245 + 12345) >>> 0; carrier[i] = (seed >>> 16) - 32768; }
  const container = Uint8Array.from({ length: 64 }, (_, i) => (i * 37 + 11) & 0xff);
  const stego = embedContainer({ sampleRate: RATE, channels: 1, samples: carrier }, container);
  ok(same(extractContainer(parseWavToPcm16(writePcm16Wav(stego))), container), "the 16-bit stego WAV reveals its container");
  for (const [kind, format, bits] of [["pcm24", 1, 24], ["float32", 3, 32]]) {
    const got = parses(wav({ format, bits, data: widen(stego.samples, kind) }), `the stego WAV re-saved as ${kind} is read`);
    if (!got) continue;
    let revealed = null;
    try { revealed = extractContainer(got); } catch { revealed = null; }
    ok(revealed !== null && same(revealed, container), `the stego WAV re-saved as ${kind} still reveals its container`);
  }
}

// --- Refusals ---
rejectsAudioStego(
  () => parseWavToPcm16(wav({ format: 1, bits: 24, data: widen(S, "pcm24"), extensible: true,
    guid: subFormat(1, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]) })),
  "an EXTENSIBLE WAV whose SubFormat is not a KSDATAFORMAT GUID is refused"
);
rejectsAudioStego(
  () => parseWavToPcm16(wav({ format: 1, bits: 24, data: widen(S, "pcm24"), extensible: true, fmtSize: 16 })),
  "an EXTENSIBLE fmt chunk too short to hold its SubFormat is refused"
);
rejectsAudioStego(
  () => parseWavToPcm16(wav({ format: 7, bits: 24, data: widen(S, "pcm24"), extensible: true })),
  "an EXTENSIBLE WAV whose SubFormat is mu-law is refused"
);

if (failed) {
  console.error(`\n${failed} check(s) failed.`);
  process.exit(1);
}
console.log("\nEvery WAV depth is read at its own rate, and a widened stego WAV keeps its payload.");
