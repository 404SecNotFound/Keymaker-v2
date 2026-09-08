#!/usr/bin/env node
/**
 * parseWavToPcm16 must refuse a malformed WAV as a typed AudioStegoError, never
 * a raw RangeError out of DataView.
 *
 * The chunk walk's loop guard only proves the 8-byte chunk header is present. A
 * WAV whose `fmt ` chunk is declared but truncated — the file ends partway
 * through the 16-byte fmt body — made `view.getUint16(body + 14)` read past the
 * buffer and throw a RangeError. That is not an AudioStegoError, so the UI's
 * `e instanceof AudioStegoError` branch fell through to a generic "could not be
 * read", and the module's whole contract ("every carrier problem is a named
 * AudioStegoError, so a bad audio file is never confused with a wrong password")
 * was broken by the one input a corrupt/attacker file most easily produces.
 *
 * This drives parseWavToPcm16 directly (esbuild bundles the TS the way the rest
 * of the project reaches its `.ts`). The control bites: with the fmt bounds
 * check removed, the truncated-fmt case throws a RangeError instead of an
 * AudioStegoError, and the type assertion below fails.
 */
import esbuild from "esbuild";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
const src = join(HERE, "..", "src", "lib", "audio-stego.ts");
const out = join(mkdtempSync(join(tmpdir(), "kaud-")), "audio-stego.mjs");
await esbuild.build({ entryPoints: [src], bundle: true, format: "esm", platform: "node", outfile: out });

const m = await import(pathToFileURL(out).href);
const { parseWavToPcm16, writePcm16Wav, AudioStegoError } = m;

let failed = 0;
const ok = (cond, msg) => {
  if (!cond) { console.error("FAIL:", msg); failed++; }
  else console.log("ok   ", msg);
};

/** Assert `fn` throws, and that the thrown value is an AudioStegoError — not a
 *  RangeError or any other internal exception. The type check is the bite. */
const rejectsAudioStego = (fn, msg) => {
  try {
    fn();
    ok(false, msg + " (did not throw)");
  } catch (e) {
    ok(e instanceof AudioStegoError, msg + (e instanceof AudioStegoError ? "" : ` (threw ${e?.constructor?.name}: ${e?.message})`));
  }
};

// --- Positive control: a valid 16-bit PCM WAV still parses to its samples, so
//     the new bounds check does not over-reject a real carrier. ---
const wav = writePcm16Wav({ sampleRate: 8000, channels: 1, samples: Int16Array.of(1, -2, 3, -4, 5) });
const round = parseWavToPcm16(wav);
ok(
  round.sampleRate === 8000 && round.channels === 1 &&
    round.samples.length === 5 && round.samples[0] === 1 && round.samples[4] === 5,
  "a valid 16-bit PCM WAV parses to its exact samples"
);

const ascii = (s) => Uint8Array.from(s, (c) => c.charCodeAt(0));
const u32le = (n) => Uint8Array.of(n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff);

/** Build a >=44-byte RIFF/WAVE buffer from raw chunk bytes placed after byte 12. */
function riff(chunkBytes) {
  const head = new Uint8Array(12);
  head.set(ascii("RIFF"), 0);
  head.set(u32le(4 + chunkBytes.length), 4);
  head.set(ascii("WAVE"), 8);
  const buf = new Uint8Array(head.length + chunkBytes.length);
  buf.set(head, 0);
  buf.set(chunkBytes, head.length);
  return buf;
}

// --- The finding: a fmt chunk declared 16 bytes but truncated so the file ends
//     inside its body. A JUNK chunk pads the file past the 44-byte floor so the
//     "not a WAV file" length check is cleared and the walk actually reaches the
//     truncated fmt header. body+16 lands past the buffer end. ---
{
  const junk = new Uint8Array(8 + 8); // "JUNK" header + 8 body bytes
  junk.set(ascii("JUNK"), 0);
  junk.set(u32le(8), 4);
  const fmtHeaderOnly = new Uint8Array(8 + 8); // "fmt " header declaring 16, but only 8 body bytes follow
  fmtHeaderOnly.set(ascii("fmt "), 0);
  fmtHeaderOnly.set(u32le(16), 4);
  const bytes = riff(new Uint8Array([...junk, ...fmtHeaderOnly]));
  ok(bytes.length >= 44, "truncated-fmt fixture clears the 44-byte WAV floor");
  rejectsAudioStego(() => parseWavToPcm16(bytes), "a truncated fmt chunk is an AudioStegoError, not a RangeError");
}

// --- A fmt chunk that declares fewer than 16 bytes is refused too, so the
//     fields are never read across into the following chunk. ---
{
  const fmtShort = new Uint8Array(8 + 24); // header declaring size 10, with body present
  fmtShort.set(ascii("fmt "), 0);
  fmtShort.set(u32le(10), 4);
  const bytes = riff(fmtShort);
  ok(bytes.length >= 44, "short-fmt fixture clears the 44-byte WAV floor");
  rejectsAudioStego(() => parseWavToPcm16(bytes), "a fmt chunk shorter than 16 bytes is an AudioStegoError");
}

console.log(failed === 0 ? "\nAll audio-wav-bounds checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
