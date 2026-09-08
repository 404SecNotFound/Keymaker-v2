#!/usr/bin/env node
/**
 * Every malformed audio carrier is refused as a typed AudioStegoError, on both
 * the WAV parse and the KAUD extract path.
 *
 * The module's contract is that a carrier problem is always an AudioStegoError,
 * so the UI can tell a bad audio file from a wrong password and a carrier fault
 * is never routed to the AEAD (where "decryption failed" would send someone to
 * retype a password that was never wrong). scripts/audio-wav-bounds-test.mjs
 * pins the fmt-bounds case; this pins the rest of the surface:
 *   - parseWavToPcm16: not RIFF/WAVE, no data chunk, non-PCM format, non-16-bit,
 *     zero channels;
 *   - extractContainer: no KAUD marker, an unreadable version or bit depth, an
 *     empty declared payload, and a payload length that runs past the carrier.
 *
 * esbuild bundles the TS the way the rest of the project reaches its `.ts`.
 * Controls shown to bite (see the two reverts documented inline): removing the
 * payload-length bound makes the over-long-payload case return garbage instead
 * of throwing, and removing the format/bit-depth check makes a 24-bit file be
 * misread rather than refused.
 */
import esbuild from "esbuild";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
const src = join(HERE, "..", "src", "lib", "audio-stego.ts");
const out = join(mkdtempSync(join(tmpdir(), "kaud-mal-")), "audio-stego.mjs");
await esbuild.build({ entryPoints: [src], bundle: true, format: "esm", platform: "node", outfile: out });

const m = await import(pathToFileURL(out).href);
const { parseWavToPcm16, writePcm16Wav, embedContainer, extractContainer, AudioStegoError } = m;

let failed = 0;
const ok = (cond, msg) => {
  if (!cond) { console.error("FAIL:", msg); failed++; }
  else console.log("ok   ", msg);
};
const rejectsAudioStego = (fn, msg) => {
  try {
    fn();
    ok(false, msg + " (did not throw)");
  } catch (e) {
    ok(e instanceof AudioStegoError, msg + (e instanceof AudioStegoError ? "" : ` (threw ${e?.constructor?.name}: ${e?.message})`));
  }
};

const ascii = (s) => Uint8Array.from(s, (c) => c.charCodeAt(0));
const u16 = (n) => Uint8Array.of(n & 0xff, (n >> 8) & 0xff);
const u32 = (n) => Uint8Array.of(n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff);
const cat = (...parts) => { const a = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0; for (const p of parts) { a.set(p, o); o += p.length; } return a; };

/** A 16-byte PCM fmt chunk body with the fields parseWavToPcm16 reads. */
function fmtChunk({ format = 1, channels = 1, sampleRate = 8000, bits = 16 }) {
  const body = cat(u16(format), u16(channels), u32(sampleRate), u32(sampleRate * channels * 2), u16(channels * 2), u16(bits));
  return cat(ascii("fmt "), u32(16), body);
}
function dataChunk(nBytes = 8) {
  return cat(ascii("data"), u32(nBytes), new Uint8Array(nBytes));
}
function riff(...chunks) {
  const body = cat(...chunks);
  return cat(ascii("RIFF"), u32(4 + body.length), ascii("WAVE"), body);
}

// --- parseWavToPcm16 refusals ---

// Not a RIFF/WAVE container at all (>=44 bytes so the length floor is cleared).
rejectsAudioStego(() => parseWavToPcm16(new Uint8Array(64).fill(0x41)), "a non-RIFF buffer is refused");

// RIFF/WAVE with a fmt chunk but no data chunk.
rejectsAudioStego(() => parseWavToPcm16(riff(fmtChunk({}))), "a WAV with no data chunk is refused");

// Non-PCM format (3 = IEEE float) — must be refused, not misread.
rejectsAudioStego(() => parseWavToPcm16(riff(fmtChunk({ format: 3 }), dataChunk())), "a non-PCM (float) WAV is refused");

// 24-bit PCM — the LSB scheme is defined on 16-bit ints.
rejectsAudioStego(() => parseWavToPcm16(riff(fmtChunk({ bits: 24 }), dataChunk())), "a 24-bit WAV is refused");

// Zero channels.
rejectsAudioStego(() => parseWavToPcm16(riff(fmtChunk({ channels: 0 }), dataChunk())), "a WAV declaring no channels is refused");

// Positive control: a real 16-bit PCM WAV still parses.
{
  const round = parseWavToPcm16(writePcm16Wav({ sampleRate: 8000, channels: 1, samples: Int16Array.of(7, -7, 3) }));
  ok(round.channels === 1 && round.samples.length === 3 && round.samples[0] === 7, "a valid 16-bit PCM WAV still parses");
}

// --- extractContainer refusals ---

// A carrier of `n` samples whose LSBs, most-significant-bit first, spell `bytes`.
function pcmFromLsbBytes(bytes, totalSamples) {
  const samples = new Int16Array(Math.max(totalSamples, bytes.length * 8));
  let s = 0;
  for (const byte of bytes) for (let b = 7; b >= 0; b--) samples[s++] = (byte >> b) & 1;
  return { sampleRate: 8000, channels: 1, samples };
}
const KAUD = Uint8Array.of(0x4b, 0x41, 0x55, 0x44);
/** A KAUD header: magic + version + lsbDepth + payloadLen (big-endian). */
const kaudHeader = (version, depth, payloadLen) =>
  cat(KAUD, Uint8Array.of(version), Uint8Array.of(depth), Uint8Array.of((payloadLen >>> 24) & 0xff, (payloadLen >>> 16) & 0xff, (payloadLen >>> 8) & 0xff, payloadLen & 0xff));

// No KAUD marker: plain music, reported as carrying nothing.
rejectsAudioStego(() => extractContainer(pcmFromLsbBytes(ascii("NOPE......"), 2000)), "a carrier with no KAUD marker is refused");

// KAUD but an unreadable version.
rejectsAudioStego(() => extractContainer(pcmFromLsbBytes(kaudHeader(2, 1, 4), 2000)), "an unknown KAUD version is refused");

// KAUD v1 but a bit depth this app cannot read.
rejectsAudioStego(() => extractContainer(pcmFromLsbBytes(kaudHeader(1, 2, 4), 2000)), "an unreadable KAUD bit depth is refused");

// A header claiming an empty payload.
rejectsAudioStego(() => extractContainer(pcmFromLsbBytes(kaudHeader(1, 1, 0), 2000)), "a KAUD header claiming an empty payload is refused");

// A header claiming a payload far larger than the carrier can hold. BITE: with
// the readBytes bounds guard removed, this reads past the samples (undefined & 1
// = 0) and returns garbage instead of throwing.
rejectsAudioStego(() => extractContainer(pcmFromLsbBytes(kaudHeader(1, 1, 100000), 2000)), "a payload that runs past the carrier is refused");

// Positive control: embed then extract round-trips the exact container bytes.
{
  const container = Uint8Array.from({ length: 120 }, (_, i) => (i * 31 + 9) & 0xff);
  const carrier = { sampleRate: 8000, channels: 1, samples: new Int16Array(4000) };
  const embedded = embedContainer(carrier, container);
  const got = extractContainer(embedded);
  ok(got.length === container.length && got.every((v, i) => v === container[i]), "embed → extract round-trips the container");
}

console.log(failed === 0 ? "\nAll audio-malformed checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
