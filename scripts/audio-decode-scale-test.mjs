#!/usr/bin/env node
/**
 * A carrier decoded through Web Audio comes back sample-exact, and a stego WAV
 * is recognised by its bytes rather than its name.
 *
 * Web Audio decoders hand back a 16-bit sample s as the float s / 32768. The
 * old inverse scaled positives by 32767, which returned s - 1 for every
 * s > 16384: the low bit, which is exactly where an LSB payload lives, flipped
 * on half the positive range, and the reveal failed as a wrong password.
 *
 * decodeToPcm16 takes an AudioContext factory, so a fake context that decodes
 * the way browsers do stands in for one. Every int16 value is round-tripped.
 *
 * Controls shown to bite: restoring the 32767 positive scale fails the
 * round-trip on 16,383 values; making isWavBytes return false for everything
 * fails the sniff cases.
 */
import esbuild from "esbuild";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
const src = join(HERE, "..", "src", "lib", "audio-stego.ts");
const out = join(mkdtempSync(join(tmpdir(), "kaud-scale-")), "audio-stego.mjs");
await esbuild.build({ entryPoints: [src], bundle: true, format: "esm", platform: "node", outfile: out });

const { decodeToPcm16, isWavBytes, writePcm16Wav, embedContainer, extractContainer, MAX_DECODED_SAMPLES, AudioStegoError } = await import(
  pathToFileURL(out).href
);

let failed = 0;
const ok = (cond, msg) => {
  if (!cond) { console.error("FAIL:", msg); failed++; }
  else console.log("ok   ", msg);
};

/** A stand-in AudioContext whose decode is the browsers': int16 / 32768. */
function fakeContext(int16, channels) {
  return () => ({
    async decodeAudioData() {
      const frames = int16.length / channels;
      const data = [];
      for (let c = 0; c < channels; c++) {
        const ch = new Float32Array(frames);
        for (let f = 0; f < frames; f++) ch[f] = int16[f * channels + c] / 32768;
        data.push(ch);
      }
      return {
        numberOfChannels: channels,
        length: frames,
        sampleRate: 44100,
        getChannelData: (c) => data[c],
      };
    },
    close() {},
  });
}

// 1. Every int16 value survives the decode unchanged.
{
  const all = new Int16Array(65536);
  for (let i = 0; i < 65536; i++) all[i] = i - 32768;
  const pcm = await decodeToPcm16(new ArrayBuffer(8), fakeContext(all, 1));
  let wrong = 0;
  for (let i = 0; i < all.length; i++) if (pcm.samples[i] !== all[i]) wrong++;
  ok(wrong === 0, `every 16-bit sample round-trips through a Web Audio decode (${wrong} changed)`);
}

// 2. The end to end consequence: a payload embedded in loud audio is extracted
//    intact after a Web Audio decode. Loud, because the old scale only broke
//    samples above 16384.
{
  const frames = 40_000;
  const carrier = new Int16Array(frames * 2);
  for (let i = 0; i < carrier.length; i++) carrier[i] = 20_000 + (i % 7000);
  const container = new Uint8Array(512);
  for (let i = 0; i < container.length; i++) container[i] = (i * 131 + 7) & 0xff;
  const stego = embedContainer({ sampleRate: 44100, channels: 2, samples: carrier }, container);
  const decoded = await decodeToPcm16(new ArrayBuffer(8), fakeContext(stego.samples, 2));
  let same = false;
  try {
    const got = extractContainer(decoded);
    same = got.length === container.length && got.every((b, i) => b === container[i]);
  } catch {
    same = false;
  }
  ok(same, "a payload in loud audio survives a Web Audio decode");
}

// 3. A WAV is known by its bytes, whatever it is called.
{
  const wav = writePcm16Wav({ sampleRate: 44100, channels: 1, samples: new Int16Array(16) });
  ok(isWavBytes(wav), "a RIFF/WAVE file is recognised from its bytes");
  ok(!isWavBytes(new TextEncoder().encode("fLaC\0\0\0\"...................")), "a FLAC header is not a WAV");
  ok(!isWavBytes(new TextEncoder().encode("RIFF\0\0\0\0AVI LIST")), "a RIFF that is not WAVE is not a WAV");
  ok(!isWavBytes(new Uint8Array(4)), "a short file is not a WAV, and does not throw");
}

// 4. A carrier that decodes to more samples than the ceiling is refused by
//    name, before the Int16Array is allocated: the file cap is on the
//    compressed bytes, and a long low-bitrate file decodes to gigabytes.
//    getChannelData throws here so that an allocation attempted before the
//    check is a failure, not a slow pass.
{
  const overLong = (samples) => () => ({
    async decodeAudioData() {
      return {
        numberOfChannels: 2,
        length: samples / 2,
        sampleRate: 48000,
        getChannelData: () => {
          throw new Error("the samples were read before the ceiling was checked");
        },
      };
    },
    close() {},
  });
  let err = null;
  try {
    await decodeToPcm16(new ArrayBuffer(8), overLong(MAX_DECODED_SAMPLES + 2));
  } catch (e) {
    err = e;
  }
  ok(
    err instanceof AudioStegoError && /too long/.test(err.message),
    `a decode past the sample ceiling is refused as a carrier problem (${err ? err.message : "no error"})`
  );
  ok(MAX_DECODED_SAMPLES >= 20 * 60 * 48000 * 2, "the ceiling still admits twenty minutes of stereo at 48 kHz");
}

if (failed) {
  console.error(`\n${failed} check(s) failed`);
  process.exit(1);
}
console.log("\nAudio decode scale and WAV sniffing hold.");
