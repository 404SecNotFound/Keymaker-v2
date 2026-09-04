/**
 * KAUD1 audio carrier: hide a KEYM container in the LSBs of PCM audio.
 *
 * The normative layout is docs/FORMAT-AUDIO-STEGO.md. This module is the
 * carrier only. The bytes it hides are a plain KEYM container produced by the
 * ordinary encrypt path, so the crypto lives entirely in keym-v2 and the worker;
 * nothing here parses a container or touches a key.
 *
 * Everything runs on PCM samples in memory, with no network, so it stays inside
 * the `connect-src 'none'` CSP the rest of the app keeps.
 */

/** ASCII "KAUD". First four bytes of the embedded stream. */
const MAGIC = Uint8Array.of(0x4b, 0x41, 0x55, 0x44);
const VERSION = 0x01;
/** magic(4) + version(1) + lsbDepth(1) + payloadLen(4). */
const HEADER_BYTES = 10;

/** Thrown for every carrier problem, named so the UI can tell a bad audio file
 *  from a wrong password: a carrier failure is never routed to the AEAD. */
export class AudioStegoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AudioStegoError";
  }
}

/** 16-bit PCM, interleaved, as a WAV `data` chunk stores it. */
export interface Pcm16 {
  sampleRate: number;
  channels: number;
  /** Interleaved signed 16-bit samples: [L0, R0, L1, R1, …] for stereo. */
  samples: Int16Array;
}

/**
 * Usable payload bytes for a carrier of `sampleCount` samples at `lsbDepth`
 * bits per sample, after the fixed header. Never negative: a carrier too small
 * for even the header reports 0.
 */
export function audioCapacityBytes(sampleCount: number, lsbDepth = 1): number {
  const total = Math.floor((sampleCount * lsbDepth) / 8);
  return Math.max(0, total - HEADER_BYTES);
}

/** Walk a byte array as a most-significant-first bit stream. */
function* bitsOf(bytes: Uint8Array): Generator<number> {
  for (const byte of bytes) {
    for (let b = 7; b >= 0; b--) yield (byte >> b) & 1;
  }
}

/**
 * Embed `container` into a copy of `pcm`, one bit per sample, and return the
 * new PCM. The input samples are not mutated so the caller can still write the
 * clean carrier if it decides not to.
 */
export function embedContainer(pcm: Pcm16, container: Uint8Array, lsbDepth = 1): Pcm16 {
  if (lsbDepth !== 1) {
    throw new AudioStegoError("Only one bit per sample is supported in this version.");
  }
  if (container.length === 0) {
    throw new AudioStegoError("Refusing to hide an empty container.");
  }
  const capacity = audioCapacityBytes(pcm.samples.length, lsbDepth);
  if (container.length > capacity) {
    throw new AudioStegoError(
      `This secret needs ${container.length.toLocaleString()} bytes but the carrier ` +
        `holds ${capacity.toLocaleString()}. Use a longer audio file, or hide less.`
    );
  }

  const header = new Uint8Array(HEADER_BYTES);
  header.set(MAGIC, 0);
  header[4] = VERSION;
  header[5] = lsbDepth;
  // payloadLen, big-endian, at offset 6.
  new DataView(header.buffer).setUint32(6, container.length, false);

  const out = pcm.samples.slice();
  let i = 0;
  for (const bit of bitsOf(header)) out[i] = (out[i]! & 0xfffe) | bit, i++;
  for (const bit of bitsOf(container)) out[i] = (out[i]! & 0xfffe) | bit, i++;

  return { sampleRate: pcm.sampleRate, channels: pcm.channels, samples: out };
}

/** Read `count` bytes from the sample LSBs starting at sample `from`,
 *  most-significant-bit first. Returns the bytes and the next sample index. */
function readBytes(samples: Int16Array, from: number, count: number): [Uint8Array, number] {
  if (from + count * 8 > samples.length) {
    throw new AudioStegoError("The hidden data runs past the end of this audio. The file is truncated or is not a Keymaker carrier.");
  }
  const out = new Uint8Array(count);
  let s = from;
  for (let byteIdx = 0; byteIdx < count; byteIdx++) {
    let byte = 0;
    for (let b = 0; b < 8; b++) byte = (byte << 1) | (samples[s++]! & 1);
    out[byteIdx] = byte;
  }
  return [out, s];
}

/**
 * Extract the KEYM container hidden in `pcm`. Throws `AudioStegoError` when no
 * KAUD1 header is present, so a plain music file is reported as carrying nothing
 * rather than surfacing later as a wrong-password error.
 */
export function extractContainer(pcm: Pcm16): Uint8Array {
  const { samples } = pcm;
  const [header, afterHeader] = readBytes(samples, 0, HEADER_BYTES);
  for (let i = 0; i < MAGIC.length; i++) {
    if (header[i] !== MAGIC[i]) {
      throw new AudioStegoError("No hidden Keymaker data was found in this audio file.");
    }
  }
  if (header[4] !== VERSION) {
    throw new AudioStegoError(`This carrier is KAUD version ${header[4]}, which this app cannot read.`);
  }
  if (header[5] !== 1) {
    throw new AudioStegoError(`This carrier uses ${header[5]} bits per sample, which this app cannot read.`);
  }
  const payloadLen = new DataView(header.buffer, header.byteOffset, HEADER_BYTES).getUint32(6, false);
  if (payloadLen === 0) {
    throw new AudioStegoError("The carrier's header claims an empty payload.");
  }
  const [payload] = readBytes(samples, afterHeader, payloadLen);
  return payload;
}

// ---- WAV (16-bit PCM) read and write ----

function readAscii(view: DataView, offset: number, length: number): string {
  let s = "";
  for (let i = 0; i < length; i++) s += String.fromCharCode(view.getUint8(offset + i));
  return s;
}

/**
 * Parse a 16-bit PCM WAV into interleaved samples.
 *
 * Only the one encoding the writer below produces is accepted: RIFF/WAVE, PCM
 * (format 1), 16 bits per sample. Anything else (float, 24-bit, ADPCM) is
 * refused with a message rather than misread, because the LSB scheme is defined
 * on 16-bit integers.
 */
export function parseWavToPcm16(bytes: Uint8Array): Pcm16 {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (bytes.length < 44 || readAscii(view, 0, 4) !== "RIFF" || readAscii(view, 8, 4) !== "WAVE") {
    throw new AudioStegoError("This is not a WAV file.");
  }
  let channels = 0;
  let sampleRate = 0;
  let bitsPerSample = 0;
  let format = 0;
  let dataOffset = -1;
  let dataLength = 0;

  // Walk the chunks: fmt carries the encoding, data carries the samples.
  let p = 12;
  while (p + 8 <= bytes.length) {
    const id = readAscii(view, p, 4);
    const size = view.getUint32(p + 4, true);
    const body = p + 8;
    if (id === "fmt ") {
      format = view.getUint16(body, true);
      channels = view.getUint16(body + 2, true);
      sampleRate = view.getUint32(body + 4, true);
      bitsPerSample = view.getUint16(body + 14, true);
    } else if (id === "data") {
      dataOffset = body;
      dataLength = Math.min(size, bytes.length - body);
    }
    // Chunks are word-aligned: an odd size is padded by one byte.
    p = body + size + (size & 1);
  }

  if (dataOffset < 0) throw new AudioStegoError("This WAV has no audio data.");
  if (format !== 1 || bitsPerSample !== 16) {
    throw new AudioStegoError("Only 16-bit PCM WAV is supported. Re-export the audio as 16-bit PCM WAV.");
  }
  if (channels < 1) throw new AudioStegoError("This WAV declares no channels.");

  const sampleCount = Math.floor(dataLength / 2);
  const samples = new Int16Array(sampleCount);
  for (let i = 0; i < sampleCount; i++) samples[i] = view.getInt16(dataOffset + i * 2, true);
  return { sampleRate, channels, samples };
}

/** Write interleaved 16-bit PCM as a canonical 44-byte-header WAV. */
export function writePcm16Wav(pcm: Pcm16): Uint8Array {
  const { sampleRate, channels, samples } = pcm;
  const dataLength = samples.length * 2;
  const buffer = new ArrayBuffer(44 + dataLength);
  const view = new DataView(buffer);

  const writeAscii = (offset: number, text: string) => {
    for (let i = 0; i < text.length; i++) view.setUint8(offset + i, text.charCodeAt(i));
  };
  const byteRate = sampleRate * channels * 2;
  writeAscii(0, "RIFF");
  view.setUint32(4, 36 + dataLength, true);
  writeAscii(8, "WAVE");
  writeAscii(12, "fmt ");
  view.setUint32(16, 16, true); // PCM fmt chunk size
  view.setUint16(20, 1, true); // PCM
  view.setUint16(22, channels, true);
  view.setUint32(24, sampleRate, true);
  view.setUint32(28, byteRate, true);
  view.setUint16(32, channels * 2, true); // block align
  view.setUint16(34, 16, true); // bits per sample
  writeAscii(36, "data");
  view.setUint32(40, dataLength, true);
  for (let i = 0; i < samples.length; i++) view.setInt16(44 + i * 2, samples[i]!, true);

  return new Uint8Array(buffer);
}

/**
 * Decode any browser-supported audio file to interleaved 16-bit PCM.
 *
 * A lossy input (MP3, Ogg, AAC) is decoded to float PCM and re-quantised to
 * 16-bit here; those samples become the lossless master the payload is embedded
 * into. WAV that is already 16-bit PCM is parsed directly by `parseWavToPcm16`
 * so its exact samples survive; this path is for everything else.
 *
 * `ctxFactory` is injected so a test can supply an AudioContext; in the app it
 * defaults to the platform one.
 */
export async function decodeToPcm16(
  file: ArrayBuffer,
  ctxFactory: () => AudioContext = defaultAudioContext
): Promise<Pcm16> {
  const ctx = ctxFactory();
  let audio: AudioBuffer;
  try {
    // decodeAudioData detaches the buffer, so hand it a copy.
    audio = await ctx.decodeAudioData(file.slice(0));
  } catch {
    throw new AudioStegoError("This audio file could not be decoded. Use MP3, WAV, FLAC or Ogg.");
  } finally {
    void ctx.close?.();
  }

  const channels = audio.numberOfChannels;
  const frames = audio.length;
  const samples = new Int16Array(frames * channels);
  const chans: Float32Array[] = [];
  for (let c = 0; c < channels; c++) chans.push(audio.getChannelData(c));
  for (let f = 0; f < frames; f++) {
    for (let c = 0; c < channels; c++) {
      // Clamp to [-1, 1] then scale. -32768..32767 is asymmetric, so use 32767
      // for positives and 32768 for negatives to reach the full range.
      const v = Math.max(-1, Math.min(1, chans[c]![f]!));
      samples[f * channels + c] = v < 0 ? Math.round(v * 32768) : Math.round(v * 32767);
    }
  }
  return { sampleRate: audio.sampleRate, channels, samples };
}

function defaultAudioContext(): AudioContext {
  const Ctor =
    (globalThis as unknown as { AudioContext?: typeof AudioContext; webkitAudioContext?: typeof AudioContext })
      .AudioContext ??
    (globalThis as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
  if (!Ctor) throw new AudioStegoError("This browser has no Web Audio support to decode audio.");
  return new Ctor();
}
