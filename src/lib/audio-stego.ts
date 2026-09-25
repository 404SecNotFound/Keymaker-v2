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

// ---- WAV read (any integer PCM or float depth) and write (16-bit PCM) ----

function readAscii(view: DataView, offset: number, length: number): string {
  let s = "";
  for (let i = 0; i < length; i++) s += String.fromCharCode(view.getUint8(offset + i));
  return s;
}

/**
 * Is this a RIFF/WAVE file, going by its bytes rather than its name?
 *
 * The carrier path used to choose the exact WAV parser by MIME type or a
 * `.wav` extension alone. A stego WAV sent through a messenger or saved under
 * another name loses both, falls through to Web Audio, and is resampled to the
 * device's rate on the way in, which destroys an LSB payload outright.
 */
export function isWavBytes(bytes: Uint8Array): boolean {
  if (bytes.length < 12) return false;
  const tag = (at: number) => String.fromCharCode(bytes[at]!, bytes[at + 1]!, bytes[at + 2]!, bytes[at + 3]!);
  return tag(0) === "RIFF" && tag(8) === "WAVE";
}

const WAVE_FORMAT_PCM = 1;
const WAVE_FORMAT_IEEE_FLOAT = 3;
const WAVE_FORMAT_EXTENSIBLE = 0xfffe;
/** The 14 bytes after the format code in a KSDATAFORMAT_SUBTYPE_* GUID. */
const KSDATAFORMAT_SUFFIX = [0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71];

const clamp16 = (v: number) => Math.max(-32768, Math.min(32767, v));

/**
 * Parse a WAV into interleaved 16-bit samples, without resampling.
 *
 * 16-bit PCM, the one encoding the writer below produces and the only one a
 * payload is embedded in, is read sample for sample. Other integer depths (8,
 * 24, 32) and 32- or 64-bit float, plain or WAVE_FORMAT_EXTENSIBLE, are scaled
 * to 16 bits here rather than refused. Each is scaled by a power of two, so a
 * 16-bit file re-saved losslessly at a greater depth comes back to the same
 * samples, low bit included, and a payload it carried is still there.
 *
 * This is not left to Web Audio because Web Audio resamples to the device rate,
 * which destroys the low bit. Encodings this does not read (ADPCM, A-law,
 * mu-law, unusual depths) are refused with a message rather than misread.
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
      // The PCM fmt chunk is 16 bytes and the fields below read through body+15.
      // The loop guard only proves the 8-byte chunk header is present, not the
      // body, so a declared-but-truncated fmt chunk would make DataView throw a
      // raw RangeError. Refuse it as a typed carrier error instead, keeping the
      // promise that every carrier problem is an AudioStegoError, not a crash.
      if (size < 16 || body + 16 > bytes.length) {
        throw new AudioStegoError("This WAV's format chunk is malformed or truncated.");
      }
      format = view.getUint16(body, true);
      channels = view.getUint16(body + 2, true);
      sampleRate = view.getUint32(body + 4, true);
      bitsPerSample = view.getUint16(body + 14, true);
      if (format === WAVE_FORMAT_EXTENSIBLE) {
        // The real encoding is the first two bytes of the SubFormat GUID at
        // body+24, and the rest of the GUID has to be the KSDATAFORMAT one for
        // those two bytes to mean anything.
        if (size < 40 || body + 40 > bytes.length) {
          throw new AudioStegoError("This WAV's format chunk is malformed or truncated.");
        }
        const suffixOk = KSDATAFORMAT_SUFFIX.every((b, i) => bytes[body + 26 + i] === b);
        format = suffixOk ? view.getUint16(body + 24, true) : 0;
      }
    } else if (id === "data") {
      dataOffset = body;
      dataLength = Math.min(size, bytes.length - body);
    }
    // Chunks are word-aligned: an odd size is padded by one byte.
    p = body + size + (size & 1);
  }

  if (dataOffset < 0) throw new AudioStegoError("This WAV has no audio data.");
  const pcm = format === WAVE_FORMAT_PCM && [8, 16, 24, 32].includes(bitsPerSample);
  const float = format === WAVE_FORMAT_IEEE_FLOAT && (bitsPerSample === 32 || bitsPerSample === 64);
  if (!pcm && !float) {
    throw new AudioStegoError(
      "This WAV's encoding cannot be read. Re-export it as PCM (8, 16, 24 or 32-bit) or float WAV."
    );
  }
  if (channels < 1) throw new AudioStegoError("This WAV declares no channels.");

  const width = bitsPerSample / 8;
  const sampleCount = Math.floor(dataLength / width);
  const samples = new Int16Array(sampleCount);
  for (let i = 0; i < sampleCount; i++) {
    const at = dataOffset + i * width;
    let v: number;
    if (float) {
      // The same single scale decodeToPcm16 uses, and its inverse of s / 32768.
      const f = width === 4 ? view.getFloat32(at, true) : view.getFloat64(at, true);
      v = Number.isFinite(f) ? Math.round(f * 32768) : 0;
    } else if (width === 2) {
      v = view.getInt16(at, true);
    } else if (width === 1) {
      v = (view.getUint8(at) - 128) * 256; // 8-bit WAV is unsigned
    } else if (width === 3) {
      const u = view.getUint8(at) | (view.getUint8(at + 1) << 8) | (view.getUint8(at + 2) << 16);
      v = Math.round((u & 0x800000 ? u - 0x1000000 : u) / 256);
    } else {
      v = Math.round(view.getInt32(at, true) / 65536);
    }
    samples[i] = clamp16(v);
  }
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
 * into. A WAV is parsed directly by `parseWavToPcm16` whatever its depth, so
 * its sample rate is kept and 16-bit samples survive exactly; this path is for
 * everything else.
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
      // One scale, 32768, both signs, then clamp. Web Audio decoders turn a
      // 16-bit sample s into s / 32768, so this is the exact inverse and every
      // sample, low bit included, comes back as it was written. Scaling
      // positives by 32767 instead (to reach +1.0 exactly) moved every sample
      // above 16384 down by one, which flips the one bit the payload lives
      // in: a stego WAV revealed through this path lost its payload and was
      // reported as a wrong password.
      const v = Math.round(chans[c]![f]! * 32768);
      samples[f * channels + c] = Math.max(-32768, Math.min(32767, v));
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
