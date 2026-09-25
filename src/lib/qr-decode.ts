/**
 * Decode a QR image back to the text it carries.
 *
 * The inverse of the QR codes this app already writes. A Keymaker QR encodes one
 * of three strings, and every one of them is text the Decrypt tab already knows
 * how to route:
 *
 *   - a full armor string, `keym2:…`, from the encrypt-side output QR;
 *   - a paper part, `KMPART2:i/n:…` (or a legacy `KMPART1:`), from the paper
 *     vault (one QR per part);
 *   - a recovery share, `KMSHARE2:…` (or a legacy `KMSHARE1:`), from a strip.
 *
 * So the decoder's only job is image → string. What the string *means* is left
 * to `handleTextSecretChange`, which already reassembles paper parts, unwraps a
 * self-extracting page, and tells someone a share belongs in the shares box.
 * Nothing here parses a container.
 *
 * `jsqr` is loaded lazily, the same way the crypto core lazy-loads its own heavy
 * dependencies: someone who never scans a QR never pays for the decoder. It runs
 * entirely on canvas pixels, with no network, which is what keeps it inside the
 * `connect-src 'none'` CSP.
 */

/**
 * Longest edge, in pixels, a source image is scaled down to before decoding.
 *
 * A phone photo is many megapixels and jsqr scans every one of them; capping the
 * longest edge keeps a scan fast without losing a QR that fills a sensible
 * fraction of the frame. The app's own exports (256–1024px) are already under
 * this and are never scaled.
 */
const MAX_DECODE_EDGE = 2000;

/**
 * Scales tried, relative to the first attempt's size, when a symbol is not
 * found. jsqr's sampling grid is sensitive to how a module's width falls on
 * whole pixels, not only to how many pixels it gets: the paper vault's own
 * symbol, read straight off its 300px canvas, failed at 1x and decoded at
 * 0.75x, 1.25x, 1.5x and 2x. And a phone photo capped to 2000px can leave a
 * version-40 part near 2.5 px per module, which it cannot read, where the
 * photo's own resolution would have been enough. So a miss is retried at a
 * handful of scales before being reported, first upward, then down.
 */
const RETRY_SCALES = [1, 2, 1.5, 0.75, 1.25] as const;

/** The largest edge any retry may reach: twice the first attempt's cap, which
 *  covers a 12-megapixel photo at close to its native resolution. */
const MAX_RETRY_EDGE = 2 * MAX_DECODE_EDGE;

/** Thrown when an image carries no readable QR, named so the UI can tell the
 *  two apart: a file that is not an image at all, versus an image with no code
 *  the decoder could find. */
export class QrDecodeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "QrDecodeError";
  }
}

let jsqrPromise: Promise<typeof import("jsqr").default> | null = null;

async function loadJsqr(): Promise<typeof import("jsqr").default> {
  if (!jsqrPromise) {
    jsqrPromise = import("jsqr")
      .then((m) => m.default)
      .catch((e) => {
        // Null the cache so a later attempt can retry rather than resolve the
        // same rejected promise forever.
        jsqrPromise = null;
        throw new QrDecodeError(
          "The QR decoder could not be loaded. Reload the page and try again."
        );
      });
  }
  return jsqrPromise;
}

/**
 * Draw an image bitmap onto a 2D canvas, `longestEdge` pixels on its longest
 * side, and hand back its pixels. Smoothing stays on: resampling with it is
 * what lets a retry at another scale read a symbol the first size could not.
 */
function bitmapToImageData(bitmap: ImageBitmap, longestEdge: number): ImageData {
  const scale = longestEdge / Math.max(bitmap.width, bitmap.height);
  const width = Math.max(1, Math.round(bitmap.width * scale));
  const height = Math.max(1, Math.round(bitmap.height * scale));
  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  if (!ctx) {
    throw new QrDecodeError("This browser would not give a 2D canvas to read the image.");
  }
  ctx.imageSmoothingEnabled = true;
  ctx.imageSmoothingQuality = "high";
  ctx.drawImage(bitmap, 0, 0, width, height);
  return ctx.getImageData(0, 0, width, height);
}

/**
 * The longest-edge sizes to try, in order: the image as it is (capped at
 * `MAX_DECODE_EDGE`), then the retry scales, each clamped and deduplicated.
 * Pure.
 */
function decodeAttemptEdges(longest: number): number[] {
  const base = Math.min(longest, MAX_DECODE_EDGE);
  const out: number[] = [];
  for (const factor of RETRY_SCALES) {
    const edge = Math.max(1, Math.min(Math.round(base * factor), MAX_RETRY_EDGE));
    if (!out.includes(edge)) out.push(edge);
  }
  return out;
}

/**
 * The most codes one picture is searched for. A paper vault page holds a
 * handful of container symbols, and a sheet of strips three to eight; this is
 * well past both, and bounds the work a hostile or pathological image can cause.
 */
const MAX_CODES_PER_IMAGE = 32;

/** The corners jsqr reports for a symbol it found. */
type QrCorners = {
  topLeftCorner: { x: number; y: number };
  topRightCorner: { x: number; y: number };
  bottomRightCorner: { x: number; y: number };
  bottomLeftCorner: { x: number; y: number };
};

/**
 * Paint over a symbol jsqr has already read, so the next search finds the next
 * one. jsqr returns one code per call, and always the same one while it is
 * there; blanking it is what lets a single photo of a page yield every code on
 * it. The quad is grown by a fifth about its centre so the finder patterns and
 * the edge of the quiet zone go too: a surviving finder pattern can pair with
 * another symbol's and send the next search chasing a phantom.
 */
function maskCode(ctx: CanvasRenderingContext2D, loc: QrCorners): void {
  const pts = [loc.topLeftCorner, loc.topRightCorner, loc.bottomRightCorner, loc.bottomLeftCorner];
  const cx = pts.reduce((a, p) => a + p.x, 0) / 4;
  const cy = pts.reduce((a, p) => a + p.y, 0) / 4;
  ctx.fillStyle = "#ffffff";
  ctx.beginPath();
  pts.forEach((p, i) => {
    const x = cx + (p.x - cx) * 1.2;
    const y = cy + (p.y - cy) * 1.2;
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.closePath();
  ctx.fill();
}

/**
 * Read every code jsqr can find on a canvas, painting each out as it goes.
 * Mutates the canvas. `add` records a value and says whether it was new.
 */
async function findAndMask(
  ctx: CanvasRenderingContext2D,
  width: number,
  height: number,
  add: (value: string) => boolean
): Promise<number> {
  const jsqr = await loadJsqr();
  let added = 0;
  let pixels = ctx.getImageData(0, 0, width, height);
  for (let i = 0; i < MAX_CODES_PER_IMAGE; i++) {
    const code = jsqr(pixels.data, pixels.width, pixels.height, {
      inversionAttempts: "attemptBoth",
    });
    if (!code) break;
    if (code.data && add(code.data)) added++;
    maskCode(ctx, code.location);
    pixels = ctx.getImageData(0, 0, width, height);
  }
  return added;
}

/**
 * The same search, over overlapping square tiles of the canvas.
 *
 * jsqr looks for three finder patterns and decodes the symbol they frame. With
 * several symbols in view it can pick patterns from different ones, fail, and
 * report nothing, even though every symbol is perfectly readable on its own. A
 * tile small enough to hold one symbol takes that choice away. Tiles are
 * squares of the canvas's shorter side and of half of it, each stepped by half
 * its width so a symbol cut by one tile's edge is whole in the next. Positions
 * are mapped back to the full canvas, so each code is masked there and no tile
 * reads it again. Returns how many new codes it added.
 */
async function findAndMaskTiled(
  ctx: CanvasRenderingContext2D,
  width: number,
  height: number,
  add: (value: string) => boolean
): Promise<number> {
  const jsqr = await loadJsqr();
  const short = Math.min(width, height);
  let added = 0;
  for (const size of [short, Math.round(short / 2)]) {
    // A tile the size of the whole canvas is the search already done.
    if (size < MIN_TILE_EDGE || (size === width && size === height)) continue;
    const step = Math.max(1, Math.round(size / 2));
    const xs: number[] = [];
    const ys: number[] = [];
    for (let x = 0; ; x += step) {
      xs.push(Math.min(x, width - size));
      if (x + size >= width) break;
    }
    for (let y = 0; ; y += step) {
      ys.push(Math.min(y, height - size));
      if (y + size >= height) break;
    }
    for (const y of new Set(ys)) {
      for (const x of new Set(xs)) {
        const tile = ctx.getImageData(x, y, size, size);
        const code = jsqr(tile.data, size, size, { inversionAttempts: "attemptBoth" });
        if (!code) continue;
        if (code.data && add(code.data)) added++;
        const at = (pt: { x: number; y: number }) => ({ x: pt.x + x, y: pt.y + y });
        maskCode(ctx, {
          topLeftCorner: at(code.location.topLeftCorner),
          topRightCorner: at(code.location.topRightCorner),
          bottomRightCorner: at(code.location.bottomRightCorner),
          bottomLeftCorner: at(code.location.bottomLeftCorner),
        });
      }
    }
  }
  return added;
}

/**
 * The share of a picture one code has to cover to be taken as the only code in
 * it. A page of symbols photographed whole puts each in well under a tenth of
 * the frame; an exported QR or a strip photographed on its own fills most of it.
 */
const LONE_CODE_FRACTION = 0.25;

/** Area of the quadrilateral jsqr reports, by the shoelace formula. */
function quadArea(loc: QrCorners): number {
  const p = [loc.topLeftCorner, loc.topRightCorner, loc.bottomRightCorner, loc.bottomLeftCorner];
  let twice = 0;
  for (let i = 0; i < 4; i++) {
    const a = p[i] as { x: number; y: number };
    const b = p[(i + 1) % 4] as { x: number; y: number };
    twice += a.x * b.y - b.x * a.y;
  }
  return Math.abs(twice) / 2;
}

/** Smallest tile worth searching: below this a tile is smaller than any
 *  symbol a camera or a photo would carry at a readable size. */
const MIN_TILE_EDGE = 200;

/** The browser's own detector, where there is one. Typed here because the
 *  DOM library does not declare it: it is shipped on some platforms only. */
type NativeDetector = { detect(source: ImageBitmapSource): Promise<{ rawValue: string }[]> };

async function nativeDetect(bitmap: ImageBitmapSource): Promise<string[]> {
  const Ctor = (globalThis as unknown as {
    BarcodeDetector?: {
      new (opts: { formats: string[] }): NativeDetector;
      getSupportedFormats?: () => Promise<string[]>;
    };
  }).BarcodeDetector;
  if (!Ctor) return [];
  try {
    const formats = (await Ctor.getSupportedFormats?.()) ?? ["qr_code"];
    if (!formats.includes("qr_code")) return [];
    const found = await new Ctor({ formats: ["qr_code"] }).detect(bitmap);
    return found.map((f) => f.rawValue).filter((v) => typeof v === "string" && v !== "");
  } catch {
    // A detector that exists and fails is the same as none: jsqr still runs.
    return [];
  }
}

/**
 * Decode every QR code in one image file, in no particular order.
 *
 * A photo of a printed page carries several codes, and asking someone to crop
 * each one out first is asking them to do the scanner's job. Two passes:
 *
 * - `BarcodeDetector`, where the browser ships one, which returns every code
 *   it sees in one call, and is used alone when it finds anything;
 * - jsqr, which returns one, so each code it reads is painted out and the
 *   picture searched again, until nothing new turns up; then once more over
 *   overlapping tiles, because with several symbols in view jsqr can pair
 *   finder patterns from different ones and read none (`findAndMaskTiled`).
 *   Scales are tried in the retry order below with one read each, the first
 *   scale that reads anything is searched further and is the last one tried,
 *   and tiles at the first scale are the last resort before "no code".
 *
 * A code read twice is returned once. `attemptBoth`
 * is passed so a QR printed light-on-dark (a dark-theme export, a photo of a
 * screen) reads the same as the usual dark-on-light.
 */
export async function decodeAllQrImage(file: File): Promise<string[]> {
  let bitmap: ImageBitmap;
  try {
    bitmap = await createImageBitmap(file);
  } catch {
    throw new QrDecodeError(
      `"${file.name}" is not an image this browser can read. A QR must be a PNG, JPEG or WebP.`
    );
  }

  const found: string[] = [];
  const seen = new Set<string>();
  const add = (value: string): boolean => {
    if (seen.has(value)) return false;
    seen.add(value);
    found.push(value);
    return true;
  };

  try {
    // Where the browser has its own detector it sees every code in one call,
    // and more reliably than jsqr; jsqr is the fallback, not a second opinion.
    for (const value of await nativeDetect(bitmap)) add(value);
    if (found.length > 0) return found;

    const jsqr = await loadJsqr();
    const edges = decodeAttemptEdges(Math.max(bitmap.width, bitmap.height));

    // Search a whole picture at one size: what jsqr reads, then every other
    // code on it, painted out one by one, then the tiles.
    const searchPage = async (imageData: ImageData, first: ReturnType<typeof jsqr>) => {
      const canvas = document.createElement("canvas");
      canvas.width = imageData.width;
      canvas.height = imageData.height;
      const ctx = canvas.getContext("2d", { willReadFrequently: true });
      if (!ctx) {
        throw new QrDecodeError("This browser would not give a 2D canvas to read the image.");
      }
      ctx.putImageData(imageData, 0, 0);
      if (first) {
        if (first.data) add(first.data);
        maskCode(ctx, first.location);
      }
      await findAndMask(ctx, canvas.width, canvas.height, add);
      // A code found in a tile may have been what stopped the whole-frame
      // search, so that gets one more go on what is left.
      if ((await findAndMaskTiled(ctx, canvas.width, canvas.height, add)) > 0) {
        await findAndMask(ctx, canvas.width, canvas.height, add);
      }
    };

    // One whole-frame read per size first, exactly as a one-code scan always
    // cost. jsqr's grid is sensitive to how a module falls on whole pixels, so
    // a clean 800px render of the sheet's own symbol can fail at 800 and read
    // at 600; only a size where something reads is searched further.
    for (const edge of edges) {
      const imageData = bitmapToImageData(bitmap, edge);
      const first = jsqr(imageData.data, imageData.width, imageData.height, {
        inversionAttempts: "attemptBoth",
      });
      if (!first) continue;
      // A code that fills a quarter of the picture or more is the picture: an
      // exported QR, or a strip photographed on its own. Nothing else fits.
      if (first.data && quadArea(first.location) >= LONE_CODE_FRACTION * imageData.width * imageData.height) {
        add(first.data);
      } else {
        await searchPage(imageData, first);
      }
      break;
    }

    // Nothing read whole at any size. A page of several symbols can do that:
    // jsqr pairs finder patterns from different ones and reads none. Tiles,
    // once, at the first size, before saying there is no code.
    if (found.length === 0) {
      await searchPage(bitmapToImageData(bitmap, edges[0] as number), null);
    }
  } finally {
    bitmap.close();
  }

  if (found.length === 0) {
    throw new QrDecodeError(
      `No QR code was found in "${file.name}". Crop the picture to the code, or scan it more squarely.`
    );
  }
  return found;
}

/** Longest edge a camera frame is decoded at. Enough for a strip or a symbol
 *  held up to a laptop camera, small enough to read several times a second. */
const MAX_FRAME_EDGE = 1280;

/**
 * Every code in one frame of a live camera, at one scale: a camera is read
 * again a few times a second, so the retry scales a still photo needs would
 * only slow each frame down. The frame is drawn at no more than
 * `MAX_FRAME_EDGE` on its longest side. Returns an empty list for a frame with
 * nothing in it, which for a camera is the ordinary case, not an error.
 */
export async function decodeAllQrInFrame(
  source: HTMLVideoElement,
  scratch: HTMLCanvasElement
): Promise<string[]> {
  const w0 = source.videoWidth;
  const h0 = source.videoHeight;
  if (!w0 || !h0) return [];
  const scale = Math.min(1, MAX_FRAME_EDGE / Math.max(w0, h0));
  scratch.width = Math.max(1, Math.round(w0 * scale));
  scratch.height = Math.max(1, Math.round(h0 * scale));
  const ctx = scratch.getContext("2d", { willReadFrequently: true });
  if (!ctx) return [];
  ctx.drawImage(source, 0, 0, scratch.width, scratch.height);

  const found: string[] = [];
  const seen = new Set<string>();
  const add = (value: string): boolean => {
    if (seen.has(value)) return false;
    seen.add(value);
    found.push(value);
    return true;
  };
  for (const value of await nativeDetect(scratch)) add(value);
  await findAndMask(ctx, scratch.width, scratch.height, add);
  return found;
}

/**
 * Decode one image file to the text of one QR it contains: the first that
 * `decodeAllQrImage` reads.
 */
export async function decodeQrImage(file: File): Promise<string> {
  return (await decodeAllQrImage(file))[0] as string;
}

/**
 * Decode several image files to every QR string they carry, file by file.
 *
 * This is the paper-vault case: a backup too big for one symbol is written as
 * several QR codes, photographed one at a time or a page at a time, and the
 * caller joins them with newlines for the §7.1/§7.3 reassembler, which reads
 * each part's own index and so needs no order. One unreadable image fails the
 * whole set, named, rather than silently reassembling a container with a hole
 * in it.
 */
export async function decodeQrImages(files: readonly File[]): Promise<string[]> {
  const out: string[] = [];
  for (const file of files) {
    out.push(...(await decodeAllQrImage(file)));
  }
  return out;
}
