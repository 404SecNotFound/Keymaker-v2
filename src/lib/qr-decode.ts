/**
 * Decode a QR image back to the text it carries.
 *
 * The inverse of the QR codes this app already writes. A Keymaker QR encodes one
 * of three strings, and every one of them is text the Decrypt tab already knows
 * how to route:
 *
 *   - a full armor string, `keym2:…`, from the encrypt-side output QR;
 *   - a paper part, `KMPART1:i/n:…`, from the paper vault (one QR per part);
 *   - a recovery share, `KMSHARE1:…`, from a recovery strip.
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
 * Draw an image bitmap onto a 2D canvas and hand back its pixels.
 *
 * Scales down proportionally once the longest edge exceeds `MAX_DECODE_EDGE`.
 * Kept separate so the test can reason about the pixel path without a jsqr in
 * the way.
 */
function bitmapToImageData(bitmap: ImageBitmap): ImageData {
  let { width, height } = bitmap;
  const longest = Math.max(width, height);
  if (longest > MAX_DECODE_EDGE) {
    const scale = MAX_DECODE_EDGE / longest;
    width = Math.max(1, Math.round(width * scale));
    height = Math.max(1, Math.round(height * scale));
  }
  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  if (!ctx) {
    throw new QrDecodeError("This browser would not give a 2D canvas to read the image.");
  }
  ctx.drawImage(bitmap, 0, 0, width, height);
  return ctx.getImageData(0, 0, width, height);
}

/**
 * Decode one image file to the text of the QR it contains.
 *
 * `attemptBoth` is passed so a QR printed light-on-dark (a dark-theme export,
 * a photo of a screen) reads the same as the usual dark-on-light.
 */
export async function decodeQrImage(file: File): Promise<string> {
  let bitmap: ImageBitmap;
  try {
    bitmap = await createImageBitmap(file);
  } catch {
    throw new QrDecodeError(
      `"${file.name}" is not an image this browser can read. A QR must be a PNG, JPEG or WebP.`
    );
  }

  let imageData: ImageData;
  try {
    imageData = bitmapToImageData(bitmap);
  } finally {
    bitmap.close();
  }

  const jsqr = await loadJsqr();
  const code = jsqr(imageData.data, imageData.width, imageData.height, {
    inversionAttempts: "attemptBoth",
  });
  if (!code || !code.data) {
    throw new QrDecodeError(
      `No QR code was found in "${file.name}". Crop the picture to the code, or scan it more squarely.`
    );
  }
  return code.data;
}

/**
 * Decode several image files, in the order given, to their QR strings.
 *
 * This is the paper-vault case: a backup too big for one symbol is written as
 * several QR codes, and the parts must arrive in order so the caller can join
 * them with newlines and let the §7.1 reassembler put the container back
 * together. One unreadable image fails the whole set, named, rather than
 * silently reassembling a container with a hole in it.
 */
export async function decodeQrImages(files: readonly File[]): Promise<string[]> {
  const out: string[] = [];
  for (const file of files) {
    out.push(await decodeQrImage(file));
  }
  return out;
}
