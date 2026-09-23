import type { Page, Locator } from "@playwright/test";

/**
 * Shared driving helpers for the browser suite.
 *
 * Both mode tabs are mounted at once, so almost every control exists twice in
 * the DOM. `visible()` disambiguates by what the user can actually see, which
 * is also what a user would click.
 */
export const visible = (locator: Locator): Locator => locator.locator("visible=true").first();

/**
 * The base path this run's build was made for, "" when served from the origin
 * root.
 *
 * Production ships under `/Keymaker-v2` (deploy.yml), so any test that names
 * an absolute path — `/verify.html`, `/recovery/keym.py`, a precached chunk —
 * is naming something the deployment does not serve unless it is prefixed.
 * Eight tests did exactly that and had therefore only ever been valid against
 * a layout no user receives.
 */
export const BASE_PATH = (process.env.KEYMAKER_BASE_PATH ?? "").replace(/\/$/, "");

/** An app-absolute path, prefixed for however this run is being served. */
export const appPath = (path: string): string =>
  `${BASE_PATH}${path.startsWith("/") ? path : `/${path}`}`;

export type Kdf = "pbkdf2" | "argon2id";
export type Cipher = "aes" | "chacha" | "chained";

export const CIPHER_LABEL: Record<Cipher, string | RegExp> = {
  aes: "AES-256-GCM",
  chacha: "ChaCha20-Poly1305",
  chained: "AES → ChaCha (chained)",
};

/** Switch the visible panel from File mode to Text mode. */
export async function useTextMode(page: Page): Promise<void> {
  await visible(page.getByRole("button", { name: "Text", exact: true })).click();
}

/** Open Advanced and select a KDF + cipher combination. */
export async function selectCrypto(page: Page, kdf: Kdf, cipher: Cipher): Promise<void> {
  const advanced = visible(page.getByRole("button", { name: /^Advanced/ }));
  if ((await advanced.getAttribute("aria-expanded")) !== "true") {
    await advanced.click();
  }

  const kdfLabel = kdf === "pbkdf2" ? "PBKDF2" : "Argon2id";
  await visible(page.getByRole("button").filter({ hasText: kdfLabel })).click();

  await visible(page.getByRole("button").filter({ hasText: CIPHER_LABEL[cipher] })).click();
}

/**
 * Every armor prefix the app has ever written.
 *
 * `KEYM1:` for v1, `keym2:` for v2 — and the case difference is the point of
 * FORMAT-V2-DESIGN §7 rather than an inconsistency: lowercase `k` (0x6B) is
 * what separates armored text from the binary magic `KEYM` (0x4B) in a single
 * byte, with no ordering dependency between checks.
 *
 * This helper matches any of them deliberately. Its job is "some armored
 * output appeared", so that a silently-failing crypto path surfaces as a
 * timeout. **Which** format the app writes is a separate assertion and lives
 * in crypto.spec.ts, where it can fail with a message that names the prefix.
 *
 * Hard-coding `KEYM` here is what broke the suite when the app started writing
 * v2: `"keym2:…".startsWith("KEYM")` is false, so every test routed through
 * this helper waited its full 90 s and failed on a timeout — 60 of them across
 * three engines, none of the messages mentioning a prefix.
 */
export const ARMOR_PREFIXES = ["KEYM1:", "keym2:"] as const;

/**
 * Encrypt `secret` and return the container as the UI produced it.
 * Waits on the Result field carrying an armored payload rather than on a
 * timeout, so a silently-failing crypto path shows up as a timeout instead of
 * passing.
 */
export async function encryptText(page: Page, secret: string, password: string): Promise<string> {
  await visible(page.getByPlaceholder("Enter text to encrypt")).fill(secret);
  await visible(page.getByPlaceholder("Enter a strong password")).fill(password);
  await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();

  await page.waitForFunction(
    (prefixes: readonly string[]) => {
      const value = (document.querySelector("#output-text") as HTMLTextAreaElement | null)?.value;
      return !!value && prefixes.some((p) => value.startsWith(p));
    },
    ARMOR_PREFIXES,
    { timeout: 90_000 }
  );
  return page.evaluate(() => (document.querySelector("#output-text") as HTMLTextAreaElement).value);
}

/** Decrypt a container on the Decrypt tab and return the recovered plaintext. */
export async function decryptText(page: Page, container: string, password: string): Promise<string> {
  await visible(page.getByRole("tab", { name: "Decrypt" })).click();
  await useTextMode(page);
  await visible(page.getByPlaceholder("Enter text to decrypt")).fill(container);
  await visible(page.getByPlaceholder("Enter decryption password")).fill(password);
  await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();

  // "Output exists and is not still the container." The exclusion has to cover
  // every armor prefix, not just v1's: `"keym2:…".startsWith("KEYM")` is false,
  // so the old check would have accepted a leftover v2 container as though it
  // were recovered plaintext — a test helper handing back its own input and
  // calling it a round-trip.
  await page.waitForFunction(
    (prefixes: readonly string[]) => {
      const el = document.querySelector("#output-text") as HTMLTextAreaElement | null;
      return !!el && el.value.length > 0 && !prefixes.some((p) => el.value.startsWith(p));
    },
    ARMOR_PREFIXES,
    { timeout: 90_000 }
  );
  return page.evaluate(() => (document.querySelector("#output-text") as HTMLTextAreaElement).value);
}

/** A password that satisfies the strength gate. */
export const STRONG_PASSWORD = "correct-horse-battery-staple-9271!X";

/** The symbols on the printed paper vault, as PNG bytes a scan would see. */
export interface PrintedSymbols {
  /** Container parts, in sheet order. */
  parts: Buffer[];
  /** Recovery strips, in sheet order. */
  strips: Buffer[];
}

/**
 * Click a "Print paper vault" button and return every symbol on the sheet as
 * a PNG, snapshotted from inside `window.print()` (the stub throws, which is
 * what leaves the sheet mounted long enough to read).
 *
 * Each symbol is turned into pixels the way it would reach paper. An SVG is
 * vector, and a printer draws it at its own resolution, so it is rasterised
 * here at `printPx` on its longest side (800px over the sheet's 46mm is about
 * 440dpi, below any laser printer). A canvas is already a bitmap, and a
 * printer can only stretch it, so it is taken exactly as it is. That is the
 * difference the scan-back test exists to see.
 */
export async function capturePrintedSymbols(
  page: Page,
  printButton: Locator,
  printPx = 800
): Promise<PrintedSymbols> {
  await page.evaluate(() => {
    const w = window as unknown as { __symbols?: unknown; print: () => void };
    w.__symbols = null;
    w.print = () => {
      const sheet = document.querySelector(".paper-vault");
      const grab = (el: Element) =>
        el instanceof HTMLCanvasElement
          ? { kind: "png", data: el.toDataURL("image/png") }
          : { kind: "svg", data: new XMLSerializer().serializeToString(el) };
      const symbols = Array.from(sheet?.querySelectorAll(".pv-qr canvas, .pv-qr svg, .pv-strip canvas, .pv-strip svg") ?? []);
      w.__symbols = {
        parts: symbols.filter((el) => !el.closest(".pv-strip")).map(grab),
        strips: symbols.filter((el) => el.closest(".pv-strip")).map(grab),
      };
      throw new Error("print stubbed");
    };
  });
  await visible(printButton).click();
  await page.waitForFunction(
    () => (window as unknown as { __symbols: unknown }).__symbols !== null,
    null,
    { timeout: 30_000 }
  );
  const urls = await page.evaluate(async (px: number) => {
    type Grabbed = { kind: "png" | "svg"; data: string };
    const got = (window as unknown as { __symbols: { parts: Grabbed[]; strips: Grabbed[] } }).__symbols;
    const toPng = async (g: Grabbed): Promise<string> => {
      if (g.kind === "png") return g.data;
      const img = new Image();
      img.src = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(g.data)}`;
      await img.decode();
      const canvas = document.createElement("canvas");
      canvas.width = px;
      canvas.height = px;
      const ctx = canvas.getContext("2d")!;
      ctx.fillStyle = "#ffffff";
      ctx.fillRect(0, 0, px, px);
      ctx.drawImage(img, 0, 0, px, px);
      return canvas.toDataURL("image/png");
    };
    return {
      parts: await Promise.all(got.parts.map(toPng)),
      strips: await Promise.all(got.strips.map(toPng)),
    };
  }, printPx);
  const toBuffer = (d: string) => Buffer.from(d.split(",")[1] as string, "base64");
  return { parts: urls.parts.map(toBuffer), strips: urls.strips.map(toBuffer) };
}
