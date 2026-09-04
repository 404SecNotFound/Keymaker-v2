import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";
import { appPath, visible, useTextMode, encryptText, STRONG_PASSWORD } from "./helpers";

/**
 * Decrypt-by-QR: upload a QR image and it fills the encrypted-text box, which
 * then opens with a password like any other paste.
 *
 * The QR under test is the one the app itself writes; this drives Encrypt,
 * opens the "Encrypted QR Code" dialog, and reads the rendered canvas back out
 * as a PNG. That is the exact artefact a user photographs or downloads, so a
 * round trip through it is the real path rather than a fixture that could drift
 * from what the encoder produces.
 *
 * The negative control is the blank-image case: an image with no QR must leave
 * the box empty and say so. Without it, a decoder that trusted the filename and
 * returned something plausible would pass the positive test just as well; the
 * blank case is what proves the pixels are actually read.
 */

/** A short secret whose container fits one QR symbol. */
const SECRET = "correct horse battery staple";

/**
 * Encrypt `SECRET`, open the QR dialog, and return the rendered QR as PNG bytes.
 *
 * qrcode.react draws a single `<canvas>`; the visible dialog copy is the 256px
 * one. `toDataURL` gives a lossless PNG of exactly the modules jsqr will read.
 */
async function encryptAndCaptureQr(page: Page): Promise<Buffer> {
  await useTextMode(page);
  await encryptText(page, SECRET, STRONG_PASSWORD);

  // Open the "Encrypted QR Code" dialog. The only visible QR-icon button on the
  // encrypt side is the Result toolbar's dialog trigger; the decrypt-side scan
  // button carries the same icon but sits under the inactive tab, so the
  // visible filter picks the right one.
  await visible(page.locator("button:has(svg.lucide-qr-code)")).click();

  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText("Encrypted QR Code")).toBeVisible();

  const dataUrl = await dialog.locator("canvas").first().evaluate((el) => {
    return (el as HTMLCanvasElement).toDataURL("image/png");
  });
  // Dismiss the dialog so it does not intercept later clicks.
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();

  return Buffer.from(dataUrl.split(",")[1]!, "base64");
}

/** A plain white PNG with no QR anywhere in it. */
async function blankPng(page: Page): Promise<Buffer> {
  const dataUrl = await page.evaluate(() => {
    const canvas = document.createElement("canvas");
    canvas.width = 256;
    canvas.height = 256;
    const ctx = canvas.getContext("2d")!;
    ctx.fillStyle = "#ffffff";
    ctx.fillRect(0, 0, 256, 256);
    return canvas.toDataURL("image/png");
  });
  return Buffer.from(dataUrl.split(",")[1]!, "base64");
}

test.describe("decrypt by scanning a QR image", () => {
  test("a scanned QR fills the box and the container opens with the password", async ({ page }) => {
    await page.goto(appPath("/"));

    const qrPng = await encryptAndCaptureQr(page);

    // Move to Decrypt / Text and hand the PNG to the scan input.
    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);

    await page.locator("#qr-scan-input").setInputFiles({
      name: "encrypted-qr.png",
      mimeType: "image/png",
      buffer: qrPng,
    });

    // The decoded armor lands in the encrypted-text box, exactly as a paste
    // would. `keym2:` is the v2 armor prefix.
    await page.waitForFunction(
      () => {
        const el = document.querySelector("#text-secret") as HTMLTextAreaElement | null;
        return !!el && el.value.startsWith("keym2:");
      },
      undefined,
      { timeout: 20_000 }
    );

    // From here it is the ordinary password unlock.
    await visible(page.getByPlaceholder("Enter decryption password")).fill(STRONG_PASSWORD);
    await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();

    await page.waitForFunction(
      () => {
        const el = document.querySelector("#output-text") as HTMLTextAreaElement | null;
        return !!el && el.value.length > 0 && !el.value.startsWith("keym2:");
      },
      undefined,
      { timeout: 90_000 }
    );

    const recovered = await page.evaluate(
      () => (document.querySelector("#output-text") as HTMLTextAreaElement).value
    );
    expect(recovered).toBe(SECRET);
  });

  test("an image with no QR is refused and leaves the box empty", async ({ page }) => {
    await page.goto(appPath("/"));

    const png = await blankPng(page);

    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);

    await page.locator("#qr-scan-input").setInputFiles({
      name: "not-a-qr.png",
      mimeType: "image/png",
      buffer: png,
    });

    // The failure is a scanning problem, reported as one, never routed into the
    // encrypted-text box, where an empty or garbage value would surface later as
    // a wrong-password error.
    // The message shows in both the toast body and an aria-live status region;
    // either being present proves the refusal surfaced.
    await expect(page.getByText(/No QR code was found/i).first()).toBeVisible();

    const boxValue = await page.evaluate(
      () => (document.querySelector("#text-secret") as HTMLTextAreaElement | null)?.value ?? ""
    );
    expect(boxValue).toBe("");
  });
});
