import { test, expect, chromium } from "@playwright/test";
import type { Page } from "@playwright/test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { visible, useTextMode, selectCrypto, capturePrintedSymbols, STRONG_PASSWORD } from "./helpers";

/**
 * Live camera scanning, against a camera that is really a file.
 *
 * Chromium can be told to use a video file as its camera
 * (`--use-file-for-fake-video-capture`) and to allow it without a prompt
 * (`--use-fake-ui-for-media-stream`). The file here is built from the real
 * print sheet's strip symbols, so the scanner sees what a person would hold up:
 * strip 1, a moment of nothing, strip 3, looping. It must read both, say what
 * is still needed in between, stop on its own once two are in, and leave them
 * in the shares box, where they open the backup with no password.
 *
 * The flags have to be given at launch, and the video can only be made once the
 * strips exist, so this test launches its own browser for the second half.
 * Chromium only: the flags are Chromium's.
 */

const SECRET = "held up to the camera, one strip after another";
const W = 640;
const H = 480;
const FPS = 15;

/** RGBA frames from strip PNGs, drawn centred on white by the page itself. */
async function framesFrom(page: Page, pngs: Buffer[]): Promise<Uint8ClampedArray[]> {
  const b64 = await page.evaluate(
    async ({ sources, w, h }) => {
      const out: string[] = [];
      for (const src of sources) {
        const canvas = document.createElement("canvas");
        canvas.width = w;
        canvas.height = h;
        const ctx = canvas.getContext("2d")!;
        ctx.fillStyle = "#ffffff";
        ctx.fillRect(0, 0, w, h);
        if (src) {
          const img = new Image();
          img.src = src;
          await img.decode();
          const size = Math.min(w, h) - 40;
          ctx.drawImage(img, (w - size) / 2, (h - size) / 2, size, size);
        }
        const data = ctx.getImageData(0, 0, w, h).data;
        let bin = "";
        for (let i = 0; i < data.length; i += 0x8000) {
          bin += String.fromCharCode(...data.subarray(i, i + 0x8000));
        }
        out.push(btoa(bin));
      }
      return out;
    },
    { sources: pngs.map((b) => (b.length ? `data:image/png;base64,${b.toString("base64")}` : "")), w: W, h: H }
  );
  return b64.map((s) => new Uint8ClampedArray(Buffer.from(s, "base64")));
}

/** One RGBA frame as a Y4M 4:2:0 frame (full-range BT.601, `C420jpeg`). */
function toI420(rgba: Uint8ClampedArray): Buffer {
  const y = Buffer.alloc(W * H);
  const u = Buffer.alloc((W / 2) * (H / 2));
  const v = Buffer.alloc((W / 2) * (H / 2));
  for (let j = 0; j < H; j++) {
    for (let i = 0; i < W; i++) {
      const k = (j * W + i) * 4;
      const r = rgba[k] as number;
      const g = rgba[k + 1] as number;
      const b = rgba[k + 2] as number;
      y[j * W + i] = Math.round(0.299 * r + 0.587 * g + 0.114 * b);
      if (j % 2 === 0 && i % 2 === 0) {
        const c = (j / 2) * (W / 2) + i / 2;
        u[c] = Math.max(0, Math.min(255, Math.round(128 - 0.168736 * r - 0.331264 * g + 0.5 * b)));
        v[c] = Math.max(0, Math.min(255, Math.round(128 + 0.5 * r - 0.418688 * g - 0.081312 * b)));
      }
    }
  }
  return Buffer.concat([Buffer.from("FRAME\n"), y, u, v]);
}

test("strips held up to the camera, one after another, open the backup", async ({ page, browserName }, testInfo) => {
  test.skip(browserName !== "chromium", "the fake-camera flags are Chromium's");

  // First half: an ordinary page makes the backup and prints its strips.
  await page.goto("/");
  await useTextMode(page);
  await selectCrypto(page, "pbkdf2", "aes");
  const advanced = visible(page.getByRole("button", { name: /^Advanced/ }));
  if ((await advanced.getAttribute("aria-expanded")) !== "true") await advanced.click();
  const sharesSwitch = visible(page.getByRole("switch", { name: "Recovery shares" }));
  await expect(async () => {
    if ((await sharesSwitch.getAttribute("aria-checked")) !== "true") await sharesSwitch.click();
    await expect(sharesSwitch).toHaveAttribute("aria-checked", "true", { timeout: 1_000 });
  }).toPass({ timeout: 20_000 });
  await visible(page.getByPlaceholder("Enter text to encrypt")).fill(SECRET);
  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
  await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();
  await expect(page.getByText(/Save these 3 shares now/)).toBeVisible({ timeout: 90_000 });
  const shares = (await page.locator("p.font-mono").allTextContents()).filter((s) => s.startsWith("KMSHARE2:"));
  const printed = await capturePrintedSymbols(
    page,
    page.getByRole("dialog").getByRole("button", { name: /Print paper vault/i })
  );
  await page.getByRole("button", { name: "I have saved these shares" }).click();
  const armored = await page.evaluate(() => (document.querySelector("#output-text") as HTMLTextAreaElement).value);

  // The camera's footage: strip 1, nothing, strip 3, nothing; Chromium loops it.
  const [one, blank, three] = await framesFrom(page, [
    printed.strips[0] as Buffer,
    Buffer.alloc(0),
    printed.strips[2] as Buffer,
  ]);
  const sequence = [...Array(FPS).fill(one), ...Array(FPS / 3).fill(blank), ...Array(FPS).fill(three), ...Array(FPS / 3).fill(blank)];
  const dir = mkdtempSync(join(tmpdir(), "km-camera-"));
  const video = join(dir, "strips.y4m");
  writeFileSync(
    video,
    Buffer.concat([Buffer.from(`YUV4MPEG2 W${W} H${H} F${FPS}:1 Ip A1:1 C420jpeg\n`), ...sequence.map(toI420)])
  );

  // Second half: a browser whose camera is that file.
  const browser = await chromium.launch({
    args: [
      "--use-fake-device-for-media-stream",
      "--use-fake-ui-for-media-stream",
      `--use-file-for-fake-video-capture=${video}`,
    ],
  });
  try {
    const context = await browser.newContext({ baseURL: testInfo.project.use.baseURL ?? "http://127.0.0.1:4321" });
    await context.grantPermissions(["camera"]);
    const cam = await context.newPage();
    await cam.goto("/");
    await visible(cam.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(cam);
    await visible(cam.getByPlaceholder("Enter text to decrypt")).fill(armored);
    await visible(cam.getByRole("button", { name: /^Use recovery shares$/ })).click();
    await visible(cam.getByRole("button", { name: "Scan strips with the camera" })).click();

    const dialog = cam.getByTestId("camera-scan");
    await expect(dialog).toBeVisible();
    // After the first strip, and before the second, it says what is missing.
    await expect(cam.getByTestId("camera-progress")).toContainText(/1 of the 2 needed\. Show the next strip\./, {
      timeout: 30_000,
    });
    // With two in, it stops by itself.
    await expect(dialog).toBeHidden({ timeout: 30_000 });

    const lines = (await visible(cam.locator("#share-input")).inputValue())
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("#"));
    expect(lines.sort()).toEqual([shares[0], shares[2]].sort());

    await visible(cam.getByRole("button", { name: /^Decrypt Text$/i })).click();
    await expect(visible(cam.locator("#output-text"))).toHaveValue(SECRET, { timeout: 90_000 });
  } finally {
    await browser.close();
  }
});
