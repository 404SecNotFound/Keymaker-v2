import { test, expect, type Page } from "@playwright/test";

/**
 * The hero plate, measured in the pixels it actually paints.
 *
 * The plate used to sit under three suppressors at once — `opacity-40`, a
 * radial mask, and a canvas scrim laid over the middle of the frame — and the
 * result was a background you could not see: a lift of about two values out of
 * 255 over the canvas it sat on. Each layer had been added for a defensible
 * reason and nobody had measured what survived all three together.
 *
 * A sweep of the rendered page settled it. Across every combination from
 * 0.4-with-scrim to 1.0-without, the worst background behind the headline moved
 * only 9.3:1 to 9.0:1, while the plate itself went from 1.52x the canvas to
 * 2.07x. The scrim was costing a third of the image's visibility to buy 0.3:1
 * of contrast on a floor of 4.5. So it is gone, and what it was guarding is
 * asserted here instead.
 *
 * Both directions are checked on purpose, because each alone is a gate that
 * cannot fail in the way that matters:
 *
 *   - contrast alone passes perfectly on an invisible plate, which is the exact
 *     defect this file exists because of;
 *   - visibility alone passes on a plate so bright the headline is unreadable.
 *
 * Pixels come from a real screenshot decoded by the browser's own PNG decoder —
 * the shot is handed back to the page as a data URL and drawn to a canvas — so
 * nothing here re-implements compositing, and no decoding dependency is added
 * to a project that keeps its supply chain small on purpose.
 */

/** Nightpaper's canvas, the ground the plate is composited over. */
const CANVAS = { r: 0x0e, g: 0x0d, b: 0x0b };
/** `ink`, the headline's colour. */
const INK = { r: 0xf5, g: 0xf3, b: 0xf1 };

const channel = (c: number) => {
  const v = c / 255;
  return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
};
const luminance = (c: { r: number; g: number; b: number }) =>
  0.2126 * channel(c.r) + 0.7152 * channel(c.g) + 0.0722 * channel(c.b);
const contrast = (a: typeof INK, b: typeof INK) => {
  const la = luminance(a);
  const lb = luminance(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
};

/**
 * Screenshot a region and read it back as pixels.
 *
 * The decode happens inside the page: Playwright hands us PNG bytes, we hand
 * them back as a data URL, and the browser draws them to a canvas we can call
 * getImageData on. That keeps this measurement on real composited output
 * without pulling an image codec into package.json.
 */
async function pixels(page: Page, clip: { x: number; y: number; width: number; height: number }) {
  const png = await page.screenshot({ clip });
  const dataUrl = `data:image/png;base64,${png.toString("base64")}`;
  return page.evaluate(async (url) => {
    const img = new Image();
    img.src = url;
    await img.decode();
    const canvas = document.createElement("canvas");
    canvas.width = img.naturalWidth;
    canvas.height = img.naturalHeight;
    const ctx = canvas.getContext("2d")!;
    ctx.drawImage(img, 0, 0);
    const { data, width, height } = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const out: { r: number; g: number; b: number }[] = [];
    // Every fourth column and second row: enough samples to be stable, small
    // enough to cross the bridge back out of the page quickly.
    for (let y = 0; y < height; y += 2) {
      for (let x = 0; x < width; x += 4) {
        const i = (y * width + x) << 2;
        out.push({ r: data[i] as number, g: data[i + 1] as number, b: data[i + 2] as number });
      }
    }
    return out;
  }, dataUrl);
}

const nth = <T,>(sorted: T[], q: number) => sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * q))]!;

test.beforeEach(async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/");
  // The plate is a background image; nothing below should run before it paints.
  await page.locator('img[src*="hero-"]').first().waitFor({ state: "attached" });
  await page.waitForLoadState("networkidle");
});

test("the hero plate is actually visible against the canvas", async ({ page }) => {
  // A band above the headline, where the plate is the only thing painting.
  const band = await pixels(page, { x: 60, y: 40, width: 1320, height: 110 });
  const lums = band.map(luminance).sort((a, b) => a - b);
  const canvasL = luminance(CANVAS);

  const meanLift = lums.reduce((a, c) => a + c, 0) / lums.length / canvasL;
  const peakLift = nth(lums, 0.99) / canvasL;

  // As shipped: 2.32x mean, 10.24x peak. The floors are set from a measured
  // sweep of the thing they exist to catch rather than picked to look safe —
  // the first draft used 1.5x and 6.5x/3x, and re-dimming the plate to the
  // `opacity-40` it shipped with for weeks sailed straight through both.
  //
  //   opacity 1.0 (shipped)  2.32x mean  10.24x peak   pass
  //   opacity 0.8            2.04x        8.44x        pass
  //   opacity 0.6            1.83x        6.01x        FAIL
  //   opacity 0.4 (the bug)  1.66x        4.92x        FAIL
  //
  // The gap between shipped and the floor is ~25%, which is headroom for a
  // different plate and for the other two engines compositing slightly
  // differently, without letting a genuinely washed-out one through.
  expect(meanLift, "the plate is washed out — check opacity, the mask, and any scrim over it").toBeGreaterThan(1.85);
  expect(peakLift, "the plate has no bright detail left; its sparks have been suppressed away").toBeGreaterThan(6.5);
});

test("the headline still clears AA over the plate", async ({ page }) => {
  const box = (await page.locator("h1").first().boundingBox())!;
  const behind = await pixels(page, {
    x: Math.round(box.x),
    y: Math.round(box.y),
    width: Math.round(box.width),
    height: Math.round(box.height),
  });

  // The glyphs are in this region too. Keep only what is dark enough to be
  // background rather than letterform, then take the brightest of those: the
  // worst ground any part of the headline is sitting on.
  const ground = behind.filter((p) => luminance(p) < 0.2).sort((a, b) => luminance(a) - luminance(b));
  expect(ground.length, "found no background pixels behind the headline — the sample is wrong").toBeGreaterThan(50);

  const worst = nth(ground, 0.99);
  const ratio = contrast(INK, worst);

  // WCAG AA for large text is 3:1 and 4.5:1 for body; the headline is large but
  // held to the stricter floor. Measured at 9.0:1.
  expect(
    ratio,
    `the brightest ground behind the headline is rgb(${worst.r}, ${worst.g}, ${worst.b}), ` +
      "which the ink does not clear. The plate is too bright behind the words."
  ).toBeGreaterThan(4.5);
});
