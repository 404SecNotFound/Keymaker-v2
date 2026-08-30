/**
 * public/og-card.png, from scripts/og-card-template.html.
 *
 * A script rather than a remembered command line: the card has to be
 * regenerated whenever the palette, the hero plate or the wordmark changes,
 * and the one thing that must never happen is shipping a card in the previous
 * identity because the command was in someone's shell history and not in the
 * repository.
 *
 * Verified before it ships. A card whose background came out as the browser's
 * default white, or whose hero plate silently failed to load, looks fine in a
 * file listing and wrong in every link preview — so the corners are sampled
 * and must be the canvas colour.
 */
import { chromium } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = join(ROOT, 'public/og-card.png');
const CANVAS = [14, 13, 11];

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1200, height: 630 } });
await page.goto(`file://${join(ROOT, 'scripts/og-card-template.html')}`, { waitUntil: 'networkidle' });
await page.waitForTimeout(500);
await page.screenshot({ path: OUT });

const b64 = readFileSync(OUT).toString('base64');
const samples = await page.evaluate(
  (src) =>
    new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => {
        const c = document.createElement('canvas');
        c.width = img.width;
        c.height = img.height;
        const ctx = c.getContext('2d', { willReadFrequently: true });
        ctx.drawImage(img, 0, 0);
        const at = (x, y) => Array.from(ctx.getImageData(x, y, 1, 1).data).slice(0, 3);
        resolve({
          size: [img.width, img.height],
          topLeft: at(3, 3),
          bottomLeft: at(3, img.height - 4),
        });
      };
      img.onerror = () => reject(new Error('the written card could not be decoded'));
      img.src = src;
    }),
  `data:image/png;base64,${b64}`
);
await browser.close();

const near = (a) => a.every((v, i) => Math.abs(v - CANVAS[i]) <= 3);
const sizeOk = samples.size[0] === 1200 && samples.size[1] === 630;
const ok = sizeOk && near(samples.topLeft) && near(samples.bottomLeft);

console.log(`og-card: ${samples.size.join('x')}  topLeft=${samples.topLeft}  bottomLeft=${samples.bottomLeft}`);
if (!ok) {
  console.error('\nThe card did not render onto the canvas colour at 1200x630. Not shipping it.');
  process.exit(1);
}
console.log('Card renders on the Nightpaper canvas at the required size.');
