/**
 * The PWA icons, rendered from public/logo.svg.
 *
 * A script rather than three binaries someone remembers to redraw: the icons
 * are the logo on the canvas colour, and both of those live in exactly one
 * place each — the SVG and docs/design/DESIGN-SYSTEM.md. Regenerate with
 * `node scripts/make-icons.mjs` after either changes.
 *
 * The SVG is inlined into the page rather than referenced with <img src>. A
 * file:// image inside setContent() does not load, and the failure is silent:
 * the previous icons carried a pale blue fringe in every corner because the
 * page was screenshotting a broken image over an unpainted root. Inlining
 * removes the fetch, and painting `html` as well as `body` removes the
 * engine's default ground, which is what the fringe actually was.
 *
 * Every icon is verified by sampling its own pixels before this exits — a
 * renderer that quietly produced the wrong thing is the whole reason this
 * file has a comment this long.
 */
import { chromium } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const CANVAS = '#0E0D0B';
const CANVAS_RGB = [14, 13, 11];
const SIZES = [
  [192, 'icon-192x192.png'],
  [512, 'icon-512x512.png'],
  [1024, 'apple-touch-icon.png'],
];

const svg = readFileSync(join(ROOT, 'public/logo.svg'), 'utf8');
const browser = await chromium.launch();

for (const [px, name] of SIZES) {
  const page = await browser.newPage({ viewport: { width: px, height: px } });
  await page.setContent(
    `<!doctype html><html style="background:${CANVAS}"><body style="margin:0;background:${CANVAS}">` +
      `<div style="width:${px}px;height:${px}px">${svg.replace('<svg ', `<svg width="${px}" height="${px}" `)}</div>` +
      `</body></html>`,
    { waitUntil: 'load' }
  );
  await page.screenshot({ path: join(ROOT, 'public', name) });
  await page.close();
}
await browser.close();

let bad = 0;
// Read the written files back through the browser's own decoder rather than a
// PNG library: no new dependency, and it samples the bytes that actually
// shipped instead of the page they came from.
const verifier = await (await chromium.launch()).newPage();
for (const [, name] of SIZES) {
  const b64 = readFileSync(join(ROOT, 'public', name)).toString('base64');
  const [corner, keyhole] = await verifier.evaluate(
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
          resolve([at(2, 2), at(img.width >> 1, Math.round(img.height * 0.4))]);
        };
        img.onerror = () => reject(new Error('the written icon could not be decoded'));
        img.src = src;
      }),
    `data:image/png;base64,${b64}`
  );
  // Outside the 24%-radius corner is canvas; the keyhole is masked out, so it
  // is canvas too. If either is anything else the render went wrong.
  const near = (a) => a.every((v, i) => Math.abs(v - CANVAS_RGB[i]) <= 2);
  const ok = near(corner) && near(keyhole);
  if (!ok) bad++;
  console.log(`${name.padEnd(22)} corner=${corner} keyhole=${keyhole} ${ok ? 'ok' : 'WRONG'}`);
}
await verifier.context().browser().close();

if (bad) {
  console.error(`\n${bad} icon(s) did not render onto ${CANVAS}. Not shipping them.`);
  process.exit(1);
}
console.log(`\nAll ${SIZES.length} icons render the logo on ${CANVAS}.`);
