#!/usr/bin/env node
/**
 * Every README and walkthrough screenshot is one width.
 *
 * docs/design/DESIGN-SYSTEM.md § Screenshots fixes the capture width at the
 * viewport (1180 CSS) times the device scale (2) — 2360px intrinsic — so the
 * folder listing and the rendered README read as one set rather than a ragged
 * pile. The two shots that broke this were captured with element
 * `.screenshot()`, which frames the element edge-to-edge at its own width
 * (960 and 1024); nothing failed when they did, so nothing said so. This gate
 * is that "nothing".
 *
 * Width only. Height follows content by design (a band is as tall as the panel
 * it frames), so it is deliberately not checked.
 *
 * No build and no browser: it reads the committed PNG headers directly, so it
 * belongs in the first cheap CI job rather than waiting on `out/`.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const SHOTS = join(HERE, '..', 'docs', 'screenshots');

// Must match VIEWPORT.width * SCALE in scripts/capture-screenshots.mjs.
const VIEWPORT_WIDTH = 1180;
const SCALE = 2;
const EXPECTED = VIEWPORT_WIDTH * SCALE;

function pngSize(file) {
  const buf = readFileSync(file);
  // 8-byte signature, then the IHDR chunk: length(4) + "IHDR"(4) + width(4, BE)
  // + height(4, BE). IHDR is mandated first by the spec, so this is enough.
  if (buf.length < 24 || buf.toString('ascii', 12, 16) !== 'IHDR') {
    throw new Error(`${file} is not a PNG whose header this check understands`);
  }
  return { width: buf.readUInt32BE(16), height: buf.readUInt32BE(20) };
}

const files = readdirSync(SHOTS)
  .filter((f) => f.endsWith('.png'))
  .sort();

if (files.length === 0) {
  console.error('screenshot-audit: FAILED — no PNGs in docs/screenshots/.');
  process.exit(1);
}

const offenders = [];
const heights = [];
for (const name of files) {
  const { width, height } = pngSize(join(SHOTS, name));
  heights.push(height);
  if (width !== EXPECTED) offenders.push({ name, width });
}

if (offenders.length) {
  for (const o of offenders) {
    console.error(
      `screenshot-audit: ${o.name} is ${o.width}px wide, not ${EXPECTED}. ` +
        'Recapture with scripts/capture-screenshots.mjs — a viewport-width band, ' +
        'never an element .screenshot().'
    );
  }
  console.error(
    `\nscreenshot-audit: FAILED — ${offenders.length} of ${files.length} shot(s) off-width.\n` +
      `§ Screenshots fixes every shot at ${EXPECTED}px (viewport ${VIEWPORT_WIDTH} × DPR ${SCALE}).`
  );
  process.exit(1);
}

console.log(
  `screenshot-audit: ${files.length} shots, all ${EXPECTED}px wide ` +
    `(heights ${Math.min(...heights)}–${Math.max(...heights)}). ` +
    'docs/design/DESIGN-SYSTEM.md § Screenshots holds.'
);
