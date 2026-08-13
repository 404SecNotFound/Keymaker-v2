#!/usr/bin/env node
/**
 * Recapture the README screenshots from the production export.
 *
 * Run after `npm run build`:
 *   node scripts/static-server.mjs out 4323 &
 *   node scripts/capture-screenshots.mjs
 *
 * Why this exists as a script rather than a manual pass: the README leads with
 * a screenshot of the encrypt panel, and the panel's controls change. A shot
 * showing a button that has since been renamed is worse than no shot — it is a
 * confident, wrong answer to "what does this look like". Regenerating has to be
 * cheap enough that it actually happens.
 *
 * Framing is fixed here (1180 CSS wide at DPR 2) so re-runs produce drop-in
 * replacements rather than images that shift every time.
 *
 * Viewport crops, never fullPage: the footer is sticky, and a fullPage capture
 * paints a ghost copy of it across the top of the hero.
 */
import { chromium } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const SHOTS = join(HERE, '..', 'docs', 'screenshots');
const BASE = process.env.KEYMAKER_SHOT_URL || 'http://127.0.0.1:4323';

const VIEWPORT = { width: 1180, height: 1020 };
const SCALE = 2;

const browser = await chromium.launch();
const context = await browser.newContext({
  viewport: VIEWPORT,
  deviceScaleFactor: SCALE,
  colorScheme: 'dark',
  reducedMotion: 'reduce',
});
const page = await context.newPage();

const visible = (l) => l.locator('visible=true').first();

async function settle() {
  // Fonts drive layout; capturing before they load produces a shot with
  // different metrics than any user will ever see.
  await page.evaluate(() => document.fonts.ready);
  await page.waitForTimeout(400);
}

try {
  // ---- 01: landing, File mode, untouched ----
  await page.goto(BASE, { waitUntil: 'networkidle' });
  await settle();
  await page.screenshot({ path: join(SHOTS, '01-landing.png') });
  console.log('captured 01-landing.png');

  // ---- 10: the word passphrase generator, with its entropy statement ----
  // Text mode, and a taller viewport so the button row, the entropy line and
  // the toast are all in one frame.
  await page.setViewportSize({ width: 1180, height: 1340 });
  await visible(page.getByRole('button', { name: 'Text', exact: true })).click();
  // Ordinary prose, deliberately not BIP-39 words: seed detection would put a
  // red border on the field and the shot would read as an error state.
  await visible(page.getByPlaceholder('Enter text to encrypt')).fill(
    'Safe deposit box 447, Nationwide, Cheapside branch. Spare key with Rachel.'
  );
  await visible(page.getByRole('button', { name: /^Passphrase$/ })).click();
  // Reveal it — a blurred field would show nothing worth screenshotting.
  await visible(page.getByRole('button', { name: /^(Show|Hide)$/ })).click();
  await settle();
  await page.screenshot({ path: join(SHOTS, '10-passphrase-generator.png') });
  console.log('captured 10-passphrase-generator.png');
} finally {
  await context.close();
  await browser.close();
}
