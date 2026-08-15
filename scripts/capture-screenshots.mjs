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

/**
 * Capture the band of page running from the top of `from` to the bottom of `to`.
 *
 * The walkthrough shots have to frame a named stretch of a long scrolling
 * column — "the Advanced panel", "the result" — and a plain viewport capture
 * frames wherever the last click happened to scroll to. That is how the first
 * attempt at these cropped the KDF cards off the top of the very panel the
 * shot existed to show.
 *
 * Clipped rather than fullPage, for the reason at the top of this file: a
 * fullPage capture paints a ghost of the sticky footer across the page.
 */
async function shotRegion(from, to, path, pad = 20) {
  await from.scrollIntoViewIfNeeded();
  await page.evaluate((p) => window.scrollBy(0, -p), pad + 8);
  await settle();
  const a = await from.boundingBox();
  const b = await to.boundingBox();
  if (!a || !b) throw new Error(`shotRegion: ${path} — an anchor has no bounding box`);
  const { width, height: vh } = page.viewportSize();
  const y = Math.max(0, a.y - pad);
  const height = Math.min(b.y + b.height + pad - y, vh - y);
  if (height <= 0) throw new Error(`shotRegion: ${path} — anchors are not both on screen`);
  await page.screenshot({ path, clip: { x: 0, y, width, height } });
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
  // The name is the aria-label, not the visible text: U25 gave this toggle
  // `aria-label="Show password"` so a screen reader stops hearing "Show,
  // button" in both states. This script was still matching /^Show$/ and had
  // been failing since — nothing ran it, so nothing said so.
  await visible(page.getByRole('button', { name: /^(Show|Hide) password$/ })).click();
  await settle();
  await page.screenshot({ path: join(SHOTS, '10-passphrase-generator.png') });
  console.log('captured 10-passphrase-generator.png');

  // ---- docs/WALKTHROUGH.md ----
  //
  // Four shots, in the order the walkthrough tells the story. Captured here
  // rather than taken by hand for the reason at the top of this file, and it
  // binds harder for the walkthrough than for the README: the walkthrough
  // tells someone which control to click *next*, so a stale image is a wrong
  // instruction rather than a dated illustration.
  //
  // tests/browser/walkthrough.spec.ts drives the same path and asserts the
  // outcomes, so the prose and the images fail together rather than one of
  // them rotting quietly.
  const WT_SECRET =
    'Emergency kit — the password manager master password is in the sealed\n' +
    'envelope in the safe. Recovery codes: 4471-0092, 8823-5510, 6104-7735.';
  const WT_PASSWORD = 'Ridge-Blender-Oakwood-Marina-72!';

  // A tall viewport so a whole panel fits in one frame; shotRegion clips the
  // band that matters, so the extra height costs nothing in the output.
  await page.setViewportSize({ width: 1180, height: 1800 });
  await page.goto(BASE, { waitUntil: 'networkidle' });
  await visible(page.getByRole('button', { name: 'Text', exact: true })).click();
  await visible(page.getByPlaceholder('Enter text to encrypt')).fill(WT_SECRET);

  // 1: the Advanced panel — the KDF, the cipher, and the "Effective
  // configuration" line that states in one string what the container will say
  // about itself when it is opened years later.
  await visible(page.getByRole('button', { name: /^Advanced/ })).click();
  await visible(page.getByRole('button').filter({ hasText: 'Argon2id' })).click();
  await visible(page.getByRole('button').filter({ hasText: 'AES \u2192 ChaCha (chained)' })).click();
  await shotRegion(
    visible(page.getByText('Key derivation', { exact: true })),
    visible(page.getByText(/^Effective configuration:/)),
    join(SHOTS, 'walkthrough-1-protection.png')
  );
  console.log('captured walkthrough-1-protection.png');

  // 2: the password field and what the app is willing to say about it — a
  // policy floor, deliberately not a strength score. Revealed, because a
  // blurred field illustrates nothing.
  await visible(page.getByRole('button', { name: /^Advanced/ })).click();
  await visible(page.getByPlaceholder('Enter a strong password')).fill(WT_PASSWORD);
  await visible(page.getByRole('button', { name: /^(Show|Hide) password$/ })).click();
  await shotRegion(
    visible(page.getByPlaceholder('Enter text to encrypt')),
    visible(page.getByRole('button', { name: /^Encrypt Text$/i })),
    join(SHOTS, 'walkthrough-2-password.png')
  );
  console.log('captured walkthrough-2-password.png');

  // 3: the container. The shot that shows what the reader is meant to keep.
  await visible(page.getByRole('button', { name: /^Encrypt Text$/i })).click();
  await page.waitForFunction(
    () => {
      const el = document.querySelector('#output-text');
      return !!el && el.value.startsWith('keym2:');
    },
    null,
    { timeout: 90_000 }
  );
  await shotRegion(
    visible(page.getByText(/^Result/)),
    page.locator('#output-text'),
    join(SHOTS, 'walkthrough-3-container.png')
  );
  console.log('captured walkthrough-3-container.png');

  const container = await page.evaluate(() => document.querySelector('#output-text').value);

  // 4: verify-only. The step the walkthrough argues hardest for — proving the
  // backup opens while the original is still there to re-make it from.
  await visible(page.getByRole('tab', { name: 'Decrypt' })).click();
  await visible(page.getByRole('button', { name: 'Text', exact: true })).click();
  await visible(page.getByPlaceholder('Enter text to decrypt')).fill(container);
  await visible(page.getByPlaceholder('Enter decryption password')).fill(WT_PASSWORD);
  await visible(page.getByLabel(/Verify only/i)).click();
  await visible(page.getByRole('button', { name: /^Verify Text$/i })).click();
  // The result panel, not any text containing "opens" — the toggle's own
  // description says "still opens with this password", and matching that
  // produced a shot of the toggle and nothing else.
  const verdict = visible(page.getByRole('status').filter({ hasText: /backup opens/i }));
  await verdict.waitFor({ timeout: 90_000 });
  await shotRegion(
    visible(page.getByLabel(/Verify only/i)),
    verdict,
    join(SHOTS, 'walkthrough-4-verified.png')
  );
  console.log('captured walkthrough-4-verified.png');
} finally {
  await context.close();
  await browser.close();
}
