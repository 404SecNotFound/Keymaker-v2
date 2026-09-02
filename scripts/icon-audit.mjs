/**
 * The icon gate.
 *
 * docs/design/DESIGN-SYSTEM.md § Icons rations lucide to three sizes, each with
 * a job: 14px inline, 16px standalone and in controls, 20px display. The reason
 * is that lucide draws a 2-unit stroke on a 24 grid, so the painted line weight
 * is a function of the height — six sizes is six line weights in one family,
 * and that is what reads as inconsistent long before anyone notices a glyph.
 *
 * This walks the rendered page rather than the source, for the same reason the
 * palette gate does, and here the reason is not hypothetical. The button base
 * carries `[&_svg]:size-4`, a class-plus-type selector that outranks the `.h-5`
 * on the icon itself, so an icon authored at 20px inside a button paints at 16
 * and no amount of reading the JSX will tell you. Only the computed box does.
 *
 *     node scripts/icon-audit.mjs               # against out/ on a free port
 *     KEYMAKER_SHOT_URL=http://… node scripts/icon-audit.mjs
 *
 * Exits non-zero and names every offender by its lucide class.
 *
 * Scope is `svg.lucide` — the class the library stamps on every icon it draws.
 * The logo is a fill-based mark on a 512 grid with no stroke and no such class,
 * so it is not covered, which is correct: it is not part of the icon family.
 */

import { spawn } from 'node:child_process';
import { chromium } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const PORT = 4735;
const BASE = process.env.KEYMAKER_SHOT_URL || `http://127.0.0.1:${PORT}`;

/**
 * Transcribed from the design document, not read back out of the stylesheet.
 * Deriving these from the CSS would make the gate agree with whatever the CSS
 * currently says, which is a gate that cannot fail.
 */
const SIZES = new Map([
  [14, 'inline (h-3.5)'],
  [16, 'standalone or in a control (h-4)'],
  [20, 'display (h-5)'],
]);
const STROKE = '2px';

/** Every lucide icon the current view has painted. */
const scan = (page, view) =>
  page.evaluate((v) => {
    const seen = [];
    for (const svg of document.querySelectorAll('svg.lucide')) {
      const cs = getComputedStyle(svg);
      const box = svg.getBoundingClientRect();
      // Skip what is not laid out: a display:none subtree reports 0 and is not
      // painting anything a reader could call inconsistent.
      if (box.width === 0 && box.height === 0) continue;
      const name = [...svg.classList].find((c) => c.startsWith('lucide-')) || 'lucide-(unnamed)';
      seen.push({
        view: v,
        name,
        w: Math.round(parseFloat(cs.width)),
        h: Math.round(parseFloat(cs.height)),
        stroke: cs.strokeWidth,
        authored: [...svg.classList].filter((c) => /^[hw]-/.test(c)).join(' ') || '(no size class)',
        inControl: !!svg.closest('button, a[role="button"], [role="switch"]'),
      });
    }
    return seen;
  }, view);

const server = spawn('node', [join(ROOT, 'scripts/static-server.mjs'), 'out', String(PORT)], {
  cwd: ROOT,
  stdio: 'ignore',
});
await new Promise((r) => setTimeout(r, 1200));

const icons = [];
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 1050 } });

try {
  await page.goto(BASE, { waitUntil: 'networkidle' });
  icons.push(...(await scan(page, 'encrypt')));

  const advanced = page.getByRole('button', { name: /^Advanced/ }).locator('visible=true').first();
  await advanced.click();
  await page.waitForTimeout(400);
  icons.push(...(await scan(page, 'encrypt · advanced')));

  // Seed Phrase mode with a word flagged: the status line's glyph and the
  // reveal toggle are icons no other view paints.
  await page.getByRole('button', { name: 'Seed phrase', exact: true }).locator('visible=true').first().click();
  const seedWords = 'legal winner thank year wave sausage wotrh useful legal winner thank yellow'.split(' ');
  for (const [i, w] of seedWords.entries()) {
    await page
      .getByRole('combobox', { name: `Word ${i + 1}`, exact: true })
      .locator('visible=true')
      .first()
      .fill(w);
  }
  await page.getByRole('combobox', { name: 'Word 12', exact: true }).locator('visible=true').first().blur();
  await page.waitForTimeout(400);
  icons.push(...(await scan(page, 'encrypt · seed grid')));

  for (const tab of ['Decrypt', 'Tools']) {
    await page.getByRole('tab', { name: tab }).locator('visible=true').first().click();
    await page.waitForTimeout(400);
    icons.push(...(await scan(page, tab.toLowerCase())));
  }

  // Dialogs portal to the end of <body>, so the sweeps above never reach them.
  await page.getByRole('tab', { name: 'Encrypt' }).locator('visible=true').first().click();
  await page.getByRole('button', { name: /Recovery kit/ }).locator('visible=true').first().click();
  await page.getByRole('dialog').waitFor({ state: 'visible', timeout: 15_000 });
  await page.waitForTimeout(400);
  icons.push(...(await scan(page, 'recovery dialog')));
  await page.keyboard.press('Escape');

  // The command bar portals like the recovery dialog and gets the same walk.
  await page.keyboard.press('Control+k');
  await page.getByRole('dialog', { name: 'Command menu' }).waitFor({ state: 'visible', timeout: 15_000 });
  await page.waitForTimeout(400);
  icons.push(...(await scan(page, 'command bar')));
  await page.keyboard.press('Escape');

  await page.goto(`${BASE}/verify.html`, { waitUntil: 'networkidle' });
  icons.push(...(await scan(page, 'verify')));
} finally {
  await browser.close();
  server.kill();
}

// A run that found nothing would report success having checked nothing, which
// is the failure mode this repository keeps finding in its own gates. The
// number is deliberately far below the real count so it never needs updating.
if (icons.length < 20) {
  console.error(
    `icon-audit: ERROR — only ${icons.length} lucide icon(s) rendered across the views. ` +
      'Either the library stopped stamping the `lucide` class, or the walk is no longer ' +
      'reaching the app. Either way this run checked nothing. Fix the scan, not this floor.'
  );
  process.exit(1);
}

const badSize = icons.filter((i) => !SIZES.has(i.w) || i.w !== i.h);
const badStroke = icons.filter((i) => i.stroke !== STROKE);

if (badSize.length || badStroke.length) {
  for (const i of badSize) {
    console.error(
      `icon-audit: ${i.view} — ${i.name} paints ${i.w}×${i.h}, which § Icons does not name. ` +
        `Authored ${i.authored}${i.inControl ? ' (inside a control, where the base forces 16)' : ''}.`
    );
  }
  for (const i of badStroke) {
    console.error(
      `icon-audit: ${i.view} — ${i.name} has stroke-width ${i.stroke}, not ${STROKE}. ` +
        'The family sets weight by size alone; nothing may set it by hand.'
    );
  }
  console.error(
    `\nicon-audit: FAILED — ${badSize.length + badStroke.length} of ${icons.length} icon(s) off-system.\n` +
      'Allowed: ' +
      [...SIZES].map(([px, job]) => `${px}px ${job}`).join(', ') +
      '.'
  );
  process.exit(1);
}

const histogram = [...SIZES.keys()]
  .map((px) => `${icons.filter((i) => i.w === px).length}×${px}px`)
  .join(', ');
console.log(`icon-audit: ${icons.length} lucide icons across 8 views — ${histogram}\n`);
console.log(`All icons are a size docs/design/DESIGN-SYSTEM.md names, at stroke ${STROKE}.`);
