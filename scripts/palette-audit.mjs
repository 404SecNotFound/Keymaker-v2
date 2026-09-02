/**
 * The palette gate.
 *
 * docs/design/DESIGN-SYSTEM.md makes one claim that is easy to write down and
 * very hard to keep by proofreading: every ground shares one warm hue family,
 * and a cool or neutral grey anywhere is the defect the palette exists to
 * prevent. Nothing enforced it. The washes this replaced — `bg-white/4` and
 * friends — were exactly how the rule got broken, because a white wash over a
 * warm ground pulls it toward neutral by construction and no one reviewing a
 * class name would see it.
 *
 * So this walks the rendered page rather than the source, reads the *computed*
 * colour of every element, and fails on anything that is not a value the
 * system named. Computed, because that is the only place a wash, an opacity
 * modifier, and an inherited colour all resolve to the thing a user actually
 * sees.
 *
 *     node scripts/palette-audit.mjs            # against out/ on a free port
 *     KEYMAKER_SHOT_URL=http://… node scripts/palette-audit.mjs
 *
 * Exits non-zero and names every offender with the selector that carries it.
 */

import { spawn } from 'node:child_process';
import { chromium } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const PORT = 4732;
const BASE = process.env.KEYMAKER_SHOT_URL || `http://127.0.0.1:${PORT}`;

/**
 * The palette, as hex, from docs/design/DESIGN-SYSTEM.md.
 *
 * Written out rather than parsed from CSS on purpose: parsing the stylesheet
 * would make the gate agree with whatever the stylesheet currently says, which
 * is a gate that cannot fail. These are transcribed from the design document,
 * so a token that drifts away from the document fails here.
 */
const ALLOWED = new Set(
  [
    // Surfaces
    '#0e0d0b', '#171512', '#1d1a17', '#262320', '#292521', '#3a342e',
    // Text
    '#f5f3f1', '#a9a29a', '#918a83',
    // Primary action and its ink
    '#fdfcfc', '#14120f',
    // Semantic status — data, not decoration
    '#53b37e', '#d9a23f', '#e5624e',
    // The spark cuts § "The sparks — quarantined" permits for data-viz
    // strokes on dark grounds. Membership is what this gate can check; the
    // "viz only" clause — marks, never text, never chrome — is the reviewer's
    // to hold, and the container inspector's byte map is the one sanctioned
    // user today.
    '#5c7fff', '#ff7a47',
    // Absolutes that are always legitimate
    '#000000', '#ffffff',
  ].map((h) => h.toLowerCase())
);

/** How far a rendered colour may sit from a named one and still count as it. */
const TOLERANCE = 10;

/**
 * The text scale and the grounds it can be drawn on, from the same document.
 *
 * Membership was the only thing this gate checked, and membership cannot see
 * the defect it missed: every colour involved was a named one, and the pair
 * they formed was still under AA. `muted` was raised once to clear 4.5:1 on
 * `canvas` and sat at 4.45:1 on `inset` afterwards — the ground its own row
 * describes it as living on — because the table had a single "on canvas"
 * column and the fix measured the column.
 *
 * A token does not have a contrast ratio; a pair does. Every pair is checked
 * below, and the check is arithmetic on constants, so it runs before the
 * browser starts and fails in milliseconds.
 *
 * What this does NOT establish: that the app only ever composes these pairs.
 * It proves the palette cannot fail. The membership sweep further down is what
 * keeps an element from inventing a ground that is not on the list.
 */
const TEXT_TOKENS = { ink: '#f5f3f1', body: '#a9a29a', muted: '#918a83' };
const GROUND_TOKENS = {
  canvas: '#0e0d0b',
  card: '#171512',
  inset: '#1d1a17',
  raised: '#262320',
};
const AA_FLOOR = 4.5;

const channels = (hex) =>
  [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);

const relativeLuminance = (hex) => {
  const [r, g, b] = channels(hex).map((c) =>
    c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4)
  );
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};

const contrast = (a, b) => {
  const [x, y] = [relativeLuminance(a), relativeLuminance(b)];
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
};

const underFloor = [];
for (const [textName, text] of Object.entries(TEXT_TOKENS)) {
  for (const [groundName, ground] of Object.entries(GROUND_TOKENS)) {
    const ratio = contrast(text, ground);
    if (ratio < AA_FLOOR) {
      underFloor.push({ textName, text, groundName, ground, ratio });
    }
  }
}

if (underFloor.length) {
  console.error(
    `FAIL — ${underFloor.length} text/ground pair(s) below the ${AA_FLOOR}:1 AA floor:\n`
  );
  for (const p of underFloor) {
    console.error(
      `  ${p.textName} ${p.text} on ${p.groundName} ${p.ground} — ${p.ratio.toFixed(2)}:1`
    );
  }
  console.error(
    '\nDESIGN-SYSTEM.md says the floor overrides the palette. Lift the text\n' +
      'token until it clears on every ground, and update its row: the table\n' +
      'carries one column per ground precisely so a fix cannot measure one\n' +
      'and call it done.'
  );
  process.exit(1);
}

const hexOf = (r, g, b) =>
  '#' + [r, g, b].map((n) => n.toString(16).padStart(2, '0')).join('');

function nearestAllowed(r, g, b) {
  let best = null;
  let bestDist = Infinity;
  for (const hex of ALLOWED) {
    const ar = parseInt(hex.slice(1, 3), 16);
    const ag = parseInt(hex.slice(3, 5), 16);
    const ab = parseInt(hex.slice(5, 7), 16);
    const d = Math.max(Math.abs(r - ar), Math.abs(g - ag), Math.abs(b - ab));
    if (d < bestDist) {
      bestDist = d;
      best = hex;
    }
  }
  return { hex: best, distance: bestDist };
}

function hueOf(r, g, b) {
  const [rn, gn, bn] = [r / 255, g / 255, b / 255];
  const max = Math.max(rn, gn, bn);
  const min = Math.min(rn, gn, bn);
  const d = max - min;
  if (d === 0) return { hue: null, sat: 0 };
  let h;
  if (max === rn) h = ((gn - bn) / d) % 6;
  else if (max === gn) h = (bn - rn) / d + 2;
  else h = (rn - gn) / d + 4;
  h = Math.round(h * 60);
  if (h < 0) h += 360;
  const l = (max + min) / 2;
  return { hue: h, sat: d / (1 - Math.abs(2 * l - 1)) };
}

const PROPS = [
  'backgroundColor',
  'color',
  'borderTopColor',
  'borderRightColor',
  'borderBottomColor',
  'borderLeftColor',
  'outlineColor',
];

async function scan(page, label) {
  return page.evaluate(
    ({ props, label }) => {
      const out = [];
      const unreadable = [];
      // A 1x1 canvas is the only colour parser guaranteed to agree with the
      // renderer: whatever notation the stylesheet used — oklch, color(),
      // a named colour, a relative colour — this is the value that gets
      // painted.
      const cv = document.createElement('canvas');
      cv.width = cv.height = 1;
      const ctx = cv.getContext('2d', { willReadFrequently: true });
      // fillStyle silently keeps its previous value when handed something it
      // cannot parse, so "did it change?" cannot tell an unparseable value
      // from a value that happens to equal the sentinel. Two different
      // sentinels can: a parseable value lands on the same colour from both
      // starting points, an unparseable one keeps whichever sentinel it
      // started from. (Asking whether the value looked like black is what
      // this replaced, and it reported every genuine rgb(0,0,0) as broken.)
      const resolveFrom = (sentinel, value) => {
        ctx.fillStyle = sentinel;
        ctx.fillStyle = value;
        ctx.clearRect(0, 0, 1, 1);
        ctx.fillRect(0, 0, 1, 1);
        return Array.from(ctx.getImageData(0, 0, 1, 1).data);
      };
      const probe = (value) => {
        const a = resolveFrom('#ff0000', value);
        const b = resolveFrom('#0000ff', value);
        if (a.join() !== b.join()) return null;
        return a;
      };
      for (const el of document.querySelectorAll('*')) {
        const cs = getComputedStyle(el);
        if (cs.display === 'none' || cs.visibility === 'hidden') continue;
        const box = el.getBoundingClientRect();
        if (box.width === 0 || box.height === 0) continue;
        for (const prop of props) {
          const raw = cs[prop];
          if (!raw || raw === 'transparent' || raw === 'none') continue;
          // Normalised by the browser rather than parsed here. Tailwind v4
          // emits its default palette in oklch, and the regex this replaced
          // matched only rgb()/rgba() — so every oklch colour was skipped in
          // silence, which is how a slate grey injected as a control walked
          // straight through a "passing" audit. Anything the canvas cannot
          // resolve is counted and reported rather than dropped.
          const px = probe(raw);
          if (!px) {
            unreadable.push({ raw, prop, label });
            continue;
          }
          const [pr, pg, pb, pa] = px;
          const m = [null, pr, pg, pb, pa / 255];
          const alpha = pa / 255;
          // A fully transparent colour paints nothing, and a border colour on
          // an element with no border width is never drawn.
          if (alpha === 0) continue;
          if (prop.startsWith('border')) {
            const side = prop.replace('border', '').replace('Color', '');
            if (parseFloat(cs[`border${side}Width`]) === 0) continue;
            if (cs[`border${side}Style`] === 'none') continue;
          }
          if (prop === 'outlineColor' && parseFloat(cs.outlineWidth) === 0) continue;
          out.push({
            r: Math.round(+m[1]),
            g: Math.round(+m[2]),
            b: Math.round(+m[3]),
            alpha,
            prop,
            label,
            tag: el.tagName.toLowerCase(),
            cls: (typeof el.className === 'string' ? el.className : '').slice(0, 90),
          });
        }
      }
      return { out, unreadable };
    },
    { props: PROPS, label }
  );
}

const server = spawn('node', [join(ROOT, 'scripts/static-server.mjs'), 'out', String(PORT)], {
  cwd: ROOT,
  stdio: 'ignore',
});
await new Promise((r) => setTimeout(r, 1200));

const VIEWS = 11;
const unreadable = [];
const collect = ({ out, unreadable: bad }) => {
  samples.push(...out);
  unreadable.push(...bad);
};

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 1050 } });
const samples = [];

try {
  await page.goto(BASE, { waitUntil: 'networkidle' });
  collect(await scan(page, 'encrypt'));

  // The inspector's sealed status, opened and with its in-place check run:
  // the one place the page paints a success wash for a fact about itself.
  // Waits for the worker's precache so the check reaches the "match" state
  // rather than the "try again in a moment" one.
  await page.waitForFunction(() => navigator.serviceWorker?.controller !== null, null, { timeout: 30_000 });
  await page.waitForFunction(
    async () => {
      for (const key of await caches.keys()) {
        if (!key.startsWith('keymaker-')) continue;
        if (await (await caches.open(key)).match('/SHA256SUMS')) return true;
      }
      return false;
    },
    null,
    { timeout: 30_000 }
  );
  await page.getByTestId('sealed-toggle').click();
  await page.getByTestId('sealed-panel').getByRole('button', { name: /^Check now$/ }).click();
  await page.getByTestId('verify-result').waitFor({ timeout: 60_000 });
  await page.waitForTimeout(400);
  collect(await scan(page, 'encrypt · sealed status'));
  await page.getByTestId('sealed-toggle').click();

  // The itemised plan — behind the anticipation disclosure — is where the
  // byte map paints the spark cuts, so the sweep has to open it or the only
  // sanctioned use of those colours ships unaudited.
  await page
    .getByRole('button', { name: 'Show the header it will write' })
    .locator('visible=true')
    .first()
    .click();
  await page.waitForTimeout(400);
  collect(await scan(page, 'encrypt · plan detail'));

  const advanced = page.getByRole('button', { name: /^Advanced/ }).locator('visible=true').first();
  await advanced.click();
  await page.waitForTimeout(400);
  collect(await scan(page, 'encrypt · advanced'));

  // Seed Phrase mode, with one word flagged and a completion list open. The
  // grid is the one surface that paints the danger token as a *field* border
  // rather than as text, its flagged status is a wash nothing above composes,
  // and the listbox is a card on a card — none of it is reached by any other
  // view, so the mode would otherwise ship unaudited.
  await page.getByRole('button', { name: 'Seed phrase', exact: true }).locator('visible=true').first().click();
  const seedWords = 'legal winner thank year wave sausage wotrh useful legal winner thank yellow'.split(' ');
  for (const [i, w] of seedWords.entries()) {
    await page
      .getByRole('combobox', { name: `Word ${i + 1}`, exact: true })
      .locator('visible=true')
      .first()
      .fill(w);
  }
  await page.getByRole('combobox', { name: 'Word 12', exact: true }).locator('visible=true').first().fill('ye');
  await page.getByRole('listbox', { name: 'Completions for word 12' }).waitFor({ state: 'visible', timeout: 15_000 });
  await page.waitForTimeout(400);
  collect(await scan(page, 'encrypt · seed grid'));

  // The shares dialog in its rehearsal state. Reachable only by sealing with
  // a share set and opening the result again with two of them, and worth the
  // seal: it is where a success wash, a form and the dialog chrome meet, and
  // nothing above ever paints it. PBKDF2, because the KDF is not what is
  // being painted.
  await page.getByRole('button', { name: 'Text', exact: true }).locator('visible=true').first().click();
  await page.getByPlaceholder('Enter text to encrypt').locator('visible=true').first().fill('for the audit');
  await page.getByRole('button').filter({ hasText: 'PBKDF2' }).locator('visible=true').first().click();
  const sharesSwitch = page.getByRole('switch', { name: 'Recovery shares' }).locator('visible=true').first();
  if ((await sharesSwitch.getAttribute('aria-checked')) !== 'true') await sharesSwitch.click();
  await page
    .getByPlaceholder('Enter a strong password')
    .locator('visible=true')
    .first()
    .fill('correct-horse-battery-staple-9271!X');
  await page.getByRole('button', { name: /^Encrypt Text$/i }).locator('visible=true').first().click();
  const sharesDialog = page.getByRole('dialog');
  await sharesDialog.getByText(/Save these 3 shares now/).waitFor({ timeout: 90_000 });
  await sharesDialog.getByRole('button', { name: /Rehearse now/ }).click();
  const issued = await sharesDialog.getByText(/^KMSHARE1:/).allTextContents();
  await sharesDialog.getByLabel('Strips to rehearse with').fill(`${issued[0]}\n${issued[1]}`);
  await sharesDialog.getByRole('button', { name: /^Open with these strips$/ }).click();
  await sharesDialog.getByTestId('rehearsal-result').waitFor({ timeout: 60_000 });
  await page.waitForTimeout(400);
  collect(await scan(page, 'shares dialog · rehearsal'));
  await page.keyboard.press('Escape');

  for (const tab of ['Decrypt', 'Tools']) {
    await page.getByRole('tab', { name: tab }).locator('visible=true').first().click();
    await page.waitForTimeout(400);
    collect(await scan(page, tab.toLowerCase()));
  }

  // Dialogs render into a portal at the end of <body>, so nothing above ever
  // reaches them: the workbench sweep restyled these surfaces and no run had
  // looked at one. The recovery kit is the cheapest to open — a footer button,
  // no crypto — and it carries the whole dialog vocabulary: overlay, panel,
  // heading, body copy, inline code chips and a bordered download row.
  await page.getByRole('tab', { name: 'Encrypt' }).locator('visible=true').first().click();
  await page.getByRole('button', { name: /Recovery kit/ }).locator('visible=true').first().click();
  await page.getByRole('dialog').waitFor({ state: 'visible', timeout: 15_000 });
  await page.waitForTimeout(400);
  collect(await scan(page, 'recovery dialog'));
  await page.keyboard.press('Escape');

  // The command bar is a portal too, and a younger one — the same reasoning
  // that added the recovery dialog adds it: a restyle of this surface would
  // otherwise be invisible to every view above.
  await page.keyboard.press('Control+k');
  await page.getByRole('dialog', { name: 'Command menu' }).waitFor({ state: 'visible', timeout: 15_000 });
  await page.waitForTimeout(400);
  collect(await scan(page, 'command bar'));
  await page.keyboard.press('Escape');

  await page.goto(`${BASE}/verify.html`, { waitUntil: 'networkidle' });
  collect(await scan(page, 'verify'));
} finally {
  await browser.close();
  server.kill();
}

/**
 * A colour drawn at partial alpha lands somewhere between itself and whatever
 * is behind it, so it cannot be compared to a named value directly. Those are
 * reported separately: an intentional translucent scrim is fine, and the point
 * of listing them is that "intentional" stays a decision someone made.
 */
const offenders = new Map();

/**
 * Canvas hands back straight alpha, so `r,g,b` are the colour as authored
 * even when it is painted at a fraction — which means a translucent value can
 * be held to the same list as an opaque one, and the whole `bg-white/4` family
 * is catchable rather than merely visible.
 *
 * White and black are the exception, and the reason this gate exists: a
 * translucent white over a warm ground *is* the drift. They stay legitimate at
 * full opacity and are refused at any fraction.
 */
const ABSOLUTES = new Set(['#ffffff', '#000000']);

for (const s of samples) {
  const hex = hexOf(s.r, s.g, s.b);
  const washingAnAbsolute = s.alpha < 1 && ABSOLUTES.has(hex);
  if (ALLOWED.has(hex) && !washingAnAbsolute) continue;
  const { hex: near, distance } = nearestAllowed(s.r, s.g, s.b);
  if (distance <= TOLERANCE && !washingAnAbsolute) continue;

  const { hue, sat } = hueOf(s.r, s.g, s.b);
  const why = washingAnAbsolute
    ? `${hex} at ${s.alpha.toFixed(2)} — a translucent white or black wash is exactly ` +
      'the drift this palette forbids; use the surface token the wash was imitating'
    : hue === null || sat < 0.04
      ? 'neutral grey — the palette has no colour without a hue'
      : hue >= 20 && hue <= 90
        ? `warm (hue ${hue}) but not a named value; nearest is ${near}, ${distance} off`
        : `cool (hue ${hue}) — outside the warm family entirely`;
  const key = `${hex}|${why}`;
  if (!offenders.has(key)) offenders.set(key, { hex, why, alpha: s.alpha, seen: [] });
  const rec = offenders.get(key);
  if (rec.seen.length < 3) rec.seen.push(`${s.label} · ${s.tag}.${s.cls || '(no class)'} · ${s.prop}`);
}

console.log(`palette-audit: ${samples.length} painted colours across ${VIEWS} views\n`);

if (unreadable.length) {
  console.error(`FAIL — ${unreadable.length} colour(s) the audit could not resolve:`);
  for (const u of unreadable.slice(0, 8)) console.error(`  ${u.label} · ${u.prop} · ${u.raw}`);
  console.error('\nAn audit that skips what it cannot parse is an audit that passes\neverything. Teach it the notation rather than ignoring the value.');
  process.exit(1);
}

if (offenders.size === 0) {
  console.log('All opaque colours are values docs/design/DESIGN-SYSTEM.md names.');
  process.exit(0);
}

console.error(`FAIL — ${offenders.size} colour(s) outside the system:\n`);
for (const rec of offenders.values()) {
  console.error(`  ${rec.hex}  ${rec.why}`);
  for (const s of rec.seen) console.error(`      ${s}`);
}
console.error(
  '\nEither the element should use a token, or the value belongs in the design\n' +
    'document and in ALLOWED here. Adding it to only one of those is the drift\n' +
    'this gate exists to catch.'
);
process.exit(1);
