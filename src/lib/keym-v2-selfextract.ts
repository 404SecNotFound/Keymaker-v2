/**
 * Self-extracting pages for KEYM v2 — `docs/FORMAT-V2-DESIGN.md` §7.2.
 *
 * One `.html` file holding a container and a decryptor for it, so the person
 * who inherits a backup does not also have to inherit a toolchain. The whole
 * artefact is one file, opens from `file://`, makes no network request, and
 * uses nothing but `crypto.subtle`.
 *
 * **No WebAssembly, deliberately and permanently.** That is what forces the
 * WebCrypto-only subset §7.2 defines — AES-256-GCM, a PBKDF2 passphrase slot,
 * no key file — and the subset is why this module refuses containers rather
 * than doing its best with them. A page that cannot open its own container is
 * discovered by an heir with no second copy and nobody to ask.
 *
 * The container inside is an ordinary KEYM v2 container: `reference/keym2.py`
 * opens it, the app opens it, the page opens it. Three independent readers of
 * one file, which is the argument the Python reference makes for the format as
 * a whole, applied to the artefact most likely to outlive all three.
 */

import {
  KEYM2_ARMOR_PREFIX,
  KEYM2_CORE_HEADER_LEN,
  armorKeym2,
  dearmorKeym2,
  keym2SlotLen,
  keym2SlotCountOffset,
  keym2SlotTableOffset,
  parseKeym2CoreHeader,
  parseKeym2Slot,
} from "@/lib/keym-v2";
import { CipherId, KdfId } from "@/lib/keymaker-crypto";

/**
 * §7.2. The sentinels bracketing the armor.
 *
 * HTML comments rather than a `<script>` or a data attribute, so the armor is
 * visible text in the document. The case this artefact exists for is the one
 * where its JavaScript does not run — a locked-down viewer, a browser that
 * moved on — and the container has to still be reachable with a text editor.
 */
export const KEYM2_SELFEXTRACT_BEGIN = "<!--KEYM2-BEGIN-->";
export const KEYM2_SELFEXTRACT_END = "<!--KEYM2-END-->";

/** §7. Explicitly ASCII: two readers disagreeing about U+00A0 is a backup that opens for one of them. */
const ASCII_WHITESPACE = /[ \t\n\r\v\f]/g;

// The table's position depends on the container's version, and reading it at a
// fixed 9 is how this file came to answer "the password slot uses Argon2id" for
// a v3 container written with PBKDF2: offset 8 in v3 is the first byte of
// container_id, so the slot count was a random number and the walk stepped
// through the middle of the header. Taken from keym-v2.ts now rather than
// restated, because a second copy of a layout constant is a second thing to
// forget.

/**
 * §7.2. Why a WebCrypto-only reader could not open this container.
 *
 * Empty means it can. Reasons rather than a boolean because each one names a
 * different thing the writer has to change, and "unsuitable" alone gives the
 * user nothing to act on.
 */
export function webcryptoProfileViolations(container: Uint8Array): string[] {
  const reasons: string[] = [];

  // parseKeym2CoreHeader rejects rather than returning null, and its rejection
  // is §6's deliberately uninformative one. That is right for a reader holding
  // someone else's file and wrong here, where the caller wrote the container a
  // moment ago and needs to be told what to change.
  let core;
  try {
    core = parseKeym2CoreHeader(container);
  } catch {
    return ["this is not a KEYM v2 container"];
  }

  if (core.cipher !== CipherId.AES_256_GCM) {
    reasons.push(
      "the payload is encrypted with ChaCha20-Poly1305, which WebCrypto has " +
        "never had and no proposal adds. A self-extracting page can only carry AES-256-GCM."
    );
  }

  const slotCount = container[keym2SlotCountOffset(core.version)] as number;
  const table = keym2SlotTableOffset(core.version);
  const width = keym2SlotLen(core.cipher);
  let usable = false;
  let keyFileOnly = false;

  for (let j = 0; j < slotCount; j++) {
    const start = table + j * width;
    const record = container.subarray(start, start + width);
    if (record.length < width) break;
    // §4.4's skip rule: a slot this reader cannot parse is not evidence about
    // the container. The question is only whether *some* slot is in the subset.
    const slot = parseKeym2Slot(record);
    if (!slot) continue;
    if (slot.slotType !== 0x00) continue;
    if (slot.kdf.kdf !== KdfId.PBKDF2) continue;
    if (slot.keyFileUsed) {
      keyFileOnly = true;
      continue;
    }
    usable = true;
  }

  if (!usable) {
    if (keyFileOnly) {
      reasons.push(
        "this backup uses a key file. Embedding it would put both factors in " +
          "one file, which is exactly what a key file exists to prevent; leaving " +
          "it out would write a weaker backup than you think you have."
      );
    } else {
      reasons.push(
        "the password slot uses Argon2id, which needs WebAssembly. A page that " +
          "still works in twenty years cannot depend on it."
      );
    }
  }
  return reasons;
}

/** §7.2. The sentinel block, policy-checked. Never emitted for a container the page could not open. */
export function embedSelfExtract(container: Uint8Array): string {
  const reasons = webcryptoProfileViolations(container);
  if (reasons.length) {
    throw new Error(`Outside the WebCrypto-only subset: ${reasons.join(" ")}`);
  }
  return `${KEYM2_SELFEXTRACT_BEGIN}\n${armorKeym2(container)}\n${KEYM2_SELFEXTRACT_END}`;
}

/**
 * §7.2. Recover the container from a self-extracting page.
 *
 * Zero sentinel pairs or more than one is a rejection rather than a guess: two
 * pairs means two backups in one file, or a page quoting another, and picking
 * one is how a reader hands someone the wrong container with an ordinary
 * "decryption failed" to explain it.
 *
 * Structural failures throw plain `Error`s and never route through the AEAD.
 * A page problem reported as a decryption failure sends someone to retype a
 * password that was never wrong — §7.1 made the same argument about a short set
 * of paper parts.
 */
export function extractSelfExtract(text: string): Uint8Array {
  const opens = text.split(KEYM2_SELFEXTRACT_BEGIN).length - 1;
  if (opens !== 1) {
    throw new Error(
      opens === 0
        ? "This file has no Keymaker backup marker in it."
        : `This file contains ${opens} backups. Split them into separate files first.`
    );
  }
  const start = text.indexOf(KEYM2_SELFEXTRACT_BEGIN) + KEYM2_SELFEXTRACT_BEGIN.length;
  const end = text.indexOf(KEYM2_SELFEXTRACT_END, start);
  if (end === -1) throw new Error("The backup marker in this file is never closed.");

  const body = text.slice(start, end).replace(ASCII_WHITESPACE, "");
  if (!body.startsWith(KEYM2_ARMOR_PREFIX)) {
    throw new Error("The marked region of this file is not a KEYM v2 backup.");
  }
  return dearmorKeym2(body);
}

/** §7.2's wrong-box paste, answered without committing to the page being valid. */
export function looksLikeSelfExtract(text: string): boolean {
  return text.includes(KEYM2_SELFEXTRACT_BEGIN);
}

// ---------------------------------------------------------------------------
// The page
// ---------------------------------------------------------------------------

/**
 * The decryptor, as source.
 *
 * Written to be read, not to be small. Someone deciding whether to type a
 * password into this file can open it in a text editor and check that it does
 * what it says — there is no network call, no `eval`, no dependency, and the
 * whole of it is below. That auditability is the point: an heir is being asked
 * to trust a file they did not make.
 *
 * Single quotes and string concatenation throughout, so the whole thing embeds
 * in a template literal without escaping. Escaped source is source nobody reads.
 */
/**
 * The policy the exported page carries.
 *
 * This file is the artifact with the highest trust requirement in the project
 * and, until now, the only one that shipped no CSP at all: a single HTML file
 * an heir opens from `file://`, years from now, on a machine nobody vetted,
 * to recover a seed phrase. The app's own pages have had `default-src 'none'`
 * for a long time; the page that outlives the app had nothing.
 *
 * `connect-src 'none'` is the directive that earns its place. The decryptor
 * holds a plaintext seed phrase in a DOM it did not author defensively, and
 * this is what stops anything on that page — injected through the container,
 * through a mangled paste, through a future edit — from opening a socket and
 * sending it somewhere. `default-src 'none'` covers the rest by refusing every
 * fetch this page has no reason to make.
 *
 * The script is pinned by hash rather than 'unsafe-inline' because the page
 * has exactly one script and we generate it, so there is no reason to allow a
 * second. SELF_EXTRACT_SCRIPT_SHA256 must equal the sha256 of DECRYPTOR_JS
 * exactly; a stale value means the browser refuses the only script on the page
 * and the heir gets a document that renders and cannot decrypt. That is the
 * worst failure this project has, so it is guarded twice: the browser test
 * that opens the page and decrypts a real container fails outright, and
 * `the exported page pins its own script by hash` recomputes the digest and
 * says so in words.
 *
 * style-src keeps 'unsafe-inline' for the one <style> block, for the same
 * reason the app does: hashing a stylesheet buys nothing when no untrusted
 * style can reach the document.
 */
const SELF_EXTRACT_SCRIPT_SHA256 = "sha256-9HitD62CnjU7w9Lg87XIXNvyspR1eoO2VNjtAksD998=";

const SELF_EXTRACT_CSP = [
  "default-src 'none'",
  `script-src '${SELF_EXTRACT_SCRIPT_SHA256}'`,
  "style-src 'unsafe-inline'",
  "connect-src 'none'",
  "img-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join("; ");

const DECRYPTOR_JS = `
'use strict';
// KEYM v2, the WebCrypto-only subset (FORMAT-V2-DESIGN.md 7.2).
// AES-256-GCM + PBKDF2-HMAC-SHA-256 only: no WebAssembly, no network, no deps.

var CHUNK = 1048576, TAG = 16, SLOT_LEN = 96;
// v2 puts slot_count at 8 and the table at 9. v3 widens the core header to 24
// for container_id and puts a 32-byte slot_table_mac between them, so the table
// starts at 57. Both are read here because a page written today has to keep
// opening after the app has moved on, and a page written before v3 has to keep
// opening now.
var V2 = { core: 8, count: 8, table: 9 };
var V3 = { core: 24, count: 24, mac: 25, table: 57 };

function bytes(s) { return new TextEncoder().encode(s); }

function cat(list) {
  var n = 0, i;
  for (i = 0; i < list.length; i++) n += list[i].length;
  var out = new Uint8Array(n), at = 0;
  for (i = 0; i < list.length; i++) { out.set(list[i], at); at += list[i].length; }
  return out;
}

// LP(x) = uint32_be(len(x)) || x  -- section 4.1. The length prefixes are what
// make the concatenation injective, so no two field sequences collide.
function lp(b) {
  var head = new Uint8Array(4), v = new DataView(head.buffer);
  v.setUint32(0, b.length, false);
  return cat([head, b]);
}

function dearmor(text) {
  var s = text.replace(/[\\s]/g, '');
  if (s.indexOf('keym2:') !== 0) throw new Error('This file does not contain a KEYM v2 backup.');
  s = s.slice(6).replace(/-/g, '+').replace(/_/g, '/');
  var bin = atob(s + '='.repeat((4 - (s.length % 4)) % 4));
  var out = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// section 5.2: nonce_i = uint88_be(i) || final_flag.
function nonceFor(index, isFinal) {
  var n = new Uint8Array(12);
  for (var i = 10, v = index; i >= 0 && v > 0; i--) { n[i] = v % 256; v = Math.floor(v / 256); }
  n[11] = isFinal ? 1 : 0;
  return n;
}

// section 5.1, recovered from the payload length alone. A remainder above the
// chunk size means a truncated or padded payload, not a short final chunk.
function chunkLayout(payloadLen) {
  if (payloadLen < TAG) throw new Error('bad payload');
  var q = Math.floor((payloadLen - TAG) / (CHUNK + TAG));
  var rem = (payloadLen - TAG) % (CHUNK + TAG);
  if (rem > CHUNK) throw new Error('bad payload');
  var sizes = [];
  for (var i = 0; i < q; i++) sizes.push(CHUNK);
  sizes.push(rem);
  return sizes;
}

async function openAesGcm(rawKey, nonce, data, aad) {
  var k = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt']);
  var out = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, k, data);
  return new Uint8Array(out);
}

async function slotKeyFor(password, salt, iterations) {
  // section 4.1: LP(context) || LP(NFC(password)) || LP("") -- the third field is
  // the key-file digest, and this subset never carries one.
  var kdfInput = cat([
    lp(bytes('keymaker.v2.kdf-input')),
    lp(bytes(password.normalize('NFC'))),
    lp(new Uint8Array(0))
  ]);
  var base = await crypto.subtle.importKey('raw', kdfInput, 'PBKDF2', false, ['deriveBits']);
  var bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'SHA-256' }, base, 256);
  return new Uint8Array(bits);
}

// v3 section 5.1. HKDF-SHA-256(master_key, salt = "", info) then HMAC-SHA-256
// over the core header, the slot count and every slot record in order. Both
// primitives are in Web Crypto, so this stays a page with no wasm and no deps.
async function slotTableAuthentic(container, geom, slotCount, masterKey) {
  var prk = await crypto.subtle.importKey('raw', masterKey, 'HKDF', false, ['deriveBits']);
  var raw = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: bytes('keymaker.v3.slot-table') },
    prk, 256);
  var key = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  var msg = cat([container.subarray(0, geom.core), new Uint8Array([slotCount]),
                 container.subarray(geom.table, geom.table + slotCount * SLOT_LEN)]);
  var want = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
  var got = container.subarray(geom.mac, geom.mac + 32);
  var diff = 0;
  for (var i = 0; i < 32; i++) diff |= want[i] ^ got[i];
  return diff === 0;
}

async function decrypt(container, password) {
  if (container.length < 5) throw new Error('too short');
  if (container[0] !== 0x4B || container[1] !== 0x45 ||
      container[2] !== 0x59 || container[3] !== 0x4D) throw new Error('not a KEYM container');
  // v3 section 6: a reader that understands v3 must still open v2. This page
  // ships inside the backup it opens, so it is the one reader that can never be
  // updated afterwards -- it has to know every version it might be handed.
  if (container[4] !== 2 && container[4] !== 3) throw new Error('not KEYM v2 or v3');
  var geom = container[4] === 3 ? V3 : V2;
  if (container.length < geom.table) throw new Error('too short');
  if (container[5] !== 0) throw new Error('this backup is not AES-256-GCM');
  if (container[6] !== 0 || container[7] !== 0) throw new Error('reserved header field set');

  var slotCount = container[geom.count];
  if (slotCount < 1 || slotCount > 8) throw new Error('bad slot count');
  var payloadOffset = geom.table + slotCount * SLOT_LEN;
  if (container.length < payloadOffset + TAG) throw new Error('too short');

  var core = container.subarray(0, geom.core);   // section 5.3, payload_aad
  var wrapNonce = new Uint8Array(12);
  wrapNonce[11] = 0xFF;                          // section 4.3

  var masterKey = null;
  for (var j = 0; j < slotCount && !masterKey; j++) {
    var rec = container.subarray(geom.table + j * SLOT_LEN, geom.table + (j + 1) * SLOT_LEN);
    // section 4.4: skip what this reader cannot attempt, never reject the
    // container for it. A share slot or an Argon2id slot sitting beside a
    // usable passphrase slot must not make the file unopenable here.
    if (rec[0] !== 0x00) continue;               // passphrase slots only
    if (rec[1] !== 0x00) continue;               // PBKDF2 only
    if (rec[2] & 0x01) continue;                 // a key file this page does not have
    if (rec[2] & 0xFE) continue;                 // reserved flag bits
    var ok = true;
    for (var r = 3; r < 8; r++) if (rec[r] !== 0) ok = false;
    if (!ok) continue;

    var view = new DataView(rec.buffer, rec.byteOffset, rec.byteLength);
    var iterations = view.getUint32(40, false);
    if (iterations < 1 || iterations > 10000000) continue;   // section 6
    if (view.getUint32(44, false) !== 0) continue;           // reserved

    var salt = rec.subarray(8, 40);
    var slotAad = cat([core, rec.subarray(0, 48)]);          // section 5.3
    var sk = await slotKeyFor(password, salt, iterations);
    try {
      masterKey = await openAesGcm(sk, wrapNonce, rec.subarray(48, SLOT_LEN), slotAad);
    } catch (e) {
      masterKey = null;                          // wrong password for this slot; try the next
    }
  }
  // section 4.4: report failure only once the slot table is exhausted.
  if (!masterKey) throw new Error('WRONG');

  // v3 section 5.2, and note what it is not: this does not decide whether to
  // continue. The plaintext is returned either way, because refusing would turn
  // a detectable edit into a lost backup. It is checked here only so the page
  // can say so, and only after a slot has already opened -- which is what makes
  // it leak nothing to someone who cannot open the file at all.
  var authentic = geom.mac === undefined ? null
    : await slotTableAuthentic(container, geom, slotCount, masterKey);

  var payload = container.subarray(payloadOffset);
  var sizes = chunkLayout(payload.length);
  var parts = [], at = 0;
  for (var i = 0; i < sizes.length; i++) {
    var isFinal = (i === sizes.length - 1);
    var take = sizes[i] + TAG;
    // section 5.2: the final chunk carries a different flag byte, so a truncated
    // container fails here rather than decrypting to a valid-looking prefix.
    parts.push(await openAesGcm(masterKey, nonceFor(i, isFinal),
                                payload.subarray(at, at + take), core));
    at += take;
  }
  if (at !== payload.length) throw new Error('bad payload');
  return { data: cat(parts), slotTableAuthentic: authentic };
}

// --- the page ---------------------------------------------------------------

// Every one of these is suffixed, because a bare 'var status' at global scope
// does not create a variable at all -- window.status is a legacy string
// property, so the element is coerced and every later use fails on a string.
// Found by running the page rather than by reading it.
var formEl = document.getElementById('f');
var pwEl = document.getElementById('pw');
var statusEl = document.getElementById('status');
var resultEl = document.getElementById('result');
var outEl = document.getElementById('out');
var tableEl = document.getElementById('table');
var saveEl = document.getElementById('save');
var goEl = document.getElementById('go');

function say(text, bad) {
  statusEl.textContent = text;
  statusEl.className = bad ? 'bad' : 'busy';
}

formEl.addEventListener('submit', async function (e) {
  e.preventDefault();
  if (!crypto || !crypto.subtle) {
    say('This browser has no Web Crypto. Open the file over file:// or https://, ' +
        'or use keym2.py -- the backup text is in this file either way.', true);
    return;
  }
  resultEl.hidden = true;
  tableEl.hidden = true;
  goEl.disabled = true;
  say('Working. This takes a few seconds by design.');
  // Yield once so the browser paints the line above before PBKDF2 blocks it.
  await new Promise(function (r) { setTimeout(r, 30); });
  try {
    var container = dearmor(document.getElementById('keym2-container').textContent);
    var opened = await decrypt(container, pwEl.value);
    var plain = opened.data;
    var text = null;
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(plain);
    } catch (e) { text = null; }

    statusEl.textContent = '';
    statusEl.className = '';
    resultEl.hidden = false;
    outEl.hidden = (text === null);
    if (text !== null) outEl.value = text;
    // v3 section 5.2. The plaintext is above and it is genuine; what this says
    // is that the *slot table* is not the one sealed with the file, which means
    // someone has added or removed a way in since it was written. Deliberately
    // not phrased as a failure, and deliberately not guessing which slot: the
    // MAC covers the table whole and cannot say.
    tableEl.hidden = (opened.slotTableAuthentic !== false);
    var blob = new Blob([plain], { type: 'application/octet-stream' });
    saveEl.href = URL.createObjectURL(blob);
    saveEl.download = 'recovered.bin';
    pwEl.value = '';
  } catch (err) {
    // One message for every failure, per section 6: a wrong password and a
    // damaged file are not distinguished, here or anywhere else in the format.
    say('That did not open it. Either the password is wrong or this file is ' +
        'damaged -- the two are deliberately indistinguishable.', true);
  } finally {
    goEl.disabled = false;
  }
});
`;

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export interface SelfExtractOptions {
  container: Uint8Array;
  /** ISO date the page records as its creation. Supplied rather than read from the clock, so a build is reproducible. */
  createdOn: string;
  /** The app version that wrote it, for the same reason `verify.html` states one. */
  appVersion: string;
}

/**
 * §7.2. Build the whole page.
 *
 * Deliberately plain HTML with one inline `<style>` and one inline `<script>`.
 * A page whose job is to still work in 2040 does not get a framework, a font
 * download or a build step — every one of those is a thing that can stop
 * resolving while the file sits in a drawer.
 */
export function buildSelfExtractingPage(options: SelfExtractOptions): string {
  const { container, createdOn, appVersion } = options;
  const block = embedSelfExtract(container); // throws for anything outside the subset

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="${SELF_EXTRACT_CSP}">
<title>Encrypted backup — Keymaker</title>
<style>
  :root { color-scheme: light dark; }
  body { margin: 0 auto; padding: 2rem 1.25rem 4rem; max-width: 44rem;
         font: 16px/1.6 system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
         background: #fbfbfd; color: #16161d; }
  @media (prefers-color-scheme: dark) { body { background: #16161d; color: #e8e8ee; } }
  h1 { font-size: 1.5rem; margin: 0 0 .25rem; }
  h2 { font-size: 1.05rem; margin: 2rem 0 .5rem; }
  .sub { opacity: .7; margin: 0 0 2rem; font-size: .95rem; }
  form { display: flex; gap: .5rem; flex-wrap: wrap; margin: 0 0 .75rem; }
  input[type=password] { flex: 1 1 16rem; padding: .6rem .7rem; font-size: 1rem;
    border: 1px solid #8a8a99; border-radius: .4rem; background: canvas; color: canvastext; }
  button { padding: .6rem 1.1rem; font-size: 1rem; border: 0; border-radius: .4rem;
    background: #3b5bdb; color: #fff; cursor: pointer; }
  button[disabled] { opacity: .55; cursor: progress; }
  .busy { opacity: .75; } .bad { color: #c92a2a; font-weight: 600; }
  @media (prefers-color-scheme: dark) { .bad { color: #ff8787; } }
  .warn { border: 1px solid #b8860b; background: #fff8e1; color: #6b4e00;
    padding: .6rem .75rem; border-radius: .4rem; margin: 0 0 .75rem; }
  @media (prefers-color-scheme: dark) {
    .warn { border-color: #b8860b; background: #2a2410; color: #ffd77a; } }
  textarea { width: 100%; min-height: 12rem; font: 13px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace;
    padding: .6rem; border-radius: .4rem; border: 1px solid #8a8a99; background: canvas; color: canvastext; }
  a.save { display: inline-block; margin-top: .6rem; }
  pre#keym2-container { white-space: pre-wrap; word-break: break-all; font: 11px/1.45 ui-monospace, SFMono-Regular, Menlo, monospace;
    background: #00000010; padding: .75rem; border-radius: .4rem; max-height: 11rem; overflow: auto; }
  details { margin-top: 1rem; } summary { cursor: pointer; }
  footer { margin-top: 3rem; font-size: .875rem; opacity: .75; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .9em; }
</style>
</head>
<body>

<h1>Encrypted backup</h1>
<p class="sub">Everything needed to open this is in this one file. It works offline —
disconnect from the network first if you like, and it will behave identically.</p>

<form id="f">
  <label for="pw" hidden>Password</label>
  <input id="pw" type="password" placeholder="Password" autocomplete="current-password" autofocus>
  <button id="go" type="submit">Decrypt</button>
</form>
<p id="status" aria-live="polite"></p>

<div id="result" hidden>
  <p id="table" class="warn" role="alert" hidden><strong>This backup&#39;s list of unlock
  methods has changed since it was created.</strong> Your data is intact — it is
  authenticated separately and was verified before anything was shown. What changed is
  the set of ways back in: an unlock method may have been added or removed. It is not
  possible to say which one. If you did not change it yourself, treat this copy as
  untrusted and recover from another one.</p>
  <textarea id="out" readonly spellcheck="false"></textarea>
  <a class="save" id="save" href="#" download="recovered.bin">Save the recovered file</a>
</div>

<h2>If this page will not run</h2>
<p>The backup itself is the block of text below, and it is not going anywhere. Copy it
into <a href="https://github.com/404SecNotFound/Keymaker-v2">Keymaker</a>, or open it with
the reference implementation, which needs only Python:</p>
<p><code>python3 keym2.py decrypt --in backup.html</code></p>
<p>That script reads this page directly — you do not have to pull the text out by hand.</p>

<details>
  <summary>The backup (KEYM v2, base64)</summary>
  <pre id="keym2-container">${block}</pre>
</details>

<h2>What this is</h2>
<p>A KEYM v2 container encrypted with AES-256-GCM, unlocked by a password stretched with
PBKDF2-HMAC-SHA-256. The page uses only <code>crypto.subtle</code>, which every browser
has had for a decade — no WebAssembly, no libraries, no network. The entire decryptor is
in this file and can be read before you type anything into it.</p>
<p><strong>PBKDF2 is a weaker key derivation than the Argon2id the app normally uses.</strong>
That is the trade this file makes on purpose: Argon2id needs WebAssembly, and this page is
built to still work when nothing can be downloaded to repair it. Keep your ordinary backup
as the primary copy; this one is the line of last resort. Anyone who copies this file can
attack the password offline, so it deserves the same care as the backup it came from.</p>

<footer>
  Written by Keymaker ${escapeHtml(appVersion)} on ${escapeHtml(createdOn)} · KEYM v2 ·
  format: <code>docs/FORMAT-V2-DESIGN.md</code> §7.2
</footer>

<script>${DECRYPTOR_JS}</script>
</body>
</html>
`;
}
