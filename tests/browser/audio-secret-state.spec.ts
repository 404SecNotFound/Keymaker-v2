import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { appPath, visible, STRONG_PASSWORD } from "./helpers";
import { embedContainer, writePcm16Wav, type Pcm16 } from "../../src/lib/audio-stego";

/**
 * R04 and R05, on the Audio tab: the two things the main Decrypt tab does that
 * the audio path was not.
 *
 * R05 — it now reports what a decrypt learns about the container. A stripped
 * slot table (§5.2) and a pre-floor KDF both open exactly as before, and both
 * now say so beside the recovered secret. The containers are the frozen corpus
 * vectors, embedded into a carrier here rather than built, so the verdict is one
 * a decrypt reaches on bytes written on a known day, not a check the app agrees
 * with itself about.
 *
 * R04 — a recovered secret no longer outlives the wipe that was meant to erase
 * it. The generation guard is the load-bearing part: a decrypt that finishes
 * *after* the tab was cleared must drop its plaintext, not repaint it. That is
 * the assertion the last test makes, by wiping while the KDF is still running.
 *
 * Every assertion here fails if its change is reverted: no slot warning without
 * `setSlotWarning`, no advisory without `setKdfNotice`, a surviving password
 * without the success-path clear, and a reappearing secret without the guard.
 */

const CORPUS = resolve(__dirname, "../../scripts/fixtures/keymaker");
const corpusMeta = JSON.parse(readFileSync(resolve(CORPUS, "fixtures.json"), "utf8")) as {
  password: string;
  fixtures: Array<{ name: string; file: string; plaintext: string }>;
};
const corpus = (name: string) => {
  const fx = corpusMeta.fixtures.find((f) => f.name === name);
  if (!fx) throw new Error(`corpus has no fixture named ${name}`);
  return fx;
};

const weak = JSON.parse(
  readFileSync(resolve(__dirname, "fixtures/weak-legacy-kdf.json"), "utf8")
) as { armor: string; password: string; plaintext: string; iterations: number };

/** Undo §7 armor to the raw container bytes: prefix off, base64url to bytes. */
function dearmor(armor: string): Uint8Array {
  const b64 = armor.replace(/^keym2:/, "").replace(/-/g, "+").replace(/_/g, "/");
  return new Uint8Array(Buffer.from(b64, "base64"));
}

/** Wrap raw container bytes in a KAUD1 WAV carrier, the exact file the reveal
 *  side parses. A quiet tone long enough to hold the container plus its header. */
function stegoWav(container: Uint8Array): Buffer {
  const frames = container.length * 8 + 1024;
  const samples = new Int16Array(frames);
  for (let i = 0; i < frames; i++) samples[i] = Math.round(Math.sin(i * 0.02) * 8000);
  const pcm: Pcm16 = { sampleRate: 44100, channels: 1, samples };
  return Buffer.from(writePcm16Wav(embedContainer(pcm, container, 1)));
}

/** A clean 16-bit PCM mono WAV with no hidden data, for the round-trip test. */
function makeWav(frames: number, sampleRate = 44100): Buffer {
  const dataLen = frames * 2;
  const buf = Buffer.alloc(44 + dataLen);
  buf.write("RIFF", 0, "ascii");
  buf.writeUInt32LE(36 + dataLen, 4);
  buf.write("WAVE", 8, "ascii");
  buf.write("fmt ", 12, "ascii");
  buf.writeUInt32LE(16, 16);
  buf.writeUInt16LE(1, 20);
  buf.writeUInt16LE(1, 22);
  buf.writeUInt32LE(sampleRate, 24);
  buf.writeUInt32LE(sampleRate * 2, 28);
  buf.writeUInt16LE(2, 32);
  buf.writeUInt16LE(16, 34);
  buf.write("data", 36, "ascii");
  buf.writeUInt32LE(dataLen, 40);
  for (let i = 0; i < frames; i++) buf.writeInt16LE(Math.round(Math.sin(i * 0.02) * 8000), 44 + i * 2);
  return buf;
}

async function gotoReveal(page: Page): Promise<void> {
  await page.goto(appPath("/"));
  await visible(page.getByRole("tab", { name: "Audio" })).click();
  await visible(page.getByRole("button", { name: "Unpack from audio" })).click();
}

async function revealFrom(page: Page, wav: Buffer, password: string): Promise<void> {
  await page.locator("#audio-carrier-input").setInputFiles({
    name: "carry.wav",
    mimeType: "audio/wav",
    buffer: wav,
  });
  await expect(page.getByText(/holds \d/)).toBeVisible({ timeout: 20_000 });
  await visible(page.getByPlaceholder("Password the secret was packed with")).fill(password);
  await visible(page.getByRole("button", { name: /^Reveal secret$/i })).click();
}

test.describe("the audio reveal reports what the decrypt learns (R05)", () => {
  test("a stripped slot table gives back the plaintext and warns", async ({ page }) => {
    const fx = corpus("v3-stripped-aes256gcm");
    await gotoReveal(page);
    await revealFrom(page, stegoWav(new Uint8Array(readFileSync(resolve(CORPUS, fx.file)))), corpusMeta.password);

    // §5.2, first half: the plaintext still comes back. Refusing it would turn
    // a noticeable edit into a lost backup.
    await expect(
      page.getByTestId("audio-recovered-text"),
      "a stripped container refused to open through the audio path"
    ).toHaveValue(fx.plaintext, { timeout: 90_000 });

    // §5.2, second half: and the audio path says the list of ways back in
    // changed, in the same words the Decrypt tab uses.
    const warn = page.getByTestId("audio-slot-table-warning");
    await expect(visible(warn), "the audio path opened a tampered table in silence").toBeVisible();
    await expect(visible(warn)).toContainText(/list of unlock methods has changed/i);
    await expect(visible(warn)).toContainText(/Your data is intact/i);

    // R04, on the success path: the password that opened it is not left in the
    // field. (Removing the success-path clear leaves the value here.)
    await expect(
      page.getByPlaceholder("Password the secret was packed with"),
      "the password survived a successful reveal"
    ).toHaveValue("");
  });

  test("a pre-floor KDF gives back the plaintext and advises re-packing", async ({ page }) => {
    await gotoReveal(page);
    await revealFrom(page, stegoWav(dearmor(weak.armor)), weak.password);

    await expect(
      page.getByTestId("audio-recovered-text"),
      "a weak-KDF container failed to open through the audio path"
    ).toHaveValue(weak.plaintext, { timeout: 90_000 });

    const notice = page.getByTestId("audio-weak-kdf-notice");
    await expect(visible(notice), "a dated-KDF container opened without saying so").toBeVisible();
    await expect(visible(notice)).toContainText(/Heads up: this was packed with/i);
    await expect(visible(notice)).toContainText(/1,000 PBKDF2 iterations/);
  });

  test("a current container carries neither warning", async ({ page }) => {
    // The control on the two above: a warning that fires on everything is
    // furniture. A container written at today's settings, round-tripped through
    // the audio path, must show no slot warning and no KDF advisory.
    await page.goto(appPath("/"));
    await visible(page.getByRole("tab", { name: "Audio" })).click();
    await page.locator("#audio-carrier-input").setInputFiles({
      name: "carrier.wav",
      mimeType: "audio/wav",
      buffer: makeWav(44100),
    });
    await expect(page.getByText(/holds \d/)).toBeVisible({ timeout: 20_000 });
    await visible(page.getByPlaceholder("Enter the secret text to pack in…")).fill("written today");
    await visible(page.getByPlaceholder("Password to lock the secret")).fill(STRONG_PASSWORD);

    const dl = page.waitForEvent("download");
    await visible(page.getByRole("button", { name: "Pack into audio & download WAV" })).click();
    const stego = await (await dl).path().then(async (p) => {
      const { readFile } = await import("node:fs/promises");
      return readFile(p);
    });

    await visible(page.getByRole("button", { name: "Unpack from audio" })).click();
    await revealFrom(page, stego, STRONG_PASSWORD);

    await expect(page.getByTestId("audio-recovered-text")).toHaveValue("written today", { timeout: 90_000 });
    await expect(
      page.getByTestId("audio-slot-table-warning"),
      "an intact container was accused of tampering"
    ).toHaveCount(0);
    await expect(
      page.getByTestId("audio-weak-kdf-notice"),
      "a current-strength container was labelled dated"
    ).toHaveCount(0);
  });
});

test.describe("a recovered secret does not outlive the wipe (R04)", () => {
  test("a decrypt that finishes after a wipe drops its plaintext", async ({ page }) => {
    await page.goto(appPath("/"));
    await visible(page.getByRole("tab", { name: "Audio" })).click();

    // Hide a secret with the app's own (calibrated) KDF, so the reveal below has
    // a real derivation to run — long enough to wipe during.
    await page.locator("#audio-carrier-input").setInputFiles({
      name: "carrier.wav",
      mimeType: "audio/wav",
      buffer: makeWav(44100),
    });
    await expect(page.getByText(/holds \d/)).toBeVisible({ timeout: 20_000 });
    await visible(page.getByPlaceholder("Enter the secret text to pack in…")).fill("must not survive a wipe");
    await visible(page.getByPlaceholder("Password to lock the secret")).fill(STRONG_PASSWORD);
    const dl = page.waitForEvent("download");
    await visible(page.getByRole("button", { name: "Pack into audio & download WAV" })).click();
    const stego = await (await dl).path().then(async (p) => {
      const { readFile } = await import("node:fs/promises");
      return readFile(p);
    });

    await visible(page.getByRole("button", { name: "Unpack from audio" })).click();
    await page.locator("#audio-carrier-input").setInputFiles({
      name: "keymaker-audio.wav",
      mimeType: "audio/wav",
      buffer: stego,
    });
    await expect(page.getByText(/holds \d/)).toBeVisible({ timeout: 20_000 });
    await visible(page.getByPlaceholder("Password the secret was packed with")).fill(STRONG_PASSWORD);

    // Start the reveal, then wipe while the KDF is still running, the way a tab
    // switch or a hidden page does.
    await visible(page.getByRole("button", { name: /^Reveal secret$/i })).click();
    await expect(page.getByRole("button", { name: /Working…/ })).toBeVisible();
    await page.evaluate(() => {
      Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "hidden" });
      document.dispatchEvent(new Event("visibilitychange"));
    });

    // Once the button re-enables, the derivation has finished. Without the
    // generation guard the recovered secret repaints here despite the wipe.
    await expect(page.getByRole("button", { name: /^Reveal secret$/i })).toBeVisible({ timeout: 90_000 });
    await expect(
      page.getByTestId("audio-recovered-text"),
      "the recovered secret reappeared after the tab was wiped mid-derivation"
    ).toHaveCount(0);
    await expect(page.getByPlaceholder("Password the secret was packed with")).toHaveValue("");
  });
});
