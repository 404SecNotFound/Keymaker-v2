import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";
import { appPath, visible, STRONG_PASSWORD } from "./helpers";

/**
 * The Audio tab: hide a secret in a WAV carrier and recover it.
 *
 * The round trip is the real path: encrypt into a container, embed it in the
 * carrier's sample LSBs, write a WAV, then read that exact WAV back and decrypt.
 * The negative controls are what prove the LSBs are actually carrying the data:
 * a clean carrier must report nothing hidden, and a wrong password must fail. A
 * stub that ignored the audio and echoed the input would pass the positive test
 * but fail both controls.
 */

const SECRET = "The vault key is behind the third brick. correct horse battery staple.";

/** A minimal 16-bit PCM mono WAV with `frames` samples of quiet tone, big
 *  enough to hold a small container. Built in the test so the carrier is a
 *  known clean file with no hidden data. */
function makeWav(frames: number, sampleRate = 44100): Buffer {
  const dataLen = frames * 2;
  const buf = Buffer.alloc(44 + dataLen);
  buf.write("RIFF", 0, "ascii");
  buf.writeUInt32LE(36 + dataLen, 4);
  buf.write("WAVE", 8, "ascii");
  buf.write("fmt ", 12, "ascii");
  buf.writeUInt32LE(16, 16);
  buf.writeUInt16LE(1, 20); // PCM
  buf.writeUInt16LE(1, 22); // mono
  buf.writeUInt32LE(sampleRate, 24);
  buf.writeUInt32LE(sampleRate * 2, 28);
  buf.writeUInt16LE(2, 32);
  buf.writeUInt16LE(16, 34);
  buf.write("data", 36, "ascii");
  buf.writeUInt32LE(dataLen, 40);
  for (let i = 0; i < frames; i++) buf.writeInt16LE(Math.round(Math.sin(i * 0.02) * 8000), 44 + i * 2);
  return buf;
}

async function gotoAudio(page: Page): Promise<void> {
  await page.goto(appPath("/"));
  await visible(page.getByRole("tab", { name: "Audio" })).click();
}

test.describe("hide a secret in audio", () => {
  test("round trip: hide text in a WAV, then reveal it with the password", async ({ page }) => {
    await gotoAudio(page);

    // Hide side. Upload the carrier and wait for its capacity line.
    await page.locator("#audio-carrier-input").setInputFiles({
      name: "carrier.wav",
      mimeType: "audio/wav",
      buffer: makeWav(44100),
    });
    await expect(page.getByText(/holds \d/)).toBeVisible({ timeout: 20_000 });

    await visible(page.getByPlaceholder("Enter the secret text to pack in…")).fill(SECRET);
    await visible(page.getByPlaceholder("Password to lock the secret")).fill(STRONG_PASSWORD);

    const downloadPromise = page.waitForEvent("download");
    await visible(page.getByRole("button", { name: "Pack into audio & download WAV" })).click();
    const download = await downloadPromise;
    const path = await download.path();
    const { readFile } = await import("node:fs/promises");
    const stego = await readFile(path);
    // The carrier came out larger than the header alone, and is a WAV.
    expect(stego.length).toBeGreaterThan(44);
    expect(stego.subarray(0, 4).toString("ascii")).toBe("RIFF");

    // Reveal side. Switch, upload the produced WAV, decrypt.
    await visible(page.getByRole("button", { name: "Unpack from audio" })).click();
    await page.locator("#audio-carrier-input").setInputFiles({
      name: "keymaker-audio.wav",
      mimeType: "audio/wav",
      buffer: stego,
    });
    await expect(page.getByText(/holds \d/)).toBeVisible({ timeout: 20_000 });
    await visible(page.getByPlaceholder("Password the secret was packed with")).fill(STRONG_PASSWORD);
    await visible(page.getByRole("button", { name: /^Reveal secret$/i })).click();

    const recovered = page.getByTestId("audio-recovered-text");
    await expect(recovered).toBeVisible({ timeout: 90_000 });
    await expect(recovered).toHaveValue(SECRET);
  });

  test("a clean carrier reports nothing hidden", async ({ page }) => {
    await gotoAudio(page);
    await visible(page.getByRole("button", { name: "Unpack from audio" })).click();

    await page.locator("#audio-carrier-input").setInputFiles({
      name: "plain.wav",
      mimeType: "audio/wav",
      buffer: makeWav(44100),
    });
    await expect(page.getByText(/holds \d/)).toBeVisible({ timeout: 20_000 });
    await visible(page.getByPlaceholder("Password the secret was packed with")).fill(STRONG_PASSWORD);
    await visible(page.getByRole("button", { name: /^Reveal secret$/i })).click();

    await expect(page.getByText(/No hidden Keymaker data/i).first()).toBeVisible({ timeout: 20_000 });
    await expect(page.getByTestId("audio-recovered-text")).toHaveCount(0);
  });

  test("the wrong password does not recover the secret", async ({ page }) => {
    await gotoAudio(page);

    await page.locator("#audio-carrier-input").setInputFiles({
      name: "carrier.wav",
      mimeType: "audio/wav",
      buffer: makeWav(44100),
    });
    await expect(page.getByText(/holds \d/)).toBeVisible({ timeout: 20_000 });
    await visible(page.getByPlaceholder("Enter the secret text to pack in…")).fill(SECRET);
    await visible(page.getByPlaceholder("Password to lock the secret")).fill(STRONG_PASSWORD);

    const downloadPromise = page.waitForEvent("download");
    await visible(page.getByRole("button", { name: "Pack into audio & download WAV" })).click();
    const stego = await (await downloadPromise).path().then(async (p) => {
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
    // A valid-looking but wrong password: same policy shape, different string.
    await visible(page.getByPlaceholder("Password the secret was packed with")).fill("Wrong-Passphrase-Entirely-9999!");
    await visible(page.getByRole("button", { name: /^Reveal secret$/i })).click();

    await expect(page.getByText(/Wrong password or damaged carrier/i).first()).toBeVisible({ timeout: 90_000 });
    await expect(page.getByTestId("audio-recovered-text")).toHaveCount(0);
  });
});
