import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { visible, useTextMode } from "./helpers";

/**
 * KM-R08: text mode must not silently mangle bytes that are not text.
 *
 * `new TextDecoder()` replaces every malformed sequence with U+FFFD and reports
 * no error. A KEYM container can hold arbitrary bytes — nothing in the format
 * says a payload is text, and another conforming implementation may well write
 * binary — so decoding leniently handed the user irreversibly corrupted data
 * under a success message. Authenticate the plaintext, then break it.
 *
 * ## Why the container is frozen rather than generated
 *
 * It was written by the **Python reference**, not by the app. Building it
 * through the app would prove only that the app round-trips its own output, and
 * text mode cannot produce a non-UTF-8 payload in the first place — every
 * JavaScript string encodes to valid UTF-8. The scenario this guards is exactly
 * a file this app did not write.
 *
 * It is checked in rather than generated per run for two reasons. The browser
 * job installs Node and three browsers and no Python, so shelling out to the
 * reference made this the one test in the suite that could fail on a toolchain
 * question rather than on behaviour. And a frozen container is the better
 * artifact anyway: a generated one is written by today's reference, while this
 * one was written on a known day by a named revision and has to keep opening.
 *
 * Its password lives in the fixture rather than coming from `STRONG_PASSWORD`.
 * The bytes are frozen, so the password that opens them is frozen with them,
 * and borrowing the shared constant would mean an edit to that constant
 * silently breaks a container the browser suite cannot regenerate.
 */

interface BinaryFixture {
  /** A payload with a lone continuation byte and an unpaired 0xFF/0xFE. */
  plaintextHex: string;
  password: string;
  armor: string;
}

const FIXTURE: BinaryFixture = JSON.parse(
  readFileSync(resolve(__dirname, "fixtures/binary-plaintext.json"), "utf8")
);

test("a container of non-UTF-8 bytes is not reported as decrypted text", async ({ page }) => {
  // The fixture is worth nothing unless its payload really is malformed. An
  // edit that quietly replaced it with text would leave every assertion below
  // passing against a container that never reaches the guard.
  expect(() =>
    new TextDecoder("utf-8", { fatal: true }).decode(Buffer.from(FIXTURE.plaintextHex, "hex"))
  ).toThrow();
  expect(FIXTURE.armor.startsWith("keym2:")).toBe(true);

  await page.goto("/");
  await visible(page.getByRole("tab", { name: "Decrypt" })).click();
  await useTextMode(page);
  await visible(page.getByPlaceholder("Enter text to decrypt")).fill(FIXTURE.armor);
  await visible(page.getByPlaceholder("Enter decryption password")).fill(FIXTURE.password);

  const downloadPromise = page.waitForEvent("download", { timeout: 90_000 }).catch(() => null);
  await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();

  // Said plainly, and not as a success. The old behaviour showed "Success! Your
  // text has been successfully decrypted" over five replacement characters.
  await expect(
    visible(page.getByText(/not valid UTF-8/i)),
    "the app did not say the content was not text"
  ).toBeVisible({ timeout: 90_000 });

  // The bytes are handed over rather than discarded — they are already
  // authenticated, and making the user derive the key again in File mode to
  // reach them would be a second Argon2id run for nothing.
  const download = await downloadPromise;
  expect(download, "the verified bytes were not offered as a download").not.toBeNull();

  // And nothing was rendered as text. This is the assertion that would have
  // failed before the fix: the output field held U+FFFD where the bytes were.
  await expect(
    page.locator("#output-text"),
    "non-text bytes were rendered into the output field"
  ).toHaveCount(0);
});
