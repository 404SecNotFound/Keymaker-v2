import { test, expect } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { STRONG_PASSWORD, visible, useTextMode } from "./helpers";

/**
 * KM-R08: text mode must not silently mangle bytes that are not text.
 *
 * `new TextDecoder()` replaces every malformed sequence with U+FFFD and reports
 * no error. A KEYM container can hold arbitrary bytes — nothing in the format
 * says a payload is text, and another conforming implementation may well write
 * binary — so decoding leniently handed the user irreversibly corrupted data
 * under a success message. Authenticate the plaintext, then break it.
 *
 * The container here is built by the **Python reference**, on purpose. Building
 * it through the app would prove only that the app round-trips its own output,
 * and the app has no way to produce a non-UTF-8 payload in text mode. The
 * scenario this guards is exactly a file this app did not write.
 */

const REFERENCE = resolve(process.cwd(), "reference/keym2.py");

/** A payload with a lone continuation byte and an unpaired 0xFF/0xFE. */
const RAW = Buffer.from([0x00, 0x80, 0xff, 0xfe, 0x41]);

function armoredBinaryContainer(): string {
  const script = `
import sys
sys.path.insert(0, ${JSON.stringify(resolve(process.cwd(), "reference"))})
import keym2
raw = bytes(${JSON.stringify(Array.from(RAW))})
c = keym2.encrypt(raw, ${JSON.stringify(STRONG_PASSWORD)},
                  kdf_id=keym2.KDF_PBKDF2,
                  iterations=keym2.PBKDF2_ITER_POLICY_MIN)
print(keym2.armor(c))
`;
  return execFileSync("python3", ["-c", script], { encoding: "utf8" }).trim();
}

test("a container of non-UTF-8 bytes is not reported as decrypted text", async ({ page }) => {
  // Fails loudly rather than skipping if the reference cannot run: a silently
  // skipped test here would leave the regression unguarded.
  const container = armoredBinaryContainer();
  expect(container.startsWith("keym2:"), `the reference did not produce a container: ${container}`).toBe(
    true
  );
  expect(REFERENCE).toBeTruthy();

  await page.goto("/");
  await visible(page.getByRole("tab", { name: "Decrypt" })).click();
  await useTextMode(page);
  await visible(page.getByPlaceholder("Enter text to decrypt")).fill(container);
  await visible(page.getByPlaceholder("Enter decryption password")).fill(STRONG_PASSWORD);

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
