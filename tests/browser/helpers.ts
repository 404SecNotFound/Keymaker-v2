import type { Page, Locator } from "@playwright/test";

/**
 * Shared driving helpers for the browser suite.
 *
 * Both mode tabs are mounted at once, so almost every control exists twice in
 * the DOM. `visible()` disambiguates by what the user can actually see, which
 * is also what a user would click.
 */
export const visible = (locator: Locator): Locator => locator.locator("visible=true").first();

export type Kdf = "pbkdf2" | "argon2id";
export type Cipher = "aes" | "chacha" | "chained";

export const CIPHER_LABEL: Record<Cipher, string | RegExp> = {
  aes: "AES-256-GCM",
  chacha: "ChaCha20-Poly1305",
  chained: "AES → ChaCha (chained)",
};

/** Switch the visible panel from File mode to Text mode. */
export async function useTextMode(page: Page): Promise<void> {
  await visible(page.getByRole("button", { name: "Text", exact: true })).click();
}

/** Open Advanced and select a KDF + cipher combination. */
export async function selectCrypto(page: Page, kdf: Kdf, cipher: Cipher): Promise<void> {
  const advanced = visible(page.getByRole("button", { name: /^Advanced/ }));
  if ((await advanced.getAttribute("aria-expanded")) !== "true") {
    await advanced.click();
  }

  const kdfLabel = kdf === "pbkdf2" ? "PBKDF2" : "Argon2id";
  await visible(page.getByRole("button").filter({ hasText: kdfLabel })).click();

  await visible(page.getByRole("button").filter({ hasText: CIPHER_LABEL[cipher] })).click();
}

/**
 * Every armor prefix the app has ever written.
 *
 * `KEYM1:` for v1, `keym2:` for v2 — and the case difference is the point of
 * FORMAT-V2-DESIGN §7 rather than an inconsistency: lowercase `k` (0x6B) is
 * what separates armored text from the binary magic `KEYM` (0x4B) in a single
 * byte, with no ordering dependency between checks.
 *
 * This helper matches any of them deliberately. Its job is "some armored
 * output appeared", so that a silently-failing crypto path surfaces as a
 * timeout. **Which** format the app writes is a separate assertion and lives
 * in crypto.spec.ts, where it can fail with a message that names the prefix.
 *
 * Hard-coding `KEYM` here is what broke the suite when the app started writing
 * v2: `"keym2:…".startsWith("KEYM")` is false, so every test routed through
 * this helper waited its full 90 s and failed on a timeout — 60 of them across
 * three engines, none of the messages mentioning a prefix.
 */
export const ARMOR_PREFIXES = ["KEYM1:", "keym2:"] as const;

/**
 * Encrypt `secret` and return the container as the UI produced it.
 * Waits on the Result field carrying an armored payload rather than on a
 * timeout, so a silently-failing crypto path shows up as a timeout instead of
 * passing.
 */
export async function encryptText(page: Page, secret: string, password: string): Promise<string> {
  await visible(page.getByPlaceholder("Enter text to encrypt")).fill(secret);
  await visible(page.getByPlaceholder("Enter a strong password")).fill(password);
  await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();

  await page.waitForFunction(
    (prefixes: readonly string[]) => {
      const value = (document.querySelector("#output-text") as HTMLTextAreaElement | null)?.value;
      return !!value && prefixes.some((p) => value.startsWith(p));
    },
    ARMOR_PREFIXES,
    { timeout: 90_000 }
  );
  return page.evaluate(() => (document.querySelector("#output-text") as HTMLTextAreaElement).value);
}

/** Decrypt a container on the Decrypt tab and return the recovered plaintext. */
export async function decryptText(page: Page, container: string, password: string): Promise<string> {
  await visible(page.getByRole("tab", { name: "Decrypt" })).click();
  await useTextMode(page);
  await visible(page.getByPlaceholder("Enter text to decrypt")).fill(container);
  await visible(page.getByPlaceholder("Enter decryption password")).fill(password);
  await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();

  // "Output exists and is not still the container." The exclusion has to cover
  // every armor prefix, not just v1's: `"keym2:…".startsWith("KEYM")` is false,
  // so the old check would have accepted a leftover v2 container as though it
  // were recovered plaintext — a test helper handing back its own input and
  // calling it a round-trip.
  await page.waitForFunction(
    (prefixes: readonly string[]) => {
      const el = document.querySelector("#output-text") as HTMLTextAreaElement | null;
      return !!el && el.value.length > 0 && !prefixes.some((p) => el.value.startsWith(p));
    },
    ARMOR_PREFIXES,
    { timeout: 90_000 }
  );
  return page.evaluate(() => (document.querySelector("#output-text") as HTMLTextAreaElement).value);
}

/** A password that satisfies the strength gate. */
export const STRONG_PASSWORD = "correct-horse-battery-staple-9271!X";
