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
 * Encrypt `secret` and return the KEYM container as the UI produced it.
 * Waits on the Result field carrying a KEYM payload rather than on a timeout,
 * so a silently-failing crypto path shows up as a timeout instead of passing.
 */
export async function encryptText(page: Page, secret: string, password: string): Promise<string> {
  await visible(page.getByPlaceholder("Enter text to encrypt")).fill(secret);
  await visible(page.getByPlaceholder("Enter a strong password")).fill(password);
  await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();

  await page.waitForFunction(
    () => (document.querySelector("#output-text") as HTMLTextAreaElement | null)?.value?.startsWith("KEYM"),
    null,
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

  await page.waitForFunction(
    () => {
      const el = document.querySelector("#output-text") as HTMLTextAreaElement | null;
      return !!el && el.value.length > 0 && !el.value.startsWith("KEYM");
    },
    null,
    { timeout: 90_000 }
  );
  return page.evaluate(() => (document.querySelector("#output-text") as HTMLTextAreaElement).value);
}

/** A password that satisfies the strength gate. */
export const STRONG_PASSWORD = "correct-horse-battery-staple-9271!X";
