import { test, expect } from "@playwright/test";
import {
  decryptText,
  encryptText,
  selectCrypto,
  useTextMode,
  visible,
  STRONG_PASSWORD,
  type Cipher,
  type Kdf,
} from "./helpers";

/**
 * Every KDF x cipher combination, exercised through the real UI against the
 * production build.
 *
 * The Node suite already covers these combinations at the library level and
 * passes. It passed while Argon2id could not derive a single key in the
 * shipped bundle, because the CSP that blocked WebAssembly exists only in the
 * production HTML and Node has no CSP at all. These tests are the ones that
 * would have caught it.
 */

const KDFS: Kdf[] = ["pbkdf2", "argon2id"];
const CIPHERS: Cipher[] = ["aes", "chacha", "chained"];

const SECRET = "attack at dawn — keymaker browser suite ✅ 日本語";

test.describe("KEYM round-trips in a real browser", () => {
  for (const kdf of KDFS) {
    for (const cipher of CIPHERS) {
      test(`${kdf} + ${cipher} round-trips through the UI`, async ({ page }) => {
        const consoleErrors: string[] = [];
        page.on("pageerror", (e) => consoleErrors.push(e.message));

        await page.goto("/");
        await useTextMode(page);
        await selectCrypto(page, kdf, cipher);

        const container = await encryptText(page, SECRET, STRONG_PASSWORD);
        expect(container.startsWith("KEYM1:")).toBe(true);

        const recovered = await decryptText(page, container, STRONG_PASSWORD);
        expect(recovered).toBe(SECRET);

        expect(consoleErrors, "no uncaught page errors").toEqual([]);
      });
    }
  }
});

test("the self-describing header is read back on decrypt", async ({ page }) => {
  await page.goto("/");
  await useTextMode(page);
  await selectCrypto(page, "argon2id", "chained");

  const container = await encryptText(page, SECRET, STRONG_PASSWORD);
  await decryptText(page, container, STRONG_PASSWORD);

  // The container states its own parameters, and the UI surfaces them.
  const body = await page.evaluate(() => document.body.innerText);
  expect(body).toContain("Argon2id");
  expect(body).toMatch(/Format:\s*Keymaker v1/);
});

test("a wrong password is refused", async ({ page }) => {
  await page.goto("/");
  await useTextMode(page);
  await selectCrypto(page, "pbkdf2", "aes");

  const container = await encryptText(page, SECRET, STRONG_PASSWORD);

  await visible(page.getByRole("tab", { name: "Decrypt" })).click();
  await useTextMode(page);
  await visible(page.getByPlaceholder("Enter text to decrypt")).fill(container);
  await visible(page.getByPlaceholder("Enter decryption password")).fill("not-the-right-password-at-all-9999");
  await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();

  // The Result field must never populate with plaintext.
  await page.waitForTimeout(6000);
  const output = await page.evaluate(
    () => (document.querySelector("#output-text") as HTMLTextAreaElement | null)?.value ?? ""
  );
  expect(output).not.toContain("attack at dawn");
});

test("a tampered container is refused", async ({ page }) => {
  await page.goto("/");
  await useTextMode(page);
  await selectCrypto(page, "pbkdf2", "aes");

  const container = await encryptText(page, SECRET, STRONG_PASSWORD);

  // Corrupt one base64 character in the body, leaving the KEYM1: prefix.
  const prefix = "KEYM1:";
  const payload = container.slice(prefix.length);
  const idx = Math.floor(payload.length / 2);
  const swapped = payload[idx] === "A" ? "B" : "A";
  const tampered = prefix + payload.slice(0, idx) + swapped + payload.slice(idx + 1);

  await visible(page.getByRole("tab", { name: "Decrypt" })).click();
  await useTextMode(page);
  await visible(page.getByPlaceholder("Enter text to decrypt")).fill(tampered);
  await visible(page.getByPlaceholder("Enter decryption password")).fill(STRONG_PASSWORD);
  await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();

  await page.waitForTimeout(6000);
  const output = await page.evaluate(
    () => (document.querySelector("#output-text") as HTMLTextAreaElement | null)?.value ?? ""
  );
  expect(output).not.toContain("attack at dawn");
});
