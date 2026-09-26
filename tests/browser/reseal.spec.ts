import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { visible, useTextMode, encryptText, STRONG_PASSWORD } from "./helpers";

/**
 * Re-sealing an old backup.
 *
 * v3 §7: "A v2 container is still strippable. v3 protects containers written
 * as v3." And v3 §6: "There is no in-place upgrade. Moving a v2 backup to v3
 * means decrypting and re-encrypting it, which is a user's decision and needs
 * their secret." Nothing in the app said so at the moment it matters — with a
 * v2 backup open on the Decrypt tab.
 *
 * The offer is deliberately not a one-click re-encrypt. The password is
 * cleared on a successful decrypt (U13) and the plaintext buffer is erased, so
 * a silent re-seal would have to keep both. Instead the recovered text is
 * carried to the Encrypt tab as its input — where it is already on screen —
 * and the ordinary seal path writes today's format with a password the owner
 * types. Shares and passkeys are not carried over, and the notice says so:
 * the share secret is discarded at enrolment (v2 §4.6) and a passkey slot
 * needs the authenticator.
 */

const CORPUS = resolve(__dirname, "../../scripts/fixtures/keymaker");
const meta = JSON.parse(readFileSync(resolve(CORPUS, "fixtures.json"), "utf8")) as {
  password: string;
  fixtures: Array<{ name: string; file: string; plaintext: string }>;
};
const fixture = (name: string) => {
  const fx = meta.fixtures.find((f) => f.name === name);
  if (!fx) throw new Error(`corpus has no fixture named ${name}`);
  return fx;
};
const armor = (file: string): string =>
  "keym2:" +
  readFileSync(resolve(CORPUS, file)).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

function versionOf(armorText: string): number {
  const b64 = armorText.slice("keym2:".length).replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(b64 + "=".repeat((4 - (b64.length % 4)) % 4), "base64")[4]!;
}

async function openFixture(page: import("@playwright/test").Page, name: string) {
  const fx = fixture(name);
  await page.goto("/");
  await visible(page.getByRole("tab", { name: "Decrypt" })).click();
  await useTextMode(page);
  await visible(page.getByPlaceholder("Enter text to decrypt")).fill(armor(fx.file));
  await visible(page.getByPlaceholder("Enter decryption password")).fill(meta.password);
  await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();
  await expect(visible(page.locator("#output-text"))).toHaveValue(fx.plaintext, { timeout: 90_000 });
  return fx;
}

test.describe("re-seal an old backup", () => {
  test("a v2 backup is offered a re-seal, and the seal writes v3", async ({ page }) => {
    const fx = await openFixture(page, "v2-pbkdf2-aes256gcm");
    const offer = visible(page.getByRole("button", { name: "Re-seal this backup" }));
    await expect(offer, "the offer appears with the v2 backup open").toBeVisible();
    await expect(page.getByText(/its list of ways in is not authenticated/i)).toBeVisible();
    await offer.click();

    await expect(visible(page.getByRole("tab", { name: "Encrypt" }))).toHaveAttribute("aria-selected", "true");
    await expect(
      visible(page.getByPlaceholder("Enter text to encrypt")),
      "the recovered text is the new backup's input"
    ).toHaveValue(fx.plaintext);
    await expect(page.getByText(/shares and passkeys are not carried over/i)).toBeVisible();

    const sealed = await encryptText(page, fx.plaintext, STRONG_PASSWORD);
    expect(versionOf(sealed), "the re-sealed backup is today's format").toBe(3);
  });

  test("a v3 backup is not offered one", async ({ page }) => {
    await openFixture(page, "v3-pbkdf2-aes256gcm");
    await expect(page.getByRole("button", { name: "Re-seal this backup" })).toHaveCount(0);
  });
});
