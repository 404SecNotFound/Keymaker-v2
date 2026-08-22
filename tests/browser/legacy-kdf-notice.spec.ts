import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { visible, useTextMode, selectCrypto, STRONG_PASSWORD } from "./helpers";

/**
 * A backup written before the current derivation floor opens exactly as it
 * always did — and now says so.
 *
 * §6's lower bounds are write-side on purpose: `validateKdfParams` enforces
 * minimums only when encrypting, because a tool whose entire promise is "you
 * can open this in twenty years" cannot start refusing files it wrote itself.
 * That behaviour is unchanged here and is pinned by the first test below.
 *
 * What was missing was that nobody was told. A container at a thousand PBKDF2
 * iterations opened with precisely as much ceremony as one at a million, so the
 * weakness was inherited in silence and its owner had no reason to re-encrypt.
 * The notice is informational: it appears beside the format line, after a
 * successful decrypt, and changes nothing about the decrypt itself.
 */

const fx = JSON.parse(
  readFileSync(resolve(__dirname, "fixtures/weak-legacy-kdf.json"), "utf8")
) as { armor: string; password: string; plaintext: string; iterations: number };

async function openWeakContainer(page: import("@playwright/test").Page) {
  await page.goto("/");
  await visible(page.getByRole("tab", { name: "Decrypt" })).click();
  await useTextMode(page);
  await visible(page.getByPlaceholder("Enter text to decrypt")).fill(fx.armor);
  await visible(page.getByPlaceholder("Enter decryption password")).fill(fx.password);
  await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();
}

test.describe("a pre-floor backup still opens, and now says it is old", () => {
  test("it decrypts, and the plaintext is intact", async ({ page }) => {
    // The control on every other test in this file. A notice about weak
    // parameters is worthless — worse than worthless — if the price of it is
    // that the file no longer opens.
    await openWeakContainer(page);

    await expect(
      visible(page.getByPlaceholder(/decrypted|Decrypted/)).or(page.locator("#output-text")).first(),
      "a container written below the current floor failed to open"
    ).toHaveValue(fx.plaintext, { timeout: 90_000 });
  });

  test("the notice names the parameters and recommends re-encryption", async ({ page }) => {
    await openWeakContainer(page);

    await expect(
      visible(page.getByText(/Heads up: this backup was made with/i)),
      "a weak-parameter container opened without saying its derivation is dated"
    ).toBeVisible({ timeout: 90_000 });

    // The specific number, not just a vague adjective — 1,000 against the
    // 600,000 floor is the whole reason to re-encrypt, and a warning that
    // will not say how bad it is invites being ignored.
    await expect(visible(page.getByText(/1,000 PBKDF2 iterations/))).toBeVisible();
    await expect(visible(page.getByText(/600,000 this version writes/))).toBeVisible();

    // And it must not read as a failure. The file opened.
    await expect(visible(page.getByText(/It opened fine and its contents are intact/i))).toBeVisible();
  });

  test("a container written today gets no notice", async ({ page }) => {
    // The other control. A warning that fires on everything is furniture: if
    // current-strength backups carry it too, it stops carrying information.
    await page.goto("/");
    await useTextMode(page);
    await selectCrypto(page, "pbkdf2", "aes");
    await visible(page.getByPlaceholder("Enter text to encrypt")).fill("written today");
    await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
    await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();

    const out = page.locator("#output-text");
    await expect.poll(async () => (await out.inputValue()).slice(0, 6), { timeout: 90_000 }).toBe("keym2:");
    const armor = await out.inputValue();

    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);
    await visible(page.getByPlaceholder("Enter text to decrypt")).fill(armor);
    await visible(page.getByPlaceholder("Enter decryption password")).fill(STRONG_PASSWORD);
    await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();

    await expect(visible(page.getByText(/Format:/))).toBeVisible({ timeout: 90_000 });
    await expect(
      page.getByText(/Heads up: this backup was made with/i),
      "a container written at today's settings was labelled as weak"
    ).toHaveCount(0);
  });
});
