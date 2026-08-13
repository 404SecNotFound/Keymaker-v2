import { test, expect } from "@playwright/test";
import { decryptText, encryptText, useTextMode, visible } from "./helpers";
import { EFF_LARGE_WORDLIST, EFF_LARGE_WORDLIST_SIZE } from "../../src/lib/eff-wordlist";

/**
 * The passphrase generator, exercised against the production build.
 *
 * scripts/verify-wordlist.mjs proves the shipped list is EFF's, complete and
 * unaltered. That is the denominator. These tests cover the numerator: that
 * the running app draws from that list, states a bit count consistent with it,
 * and can actually encrypt under what it produced.
 *
 * The last of those is not a formality. The password policy gate blocks
 * encryption, and it judges typed input on morphology — distinct words and
 * length. A uniform seven-word draw repeats a word roughly once in 370, which
 * the distinct-word rule reads as padding. Without provenance being passed to
 * the gate, roughly one generated passphrase in 370 would be certified as 90
 * bits in the UI and then refused by the Encrypt button.
 */

const WORDS = 7;
const EXPECTED_BITS = Math.floor(WORDS * Math.log2(EFF_LARGE_WORDLIST_SIZE)); // 90

/**
 * The inline status line under the password field — the app's live claim about
 * the string currently in it. Distinct from the toast, which reports that a
 * generation happened and keeps quoting its figure for a few seconds after.
 */
const CLAIM = /Generated · \d+ words drawn uniformly/;

/** Click Generate → Passphrase and read back what landed in the field. */
async function generatePassphrase(page: import("@playwright/test").Page): Promise<string> {
  await visible(page.getByRole("button", { name: "Passphrase", exact: true })).click();
  return visible(page.getByPlaceholder("Enter a strong password")).inputValue();
}

test("generates seven words, all drawn from the EFF long list", async ({ page }) => {
  await page.goto("/");
  await useTextMode(page);

  const phrase = await generatePassphrase(page);
  const words = phrase.split(" ");

  expect(words).toHaveLength(WORDS);

  // Membership is the claim that matters: a word not on the list would mean
  // the index arithmetic is wrong, and the stated bit count would describe a
  // sampling process the app is not performing.
  const list = new Set(EFF_LARGE_WORDLIST);
  const strangers = words.filter((w) => !list.has(w));
  expect(strangers, "every word comes from the bundled list").toEqual([]);

  // No entry on the list contains whitespace, so the split is exact and the
  // word count the UI states is the number of draws that were actually made.
  expect(phrase.trim()).toBe(phrase);
});

test("states the entropy the wordlist actually supports", async ({ page }) => {
  await page.goto("/");
  await useTextMode(page);
  await generatePassphrase(page);

  const body = await page.evaluate(() => document.body.innerText);
  expect(body).toContain(`${EXPECTED_BITS} bits`);
  expect(body).toContain(EFF_LARGE_WORDLIST_SIZE.toLocaleString("en-US"));
  // The figure is claimed only for what the CSPRNG produced, so it must be
  // presented as generated rather than as a rating of the string.
  expect(body).toMatch(CLAIM);
});

test("successive passphrases differ", async ({ page }) => {
  await page.goto("/");
  await useTextMode(page);

  const seen = new Set<string>();
  for (let i = 0; i < 5; i++) {
    seen.add(await generatePassphrase(page));
  }
  // Collision probability for 5 draws of 7 words is ~2^-88. A repeat means the
  // CSPRNG is not being consulted per click.
  expect(seen.size).toBe(5);
});

test("a generated passphrase can encrypt and decrypt", async ({ page }) => {
  await page.goto("/");
  await useTextMode(page);

  const phrase = await generatePassphrase(page);
  const secret = "seed phrase behind a generated passphrase";

  const container = await encryptText(page, secret, phrase);
  expect(container.startsWith("KEYM1:")).toBe(true);

  expect(await decryptText(page, container, phrase)).toBe(secret);
});

test("editing a generated passphrase withdraws the entropy claim", async ({ page }) => {
  await page.goto("/");
  await useTextMode(page);

  const phrase = await generatePassphrase(page);
  expect(await page.evaluate(() => document.body.innerText)).toMatch(CLAIM);

  // The claim holds for the exact string the CSPRNG produced and nothing else.
  // Retyping the same words by hand is indistinguishable from having chosen
  // them, which is the whole reason the figure is provenance-gated.
  await visible(page.getByPlaceholder("Enter a strong password")).fill(`${phrase} extra`);

  // Matched against the inline status line, not a bare bit count: the toast
  // announcing the generation is still on screen and still quotes the figure,
  // which is fine — it is a record of what happened, not a claim about the
  // string now in the field.
  const body = await page.evaluate(() => document.body.innerText);
  expect(body).not.toMatch(CLAIM);
  expect(body).toContain("Minimum policy met");
});
