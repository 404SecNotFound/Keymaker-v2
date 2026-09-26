import { test, expect } from "@playwright/test";
import { visible, useTextMode, encryptText, decryptText, STRONG_PASSWORD } from "./helpers";

/**
 * KEYM v4 (docs/FORMAT-V4-DESIGN.md), at the one place it is chosen: a switch
 * on the Encrypt tab.
 *
 * v4 §6 says writers MAY pad and does not move the default, because the cost
 * lands on the owner's medium: a padded backup is more bytes, and on paper
 * more bytes are more symbols. So the switch is off until the owner turns it
 * on, and states the cost beside itself. What this file checks is that turning
 * it on does what the format promises — two secrets of different lengths give
 * one container length — and that the result still opens here.
 */

/** The container bytes, read out of armored text. */
function bytesOf(armor: string): Buffer {
  const b64 = armor.slice("keym2:".length).replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(b64 + "=".repeat((4 - (b64.length % 4)) % 4), "base64");
}

async function openTheSwitch(page: import("@playwright/test").Page) {
  await page.goto("/");
  await useTextMode(page);
  await visible(page.getByRole("button", { name: /^Advanced/ })).click();
  const sw = visible(page.getByRole("switch", { name: "Hide the size of what is inside" }));
  await expect(sw, "the switch is off by default (v4 §6)").toHaveAttribute("aria-checked", "false");
  await sw.click();
  await expect(sw).toHaveAttribute("aria-checked", "true");
  return sw;
}

test.describe("hide the size", () => {
  test("the switch is off by default and names its cost", async ({ page }) => {
    await openTheSwitch(page);
    await expect(
      page.getByText(/older readers cannot open it/i),
      "the cost is stated where the choice is made"
    ).toBeVisible();
  });

  test("on, a short secret and a long one seal to the same length, as v4", async ({ page }) => {
    await openTheSwitch(page);
    const short = await encryptText(page, "a", STRONG_PASSWORD);
    const shortBytes = bytesOf(short);
    expect(shortBytes[4], "the switch writes KEYM v4").toBe(4);

    await page.goto("/");
    await openTheSwitch(page);
    const long = await encryptText(page, "b".repeat(200), STRONG_PASSWORD);
    const longBytes = bytesOf(long);
    expect(longBytes[4]).toBe(4);
    expect(
      longBytes.length,
      "v4 §4.3: every plaintext up to 248 bytes gives the same container length"
    ).toBe(shortBytes.length);
  });

  test("a padded backup opens here, with the padding gone", async ({ page }) => {
    await openTheSwitch(page);
    const secret = "twelve words that must come back exactly as they went in, no more";
    const container = await encryptText(page, secret, STRONG_PASSWORD);
    expect(bytesOf(container)[4]).toBe(4);
    const recovered = await decryptText(page, container, STRONG_PASSWORD);
    expect(recovered, "not one padding byte reaches the owner").toBe(secret);
    await expect(page.getByText(/Format: KEYM v4/)).toBeVisible();
  });

  test("off, the app still writes v3", async ({ page }) => {
    await page.goto("/");
    await useTextMode(page);
    const container = await encryptText(page, "unchanged default", STRONG_PASSWORD);
    expect(bytesOf(container)[4], "the default did not move (v4 §6)").toBe(3);
  });
});
