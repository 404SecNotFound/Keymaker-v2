import { test, expect } from "@playwright/test";
import { visible, useTextMode, selectCrypto } from "./helpers";

/**
 * Phase 4.1d — recovery shares, driven the way a user reaches them.
 *
 * The format and the core landed with byte-equality parity against the Python
 * reference, and none of that is retested here. What these cover is the part
 * that has no reference implementation: whether a person can actually enrol a
 * share set and, later, open the container with nothing but paper.
 *
 * The last test is the one that matters. Everything else is a control on it.
 */

const PASSWORD = "correct-horse-battery-staple-9271!X";
const SECRET = "abandon ability able about above absent absorb abstract 🔑";

/** Turn on shares in Advanced and set the k-of-n. */
async function enableShares(page: import("@playwright/test").Page, k: number, n: number) {
  const advanced = visible(page.getByRole("button", { name: /^Advanced/ }));
  if ((await advanced.getAttribute("aria-expanded")) !== "true") await advanced.click();
  await visible(page.getByLabel("Recovery shares")).click();
  await visible(page.getByLabel("Shares to print")).fill(String(n));
  await visible(page.getByLabel("Needed to open")).fill(String(k));
}

async function encryptWithShares(
  page: import("@playwright/test").Page,
  k: number,
  n: number
): Promise<{ armored: string; shares: string[] }> {
  await page.goto("/");
  await useTextMode(page);
  await selectCrypto(page, "pbkdf2", "aes");
  await enableShares(page, k, n);

  await visible(page.getByPlaceholder("Enter text to encrypt")).fill(SECRET);
  await visible(page.getByPlaceholder("Enter a strong password")).fill(PASSWORD);
  await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();

  await expect(page.getByText(new RegExp(`Save these ${n} shares now`))).toBeVisible({
    timeout: 90_000,
  });
  const shares = await page.locator("p.font-mono").allTextContents();
  // Escape rather than hunting for a close control. Radix's dismiss button is
  // an icon whose accessible name and attributes are an implementation detail
  // of the component library, and a locator built on those is a portability
  // hazard between engines — which is precisely how the U28 clipboard test put
  // main red on two of three.
  await page.keyboard.press("Escape");
  await expect(page.getByText(/Save these/)).toHaveCount(0);

  const armored = await page.evaluate(
    () => (document.querySelector("#output-text") as HTMLTextAreaElement).value
  );
  return { armored, shares: shares.filter((s) => s.startsWith("KMSHARE1:")) };
}

test.describe("enrolling a share set", () => {
  test("issues n shares and says what they cost, once", async ({ page }) => {
    const { armored, shares } = await encryptWithShares(page, 2, 3);

    expect(shares, "the share set was not produced").toHaveLength(3);
    for (const s of shares) expect(s).toMatch(/^KMSHARE1:[0-9A-HJKMNP-TV-Z-]+$/);
    expect(new Set(shares).size, "two shares came out identical").toBe(3);
    expect(armored.startsWith("keym2:"), "the container is not v2 armor").toBe(true);
  });

  test("the honest framing is on screen, not only in the docs", async ({ page }) => {
    await page.goto("/");
    await useTextMode(page);
    await enableShares(page, 2, 3);

    // Roadmap, "Honest framing to preserve": any k shares open the container
    // without the password, so each share is as sensitive as the password.
    // A test rather than a comment, because copy is the first thing to be
    // trimmed by someone who does not know why it is there.
    await expect(
      page.getByText(/Each share is as sensitive as your password/i).first()
    ).toBeVisible();
  });

  test("the threshold cannot exceed the number of shares", async ({ page }) => {
    await page.goto("/");
    await useTextMode(page);
    await enableShares(page, 2, 3);

    // A set nobody can ever reach is the worst outcome a backup feature has.
    await visible(page.getByLabel("Needed to open")).fill("9");
    await expect(visible(page.getByLabel("Needed to open"))).toHaveValue("3");

    await visible(page.getByLabel("Shares to print")).fill("2");
    await expect(
      visible(page.getByLabel("Needed to open")),
      "lowering the count left a threshold above it"
    ).toHaveValue("2");
  });
});

test.describe("a share pasted into the wrong box", () => {
  test("is named as a share rather than failing as a container", async ({ page }) => {
    const { shares } = await encryptWithShares(page, 2, 3);

    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);
    await visible(page.getByPlaceholder("Enter text to decrypt")).fill(shares[0] as string);

    // §7's wrong-box paste. Without this it reaches the parser and comes back
    // as a generic decryption failure.
    await expect(page.getByText(/recovery share, not an encrypted container/i)).toBeVisible();
  });
});

test.describe("the inheritance path", () => {
  test("k shares open the container with no password at all", async ({ page }) => {
    const { armored, shares } = await encryptWithShares(page, 2, 3);

    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);
    await visible(page.getByPlaceholder("Enter text to decrypt")).fill(armored);

    await visible(page.getByRole("button", { name: /^Use recovery shares$/ })).click();

    // Shares 2 and 3, not 1 and 2 — a reconstruction that had quietly become
    // positional would still pass with the leading pair.
    await visible(page.locator("#share-input")).fill(
      `# share 2 of 3\n${shares[1]}\n# share 3 of 3\n${shares[2]}\n`
    );

    // The password field is left completely empty. That is the whole claim.
    await expect(
      visible(page.getByRole("button", { name: /^Decrypt Text$/i })),
      "the button stayed disabled with a valid share set entered and no password"
    ).toBeEnabled();

    await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();
    await expect(visible(page.locator("#output-text"))).toHaveValue(SECRET, { timeout: 90_000 });
  });

  test("k-1 shares do not", async ({ page }) => {
    const { armored, shares } = await encryptWithShares(page, 3, 5);

    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);
    await visible(page.getByPlaceholder("Enter text to decrypt")).fill(armored);
    await visible(page.getByRole("button", { name: /^Use recovery shares$/ })).click();
    await visible(page.locator("#share-input")).fill(`${shares[0]}\n${shares[1]}\n`);
    await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();

    await expect(page.getByText(/Decryption failed/i).first()).toBeVisible({ timeout: 90_000 });
    await expect(page.locator("#output-text")).toHaveCount(0);
  });

  test("the password still opens a container that has a share set", async ({ page }) => {
    const { armored } = await encryptWithShares(page, 2, 3);

    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);
    await visible(page.getByPlaceholder("Enter text to decrypt")).fill(armored);
    await visible(page.getByPlaceholder("Enter decryption password")).fill(PASSWORD);
    await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();

    // §4.4's skip rule from the owner's side: enrolling shares must not cost
    // them the way in they already had.
    await expect(visible(page.locator("#output-text"))).toHaveValue(SECRET, { timeout: 90_000 });
  });
});
