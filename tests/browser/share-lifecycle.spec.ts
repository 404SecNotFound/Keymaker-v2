import { test, expect, type Page } from "@playwright/test";
import { visible, useTextMode, selectCrypto, STRONG_PASSWORD } from "./helpers";

/**
 * KM-R03: recovery shares are password-equivalent, and were outside the
 * lifecycle that treats passwords as secrets.
 *
 * §4.6 is explicit that k shares open a container *without* the password. The
 * auto-lock predicate and the panic-wipe button both keyed off password, text
 * secret and output text only — so in the flow that matters most, an heir
 * recovering a file, all three can be empty while the textarea holds enough
 * shares to open everything. The countdown never started and the Wipe now
 * button was not rendered.
 *
 * That is the wrong way round. Share-based recovery is the flow where the
 * person at the keyboard is least likely to be at their own desk.
 */

/** Enough share-shaped text to make the state non-empty. */
const SHARE_TEXT = [
  "KMSHARE1:05DZ-4EG3-07VX-TDNP-J21H-K81F-5P11-ZPRS-H0PG-NGC1-PJAP-9ZZY-W78Z-GT37-NF2B-RXE1-JYF0",
  "KMSHARE1:05DZ-4EG3-095E-01FR-2W41-DTRC-G4Z5-YVCK-MRX3-8TVN-5FGC-63MX-3H4B-7PMX-FVDK-Z4V5-0KTG",
].join("\n");

async function pasteShares(page: Page) {
  await page.goto("/");
  await visible(page.getByRole("tab", { name: "Decrypt" })).click();
  await useTextMode(page);
  await visible(page.getByRole("button", { name: /^Use recovery shares$/i })).click();
  await visible(page.getByPlaceholder(/KMSHARE1:/)).fill(SHARE_TEXT);
}

test.describe("recovery shares are treated as secrets", () => {
  test("pasted shares alone arm the lock and show Wipe now", async ({ page }) => {
    await pasteShares(page);

    // No password, no text secret, no output — exactly the state the old
    // predicate called "nothing worth locking".
    await expect(
      visible(page.getByPlaceholder("Enter decryption password")),
      "this test only means something with the password field empty"
    ).toHaveValue("");

    await expect(
      visible(page.getByRole("button", { name: /^Wipe now$/i })),
      "shares on screen did not count as secrets on screen"
    ).toBeVisible({ timeout: 30_000 });
  });

  test("Wipe now clears the pasted shares", async ({ page }) => {
    await pasteShares(page);
    await visible(page.getByRole("button", { name: /^Wipe now$/i })).click();

    // Absent or empty both count: the wipe may unmount the textarea along with
    // the mode. What must not survive is the text.
    await expect
      .poll(
        async () => {
          const box = page.getByPlaceholder(/KMSHARE1:/);
          return (await box.count()) === 0 ? "" : await box.first().inputValue();
        },
        { message: "the panic wipe left recovery shares in the DOM", timeout: 30_000 }
      )
      .toBe("");
  });

  /**
   * The other half of KM-R03, and the half with teeth.
   *
   * Pasted shares can be pasted again. *Issued* shares exist exactly once: the
   * dialog says so itself, and closing it is the only copy gone. Bringing them
   * inside the auto-lock — which is right, they are the most password-
   * equivalent thing the app ever shows — hands a five-minute fuse to a screen
   * whose entire purpose is being read off slowly onto paper.
   *
   * Reading is not activity. `lastActivityRef` moves on pointer and key events,
   * and a person copying sixteen-group share strings by hand touches nothing
   * for minutes at a time. So the warning is the whole safety mechanism, and
   * the warning has to be reachable from where the user actually is.
   */
  test("the lock warning is reachable while issued shares are on screen", async ({ page }) => {
    await page.clock.install();
    await page.goto("/");
    await useTextMode(page);
    await selectCrypto(page, "pbkdf2", "aes");

    const advanced = visible(page.getByRole("button", { name: /^Advanced/ }));
    if ((await advanced.getAttribute("aria-expanded")) !== "true") await advanced.click();
    await visible(page.getByLabel("Recovery shares")).click();
    await visible(page.getByLabel("Shares to print")).fill("3");
    await visible(page.getByLabel("Needed to open")).fill("2");

    await visible(page.getByPlaceholder("Enter text to encrypt")).fill("shares to transcribe");
    await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
    await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();
    await expect(page.getByText(/Save these 3 shares now/)).toBeVisible({ timeout: 90_000 });

    // Four and a half minutes of transcription. The countdown is showing
    // somewhere by now — the question is whether it is showing anywhere the
    // person reading the shares can reach it.
    await page.clock.runFor("04:40");

    // Clicked, not merely queried for visibility. Playwright calls an element
    // visible when it has a box, covered or not, so `toBeVisible` passes on a
    // warning sitting underneath a modal overlay. The hit-target check is what
    // distinguishes "rendered" from "usable", and usable is the claim.
    await visible(page.getByRole("button", { name: /Keep open/i })).click({ timeout: 10_000 });

    // And the shares survived, because the user said so.
    await page.clock.runFor("01:00");
    await expect(
      page.getByText(/Save these 3 shares now/),
      "the issued shares were wiped despite the user asking to keep them"
    ).toBeVisible();
  });

  test("turning the mode off does not leave the shares behind it", async ({ page }) => {
    await pasteShares(page);
    // Back to a password. The textarea disappears; the question is whether its
    // contents did.
    await visible(page.getByRole("button", { name: /^Use a password instead$/i })).click();
    await visible(page.getByRole("button", { name: /^Use recovery shares$/i })).click();

    await expect(
      visible(page.getByPlaceholder(/KMSHARE1:/)),
      "the shares came back when the mode was re-enabled"
    ).toHaveValue("");
  });
});
