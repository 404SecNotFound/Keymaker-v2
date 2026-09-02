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

/**
 * Review item 5: the share textarea was unbounded.
 *
 * It took whatever was pasted straight into state, and two render-path callers
 * re-split the whole thing on every keystroke. Not a crypto boundary — the
 * parser rejects anything that is not a share — but an input the UI rescans
 * that often should have a size, and the realistic way to hit it is pasting
 * the wrong thing, which §7 says to name rather than swallow.
 */
test.describe("the share input has a size", () => {
  async function openShareBox(page: Page) {
    await page.goto("/");
    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);
    await visible(page.getByRole("button", { name: /^Use recovery shares$/i })).click();
    return visible(page.getByPlaceholder(/KMSHARE1:/));
  }

  test("a real share set is still accepted", async ({ page }) => {
    // The control. Every rejection below is worthless if the gate also refuses
    // the thing it exists to let through.
    const box = await openShareBox(page);
    await box.fill(SHARE_TEXT);
    await expect(box).toHaveValue(SHARE_TEXT);
    await expect(visible(page.getByText(/2 shares entered/))).toBeVisible();
  });

  test("an oversized paste is refused and says so", async ({ page }) => {
    const box = await openShareBox(page);
    await box.fill(SHARE_TEXT);

    // Someone pastes the encrypted container into the share box — the wrong-box
    // paste, with a large artefact.
    await box.fill("A".repeat(9 * 1024));

    await expect(
      visible(page.getByText(/this box takes up to 8 KB/i)),
      "an oversized paste was accepted, or was refused without saying why"
    ).toBeVisible();
    await expect(
      box,
      "the refused paste replaced what was already there"
    ).toHaveValue(SHARE_TEXT);
  });

  test("too many lines is refused", async ({ page }) => {
    const box = await openShareBox(page);
    await box.fill(Array.from({ length: 20 }, (_, i) => `KMSHARE1:LINE-${i}`).join("\n"));

    await expect(
      visible(page.getByText(/takes up to 16/i)),
      "20 lines were accepted into a box for at most 8 shares"
    ).toBeVisible();
    await expect(box, "the refused paste was kept").toHaveValue("");
  });
});

/**
 * The two data-loss paths a code review found after KM-R03 landed.
 *
 * KM-R03 brought issued shares into the auto-lock, which was right, and the
 * follow-up made the countdown reachable from inside their dialog, which was
 * also right. Neither addressed what the timer then *does*: freshly issued
 * shares exist exactly once, and destroying them on an idle timer is aimed
 * precisely at the person transcribing them onto paper — reading produces no
 * pointer or key events.
 */
test.describe("issued shares survive what they must", () => {
  async function issueShares(page: Page) {
    await page.goto("/");
    await useTextMode(page);
    await selectCrypto(page, "pbkdf2", "aes");
    const advanced = visible(page.getByRole("button", { name: /^Advanced/ }));
    if ((await advanced.getAttribute("aria-expanded")) !== "true") await advanced.click();
    await visible(page.getByLabel("Recovery shares")).click();
    await visible(page.getByLabel("Shares to print")).fill("3");
    await visible(page.getByLabel("Needed to open")).fill("2");
    await visible(page.getByPlaceholder("Enter text to encrypt")).fill("inheritance");
    await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
    await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();
    await expect(page.getByText(/Save these 3 shares now/)).toBeVisible({ timeout: 90_000 });
  }

  test("the idle lock clears the password but not the shares", async ({ page }) => {
    await page.clock.install();
    await issueShares(page);

    // Well past the deadline, with no interaction at all — the transcription
    // case. Before this fix the dialog closed here and the shares were gone.
    await page.clock.runFor("06:00");

    await expect(
      page.getByText(/Save these 3 shares now/),
      "an idle timer destroyed shares that exist exactly once"
    ).toBeVisible();

    // And the lock still did its job on everything recoverable.
    await expect(
      page.getByPlaceholder("Enter a strong password"),
      "the lock spared the shares but also spared the password"
    ).toHaveValue("");
  });

  test("the idle lock fires once, not once a second", async ({ page }) => {
    await page.clock.install();
    await issueShares(page);

    // Sparing the shares keeps secrets on screen, so the lock effect never
    // re-runs and its interval keeps sampling. Nothing moved the activity
    // mark when the lock fired, so every later tick was past the deadline
    // again: a new "Locked" toast each second, replacing the last, on top of
    // the person transcribing shares. Each firing mounts a fresh toast element
    // (the toast store gives each one a new id, so the old root unmounts and
    // a new `li` is inserted with its subtree), so counting toast roots that
    // enter the DOM distinguishes one firing from many. The root is matched
    // by its `data-state` attribute rather than a role: the only
    // `role="status"` element is Radix's hidden announcer, which is inserted
    // empty and gets its text a frame later.
    await page.evaluate(() => {
      const w = window as unknown as { __lockToasts: number };
      w.__lockToasts = 0;
      new MutationObserver((records) => {
        for (const record of records) {
          for (const node of record.addedNodes) {
            if (
              node instanceof HTMLLIElement &&
              node.hasAttribute("data-state") &&
              (node.textContent ?? "").includes("Locked")
            ) {
              w.__lockToasts++;
            }
          }
        }
      }).observe(document.body, { childList: true, subtree: true });
    });

    await page.clock.runFor("05:01");
    await expect
      .poll(() => page.evaluate(() => (window as unknown as { __lockToasts: number }).__lockToasts), {
        message: "expected exactly one lock at the deadline: 0 means it never fired, more means it fired on every tick",
      })
      .toBe(1);

    // Five more idle seconds. With the defect these are five more locks.
    await page.clock.runFor("00:05");
    expect(
      await page.evaluate(() => (window as unknown as { __lockToasts: number }).__lockToasts),
      "the lock fired again on every tick after the deadline"
    ).toBe(1);

    await expect(
      page.getByText(/Save these 3 shares now/),
      "the once-only lock stopped sparing the shares"
    ).toBeVisible();
  });

  test("Wipe now still destroys them, because that is a person deciding", async ({ page }) => {
    // The control on the test above. Sparing them from the timer must not
    // spare them from the panic button, or the button stops meaning anything.
    await issueShares(page);
    await page.keyboard.press("Escape");
    await expect(page.getByText(/Save these 3 shares now/)).toHaveCount(0);

    await visible(page.getByPlaceholder("Enter text to encrypt")).fill("something");
    await visible(page.getByRole("button", { name: /^Wipe now$/i })).click();
    await expect(page.getByText(/^Wiped$/).first()).toBeVisible();
  });
});

/**
 * The paper-vault button in the shares dialog read `outputText`, which is only
 * written on the text branch. Encrypting a *file* with shares — the commonest
 * route to this dialog — left it empty, so `dearmorKeym2('')` threw inside an
 * async handler with no catch: no print, no error, nothing.
 */
test("the paper vault button never fails silently", async ({ page }) => {
  await page.goto("/");
  await selectCrypto(page, "pbkdf2", "aes");
  const advanced = visible(page.getByRole("button", { name: /^Advanced/ }));
  if ((await advanced.getAttribute("aria-expanded")) !== "true") await advanced.click();
  await visible(page.getByLabel("Recovery shares")).click();
  await visible(page.getByLabel("Shares to print")).fill("3");
  await visible(page.getByLabel("Needed to open")).fill("2");

  // File mode, which is where the bug lives.
  await page.locator("#encrypt-file").setInputFiles({
    name: "will.txt",
    mimeType: "text/plain",
    buffer: Buffer.from("the estate"),
  });
  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
  await visible(page.getByRole("button", { name: /^Encrypt File$/i })).click();
  await expect(page.getByText(/Save these 3 shares now/)).toBeVisible({ timeout: 90_000 });

  const print = page.getByRole("button", { name: /^Print paper vault$/ });
  await expect(
    print,
    "the button is live on a path where it cannot work, so pressing it does nothing"
  ).toBeDisabled();
  await expect(
    visible(page.getByText(/not here to print/i)),
    "the button is disabled without saying why"
  ).toBeVisible();
});
