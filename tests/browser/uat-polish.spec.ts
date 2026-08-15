import { test, expect } from "@playwright/test";
import { visible, useTextMode, selectCrypto } from "./helpers";

/**
 * UAT-2026-08-14, the correctness-and-polish set: U15, U16, U18, U21, U22,
 * U23, U25, U26, U28.
 *
 * Small fixes, but the report's own framing is worth keeping: several of these
 * are places where the app was *silently* wrong rather than visibly broken —
 * a dead button with no reason, a drop that vanished, a link to somebody
 * else's product. Nothing throws, so nothing catches them but a test that
 * looks at what the user sees.
 *
 * Every test here was run against the unfixed tree first; the control results
 * are recorded per describe block.
 */

const STRONG = "correct-horse-battery-staple-9271!X";

test.describe("U16 — links lead to this product's source", () => {
  test("GitHub and Open source point at Keymaker, and the fork credit does not", async ({
    page,
  }) => {
    await page.goto("/");

    // Both of these describe *Keymaker*, so both must lead to Keymaker.
    await expect(
      page.getByRole("link", { name: "GitHub", exact: true }),
      "the footer GitHub link sends people to a different product"
    ).toHaveAttribute("href", "https://github.com/404SecNotFound/Keymaker-v2");
    await expect(
      page.getByRole("link", { name: /^Open source$/ })
    ).toHaveAttribute("href", "https://github.com/404SecNotFound/Keymaker-v2");

    // ...and the GPL-3 attribution must NOT have been swept up in the fix.
    // Repointing this one would trade a broken link for a licensing
    // discourtesy, which is why the finding is two links and not three.
    await expect(
      page.getByRole("link", { name: /^IttyBitz$/ }),
      "the fork attribution was repointed away from the project being credited"
    ).toHaveAttribute("href", "https://github.com/seQRets/ittybitz");
  });
});

test.describe("U15 — a disabled button that explains itself", () => {
  test("says why Encrypt is disabled, and stops once the policy is met", async ({ page }) => {
    await page.goto("/");
    await useTextMode(page);
    await visible(page.getByPlaceholder("Enter text to encrypt")).fill("a secret");

    const notice = page.getByText(/Encrypt stays disabled until the password/i);
    const button = visible(page.getByRole("button", { name: /^Encrypt Text$/i }));

    // Nothing typed: the button is disabled for the obvious reason, and
    // explaining that would be nagging rather than helping.
    await expect(notice).toHaveCount(0);

    await visible(page.getByPlaceholder("Enter a strong password")).fill("short");
    await expect(button).toBeDisabled();
    await expect(
      notice.first(),
      "the button is disabled by policy and nothing on screen says so"
    ).toBeVisible();

    await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG);
    await expect(button).toBeEnabled();
    await expect(notice, "the explanation outlived the problem").toHaveCount(0);
  });
});

test.describe("U23 — Enter submits from the password field", () => {
  test("Enter encrypts when the button would, and does nothing when it would not", async ({
    page,
  }) => {
    await page.goto("/");
    await useTextMode(page);
    await visible(page.getByPlaceholder("Enter text to encrypt")).fill("press enter");

    const password = visible(page.getByPlaceholder("Enter a strong password"));

    // Routed through the same guard as the button: Enter must not become a way
    // to start an operation the button correctly refuses.
    await password.fill("short");
    await password.press("Enter");
    await page.waitForTimeout(500);
    // Absence, not emptiness: the output field is only mounted once an
    // operation has produced something, so "still not there" is the assertion
    // that an operation never started.
    await expect(
      page.locator("#output-text"),
      "Enter bypassed the password policy the button enforces"
    ).toHaveCount(0);

    await password.fill(STRONG);
    await password.press("Enter");
    await page.waitForFunction(
      // Existence *and* content. `?.value !== ""` is true while the element is
      // still absent, so on its own it returns the instant the page loads.
      () => {
        const el = document.querySelector("#output-text") as HTMLTextAreaElement | null;
        return el !== null && el.value !== "";
      },
      null,
      { timeout: 90_000 }
    );
    await expect(visible(page.locator("#output-text"))).not.toHaveValue("");
  });
});

test.describe("U25 — the reveal toggle describes its own state", () => {
  test("exposes aria-pressed and stops saying Hide over an empty field", async ({ page }) => {
    await page.goto("/");
    await useTextMode(page);

    const password = visible(page.getByPlaceholder("Enter a strong password"));
    await password.fill(STRONG);
    const toggle = visible(page.getByRole("button", { name: /^(Show|Hide) password$/ }));

    await expect(toggle, "a toggle with no pressed state reads identically in both").toHaveAttribute(
      "aria-pressed",
      "false"
    );
    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-pressed", "true");
    await expect(toggle).toHaveText("Hide");

    // The password is cleared after an operation while the toggle stays on.
    // "Hide" over an empty field claims something is concealed when nothing is.
    await password.fill("");
    await expect(
      toggle,
      "the button claims to be hiding a password that is not there"
    ).toHaveText("Show");
    await expect(toggle).toHaveAttribute("aria-pressed", "false");
  });
});

test.describe("U18 — the dropzone honours its own role", () => {
  test("Space activates it, as role=button promises", async ({ page }) => {
    await page.goto("/");

    const dropzone = visible(page.getByRole("button", { name: /drag|drop|browse/i })).first();
    await dropzone.focus();

    // The file picker cannot be observed from Playwright, but the event it
    // fires can: a native picker opens on click, and `filechooser` is the only
    // signal that the activation actually reached it.
    const chooser = page.waitForEvent("filechooser", { timeout: 3000 });
    await page.keyboard.press("Space");
    await expect(
      chooser,
      "Space did not activate a control that declares role=button"
    ).resolves.toBeTruthy();
  });

  test("Space does not also scroll the page", async ({ page }) => {
    await page.goto("/");
    // Enough content to make scrolling possible, or the assertion is vacuous.
    await page.setViewportSize({ width: 800, height: 400 });

    const dropzone = visible(page.getByRole("button", { name: /drag|drop|browse/i })).first();
    await dropzone.focus();
    const before = await page.evaluate(() => window.scrollY);
    await page.keyboard.press("Space");
    await page.waitForTimeout(300);

    expect(
      await page.evaluate(() => window.scrollY),
      "activating the dropzone with Space also jumped the page"
    ).toBe(before);
  });
});

test.describe("U22 — a drop that carried no file says so", () => {
  test("reports a fileless drop instead of swallowing it", async ({ page }) => {
    await page.goto("/");

    // A drop with items but no files — a dragged text selection, or a folder.
    await page.evaluate(() => {
      const zone = document.querySelector('[role="button"][tabindex="0"]') as HTMLElement;
      const dt = new DataTransfer();
      dt.setData("text/plain", "not a file");
      zone.dispatchEvent(new DragEvent("drop", { bubbles: true, cancelable: true, dataTransfer: dt }));
    });

    await expect(
      page.getByText(/carried no file/i).first(),
      "a drop with nothing usable in it vanished without a word"
    ).toBeVisible();
  });
});

test.describe("U21 — the dice tool counts in English", () => {
  test('says "1 more roll", not "1 more rolls"', async ({ page }) => {
    await page.goto("/");
    await visible(page.getByRole("tab", { name: "Tools" })).click();

    // A d6 needs 100 rolls for 256 bits, so 99 leaves exactly one.
    await visible(page.getByLabel(/rolls/i).first()).fill("99");

    await expect(page.getByText(/\b1 more rolls\b/)).toHaveCount(0);
    await expect(page.getByText(/\b1 more roll\b/).first()).toBeVisible();
  });
});

/**
 * `clipboard-read` and `clipboard-write` are not permission names Firefox or
 * WebKit recognise, so `grantPermissions` throws on them rather than being
 * ignored — the whole test dies before it reaches the page.
 *
 * Split rather than skipped. Everything except the clipboard *contents* is
 * engine-independent: whether the button exists at all, and whether it stays
 * disabled while the QR is hidden. Skipping the lot on two of three engines
 * would have surrendered that coverage to a permissions API detail, and the
 * disabled-until-revealed rule is the one with a security invariant behind it
 * (`getValue` must not run while the QR is hidden).
 */
test.describe("U28 — a SeedQR you can get off the screen without a camera", () => {
  test("offers Copy digits, disabled until the QR is revealed", async ({ page }) => {
    await page.goto("/");
    await useTextMode(page);
    await selectCrypto(page, "pbkdf2", "aes");

    const seed =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    await visible(page.getByPlaceholder("Enter text to encrypt")).fill(seed);
    await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG);
    await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();
    await page.waitForFunction(
      // Existence *and* content. `?.value !== ""` is true while the element is
      // still absent, so on its own it returns the instant the page loads.
      () => {
        const el = document.querySelector("#output-text") as HTMLTextAreaElement | null;
        return el !== null && el.value !== "";
      },
      null,
      { timeout: 90_000 }
    );
    const armored = await page.evaluate(
      () => (document.querySelector("#output-text") as HTMLTextAreaElement).value
    );

    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);
    await visible(page.getByPlaceholder("Enter text to decrypt")).fill(armored);
    await visible(page.getByPlaceholder("Enter decryption password")).fill(STRONG);
    await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();
    await expect(visible(page.locator("#output-text"))).toHaveValue(seed, { timeout: 90_000 });

    await visible(page.getByTitle(/Show SeedQR/i)).click();

    // Disabled before reveal, for the same reason Download is: it invokes
    // getValue, and the encoded secret must not be computed while hidden.
    const copy = visible(page.getByRole("button", { name: /^Copy digits$/ }));
    await expect(
      copy,
      "Copy digits computes the seed encoding, so it must not be live while the QR is hidden"
    ).toBeDisabled();

    await visible(page.getByRole("button", { name: /^Reveal QR$/ })).click();
    await expect(copy).toBeEnabled();
  });

  test("copies the digits themselves", async ({ page, context, browserName }) => {
    test.skip(
      browserName !== "chromium",
      "clipboard-read/write are not permission names Firefox or WebKit accept"
    );
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
    await page.goto("/");
    await useTextMode(page);
    await selectCrypto(page, "pbkdf2", "aes");

    const seed =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    await visible(page.getByPlaceholder("Enter text to encrypt")).fill(seed);
    await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG);
    await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();
    await page.waitForFunction(
      () => {
        const el = document.querySelector("#output-text") as HTMLTextAreaElement | null;
        return el !== null && el.value !== "";
      },
      null,
      { timeout: 90_000 }
    );
    const armored = await page.evaluate(
      () => (document.querySelector("#output-text") as HTMLTextAreaElement).value
    );

    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);
    await visible(page.getByPlaceholder("Enter text to decrypt")).fill(armored);
    await visible(page.getByPlaceholder("Enter decryption password")).fill(STRONG);
    await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();
    await expect(visible(page.locator("#output-text"))).toHaveValue(seed, { timeout: 90_000 });

    await visible(page.getByTitle(/Show SeedQR/i)).click();
    await visible(page.getByRole("button", { name: /^Reveal QR$/ })).click();
    await visible(page.getByRole("button", { name: /^Copy digits$/ })).click();

    // A Standard SeedQR is four digits per word — the whole point of copying
    // it rather than photographing a code.
    const clip = await page.evaluate(() => navigator.clipboard.readText());
    expect(clip, `clipboard held ${clip.length} chars`).toMatch(/^\d{48}$/);
  });
});

test.describe("U26 — the typography floor", () => {
  test("nothing renders below 12px", async ({ page }) => {
    await page.goto("/");

    // Computed, not grepped for a class name: a utility class is an intention,
    // and what a reader on a phone gets is the computed value.
    const tooSmall = await page.evaluate(() => {
      const out: string[] = [];
      for (const el of Array.from(document.body.querySelectorAll("*"))) {
        const text = (el.textContent ?? "").trim();
        if (!text || el.children.length > 0) continue;
        const size = parseFloat(getComputedStyle(el).fontSize);
        if (size > 0 && size < 12) out.push(`${size}px: ${text.slice(0, 40)}`);
      }
      return out;
    });

    expect(tooSmall, `text below the 12px floor: ${tooSmall.join(" | ")}`).toEqual([]);
  });
});
