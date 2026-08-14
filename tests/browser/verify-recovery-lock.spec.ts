import { test, expect, type Page } from "@playwright/test";
import { visible, useTextMode, encryptText, STRONG_PASSWORD } from "./helpers";

/**
 * Phase 2.3, 2.4 and 2.6 — three features that share one theme: what happens
 * to a secret *after* the cryptography is done with it.
 *
 * The crypto core cannot see any of this. A container can be perfectly
 * authenticated and the plaintext still end up in the clipboard for an hour, on
 * an unattended screen, or unreadable in 2040 because the only decryptor lived
 * on a website that no longer exists.
 */

/** Encrypt a secret on a fresh page and return the container. */
async function makeContainer(page: Page, secret: string) {
  await page.goto("/");
  await useTextMode(page);
  return encryptText(page, secret, STRONG_PASSWORD);
}

/** Put a KEYM blob into the Decrypt panel's text field, ready to process. */
async function stageForDecrypt(page: Page, blob: string) {
  await visible(page.getByRole("tab", { name: "Decrypt" })).click();
  await useTextMode(page);
  await visible(page.getByPlaceholder("Enter text to decrypt")).fill(blob);
}

const decryptPassword = (page: Page) =>
  visible(page.getByPlaceholder("Enter decryption password"));

// ---------------------------------------------------------------- 2.3 verify

test.describe("verify-only mode", () => {
  test("confirms a backup opens without ever showing what is in it", async ({ page }) => {
    const secret = "abandon ability able about above absent absorb abstract";
    const blob = await makeContainer(page, secret);

    await stageForDecrypt(page, blob);
    await visible(page.getByLabel(/Verify only/i)).click();

    // The action renames itself: "Decrypt" would be a lie about what happens.
    const action = visible(page.getByRole("button", { name: /^Verify Text$/i }));
    await expect(action).toBeVisible();

    await decryptPassword(page).fill(STRONG_PASSWORD);
    await action.click();

    await expect(page.getByText(/The backup opens with this password/i)).toBeVisible();

    // The claim that matters: the plaintext reached no part of the page.
    const body = (await page.locator("body").textContent()) ?? "";
    expect(body, "verify-only rendered the decrypted contents").not.toContain(secret);
    expect(body, "verify-only rendered part of the decrypted contents").not.toContain(
      "abandon ability"
    );
    await expect(
      page.locator("#output-text"),
      "verify-only populated the result field"
    ).toHaveCount(0);

    // A byte count is reported, because "it opens" alone does not catch the
    // right password on the wrong backup.
    await expect(page.getByText(new RegExp(`${secret.length} bytes`))).toBeVisible();
  });

  test("a wrong password fails verification", async ({ page }) => {
    const blob = await makeContainer(page, "correct horse battery staple");

    await stageForDecrypt(page, blob);
    await visible(page.getByLabel(/Verify only/i)).click();
    await decryptPassword(page).fill(`${STRONG_PASSWORD}-wrong`);
    await visible(page.getByRole("button", { name: /^Verify Text$/i })).click();

    // .first(): the toast renders its text twice — once visibly, and once in
    // the aria-live region a screen reader announces.
    await expect(page.getByText(/Decryption failed/i).first()).toBeVisible();
    await expect(
      page.getByText(/The backup opens with this password/i),
      "a wrong password must not report success"
    ).toHaveCount(0);
  });

  test("leaving it off still decrypts normally", async ({ page }) => {
    const secret = "this one should be visible";
    const blob = await makeContainer(page, secret);

    await stageForDecrypt(page, blob);
    await decryptPassword(page).fill(STRONG_PASSWORD);
    await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();

    await expect(visible(page.locator("#output-text"))).toHaveValue(secret);
  });
});

// ---------------------------------------------------------- 2.4 recovery kit

test.describe("recovery kit", () => {
  test("both files are served from this origin and are the real thing", async ({
    page,
    baseURL,
  }) => {
    // Fetched over HTTP rather than read off disk: the question is whether a
    // user can actually get them from the deployment, not whether the build
    // produced them.
    const py = await page.request.get(`${baseURL}/recovery/keym.py`);
    expect(py.status(), "keym.py is not being served").toBe(200);
    const pySource = await py.text();
    expect(pySource, "keym.py is not the reference decryptor").toContain("def decrypt");
    expect(pySource.length).toBeGreaterThan(5_000);

    const md = await page.request.get(`${baseURL}/recovery/RECOVERY.md`);
    expect(md.status(), "RECOVERY.md is not being served").toBe(200);
    expect(await md.text()).toContain("keym.py");
  });

  test("the footer opens a kit with working download links", async ({ page }) => {
    await page.goto("/");
    await visible(page.getByRole("button", { name: /Recovery kit/i })).click();

    const dialog = page.getByRole("dialog");
    await expect(dialog.getByText("keym.py").first()).toBeVisible();
    await expect(dialog.getByText("RECOVERY.md").first()).toBeVisible();

    // Same-origin and download-flagged, so saving it does not navigate away
    // from a page that may be holding a decrypted secret.
    const links = dialog.getByRole("link", { name: /Save/i });
    await expect(links).toHaveCount(2);
    for (const link of await links.all()) {
      await expect(link).toHaveAttribute("download", "");
      expect(await link.getAttribute("href")).toMatch(/\/recovery\/(keym\.py|RECOVERY\.md)$/);
    }
  });

  test("the service worker precaches the kit for offline use", async ({
    page,
    browserName,
  }) => {
    // Same exclusion as every other service-worker test in this suite — see
    // platform.spec.ts. The kit is still asserted to be *served* on WebKit by
    // the test above; only the Cache Storage half is unobservable there.
    test.skip(browserName === "webkit", "service workers are not testable in WebKit here");
    await page.goto("/");
    await page.evaluate(() => navigator.serviceWorker.ready);

    const cached = await page.evaluate(async () => {
      const names = await caches.keys();
      const found: string[] = [];
      for (const name of names) {
        const keys = await (await caches.open(name)).keys();
        for (const request of keys) {
          if (request.url.includes("/recovery/")) found.push(new URL(request.url).pathname);
        }
      }
      return found.sort();
    });

    // The whole point of the kit is that it survives the site being gone. A
    // copy that requires the network to read is not that.
    expect(cached.join(" "), "the recovery kit is not in Cache Storage").toMatch(
      /RECOVERY\.md/
    );
    expect(cached.join(" ")).toMatch(/keym\.py/);
  });
});

// ------------------------------------------------- 2.6 auto-lock & clipboard

test.describe("auto-lock and clipboard", () => {
  test("idle time wipes the password and any decrypted output", async ({ page }) => {
    // Playwright's clock control, rather than a five-minute wait or a test-only
    // shortcut wired into the production build. The timeout under test is the
    // real one.
    await page.clock.install();
    const secret = "wipe me after five minutes";
    const blob = await makeContainer(page, secret);

    await stageForDecrypt(page, blob);
    await decryptPassword(page).fill(STRONG_PASSWORD);
    await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();
    await expect(visible(page.locator("#output-text"))).toHaveValue(secret);

    // Just inside the warning window: it should say so, and still be showing.
    await page.clock.runFor("04:35");
    await expect(page.getByText(/Locking in/i)).toBeVisible();
    await expect(visible(page.locator("#output-text"))).toHaveValue(secret);

    // Past the deadline. Asserted on the wipe rather than the toast: toasts are
    // removed 1s after dismissal, and 40s of virtual time takes the notice with
    // it. The security claim is that the secrets are gone, not that something
    // was announced — and the announcement is covered by the Wipe now test,
    // which runs on a real clock.
    await page.clock.runFor("00:40");
    await expect(
      page.locator("#output-text"),
      "a decrypted secret survived the auto-lock"
    ).toHaveCount(0);
    await expect(decryptPassword(page)).toHaveValue("");
    await expect(page.getByText(/Locking in/i)).toHaveCount(0);
  });

  test("Keep open cancels the pending lock", async ({ page }) => {
    await page.clock.install();
    await page.goto("/");

    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await decryptPassword(page).fill(STRONG_PASSWORD);

    await page.clock.runFor("04:40");
    const keepOpen = visible(page.getByRole("button", { name: /Keep open/i }));
    await expect(keepOpen).toBeVisible();
    await keepOpen.click();
    await expect(page.getByText(/Locking in/i)).toHaveCount(0);

    // The clock that would have fired the lock passes with nothing happening.
    await page.clock.runFor("01:00");
    await expect(decryptPassword(page)).toHaveValue(STRONG_PASSWORD);
  });

  test("Wipe now clears secrets but keeps settings", async ({ page }) => {
    await page.goto("/");
    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);
    await decryptPassword(page).fill(STRONG_PASSWORD);

    await visible(page.getByRole("button", { name: /Wipe now/i })).click();

    await expect(decryptPassword(page)).toHaveValue("");
    await expect(page.getByText(/^Wiped$/).first()).toBeVisible();

    // A wipe is not a reset: Text mode was the user's choice, not a secret, and
    // resetState would have thrown it away by returning the panel to File.
    await expect(
      visible(page.getByPlaceholder("Enter text to decrypt")),
      "wiping threw away the input-type choice as well"
    ).toBeVisible();
  });

  test("copying starts a visible countdown and clears unconditionally", async ({
    page,
    context,
    browserName,
  }) => {
    test.skip(browserName !== "chromium", "clipboard permissions are Chromium-only here");
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
    await page.clock.install();
    await page.goto("/");

    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await decryptPassword(page).fill(STRONG_PASSWORD);
    await visible(page.getByRole("button", { name: /^Copy$/i })).click();

    await expect(page.getByText(/Clipboard clears in/i)).toBeVisible();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(STRONG_PASSWORD);

    // The old implementation read the clipboard back and only cleared it if the
    // contents still matched. That read needs focus and permission, threw in
    // practice, and sat inside a bare catch — so the secret stayed. Overwriting
    // is now unconditional, which is what this asserts.
    await page.clock.runFor("01:05");
    await expect(page.getByText(/Clipboard clears in/i)).toHaveCount(0);
    expect(
      await page.evaluate(() => navigator.clipboard.readText()),
      "the clipboard still held the secret after its stated lifetime"
    ).toBe("");
  });
});
