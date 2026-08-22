import { test, expect } from "@playwright/test";
import { visible, useTextMode, selectCrypto, STRONG_PASSWORD } from "./helpers";

/**
 * The shipped layout, not the convenient one.
 *
 * Production is built with `KEYMAKER_BASE_PATH: /Keymaker-v2` (deploy.yml), so
 * every script and stylesheet in the built HTML is referenced absolutely:
 * `/Keymaker-v2/_next/static/...`. Until now the suite served `out/` at the
 * origin root, where those URLs are never exercised — the whole suite could be
 * green against a layout no user has ever received.
 *
 * That is not a hypothetical gap. PR #68 found what lives in it: opening a
 * release's `index.html` from `file://` resolves those absolute paths against
 * the filesystem root, all ten of them 404, and the page still renders a
 * heading, a password box and an Encrypt button. It looks like a styling
 * glitch. It cannot encrypt anything.
 *
 * These tests only mean something when the run is base-path'd, so they skip
 * otherwise rather than passing vacuously — a skip is visible in the report,
 * a silent pass is not.
 */

const BASE_PATH = (process.env.KEYMAKER_BASE_PATH ?? "").replace(/\/$/, "");

test.describe("the build is served the way it ships", () => {
  test.skip(
    () => BASE_PATH === "",
    "no KEYMAKER_BASE_PATH: this run serves from the origin root, so there is no base path to verify"
  );

  test("every asset the page asks for is found under the base path", async ({ page }) => {
    const failed: string[] = [];
    const notFound: string[] = [];
    page.on("requestfailed", (r) => failed.push(`${r.failure()?.errorText} ${r.url()}`));
    page.on("response", (r) => {
      if (r.status() >= 400) notFound.push(`${r.status()} ${r.url()}`);
    });

    await page.goto(`${BASE_PATH}/`);
    await visible(page.getByRole("button", { name: /^Advanced/ })).waitFor();

    expect(failed, "a request failed outright").toEqual([]);
    expect(notFound, "the page asked for something the host does not have").toEqual([]);
  });

  test("the assets really are prefixed, so this is not passing by accident", async ({ page }) => {
    // The control on the test above. If the build were served at the root
    // after all, or emitted relative URLs, "nothing 404'd" would be true and
    // would prove nothing about the shipped layout.
    await page.goto(`${BASE_PATH}/`);

    const srcs = await page.evaluate(() =>
      Array.from(document.querySelectorAll("script[src]")).map((s) => s.getAttribute("src") ?? "")
    );

    expect(srcs.length, "no external scripts on the page at all").toBeGreaterThan(0);
    expect(
      srcs.filter((s) => !s.startsWith(`${BASE_PATH}/`)),
      "a script is referenced without the base path, so this build is not the one that ships"
    ).toEqual([]);
  });

  test("and it still encrypts, which is the point of the assets loading", async ({ page }) => {
    // Rendering proves the HTML arrived. Only a round trip proves the
    // JavaScript did — #68's broken page rendered perfectly and was inert.
    await page.goto(`${BASE_PATH}/`);
    await useTextMode(page);
    await selectCrypto(page, "pbkdf2", "aes");
    await visible(page.getByPlaceholder("Enter text to encrypt")).fill("served as it ships");
    await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
    await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();

    await expect
      .poll(async () => (await page.locator("#output-text").inputValue()).slice(0, 6), {
        message: "the base-path build rendered but produced no container",
        timeout: 120_000,
      })
      .toBe("keym2:");
  });
});
