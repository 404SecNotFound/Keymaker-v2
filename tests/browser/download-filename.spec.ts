import { test, expect, type Page } from "@playwright/test";
import { visible, STRONG_PASSWORD } from "./helpers";

/**
 * U27, settled: **the non-ASCII download filename was a harness artifact.**
 *
 * The UAT reported that a file called `café-日本語-notes.txt` came back named
 * `download`, and parked the finding rather than fixing it, because a fix aimed
 * at a test-harness bug is worse than no fix. Confirming it needed something
 * that could see both sides of the boundary.
 *
 * This test is that confirmation, kept rather than discarded. It asserts what
 * the *application* hands the browser — the `download` attribute on the anchor
 * — which is the only part Keymaker controls and the only part a fix could ever
 * have changed. Measured here: the attribute carries
 * `café-日本語-notes.txt.keym` intact, while Playwright's `suggestedFilename()`
 * for the same download reports `download`.
 *
 * Two different answers for one event, and the one that names the product is
 * correct. So there is nothing to fix, and this exists so that stays true: if
 * the app ever *did* start mangling the name, the report would be real, and
 * this is what would say so.
 *
 * Deliberately not asserted here: what the file is finally called on disk. That
 * is the browser's decision, it varies by platform and download settings, and a
 * test claiming to pin it would be claiming to test something it cannot see.
 */

/** Record the `download` attribute of every anchor the page clicks. */
async function captureDownloadNames(page: Page): Promise<void> {
  await page.evaluate(() => {
    (window as unknown as { __downloadNames: string[] }).__downloadNames = [];
    const original = HTMLAnchorElement.prototype.click;
    HTMLAnchorElement.prototype.click = function (this: HTMLAnchorElement) {
      if (this.download) {
        (window as unknown as { __downloadNames: string[] }).__downloadNames.push(this.download);
      }
      return original.call(this);
    };
  });
}

test("a non-ASCII filename survives into the download the app offers", async ({ page }) => {
  await page.goto("/");
  await captureDownloadNames(page);

  const NAME = "café-日本語-notes.txt";
  await visible(page.getByRole("button", { name: "File", exact: true })).first().click();
  await page.setInputFiles('input[type="file"]', {
    name: NAME,
    mimeType: "text/plain",
    buffer: Buffer.from("a secret with an awkward filename"),
  });
  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);

  // The download event is awaited so the click has certainly completed, but its
  // suggestedFilename is not what this asserts — see the header.
  const downloadPromise = page.waitForEvent("download", { timeout: 90_000 }).catch(() => null);
  await visible(page.getByRole("button", { name: /^Encrypt File$/i })).click();
  await downloadPromise;

  await expect
    .poll(() => page.evaluate(() => (window as unknown as { __downloadNames: string[] }).__downloadNames), {
      message:
        "the app offered no download at all, so nothing here says anything about filenames",
      timeout: 30_000,
    })
    .toEqual([`${NAME}.keym`]);
});
