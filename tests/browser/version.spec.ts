import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { visible } from "./helpers";

/**
 * Roadmap 6.1 — the app version is stated once and read everywhere.
 *
 * The footer used to carry its own literal beside package.json's, which is two
 * strings free to drift. The one that drifts is the one that matters: the
 * footer is what a user can see, so it is what they quote in a bug report, so
 * a wrong value there sends someone debugging the wrong build.
 *
 * The point of this test is not that the number is 2.0.0. It is that there is
 * only one place the number comes from.
 */
// Relative to the project root, which is where Playwright runs. `import.meta.url`
// would be tidier and flips this file into ESM mode, which breaks the helpers
// import that every other spec here relies on.
const pkg = JSON.parse(readFileSync("package.json", "utf8"));

test.describe("version coherence", () => {
  test("the footer reports exactly the version in package.json", async ({ page }) => {
    await page.goto("/");

    const footer = visible(page.getByText(/^Keymaker v/));
    await expect(
      footer,
      "the footer version does not match package.json — one of them is a stale literal"
    ).toContainText(`Keymaker v${pkg.version}`);

    // The placeholder from next.config.js's fallback. Seeing it means the
    // build-time injection broke and the footer is guessing.
    await expect(footer).not.toContainText("unknown");
  });

  test("the app version and the container format version are stated separately", async ({
    page,
  }) => {
    await page.goto("/");

    // Someone whose file will not open needs to know which number is which.
    // Conflating them is the confusion 6.1 exists to prevent, and it would be
    // invisible in a test that only checked the app version was present.
    const footer = visible(page.getByText(/^Keymaker v/));
    await expect(footer).toContainText("writes KEYM v2");
    expect(
      pkg.version.startsWith("2."),
      `app version is ${pkg.version}; if it ever diverges from the format major, ` +
        `that is fine — but the footer must keep saying both, which is what the ` +
        `assertion above pins`
    ).toBe(true);
  });
});
