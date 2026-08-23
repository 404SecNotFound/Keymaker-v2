import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { visible, appPath } from "./helpers";

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

  test("a build that is not the tagged release says so", async ({ page }) => {
    // The provenance half of 6.1, and the half that was missing. The deployed
    // site reported "v2.0.0" while running twenty-odd commits past the v2.0.0
    // tag, so the number a user quotes in a bug report — or checks a signature
    // against — named an artifact they were not running.
    //
    // Only release.yml sets KEYMAKER_RELEASE_TAG, so every build this suite
    // ever sees is a development one. That makes the assertion unambiguous
    // here and is exactly why it is worth pinning: if the marker regressed to
    // always-absent, nothing else in the suite would notice.
    await page.goto("/");
    const footer = visible(page.getByText(/^Keymaker v/));
    await expect(
      footer,
      "a non-release build did not mark itself — the version is claiming to be the tag"
    ).toContainText(`Keymaker v${pkg.version}-dev`);
  });

  test("the app version and the container format version are stated separately", async ({
    page,
  }) => {
    await page.goto("/");

    // Someone whose file will not open needs to know which number is which.
    // Conflating them is the confusion 6.1 exists to prevent, and it would be
    // invisible in a test that only checked the app version was present.
    const footer = visible(page.getByText(/^Keymaker v/));

    // Not pinned to a number. The footer renders `KEYM2_VERSION`, so pinning a
    // literal here would only re-record whatever the app happens to write —
    // which is how the previous version of this assertion sat green while the
    // footer said v2 and the app wrote v3. What is worth pinning is the shape:
    // two versions, stated separately, one of them the container format's.
    const written = (await footer.textContent())?.match(/writes KEYM v(\d+)/);
    expect(
      written,
      "the footer no longer names the container format it writes, so someone " +
        "whose file will not open cannot tell which number is which"
    ).not.toBeNull();
    expect(
      pkg.version.startsWith("2."),
      `app version is ${pkg.version}; if it ever diverges from the format major, ` +
        `that is fine — but the footer must keep saying both, which is what the ` +
        `assertion above pins`
    ).toBe(true);

    // The claim on /verify is a literal, because importing the constant there
    // would pull the crypto core into the one route that should stay small.
    // This is what keeps it honest: the page that cannot derive the number is
    // checked against the page that does.
    await page.goto(appPath("/verify.html"));
    await expect(
      page.getByTestId("verify-format"),
      "the verify page and the footer disagree about which container format " +
        "this build writes, which is the drift that let the footer say v2 for " +
        "as long as it did"
    ).toHaveText(`KEYM v${written?.[1]}`);
  });
});
