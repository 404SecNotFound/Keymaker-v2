import { test, expect } from "@playwright/test";

/**
 * The app does not render inside another document.
 *
 * The CSP arrives as a `<meta>`, which cannot carry `frame-ancestors`, and
 * GitHub Pages cannot send `X-Frame-Options`. Nothing stopped another site
 * framing the app invisibly over a decoy and steering a visitor's clicks
 * through the decrypt and copy flow. The one defence left to the page is to
 * hide itself when `window.top` is not `window.self`.
 *
 * Framed from a document with no policy of its own, the way an attacker's
 * page would do it. The control bites: with the check removed from the
 * layout's inline script, the framed document keeps its display.
 */
test.describe("framing", () => {
  test("the app hides itself when framed, and not otherwise", async ({ page, baseURL }) => {
    // The decoy is served on the test origin, by a route, with no policy of
    // its own. Written into about:blank it counts as a public document and
    // Chromium's private-network-access check refuses to let it frame
    // 127.0.0.1; written over a page the app had loaded, it inherits the
    // app's meta CSP, whose default-src 'none' refuses to frame anything.
    // Either way the frame never loads and proves nothing. The guard compares
    // window.top with window.self and does not care about origins.
    await page.route("**/__decoy.html", (route) =>
      route.fulfill({
        contentType: "text/html",
        body: `<!doctype html><title>decoy</title><iframe id="f" src="${baseURL}/" width="1000" height="800"></iframe>`,
      })
    );
    await page.goto("/__decoy.html");
    const handle = await page.waitForSelector("#f");
    const frame = await handle.contentFrame();
    expect(frame, "the iframe never produced a frame").not.toBeNull();
    // The guard runs from the inline script at the end of <body>, so the
    // framed document reaches it as soon as it has parsed.
    await expect
      .poll(() => frame!.evaluate(() => document.documentElement.style.display), { timeout: 30_000 })
      .toBe("none");

    // Top-level, the same document is shown: the guard is a frame check, not
    // a kill switch.
    await page.goto("/");
    await expect(page.getByRole("tab", { name: "Decrypt" })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.style.display)).toBe("");
  });
});
