import { test, expect } from "@playwright/test";
import { encryptText, selectCrypto, useTextMode, STRONG_PASSWORD } from "./helpers";

/**
 * Platform guarantees that only exist in a browser running the production
 * bundle: the CSP, WebAssembly availability under that CSP, zero egress, the
 * service worker, and offline operation.
 *
 * None of this is observable from Node. Every regression these catch would
 * otherwise ship green.
 */

test("the production page ships a strict CSP", async ({ page }) => {
  await page.goto("/");
  const csp = await page.evaluate(
    () =>
      document
        .querySelector('meta[http-equiv="Content-Security-Policy"]')
        ?.getAttribute("content") ?? ""
  );

  expect(csp, "CSP meta tag must be present in the production build").not.toBe("");
  expect(csp).toContain("default-src 'none'");
  // The page must not be able to open a connection at all — this is what makes
  // "nothing leaves your browser" a property of the policy, not of the code.
  expect(csp).toContain("connect-src 'none'");
  expect(csp).toContain("object-src 'none'");
  expect(csp).toContain("base-uri 'self'");
  const scriptSrc = csp.split(";").find((d) => d.trim().startsWith("script-src")) ?? "";
  // script-src is tightened at build time from 'unsafe-inline' to per-file hashes.
  expect(scriptSrc).not.toContain("'unsafe-inline'");
  expect(scriptSrc).toMatch(/'sha256-/);
  // Argon2id cannot instantiate without this, and fails silently if it is gone.
  expect(scriptSrc).toContain("'wasm-unsafe-eval'");

  // style-src keeps 'unsafe-inline' deliberately: React and Tailwind set
  // style="" attributes, which hashes cannot cover without 'unsafe-hashes'
  // and a per-attribute hash for every one — fragile, for no gain here.
  const styleSrc = csp.split(";").find((d) => d.trim().startsWith("style-src")) ?? "";
  expect(styleSrc).toContain("'unsafe-inline'");
});

test("WebAssembly can actually compile under that CSP", async ({ page }) => {
  await page.goto("/");
  const result = await page.evaluate(async () => {
    try {
      // Smallest valid module: the 8-byte header.
      await WebAssembly.instantiate(new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]));
      return "ok";
    } catch (e) {
      return `blocked: ${(e as Error).message}`;
    }
  });
  // This exact assertion is the regression test for the shipped Argon2id bug.
  expect(result).toBe("ok");
});

test("Argon2id is the default and the UI does not offer a dead option", async ({ page }) => {
  await page.goto("/");
  await useTextMode(page);
  await page.getByRole("button", { name: /^Advanced/ }).locator("visible=true").first().click();
  await page.waitForTimeout(1500); // let the capability probe settle

  const state = await page.evaluate(() => {
    const buttons = Array.from(document.querySelectorAll("button"));
    const argon = buttons.find((b) => b.textContent?.includes("Argon2id"));
    return {
      argonText: argon?.textContent ?? "",
      argonDisabled: argon?.hasAttribute("disabled") ?? false,
      // The selected option carries the accent border.
      argonSelected: argon?.className.includes("border-accent") ?? false,
    };
  });

  // Where WASM works — every browser in this matrix — Argon2id must be the
  // default rather than a recommendation the user has to go and find.
  expect(state.argonDisabled).toBe(false);
  expect(state.argonSelected).toBe(true);
  expect(state.argonText).toContain("default");
});

test("no off-origin request is ever made", async ({ page }) => {
  const offOrigin: string[] = [];
  page.on("request", (r) => {
    if (!r.url().startsWith("http://127.0.0.1:4321") && !r.url().startsWith("data:")) {
      offOrigin.push(`${r.method()} ${r.url()}`);
    }
  });

  await page.goto("/");
  await useTextMode(page);
  await selectCrypto(page, "argon2id", "chained");
  await encryptText(page, "a secret that must not leave the device", STRONG_PASSWORD);

  expect(offOrigin, "the page must not talk to anything").toEqual([]);
});

test("the app works fully offline after first load", async ({ page, context, browserName }) => {
  // Service workers are not available in WebKit under Playwright's default
  // configuration, so offline support cannot be exercised there.
  test.skip(browserName === "webkit", "service worker offline mode is not testable in WebKit here");

  await page.goto("/");
  // Wait for the service worker to take control.
  await page.waitForFunction(() => navigator.serviceWorker?.controller !== null, null, {
    timeout: 30_000,
  });

  await context.setOffline(true);
  await page.reload();

  // The shell must still render and crypto must still work with no network.
  await expect(page.getByRole("tab", { name: "Encrypt" })).toBeVisible();
  await useTextMode(page);
  await selectCrypto(page, "argon2id", "aes");
  const container = await encryptText(page, "offline secret", STRONG_PASSWORD);
  expect(container.startsWith("KEYM1:")).toBe(true);

  await context.setOffline(false);
});
