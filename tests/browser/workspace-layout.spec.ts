import { test, expect } from "@playwright/test";
import { useTextMode, encryptText, STRONG_PASSWORD, visible } from "./helpers";
import { dearmorKeym2, keym2SlotTableOffset, keym2SlotCountOffset, keym2SlotLen, parseKeym2CoreHeader } from "../../src/lib/keym-v2";

test.beforeEach(async ({ page }) => { await page.goto("/"); });

test("Spline Sans renders the interface and both font families are cached offline", async ({ page }) => {
  await page.evaluate(() => document.fonts.ready);
  for (const selector of ["body", ".km-page-heading h1", "#encrypt-content-title", "#password"]) {
    const family = await page.locator(selector).evaluate(el => getComputedStyle(el).fontFamily);
    expect(family, `${selector} must use the selected interface face`).toMatch(/^"?Spline Sans Variable"?,/);
  }
  await expect(page.locator(".km-section-number").first()).toHaveCSS("font-family", /JetBrains Mono Variable/);
  const loaded = await page.evaluate(() => Array.from(document.fonts)
    .filter(face => face.status === "loaded").map(face => face.family.replaceAll('"', '')));
  expect(loaded).toContain("Spline Sans Variable");
  expect(loaded).toContain("JetBrains Mono Variable");
  await page.waitForFunction(() => !!navigator.serviceWorker?.controller);
  const cachedFonts = await page.evaluate(async () => {
    const fonts: string[] = [];
    for (const name of await caches.keys()) {
      if (!name.startsWith("keymaker-")) continue;
      for (const request of await (await caches.open(name)).keys()) {
        if (request.url.endsWith(".woff2")) fonts.push(new URL(request.url).pathname);
      }
    }
    return fonts;
  });
  for (const family of ["spline-sans", "jetbrains-mono"]) {
    for (const subset of ["latin", "latin-ext"]) {
      expect(cachedFonts.some(path => path.includes(`${family}-${subset}-wght-normal`)),
        `${family} ${subset} must be precached`).toBe(true);
    }
  }
});

test("workspace hierarchy replaces the marketing hero", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await expect(page.getByRole("heading", { name: "Encrypt", exact: true })).toBeVisible();
  await expect(page.locator('img[src*="hero-"]')).toHaveCount(0);
  await expect(page.getByRole("tab", { name: "Encrypt", exact: true })).toHaveAttribute("aria-selected", "true");
  const content = await page.locator("#encrypt-content-title").boundingBox();
  const inspector = await page.getByTestId("container-inspector").boundingBox();
  expect(content!.y).toBeLessThan(340);
  expect(inspector!.x).toBeGreaterThan(content!.x + 300);
  const button = page.getByRole("button", { name: "Encrypt File", exact: true });
  await expect(button).toHaveCSS("border-radius", "8px");
  await expect(button).toHaveCSS("scale", "none");
});

for (const width of [320, 393, 768, 1440]) {
  test(`workspace views fit a ${width}px viewport`, async ({ page }) => {
    await page.setViewportSize({ width, height: 1000 });
    for (const view of ["Workspace", "Encrypt", "Decrypt", "Recovery", "Audio", "Tools", "Docs"]) {
      await page.getByRole("tab", { name: view, exact: true }).click();
      await expect(page.getByRole("tab", { name: view, exact: true })).toHaveAttribute("aria-selected", "true");
      await expect(page.getByRole("tabpanel", { name: view, exact: true })).toBeVisible();
      await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - innerWidth);
      expect(overflow, `${view} overflows at ${width}`).toBeLessThanOrEqual(1);
      expect(await page.locator('#password:visible').count()).toBeLessThanOrEqual(1);
    }
  });
}

test("visiting recovery preserves the controlled form without duplicate secret fields", async ({ page }) => {
  await useTextMode(page);
  await page.getByPlaceholder("Enter text to encrypt").fill("A private test note");
  await page.getByPlaceholder("Enter a strong password").fill(STRONG_PASSWORD);
  await page.getByRole("tab", { name: "Recovery", exact: true }).click();
  await expect(page.getByText("No newly created backup in this session.", { exact: false })).toBeVisible();
  await expect(page.locator("#password")).toHaveCount(0);
  await page.getByRole("tab", { name: "Encrypt", exact: true }).click();
  await expect(page.getByPlaceholder("Enter text to encrypt")).toHaveValue("A private test note");
  await expect(page.getByPlaceholder("Enter a strong password")).toHaveValue(STRONG_PASSWORD);
  await expect(page.locator("#password")).toHaveCount(1);
});

test("typography accents separate structure, body copy and actual password feedback", async ({ page }) => {
  await expect(page.locator(".km-section-number").first()).toHaveCSS("color", "rgb(158, 197, 255)");
  await expect(page.locator("#encrypt-content-title")).toHaveCSS("color", "rgb(158, 197, 255)");
  await expect(page.locator("#encrypt-protection-title")).toHaveCSS("color", "rgb(158, 197, 255)");
  await expect(page.locator(".km-inspector-title h2")).toHaveCSS("color", "rgb(158, 197, 255)");
  await expect(page.locator("#encrypt-content-title")).toHaveCSS("font-size", "15px");
  await expect(page.locator(".km-page-heading h1")).toHaveCSS("color", "rgb(247, 249, 252)");
  await expect(page.locator(".km-page-heading > p").last()).toHaveCSS("color", "rgb(177, 183, 193)");
  const password = page.locator("#password");
  await expect(password).not.toHaveCSS("border-top-color", "rgb(105, 219, 170)");
  await expect(page.locator("#password-feedback")).toHaveCount(0);
  await password.fill("short");
  await expect(page.locator("#password-feedback")).toContainText("Below the minimum policy");
  await expect(page.locator("#password-feedback")).not.toHaveCSS("color", "rgb(105, 219, 170)");
  await password.fill(STRONG_PASSWORD);
  await password.blur();
  await expect(password).toHaveCSS("border-top-color", "rgb(105, 219, 170)");
  await expect(page.locator("#password-feedback > span")).toHaveCSS("color", "rgb(105, 219, 170)");
  await expect(page.locator("#password-feedback")).toContainText("not a strength rating");
  await expect(password).toHaveAttribute("aria-describedby", "password-feedback");
  await page.getByRole("button", { name: "Random", exact: true }).click();
  await expect(page.locator("#password-feedback")).toHaveCSS("color", "rgb(105, 219, 170)");
  await expect(page.locator("#password-feedback")).toContainText("Generated");
});

test("cyan selection follows navigation and the selected content type", async ({ page }) => {
  const cyan = "rgb(110, 231, 242)";
  expect(await page.getByRole("tab", { name: "Encrypt", exact: true })
    .evaluate(el => getComputedStyle(el).color)).toBe(cyan);
  for (const view of ["Encrypt", "Decrypt"]) {
    await page.getByRole("tab", { name: view, exact: true }).click();
    const file = page.getByRole("button", { name: "File", exact: true });
    const text = page.getByRole("button", { name: "Text", exact: true });
    await file.click();
    await expect(file).toHaveAttribute("aria-pressed", "true");
    await expect(file).toHaveCSS("color", cyan);
    await expect(file).toHaveCSS("background-color", "rgb(16, 42, 50)");
    await expect(file).toHaveCSS("border-top-color", "rgb(66, 135, 149)");
    await expect(text).toHaveAttribute("aria-pressed", "false");
    await expect(text).toHaveCSS("color", "rgb(177, 183, 193)");
    await text.click();
    await expect(text).toHaveAttribute("aria-pressed", "true");
    await expect(text).toHaveCSS("color", cyan);
    await expect(file).toHaveCSS("color", "rgb(177, 183, 193)");
    await file.click();
  }
  await page.getByRole("tab", { name: "Recovery", exact: true }).click();
  await expect(page.getByRole("tab", { name: "Recovery", exact: true })).toHaveCSS("color", cyan);
  await expect(page.getByRole("button", { name: "Verify with password", exact: true })).toHaveCSS("color", "rgb(132, 185, 255)");
});

test("blue actions remain distinct from disabled controls, input and mint validation", async ({ page }) => {
  const random = page.getByRole("button", { name: "Random", exact: true });
  expect(await random.evaluate(el => getComputedStyle(el).color)).toBe("rgb(132, 185, 255)");
  const submit = page.getByRole("button", { name: "Encrypt File", exact: true });
  await expect(submit).toBeDisabled();
  await expect(submit).toHaveCSS("background-color", "rgba(0, 0, 0, 0)");
  await expect(submit).toHaveCSS("color", "rgb(148, 156, 169)");
  await expect(page.getByRole("button", { name: "Copy", exact: true })).toHaveCSS("color", "rgb(148, 156, 169)");
  await page.locator("#encrypt-file").setInputFiles({ name: "example.txt", mimeType: "text/plain", buffer: Buffer.from("test file") });
  await expect(page.locator(".km-file-icon")).toHaveCSS("color", "rgb(110, 231, 242)");
  await expect(page.locator(".km-file-name > span")).toHaveCSS("color", "rgb(240, 242, 245)");
  await random.click();
  await expect(submit).toBeEnabled();
  await expect(submit).toHaveCSS("background-color", "rgb(132, 185, 255)");
  await expect(submit).toHaveCSS("color", "rgb(17, 19, 22)");
  await expect(page.locator("#password")).toHaveCSS("color", "rgb(240, 242, 245)");
  await expect(page.locator("#password-feedback")).toHaveCSS("color", "rgb(105, 219, 170)");
  await page.locator("#password").focus();
  await expect(page.locator("#password")).toHaveCSS("outline-color", "rgb(132, 185, 255)");
});

test("advanced selection separates option titles from their supporting descriptions", async ({ page }) => {
  await page.getByRole("button", { name: /^Advanced/ }).click();
  const pbkdf = page.getByRole("button", { name: /^PBKDF2/ });
  await pbkdf.click();
  await expect(pbkdf).toHaveAttribute("aria-pressed", "true");
  await expect(pbkdf).toHaveCSS("color", "rgb(110, 231, 242)");
  await expect(pbkdf.locator("p").last()).toHaveCSS("color", "rgb(177, 183, 193)");
  await expect(page.locator("#use-keyfile")).toHaveAttribute("aria-checked", "false");
  await page.locator("#use-keyfile").click();
  await expect(page.locator("#use-keyfile")).toHaveCSS("background-color", "rgb(110, 231, 242)");
});

test("Advanced option copy stays inside its cards at narrow desktop and phone widths", async ({ page }) => {
  for (const width of [1180, 320, 768, 1440]) {
    await page.setViewportSize({ width, height: 1100 });
    await page.goto("/");
    await page.getByRole("button", { name: /^Advanced/ }).click();
    await page.evaluate(() => document.fonts.ready);
    const overflow = await page.locator(".km-choice").evaluateAll((cards) => cards.flatMap((card) => {
      const bounds = card.getBoundingClientRect();
      const style = getComputedStyle(card);
      const right = bounds.right - parseFloat(style.paddingRight) - 1;
      return Array.from(card.querySelectorAll("p")).flatMap((p) => {
        const range = document.createRange();
        range.selectNodeContents(p);
        return Array.from(range.getClientRects()).some((r) => r.right > right + 1)
          ? [p.textContent] : [];
      });
    }));
    expect(overflow, `option copy overflows at ${width}px`).toEqual([]);
  }
});

test("selected file is compact, replace cancellation preserves it, remove clears it", async ({ page }) => {
  await page.locator("#encrypt-file").setInputFiles({ name: "example.txt", mimeType: "text/plain", buffer: Buffer.from("test file") });
  await expect(page.getByTestId("selected-file")).toContainText("example.txt");
  await expect(page.getByTestId("selected-file")).toContainText("9 bytes");
  expect((await page.getByTestId("selected-file").boundingBox())!.height).toBeLessThan(100);
  await page.locator("#encrypt-file").dispatchEvent("change");
  await expect(page.getByTestId("selected-file")).toContainText("example.txt");
  await page.getByRole("button", { name: "Remove file", exact: true }).click();
  await expect(page.getByTestId("selected-file")).toHaveCount(0);
  await expect(page.getByRole("button", { name: /Drop a file here/ })).toBeVisible();
});

test("recovery hands the current container to verify-only without showing plaintext", async ({ page }) => {
  await useTextMode(page);
  const armor = await encryptText(page, "Recovery handoff test note", STRONG_PASSWORD);
  const bytes = dearmorKeym2(armor);
  const header = parseKeym2CoreHeader(bytes);
  const actualHeaderBytes = keym2SlotTableOffset(header.version) + keym2SlotLen(header.cipher) * bytes[keym2SlotCountOffset(header.version)]!;
  const picturedBytes = await page.locator('[data-testid="inspector-header-schematic"] [data-bytes]').evaluateAll(
    cells => cells.reduce((sum, cell) => sum + Number(cell.getAttribute("data-bytes")), 0)
  );
  expect(picturedBytes).toBe(actualHeaderBytes);
  await page.getByRole("tab", { name: "Recovery", exact: true }).click();
  await expect(page.getByText("Container created", { exact: false })).toBeVisible();
  await page.getByRole("button", { name: "Verify with password", exact: true }).click();
  await expect(page.getByPlaceholder("Enter text to decrypt")).toHaveValue(armor);
  await visible(page.getByPlaceholder("Enter decryption password")).fill(STRONG_PASSWORD);
  await page.getByRole("button", { name: "Verify Text", exact: true }).click();
  await expect(page.getByTestId("verify-result")).toBeVisible();
  await expect(page.getByLabel("Result", { exact: true })).toHaveCount(0);
});
