import { test, expect, type Page } from "@playwright/test";
import { visible, useTextMode, selectCrypto, encryptText, decryptText, showFormatDetail, STRONG_PASSWORD } from "./helpers";

/**
 * The "Format detail" switch (roadmap Section 06, part c).
 *
 * Off by default and not stored. Off, the page leaves out KDF parameters,
 * header bytes and offsets. It still names the KDF and cipher, the ways in
 * and the version, keeps the byte map, and keeps every warning. On, it shows
 * what it always showed. Each test reads the same screen both ways, so a
 * switch that hid nothing, or hid too much, fails here.
 */

const SECRET = "expert-view synthetic secret, not a real one";
const pane = (page: Page) => visible(page.getByTestId("container-inspector"));
const detailSwitch = (page: Page) => visible(page.getByTestId("format-detail-switch"));

test("the inspector leaves out bytes and KDF parameters until format detail is on", async ({ page }) => {
  await page.goto("/");
  await useTextMode(page);
  await expect(detailSwitch(page)).toHaveAttribute("aria-checked", "false");

  // Real input opens the itemisation; the default KDF is Argon2id.
  await visible(page.getByPlaceholder("Enter text to encrypt")).fill(SECRET);
  await expect(pane(page)).toContainText("ways in · as configured");
  await expect(pane(page)).toContainText("Argon2id");
  await expect(pane(page)).toContainText("KEYM v3");
  await expect(pane(page)).toContainText("Header layout");
  await expect(page.getByTestId("inspector-hex")).toHaveCount(0);
  await expect(pane(page)).not.toContainText("salts and nonces");
  await expect(pane(page)).not.toContainText("MiB");
  await expect(pane(page)).not.toContainText(/\bt=\d/);

  await showFormatDetail(page);
  // The gaps between bytes are margins, so the text runs together.
  await expect(visible(page.getByTestId("inspector-hex"))).toContainText("4B45594D");
  await expect(pane(page)).toContainText("salts and nonces are drawn fresh at seal time");
  await expect(pane(page)).toContainText(/Argon2id · \d+ MiB · t=\d+ · p=\d+/);

  // Not stored: a reload starts with it off again.
  await page.reload();
  await expect(detailSwitch(page)).toHaveAttribute("aria-checked", "false");
});

test("the pane's first-visit copy promises only what the detail level shows", async ({ page }) => {
  // Usability finding S2: with Format detail off the itemisation has no
  // header bytes, so the copy must not promise them.
  await page.goto("/");
  const promise = visible(page.getByTestId("inspector-plan-promise"));
  await expect(promise).toContainText("its version, its ways in and its layout");
  await expect(promise).not.toContainText("header byte by header byte");
  await expect(visible(page.getByRole("button", { name: "Show what it will write" }))).toBeVisible();

  await showFormatDetail(page);
  await expect(promise).toContainText("header byte by header byte");
  await expect(visible(page.getByRole("button", { name: "Show the header it will write" }))).toBeVisible();
});

test("the receipt, the parsed slot rows and the Recovery tab name the KDF without its parameters", async ({ page }) => {
  await page.goto("/");
  await useTextMode(page);
  await selectCrypto(page, "pbkdf2", "aes");
  await encryptText(page, SECRET, STRONG_PASSWORD);

  const kdf = visible(page.getByTestId("receipt-kdf"));
  const firstSlot = page.getByTestId("inspector-slot-row").first();
  await expect(kdf).toHaveText("PBKDF2");
  await expect(firstSlot).toContainText("PBKDF2");
  await expect(firstSlot).not.toContainText("iterations");
  await expect(page.getByTestId("inspector-hex")).toHaveCount(0);

  await showFormatDetail(page);
  await expect(kdf).toHaveText("PBKDF2 · 1,000,000 iterations");
  await expect(firstSlot).toContainText("PBKDF2 · 1,000,000 iterations");
  await expect(visible(page.getByTestId("inspector-hex"))).toBeVisible();

  // The Recovery tab reads the same switch.
  await visible(page.getByRole("tab", { name: "Recovery", exact: true })).click();
  await expect(page.getByText("AES-256-GCM · PBKDF2 · 1,000,000 iterations")).toBeVisible();
  await visible(page.getByRole("tab", { name: "Encrypt", exact: true })).click();
  await detailSwitch(page).click();
  await expect(detailSwitch(page)).toHaveAttribute("aria-checked", "false");
  await visible(page.getByRole("tab", { name: "Recovery", exact: true })).click();
  await expect(page.getByText("AES-256-GCM · PBKDF2", { exact: true })).toBeVisible();
});

test("the unlock line keeps the version and cipher, and drops only the parameters", async ({ page }) => {
  await page.goto("/");
  await useTextMode(page);
  await selectCrypto(page, "pbkdf2", "aes");
  const container = await encryptText(page, SECRET, STRONG_PASSWORD);
  await decryptText(page, container, STRONG_PASSWORD);

  const line = visible(page.getByText(/^Format: KEYM v3/));
  await expect(line).toHaveText("Format: KEYM v3 · PBKDF2 · AES-256-GCM");
  await showFormatDetail(page);
  await expect(line).toHaveText("Format: KEYM v3 · PBKDF2 (1,000,000 iters) · AES-256-GCM");
});

test("the self-extract notice keeps its trade-off and leaves the per-format reasons to format detail", async ({ page }) => {
  await page.goto("/");
  await useTextMode(page);
  await selectCrypto(page, "argon2id", "aes");
  await encryptText(page, SECRET, STRONG_PASSWORD);

  const notice = visible(page.getByTestId("selfextract-unavailable"));
  await expect(notice).toContainText("A self-extracting page is not available for this backup");
  await expect(notice).toContainText("AES-256-GCM and PBKDF2");
  await expect(notice).toContainText(/weaker/i);
  await expect(page.getByTestId("selfextract-reasons")).toHaveCount(0);

  await showFormatDetail(page);
  await expect(visible(page.getByTestId("selfextract-reasons"))).toContainText(/WebAssembly/i);
});
