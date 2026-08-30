import { test, expect, type Page } from "@playwright/test";
import { visible, useTextMode, encryptText, decryptText, STRONG_PASSWORD } from "./helpers";
import { armorKeym2, dearmorKeym2, keym2SlotCountOffset, KEYM2_VERSION_V3 } from "../../src/lib/keym-v2";

/**
 * The container inspector — the workbench pane that reads a container's
 * header out loud.
 *
 * The pane's one promise is that it never invents: what it shows is either
 * the form restated ("What will be written") or the container parsed ("What
 * was written" / "What you loaded"). So every test here checks the pane
 * *against the bytes*, not against another copy of the UI's own claim: the
 * armored output is dearmored in the test and the slot-count byte read
 * directly, and the pane must agree with that byte — the same relationship
 * the Python reference would report.
 *
 * The last test is the negative control on all of the others: a container
 * with a version byte no parser accepts must produce no rows at all. If the
 * pane were keying off "something that looks like armor was pasted" rather
 * than off the parse, that is the test that catches it.
 */

const SECRET = "abandon ability able about above absent absorb abstract";

const inspector = (page: Page) => page.getByTestId("container-inspector");
const slotRows = (page: Page) => page.getByTestId("inspector-slot-row");

/** The slot-count byte of an armored container, read the way §5 defines it. */
function slotCountByte(armored: string): number {
  const bytes = dearmorKeym2(armored);
  expect(bytes[4], "these tests are written against v3 output").toBe(KEYM2_VERSION_V3);
  return bytes[keym2SlotCountOffset(KEYM2_VERSION_V3)] as number;
}

/** Enrol a k-of-n share set. A lean copy of shamir-ui.spec.ts's helper. */
async function enableShares(page: Page, k: number, n: number) {
  const advanced = visible(page.getByRole("button", { name: /^Advanced/ }));
  if ((await advanced.getAttribute("aria-expanded")) !== "true") await advanced.click();
  await expect(advanced).toHaveAttribute("aria-expanded", "true");

  const sharesSwitch = visible(page.getByRole("switch", { name: "Recovery shares" }));
  await expect(async () => {
    if ((await sharesSwitch.getAttribute("aria-checked")) !== "true") {
      await sharesSwitch.click();
    }
    await expect(sharesSwitch).toHaveAttribute("aria-checked", "true", { timeout: 1_000 });
  }).toPass({ timeout: 20_000 });

  await visible(page.getByLabel("Shares to print")).fill(String(n));
  await visible(page.getByLabel("Needed to open")).fill(String(k));
}

test.beforeEach(async ({ page }) => {
  await page.goto("/");
});

test("encrypt: the pane restates the plan before anything exists", async ({ page }) => {
  const pane = inspector(page);
  await expect(pane).toContainText("What will be written");
  await expect(pane).toContainText("KEYM v3");
  // The declared slot, not a parsed one: Argon2id is the default the form
  // starts on, and the pane must say so without a container existing.
  await expect(pane).toContainText("Passphrase");
  await expect(pane).toContainText("Argon2id");
  await expect(pane).toContainText("salts and nonces are drawn fresh at seal time");
  // Nothing parsed yet, so no parsed slot rows.
  await expect(slotRows(page)).toHaveCount(0);
});

test("encrypt: after sealing, the pane shows what the bytes say", async ({ page }) => {
  await useTextMode(page);
  const armored = await encryptText(page, SECRET, STRONG_PASSWORD);

  const trueCount = slotCountByte(armored);
  expect(trueCount, "a plain passphrase encrypt writes exactly one slot").toBe(1);

  const pane = inspector(page);
  await expect(pane).toContainText("What was written");
  await expect(pane).toContainText(`${trueCount} slot`);
  // Control on the count assertion: the pane must not also carry the claim
  // this container does not make.
  await expect(pane).not.toContainText("2 slots");
  await expect(slotRows(page)).toHaveCount(trueCount);
  await expect(slotRows(page).first()).toContainText("Passphrase");
  await expect(slotRows(page).first()).toContainText("Argon2id");
});

test("encrypt with shares: the second slot the worker enrolled is itemised", async ({ page }) => {
  await useTextMode(page);
  await enableShares(page, 2, 3);
  const armored = await encryptText(page, SECRET, STRONG_PASSWORD);

  // The one-time shares dialog sits over the page; the pane is behind it.
  await expect(page.getByText(/Save these 3 shares now/)).toBeVisible({ timeout: 30_000 });
  await page.keyboard.press("Escape");
  await expect(page.getByText(/Save these/)).toHaveCount(0);

  // The byte is the authority: slot 0 is the passphrase, slot 1 the share
  // set, both written by the worker in the same call.
  const trueCount = slotCountByte(armored);
  expect(trueCount).toBe(2);

  const pane = inspector(page);
  await expect(pane).toContainText(`${trueCount} slots`);
  await expect(pane).not.toContainText("1 slot ·");
  await expect(slotRows(page)).toHaveCount(trueCount);
  await expect(slotRows(page).nth(1)).toContainText("Share set");
});

test("decrypt: a loaded container is itemised before any unlock is attempted", async ({ page }) => {
  await useTextMode(page);
  const armored = await encryptText(page, SECRET, STRONG_PASSWORD);

  await visible(page.getByRole("tab", { name: "Decrypt" })).click();
  await useTextMode(page);
  await visible(page.getByPlaceholder("Enter text to decrypt")).fill(armored);

  // No password typed, no button pressed: the header is public and the pane
  // reads it as pasted.
  const pane = inspector(page);
  await expect(pane).toContainText("What you loaded");
  await expect(pane).toContainText("KEYM v3");
  await expect(slotRows(page)).toHaveCount(1);
  await expect(slotRows(page).first()).toContainText("Argon2id");
  await expect(visible(page.getByPlaceholder("Enter decryption password"))).toHaveValue("");

  // And the unlock it previews still works — the pane is a reading, not a
  // fork of the format code.
  const recovered = await decryptText(page, armored, STRONG_PASSWORD);
  expect(recovered).toBe(SECRET);
});

test("negative control: a version no parser accepts produces no rows", async ({ page }) => {
  await useTextMode(page);
  const armored = await encryptText(page, SECRET, STRONG_PASSWORD);

  // Flip the version byte to one no generation of the format has ever used.
  // If the pane keyed off "armor was pasted" instead of off the parse, this
  // paste would still grow rows — and this test is what would say so.
  const bytes = dearmorKeym2(armored);
  bytes[4] = 0x7f;
  const corrupted = armorKeym2(bytes);

  await visible(page.getByRole("tab", { name: "Decrypt" })).click();
  await useTextMode(page);
  await visible(page.getByPlaceholder("Enter text to decrypt")).fill(corrupted);

  const pane = inspector(page);
  // The pane stays in its guidance state: present, honest, row-free.
  await expect(pane).toBeVisible();
  await expect(slotRows(page)).toHaveCount(0);
  await expect(pane).not.toContainText("What you loaded — KEYM");
  await expect(pane).not.toContainText("slots · ways in");
});
