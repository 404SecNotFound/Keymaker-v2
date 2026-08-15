import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { visible, useTextMode, selectCrypto, STRONG_PASSWORD } from "./helpers";

/**
 * Roadmap 4.5 — the inheritance wizard.
 *
 * 4.5 adds no format, so there is nothing here for byte equality to check.
 * What there is to check is that the *package* holds together: that every
 * artefact it promises comes out, that the two containers really are two, and
 * that the honest framing the roadmap requires is on the screen rather than
 * only in a design document.
 *
 * `reference/crosstest2.py` owns the complementary half — that `keym2.py` opens
 * the same package by password, by k shares, and through the page.
 */

const SECRET = "abandon ability able about above absent absorb abstract absurd abuse access accident";

async function openWizard(page: Page, kdf: "pbkdf2" | "argon2id" = "argon2id") {
  await page.goto("/");
  await useTextMode(page);
  await selectCrypto(page, kdf, "chained");
  await visible(page.getByPlaceholder("Enter text to encrypt")).fill(SECRET);
  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
  await visible(page.getByTestId("open-inheritance-wizard")).click();
  await expect(page.getByTestId("inheritance-wizard")).toBeVisible();
}

test.describe("4.5 inheritance package", () => {
  test("builds every artefact, and the two containers are genuinely two", async ({
    page,
  }, testInfo) => {
    await openWizard(page);

    // "Honest framing to preserve": any k shares open the container without the
    // password, which makes each share as sensitive as the password. It has to
    // be on the screen where the set is chosen, not only in the roadmap.
    const wizard = page.getByTestId("inheritance-wizard");
    await expect(wizard).toContainText(/without the password/i);
    await expect(wizard).toContainText(/as sensitive as the password/i);
    // And §7.2's trade, stated where the page is chosen rather than discovered.
    await expect(wizard).toContainText(/PBKDF2 rather than Argon2id/i);
    await expect(wizard).toContainText(/your main backup is not changed/i);

    await page.getByTestId("inheritance-build").click();
    await expect(page.getByTestId("inheritance-results")).toBeVisible({ timeout: 120_000 });

    // The share set exists exactly once (§4.6) and the results step must say so
    // rather than reading like a summary that can be reopened.
    await expect(wizard).toContainText(/exist exactly once/i);

    const saved: Record<string, string> = {};
    for (const [testid, name] of [
      ["inh-save-backup", "backup.keym"],
      ["inh-save-shares", "shares.txt"],
      ["inh-save-letter", "LETTER.txt"],
      ["inh-save-page", "backup.html"],
    ] as const) {
      const [dl] = await Promise.all([
        page.waitForEvent("download"),
        page.getByTestId(testid).click(),
      ]);
      const path = testInfo.outputPath(name);
      await dl.saveAs(path);
      saved[name] = path;
      expect(dl.suggestedFilename()).toBe(name);
    }

    const shares = (await readFile(saved["shares.txt"]!, "utf8"))
      .split("\n")
      .filter((l) => l.startsWith("KMSHARE1:"));
    expect(shares).toHaveLength(3);

    const letter = await readFile(saved["LETTER.txt"]!, "utf8");
    expect(letter).toMatch(/as carefully as the password/i);
    expect(letter).toMatch(/any 2 of the 3/i);

    // The page's container must NOT be the primary one. If these were ever the
    // same bytes, the strong backup would have been silently downgraded to
    // PBKDF2 — the whole reason §7.2 gives a page its own container.
    const html = await readFile(saved["backup.html"]!, "utf8");
    const armor = html
      .slice(html.indexOf("<!--KEYM2-BEGIN-->") + 18, html.indexOf("<!--KEYM2-END-->"))
      .replace(/\s+/g, "");
    const pageBytes = Buffer.from(armor.slice(6).replace(/-/g, "+").replace(/_/g, "/"), "base64");
    const primary = await readFile(saved["backup.keym"]!);
    expect(Buffer.compare(pageBytes, primary)).not.toBe(0);
    // cipher_id at offset 5: the primary is chained (0x02), the page must be AES (0x00).
    expect(primary[5]).toBe(0x02);
    expect(pageBytes[5]).toBe(0x00);
  });

  test("declining the page leaves nothing weaker than what was chosen", async ({ page }) => {
    await openWizard(page);
    await page.getByTestId("inheritance-wizard").getByLabel(/self-extracting page/i).click();

    await page.getByTestId("inheritance-build").click();
    await expect(page.getByTestId("inheritance-results")).toBeVisible({ timeout: 120_000 });

    await expect(page.getByTestId("inh-save-page")).toHaveCount(0);
    await expect(page.getByTestId("inh-save-backup")).toBeVisible();
  });

  test("the threshold can never exceed the number of slips", async ({ page }) => {
    await openWizard(page);
    const threshold = page.getByTestId("inheritance-wizard").getByLabel("Slips needed to open it");
    const count = page.getByTestId("inheritance-wizard").getByLabel("Slips to print");

    // The order matters, and a first version of this test got it wrong: filling
    // the threshold first clamps it against the count that is *already* there,
    // so the assertion passed with the count's own clamp deleted. Raise the
    // count, raise the threshold into the new room, then shrink the count —
    // that is the only sequence in which an impossible pair can be constructed.
    await count.fill("8");
    await threshold.fill("6");
    await expect(threshold).toHaveValue("6");

    await count.fill("3");
    await expect(threshold).toHaveValue("3");

    // And the threshold cannot be pushed past the count directly either.
    await threshold.fill("9");
    await expect(threshold).toHaveValue("3");
  });
});
