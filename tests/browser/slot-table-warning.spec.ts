import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { visible, useTextMode } from "./helpers";

/**
 * KEYM v3 §5.2, in the only place it finally means anything: on screen.
 *
 * The whole revision exists because of §1.1. Anyone who can write a backup file
 * can cut a slot out of its table — no key material required — and before v3 the
 * result was indistinguishable from the original: the owner opened it exactly as
 * before, and the heir enrolled in the deleted slot was locked out permanently
 * and found out years later, at the worst possible moment.
 *
 * v3 does not prevent that edit. It makes it *visible*, and §5.2 is precise
 * about the shape: the reader MUST still return the plaintext, and MUST report
 * that the table is not authentic. Refusing would convert tampering someone
 * could have noticed into a backup that is simply gone, which is the more severe
 * outcome and the one this project declines to cause.
 *
 * Everything under `scripts/` and `reference/` proves the *library* reaches that
 * verdict. Nothing proved it reached a person — and a report that stops at the
 * crypto boundary has not been reported to anyone. That is what this file is
 * for, and it is why the assertions come in pairs: the plaintext, and the
 * warning, in the same run.
 *
 * The containers are the frozen corpus vectors, read rather than built. A
 * warning driven by a container this test constructed would be a check the app
 * agrees with itself; these are bytes written on a known day that must keep
 * producing the same verdict for as long as the format is supported.
 */

const CORPUS = resolve(__dirname, "../../scripts/fixtures/keymaker");
const meta = JSON.parse(readFileSync(resolve(CORPUS, "fixtures.json"), "utf8")) as {
  password: string;
  fixtures: Array<{ name: string; file: string; plaintext: string; slotTableAuthentic?: boolean }>;
};

const fixture = (name: string) => {
  const fx = meta.fixtures.find((f) => f.name === name);
  if (!fx) throw new Error(`corpus has no fixture named ${name}`);
  return fx;
};

/**
 * §7's armor, built here rather than imported.
 *
 * The encoding is a prefix and base64url and nothing else — line breaks are
 * presentation, since every reader strips whitespace before decoding — so this
 * is not a second copy of any logic worth keeping in one place. Importing
 * `armorKeym2` would drag `keym-v2.ts` and its lazy crypto imports into
 * Playwright's transform for the sake of two lines.
 */
const armor = (file: string): string =>
  "keym2:" +
  readFileSync(resolve(CORPUS, file))
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

async function open(page: import("@playwright/test").Page, name: string) {
  const fx = fixture(name);
  await page.goto("/");
  await visible(page.getByRole("tab", { name: "Decrypt" })).click();
  await useTextMode(page);
  await visible(page.getByPlaceholder("Enter text to decrypt")).fill(armor(fx.file));
  await visible(page.getByPlaceholder("Enter decryption password")).fill(meta.password);
  await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();
  return fx;
}

const warning = (page: import("@playwright/test").Page) =>
  page.getByTestId("slot-table-warning");

test.describe("a v3 container whose slot table was stripped", () => {
  test("still gives back the plaintext (§5.2, first half)", async ({ page }) => {
    // Asserted before the warning, and in its own test, because this is the
    // half an implementer gets wrong by being careful. A reader that refuses a
    // container with a bad MAC has destroyed a recoverable backup to report a
    // problem with its metadata.
    const fx = await open(page, "v3-stripped-aes256gcm");

    await expect(
      visible(page.getByPlaceholder(/decrypted|Decrypted/)).or(page.locator("#output-text")).first(),
      "a stripped container refused to open — §5.2 requires the plaintext back"
    ).toHaveValue(fx.plaintext, { timeout: 90_000 });
  });

  test("and says the list of unlock methods has changed (§5.2, second half)", async ({ page }) => {
    await open(page, "v3-stripped-aes256gcm");

    await expect(
      visible(warning(page)),
      "a stripped container opened in silence, which is exactly the v2 behaviour v3 exists to end"
    ).toBeVisible({ timeout: 90_000 });

    // The report must not claim to name the slot. §5.2 is explicit that it
    // cannot: the MAC covers the table as a whole, and the sealed table is not
    // recoverable from the tampered one. "Something changed" is the whole of
    // what is known, and a warning that guessed further would be inventing it.
    await expect(visible(warning(page))).toContainText(/list of unlock methods has changed/i);
    await expect(visible(warning(page))).toContainText(/not possible to say which one/i);

    // And it must not read as data loss, because there is none. The payload
    // authenticated on its own before any of this was shown.
    await expect(visible(warning(page))).toContainText(/Your data is intact/i);
  });

  test("the format line still names v3", async ({ page }) => {
    // The dispatcher fix, from the user's side. While `detectFormat` did not
    // name version 3, this container did not reach the v3 reader at all — it was
    // refused as "a newer KEYM version", by an app that had already implemented
    // the format it was turning away.
    await open(page, "v3-stripped-aes256gcm");
    await expect(visible(page.getByText(/Format: KEYM v3/))).toBeVisible({ timeout: 90_000 });
  });
});

test.describe("the warning is not furniture", () => {
  // Two controls. A warning that appears on everything carries no information,
  // and these are the two ways it could: firing on an intact v3 table, or
  // firing on a v2 container that has no table MAC to check and about which the
  // format claims nothing at all.
  test("an intact v3 container opens without it", async ({ page }) => {
    const fx = await open(page, "v3-pbkdf2-aes256gcm");

    await expect(
      visible(page.getByPlaceholder(/decrypted|Decrypted/)).or(page.locator("#output-text")).first()
    ).toHaveValue(fx.plaintext, { timeout: 90_000 });
    await expect(visible(page.getByText(/Format: KEYM v3/))).toBeVisible();
    await expect(
      warning(page),
      "an untouched v3 container was reported as tampered with"
    ).toHaveCount(0);
  });

  test("a v2 container opens without it", async ({ page }) => {
    const fx = await open(page, "v2-pbkdf2-aes256gcm");

    await expect(
      visible(page.getByPlaceholder(/decrypted|Decrypted/)).or(page.locator("#output-text")).first()
    ).toHaveValue(fx.plaintext, { timeout: 90_000 });
    await expect(visible(page.getByText(/Format: KEYM v2/))).toBeVisible();
    await expect(
      warning(page),
      "a v2 container was accused of tampering, but v2 has no slot table MAC and claims nothing"
    ).toHaveCount(0);
  });
});
