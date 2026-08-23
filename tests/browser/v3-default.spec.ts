import { test, expect } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { visible, useTextMode, encryptText, STRONG_PASSWORD } from "./helpers";

/**
 * The app writes KEYM v3, and the artefact that cannot be updated afterwards
 * can open one.
 *
 * v3 §6 says writers SHOULD emit v3, and moving that default is only safe once
 * every shipped reader understands the format. Two of the three are updatable —
 * this app and `keym2.py`. The third is not: §7.2's self-extracting page carries
 * its decryptor *inside* the backup, so a page written today runs the reader it
 * was born with for as long as the file exists. If that reader had stayed
 * v2-only, every page exported after the default moved would have been a backup
 * with no way in. That is the failure this file exists to prevent, and it is
 * why the page is tested against a container it did not write.
 */

const CORPUS = resolve(__dirname, "../../scripts/fixtures/keymaker");
const meta = JSON.parse(readFileSync(resolve(CORPUS, "fixtures.json"), "utf8")) as {
  password: string;
  fixtures: Array<{ name: string; file: string; plaintext: string }>;
};
const fixture = (name: string) => {
  const fx = meta.fixtures.find((f) => f.name === name);
  if (!fx) throw new Error(`corpus has no fixture named ${name}`);
  return fx;
};

/**
 * Build a self-extracting page from a frozen container, through the shipping
 * builder rather than a hand-assembled approximation.
 *
 * The corpus vectors are the point: a page built from a container this test
 * also wrote would only prove the code agrees with itself. These bytes were
 * written on a known day, and one of them has had a slot cut out of it.
 */
function pageFrom(fixtureName: string, outPath: string): string {
  const fx = fixture(fixtureName);
  execFileSync(
    "node",
    [
      resolve(__dirname, "../../reference/bridge.mjs"), "selfextract",
      "--in", resolve(CORPUS, fx.file),
      "--out", outPath,
      "--created-on", "2026-01-01",
      "--app-version", "0.0.0",
    ],
    { cwd: resolve(__dirname, "../.."), encoding: "utf8" }
  );
  return outPath;
}

/** The container version byte, read out of armored text. */
function versionOf(armor: string): number {
  const b64 = armor.slice("keym2:".length).replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(b64 + "=".repeat((4 - (b64.length % 4)) % 4), "base64")[4]!;
}

test.describe("the app writes v3", () => {
  test("a container encrypted here carries version 3 on the wire", async ({ page }) => {
    await page.goto("/");
    await useTextMode(page);
    const armor = await encryptText(page, "written today", STRONG_PASSWORD);
    // Read from the bytes, not from the format line: a label is what the app
    // believes it wrote, and this has to be what it actually wrote.
    expect(versionOf(armor), "the app is still writing v2").toBe(3);
  });

  test("and opens it again, reporting v3 and an authentic table", async ({ page }) => {
    await page.goto("/");
    await useTextMode(page);
    const armor = await encryptText(page, "written today", STRONG_PASSWORD);

    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);
    await visible(page.getByPlaceholder("Enter text to decrypt")).fill(armor);
    await visible(page.getByPlaceholder("Enter decryption password")).fill(STRONG_PASSWORD);
    await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();

    await expect(visible(page.getByText(/Format: KEYM v3/))).toBeVisible({ timeout: 90_000 });
    await expect(
      page.getByTestId("slot-table-warning"),
      "a container the app had just written was reported as tampered with"
    ).toHaveCount(0);
  });
});

test.describe("§7.2 — the page that cannot be updated later", () => {
  test("opens a v3 container it did not write", async ({ context }, testInfo) => {
    const fx = fixture("v3-pbkdf2-aes256gcm");
    const saved = pageFrom(fx.name, testInfo.outputPath("v3-intact.html"));

    const offline = await context.newPage();
    const pageErrors: string[] = [];
    offline.on("pageerror", (e) => pageErrors.push(e.message));
    await offline.goto(`file://${saved}`);
    await offline.fill("#pw", meta.password);
    await offline.click("#go");
    await offline.waitForSelector("#result:not([hidden])", { timeout: 90_000 });

    expect(await offline.inputValue("#out")).toBe(fx.plaintext);
    expect(pageErrors).toEqual([]);
    // The control for the warning below: an intact table must stay silent, or
    // the notice is furniture and carries no information when it does appear.
    expect(await offline.isHidden("#table")).toBe(true);
    await offline.close();
  });

  test("still opens a stripped container, and says the table changed", async ({
    context,
  }, testInfo) => {
    const fx = fixture("v3-stripped-aes256gcm");
    const saved = pageFrom(fx.name, testInfo.outputPath("v3-stripped.html"));

    const offline = await context.newPage();
    const pageErrors: string[] = [];
    offline.on("pageerror", (e) => pageErrors.push(e.message));
    await offline.goto(`file://${saved}`);
    await offline.fill("#pw", meta.password);
    await offline.click("#go");
    await offline.waitForSelector("#result:not([hidden])", { timeout: 90_000 });

    // §5.2, both halves, in the reader that has the least chance of ever being
    // fixed. The plaintext first: refusing here would mean a page that destroys
    // a recoverable backup to complain about its metadata, and the page is the
    // copy someone reaches for when the other copies are gone.
    expect(
      await offline.inputValue("#out"),
      "the page refused a stripped container instead of opening it"
    ).toBe(fx.plaintext);
    expect(pageErrors).toEqual([]);

    await expect(
      offline.locator("#table"),
      "the page opened a tampered container in silence"
    ).toBeVisible();
    // String matchers, not regexes: the notice is wrapped across several source
    // lines, so its textContent carries the newlines and indentation verbatim
    // and a regex written as one phrase never matches. Playwright normalises
    // whitespace for a string and does not for a pattern.
    await expect(offline.locator("#table")).toContainText(
      "list of unlock methods has changed"
    );
    await expect(offline.locator("#table")).toContainText("not possible to say which one");
    await expect(offline.locator("#table")).toContainText("Your data is intact");
    await offline.close();
  });

  test("a v2 page still opens, and claims nothing about its table", async ({
    context,
  }, testInfo) => {
    // §6, from the other direction. v2 carries no slot_table_mac, so the page
    // must open it and stay quiet — a notice here would accuse every backup
    // written before this revision of having been tampered with.
    const fx = fixture("v2-pbkdf2-aes256gcm");
    const saved = pageFrom(fx.name, testInfo.outputPath("v2-intact.html"));

    const offline = await context.newPage();
    await offline.goto(`file://${saved}`);
    await offline.fill("#pw", meta.password);
    await offline.click("#go");
    await offline.waitForSelector("#result:not([hidden])", { timeout: 90_000 });

    expect(await offline.inputValue("#out")).toBe(fx.plaintext);
    expect(await offline.isHidden("#table")).toBe(true);
    await offline.close();
  });
});
