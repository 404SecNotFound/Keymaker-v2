import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { encodePaperParts } from "../../src/lib/keym-v2-paper";
import { visible, useTextMode, selectCrypto, STRONG_PASSWORD } from "./helpers";

/**
 * Roadmap 4.2 — the paper vault print kit.
 *
 * What has to be true is awkward to assert: *what comes out of a printer*. So
 * these snapshot the document from inside `window.print()` — the exact instant
 * the browser hands the page to the print pipeline — and assert on that. Each
 * property is here because breaking it silently produces a page that looks fine
 * on screen and is useless on paper.
 *
 * Snapshotting rather than inspecting afterwards is not incidental: the handler
 * clears the sheet the moment printing returns, so the DOM a test could examine
 * later is deliberately empty. A first attempt at this stubbed `print` as a
 * no-op and then looked for the sheet, and every assertion failed on an element
 * that had already been unmounted exactly as designed.
 */

const SECRET = "Emergency kit — recovery codes 4471-0092, 8823-5510, 6104-7735.";

interface PrintSnapshot {
  sheets: number;
  symbols: number;
  firstCaption: string;
  rules: number;
  text: string;
}

async function encryptSomething(page: Page) {
  await page.goto("/");
  await useTextMode(page);

  // PBKDF2, not the Argon2id default, and the reason is cost rather than
  // coverage. Nothing below asserts anything about key derivation — these tests
  // are about what reaches the printer: page count, symbols, captions, rules,
  // and that the sheet is unmounted afterwards. A container is a container, and
  // §7.1 splitting does not care how its master key was wrapped.
  //
  // Left on the default, this file ran five memory-hard derivations per engine,
  // fifteen across the matrix, and it was the only encrypting spec that had not
  // opted out — share-lifecycle and shamir-ui both already select pbkdf2 here.
  // On webkit, with two workers, sharing a runner with crypto.spec's own
  // Argon2id cases, that was enough to blow the 90s wait on a test that takes
  // about six seconds: one timeout on an unrelated documentation-only PR, while
  // its four siblings passed in the same run.
  //
  // Argon2id on webkit stays covered by crypto.spec.ts, which is the file whose
  // job that is, and which exercises it on every engine.
  await selectCrypto(page, "pbkdf2", "aes");

  await visible(page.getByPlaceholder("Enter text to encrypt")).fill(SECRET);
  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
  await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();
  await page.waitForFunction(
    () => {
      const el = document.querySelector("#output-text") as HTMLTextAreaElement | null;
      return !!el && el.value.startsWith("keym2:");
    },
    null,
    { timeout: 90_000 }
  );
}

/**
 * Click Print and return what the document looked like at the moment it printed.
 *
 * Two things this has to work around, both learned the hard way:
 *
 *  - **The click must happen under screen media.** The print rule hides every
 *    element on the page, so under `emulateMedia({media:"print"})` Playwright's
 *    actionability check never sees a visible button and the click times out.
 *  - **The stub throws.** The handler clears the sheet on the line *after*
 *    `window.print()` returns, so a no-op stub unmounts it before anything can
 *    be inspected. Throwing leaves the sheet mounted, which lets a caller
 *    switch to print media afterwards and read the styles the printer would
 *    have used.
 */
async function capturePrint(page: Page): Promise<PrintSnapshot> {
  await page.evaluate(() => {
    const w = window as unknown as { __snap?: unknown; print: () => void };
    w.__snap = null;
    w.print = () => {
      const el = document.querySelector(".paper-vault") as HTMLElement | null;
      w.__snap = {
        sheets: document.querySelectorAll(".paper-vault").length,
        symbols: el ? el.querySelectorAll(".pv-qr canvas").length : 0,
        firstCaption: el?.querySelector(".pv-qr figcaption")?.textContent ?? "",
        rules: el ? el.querySelectorAll(".pv-rule").length : 0,
        text: el?.textContent ?? "",
      };
      throw new Error("print stubbed — see capturePrint()");
    };
  });

  await visible(page.getByRole("button", { name: /Print paper vault/i })).click();
  await page.waitForFunction(
    () => (window as unknown as { __snap: unknown }).__snap !== null,
    null,
    { timeout: 30_000 }
  );
  return page.evaluate(() => (window as unknown as { __snap: PrintSnapshot }).__snap);
}

test.describe("paper vault", () => {
  test("prints a sheet of scannable parts for the container", async ({ page }) => {
    await encryptSomething(page);
    const snap = await capturePrint(page);

    expect(snap.sheets, "no paper vault sheet was in the document when it printed").toBe(1);

    // One canvas per §7.1 part. The encoding itself is gated by the Python
    // conformance suite comparing emitted strings; this gates the wiring.
    expect(snap.symbols).toBe(1);
    expect(snap.firstCaption).toMatch(/part 1 of 1/);
  });

  test("prints black on white, and is invisible on screen", async ({ page }) => {
    await encryptSomething(page);

    // Hidden on screen. If this inverts, the sheet appears in the middle of the
    // app and the app prints its dark self — the debt 4.2 exists to pay.
    await expect(page.locator(".paper-vault")).toHaveCount(0);

    // capturePrint's stub throws, so the sheet is still mounted here and its
    // styles can be read under each medium in turn.
    await capturePrint(page);
    const sheet = page.locator(".paper-vault");
    await expect(sheet).toBeHidden();

    await page.emulateMedia({ media: "print" });
    const ink = await sheet.evaluate((el) => {
      const s = getComputedStyle(el);
      return { display: s.display, visibility: s.visibility, color: s.color, bg: s.backgroundColor };
    });
    const rest = await page.evaluate(() => {
      // The app's own content, by element rather than by label: a text match
      // for a button silently returns nothing when the label differs by mode,
      // and an assertion that cannot find its subject passes for the wrong
      // reason.
      const main = document.querySelector("main");
      const heading = document.querySelector("h1");
      return {
        main: main ? getComputedStyle(main).visibility : "missing",
        heading: heading ? getComputedStyle(heading).visibility : "missing",
      };
    });
    await page.emulateMedia({ media: "screen" });

    expect(ink.display).not.toBe("none");
    expect(ink.visibility).toBe("visible");
    // …and nothing else does. This half is the actual feature: the sheet being
    // styled correctly is no use if the dark app prints around it. A control
    // that deleted the `body *` hide rule left every other assertion here
    // passing, which is how this line came to exist.
    expect(rest.main, "the app's UI still prints alongside the sheet").toBe("hidden");
    expect(rest.heading, "the app's UI still prints alongside the sheet").toBe("hidden");
    // Explicit, not inherited. Inheriting the app's palette is precisely how
    // the previous printout came out as a dark rectangle.
    expect(ink.color).toBe("rgb(0, 0, 0)");
    expect(ink.bg).toBe("rgb(255, 255, 255)");
  });

  test("carries the procedure, not just the squares", async ({ page }) => {
    await encryptSomething(page);
    const snap = await capturePrint(page);

    // Named tools, so the sheet is actionable by someone who has only the
    // sheet. A page of squares with no instructions is a puzzle.
    expect(snap.text).toContain("keym2.py");
    expect(snap.text).toContain("join --in parts.txt");
    expect(snap.text).toContain("docs/RECOVERY.md");

    // The reminder is a ruled line and the sheet says why it is not the
    // password itself.
    expect(snap.text).toMatch(/Password reminder/i);
    expect(snap.text).toMatch(/Not the password/i);
    expect(snap.rules).toBe(2);
  });

  test("prints no secret it was not given", async ({ page }) => {
    await encryptSomething(page);
    const snap = await capturePrint(page);

    // The sheet is handed the container and nothing else. This is what keeps
    // a future edit from "helpfully" printing the plaintext beside the QR.
    expect(snap.text).not.toContain("4471-0092");
    expect(snap.text).not.toContain(STRONG_PASSWORD);
  });

  test("the sheet is not left in the DOM afterwards", async ({ page }) => {
    await encryptSomething(page);

    // A stub that *returns*, unlike capturePrint's — this test is about the
    // cleanup that runs on the line after window.print() comes back.
    await page.evaluate(() => {
      (window as unknown as { print: () => void }).print = () => {};
    });
    await visible(page.getByRole("button", { name: /Print paper vault/i })).click();

    // Rendered on demand and cleared again. The sheet holds the container and,
    // after a share enrolment, the share strings; leaving it mounted would put
    // both somewhere `document.body.textContent` reaches for the rest of the
    // session, which is the surface auto-lock and the field blur exist to
    // shrink.
    await expect(page.locator(".paper-vault")).toHaveCount(0);
  });
});

/**
 * §7.1's other half: the parts printed above have to be readable back.
 *
 * The print kit shipped a year before anything could reassemble what it
 * printed. `decodePaperParts` was written, exported, and called from nowhere in
 * the app — only from `keym2.py join`. Meanwhile the decrypt box, on seeing a
 * part, said "scan them all into this box, one per line", and on being given
 * exactly that said it again. The one instruction the paper vault gives its own
 * user could not be followed in the tool that gave it.
 *
 * Built from a frozen corpus container rather than one this test wrote, for the
 * reason v3-default.spec.ts gives: a round trip through code that agrees with
 * itself proves only that.
 */
test.describe("a printed backup can be scanned back in", () => {
  const CORPUS = resolve(__dirname, "../../scripts/fixtures/keymaker");
  const meta = JSON.parse(readFileSync(resolve(CORPUS, "fixtures.json"), "utf8")) as {
    password: string;
    fixtures: Array<{ name: string; file: string; plaintext: string }>;
  };
  const fx = meta.fixtures.find((f) => f.name === "pbkdf2-aes256gcm");

  test("every part pasted in, one per line, opens the backup", async ({ page }) => {
    if (!fx) throw new Error("corpus has no pbkdf2-aes256gcm fixture");
    const container = new Uint8Array(readFileSync(resolve(CORPUS, fx.file)));
    // Derived from the container rather than fixed. The corpus vectors are
    // small — 97 bytes here — so a printer-sized capacity yields one part, and
    // a single part would pass this test without reassembling anything. Three
    // is the smallest count that exercises ordering as well as joining.
    const parts = encodePaperParts(container, Math.ceil(container.length / 3));
    expect(parts.length, "the fixture must split into more than one part").toBeGreaterThan(1);

    await page.goto("/");
    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);

    // One part first. This is the state the old code got stuck in, and the
    // message is still right — it is the *next* step that used to be missing.
    await visible(page.getByPlaceholder("Enter text to decrypt")).fill(parts[0] as string);
    await expect(
      page.getByText(/part 1 of \d+ of a paper backup/i),
      "a single part should still say which part it is and that the rest are needed"
    ).toBeVisible();

    await visible(page.getByPlaceholder("Enter text to decrypt")).fill(parts.join("\n"));
    await visible(page.getByPlaceholder("Enter decryption password")).fill(meta.password);
    await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();

    await expect(
      page.locator("#output-text"),
      "the parts this app printed did not reassemble into the backup it printed them from"
    ).toHaveValue(fx.plaintext, { timeout: 90_000 });
  });

  test("a missing page is named as a missing page, not as a wrong password", async ({ page }) => {
    if (!fx) throw new Error("corpus has no pbkdf2-aes256gcm fixture");
    const container = new Uint8Array(readFileSync(resolve(CORPUS, fx.file)));
    const parts = encodePaperParts(container, Math.ceil(container.length / 3));

    await page.goto("/");
    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);
    // All but the last. Routed to the AEAD this is "decryption failed", which
    // sends someone to retype a password that was never wrong.
    await visible(page.getByPlaceholder("Enter text to decrypt")).fill(parts.slice(0, -1).join("\n"));

    await expect(
      page.getByText(/Missing part \d+ of \d+/i),
      "a short set of parts must say which page is missing"
    ).toBeVisible();
  });
});
