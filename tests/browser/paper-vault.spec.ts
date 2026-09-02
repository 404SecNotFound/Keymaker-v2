import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { encodePaperParts } from "../../src/lib/keym-v2-paper";
import { dearmorKeym2, keym2SlotCountOffset, KEYM2_VERSION_V3 } from "../../src/lib/keym-v2";
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
  /** The cover's three headings, in order. */
  coverCells: string[];
  /** Slot segments in the byte map under the symbols. */
  slotSegments: number;
  /** Recovery strips, and how many of them carry a "Held by" line. */
  strips: number;
  heldBy: number;
  /** Container symbols on the strips page — the owner's copy keeps those. */
  stripsPageSymbols: number;
  /** The rehearsal box's text. */
  rehearsal: string;
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

/** Enrol a k-of-n share set. The same helper container-inspector.spec.ts carries. */
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

/**
 * Encrypt with a share set enrolled, and leave the one-time shares dialog
 * open: its Print button is the one that hands the sheet the shares.
 */
async function encryptWithShares(page: Page, k: number, n: number) {
  await page.goto("/");
  await useTextMode(page);
  await selectCrypto(page, "pbkdf2", "aes");
  await enableShares(page, k, n);
  await visible(page.getByPlaceholder("Enter text to encrypt")).fill(SECRET);
  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
  await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();
  await expect(page.getByText(new RegExp(`Save these ${n} shares now`))).toBeVisible({ timeout: 90_000 });
}

/** The slot-count byte of the container the app just wrote, read the way §5 defines it. */
async function slotCountByte(page: Page): Promise<number> {
  const armored = await page.evaluate(
    () => (document.querySelector("#output-text") as HTMLTextAreaElement).value
  );
  const bytes = dearmorKeym2(armored);
  expect(bytes[4], "these tests are written against v3 output").toBe(KEYM2_VERSION_V3);
  return bytes[keym2SlotCountOffset(KEYM2_VERSION_V3)] as number;
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
async function capturePrint(page: Page, from: "form" | "dialog" = "form"): Promise<PrintSnapshot> {
  await page.evaluate(() => {
    const w = window as unknown as { __snap?: unknown; print: () => void };
    w.__snap = null;
    w.print = () => {
      const el = document.querySelector(".paper-vault") as HTMLElement | null;
      const strips = el ? Array.from(el.querySelectorAll(".pv-strip")) : [];
      w.__snap = {
        sheets: document.querySelectorAll(".paper-vault").length,
        symbols: el ? el.querySelectorAll(".pv-qr canvas").length : 0,
        firstCaption: el?.querySelector(".pv-qr figcaption")?.textContent ?? "",
        rules: el ? el.querySelectorAll(".pv-rule").length : 0,
        text: el?.textContent ?? "",
        coverCells: el
          ? Array.from(el.querySelectorAll(".pv-cover-cell h2"), (h) => h.textContent ?? "")
          : [],
        slotSegments: el ? el.querySelectorAll('.pv-bytemap [data-kind="slot"]').length : 0,
        strips: strips.length,
        heldBy: strips.filter((s) => /Held by/.test(s.textContent ?? "")).length,
        stripsPageSymbols: el ? el.querySelectorAll(".pv-strips .pv-qr canvas").length : 0,
        rehearsal: el?.querySelector(".pv-rehearsal")?.textContent ?? "",
      };
      throw new Error("print stubbed — see capturePrint()");
    };
  });

  // Two buttons print the sheet: the one under the result, and the one in
  // the one-time shares dialog. While the dialog is up its scrim covers the
  // first, so the caller says which.
  const scope = from === "dialog" ? page.getByRole("dialog") : page;
  await visible(scope.getByRole("button", { name: /Print paper vault/i })).click();
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
 * The sheet as a procedure (10× plan, Bet 4).
 *
 * The same snapshot, taken at the instant of printing, asked four more
 * questions: does a cover in plain language come before the squares; does the
 * byte map under them draw one segment per slot the container *actually*
 * holds — the slot-count byte is the authority, read from the armored output
 * the way container-inspector.spec.ts reads it; is every share a strip with a
 * "Held by" line, on a page that carries no container symbol; and is there a
 * rehearsal box to fill in ink. The strips test is the file's negative
 * control: rendered as a list again, its count fails by number.
 */
test.describe("the sheet as a procedure", () => {
  test("opens with a cover in plain language: what this is, what you need, do this", async ({ page }) => {
    await encryptSomething(page);
    const snap = await capturePrint(page);

    expect(snap.coverCells).toEqual(["What this is", "What you need", "Do this"]);
    // Written for someone who did not choose this tool: what the squares
    // are, and the one fact that makes the page safe to keep.
    expect(snap.text).toMatch(/The squares on this page are the backup itself/);
    expect(snap.text).toMatch(/safe to keep and useless to steal/);
    expect(snap.text).toMatch(/nothing here depends on it still existing/i);
    // The cover points at the procedure rather than repeating it.
    expect(snap.text).toContain("How to open this without Keymaker");
  });

  test("the byte map under the symbols draws one segment per slot the container holds", async ({ page }) => {
    await encryptSomething(page);
    const trueCount = await slotCountByte(page);
    expect(trueCount, "a plain passphrase encrypt writes exactly one slot").toBe(1);

    const snap = await capturePrint(page);
    expect(snap.slotSegments).toBe(trueCount);
    expect(snap.text).toMatch(/1 slot — the ways in/);
    expect(snap.text).toMatch(/bytes of header, then the sealed payload/);
  });

  test("with shares: one strip per envelope, each with a held-by line, on a page without the symbols", async ({ page }) => {
    await encryptWithShares(page, 2, 3);
    const trueCount = await slotCountByte(page);
    expect(trueCount, "a passphrase plus a share set is two slots").toBe(2);

    const snap = await capturePrint(page, "dialog");
    expect(snap.strips, "one strip per share, or an envelope is short a key").toBe(3);
    expect(snap.heldBy, "every strip needs a line for its holder's name").toBe(3);
    expect(snap.text).toContain("Recovery strip 1 of 3");
    expect(snap.text).toContain("Recovery strip 3 of 3");
    expect(snap.text).toMatch(/cut here/);
    // The owner's copy keeps the symbols; a strip is a key and nothing else.
    expect(snap.stripsPageSymbols).toBe(0);
    expect(snap.symbols).toBeGreaterThan(0);
    // The map grew with the container: two slots in the byte, two segments.
    expect(snap.slotSegments).toBe(trueCount);
    // And the strip says what it is to whoever finds it alone.
    expect(snap.text).toMatch(/alone, this one reveals nothing/);
    expect(snap.text).toContain("keym2.py decrypt --share");
    // The rehearsal line asks which strips were used, one blank per strip needed.
    expect(snap.rehearsal).toMatch(/with strips ______ and ______/);
  });

  test("carries a rehearsal box to be filled in ink", async ({ page }) => {
    await encryptSomething(page);
    const snap = await capturePrint(page);

    expect(snap.rehearsal).toContain("Rehearsed on");
    expect(snap.rehearsal).toContain("rehearse again by");
    // A box to tick, not a value the app filled in: nothing is stored.
    expect(snap.rehearsal).toContain("\u2610");
    expect(snap.rehearsal).toMatch(/A backup that has never been opened is a hope/);
    // No strips, no strip blanks.
    expect(snap.rehearsal).not.toMatch(/with strips/);
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
