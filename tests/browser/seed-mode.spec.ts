import { test, expect, type Locator, type Page } from "@playwright/test";
import { visible, useTextMode, decryptText, ARMOR_PREFIXES, STRONG_PASSWORD } from "./helpers";

/**
 * Seed Phrase mode — the doors under the hero, and the grid behind one of them.
 *
 * Two authorities matter here, and every test is written against one of them
 * rather than against the grid's own claims. The wordlist: a word is on it or
 * it is not, and the grid must say which one is wrong *by position*, in words
 * — a red border that a tenth of men cannot see is the defect the mode
 * replaces, so every verdict below is asserted as text and as `data-tone`,
 * never as a colour. And the bytes: the phrase the grid seals must come back
 * from the decryptor as exactly the words typed, joined by single spaces. The
 * round trip is the test, not the appearance of a filled grid.
 *
 * The negative control for the file is the misspelling test. With per-word
 * validation removed, "Word 7 is not on the list" never appears and that test
 * fails by name; docs/design/STATUS.md records the run.
 */

/** BIP-39's own test vectors (Trezor's vectors.json, English). Nothing here is a wallet. */
const VARIED_12 = "legal winner thank year wave sausage worth useful legal winner thank yellow";
const ZEROS_12 =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ZEROS_24 =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

// `exact`, or "Word 1" also matches "Word 10" through "Word 12".
const cell = (page: Page, n: number): Locator =>
  visible(page.getByRole("combobox", { name: `Word ${n}`, exact: true }));
const status = (page: Page) => page.getByTestId("seed-grid-status");
const encryptButton = (page: Page) => visible(page.getByRole("button", { name: /^Encrypt Text$/i }));
const wipeNow = (page: Page) => page.getByRole("button", { name: /Wipe now/i });

/** The pill route, which configures nothing else. The door route is its own test. */
async function enterSeedMode(page: Page) {
  await visible(page.getByRole("button", { name: "Seed phrase", exact: true })).click();
  await expect(visible(page.getByTestId("seed-grid"))).toBeVisible();
  // The wordlist is lazy; no verdict below means anything until it has landed.
  await expect(status(page)).not.toContainText("Loading the word list");
}

/** Fill the cells one by one, then leave the last so nothing is "still being typed". */
async function fillGrid(page: Page, phrase: string) {
  const words = phrase.split(" ");
  for (const [i, w] of words.entries()) await cell(page, i + 1).fill(w);
  await cell(page, words.length).blur();
}

/** Seal what the grid holds and hand back the armored container. */
async function sealGrid(page: Page): Promise<string> {
  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
  await encryptButton(page).click();
  await page.waitForFunction(
    (prefixes: readonly string[]) => {
      const value = (document.querySelector("#output-text") as HTMLTextAreaElement | null)?.value;
      return !!value && prefixes.some((p) => value.startsWith(p));
    },
    ARMOR_PREFIXES,
    { timeout: 90_000 }
  );
  return page.evaluate(() => (document.querySelector("#output-text") as HTMLTextAreaElement).value);
}

test.beforeEach(async ({ page }) => {
  await page.goto("/");
});

test("a door sets the mode and the defaults — seed, then open, then file", async ({ page }) => {
  // The page lands on Encrypt / File with one way in: the file door's
  // configuration, before any door is pressed.
  await expect(page.getByTestId("door-file")).toHaveAttribute("aria-pressed", "true");
  const inspector = page.getByTestId("container-inspector");
  await expect(inspector).toContainText("1 way in");

  await page.getByTestId("door-seed").click();
  await expect(page.getByRole("tab", { name: "Encrypt" })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByTestId("door-seed")).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByTestId("door-file")).toHaveAttribute("aria-pressed", "false");
  await expect(visible(page.getByTestId("seed-grid"))).toBeVisible();
  await expect(cell(page, 12)).toBeVisible();
  await expect(page.getByRole("combobox", { name: "Word 13", exact: true })).toHaveCount(0);
  // Shares suggested: the door changed what will be written, and the pane
  // that restates the form says so.
  await expect(inspector).toContainText("2 ways in");

  // Pressing the door already pressed does nothing — a form in progress is
  // not reset by a stray click.
  await cell(page, 1).fill("legal");
  await page.getByTestId("door-seed").click();
  await expect(cell(page, 1)).toHaveValue("legal");

  await page.getByTestId("door-open").click();
  await expect(page.getByRole("tab", { name: "Decrypt" })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByTestId("door-open")).toHaveAttribute("aria-pressed", "true");
  await expect(visible(page.getByPlaceholder("Enter decryption password"))).toBeVisible();
  await expect(page.getByTestId("seed-grid")).toHaveCount(0);

  await page.getByTestId("door-file").click();
  await expect(page.getByRole("tab", { name: "Encrypt" })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByTestId("door-file")).toHaveAttribute("aria-pressed", "true");
  await expect(visible(page.getByText("Drop a file here"))).toBeVisible();
  // And its own default: a file does not suggest shares.
  await expect(inspector).toContainText("1 way in");
});

test("a valid phrase typed with spaces lands word by word, and the checksum is reported in words", async ({ page }) => {
  await enterSeedMode(page);
  await cell(page, 1).click();
  // The way a person types a phrase: word, space, word. Space is the "next
  // cell" key for a word the list knows.
  await page.keyboard.type(VARIED_12);

  for (const [i, w] of VARIED_12.split(" ").entries()) {
    await expect(cell(page, i + 1)).toHaveValue(w);
  }
  await expect(status(page)).toContainText("Checksum matches — a valid 12-word phrase");
  await expect(status(page)).toHaveAttribute("data-tone", "success");
  // Repeated words are legal — legal, winner and thank each appear twice —
  // and none of them is flagged.
  for (let n = 1; n <= 12; n++) {
    await expect(cell(page, n)).not.toHaveAttribute("aria-invalid", "true");
  }

  // Control on the verdict: every word on the list and the checksum wrong is
  // a different sentence, not a different colour.
  await cell(page, 12).fill("year");
  await cell(page, 12).blur();
  await expect(status(page)).toContainText("checksum does not match");
  await expect(status(page)).toHaveAttribute("data-tone", "danger");
});

test("a misspelled word is named by position, with the word it was probably meant to be", async ({ page }) => {
  await enterSeedMode(page);
  const words = VARIED_12.split(" ");
  words[6] = "wotrh"; // "worth", two letters swapped
  await fillGrid(page, words.join(" "));

  await expect(status(page)).toContainText("Word 7 is not on the list");
  await expect(status(page)).toContainText("did you mean worth");
  await expect(status(page)).toHaveAttribute("data-tone", "danger");
  await expect(cell(page, 7)).toHaveAttribute("aria-invalid", "true");
  await expect(cell(page, 6)).not.toHaveAttribute("aria-invalid", "true");

  // Sealing a word that can be part of no phrase is withheld until it is fixed.
  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
  await expect(encryptButton(page)).toBeDisabled();

  await cell(page, 7).fill("worth");
  await cell(page, 7).blur();
  await expect(status(page)).toContainText("Checksum matches");
  await expect(cell(page, 7)).not.toHaveAttribute("aria-invalid", "true");
  await expect(encryptButton(page)).toBeEnabled();
});

test("a word that is only the start of one is named as incomplete, with what it could be", async ({ page }) => {
  await enterSeedMode(page);
  await cell(page, 1).fill("abs");
  await cell(page, 1).blur();
  await expect(status(page)).toContainText("Word 1 isn't complete");
  await expect(status(page)).toContainText("absorb");
  await expect(cell(page, 1)).toHaveAttribute("aria-invalid", "true");
});

test("autocomplete completes a word from its prefix, and never guesses between several", async ({ page }) => {
  await enterSeedMode(page);
  const first = cell(page, 1);
  await first.click();
  await first.pressSequentially("saus");
  const list = page.getByRole("listbox", { name: "Completions for word 1" });
  await expect(list).toBeVisible();
  await expect(list.getByRole("option")).toHaveText(["sausage"]);
  await first.press("Enter");
  await expect(first).toHaveValue("sausage");
  await expect(cell(page, 2)).toBeFocused();

  // An ambiguous prefix lists its candidates — eight of the ten "ab" words —
  // and Space does not pick one on the user's behalf.
  const second = cell(page, 2);
  await second.pressSequentially("ab");
  const list2 = page.getByRole("listbox", { name: "Completions for word 2" });
  await expect(list2.getByRole("option")).toHaveCount(8);
  await expect(list2.getByRole("option").first()).toHaveText("abandon");
  await second.press("Space");
  await expect(second).toHaveValue("ab");
  await expect(second).toBeFocused();

  // The arrow keys are a choice, and Enter honours it: two steps down is "able".
  await second.press("ArrowDown");
  await second.press("ArrowDown");
  await expect(second).toHaveAttribute("aria-activedescendant", /option-2$/);
  await second.press("Enter");
  await expect(second).toHaveValue("able");
  await expect(cell(page, 3)).toBeFocused();

  // Escape closes the list without touching the word.
  const third = cell(page, 3);
  await third.pressSequentially("wi");
  await expect(page.getByRole("listbox", { name: "Completions for word 3" })).toBeVisible();
  await third.press("Escape");
  await expect(page.getByRole("listbox", { name: "Completions for word 3" })).toHaveCount(0);
  await expect(third).toHaveValue("wi");
  await expect(third).toHaveAttribute("aria-expanded", "false");
});

test("a whole phrase pasted into one cell fills the grid, growing it to fit", async ({ page }) => {
  await enterSeedMode(page);
  await expect(page.getByRole("button", { name: "12", exact: true })).toHaveAttribute("aria-pressed", "true");

  // Twenty-four words into a twelve-word grid: the grid grows rather than
  // dropping half a phrase on the floor.
  await cell(page, 1).fill(ZEROS_24);
  for (const [i, w] of ZEROS_24.split(" ").entries()) {
    await expect(cell(page, i + 1)).toHaveValue(w);
  }
  await expect(page.getByRole("button", { name: "24", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(status(page)).toContainText("Checksum matches — a valid 24-word phrase");

  // Numbering from a wallet's printout falls away with the other non-letters.
  await page.getByRole("button", { name: "12", exact: true }).click();
  await cell(page, 1).fill(
    VARIED_12.split(" ").map((w, i) => `${i + 1}. ${w}`).join("\n")
  );
  await expect(cell(page, 12)).toHaveValue("yellow");
  await expect(status(page)).toContainText("Checksum matches — a valid 12-word phrase");
});

test("a phrase entered in the grid seals and opens to the same words — byte authority", async ({ page }) => {
  await enterSeedMode(page);
  await fillGrid(page, VARIED_12);
  await expect(status(page)).toContainText("Checksum matches");

  const armored = await sealGrid(page);
  // Sealed means gone, exactly as the textarea empties: the cells hold the
  // same plaintext and are cleared with it.
  await expect(cell(page, 1)).toHaveValue("");
  await expect(cell(page, 12)).toHaveValue("");

  const recovered = await decryptText(page, armored, STRONG_PASSWORD);
  // The words, joined by single spaces, nothing before and nothing after —
  // what the decryptor and keym2.py would both hand back.
  expect(recovered).toBe(VARIED_12);
  // And the decrypt side's own detector, which never saw the grid, agrees
  // it is a phrase.
  await expect(page.getByText(/All words recognised/)).toBeVisible();
});

test("the button waits for every cell to hold a listed word, and for nothing else", async ({ page }) => {
  await enterSeedMode(page);
  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);

  // Twelve times "abandon": every word on the list, checksum wrong. Reported,
  // not enforced — a phrase from a wallet that never followed the standard
  // is its owner's to seal.
  await fillGrid(page, ZEROS_12.replace(/about$/, "abandon"));
  await expect(status(page)).toContainText("checksum does not match");
  await expect(encryptButton(page)).toBeEnabled();

  // An empty cell is not a phrase.
  await cell(page, 12).fill("");
  await cell(page, 12).blur();
  await expect(status(page)).toContainText("11 of 12 words entered");
  await expect(encryptButton(page)).toBeDisabled();
});

test("only the cell being typed into is readable; reveal lifts all of them", async ({ page }) => {
  await enterSeedMode(page);
  await cell(page, 1).fill("legal");
  await cell(page, 2).fill("winner");
  // fill leaves the second cell focused.
  await expect(cell(page, 2)).toBeFocused();
  await expect(cell(page, 1)).toHaveCSS("filter", /blur/);
  await expect(cell(page, 2)).toHaveCSS("filter", "none");

  await visible(page.getByRole("button", { name: "Show secret text" })).click();
  await expect(cell(page, 1)).toHaveCSS("filter", "none");
});

test("the grid and the textarea edit one secret: a phrase moves between them intact", async ({ page }) => {
  await useTextMode(page);
  const textarea = visible(page.getByPlaceholder("Enter text to encrypt"));
  await expect(textarea).toBeVisible();
  await expect(page.getByTestId("seed-grid")).toHaveCount(0);

  await textarea.fill(VARIED_12);
  await visible(page.getByRole("button", { name: "Seed phrase", exact: true })).click();
  await expect(cell(page, 12)).toHaveValue("yellow");
  await expect(status(page)).toContainText("Checksum matches");

  await cell(page, 12).fill("year");
  await cell(page, 12).blur();
  await useTextMode(page);
  await expect(visible(page.getByPlaceholder("Enter text to encrypt"))).toHaveValue(
    VARIED_12.replace(/yellow$/, "year")
  );
});

test("the cells are secrets: they arm the lock and Wipe now empties them", async ({ page }) => {
  await enterSeedMode(page);
  await expect(wipeNow(page)).toHaveCount(0);

  await cell(page, 1).fill("legal");
  await visible(wipeNow(page)).click();
  await expect(cell(page, 1)).toHaveValue("");
  await expect(wipeNow(page)).toHaveCount(0);
});
