import { test, expect, type Page } from "@playwright/test";
import { visible, useTextMode, selectCrypto, STRONG_PASSWORD } from "./helpers";

/**
 * The rehearsal — test the backup before you trust it (10× plan, Bet 2).
 *
 * Shares are shown once with a strong warning, then gone, and until now the
 * first time anyone learned whether they worked was the day they were needed.
 * The rehearsal walks the owner through the heir's path while the strips are
 * still on screen: paste any k of them, open the backup with them alone, and
 * be told that it opened — never what was in it.
 *
 * So the file asserts two things at once, and the second is the one that
 * matters. That the strips open the backup: the report names the seconds, the
 * strips and the byte count, and the byte count is checked against the secret
 * this test sealed. And that the plaintext went nowhere: after a successful
 * rehearsal the secret is absent from every text node and every field on the
 * page, and the Result box still holds the container.
 *
 * The negative control is the wrong-strip test. A rehearsal that reported
 * success without opening anything would pass every "it said opened" line and
 * fail that one — and the byte count in the first test with it.
 */

const SECRET = "The safe combination is 31-07-1966; the spare key is under the third stone.";

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

const dialog = (page: Page) => page.getByRole("dialog");
const rehearsalInput = (page: Page) => dialog(page).getByLabel("Strips to rehearse with");
const openButton = (page: Page) =>
  dialog(page).getByRole("button", { name: /^Open with these strips$/ });
const result = (page: Page) => dialog(page).getByTestId("rehearsal-result");

/**
 * Seal SECRET with a k-of-n share set and leave the one-time dialog open.
 * Returns the share strings as the owner sees them, read off the dialog.
 */
async function sealWithShares(page: Page, k: number, n: number): Promise<string[]> {
  await page.goto("/");
  await useTextMode(page);
  // PBKDF2 for the reason paper-vault.spec.ts gives: the KDF is not under
  // test, and Argon2id on a shared runner is what times a 6-second test out.
  await selectCrypto(page, "pbkdf2", "aes");
  await enableShares(page, k, n);
  await visible(page.getByPlaceholder("Enter text to encrypt")).fill(SECRET);
  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
  await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();
  await expect(dialog(page).getByText(new RegExp(`Save these ${n} shares now`))).toBeVisible({
    timeout: 90_000,
  });
  const shares = (await dialog(page).getByText(/^KMSHARE1:/).allTextContents()).map((s) => s.trim());
  expect(shares, "the dialog shows one string per share").toHaveLength(n);
  await dialog(page).getByRole("button", { name: /Rehearse now/ }).click();
  await expect(rehearsalInput(page)).toBeVisible();
  return shares;
}

/** One character of the payload changed — what a mistyped strip looks like. */
function corrupt(share: string): string {
  const i = share.length - 3;
  const c = share[i] === "A" ? "B" : "A";
  return share.slice(0, i) + c + share.slice(i + 1);
}

/** Read the rehearsal box of the sheet at the instant the dialog prints it. */
async function printedRehearsalBox(page: Page): Promise<string> {
  await page.evaluate(() => {
    const w = window as unknown as { __box?: unknown; print: () => void };
    w.__box = null;
    w.print = () => {
      w.__box = document.querySelector(".paper-vault .pv-rehearsal")?.textContent ?? "";
      // Throwing keeps the sheet mounted; the handler clears it on the line
      // after print() returns. paper-vault.spec.ts explains.
      throw new Error("print stubbed");
    };
  });
  await dialog(page).getByRole("button", { name: /Print paper vault/i }).click();
  await page.waitForFunction(() => (window as unknown as { __box: unknown }).__box !== null, null, {
    timeout: 30_000,
  });
  return page.evaluate(() => (window as unknown as { __box: string }).__box);
}

/** The same day next year, computed the way the sheet computes it. */
function aYearAfter(isoDate: string): string {
  const d = new Date(`${isoDate}T00:00:00Z`);
  d.setUTCFullYear(d.getUTCFullYear() + 1);
  return d.toISOString().slice(0, 10);
}

test("two of three strips open the backup in rehearsal, and the contents stay hidden", async ({ page }) => {
  const shares = await sealWithShares(page, 2, 3);

  // Strips 1 and 3, as an heir would paste them — and not the password.
  await rehearsalInput(page).fill(`${shares[0]}\n${shares[2]}`);
  await expect(dialog(page).getByText("2 of 2 strips pasted")).toBeVisible();
  await openButton(page).click();

  // A share unlock is HKDF, not a KDF, so "under a second" is the common
  // report; a slow machine gets the figure.
  await expect(result(page)).toContainText(/Opened in (under a second|\d+\.\d s) with strips 1 and 3/, {
    timeout: 60_000,
  });
  await expect(result(page)).toContainText("kept hidden");
  await expect(result(page)).toHaveAttribute("role", "status");
  // The byte count is the one fact about the contents that is reported, and
  // it has to be the size of what was sealed: a rehearsal that opened
  // nothing would have nothing to count.
  await expect(result(page)).toContainText(
    `${new TextEncoder().encode(SECRET).length.toLocaleString("en-US")} bytes`
  );

  // Kept hidden, checked rather than trusted: not in any text node, not in
  // any field, and the Result box still holds the container.
  const leak = await page.evaluate((secret) => {
    const inText = (document.body.textContent ?? "").includes(secret);
    const inFields = Array.from(document.querySelectorAll("input, textarea")).some((el) =>
      (el as HTMLInputElement).value.includes(secret)
    );
    return { inText, inFields };
  }, SECRET);
  expect(leak, "the rehearsal rendered the plaintext somewhere").toEqual({ inText: false, inFields: false });
  const output = await page.evaluate(
    () => (document.querySelector("#output-text") as HTMLTextAreaElement).value
  );
  expect(output.startsWith("keym2:"), "the Result box no longer holds the container").toBe(true);

  // The pasted strips have done their job and are gone from the box.
  await expect(rehearsalInput(page)).toHaveValue("");
});

test("a wrong strip fails with a named error, and stamps nothing", async ({ page }) => {
  const shares = await sealWithShares(page, 2, 3);

  await rehearsalInput(page).fill(`${shares[0]}\n${corrupt(shares[1]!)}`);
  await openButton(page).click();

  await expect(result(page)).toContainText("did not open the backup", { timeout: 60_000 });
  await expect(result(page)).toHaveAttribute("role", "alert");
  await expect(result(page)).toContainText("a single wrong character is enough");

  // A failed rehearsal is not a rehearsal: the box prints blank.
  const box = await printedRehearsalBox(page);
  expect(box).toContain("☐");
  expect(box).not.toContain("☑");
  expect(box).not.toMatch(/Rehearsed on \d{4}-\d{2}-\d{2}/);
});

test("fewer than k strips is refused before any attempt", async ({ page }) => {
  const shares = await sealWithShares(page, 2, 3);

  await rehearsalInput(page).fill(shares[0]!);
  await expect(dialog(page).getByText("1 of 2 strips pasted")).toBeVisible();
  await expect(openButton(page)).toBeDisabled();

  // Comment lines are dropped the way the decrypt box drops them — pasting
  // the reference CLI's `# share 2 of 3` output back in is the obvious move.
  await rehearsalInput(page).fill(`# share 1 of 3\n${shares[0]}\n# share 3 of 3\n${shares[2]}`);
  await expect(dialog(page).getByText("2 of 2 strips pasted")).toBeVisible();
  await expect(openButton(page)).toBeEnabled();
});

test("the following print carries the filled stamp", async ({ page }) => {
  const shares = await sealWithShares(page, 2, 3);
  await rehearsalInput(page).fill(`${shares[2]}\n${shares[0]}`);
  await openButton(page).click();
  // Named in strip order, whichever order they were pasted in.
  await expect(result(page)).toContainText(/with strips 1 and 3/, { timeout: 60_000 });

  const box = await printedRehearsalBox(page);
  const today = new Date().toISOString().slice(0, 10);
  expect(box).toContain(`☑ Rehearsed on ${today} with strips 1 and 3`);
  expect(box).toContain(`rehearse again by ${aYearAfter(today)}`);
  expect(box).not.toContain("☐");
});
