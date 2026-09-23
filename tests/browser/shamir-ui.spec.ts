import { test, expect } from "@playwright/test";
import { visible, useTextMode, selectCrypto, capturePrintedSymbols, composePhoto } from "./helpers";

/**
 * Phase 4.1d — recovery shares, driven the way a user reaches them.
 *
 * The format and the core landed with byte-equality parity against the Python
 * reference, and none of that is retested here. What these cover is the part
 * that has no reference implementation: whether a person can actually enrol a
 * share set and, later, open the container with nothing but paper.
 *
 * The last test is the one that matters. Everything else is a control on it.
 */

const PASSWORD = "correct-horse-battery-staple-9271!X";
const SECRET = "abandon ability able about above absent absorb abstract 🔑";

/**
 * Turn on shares in Advanced and set the k-of-n.
 *
 * Both toggles are driven to a *state* and then confirmed, rather than clicked
 * once and assumed. The previous version read `aria-expanded`, clicked, and
 * moved straight on to filling a field — which hung for the full 120 s test
 * timeout in CI:
 *
 *     locator.fill: waiting for getByLabel('Shares to print')
 *
 * "Recovery shares" is a Radix `Switch`, and the fields below it are behind
 * `{shamirEnabled && …}`, so they do not exist until it flips. A click that
 * lands before the handler is attached is swallowed, the switch stays off, and
 * the wait is for an element that is never going to be rendered. Nothing in
 * the old helper could tell that apart from a slow page, so it waited out the
 * clock and reported a timeout on `fill` — the symptom, two steps from the
 * cause.
 *
 * Asserting the state after each click costs one expect and turns that into an
 * immediate, named failure.
 */
async function enableShares(page: import("@playwright/test").Page, k: number, n: number) {
  const advanced = visible(page.getByRole("button", { name: /^Advanced/ }));
  if ((await advanced.getAttribute("aria-expanded")) !== "true") await advanced.click();
  await expect(advanced, "the Advanced panel did not open").toHaveAttribute(
    "aria-expanded",
    "true"
  );

  const sharesSwitch = visible(page.getByRole("switch", { name: "Recovery shares" }));
  // Retried, not clicked once. A single click that gets swallowed leaves the
  // switch off forever, and asserting afterwards only reports that faster — it
  // does not make the run pass. The guard re-reads `aria-checked` before every
  // attempt, so a click that *did* land is never undone by a retry.
  await expect(
    async () => {
      if ((await sharesSwitch.getAttribute("aria-checked")) !== "true") {
        await sharesSwitch.click();
      }
      await expect(sharesSwitch).toHaveAttribute("aria-checked", "true", { timeout: 1_000 });
    },
    "the Recovery shares switch never turned on, so its fields were never rendered"
  ).toPass({ timeout: 20_000 });

  await visible(page.getByLabel("Shares to print")).fill(String(n));
  await visible(page.getByLabel("Needed to open")).fill(String(k));
}

async function encryptWithShares(
  page: import("@playwright/test").Page,
  k: number,
  n: number
): Promise<{ armored: string; shares: string[] }> {
  await page.goto("/");
  await useTextMode(page);
  await selectCrypto(page, "pbkdf2", "aes");
  await enableShares(page, k, n);

  await visible(page.getByPlaceholder("Enter text to encrypt")).fill(SECRET);
  await visible(page.getByPlaceholder("Enter a strong password")).fill(PASSWORD);
  await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();

  await expect(page.getByText(new RegExp(`Save these ${n} shares now`))).toBeVisible({
    timeout: 90_000,
  });
  const shares = await page.locator("p.font-mono").allTextContents();
  // The dialog's own labelled button, not Radix's icon X: the X's accessible
  // name is an implementation detail of the component library, and a locator
  // built on it is a portability hazard between engines (how the U28
  // clipboard test put main red on two of three). Escape no longer closes this
  // dialog at all; see "the one-time shares survive a stray Escape".
  await page.getByRole("button", { name: "I have saved these shares" }).click();
  await expect(page.getByText(/Save these/)).toHaveCount(0);

  const armored = await page.evaluate(
    () => (document.querySelector("#output-text") as HTMLTextAreaElement).value
  );
  return { armored, shares: shares.filter((s) => s.startsWith("KMSHARE2:")) };
}

test.describe("enrolling a share set", () => {
  test("issues n shares and says what they cost, once", async ({ page }) => {
    const { armored, shares } = await encryptWithShares(page, 2, 3);

    expect(shares, "the share set was not produced").toHaveLength(3);
    for (const s of shares) expect(s).toMatch(/^KMSHARE2:[0-9A-HJKMNP-TV-Z-]+$/);
    expect(new Set(shares).size, "two shares came out identical").toBe(3);
    expect(armored.startsWith("keym2:"), "the container is not v2 armor").toBe(true);
  });

  test("a preset fills both fields, and the set it issues is that set", async ({ page }) => {
    await page.goto("/");
    await useTextMode(page);
    await selectCrypto(page, "pbkdf2", "aes");
    await enableShares(page, 2, 4);

    const presets = page.getByRole("group", { name: "Common share sets" });
    const twoOfThree = visible(presets.getByRole("button", { name: "2 of 3" }));
    const threeOfFive = visible(presets.getByRole("button", { name: "3 of 5" }));
    // 2 of 4 is neither preset, so neither may claim to be chosen.
    await expect(twoOfThree).toHaveAttribute("aria-pressed", "false");
    await expect(threeOfFive).toHaveAttribute("aria-pressed", "false");

    await threeOfFive.click();
    await expect(page.getByLabel("Needed to open")).toHaveValue("3");
    await expect(page.getByLabel("Shares to print")).toHaveValue("5");
    await expect(threeOfFive).toHaveAttribute("aria-pressed", "true");
    await expect(twoOfThree).toHaveAttribute("aria-pressed", "false");

    // A preset only fills the fields. Editing one afterwards is a custom set,
    // and the button must stop saying otherwise.
    await visible(page.getByLabel("Needed to open")).fill("4");
    await expect(threeOfFive).toHaveAttribute("aria-pressed", "false");

    await threeOfFive.click();
    await visible(page.getByPlaceholder("Enter text to encrypt")).fill(SECRET);
    await visible(page.getByPlaceholder("Enter a strong password")).fill(PASSWORD);
    await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();
    await expect(page.getByText(/Save these 5 shares now/)).toBeVisible({ timeout: 90_000 });
    await expect(page.getByText(/Any 3 of them open this container/)).toBeVisible();
    const shares = (await page.locator("p.font-mono").allTextContents()).filter((s) =>
      s.startsWith("KMSHARE2:")
    );
    expect(shares, "the preset did not issue five shares").toHaveLength(5);
  });

  test("the honest framing is on screen, not only in the docs", async ({ page }) => {
    await page.goto("/");
    await useTextMode(page);
    await enableShares(page, 2, 3);

    // Roadmap, "Honest framing to preserve": any k shares open the container
    // without the password, so each share is as sensitive as the password.
    // A test rather than a comment, because copy is the first thing to be
    // trimmed by someone who does not know why it is there.
    await expect(
      page.getByText(/Each share is as sensitive as your password/i).first()
    ).toBeVisible();
  });

  test("the threshold cannot exceed the number of shares", async ({ page }) => {
    await page.goto("/");
    await useTextMode(page);
    await enableShares(page, 2, 3);

    // A set nobody can ever reach is the worst outcome a backup feature has.
    await visible(page.getByLabel("Needed to open")).fill("9");
    await expect(visible(page.getByLabel("Needed to open"))).toHaveValue("3");

    await visible(page.getByLabel("Shares to print")).fill("2");
    await expect(
      visible(page.getByLabel("Needed to open")),
      "lowering the count left a threshold above it"
    ).toHaveValue("2");
  });
});

test.describe("the one-time shares dialog", () => {
  test("survives a stray Escape and a backdrop click, and closes when asked", async ({ page }) => {
    await page.goto("/");
    await useTextMode(page);
    await selectCrypto(page, "pbkdf2", "aes");
    await enableShares(page, 2, 3);
    await visible(page.getByPlaceholder("Enter text to encrypt")).fill(SECRET);
    await visible(page.getByPlaceholder("Enter a strong password")).fill(PASSWORD);
    await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();
    const title = page.getByText(/Save these 3 shares now/);
    await expect(title).toBeVisible({ timeout: 90_000 });

    // The dialog says the shares are shown once and cannot be reissued. Each
    // of these used to close it, and closing it destroys them.
    await page.keyboard.press("Escape");
    await expect(title, "Escape discarded the one-time shares").toBeVisible();
    await page.mouse.click(5, 5);
    await expect(title, "a click on the backdrop discarded the one-time shares").toBeVisible();

    await page.getByRole("button", { name: "I have saved these shares" }).click();
    await expect(title).toHaveCount(0);
  });
});

test.describe("a share pasted into the wrong box", () => {
  test("is named as a share rather than failing as a container", async ({ page }) => {
    const { shares } = await encryptWithShares(page, 2, 3);

    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);
    await visible(page.getByPlaceholder("Enter text to decrypt")).fill(shares[0] as string);

    // §7's wrong-box paste. Without this it reaches the parser and comes back
    // as a generic decryption failure.
    await expect(page.getByText(/recovery share, not an encrypted container/i)).toBeVisible();
    // The paste is kept, so the notice must not say nothing was pasted.
    await expect(
      page.locator("#text-secret-size-error"),
      "the notice said nothing was pasted, beside the paste it had kept"
    ).not.toContainText(/Nothing was pasted/);
    await expect(visible(page.getByPlaceholder("Enter text to decrypt"))).toHaveValue(shares[0] as string);
  });
});

test.describe("the inheritance path", () => {
  test("k shares open the container with no password at all", async ({ page }) => {
    const { armored, shares } = await encryptWithShares(page, 2, 3);

    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);
    await visible(page.getByPlaceholder("Enter text to decrypt")).fill(armored);

    await visible(page.getByRole("button", { name: /^Use recovery shares$/ })).click();

    // Shares 2 and 3, not 1 and 2 — a reconstruction that had quietly become
    // positional would still pass with the leading pair.
    await visible(page.locator("#share-input")).fill(
      `# share 2 of 3\n${shares[1]}\n# share 3 of 3\n${shares[2]}\n`
    );

    // The password field is left completely empty. That is the whole claim.
    await expect(
      visible(page.getByRole("button", { name: /^Decrypt Text$/i })),
      "the button stayed disabled with a valid share set entered and no password"
    ).toBeEnabled();

    await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();
    await expect(visible(page.locator("#output-text"))).toHaveValue(SECRET, { timeout: 90_000 });
  });

  test("k-1 shares do not", async ({ page }) => {
    const { armored, shares } = await encryptWithShares(page, 3, 5);

    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);
    await visible(page.getByPlaceholder("Enter text to decrypt")).fill(armored);
    await visible(page.getByRole("button", { name: /^Use recovery shares$/ })).click();
    await visible(page.locator("#share-input")).fill(`${shares[0]}\n${shares[1]}\n`);
    await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();

    await expect(page.getByText(/Decryption failed/i).first()).toBeVisible({ timeout: 90_000 });
    await expect(page.locator("#output-text")).toHaveCount(0);
  });

  test("the password still opens a container that has a share set", async ({ page }) => {
    const { armored } = await encryptWithShares(page, 2, 3);

    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);
    await visible(page.getByPlaceholder("Enter text to decrypt")).fill(armored);
    await visible(page.getByPlaceholder("Enter decryption password")).fill(PASSWORD);
    await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();

    // §4.4's skip rule from the owner's side: enrolling shares must not cost
    // them the way in they already had.
    await expect(visible(page.locator("#output-text"))).toHaveValue(SECRET, { timeout: 90_000 });
  });
});

/**
 * The printed strips carry a QR each, and until this the app could not read
 * them into the shares box: a strip scanned on the Decrypt tab was only told it
 * was in the wrong box, and a whole printed backup scanned in one batch (parts
 * and strips together) failed as one bad paste. The images here are the strip
 * and part symbols of the real print sheet, snapshotted from inside
 * `window.print()`, so the round trip is through the artefact a person would
 * photograph rather than a fixture that could drift from it.
 */
interface PrintedBackup {
  armored: string;
  shares: string[];
  stripPngs: Buffer[];
  partPngs: Buffer[];
}

async function encryptAndPrintWithShares(
  page: import("@playwright/test").Page,
  k: number,
  n: number
): Promise<PrintedBackup> {
  await page.goto("/");
  await useTextMode(page);
  await selectCrypto(page, "pbkdf2", "aes");
  await enableShares(page, k, n);

  await visible(page.getByPlaceholder("Enter text to encrypt")).fill(SECRET);
  await visible(page.getByPlaceholder("Enter a strong password")).fill(PASSWORD);
  await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();
  await expect(page.getByText(new RegExp(`Save these ${n} shares now`))).toBeVisible({
    timeout: 90_000,
  });
  const shares = (await page.locator("p.font-mono").allTextContents()).filter((s) =>
    s.startsWith("KMSHARE2:")
  );

  // The strip and part symbols of the real print sheet, as a scan would see
  // them; see capturePrintedSymbols.
  const printed = await capturePrintedSymbols(
    page,
    page.getByRole("dialog").getByRole("button", { name: /Print paper vault/i })
  );

  await page.getByRole("button", { name: "I have saved these shares" }).click();
  await expect(page.getByText(/Save these/)).toHaveCount(0);
  const armored = await page.evaluate(
    () => (document.querySelector("#output-text") as HTMLTextAreaElement).value
  );
  return { armored, shares, stripPngs: printed.strips, partPngs: printed.parts };
}

const png = (name: string, buffer: Buffer) => ({ name, mimeType: "image/png", buffer });


async function shareBoxLines(page: import("@playwright/test").Page): Promise<string[]> {
  const value = await visible(page.locator("#share-input")).inputValue();
  return value
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"));
}

test.describe("scanning the printed strips", () => {
  test("strip QRs scan into the shares box and open the backup with no password", async ({ page }) => {
    const backup = await encryptAndPrintWithShares(page, 2, 3);
    expect(backup.stripPngs, "the sheet printed no strip symbols").toHaveLength(3);

    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);
    await visible(page.getByPlaceholder("Enter text to decrypt")).fill(backup.armored);
    await visible(page.getByRole("button", { name: /^Use recovery shares$/ })).click();

    // Strips 2 and 3, for the same reason as the typed test above.
    await page.locator("#share-qr-scan-input").setInputFiles([
      png("strip-2.png", backup.stripPngs[1] as Buffer),
      png("strip-3.png", backup.stripPngs[2] as Buffer),
    ]);
    await expect.poll(() => shareBoxLines(page), { timeout: 20_000 }).toEqual([
      backup.shares[1],
      backup.shares[2],
    ]);

    await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();
    await expect(visible(page.locator("#output-text"))).toHaveValue(SECRET, { timeout: 90_000 });
  });

  test("a whole printed backup scanned in one batch sorts parts from strips", async ({ page }) => {
    const backup = await encryptAndPrintWithShares(page, 2, 3);
    expect(backup.partPngs.length, "the sheet printed no container symbols").toBeGreaterThan(0);

    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);

    // Everything photographed off the sheet, strips interleaved with parts,
    // through the container box's own scan button. Nothing else is touched:
    // not the shares toggle, not the password.
    await page.locator("#qr-scan-input").setInputFiles([
      png("strip-1.png", backup.stripPngs[0] as Buffer),
      ...backup.partPngs.map((b, i) => png(`part-${i + 1}.png`, b)),
      png("strip-3.png", backup.stripPngs[2] as Buffer),
    ]);

    await expect(visible(page.locator("#text-secret"))).toHaveValue(backup.armored, {
      timeout: 20_000,
    });
    await expect(
      visible(page.getByRole("button", { name: /^Use a password instead$/ })),
      "the scanned strips did not turn on the shares path"
    ).toBeVisible();
    expect(await shareBoxLines(page)).toEqual([backup.shares[0], backup.shares[2]]);

    await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();
    await expect(visible(page.locator("#output-text"))).toHaveValue(SECRET, { timeout: 90_000 });
  });

  test("one photo of a whole page reads every code on it", async ({ page }) => {
    const backup = await encryptAndPrintWithShares(page, 2, 3);
    // Two strips and every container symbol laid out on one sheet and
    // photographed once, which is how a person holding the paper would do it.
    const photo = await composePhoto(page, [
      backup.stripPngs[0] as Buffer,
      ...backup.partPngs,
      backup.stripPngs[2] as Buffer,
    ]);

    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);
    await page.locator("#qr-scan-input").setInputFiles([png("the-whole-page.png", photo)]);

    await expect(visible(page.locator("#text-secret"))).toHaveValue(backup.armored, {
      timeout: 30_000,
    });
    await expect(
      page.locator("#share-input"),
      "no strip was read from the photo, so the shares box never opened"
    ).toBeVisible({ timeout: 20_000 });
    // jsqr finds codes in no particular order, and neither box cares.
    expect((await shareBoxLines(page)).sort()).toEqual([backup.shares[0], backup.shares[2]].sort());

    await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();
    await expect(visible(page.locator("#output-text"))).toHaveValue(SECRET, { timeout: 90_000 });
  });

  test("a strip scanned twice is entered once", async ({ page }) => {
    const backup = await encryptAndPrintWithShares(page, 2, 3);

    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);
    await visible(page.getByPlaceholder("Enter text to decrypt")).fill(backup.armored);
    await visible(page.getByRole("button", { name: /^Use recovery shares$/ })).click();

    // §4.6 refuses a repeated index, so a duplicate left in the box would fail
    // an otherwise sufficient set with nothing to say which photo repeated.
    await page.locator("#share-qr-scan-input").setInputFiles([
      png("strip-1.png", backup.stripPngs[0] as Buffer),
      png("strip-1-again.png", backup.stripPngs[0] as Buffer),
      png("strip-2.png", backup.stripPngs[1] as Buffer),
    ]);
    await expect.poll(() => shareBoxLines(page), { timeout: 20_000 }).toEqual([
      backup.shares[0],
      backup.shares[1],
    ]);

    await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();
    await expect(visible(page.locator("#output-text"))).toHaveValue(SECRET, { timeout: 90_000 });
  });
});

test.describe("one unlock path at a time", () => {
  test("choosing shares after a passkey does not leave the passkey in charge", async ({ page }) => {
    const { armored, shares } = await encryptWithShares(page, 2, 3);

    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);
    await visible(page.getByPlaceholder("Enter text to decrypt")).fill(armored);

    const passkey = page.getByRole("button", { name: /^Use a passkey$/ });
    test.skip((await passkey.count()) === 0, "this engine offers no passkey control");
    await visible(passkey).click();
    await visible(page.getByRole("button", { name: /^Use recovery shares$/ })).click();
    await visible(page.locator("#share-input")).fill(`${shares[0]}\n${shares[1]}\n`);

    // The passkey control is hidden while shares are on, so a passkey choice
    // left set behind it would ask for a tap and then report that this
    // container has no passkey, to someone holding a sufficient share set.
    await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();
    await expect(visible(page.locator("#output-text"))).toHaveValue(SECRET, { timeout: 90_000 });
  });
});
