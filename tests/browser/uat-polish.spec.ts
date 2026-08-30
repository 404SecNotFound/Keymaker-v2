import { test, expect } from "@playwright/test";
import { visible, useTextMode, selectCrypto, STRONG_PASSWORD } from "./helpers";

/**
 * UAT-2026-08-14, the correctness-and-polish set: U15, U16, U18, U21, U22,
 * U23, U25, U26, U28.
 *
 * Small fixes, but the report's own framing is worth keeping: several of these
 * are places where the app was *silently* wrong rather than visibly broken —
 * a dead button with no reason, a drop that vanished, a link to somebody
 * else's product. Nothing throws, so nothing catches them but a test that
 * looks at what the user sees.
 *
 * Every test here was run against the unfixed tree first; the control results
 * are recorded per describe block.
 */

const STRONG = "correct-horse-battery-staple-9271!X";

test.describe("U16 — links lead to this product's source", () => {
  test("GitHub and Open source point at Keymaker, and the fork credit does not", async ({
    page,
  }) => {
    await page.goto("/");

    // Both of these describe *Keymaker*, so both must lead to Keymaker.
    await expect(
      page.getByRole("link", { name: "GitHub", exact: true }),
      "the footer GitHub link sends people to a different product"
    ).toHaveAttribute("href", "https://github.com/404SecNotFound/Keymaker-v2");
    await expect(
      page.getByRole("link", { name: /^Open source$/ })
    ).toHaveAttribute("href", "https://github.com/404SecNotFound/Keymaker-v2");

    // ...and the GPL-3 attribution must NOT have been swept up in the fix.
    // Repointing this one would trade a broken link for a licensing
    // discourtesy, which is why the finding is two links and not three.
    await expect(
      page.getByRole("link", { name: /^IttyBitz$/ }),
      "the fork attribution was repointed away from the project being credited"
    ).toHaveAttribute("href", "https://github.com/seQRets/ittybitz");
  });
});

test.describe("U15 — a disabled button that explains itself", () => {
  test("says why Encrypt is disabled, and stops once the policy is met", async ({ page }) => {
    await page.goto("/");
    await useTextMode(page);
    await visible(page.getByPlaceholder("Enter text to encrypt")).fill("a secret");

    const notice = page.getByText(/Encrypt stays disabled until the password/i);
    const button = visible(page.getByRole("button", { name: /^Encrypt Text$/i }));

    // Nothing typed: the button is disabled for the obvious reason, and
    // explaining that would be nagging rather than helping.
    await expect(notice).toHaveCount(0);

    await visible(page.getByPlaceholder("Enter a strong password")).fill("short");
    await expect(button).toBeDisabled();
    await expect(
      notice.first(),
      "the button is disabled by policy and nothing on screen says so"
    ).toBeVisible();

    await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG);
    await expect(button).toBeEnabled();
    await expect(notice, "the explanation outlived the problem").toHaveCount(0);
  });
});

test.describe("U23 — Enter submits from the password field", () => {
  test("Enter encrypts when the button would, and does nothing when it would not", async ({
    page,
  }) => {
    await page.goto("/");
    await useTextMode(page);
    await visible(page.getByPlaceholder("Enter text to encrypt")).fill("press enter");

    const password = visible(page.getByPlaceholder("Enter a strong password"));

    // Routed through the same guard as the button: Enter must not become a way
    // to start an operation the button correctly refuses.
    await password.fill("short");
    await password.press("Enter");
    await page.waitForTimeout(500);
    // Absence, not emptiness: the output field is only mounted once an
    // operation has produced something, so "still not there" is the assertion
    // that an operation never started.
    await expect(
      page.locator("#output-text"),
      "Enter bypassed the password policy the button enforces"
    ).toHaveCount(0);

    await password.fill(STRONG);
    await password.press("Enter");
    await page.waitForFunction(
      // Existence *and* content. `?.value !== ""` is true while the element is
      // still absent, so on its own it returns the instant the page loads.
      () => {
        const el = document.querySelector("#output-text") as HTMLTextAreaElement | null;
        return el !== null && el.value !== "";
      },
      null,
      { timeout: 90_000 }
    );
    await expect(visible(page.locator("#output-text"))).not.toHaveValue("");
  });
});

test.describe("U25 — the reveal toggle describes its own state", () => {
  test("exposes aria-pressed and stops saying Hide over an empty field", async ({ page }) => {
    await page.goto("/");
    await useTextMode(page);

    const password = visible(page.getByPlaceholder("Enter a strong password"));
    await password.fill(STRONG);
    const toggle = visible(page.getByRole("button", { name: /^(Show|Hide) password$/ }));

    await expect(toggle, "a toggle with no pressed state reads identically in both").toHaveAttribute(
      "aria-pressed",
      "false"
    );
    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-pressed", "true");
    await expect(toggle).toHaveText("Hide");

    // The password is cleared after an operation while the toggle stays on.
    // "Hide" over an empty field claims something is concealed when nothing is.
    await password.fill("");
    await expect(
      toggle,
      "the button claims to be hiding a password that is not there"
    ).toHaveText("Show");
    await expect(toggle).toHaveAttribute("aria-pressed", "false");
  });
});

test.describe("U18 — the dropzone honours its own role", () => {
  test("Space activates it, as role=button promises", async ({ page }) => {
    await page.goto("/");

    const dropzone = visible(page.getByRole("button", { name: /drag|drop|browse/i })).first();
    await dropzone.focus();

    // The file picker cannot be observed from Playwright, but the event it
    // fires can: a native picker opens on click, and `filechooser` is the only
    // signal that the activation actually reached it.
    const chooser = page.waitForEvent("filechooser", { timeout: 3000 });
    await page.keyboard.press("Space");
    await expect(
      chooser,
      "Space did not activate a control that declares role=button"
    ).resolves.toBeTruthy();
  });

  test("Space does not also scroll the page", async ({ page }) => {
    await page.goto("/");
    // Enough content to make scrolling possible, or the assertion is vacuous.
    await page.setViewportSize({ width: 800, height: 400 });

    const dropzone = visible(page.getByRole("button", { name: /drag|drop|browse/i })).first();
    await dropzone.focus();
    const before = await page.evaluate(() => window.scrollY);
    await page.keyboard.press("Space");
    await page.waitForTimeout(300);

    expect(
      await page.evaluate(() => window.scrollY),
      "activating the dropzone with Space also jumped the page"
    ).toBe(before);
  });
});

test.describe("U22 — a drop that carried no file says so", () => {
  test("reports a fileless drop instead of swallowing it", async ({ page }) => {
    await page.goto("/");

    // A drop with items but no files — a dragged text selection, or a folder.
    await page.evaluate(() => {
      const zone = document.querySelector('[role="button"][tabindex="0"]') as HTMLElement;
      const dt = new DataTransfer();
      dt.setData("text/plain", "not a file");
      zone.dispatchEvent(new DragEvent("drop", { bubbles: true, cancelable: true, dataTransfer: dt }));
    });

    await expect(
      page.getByText(/carried no file/i).first(),
      "a drop with nothing usable in it vanished without a word"
    ).toBeVisible();
  });
});

test.describe("U21 — the dice tool counts in English", () => {
  test('says "1 more roll", not "1 more rolls"', async ({ page }) => {
    await page.goto("/");
    await visible(page.getByRole("tab", { name: "Tools" })).click();

    // A d6 needs 100 rolls for 256 bits, so 99 leaves exactly one.
    await visible(page.getByLabel(/rolls/i).first()).fill("99");

    await expect(page.getByText(/\b1 more rolls\b/)).toHaveCount(0);
    await expect(page.getByText(/\b1 more roll\b/).first()).toBeVisible();
  });
});

/**
 * `clipboard-read` and `clipboard-write` are not permission names Firefox or
 * WebKit recognise, so `grantPermissions` throws on them rather than being
 * ignored — the whole test dies before it reaches the page.
 *
 * Split rather than skipped. Everything except the clipboard *contents* is
 * engine-independent: whether the button exists at all, and whether it stays
 * disabled while the QR is hidden. Skipping the lot on two of three engines
 * would have surrendered that coverage to a permissions API detail, and the
 * disabled-until-revealed rule is the one with a security invariant behind it
 * (`getValue` must not run while the QR is hidden).
 */
test.describe("U28 — a SeedQR you can get off the screen without a camera", () => {
  test("offers Copy digits, disabled until the QR is revealed", async ({ page }) => {
    await page.goto("/");
    await useTextMode(page);
    await selectCrypto(page, "pbkdf2", "aes");

    const seed =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    await visible(page.getByPlaceholder("Enter text to encrypt")).fill(seed);
    await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG);
    await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();
    await page.waitForFunction(
      // Existence *and* content. `?.value !== ""` is true while the element is
      // still absent, so on its own it returns the instant the page loads.
      () => {
        const el = document.querySelector("#output-text") as HTMLTextAreaElement | null;
        return el !== null && el.value !== "";
      },
      null,
      { timeout: 90_000 }
    );
    const armored = await page.evaluate(
      () => (document.querySelector("#output-text") as HTMLTextAreaElement).value
    );

    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);
    await visible(page.getByPlaceholder("Enter text to decrypt")).fill(armored);
    await visible(page.getByPlaceholder("Enter decryption password")).fill(STRONG);
    await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();
    await expect(visible(page.locator("#output-text"))).toHaveValue(seed, { timeout: 90_000 });

    await visible(page.getByTitle(/Show SeedQR/i)).click();

    // Disabled before reveal, for the same reason Download is: it invokes
    // getValue, and the encoded secret must not be computed while hidden.
    const copy = visible(page.getByRole("button", { name: /^Copy digits$/ }));
    await expect(
      copy,
      "Copy digits computes the seed encoding, so it must not be live while the QR is hidden"
    ).toBeDisabled();

    await visible(page.getByRole("button", { name: /^Reveal QR$/ })).click();
    await expect(copy).toBeEnabled();
  });

  test("copies the digits themselves", async ({ page, context, browserName }) => {
    test.skip(
      browserName !== "chromium",
      "clipboard-read/write are not permission names Firefox or WebKit accept"
    );
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
    await page.goto("/");
    await useTextMode(page);
    await selectCrypto(page, "pbkdf2", "aes");

    const seed =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    await visible(page.getByPlaceholder("Enter text to encrypt")).fill(seed);
    await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG);
    await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();
    await page.waitForFunction(
      () => {
        const el = document.querySelector("#output-text") as HTMLTextAreaElement | null;
        return el !== null && el.value !== "";
      },
      null,
      { timeout: 90_000 }
    );
    const armored = await page.evaluate(
      () => (document.querySelector("#output-text") as HTMLTextAreaElement).value
    );

    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);
    await visible(page.getByPlaceholder("Enter text to decrypt")).fill(armored);
    await visible(page.getByPlaceholder("Enter decryption password")).fill(STRONG);
    await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();
    await expect(visible(page.locator("#output-text"))).toHaveValue(seed, { timeout: 90_000 });

    await visible(page.getByTitle(/Show SeedQR/i)).click();
    await visible(page.getByRole("button", { name: /^Reveal QR$/ })).click();
    await visible(page.getByRole("button", { name: /^Copy digits$/ })).click();

    // A Standard SeedQR is four digits per word — the whole point of copying
    // it rather than photographing a code.
    const clip = await page.evaluate(() => navigator.clipboard.readText());
    expect(clip, `clipboard held ${clip.length} chars`).toMatch(/^\d{48}$/);
  });
});

test.describe("U26 — the typography floor", () => {
  test("nothing renders below 12px", async ({ page }) => {
    await page.goto("/");

    // Computed, not grepped for a class name: a utility class is an intention,
    // and what a reader on a phone gets is the computed value.
    const tooSmall = await page.evaluate(() => {
      const out: string[] = [];
      for (const el of Array.from(document.body.querySelectorAll("*"))) {
        const text = (el.textContent ?? "").trim();
        if (!text || el.children.length > 0) continue;
        const size = parseFloat(getComputedStyle(el).fontSize);
        if (size > 0 && size < 12) out.push(`${size}px: ${text.slice(0, 40)}`);
      }
      return out;
    });

    expect(tooSmall, `text below the 12px floor: ${tooSmall.join(" | ")}`).toEqual([]);
  });
});

/**
 * U2b and U24 — the two findings that were enumerated as open and then not
 * fixed, which is a different failure from missing them.
 *
 * U2b is the one with teeth. The dice log is a tally of physical rolls someone
 * has actually performed; losing it to a tab switch means rolling again.
 */
test.describe("U2b — the dice log survives a tab switch", () => {
  test("a roll tally is still there after visiting another tab", async ({ page }) => {
    await page.goto("/");
    await visible(page.getByRole("tab", { name: "Tools" })).click();

    // Both pieces of state a user builds by rolling: the tally, and the
    // per-roll log behind the validator. The log is what the report names, and
    // it is opt-in, so it has to be opened before it can be typed into.
    await visible(page.getByLabel("Rolls completed")).fill("64");
    await visible(page.getByRole("button", { name: /Check a roll log/i })).click();

    const rolls = "4 6 2 3 1 5 5 2 6 4 3 1";
    await visible(page.locator("#roll-log")).fill(rolls);

    // The exact journey from the report: leave, come back.
    await visible(page.getByRole("tab", { name: "Encrypt" })).click();
    await expect(visible(page.getByPlaceholder("Enter a strong password"))).toBeVisible();
    await visible(page.getByRole("tab", { name: "Tools" })).click();

    await expect(
      visible(page.locator("#roll-log")),
      "the dice log was destroyed by a tab switch — those rolls have to be rolled again"
    ).toHaveValue(rolls);
    await expect(
      visible(page.getByLabel("Rolls completed")),
      "the roll tally was destroyed by a tab switch"
    ).toHaveValue("64");
  });

  /**
   * The price of forceMount, and the two tests that make sure it is not being
   * paid.
   *
   * The previous single test here selected `[role="tabpanel"][hidden]` and
   * counted focusable descendants. It could not fail. `forceMount` makes Radix
   * compute `hidden={!present}` with `present = forceMount || isSelected`, so
   * the Tools panel is never `[hidden]` unless we say so — which means the
   * selector skipped the only panel forceMount affects and landed on Decrypt,
   * which Radix unmounts and which therefore contains nothing. Zero focusables
   * found, assertion satisfied, nothing examined.
   *
   * So: select inactive panels, not hidden ones, and ask the two questions
   * separately, because the bug had two halves and only one of them is about
   * focus.
   */
  test("an inactive panel takes up no space on the page", async ({ page }) => {
    await page.goto("/");

    // The half that was visible to everyone and noticed by nobody: the Tools
    // panel rendered 566x820 in the document flow, directly under the Encrypt
    // button, dice calculator and all.
    const boxes = await page.evaluate(() =>
      Array.from(document.querySelectorAll('[role="tabpanel"][data-state="inactive"]')).map((p) => {
        const r = p.getBoundingClientRect();
        return { id: p.id, w: Math.round(r.width), h: Math.round(r.height) };
      })
    );

    expect(boxes.length, "no inactive panel to check — has the tab set changed?").toBeGreaterThan(0);
    expect(
      boxes.filter((b) => b.w > 0 || b.h > 0),
      "an unselected tab panel is being rendered into the page"
    ).toEqual([]);
  });

  test("an inactive panel stays out of the tab order", async ({ page }) => {
    await page.goto("/");

    // Asked by pressing Tab rather than by reading the DOM. A mounted panel's
    // controls still match every "focusable" selector while `display: none`
    // makes them unreachable, so counting matches would answer a question
    // nobody has — whether the elements exist, which they must, because the
    // dice tally lives in them. What matters is where focus can get to.
    await page.locator("body").click({ position: { x: 2, y: 2 } });

    const landed: string[] = [];
    for (let i = 0; i < 60; i++) {
      await page.keyboard.press("Tab");
      const inside = await page.evaluate(() => {
        const el = document.activeElement as HTMLElement | null;
        const panel = el?.closest('[role="tabpanel"][data-state="inactive"]');
        if (!panel) return null;
        return `${panel.id} -> ${el!.tagName}${el!.textContent ? ` "${el!.textContent.trim().slice(0, 30)}"` : ""}`;
      });
      if (inside) landed.push(inside);
    }

    expect(
      [...new Set(landed)],
      "Tab reached a control inside an unselected tab panel"
    ).toEqual([]);
  });
});

test.describe("U24 — the password ceiling is disclosed", () => {
  test("states the maximum, and states the one actually enforced", async ({ page }) => {
    await page.goto("/");

    await visible(page.getByRole("button", { name: "Password requirements" })).hover();
    // The number comes from the crypto core's own constant, so this fails if
    // the copy and the enforcement ever disagree.
    await expect(page.getByText(/Maximum 1,024 characters/i).first()).toBeVisible();
  });
});

/**
 * U15b — disabled and enabled are different objects, not the same one faded.
 *
 * The primary action used to carry `disabled:opacity-40`. On the filled
 * eggshell pill that composites to a mid grey block over the near-black
 * canvas — which reads as an ordinary button, so the single most important
 * control in the app announced itself in the treatment reserved for controls
 * you cannot use. A design review caught it from a screenshot; nothing in the
 * suite could, because opacity is not a colour and the palette gate reads
 * colours.
 *
 * So this asserts the property directly: the two states differ in *fill*, and
 * the disabled one is not merely a dimmed copy.
 */
test.describe("U15b — the disabled primary is not a faded enabled one", () => {
  test("fill, and element opacity, both say which state it is in", async ({ page }) => {
    await page.goto("/");
    await useTextMode(page);

    const encrypt = visible(page.getByRole("button", { name: /^Encrypt Text$/i }));
    await expect(encrypt, "the CTA should start disabled with no input").toBeDisabled();

    const disabledStyle = await encrypt.evaluate((el) => {
      const cs = getComputedStyle(el);
      return { background: cs.backgroundColor, opacity: cs.opacity, color: cs.color };
    });

    // Dimming the whole element is the defect this replaced. A disabled control
    // is drawn, not faded.
    expect(
      Number(disabledStyle.opacity),
      "the disabled control is dimmed rather than drawn — that is the treatment that made it read as an ordinary button"
    ).toBe(1);

    // Now make it available and compare the fills.
    await visible(page.getByPlaceholder("Enter text to encrypt")).fill("something to seal");
    await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
    await expect(encrypt).toBeEnabled();

    // Polled, not read once. The button carries `transition-colors`, so the
    // fill animates in and the instant `disabled` clears the computed value is
    // still the old one. Reading immediately raced that transition: chromium
    // and firefox had settled by then, webkit had not, and the test failed
    // claiming the two states paint the same background — which was true for a
    // few frames and false by the time anyone could see it.
    await expect
      .poll(async () => encrypt.evaluate((el) => getComputedStyle(el).backgroundColor), {
        timeout: 5_000,
        message: "enabled and disabled paint the same background, so the state is invisible",
      })
      .not.toBe(disabledStyle.background);

    const enabledStyle = await encrypt.evaluate((el) => {
      const cs = getComputedStyle(el);
      return { background: cs.backgroundColor, opacity: cs.opacity };
    });

    expect(
      Number(enabledStyle.opacity),
      "the available action is dimmed, which is the treatment reserved for the unavailable one"
    ).toBe(1);

    // The available action is the filled pill; the unavailable one is not
    // filled at all. Anything else and they differ only by degree.
    expect(
      disabledStyle.background,
      "the disabled control still carries a fill, so it still reads as a button you can press"
    ).toMatch(/rgba?\(0, 0, 0, 0\)|transparent/);
  });
});
