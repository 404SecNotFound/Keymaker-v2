import { test, expect, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { visible, useTextMode } from "./helpers";

/**
 * Accessibility, in two halves — because the automated half is the smaller one.
 *
 * `axe` catches the mechanical failures: a button with no accessible name, a
 * control with no label, contrast below threshold. Those are real and worth a
 * gate. What it cannot see is whether a *meaning* is reachable — and the defect
 * that prompted this work was exactly that kind: the recovery-phrase check
 * spoke only in colour, so the warning that a word had been mistyped was
 * invisible to roughly one man in twelve and silent to every screen reader.
 * axe reports zero violations for a red border.
 *
 * So the second describe block asserts the meaning directly.
 */

/** Scan whatever is currently on screen for WCAG 2.1 A/AA violations. */
async function scan(page: Page) {
  return new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
}

/** axe's own summary is unreadable in CI output; this names the offenders. */
function describeViolations(results: Awaited<ReturnType<typeof scan>>) {
  return results.violations
    .map(
      (v) =>
        `[${v.impact}] ${v.id} — ${v.help}\n` +
        v.nodes.map((n) => `      ${n.target.join(" ")}`).join("\n")
    )
    .join("\n");
}

test.describe("axe", () => {
  // Chromium only, deliberately. axe analyses the rendered DOM and the
  // accessibility tree — a missing label or an unnamed button is the same
  // finding in every engine, so running it three times buys nothing. What it
  // would buy is flake: axe's colour-contrast rule resolves computed colours
  // itself, and engines disagree at the last decimal. The behavioural tests
  // below do run everywhere, because those are where engines actually differ.
  test.skip(({ browserName }) => browserName !== "chromium", "axe analyses the DOM; one engine is enough");

  // Every panel mounts different controls, so a single scan of the landing
  // view would miss most of the app. Advanced in particular is where the
  // security-relevant settings live.
  const views: Array<[string, (page: Page) => Promise<void>]> = [
    ["encrypt", async () => {}],
    [
      // The sealed status opened: a disclosure button, three rows, a control.
      "encrypt with the sealed status open",
      async (page) => {
        await page.getByTestId("sealed-toggle").click();
        await expect(page.getByTestId("sealed-panel")).toBeVisible();
      },
    ],
    [
      "encrypt with Advanced open",
      async (page) => {
        await visible(page.getByRole("button", { name: /^Advanced/ })).click();
      },
    ],
    [
      "encrypt in text mode",
      async (page) => {
        await useTextMode(page);
      },
    ],
    [
      // With a word flagged and a completion list open: the combobox wiring,
      // the live status and the danger wash are the parts axe can judge.
      "encrypt in seed mode",
      async (page) => {
        await visible(page.getByRole("button", { name: "Seed phrase", exact: true })).click();
        const words = "legal winner thank year wave sausage wotrh useful legal winner thank yellow".split(" ");
        for (const [i, w] of words.entries()) {
          await visible(page.getByRole("combobox", { name: `Word ${i + 1}`, exact: true })).fill(w);
        }
        await visible(page.getByRole("combobox", { name: "Word 12", exact: true })).fill("ye");
        await expect(page.getByRole("listbox", { name: "Completions for word 12" })).toBeVisible();
      },
    ],
    [
      "decrypt",
      async (page) => {
        await visible(page.getByRole("tab", { name: "Decrypt" })).click();
      },
    ],
    [
      "tools",
      async (page) => {
        await visible(page.getByRole("tab", { name: "Tools" })).click();
      },
    ],
    [
      "recovery kit dialog",
      async (page) => {
        await visible(page.getByRole("button", { name: /Recovery kit/i })).click();
      },
    ],
    [
      // The one-time shares dialog with the rehearsal open: a labelled
      // textarea, a live count, and a disclosure button, all inside a modal.
      "shares dialog with the rehearsal open",
      async (page) => {
        await useTextMode(page);
        const advanced = visible(page.getByRole("button", { name: /^Advanced/ }));
        await advanced.click();
        await visible(page.getByRole("button").filter({ hasText: "PBKDF2" })).click();
        const sharesSwitch = visible(page.getByRole("switch", { name: "Recovery shares" }));
        await expect(async () => {
          if ((await sharesSwitch.getAttribute("aria-checked")) !== "true") await sharesSwitch.click();
          await expect(sharesSwitch).toHaveAttribute("aria-checked", "true", { timeout: 1_000 });
        }).toPass({ timeout: 20_000 });
        await visible(page.getByPlaceholder("Enter text to encrypt")).fill("for the scan");
        await visible(page.getByPlaceholder("Enter a strong password")).fill(
          "correct-horse-battery-staple-9271!X"
        );
        await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();
        const dialog = page.getByRole("dialog");
        await expect(dialog.getByText(/Save these 3 shares now/)).toBeVisible({ timeout: 90_000 });
        await dialog.getByRole("button", { name: /Rehearse now/ }).click();
        await expect(dialog.getByLabel("Strips to rehearse with")).toBeVisible();
      },
    ],
  ];

  for (const [name, setup] of views) {
    test(`no WCAG 2.1 A/AA violations: ${name}`, async ({ page }) => {
      await page.goto("/");
      await setup(page);

      const results = await scan(page);
      expect(results.violations.length, `\n${describeViolations(results)}\n`).toBe(0);
    });
  }
});

test.describe("information that must not be carried by colour alone", () => {
  /**
   * The encrypt-side check runs before the phrase is sealed into a backup, so
   * it is the last chance to catch a typo. It shipped as a border tint and
   * nothing else.
   */
  test("a mistyped recovery phrase says so in words, not just in red", async ({ page }) => {
    await page.goto("/");
    await useTextMode(page);

    const field = visible(page.getByPlaceholder("Enter text to encrypt"));

    // 11 valid BIP-39 words plus one that is not on the list: phrase-shaped,
    // so the checker engages, but invalid.
    await field.fill(
      "abandon ability able about above absent absorb abstract absurd abuse access zzzznotaword"
    );

    await expect(page.getByText(/A word isn't recognised/i)).toBeVisible();
    await expect(field).toHaveAttribute("aria-invalid", "true");

    // Wired to the field, not floating loose where a screen reader user would
    // have to hunt for it.
    const describedBy = await field.getAttribute("aria-describedby");
    expect(describedBy, "the status is not attached to the field").toContain(
      "text-secret-seed-status"
    );

    // A genuine phrase flips it, and the wording changes with it — if both
    // states said the same thing the text would be decoration.
    await field.fill(
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    );
    await expect(page.getByText(/All words recognised/i)).toBeVisible();
    await expect(page.getByText(/A word isn't recognised/i)).toHaveCount(0);
    await expect(field).toHaveAttribute("aria-invalid", "false");
  });

  test("ordinary text gets no verdict at all", async ({ page }) => {
    await page.goto("/");
    await useTextMode(page);

    await visible(page.getByPlaceholder("Enter text to encrypt")).fill(
      "just a note to myself, nothing to do with wallets"
    );

    // The indicator only appears for phrase-shaped input. That is what keeps
    // it from announcing "this is a seed phrase" about arbitrary text — and it
    // is why adding an icon leaks nothing the coloured border did not.
    await expect(page.getByText(/All words recognised/i)).toHaveCount(0);
    await expect(page.getByText(/A word isn't recognised/i)).toHaveCount(0);
  });

  /**
   * The ⓘ buttons explain the key file, the password policy and filename
   * privacy. They were icon-only with no name, so a screen reader announced
   * three anonymous "button"s among the security settings.
   */
  test("every icon-only control has a name and a visible focus ring", async ({
    page,
    browserName,
  }) => {
    // The ring itself is CSS and identical everywhere; reaching it by Tab is
    // not. WebKit does not put keyboard focus on buttons by default — that is
    // a platform setting on Safari, not something this page controls — so the
    // Tab traversal below cannot run there. The names are still asserted in
    // every engine by the axe scan's button-name rule.
    test.skip(browserName === "webkit", "WebKit does not Tab to buttons by default");
    await page.goto("/");
    await visible(page.getByRole("button", { name: /^Advanced/ })).click();

    for (const label of [
      "What is a key file?",
      "Password requirements",
      "What does obscuring the filename do?",
    ]) {
      const tip = visible(page.getByRole("button", { name: label }));
      await expect(tip, `no button named "${label}"`).toBeVisible();

      // focus:outline-hidden used to strip the ring and put nothing back, so a
      // keyboard user lost their place entirely.
      //
      // Reached by actual Tab, not element.focus(): Chromium does not match
      // :focus-visible on programmatic focus, so a .focus() call reports no
      // ring on a button that rings perfectly well for a real keyboard user.
      // The class list is not checked either — what matters is what the
      // browser computes.
      await tip.focus();
      await page.keyboard.press("Shift+Tab");
      await page.keyboard.press("Tab");
      // transition-colors animates outline-color, so an immediate read catches
      // it partway between currentColor and the accent.
      await page.waitForTimeout(400);

      const ring = await tip.evaluate((el) => {
        const cs = getComputedStyle(el);
        return {
          focusVisible: el.matches(":focus-visible"),
          style: cs.outlineStyle,
          width: parseFloat(cs.outlineWidth) || 0,
          color: cs.outlineColor,
        };
      });
      expect(ring.focusVisible, `"${label}" did not receive keyboard focus`).toBe(true);
      expect(
        ring.style !== "none" && ring.width > 0,
        `"${label}" has no visible focus indicator (${ring.style} ${ring.width}px)`
      ).toBe(true);
      // A deliberate ring colour, not the inherited muted text colour it would
      // fall back to if the outline utility silently failed to apply. Resolved
      // from the live focus token rather than a hex literal: the literal broke
      // the day the palette changed, while what this test actually protects —
      // "the ring is painted on purpose" — did not change at all.
      //
      // That token is --ring. It was --accent until Nightpaper retired the
      // accent colour outright; the focus ring is now ink and is specified to
      // never be a spark. The assertion is the same one, pointed at the token
      // that currently means "the colour focus is painted in".
      const ringToken = await page.evaluate(() => {
        const probe = document.createElement("span");
        probe.style.color = "hsl(var(--ring))";
        document.body.appendChild(probe);
        const rgb = getComputedStyle(probe).color;
        probe.remove();
        return rgb;
      });
      expect(ring.color, `"${label}" ring is not the focus colour`).toBe(ringToken);
    }
  });
});
