import { test, expect } from "@playwright/test";
import { visible, useTextMode } from "./helpers";

/**
 * UAT-2026-08-14, the accessibility second pass: U5, U8, U13, U17, U18.
 *
 * 2.7 was a real pass and it closed what axe can see. These are what it cannot,
 * which is the lesson 2.7 recorded about itself — a red border produces zero
 * axe violations, and so does a control that is invisible but still focusable.
 *
 * Every test here was run against the unfixed tree first; control results are
 * in the PR body.
 */

const STRONG = "correct-horse-battery-staple-9271!X";

test.describe("U5 — a collapsed panel is out of the tab order", () => {
  test("the Advanced controls are unreachable until it is opened", async ({ page }) => {
    await page.goto("/");

    const advanced = visible(page.getByRole("button", { name: /^Advanced/ }));
    await expect(advanced).toHaveAttribute("aria-expanded", "false");

    // The panel is clipped by grid-template-rows: 0fr, which hides it visually
    // and does nothing at all to focus. Counting focusable descendants is the
    // measure that matches what a keyboard user experiences.
    const reachable = async () =>
      page.evaluate(() => {
        const advancedButton = Array.from(document.querySelectorAll("button")).find((b) =>
          /^Advanced/.test(b.textContent ?? "")
        );
        // The animated wrapper is the sibling of the toggle.
        const panel = advancedButton?.parentElement?.querySelector(".min-h-0");
        if (!panel) return -1;
        const sel = "button, [href], input, select, textarea, [tabindex]:not([tabindex='-1'])";
        return Array.from(panel.querySelectorAll(sel)).filter((el) => {
          // `inert` is inherited, so asking the element itself is not enough.
          return !(el as HTMLElement).closest("[inert]");
        }).length;
      });

    expect(
      await reachable(),
      "controls inside the collapsed panel are still in the tab order"
    ).toBe(0);

    await advanced.click();
    await expect(advanced).toHaveAttribute("aria-expanded", "true");
    expect(
      await reachable(),
      "opening the panel did not return its controls to the tab order"
    ).toBeGreaterThan(5);
  });
});

test.describe("U8 — touch targets", () => {
  test("every interactive control clears 24x24 at a phone width", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto("/");

    // 24x24 is WCAG 2.2 AA (2.5.8). The 44x44 of 2.5.5 is AAA and would mean
    // redesigning the footer and the sliders, so this pins the level the
    // report cited rather than the one that sounds most impressive.
    const undersized = await page.evaluate(() => {
      const out: string[] = [];
      const sel =
        'button, a[href], input[type="range"], [role="button"], [role="tab"], summary';

      /**
       * 2.5.8's *inline* exception: "the target is in a sentence, or its size
       * is otherwise constrained by the line-height of non-target text."
       *
       * This is not a loophole to make the test pass — padding a link that sits
       * mid-sentence pushes the surrounding words around and makes the prose
       * worse for everybody, which is precisely why the exception exists. Two
       * links here qualify: "Open source" in the hero paragraph and "IttyBitz"
       * in the fork credit.
       *
       * The test still measures them; it just does not fail on them, and the
       * condition is narrow — inline display *and* a parent that holds text of
       * its own besides the link.
       */
      const inlineInSentence = (el: Element): boolean => {
        if (!getComputedStyle(el).display.startsWith("inline")) return false;
        const parent = el.parentElement;
        if (!parent) return false;
        const own = Array.from(parent.childNodes)
          .filter((n) => n.nodeType === Node.TEXT_NODE)
          .map((n) => n.textContent ?? "")
          .join("")
          .trim();
        return own.length > 0;
      };

      for (const el of Array.from(document.querySelectorAll(sel))) {
        if ((el as HTMLElement).closest("[inert]")) continue;
        if (inlineInSentence(el)) continue;
        const r = el.getBoundingClientRect();
        if (r.width === 0 || r.height === 0) continue;
        if (r.width < 24 || r.height < 24) {
          const label = (
            el.getAttribute("aria-label") ||
            el.textContent ||
            el.tagName
          )
            .trim()
            .slice(0, 32);
          out.push(`${Math.round(r.width)}x${Math.round(r.height)} ${el.tagName.toLowerCase()} "${label}"`);
        }
      }
      return out;
    });

    expect(undersized, `under 24x24: ${undersized.join(" | ")}`).toEqual([]);
  });
});

test.describe("U17 — prefers-reduced-motion", () => {
  test("animation and transition durations collapse when reduce is set", async ({ browser }) => {
    const context = await browser.newContext({ reducedMotion: "reduce" });
    const page = await context.newPage();
    await page.goto("/");

    const moving = await page.evaluate(() => {
      const out: string[] = [];
      for (const el of Array.from(document.body.querySelectorAll("*"))) {
        const s = getComputedStyle(el);
        const parse = (v: string) =>
          Math.max(...v.split(",").map((x) => parseFloat(x) * (x.includes("ms") ? 1 : 1000) || 0));
        // Anything still running for a perceptible time is what the preference
        // asked to be rid of. 1ms is the near-zero the stylesheet sets.
        if (parse(s.animationDuration) > 1 || parse(s.transitionDuration) > 1) {
          out.push(`${el.tagName.toLowerCase()}.${(el.className || "").toString().slice(0, 24)}`);
        }
      }
      return out;
    });

    expect(moving.length, `still animating under reduce: ${moving.slice(0, 6).join(" | ")}`).toBe(0);
    await context.close();
  });

  test("motion is untouched when the user has not asked to reduce it", async ({ browser }) => {
    // The other half of the control: a global !important rule is easy to get
    // wrong in the direction of killing animation for everybody.
    const context = await browser.newContext({ reducedMotion: "no-preference" });
    const page = await context.newPage();
    await page.goto("/");

    const animated = await page.evaluate(() => {
      let n = 0;
      for (const el of Array.from(document.body.querySelectorAll("*"))) {
        const s = getComputedStyle(el);
        if (parseFloat(s.transitionDuration) > 0 || parseFloat(s.animationDuration) > 0) n++;
      }
      return n;
    });

    expect(animated, "the reduce rule leaked into the default case").toBeGreaterThan(0);
    await context.close();
  });
});

test.describe("U18 — heading order and dead tab stops", () => {
  test("headings descend without skipping a level", async ({ page }) => {
    await page.goto("/");

    const levels = await page.evaluate(() =>
      Array.from(document.querySelectorAll("h1, h2, h3, h4, h5, h6")).map((h) =>
        Number(h.tagName[1])
      )
    );

    expect(levels[0], "the page does not start at h1").toBe(1);
    for (let i = 1; i < levels.length; i++) {
      expect(
        (levels[i] as number) - (levels[i - 1] as number),
        `heading jumped h${levels[i - 1]} -> h${levels[i]}`
      ).toBeLessThanOrEqual(1);
    }
  });

  test("the tab panel is not a tab stop of its own", async ({ page }) => {
    await page.goto("/");

    const panels = await page.evaluate(() =>
      Array.from(document.querySelectorAll('[role="tabpanel"]')).map((el) =>
        el.getAttribute("tabindex")
      )
    );

    expect(panels.length).toBeGreaterThan(0);
    expect(
      panels.every((t) => t === "-1"),
      `tabpanel tabindex values: ${panels.join(", ")} — a panel with tabindex=0 is a stop that shows no focus ring and does nothing`
    ).toBe(true);
  });
});

test.describe("U13 — a failed attempt keeps the password", () => {
  test("survives a wrong password, and clears on success", async ({ page }) => {
    await page.goto("/");
    await useTextMode(page);

    // Encrypt something first, so there is a real container to fail against.
    await visible(page.getByPlaceholder("Enter text to encrypt")).fill("a small secret");
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

    const password = visible(page.getByPlaceholder("Enter decryption password"));
    const wrong = "correct-horse-battery-staple-9271!Y";
    await password.fill(wrong);
    await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();

    await expect(page.getByText(/Decryption failed/i).first()).toBeVisible({ timeout: 90_000 });
    await expect(
      password,
      "a single typo wiped the whole password and forced a full retype"
    ).toHaveValue(wrong);

    // ...and success still clears it. That half is the security property and
    // must not be lost while fixing the friction.
    await password.fill(STRONG);
    await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();
    await expect(visible(page.locator("#output-text"))).toHaveValue("a small secret", {
      timeout: 90_000,
    });
    await expect(
      password,
      "the password was left on screen after a successful decrypt"
    ).toHaveValue("");
  });
});
