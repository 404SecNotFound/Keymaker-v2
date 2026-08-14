import { test, expect } from "@playwright/test";
import { visible } from "./helpers";

/**
 * The dice tool has exactly one output — a number the user is asked to trust
 * when deciding whether they have rolled enough entropy for a wallet seed.
 * Every bug worth testing for here is the same bug: the tool reporting more
 * bits than the user actually has.
 *
 * Both cases below shipped. Both were found by looking at the live site.
 */

/** Open the Tools tab, where the calculator lives. */
async function openDiceTool(page: import("@playwright/test").Page) {
  await page.goto("/");
  await visible(page.getByRole("tab", { name: "Tools" })).click();
  await expect(visible(page.getByLabel("Dice sides"))).toBeVisible();
}

/**
 * Clearing the die size yielded Number("") === 0, which was silently replaced
 * with 6 — so the tool displayed an entropy figure for a six-sided die the user
 * had never specified.
 */
test("refuses to compute entropy for a die that was not specified", async ({ page }) => {
  await openDiceTool(page);

  const sides = visible(page.getByLabel("Dice sides"));
  await sides.fill("");

  await expect(
    page.getByText(/Enter the number of sides on your die/i),
    "clearing the die size must say so instead of assuming a d6"
  ).toBeVisible();
  await expect(sides).toHaveAttribute("aria-invalid", "true");

  // Bits per roll must not be log2(6) = 2.58 for a die that does not exist.
  const body = (await page.locator("body").textContent()) ?? "";
  expect(body, "entropy was computed for an unspecified die").not.toContain("2.58");

  // A real die brings the numbers back.
  await sides.fill("6");
  await expect(sides).toHaveAttribute("aria-invalid", "false");
  await expect(page.getByText(/Enter the number of sides on your die/i)).toHaveCount(0);
});

/**
 * "Rolls completed" took a *count*; pasting the roll *values* into it — the two
 * fields sit next to each other, so this is an easy mistake — was read as
 * 1.25e+25 rolls. Number.isInteger is true for that, so it passed validation,
 * and the tool announced "256-bit target reached" over 3.2e+25 bits.
 *
 * The width of the number also blew the results grid apart, which is how it was
 * noticed. Both symptoms are asserted here: they are one bug, and a fix for the
 * arithmetic that left the layout fragile would be half a fix.
 */
test("rejects a pasted roll sequence in the count field", async ({ page }) => {
  // Narrow enough to be the two-column layout where the overlap appeared.
  await page.setViewportSize({ width: 390, height: 900 });
  await openDiceTool(page);

  const count = visible(page.getByLabel("Rolls completed"));
  await count.fill("12522333322222222443333333");

  await expect(count, "a pasted face sequence must be marked invalid").toHaveAttribute(
    "aria-invalid",
    "true"
  );
  await expect(
    page.getByText(/looks like the faces you rolled/i),
    "the message should name the actual mistake, not just say 'invalid'"
  ).toBeVisible();

  // The claim that matters: nothing was counted from it.
  await expect(
    page.getByText("256-bit target reached"),
    "26 dice faces were read as 1.25e+25 rolls and certified as full entropy"
  ).toHaveCount(0);
  await expect(page.getByText("0.0 bits", { exact: true })).toBeVisible();

  // And the results grid still fits. A grid track's min-width defaults to auto,
  // so an unbounded number pushes its neighbour out of column rather than
  // wrapping — "Total entropy" ran straight into "Rolls needed".
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth
  );
  expect(overflow, "the page scrolls sideways on a phone-width viewport").toBeLessThanOrEqual(1);

  const cells = page.locator("p", { hasText: /^Total entropy$/ });
  await expect(cells.first()).toBeVisible();
});

/** Rejecting bad input is only half of it; the good input must still work. */
test("a real roll count still computes", async ({ page }) => {
  await openDiceTool(page);

  const count = visible(page.getByLabel("Rolls completed"));

  // 100 rolls of a d6 = 258.5 bits, just over the 256-bit target.
  await count.fill("100");
  await expect(count).toHaveAttribute("aria-invalid", "false");
  await expect(page.getByText("258.5 bits", { exact: true })).toBeVisible();
  await expect(page.getByText("256-bit target reached")).toBeVisible();

  // 99 is one short, and the tool should say so rather than round up to a pass.
  await count.fill("99");
  await expect(page.getByText("255.9 bits", { exact: true })).toBeVisible();
  await expect(page.getByText("256-bit target reached")).toHaveCount(0);
});

/**
 * A count above the bound is a different mistake from a pasted sequence — the
 * user meant a number, it is just not one a human rolled — so it gets the plain
 * message rather than the "those are your faces" one.
 */
test("rejects a roll count beyond what a human could have rolled", async ({ page }) => {
  await openDiceTool(page);

  const count = visible(page.getByLabel("Rolls completed"));
  await count.fill("900000000");

  await expect(count).toHaveAttribute("aria-invalid", "true");
  await expect(page.getByText(/whole number of rolls between 1 and 10,000/i)).toBeVisible();
  await expect(page.getByText("0.0 bits", { exact: true })).toBeVisible();
  await expect(page.getByText("256-bit target reached")).toHaveCount(0);
});
