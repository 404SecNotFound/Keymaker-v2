import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { appPath } from "./helpers";

/**
 * Roadmap 6.3's gate.
 *
 * The item asks for "a browser test that reads the hash off the page and
 * checks it against the built SHA256SUMS", and gives the reason: *otherwise the
 * page becomes wrong on the first build that changes it, silently, and a stale
 * hash is worse than no hash.*
 *
 * The page states a commit rather than a manifest digest — a digest cannot be
 * put there honestly, for reasons set out in `src/app/verify/page.tsx` — so
 * this checks the value that *is* there against the build, which is the
 * staleness the gate exists to catch. Two further bindings come with it,
 * because a wrong command on this page is worse than a stale hash:
 *
 *  1. the commit matches what the build actually pinned itself to;
 *  2. the commands match `docs/VERIFYING.md` exactly, not approximately;
 *  3. the page does not claim to have verified anything.
 *
 * All three read the built artifact from disk rather than trusting the page,
 * which is the same posture the page asks its readers to take.
 */

const ROOT = join(process.cwd());
const OUT = join(ROOT, "out");

/** The URL the footer and the docs point at. Not `/verify` — see the page. */
const VERIFY_URL = appPath("/verify.html");

/** The one fenced bash block in the document containing `needle`. */
function docBlock(needle: string): string {
  const doc = readFileSync(join(ROOT, "docs", "VERIFYING.md"), "utf8");
  const blocks = [...doc.matchAll(/```bash\n([\s\S]*?)```/g)].map((m) => (m[1] ?? "").trimEnd());
  const found = blocks.filter((b) => b.includes(needle));
  const only = found.length === 1 ? found[0] : undefined;
  expect(
    only,
    `docs/VERIFYING.md should hold exactly one bash block containing ${JSON.stringify(needle)}, found ${found.length}`
  ).toBeDefined();
  return only as string;
}

test.describe("verify this build", () => {
  test("states the commit the build was actually pinned to", async ({ page }) => {
    await page.goto(VERIFY_URL);

    const shown = (await page.getByTestId("verify-commit").innerText()).trim();

    // The comparison is against the *landing* page, which this feature does
    // not author. Next embeds the build id it was given by `generateBuildId`
    // into every page's router payload as "b"; the verify page gets the same
    // value by a different route, injected as KEYMAKER_COMMIT in
    // next.config.js. Two independent paths out of one `resolveBuildId()`, so
    // a hardcoded or stale literal on the page disagrees with the build and
    // this fails — which is the staleness the gate is for.
    const landing = readFileSync(join(OUT, "index.html"), "utf8").replace(/\\"/g, '"');
    const embedded = [...landing.matchAll(/"b":"([0-9a-zA-Z_.-]{8,})"/g)].map((m) => m[1]);

    expect(
      embedded.length,
      "no build id in the landing page's router payload — this test cannot check anything"
    ).toBeGreaterThan(0);
    expect(
      new Set(embedded).size,
      `the build emitted more than one build id: ${[...new Set(embedded)].join(", ")}`
    ).toBe(1);

    expect(shown, "the commit on the page is not the one the build pinned itself to").toBe(
      embedded[0]
    );
  });

  test("the app version on the page matches package.json", async ({ page }) => {
    await page.goto(VERIFY_URL);
    const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
    await expect(page.getByTestId("verify-app-version")).toHaveText(pkg.version);
  });

  test("prints the document's commands, not a retyped copy of them", async ({ page }) => {
    await page.goto(VERIFY_URL);
    const body = await page.evaluate(() => document.body.innerText);

    // Byte-for-byte, both of them. The flags are the load-bearing part:
    // `cosign verify-blob` without --certificate-identity accepts a signature
    // from anybody and prints "Verified OK", and a page that had quietly lost
    // that flag would be handing every reader a check that passes on a forgery.
    for (const needle of ["cosign verify-blob", "sha256sum -c SHA256SUMS"]) {
      const expected = docBlock(needle);
      expect(
        body.includes(expected),
        `the page's ${needle} block has drifted from docs/VERIFYING.md.\n\nDocument:\n${expected}`
      ).toBe(true);
    }

    // The identity is the deployment's, because the running site *is* the
    // deployment. A release's tag identity here would fail for every visitor.
    expect(body).toContain("deploy.yml@refs/heads/main");
  });

  test("does not claim to have verified itself", async ({ page }) => {
    await page.goto(VERIFY_URL);
    const body = await page.evaluate(() => document.body.innerText);

    // KM-02 was a meter that certified a password it had not earned the right
    // to certify. The same overstatement here would be worse: a page that
    // announces "verified" asserts precisely the thing a tampered copy would
    // also assert, and it would be believed, because it is the page people
    // open in order to stop guessing.
    //
    // The wording blocklist is a heuristic and only catches the obvious
    // regression — someone adding a reassuring banner. The load-bearing checks
    // are the positive ones below: the disclaimers have to be present and
    // visible, which is the thing that actually makes the page honest.
    const selfCertifying = [
      /this (page|build|bundle|site) (is|has been) (verified|authentic|genuine)/i,
      /(integrity|signature) (confirmed|verified|valid)\b/i,
      /[✓✔]\s*verified/i,
      /verification (passed|succeeded|complete)/i,
    ];
    for (const pattern of selfCertifying) {
      expect(
        pattern.test(body),
        `the verify page asserted its own integrity (${pattern}) — it cannot, and saying so is the KM-02 failure`
      ).toBe(false);
    }

    // What it must say instead.
    await expect(page.getByRole("heading", { name: /What none of this proves/i })).toBeVisible();
    await expect(page.getByText(/do not take the page/i)).toBeVisible();
    await expect(page.getByText(/This page will not tell you it has verified itself/i)).toBeVisible();
  });

  test("is reachable from the app's footer", async ({ page }) => {
    await page.goto("/");
    const link = page.getByRole("link", { name: /Verify this build/i }).first();
    await expect(link).toBeVisible();

    // The href has to actually resolve. A bare /verify does not: the export
    // puts a router-payload directory there with no index.html, so the link
    // would 404 while looking perfectly reasonable in the markup.
    await link.click();
    await expect(page.getByRole("heading", { name: "Verify this build", level: 1 })).toBeVisible();
  });

  test("keeps the zero-egress policy the rest of the app has", async ({ page }) => {
    await page.goto(VERIFY_URL);
    const csp = await page.evaluate(
      () =>
        document
          .querySelector('meta[http-equiv="Content-Security-Policy"]')
          ?.getAttribute("content") ?? ""
    );

    // The page was designed around this rather than relaxing it: showing a
    // live manifest digest would have needed connect-src 'self', and KM-07 was
    // raised to get this directive to 'none'. If a later change loosens it
    // here, the app has quietly lost the property on one route.
    expect(csp, "no CSP meta tag on the verify page").not.toBe("");
    expect(csp).toContain("connect-src 'none'");
    expect(csp).toContain("default-src 'none'");
  });
});
