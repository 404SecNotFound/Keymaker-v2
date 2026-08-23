import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { visible, useTextMode, selectCrypto, STRONG_PASSWORD } from "./helpers";

/**
 * Roadmap 4.3 — the self-extracting page (`docs/FORMAT-V2-DESIGN.md` §7.2).
 *
 * The claim this file exists to test is not "the export button works". It is
 * **a browser with nothing else available can open this file**, which is a
 * claim about an artefact detached from the app that made it. So the page is
 * downloaded, written to disk, and then loaded in a fresh context over
 * `file://` with the dev server irrelevant — because that is the situation the
 * feature is for, and a page tested while still served by the app would prove
 * nothing about the one sitting in a drawer.
 *
 * `reference/crosstest2.py` owns the other half: that `keym2.py` extracts and
 * decrypts the same artefact. Between them the page is checked by two readers
 * that share no code with it.
 */

const SECRET = "Estate note — the wallet seed is in the safe, and the safe code is 4471-0092.";

/** Encrypt in text mode with an explicit KDF and cipher, and wait for v2 armor. */
async function encryptWith(page: Page, kdf: "pbkdf2" | "argon2id") {
  await page.goto("/");
  await useTextMode(page);
  await selectCrypto(page, kdf, "aes");
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

test.describe("§7.2 self-extracting page", () => {
  test("the exported page pins its own script by hash", async ({ page, context }, testInfo) => {
    // The page carries `script-src 'sha256-…'` for the one script it contains,
    // which means a stale constant does not degrade the policy — it kills the
    // page. The browser refuses the only script on it, the heir gets a
    // document that renders and cannot decrypt, and nothing says why.
    //
    // The test above catches that too, by failing to decrypt. This one exists
    // so the failure names the cause instead of looking like a broken
    // decryptor, because the person who next edits DECRYPTOR_JS is the person
    // who needs to be told exactly which constant to update.
    await encryptWith(page, "pbkdf2");
    const control = visible(page.getByTestId("selfextract-download"));
    const [download] = await Promise.all([page.waitForEvent("download"), control.click()]);
    const saved = testInfo.outputPath("hash-check.html");
    await download.saveAs(saved);
    const html = readFileSync(saved, "utf8");

    const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
    expect(scripts.length, "the page should contain exactly one inline script").toBe(1);

    const actual = "sha256-" + createHash("sha256").update(scripts[0]![1]!, "utf8").digest("base64");
    const csp = html.match(/http-equiv="Content-Security-Policy" content="([^"]*)"/)?.[1] ?? "";

    expect(csp, "the exported page carries no CSP").not.toBe("");
    expect(
      csp,
      `SELF_EXTRACT_SCRIPT_SHA256 is stale — DECRYPTOR_JS now hashes to ${actual}. ` +
        "Update the constant in src/lib/keym-v2-selfextract.ts or the exported page cannot run its own script."
    ).toContain(actual);

    // The directives that make the policy worth carrying, not just present.
    expect(csp, "the page can still reach the network").toContain("connect-src 'none'");
    expect(csp, "the page has no default deny").toContain("default-src 'none'");
    expect(csp, "the script is not pinned, so any inline script would run").not.toContain(
      "script-src 'unsafe-inline'"
    );
  });

  test("a PBKDF2/AES backup exports a page that opens itself offline", async ({
    page,
    context,
  }, testInfo) => {
    await encryptWith(page, "pbkdf2");

    const control = visible(page.getByTestId("selfextract-download"));
    await expect(control).toBeVisible();

    const [download] = await Promise.all([page.waitForEvent("download"), control.click()]);
    const saved = testInfo.outputPath("keymaker-backup.html");
    await download.saveAs(saved);
    expect(download.suggestedFilename()).toBe("keymaker-backup.html");

    // A second page, over file://, with every network request recorded. The
    // artefact's whole promise is that it needs nothing else, so anything it
    // reaches for is a defect rather than a slow path.
    const offline = await context.newPage();
    const offOrigin: string[] = [];
    offline.on("request", (r) => {
      if (!r.url().startsWith("file://")) offOrigin.push(r.url());
    });
    const pageErrors: string[] = [];
    offline.on("pageerror", (e) => pageErrors.push(e.message));

    await offline.goto(`file://${saved}`);
    await offline.fill("#pw", STRONG_PASSWORD);
    await offline.click("#go");
    await offline.waitForSelector("#result:not([hidden])", { timeout: 90_000 });

    expect(await offline.inputValue("#out")).toBe(SECRET);
    expect(pageErrors).toEqual([]);
    expect(offOrigin).toEqual([]);

    // §6: one message for every rejection. The page must not become the one
    // reader in this project that tells an attacker which check failed.
    await offline.fill("#pw", "not the password");
    await offline.click("#go");
    await offline.waitForFunction(
      () => document.querySelector("#status")?.className === "bad",
      null,
      { timeout: 90_000 }
    );
    const refusal = (await offline.textContent("#status")) ?? "";
    expect(refusal).toMatch(/password is wrong or this file is damaged/i);
    expect(refusal).not.toMatch(/slot|chunk|tag|header|nonce/i);

    // The armor is *text* in the document, which is what makes the file
    // survive its own JavaScript failing. Read with script disabled entirely.
    const noScript = await context.browser()!.newContext({ javaScriptEnabled: false });
    const inert = await noScript.newPage();
    await inert.goto(`file://${saved}`);
    const armor = ((await inert.textContent("#keym2-container")) ?? "").replace(/\s+/g, "");
    expect(armor.startsWith("keym2:")).toBe(true);
    expect(armor.length).toBeGreaterThan(100);
    await noScript.close();

    await offline.close();
  });

  test("an Argon2id backup is refused, and says what would have to change", async ({ page }) => {
    await encryptWith(page, "argon2id");

    await expect(visible(page.getByTestId("selfextract-download"))).toHaveCount(0);
    const notice = visible(page.getByTestId("selfextract-unavailable"));
    await expect(notice).toBeVisible();
    // Naming the reason is the point — a disabled control with no explanation
    // would send someone to look for a bug that is a deliberate limit.
    await expect(notice).toContainText(/Argon2id/i);
    await expect(notice).toContainText(/WebAssembly/i);
    // And the trade is stated in both directions, per "Honest framing to
    // preserve": easier to open later, weaker against a copy taken today.
    await expect(notice).toContainText(/weaker/i);
  });

  test("a page pasted into the decrypt box is unwrapped, not rejected", async ({
    page,
  }, testInfo) => {
    await encryptWith(page, "pbkdf2");
    const [download] = await Promise.all([
      page.waitForEvent("download"),
      visible(page.getByTestId("selfextract-download")).click(),
    ]);
    const saved = testInfo.outputPath("pasted.html");
    await download.saveAs(saved);
    const html = await (await import("node:fs/promises")).readFile(saved, "utf8");

    // §7.2: a reader that recognises the sentinels MUST extract and proceed.
    // Someone reassembling an inheritance should not have to know that the
    // bytes they need are buried in the page they were left.
    await page.goto("/");
    await visible(page.getByRole("tab", { name: "Decrypt" })).click();
    await useTextMode(page);
    await visible(page.getByPlaceholder("Enter text to decrypt")).fill(html);

    await page.waitForFunction(
      () => {
        const els = Array.from(
          document.querySelectorAll("textarea")
        ) as HTMLTextAreaElement[];
        return els.some((e) => e.value.startsWith("keym2:") && !e.value.includes("<html"));
      },
      null,
      { timeout: 30_000 }
    );

    await visible(page.getByPlaceholder("Enter decryption password")).fill(STRONG_PASSWORD);
    await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();
    await page.waitForFunction(
      (want) => {
        const el = document.querySelector("#output-text") as HTMLTextAreaElement | null;
        return !!el && el.value === want;
      },
      SECRET,
      { timeout: 90_000 }
    );
  });
});
