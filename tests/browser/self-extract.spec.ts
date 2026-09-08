import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { visible, useTextMode, selectCrypto, STRONG_PASSWORD } from "./helpers";

const REPO_ROOT = resolve(__dirname, "../..");
const BRIDGE = resolve(REPO_ROOT, "reference/bridge.mjs");

/** Drive the shipping TypeScript through the bridge, the way v3-default.spec.ts does. */
function bridge(...args: string[]): void {
  execFileSync("node", [BRIDGE, ...args], { cwd: REPO_ROOT, encoding: "utf8" });
}

// §4.5 forbids a pinned salt and master key on real data; these build a fixture,
// so it is exactly the case they are for. 32 bytes each, as hex.
const SE_SALT = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const SE_MASTER_KEY = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
const SE_PK_SALT = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
const SE_PK_PRF = "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f";

/**
 * A self-extracting page whose container carries a slot the WebCrypto subset
 * cannot use, placed *before* the passphrase slot that it can.
 *
 * The order is the point. §4.4 says a reader skips a slot it cannot use and
 * opens through one it can; the failure it guards against is a reader that
 * rejects the whole file for the first slot it does not understand. If the
 * usable slot came first the reader would open on it and never reach the skip,
 * so `addpasskey` (which appends its slot) is followed by a swap that puts the
 * passkey slot at index 0 and the PBKDF2/AES passphrase slot at index 1. Each
 * slot authenticates against its own 48-byte prefix (§5.3), not its position,
 * and a v2 container carries no slot_table_mac, so reordering two whole records
 * leaves a container both readers still open.
 */
function multiSlotUnusableFirstPage(outPath: string, ptPath: string, containerPath: string): string {
  writeFileSync(ptPath, SECRET, "utf8");
  const single = containerPath + ".single";
  const twoSlot = containerPath + ".two";
  bridge("encrypt2", "--password", STRONG_PASSWORD, "--in", ptPath, "--out", single,
    "--cipher", "aes", "--salt", SE_SALT, "--master-key", SE_MASTER_KEY,
    "--kdf", "pbkdf2", "--iterations", "600000");
  bridge("addpasskey", "--password", STRONG_PASSWORD, "--in", single, "--out", twoSlot,
    "--prf-output", SE_PK_PRF, "--salt", SE_PK_SALT);

  // v2 slot table starts at offset 9 (DECRYPTOR_JS `V2.table`); an AES slot is
  // 96 bytes (`SLOT_LEN`). Swap record 0 (passphrase) with record 1 (passkey).
  const TABLE = 9;
  const W = 96;
  const buf = readFileSync(twoSlot);
  if (buf[4] !== 2) throw new Error(`expected a v2 base container, got version ${buf[4]}`);
  if (buf[8] !== 2) throw new Error(`expected exactly two slots, got ${buf[8]}`);
  const passphrase = Buffer.from(buf.subarray(TABLE, TABLE + W));
  const passkey = Buffer.from(buf.subarray(TABLE + W, TABLE + 2 * W));
  passkey.copy(buf, TABLE);
  passphrase.copy(buf, TABLE + W);
  const swapped = containerPath + ".swapped";
  writeFileSync(swapped, buf);

  bridge("selfextract", "--in", swapped, "--out", outPath,
    "--created-on", "2026-01-01", "--app-version", "0.0.0");
  return outPath;
}

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

  test("armor that gained a non-ASCII space is refused, matching keym2.py (§7)", async ({
    page,
    context,
  }, testInfo) => {
    // §7: the dearmor strips ASCII whitespace only. keym2.py keeps a non-ASCII
    // space (U+00A0, a stray BOM) inside the body and its strict base64 refuses
    // the file. The embedded reader must agree — otherwise a backup opens here
    // and is rejected on the durable Python path, which is the one reader an
    // heir with no browser is left with. The `\s` this replaced stripped the
    // character and opened it, so this control bites when that regex comes back.
    await encryptWith(page, "pbkdf2");
    const [download] = await Promise.all([
      page.waitForEvent("download"),
      visible(page.getByTestId("selfextract-download")).click(),
    ]);
    const saved = testInfo.outputPath("nbsp.html");
    await download.saveAs(saved);

    const offline = await context.newPage();
    await offline.goto(`file://${saved}`);

    // Splice a U+00A0 into the middle of the base64 body, the way a notes app or
    // mail client re-wrapping the text can. Not at the ends, which are trimmed.
    const injected = await offline.evaluate(() => {
      const el = document.getElementById("keym2-container");
      if (!el) return false;
      const t = el.textContent || "";
      const at = t.indexOf("keym2:") + "keym2:".length + 10;
      if (at < "keym2:".length + 10) return false;
      el.textContent = t.slice(0, at) + " " + t.slice(at);
      return true;
    });
    expect(injected, "could not find the armor body to corrupt").toBe(true);

    await offline.fill("#pw", STRONG_PASSWORD);
    await offline.click("#go");

    // The reader keeps the U+00A0, atob rejects it, and the page refuses — it
    // does not silently strip the character and reveal the secret.
    await offline.waitForFunction(
      () => document.querySelector("#status")?.className === "bad",
      null,
      { timeout: 90_000 }
    );
    expect(await offline.inputValue("#out")).not.toBe(SECRET);
    expect(await offline.isHidden("#result")).toBe(true);
    await offline.close();
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

  test("skips a slot it cannot use and opens through the password, refusing without naming a slot", async ({
    context,
  }, testInfo) => {
    // The embedded reader's slot loop is a hand-written copy, and until now
    // every page opened here carried a single passphrase slot — so its §4.4
    // skip was never exercised in a browser. An inheritance backup is exactly
    // where multiple slots turn up: an owner password beside an heir's passkey.
    // The page must open through the password it can use and never reject the
    // file for the passkey slot it cannot. Built with the unusable slot first
    // so the skip is load-bearing; see multiSlotUnusableFirstPage.
    const saved = multiSlotUnusableFirstPage(
      testInfo.outputPath("multislot.html"),
      testInfo.outputPath("ms-pt.bin"),
      testInfo.outputPath("ms.keym2")
    );

    const offline = await context.newPage();
    const pageErrors: string[] = [];
    offline.on("pageerror", (e) => pageErrors.push(e.message));
    await offline.goto(`file://${saved}`);

    await offline.fill("#pw", STRONG_PASSWORD);
    await offline.click("#go");
    await offline.waitForSelector("#result:not([hidden])", { timeout: 90_000 });
    expect(await offline.inputValue("#out")).toBe(SECRET);
    expect(pageErrors).toEqual([]);
    // v2 has no slot_table_mac, so nothing is claimed about the table.
    expect(await offline.isHidden("#table")).toBe(true);

    // §4.4 / §6: a wrong password is refused only once every slot has been
    // tried, with the one message the format allows — nothing about the passkey
    // slot it skipped or which slot it got furthest with — and the result panel
    // goes back to hidden, so no plaintext stays on screen.
    await offline.fill("#pw", "not the password");
    await offline.click("#go");
    await offline.waitForFunction(
      () => document.querySelector("#status")?.className === "bad",
      null,
      { timeout: 90_000 }
    );
    const refusal = (await offline.textContent("#status")) ?? "";
    expect(refusal).toMatch(/password is wrong or this file is damaged/i);
    expect(refusal).not.toMatch(/slot|passkey|chunk|tag|header|nonce/i);
    expect(await offline.isHidden("#result")).toBe(true);
    await offline.close();
  });
});
