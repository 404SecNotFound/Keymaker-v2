import { test, expect, type Page, type CDPSession } from "@playwright/test";
import { visible, useTextMode, STRONG_PASSWORD } from "./helpers";

/**
 * §4.7, end to end: enrol a passkey while encrypting, then open the container
 * with the key and nothing else.
 *
 * ## Why these navigate to localhost rather than baseURL
 *
 * `playwright.config.ts` serves on `http://127.0.0.1:4321`, and **WebAuthn
 * refuses an IP address as a relying-party id**. Every call would fail with a
 * SecurityError that says nothing about passkeys. The static server binds
 * 127.0.0.1 and `localhost` resolves there, so the fix is a different name for
 * the same socket, not a different server.
 *
 * ## What the virtual authenticator does and does not prove
 *
 * `WebAuthn.addVirtualAuthenticator` gives a key that always consents, so these
 * tests cover the wiring — derive the salt, ask, take 32 bytes, unwrap — and
 * not the human parts: no prompt is shown, nothing is tapped, and a user who
 * cancels is not exercised here. `hasPrf` is what makes the extension answer at
 * all; without it every assertion returns no PRF result, which is the failure
 * the enrolment path is written to catch loudly.
 */

/** The config's baseURL is an IP, which WebAuthn will not accept as an RP id. */
const ORIGIN = "http://localhost:4321";

async function addVirtualAuthenticator(
  page: Page,
  { hasPrf = true }: { hasPrf?: boolean } = {}
): Promise<{ cdp: CDPSession; id: string }> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      ctap2Version: "ctap2_1",
      transport: "internal",
      // Discoverable credentials are what §4.7 rests on: the container stores no
      // credential id, so the authenticator has to find its own.
      hasResidentKey: true,
      hasUserVerification: true,
      // The extension this whole section exists for.
      hasPrf,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return { cdp, id: authenticatorId };
}

async function prepareEncrypt(page: Page, withPasskey: boolean) {
  await page.goto(`${ORIGIN}/`);
  await useTextMode(page);

  const advanced = visible(page.getByRole("button", { name: /^Advanced/ }));
  if ((await advanced.getAttribute("aria-expanded")) !== "true") await advanced.click();
  // PBKDF2: these tests are about the slot, and Argon2id at 64 MiB would add
  // seconds per run to prove nothing extra.
  await visible(page.getByRole("button").filter({ hasText: "PBKDF2" })).click();

  if (withPasskey) {
    const toggle = visible(page.getByRole("switch", { name: /Passkey quick access/i }));
    await expect(
      toggle,
      "the passkey control is missing — probePasskeySupport found no WebAuthn, so nothing below is being tested"
    ).toBeVisible();
    await toggle.click();
  }
}

/**
 * The `slot_type` byte of every slot, read out of the armor.
 *
 * Read from the bytes rather than inferred from the UI, because a toggle that
 * silently did nothing would otherwise satisfy every assertion in this file
 * except the one unlock that needs the slot to exist.
 */
async function slotTypes(page: Page, armor: string): Promise<number[]> {
  return page.evaluate((text: string) => {
    const b64 = text.slice("keym2:".length).replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    // The table's position follows the version byte: v2 puts slot_count at 8
    // and the table at 9; v3 §3 widens the core header to 24 for container_id
    // and inserts a 32-byte slot_table_mac, so the table starts at 57. Read at
    // v2's offsets a v3 container yields a slot count taken from container_id —
    // a random byte — and a list of slot types read out of the header.
    const v3 = bytes[4] === 3;
    const countAt = v3 ? 24 : 8;
    const table = v3 ? 57 : 9;
    const count = bytes[countAt]!;
    // §4.4: an AES slot is 96 bytes in both versions.
    return Array.from({ length: count }, (_, i) => bytes[table + i * 96]!);
  }, armor);
}

/** Encrypt `secret` and return the armored container from the Result field. */
async function encryptAndRead(page: Page, secret: string): Promise<string> {
  await visible(page.getByPlaceholder("Enter text to encrypt")).fill(secret);
  await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
  await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();
  await page.waitForFunction(
    () => {
      const v = (document.querySelector("#output-text") as HTMLTextAreaElement | null)?.value;
      return !!v && v.startsWith("keym2:");
    },
    undefined,
    { timeout: 90_000 }
  );
  return page.evaluate(() => (document.querySelector("#output-text") as HTMLTextAreaElement).value);
}

test.describe("§4.7 passkey slots", () => {
  test.skip(
    ({ browserName }) => browserName !== "chromium",
    "the virtual authenticator is a CDP feature"
  );

  test("a container enrolled with a passkey opens with the passkey alone", async ({ page }) => {
    const { cdp } = await addVirtualAuthenticator(page);
    try {
      await prepareEncrypt(page, true);
      const container = await encryptAndRead(page, "opened by a key you can hold");

      expect(
        await slotTypes(page, container),
        "the container should carry a passphrase slot and a passkey slot"
      ).toEqual([0x00, 0x01]);

      // Unlock with the key and no password at all.
      await visible(page.getByRole("tab", { name: "Decrypt" })).click();
      await useTextMode(page);
      await visible(page.getByPlaceholder("Enter text to decrypt")).fill(container);
      await visible(page.getByRole("button", { name: /^Use a passkey$/i })).click();
      await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();

      await expect(
        page.locator("#output-text"),
        "the passkey did not open the container it was enrolled on"
      ).toHaveValue("opened by a key you can hold", { timeout: 90_000 });
    } finally {
      await cdp.detach();
    }
  });

  test("the password still opens a container that has a passkey", async ({ page }) => {
    // §4.7's whole premise: the passkey is the convenient path, never the only
    // one. If enrolling cost the owner the way in they already had, the feature
    // would be a data-loss bug wearing a convenience feature's clothes.
    const { cdp } = await addVirtualAuthenticator(page);
    try {
      await prepareEncrypt(page, true);
      const container = await encryptAndRead(page, "the password still works");
      // Asserted, not assumed. Without this the test passes on a container that
      // has no passkey at all — proving only that passwords work, under a name
      // claiming something else. A control run with enrolment disabled is what
      // found that.
      expect(
        await slotTypes(page, container),
        "there is no passkey slot here, so this proves nothing about coexisting with one"
      ).toEqual([0x00, 0x01]);

      await visible(page.getByRole("tab", { name: "Decrypt" })).click();
      await useTextMode(page);
      await visible(page.getByPlaceholder("Enter text to decrypt")).fill(container);
      await visible(page.getByPlaceholder("Enter decryption password")).fill(STRONG_PASSWORD);
      await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();

      await expect(page.locator("#output-text")).toHaveValue("the password still works", {
        timeout: 90_000,
      });
    } finally {
      await cdp.detach();
    }
  });

  test("a container with no passkey says so rather than failing obscurely", async ({ page }) => {
    const { cdp } = await addVirtualAuthenticator(page);
    try {
      // Encrypted *without* the toggle, so there is no passkey slot to find.
      await prepareEncrypt(page, false);
      const container = await encryptAndRead(page, "no passkey here");

      await visible(page.getByRole("tab", { name: "Decrypt" })).click();
      await useTextMode(page);
      await visible(page.getByPlaceholder("Enter text to decrypt")).fill(container);
      await visible(page.getByRole("button", { name: /^Use a passkey$/i })).click();
      await visible(page.getByRole("button", { name: /^Decrypt Text$/i })).click();

      // Named, not generic. §6's indistinguishability rule is about *secrets*
      // being wrong; "this file has no passkey enrolled" is a fact about the
      // container the holder already has, and withholding it would only leave
      // someone tapping a key at a file that can never answer.
      await expect(
        visible(page.getByText(/no passkey enrolled/i)),
        "a container with no passkey slot should say so"
      ).toBeVisible({ timeout: 30_000 });
    } finally {
      await cdp.detach();
    }
  });

  test("an authenticator without PRF is refused, and says the passkey can be deleted", async ({
    page,
  }) => {
    // The realistic failure: a key that happily creates a credential and cannot
    // derive from it. Enrolment must refuse rather than write a slot nothing
    // can open — and must say the credential exists, because a relying party
    // can create passkeys and has no API to remove them. Silence leaves a
    // passkey manager filling with Keymaker entries, none of which open
    // anything.
    const { cdp } = await addVirtualAuthenticator(page, { hasPrf: false });
    try {
      await prepareEncrypt(page, true);
      await visible(page.getByPlaceholder("Enter text to encrypt")).fill("should not be written");
      await visible(page.getByPlaceholder("Enter a strong password")).fill(STRONG_PASSWORD);
      await visible(page.getByRole("button", { name: /^Encrypt Text$/i })).click();

      // Verbatim, not the generic string. This is what PasskeyError extending
      // KeymakerError buys: as a plain Error the whole message collapsed to
      // "Processing failed. Please try again.", which is the wrong answer for
      // the one case where the user has to go and delete something.
      await expect(
        visible(page.getByText(/safe to delete/i)),
        "the user was not told a passkey was left on their device"
      ).toBeVisible({ timeout: 60_000 });

      // And nothing was produced. A container written without the passkey slot
      // would be worse than the error: it would look like success.
      //
      // Absence rather than an empty value: the Result field is only rendered
      // once there is a result, so asserting `toHaveValue("")` fails with
      // "element(s) not found" even when the behaviour is correct.
      await expect(
        page.locator("#output-text"),
        "a container was written despite enrolment failing"
      ).toHaveCount(0);
    } finally {
      await cdp.detach();
    }
  });

  test("without the toggle, no passkey slot is written", async ({ page }) => {
    // The control on its own: everything above would still pass if the toggle
    // enrolled a passkey unconditionally.
    const { cdp } = await addVirtualAuthenticator(page);
    try {
      await prepareEncrypt(page, false);
      const container = await encryptAndRead(page, "one slot only");
      expect(
        await slotTypes(page, container),
        "encrypting without the toggle should write one passphrase slot and nothing else"
      ).toEqual([0x00]);
    } finally {
      await cdp.detach();
    }
  });
});
