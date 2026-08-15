"use client";

/**
 * WebAuthn PRF, the half of §4.7 the format deliberately does not model.
 *
 * Everything in `keym-v2.ts` treats a passkey as "32 bytes that came from
 * somewhere". This module is that somewhere. It is the only file in the project
 * that touches `navigator.credentials`, and it exists separately so the format
 * code stays testable without an authenticator and this stays swappable without
 * touching the format.
 *
 * ## Why enrolment asks twice
 *
 * The obvious implementation calls `create()` with the PRF extension and reads
 * the output from the result. That works on some authenticators and silently
 * returns nothing on others: PRF results at creation time are optional, and
 * plenty of platforms only produce them for an assertion.
 *
 * So enrolment does `create()` and then immediately `get()`, and takes the
 * output from the assertion. The extra tap is the price of a passkey that will
 * still be usable on hardware we have not met. Reading the creation-time result
 * when it happens to be there would mean enrolment succeeded on a credential
 * that could never be used to unlock — the worst possible outcome, and one that
 * would not surface until someone needed it.
 *
 * ## Why nothing is stored about the credential
 *
 * §4.7 keeps no identifier, so `get()` passes an empty `allowCredentials` and
 * lets the authenticator find its own. That requires the credential to be
 * *discoverable*, which is why `residentKey` is `required` at creation rather
 * than preferred — a non-discoverable credential cannot be found without the id
 * the container does not carry, so it would enrol happily and never open
 * anything.
 */

/** §4.7. The PRF extension returns 32 bytes. */
const PRF_OUTPUT_LEN = 32;

/**
 * What the relying party calls itself. Shown by the browser at both taps, and
 * stored on the authenticator, so it is user-visible text and not an id.
 */
const RP_NAME = "Keymaker";

/**
 * The credential's user handle and display name.
 *
 * A passkey belongs to an account at a relying party, and Keymaker has no
 * accounts — so this names the *container's* role rather than a person. The
 * handle is random because it is the only field that would otherwise be a
 * stable identifier linking two Keymaker passkeys on the same authenticator.
 */
const USER_DISPLAY = "Keymaker vault";

export interface PrfSupport {
  /** WebAuthn exists at all. */
  available: boolean;
  /** A platform authenticator is present. False still allows a security key. */
  platformAuthenticator: boolean;
}

/**
 * Whether this browser can be asked at all.
 *
 * Deliberately not a claim about the PRF extension: there is no way to ask
 * whether an authenticator supports PRF without prompting for one, and probing
 * by prompting is exactly the thing a capability check must not do. Support is
 * discovered at enrolment, where a failure can be reported against an action
 * the user just took.
 */
export async function probePasskeySupport(): Promise<PrfSupport> {
  if (typeof window === "undefined" || !window.PublicKeyCredential) {
    return { available: false, platformAuthenticator: false };
  }
  let platform = false;
  try {
    platform = await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    // A browser that has the constructor but not the probe. Not fatal: a
    // security key is still reachable through the normal flow.
    platform = false;
  }
  return { available: true, platformAuthenticator: platform };
}

/** Everything below needs the extension results, which the DOM types under-describe. */
interface PrfExtensionResults {
  prf?: { enabled?: boolean; results?: { first?: ArrayBuffer } };
}

function readPrfOutput(credential: PublicKeyCredential): Uint8Array | null {
  const results = credential.getClientExtensionResults() as PrfExtensionResults;
  const first = results.prf?.results?.first;
  if (!first || first.byteLength !== PRF_OUTPUT_LEN) return null;
  return new Uint8Array(first);
}

export class PasskeyError extends Error {
  constructor(
    message: string,
    /** True when the user dismissed the prompt, which is not a failure to report loudly. */
    readonly cancelled: boolean = false
  ) {
    super(message);
    this.name = "PasskeyError";
  }
}

function toPasskeyError(e: unknown, what: string): PasskeyError {
  const name = (e as { name?: string } | null)?.name;
  // NotAllowedError covers both "the user said no" and "the user did nothing
  // until it timed out". Neither deserves an error banner.
  if (name === "NotAllowedError" || name === "AbortError") {
    return new PasskeyError(`${what} was cancelled.`, true);
  }
  if (name === "InvalidStateError") {
    return new PasskeyError("That authenticator already holds a passkey for this site.");
  }
  if (name === "NotSupportedError") {
    return new PasskeyError("This authenticator cannot do what Keymaker needs (WebAuthn PRF).");
  }
  return new PasskeyError(`${what} failed.`);
}

/**
 * Create a discoverable passkey and return the PRF output for `prfSalt`.
 *
 * Two taps, for the reason in this file's header. The credential is created
 * first, then asserted, and only the assertion's output is used.
 */
export async function enrolPasskey(prfSalt: Uint8Array): Promise<Uint8Array> {
  if (prfSalt.length !== PRF_OUTPUT_LEN) {
    throw new PasskeyError("Keymaker asked for a PRF salt of the wrong size.");
  }

  const userId = crypto.getRandomValues(new Uint8Array(16));
  let created: PublicKeyCredential | null;
  try {
    created = (await navigator.credentials.create({
      publicKey: {
        // Not a signature anybody verifies: Keymaker has no server and the
        // attestation is not consumed. It is random because the spec requires
        // it to be, and reusing one would be worse than pointless.
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { name: RP_NAME },
        user: { id: userId, name: USER_DISPLAY, displayName: USER_DISPLAY },
        // ES256 then RS256. Neither is used for anything here — the PRF output
        // is the entire product — but the list cannot be empty.
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 },
        ],
        authenticatorSelection: {
          // Load-bearing, not a preference. See the header.
          residentKey: "required",
          requireResidentKey: true,
          userVerification: "required",
        },
        attestation: "none",
        extensions: { prf: {} } as AuthenticationExtensionsClientInputs,
      },
    })) as PublicKeyCredential | null;
  } catch (e) {
    throw toPasskeyError(e, "Enrolling the passkey");
  }
  if (!created) throw new PasskeyError("Enrolling the passkey produced no credential.");

  const enabled = (created.getClientExtensionResults() as PrfExtensionResults).prf?.enabled;
  if (enabled === false) {
    // Said plainly, because the alternative is a passkey that enrols and then
    // cannot open anything — a failure the user would meet years later.
    throw new PasskeyError(
      "That authenticator created a passkey but cannot derive a key from it (no WebAuthn PRF), so it cannot protect a backup."
    );
  }

  // The assertion, which is where the output actually comes from.
  return assertPasskeyPrf(prfSalt, "Enrolling the passkey");
}

/**
 * Ask an already-enrolled passkey for the PRF output over `prfSalt`.
 *
 * `allowCredentials` is empty on purpose: §4.7 stores no credential id, so the
 * authenticator finds its own. On a device holding several Keymaker passkeys
 * the browser shows a picker, and a wrong choice yields an output that does not
 * unwrap — indistinguishable from a wrong password, by §6.
 */
export async function assertPasskeyPrf(
  prfSalt: Uint8Array,
  what: string = "Unlocking with the passkey"
): Promise<Uint8Array> {
  if (prfSalt.length !== PRF_OUTPUT_LEN) {
    throw new PasskeyError("Keymaker asked for a PRF salt of the wrong size.");
  }

  let assertion: PublicKeyCredential | null;
  try {
    assertion = (await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [],
        userVerification: "required",
        extensions: {
          prf: { eval: { first: prfSalt as BufferSource } },
        } as AuthenticationExtensionsClientInputs,
      },
    })) as PublicKeyCredential | null;
  } catch (e) {
    throw toPasskeyError(e, what);
  }
  if (!assertion) throw new PasskeyError(`${what} produced no assertion.`);

  const output = readPrfOutput(assertion);
  if (!output) {
    throw new PasskeyError(
      "That passkey did not return the 32 bytes Keymaker needs (no WebAuthn PRF)."
    );
  }
  return output;
}
