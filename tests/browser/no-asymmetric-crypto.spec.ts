import { test, expect } from "@playwright/test";
import { readFileSync, readdirSync } from "node:fs";
import { resolve, join } from "node:path";

/**
 * The README's quantum section rests on one factual claim: there is no
 * public-key cryptography anywhere in the container path. This enforces it.
 *
 * The claim is what makes the rest of that section true. No key exchange means
 * nothing for Shor's algorithm to break and nothing for harvest-now-decrypt-
 * later to harvest, which is why the honest answer to "is this post-quantum?"
 * is "the question does not arise" rather than a roadmap. If someone later adds
 * an ECDH recipient slot — a reasonable feature, and one the README explicitly
 * describes as the thing that *would* change the answer — the documentation
 * silently becomes false. A sentence in a README cannot notice that. This can.
 *
 * Scoped to the modules that produce and consume container bytes. WebAuthn is
 * deliberately excluded: a passkey credential is signed with ECDSA or EdDSA by
 * the authenticator, but none of that reaches the file. What the slot stores is
 * PRF output — a symmetric secret — and `webauthn-prf.ts` never performs an
 * asymmetric operation itself.
 */

const CONTAINER_MODULES = [
  "keym-v2.ts",
  "keym-v2-shamir.ts",
  "keym-v2-selfextract.ts",
  "keymaker-crypto.ts",
  "crypto.ts",
  "crypto-client.ts",
  "crypto-worker.ts",
];

/** Primitives whose hardness assumption a quantum computer removes outright. */
const ASYMMETRIC = [
  "ECDH",
  "ECDSA",
  "Ed25519",
  "X25519",
  "RSA-OAEP",
  "RSA-PSS",
  "RSASSA",
  "generateKeyPair",
];

// Deliberately NOT listed: `deriveKey`. It is WebCrypto's derivation entry
// point for PBKDF2 as much as for ECDH — `crypto.subtle.deriveKey({ name:
// 'PBKDF2' }, ...)` in crypto.ts is a passphrase stretch, not a key agreement.
// Flagging it caught the frozen legacy core doing exactly what it is supposed
// to, which is a test failing on the presence of a symmetric primitive: noise
// that would train the next person to widen the list rather than read it.


test("no public-key cryptography reaches the container path", () => {
  const libDir = resolve(process.cwd(), "src/lib");
  const present = readdirSync(libDir);

  // The list must describe files that exist, or this passes by naming nothing.
  const missing = CONTAINER_MODULES.filter((m) => !present.includes(m));
  expect(missing, "a module in the container list has been renamed or removed").toEqual([]);

  const offenders: string[] = [];
  for (const mod of CONTAINER_MODULES) {
    const source = readFileSync(join(libDir, mod), "utf8");
    // Strip comments: the files discuss these primitives at length precisely
    // because they explain why none of them is used, and prose is not code.
    const code = source
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/^\s*\/\/.*$/gm, "");
    for (const token of ASYMMETRIC) {
      if (new RegExp(`\\b${token}\\b`).test(code)) offenders.push(`${mod}: ${token}`);
    }
  }

  expect(
    offenders,
    "asymmetric cryptography entered the container path — README's quantum section is now wrong " +
      "and needs a hybrid KEM story before this ships"
  ).toEqual([]);
});
