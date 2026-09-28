/**
 * What a verify result is evidence about (roadmap Section 06, part d).
 *
 * "The backup opens with this password" is a claim about one backup and one
 * set of credentials. The page used to keep it on screen until a wipe or the
 * next run, so loading another backup, choosing another key file or typing a
 * new password left a green result beside an input it had never checked.
 *
 * The page records what was checked when the check starts, and compares it
 * with the form on every render. Pure, so the rule can be tested without a
 * browser. Generic over the file type so the test can use plain objects;
 * files are compared by identity, since picking a file again makes a new one.
 */

/** What one verify checked. Holds no secret: the text is the container. */
export interface VerifiedInput<F> {
  inputType: "file" | "text";
  /** The backup file, in file mode. */
  file: F | null;
  /** The pasted container, in text mode. Ciphertext, not a secret. */
  text: string;
  keyFile: F | null;
  useShares: boolean;
  usePasskey: boolean;
}

/** A part of the form that no longer matches what was checked. */
export type VerifyChange = "backup" | "key file" | "unlock method" | "credentials";

/**
 * What changed since the check, in the order the page lists it. Empty when
 * the form still holds exactly what was checked.
 *
 * `typedSince` is whether a password or recovery shares are in the form now.
 * A successful check clears both, so anything there was typed afterwards, for
 * a new attempt, and the result says nothing about it.
 */
export function verifyChanges<F>(
  checked: VerifiedInput<F>,
  now: VerifiedInput<F>,
  typedSince: boolean
): VerifyChange[] {
  const changes: VerifyChange[] = [];
  const backupChanged =
    checked.inputType !== now.inputType ||
    (now.inputType === "file" ? checked.file !== now.file : checked.text !== now.text);
  if (backupChanged) changes.push("backup");
  if (checked.keyFile !== now.keyFile) changes.push("key file");
  if (checked.useShares !== now.useShares || checked.usePasskey !== now.usePasskey) {
    changes.push("unlock method");
  }
  if (typedSince) changes.push("credentials");
  return changes;
}

/**
 * SHA-256 of a container, in hex (Section 06e). The page keeps this for the
 * backup it created, so a later verify can tell whether it opened that exact
 * backup. A container is ciphertext, and its hash is not a secret either.
 */
export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as Uint8Array<ArrayBuffer>);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}
