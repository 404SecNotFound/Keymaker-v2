/**
 * The advisory password floor, in one place so every entry point that seals a
 * container enforces the same rule.
 *
 * This is UI-only and must stay that way: `encryptData()` has never consulted it
 * and must not, because cryptographic behaviour cannot depend on a heuristic.
 * It exists so the Encrypt tab and the Audio tab refuse the same weak passwords
 * rather than drifting apart.
 *
 * ## Why this is length + a blocklist, not a composition rule (KM-02c)
 *
 * The old rule required character classes: 24+ characters with upper, lower, a
 * number and a symbol, or a diceware-shaped phrase. That is the pattern
 * NIST SP 800-63B-4 §3.1.1 now argues *against*, and for a good reason it made
 * concrete here: it rejected a strong 18-character random lowercase secret
 * (~85 bits) while accepting `Password word river tree stone 1!`, six distinct
 * words with a token symbol, every one of them cracking-list fodder. Composition
 * rules test the shape of a string, and shape is not entropy.
 *
 * So this now enforces:
 *
 *   - a **length floor** and nothing about which characters are used;
 *   - a small nudge against trivially low-variety strings (a handful of distinct
 *     characters), which length alone cannot catch;
 *   - an **offline blocklist** of common and famous passwords, checked in a
 *     normalized form so `correct horse battery staple` and its spaced,
 *     capitalised and `1!`-suffixed variants are all refused.
 *
 * The floor is calibrated for Keymaker's threat model, which is *harsher* than
 * the one 800-63B addresses: a KEYM container is guessed offline with no rate
 * limit, only Argon2id in the way. `MIN_TYPED_LENGTH` of 16 keeps a lowercase-
 * only random secret near 75 bits, and higher for any richer alphabet, while no
 * longer punishing the person who typed one. The one entropy figure Keymaker is
 * entitled to state is still reserved for what it generated itself; a typed
 * secret gets "minimum policy met" and the honest warning that it faces
 * unlimited offline guessing. Prefer Generate.
 */

/** Minimum length for a typed secret. Tunable in one place; see the header for
 *  how the number was chosen. */
export const MIN_TYPED_LENGTH = 16;

/** A typed secret with fewer distinct characters than this is refused however
 *  long it is, so `aaaaaaaaaaaaaaaaaa` cannot clear the length floor by padding. */
const MIN_DISTINCT_CHARS = 5;

/** One-line requirement, shared by every surface that states the floor, so the
 *  Encrypt tab and the Audio tab cannot describe different rules. */
export const PASSWORD_POLICY_HINT =
  "at least 16 characters, and not a well-known weak password. There is no " +
  "character-mix requirement. A typed password is guessed offline without limit, " +
  "so prefer Generate.";

/**
 * Common, famous and Keymaker-specific passwords, stored in the normal form
 * `normalize()` produces (lowercase, spaces collapsed). Kept deliberately small
 * and curated rather than a full leaked-password corpus: the length floor
 * already removes most short weak passwords, so this only has to catch the
 * long-but-notorious ones a floor cannot: famous passphrases, repeated words,
 * and this project's own names.
 */
const BLOCKLIST = new Set<string>([
  // Famous passphrases and their obvious forms.
  "correct horse battery staple",
  "the quick brown fox jumps over the lazy dog",
  "all work and no play makes jack a dull boy",
  "may the force be with you",
  "to be or not to be that is the question",
  "lorem ipsum dolor sit amet",
  // Keymaker / lineage / hero copy.
  "keymaker",
  "keymakerkeymaker",
  "ittybitz",
  "encrypt everything trust nothing",
  "trust nothing",
  // Long-but-weak patterns people actually type.
  "password password password",
  "passwordpassword",
  "passwordpasswordpassword",
  "administrator",
  "letmeinletmein",
  "qwertyuiopasdfghjkl",
  "qwertyuiopasdfghjklzxcvbnm",
  "abcdefghijklmnop",
  "abcdefghijklmnopqrstuvwxyz",
  "1234567890123456",
  "12345678901234567890",
  "iloveyouiloveyou",
  "whatever whatever whatever",
  "changemechangeme",
  "monkeymonkeymonkey",
]);

/** Collapse a password to the form the blocklist stores: trimmed, lowercased,
 *  runs of whitespace squeezed to one space. */
function normalize(pwd: string): string {
  return pwd.trim().toLowerCase().replace(/\s+/g, " ");
}

/** Whether a password is a known weak one. Checks the normalized form, and also
 *  a letters-only form so `Correct-Horse-Battery-Staple1!` reduces to the same
 *  blocklisted `correcthorsebatterystaple` as the spaced original. */
function isBlocklisted(pwd: string): boolean {
  const normal = normalize(pwd);
  if (BLOCKLIST.has(normal)) return true;
  const lettersOnly = normal.replace(/[^a-z]/g, "");
  if (lettersOnly.length === 0) return false;
  // The blocklist stores spaced phrases; compare against their letters-only form
  // too, so a phrase and its run-together variant are both caught.
  for (const entry of BLOCKLIST) {
    if (entry.replace(/[^a-z]/g, "") === lettersOnly) return true;
  }
  return false;
}

/**
 * Whether `pwd` clears the floor. `wasGenerated` short-circuits to true because
 * a string this app drew from the CSPRNG has a known sampling process and an
 * exact bit count, so no morphology inference is needed or wanted.
 */
export function meetsPasswordPolicy(pwd: string, wasGenerated = false): boolean {
  if (wasGenerated) return true;

  const trimmed = pwd.trim();
  if (trimmed.length < MIN_TYPED_LENGTH) return false;

  const distinctChars = new Set(trimmed).size;
  if (distinctChars < MIN_DISTINCT_CHARS) return false;

  if (isBlocklisted(trimmed)) return false;

  return true;
}
