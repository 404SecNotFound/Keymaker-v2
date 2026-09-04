/**
 * The advisory password floor, in one place so every entry point that seals a
 * container enforces the same rule.
 *
 * This is UI-only and must stay that way: `encryptData()` has never consulted it
 * and must not, because cryptographic behaviour cannot depend on a heuristic.
 * It exists so the Encrypt tab and the Audio (steganography) tab refuse the same
 * weak passwords rather than drifting apart. The reasoning behind the two ways
 * to clear the floor is recorded at the call site's history (KM-02b): a typed
 * string carries no evidence of how it was chosen, so this enforces a floor and
 * claims nothing more.
 */

const PASSPHRASE_MIN_WORD_LEN = 3;

/**
 * Whether `pwd` clears the floor. `wasGenerated` short-circuits to true because
 * a string this app drew from the CSPRNG has a known sampling process and an
 * exact bit count, so no morphology inference is needed or wanted.
 */
export function meetsPasswordPolicy(pwd: string, wasGenerated = false): boolean {
  if (wasGenerated) return true;

  const trimmed = pwd.trim();

  const distinctSubstantialWords = new Set(
    trimmed
      .split(/\s+/)
      .filter(Boolean)
      .map((w) => w.toLowerCase())
      .filter((w) => w.length >= PASSPHRASE_MIN_WORD_LEN)
  ).size;

  // A genuine diceware phrase clears one of these even with a repeated word,
  // because the length floor carries it.
  if (distinctSubstantialWords >= 6 && trimmed.length >= 20) return true;
  if (distinctSubstantialWords >= 4 && trimmed.length >= 24) return true;

  const hasUpperCase = /[A-Z]/.test(pwd);
  const hasLowerCase = /[a-z]/.test(pwd);
  const hasNumbers = /\d/.test(pwd);
  const hasSpecialChars = /[!@#$%^&*()_+~`|}{[\]:;?><,.\/=-]/.test(pwd);
  const hasMinLength = pwd.length >= 24;
  return hasMinLength && hasUpperCase && hasLowerCase && hasNumbers && hasSpecialChars;
}
