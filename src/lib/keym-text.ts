/**
 * §7, "Characters a reader ignores": the one definition of which characters
 * are not part of a text form (armor, §4.6 share text, §7.1/§7.3 paper parts).
 *
 * Spelled out rather than taken from the language. JavaScript's `trim()` and
 * `\s` remove U+FEFF and miss U+0085; Python's `strip()` does the opposite and
 * also removes U+001C..U+001F; and each language's upper-casing folds a few
 * non-ASCII letters into ASCII ones. Two readers that each inherited their
 * language's idea of whitespace disagreed about which saved backups open.
 * `reference/keym2.py` defines the same set as `IGNORABLE`, and
 * `reference/crosstest2.py` holds the two to the same verdicts.
 */

/** Unicode White_Space plus U+FEFF (the byte order mark). */
export const IGNORABLE_CHARS =
  "\t\n\v\f\r \u0085  " +
  "           " +
  "    　﻿";

const IGNORABLE = new Set(IGNORABLE_CHARS);

/** Remove IGNORABLE characters from both ends. */
export function stripIgnorable(text: string): string {
  let start = 0;
  let end = text.length;
  while (start < end && IGNORABLE.has(text[start] as string)) start++;
  while (end > start && IGNORABLE.has(text[end - 1] as string)) end--;
  return text.slice(start, end);
}

/** Remove IGNORABLE characters everywhere. */
export function dropIgnorable(text: string): string {
  let out = "";
  for (const ch of text) if (!IGNORABLE.has(ch)) out += ch;
  return out;
}

/** Is this character one a reader ignores? */
export function isIgnorable(ch: string): boolean {
  return IGNORABLE.has(ch);
}

/**
 * Upper-case ASCII letters only. `"ı".toUpperCase()` is `"I"` and
 * `"ſ".toUpperCase()` is `"S"`, which let a non-ASCII letter into an ASCII
 * alphabet or prefix.
 */
export function asciiUpper(text: string): string {
  return text.replace(/[a-z]/g, (c) => String.fromCharCode(c.charCodeAt(0) - 32));
}
