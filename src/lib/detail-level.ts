/**
 * How much format detail the page shows (roadmap Section 06, part c).
 *
 * The page has one switch, "Format detail", off by default and not stored:
 * the app keeps nothing between visits. Off, the page still names every KDF
 * and cipher, every way in, the format version and every warning. What it
 * leaves out are the numbers only someone checking the format needs: KDF
 * parameters, header bytes and offsets.
 *
 * The labels this trims are built elsewhere in two shapes. The receipt and
 * the inspector join segments with " · ", and there a parameter is always a
 * segment of its own. The unlock's "Format:" line comes from the readers,
 * which put parameters in brackets: "PBKDF2 (1,000,000 iters)", "Argon2id
 * (64 MiB, t=3, p=4)", "both needed (PBKDF2 1,000,000 iters)". Only a whole
 * segment, or a token inside brackets, is ever dropped. A bracket with no
 * parameter in it ("(HKDF-SHA-256)", "(read from the file, not
 * authenticated)") is left alone, and so is running text, which is what
 * keeps a warning that quotes a number intact.
 */

const SEPARATOR = " · ";

/** Exactly a KDF parameter: "64 MiB", "t=3", "p=4", "1,000,000 iterations". */
const PARAMETER = /^(?:\d+ MiB|t=\d+|p=\d+|[\d,]+ iterations)$/;

/** A parameter inside brackets, with the space before it. */
const BRACKETED_PARAMETER = /\s*(?:[\d,]+ (?:iters|iterations)|\d+ MiB|t=\d+|p=\d+)(?![\w=])/g;

/** "(64 MiB, t=3, p=4)" goes; "(PBKDF2 1,000,000 iters)" becomes "(PBKDF2)". */
function trimBrackets(text: string): string {
  return text.replace(/ \(([^()]*)\)/g, (whole, inner: string) => {
    BRACKETED_PARAMETER.lastIndex = 0;
    if (!BRACKETED_PARAMETER.test(inner)) return whole;
    const rest = inner
      .replace(BRACKETED_PARAMETER, "")
      .replace(/(?:,\s*)+/g, ", ")
      .replace(/^[,\s]+|[,\s]+$/g, "");
    return rest === "" ? "" : ` (${rest})`;
  });
}

/** The label without its KDF parameters. Unchanged when it has none. */
export function withoutKdfParameters(label: string): string {
  return trimBrackets(
    label
      .split(SEPARATOR)
      .filter((segment) => !PARAMETER.test(segment.trim()))
      .join(SEPARATOR)
  );
}

/** The label as the current detail level shows it. */
export function atDetail(label: string, formatDetail: boolean): string {
  return formatDetail ? label : withoutKdfParameters(label);
}
