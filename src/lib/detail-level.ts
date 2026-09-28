/**
 * How much format detail the page shows (roadmap Section 06, part c).
 *
 * The page has one switch, "Format detail", off by default and not stored:
 * the app keeps nothing between visits. Off, the page still names every KDF
 * and cipher, every way in, the format version and every warning. What it
 * leaves out are the numbers only someone checking the format needs: KDF
 * parameters, header bytes and offsets.
 *
 * The labels this trims are built elsewhere (`kdfLabelOf`, the inspector's
 * slot rows, the unlock's "Format:" line) as segments joined by " · ". A
 * parameter is always a segment of its own, so it can be dropped without
 * parsing the sentence around it. Anything that is not exactly a parameter
 * is kept, which is what keeps a warning that quotes a number intact.
 */

const SEPARATOR = " · ";

/** Exactly a KDF parameter: "64 MiB", "t=3", "p=4", "1,000,000 iterations". */
const PARAMETER = /^(?:\d+ MiB|t=\d+|p=\d+|[\d,]+ iterations)$/;

/** The label without its KDF parameters. Unchanged when it has none. */
export function withoutKdfParameters(label: string): string {
  return label
    .split(SEPARATOR)
    .filter((segment) => !PARAMETER.test(segment.trim()))
    .join(SEPARATOR);
}

/** The label as the current detail level shows it. */
export function atDetail(label: string, formatDetail: boolean): string {
  return formatDetail ? label : withoutKdfParameters(label);
}
