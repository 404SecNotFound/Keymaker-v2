/**
 * Which credentials will open the backup the encrypt form is about to write.
 *
 * One function, read by everything that describes that backup before or after
 * it is sealed: the inheritance plan, the inspector's plan pane, the receipt,
 * and the request handed to the worker. Each used to work the answer out for
 * itself from the same switches, and they disagreed. With "The strips need the
 * password too" on, the receipt said "both needed" while the inheritance plan
 * told the owner that any k shares open the backup on their own, and the
 * inspector drew two slots (three with the passkey switch still on) for a
 * container the worker writes with one.
 *
 * It models only what the worker enforces, and nothing more general:
 *
 *   - a passphrase slot (with the key file mixed in when one is used) always,
 *     except under §4.8;
 *   - a share slot beside it when recovery shares are on (§4.6), which opens
 *     the backup without the password;
 *   - a passkey slot beside it when enrolment is on (§4.7);
 *   - under §4.8, one slot that takes the password and the shares together,
 *     and nothing else. A passkey would open the backup on its own, so it is
 *     ruled out, and the worker refuses the request if it arrives anyway.
 *
 * It holds no secret and reads no DOM, so the truth table in
 * scripts/access-policy-test.mts can drive it directly and then hold it
 * against the worker: every way in it advertises must open a real container,
 * and every set it does not advertise must fail.
 */

export interface ShareSetting {
  threshold: number;
  count: number;
}

/** The encrypt form's switches, and nothing else. */
export interface AccessPolicyInput {
  keyFile: boolean;
  /** Null when recovery shares are off. */
  shares: ShareSetting | null;
  /** §4.8, "The strips need the password too". Meaningless without shares. */
  sharesNeedPassword: boolean;
  /** The encrypt-side passkey enrolment switch. */
  passkey: boolean;
}

/** One slot the worker will write, in the order it writes them. */
export type WayIn =
  | { kind: "password"; keyFile: boolean }
  | { kind: "shares"; threshold: number; count: number }
  | { kind: "password-and-shares"; keyFile: boolean; threshold: number; count: number }
  | { kind: "passkey" };

export interface AccessPolicy {
  /** One entry per slot, in slot order. Its length is the slot count. */
  waysIn: WayIn[];
  /** The share set opens the backup without the password (§4.6, not §4.8). */
  sharesOpenAlone: boolean;
  /** Passkey enrolment was switched on, and §4.8 rules it out. */
  passkeyRuledOut: boolean;
}

export function accessPolicy(input: AccessPolicyInput): AccessPolicy {
  const { keyFile, shares, passkey } = input;
  if (shares && input.sharesNeedPassword) {
    return {
      waysIn: [{ kind: "password-and-shares", keyFile, threshold: shares.threshold, count: shares.count }],
      sharesOpenAlone: false,
      passkeyRuledOut: passkey,
    };
  }
  const waysIn: WayIn[] = [{ kind: "password", keyFile }];
  if (shares) waysIn.push({ kind: "shares", threshold: shares.threshold, count: shares.count });
  if (passkey) waysIn.push({ kind: "passkey" });
  return { waysIn, sharesOpenAlone: shares !== null, passkeyRuledOut: false };
}

/** The share set this policy issues, or null when it issues none. */
export function sharesOf(policy: AccessPolicy): ShareSetting | null {
  for (const w of policy.waysIn) {
    if (w.kind === "shares" || w.kind === "password-and-shares") {
      return { threshold: w.threshold, count: w.count };
    }
  }
  return null;
}

/** Whether the worker should be asked to enrol a passkey slot. */
export function enrolsPasskey(policy: AccessPolicy): boolean {
  return policy.waysIn.some((w) => w.kind === "passkey");
}

/**
 * The share part of the worker's encrypt request, derived from the policy so
 * the page cannot ask for a combination the policy did not describe.
 */
export function shamirRequestOf(
  policy: AccessPolicy
): { threshold: number; count: number; withPassword: boolean } | undefined {
  const shares = sharesOf(policy);
  if (!shares) return undefined;
  return { ...shares, withPassword: !policy.sharesOpenAlone };
}

function passphrase(keyFile: boolean): string {
  return keyFile ? "Passphrase + key file" : "Passphrase";
}

/** The receipt's wording for one way in. */
export function describeWayIn(w: WayIn): string {
  switch (w.kind) {
    case "password":
      return passphrase(w.keyFile);
    case "shares":
      return `${w.threshold}-of-${w.count} recovery shares`;
    case "password-and-shares":
      return `${passphrase(w.keyFile)} and ${w.threshold}-of-${w.count} recovery shares, both needed`;
    case "passkey":
      return "passkey";
  }
}
