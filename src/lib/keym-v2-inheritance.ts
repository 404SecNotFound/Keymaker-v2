/**
 * Roadmap 4.5 — the inheritance package.
 *
 * Pure composition of 4.1 (Shamir share sets), 4.2 (the paper vault) and 4.3
 * (the self-extracting page). No new wire format: everything here is already
 * specified, already has a Python counterpart, and already has fixtures. What
 * this module adds is the *orchestration*, and it exists as a library function
 * rather than as logic inside the wizard component for one reason — the
 * conformance path drives the same function the UI does, so the package a test
 * verifies is the package a user gets.
 *
 * ## The tension the wizard exists to resolve
 *
 * The three artefacts want different containers, and this is where that has to
 * be decided rather than left to whoever clicks last.
 *
 * - The container file and the paper vault want the **strongest** settings the
 *   device can carry: Argon2id, whatever the user chose.
 * - The self-extracting page cannot have them. §7.2's subset is AES-256-GCM
 *   with a PBKDF2 slot, because WebCrypto has never had Argon2id.
 *
 * So a package with a page in it holds **two containers of the same plaintext**
 * under the same password, and the weaker one bounds what an attacker has to
 * beat if both leak. That is stated on screen and on the paper rather than
 * discovered, and it is why the page is a deliberate choice inside the wizard
 * rather than something the wizard quietly includes.
 *
 * ## Why not one container with two slots
 *
 * Because it is the same mistake §7.2 already refuses, and refusing it once is
 * not enough if the wizard can reintroduce it: a container is only as strong as
 * its weakest slot, so a PBKDF2 slot added beside an Argon2id one downgrades the
 * container outright. Two containers keep the weakness inside the artefact that
 * needs it, and leaving the page out of a package leaves nothing weak behind.
 */

import type { CipherId, KdfParams } from "@/lib/keymaker-crypto";
import { CipherId as Cipher, KdfId } from "@/lib/keymaker-crypto";
import { armorKeym2 } from "@/lib/keym-v2";
import { buildSelfExtractingPage } from "@/lib/keym-v2-selfextract";

/** What the caller must supply: an encryptor. The UI passes the Worker-backed one. */
export type EncryptFn = (
  plaintext: Uint8Array,
  password: string,
  options: { kdf: KdfParams; cipher: CipherId },
  shamir?: { threshold: number; count: number }
) => Promise<{ container: Uint8Array; shares?: string[] | undefined }>;

export interface InheritancePlan {
  /** k-of-n. Both bounds are §6's, checked here so the wizard cannot ask for an impossible set. */
  threshold: number;
  count: number;
  /** The primary container's settings — the user's choice, untouched by the page's needs. */
  kdf: KdfParams;
  cipher: CipherId;
  /** Whether to also write §7.2's page. Off means nothing in the package uses PBKDF2. */
  includePage: boolean;
  /** Supplied rather than read from the clock, so a package is reproducible under test. */
  createdOn: string;
  appVersion: string;
}

export interface InheritancePackage {
  /** The primary container, under the user's chosen KDF and cipher. */
  container: Uint8Array;
  /** §7's armor of the primary container, which is what the paper vault prints. */
  armored: string;
  /** §4.6. Issued exactly once — nothing can reissue them. */
  shares: string[];
  threshold: number;
  /** §7.2's page, and its own weaker container. Null when the caller declined it. */
  page: { html: string; container: Uint8Array } | null;
}

/** §7.2's subset, fixed. Not a user choice — a page outside it cannot open itself. */
export const PAGE_KDF: KdfParams = { kdf: KdfId.PBKDF2, params: { iterations: 1_000_000 } };
export const PAGE_CIPHER: CipherId = Cipher.AES_256_GCM;

/**
 * Build the whole package in one pass.
 *
 * The password is taken once and used for both containers, which is deliberate:
 * an heir following the letter has one secret to be told, and a package whose
 * two halves take different passwords is a package that half-works at the worst
 * possible moment. It is also the reason both encryptions happen here rather
 * than across two user actions — U13's rule is that the password is not held
 * past the operation that needed it, and this is one operation.
 */
export async function buildInheritancePackage(
  plaintext: Uint8Array,
  password: string,
  plan: InheritancePlan,
  encrypt: EncryptFn
): Promise<InheritancePackage> {
  if (!password) throw new Error("An inheritance package needs a password.");
  // §6's Shamir bounds. Checked here as well as in the slot builder because the
  // wizard's own arithmetic (a threshold that follows a shrinking count) is
  // exactly where an impossible pair gets constructed by accident.
  if (plan.threshold < 2 || plan.threshold > 16) {
    throw new Error("The threshold must be between 2 and 16.");
  }
  if (plan.count < plan.threshold || plan.count > 16) {
    throw new Error("There must be at least as many shares as the threshold, and at most 16.");
  }

  const primary = await encrypt(
    plaintext,
    password,
    { kdf: plan.kdf, cipher: plan.cipher },
    { threshold: plan.threshold, count: plan.count }
  );
  if (!primary.shares || primary.shares.length !== plan.count) {
    // Silently shipping a package with no share set would hand someone a
    // wallet of paper their heirs cannot use, reported as success.
    throw new Error("The share set was not issued — refusing to write a package without it.");
  }

  let page: InheritancePackage["page"] = null;
  if (plan.includePage) {
    // A second container, not a second slot. See the note at the top of this
    // file: the weakness stays inside the artefact that needs it.
    //
    // Deliberately *without* a share set. A page is the copy most likely to be
    // stored casually — emailed to an executor, left on a drive — and putting
    // shares on it would mean the same k pieces of paper open a PBKDF2
    // container as well as the Argon2id one, which is a strictly worse trade
    // than the page already makes. The heirs' route is the primary container.
    const pageContainer = await encrypt(plaintext, password, {
      kdf: PAGE_KDF,
      cipher: PAGE_CIPHER,
    });
    page = {
      container: pageContainer.container,
      html: buildSelfExtractingPage({
        container: pageContainer.container,
        createdOn: plan.createdOn,
        appVersion: plan.appVersion,
      }),
    };
  }

  return {
    container: primary.container,
    armored: armorKeym2(primary.container),
    shares: primary.shares,
    threshold: plan.threshold,
    page,
  };
}

/**
 * The letter that goes in the box.
 *
 * Plain text on purpose. It is printed, and it is read by someone who may have
 * no idea what any of this is — so it names what they are holding, what to do
 * first, and what each piece is worth on its own.
 *
 * The sentence about the shares being password-equivalent is not optional and
 * is not softened. "Honest framing to preserve" in the roadmap says any k shares
 * decrypt without the password, which makes each share as sensitive as the
 * password itself — and the person who needs to know that is whoever is about to
 * put three of them in the same envelope.
 */
export function inheritanceLetter(pkg: InheritancePackage, plan: InheritancePlan): string {
  const { threshold, shares, page } = pkg;
  const lines: string[] = [
    "IF YOU ARE READING THIS, YOU ARE MEANT TO OPEN IT",
    "",
    `Prepared ${plan.createdOn} with Keymaker ${plan.appVersion}. Everything you`,
    "need is in this package. Nothing here needs the internet, an account, or",
    "any company still being in business.",
    "",
    "WHAT IS IN THE BOX",
    "",
    "  1. The backup itself, as a file and as printed squares you can scan.",
    `  2. ${shares.length} recovery slips, marked "share 1 of ${shares.length}" and so on.`,
    page
      ? "  3. A web page that opens the backup on its own, in any browser."
      : "  3. (No self-extracting page was included in this package.)",
    "",
    "TWO WAYS IN, AND YOU ONLY NEED ONE",
    "",
    "  - The password, if you were told it. Type it into any of the above.",
    `  - Or any ${threshold} of the ${shares.length} recovery slips, with no password at all.`,
    `    Fewer than ${threshold} of them reveal nothing whatsoever.`,
    "",
    "  ** Treat each slip exactly as carefully as the password. **",
    `  Any ${threshold} of them together open this backup completely, without`,
    "  needing anything else. Do not store them in one place.",
    "",
    "HOW TO ACTUALLY DO IT",
    "",
    page
      ? "  Easiest: open the .html file in any web browser and type the password."
      : "  Open keymaker in a browser and paste the backup in.",
    "",
    "  Or, with no website at all — this needs Python, which is free:",
    "",
    "      pip install cryptography argon2-cffi",
    "      python3 keym2.py decrypt --in backup.keym --out recovered.txt",
    "",
    `  With slips instead of the password, pass ${threshold} of them:`,
    "",
    "      python3 keym2.py decrypt --in backup.keym \\",
    "          --share KMSHARE1:... --share KMSHARE1:...",
    "",
    "IF IT WILL NOT OPEN",
    "",
    "  The tools will not tell you whether the password was wrong or the file",
    "  was damaged. That is deliberate and it is not a fault. Check you have",
    "  the whole backup, then try the recovery slips instead.",
  ];
  if (page) {
    lines.push(
      "",
      "ONE THING ABOUT THE WEB PAGE",
      "",
      "  It uses older, simpler cryptography than the rest of the package, so",
      "  that it still works in a browser many years from now. It is the easiest",
      "  way in and the weakest one. If you have a choice, use the backup file."
    );
  }
  return lines.join("\n") + "\n";
}
