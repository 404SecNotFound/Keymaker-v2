/**
 * The access policy against the worker (roadmap 9.1).
 *
 * `src/lib/access-policy.ts` is what the inheritance plan, the inspector, the
 * receipt and the worker request all read to say which credentials open the
 * backup about to be written. Before it existed each worked the answer out for
 * itself, and with "The strips need the password too" on they disagreed: the
 * plan told the owner that any k shares open the backup on their own when the
 * worker had written a slot that needs the password as well.
 *
 * So this does not stop at the policy's own output. For every combination the
 * form can produce it builds the worker request the way the page does (from
 * the policy), has the shipping worker write a real container, and then tries
 * every credential set against it. The expected outcome of each attempt is
 * written out below by hand, from the format's rules, not computed from the
 * policy; a policy that described the wrong backup would disagree with it.
 * It then checks the policy's claims against what actually happened: each way
 * it advertises opens the container, the slot count it gives the inspector is
 * the slot count written, and "the shares open it on their own" is true
 * exactly when shares alone did.
 *
 * Last, the one combination the format rules out (§4.8 with a passkey) must be
 * refused by the worker even if a caller asks for it, and the policy must never
 * ask for it.
 */
import {
  accessPolicy,
  describeWayIn,
  enrolsPasskey,
  shamirRequestOf,
  sharesOf,
  type AccessPolicyInput,
} from "../src/lib/access-policy.ts";

let passed = 0;
let failed = 0;
function check(name: string, ok: boolean, detail = "") {
  if (ok) {
    passed++;
    console.log(`ok    ${name}`);
  } else {
    failed++;
    console.log(`FAIL  ${name}${detail ? ` (${detail})` : ""}`);
  }
}

// ---------------------------------------------------------------------------
// The shipping worker, loaded as-is with a stand-in `self`.
// ---------------------------------------------------------------------------
let handler: ((e: { data: unknown }) => Promise<void>) | null = null;
const posted: any[] = [];
(globalThis as any).self = {
  addEventListener: (_type: string, h: any) => {
    handler = h;
  },
  postMessage: (m: any) => {
    posted.push(m);
  },
};
await import("../src/lib/crypto-worker.ts");
const { KdfId, CipherId } = await import("../src/lib/keymaker-crypto.ts");
const { inspectKeym2 } = await import("../src/lib/keym-v2.ts");

let nextId = 0;
async function send(req: Record<string, unknown>): Promise<any> {
  posted.length = 0;
  await handler!({ data: { id: ++nextId, ...req } });
  return posted[0];
}

const PASSWORD = "synthetic-access-policy-password";
const PLAINTEXT = "synthetic access-policy payload";
const KEY_FILE = new Uint8Array(64).fill(0x4b);
const WRONG_KEY_FILE = new Uint8Array(64).fill(0x4c);
const PRF = new Uint8Array(32).fill(0x07);
const PRF_SALT = new Uint8Array(32).fill(0x09);
const OPTIONS = {
  kdf: { kdf: KdfId.PBKDF2, params: { iterations: 600_000 } },
  cipher: CipherId.AES_256_GCM,
};
const buf = (u: Uint8Array) => u.slice().buffer as ArrayBuffer;

// ---------------------------------------------------------------------------
// 1. The policy on its own: slot list and receipt wording.
// ---------------------------------------------------------------------------
const TWO_OF_THREE = { threshold: 2, count: 3 };
const cases: { input: AccessPolicyInput; kinds: string[]; words: string[] }[] = [
  { input: { keyFile: false, shares: null, sharesNeedPassword: false, passkey: false }, kinds: ["password"], words: ["Passphrase"] },
  { input: { keyFile: true, shares: null, sharesNeedPassword: false, passkey: false }, kinds: ["password"], words: ["Passphrase + key file"] },
  // Meaningless without shares: the switch alone changes nothing.
  { input: { keyFile: false, shares: null, sharesNeedPassword: true, passkey: false }, kinds: ["password"], words: ["Passphrase"] },
  { input: { keyFile: false, shares: TWO_OF_THREE, sharesNeedPassword: false, passkey: false }, kinds: ["password", "shares"], words: ["Passphrase", "2-of-3 recovery shares"] },
  { input: { keyFile: false, shares: TWO_OF_THREE, sharesNeedPassword: true, passkey: false }, kinds: ["password-and-shares"], words: ["Passphrase and 2-of-3 recovery shares, both needed"] },
  { input: { keyFile: true, shares: TWO_OF_THREE, sharesNeedPassword: true, passkey: false }, kinds: ["password-and-shares"], words: ["Passphrase + key file and 2-of-3 recovery shares, both needed"] },
  { input: { keyFile: false, shares: null, sharesNeedPassword: false, passkey: true }, kinds: ["password", "passkey"], words: ["Passphrase", "passkey"] },
  { input: { keyFile: false, shares: TWO_OF_THREE, sharesNeedPassword: false, passkey: true }, kinds: ["password", "shares", "passkey"], words: ["Passphrase", "2-of-3 recovery shares", "passkey"] },
  // §4.8 rules the passkey out, even with the switch still on.
  { input: { keyFile: false, shares: TWO_OF_THREE, sharesNeedPassword: true, passkey: true }, kinds: ["password-and-shares"], words: ["Passphrase and 2-of-3 recovery shares, both needed"] },
];
for (const c of cases) {
  const p = accessPolicy(c.input);
  const label = JSON.stringify(c.input);
  check(`policy slots ${label}`, JSON.stringify(p.waysIn.map((w) => w.kind)) === JSON.stringify(c.kinds), p.waysIn.map((w) => w.kind).join(","));
  check(`policy wording ${label}`, JSON.stringify(p.waysIn.map(describeWayIn)) === JSON.stringify(c.words), p.waysIn.map(describeWayIn).join(" | "));
}
{
  const p = accessPolicy({ keyFile: false, shares: TWO_OF_THREE, sharesNeedPassword: true, passkey: true });
  check("§4.8 with the passkey switch on: flagged as ruled out", p.passkeyRuledOut === true);
  check("§4.8 with the passkey switch on: no passkey enrolment requested", enrolsPasskey(p) === false);
  check("§4.8: the share request asks for the combined slot", shamirRequestOf(p)?.withPassword === true);
  check("§4.8: the shares do not open it alone", p.sharesOpenAlone === false);
}

// ---------------------------------------------------------------------------
// 2. The policy against real containers.
// ---------------------------------------------------------------------------
type Attempt = "pw" | "pwNoKeyFile" | "pwWrongKeyFile" | "wrongPw" | "sharesK" | "sharesKm1" | "pwSharesK" | "pwSharesKm1" | "pwNoKeyFileSharesK" | "passkey";

interface Row {
  name: string;
  input: AccessPolicyInput;
  /** Written by hand from the format's rules. Attempts not listed must fail. */
  opens: Attempt[];
  /** Attempts that make no sense for this backup and are not tried. */
  skip?: Attempt[];
}
const K = 2;
const rows: Row[] = [
  { name: "password only", input: { keyFile: false, shares: null, sharesNeedPassword: false, passkey: false }, opens: ["pw"], skip: ["pwNoKeyFile", "pwWrongKeyFile", "pwNoKeyFileSharesK", "sharesK", "sharesKm1", "pwSharesK", "pwSharesKm1"] },
  { name: "password + key file", input: { keyFile: true, shares: null, sharesNeedPassword: false, passkey: false }, opens: ["pw"], skip: ["sharesK", "sharesKm1", "pwSharesK", "pwSharesKm1", "pwNoKeyFileSharesK"] },
  { name: "password OR shares", input: { keyFile: false, shares: TWO_OF_THREE, sharesNeedPassword: false, passkey: false }, opens: ["pw", "sharesK", "pwSharesK", "pwSharesKm1"], skip: ["pwNoKeyFile", "pwWrongKeyFile", "pwNoKeyFileSharesK"] },
  { name: "password + key file OR shares", input: { keyFile: true, shares: TWO_OF_THREE, sharesNeedPassword: false, passkey: false }, opens: ["pw", "sharesK", "pwSharesK", "pwSharesKm1", "pwNoKeyFileSharesK"] },
  { name: "password AND shares", input: { keyFile: false, shares: TWO_OF_THREE, sharesNeedPassword: true, passkey: false }, opens: ["pwSharesK"], skip: ["pwNoKeyFile", "pwWrongKeyFile", "pwNoKeyFileSharesK"] },
  { name: "password + key file AND shares", input: { keyFile: true, shares: TWO_OF_THREE, sharesNeedPassword: true, passkey: false }, opens: ["pwSharesK"] },
  { name: "password OR passkey", input: { keyFile: false, shares: null, sharesNeedPassword: false, passkey: true }, opens: ["pw", "passkey"], skip: ["pwNoKeyFile", "pwWrongKeyFile", "pwNoKeyFileSharesK", "sharesK", "sharesKm1", "pwSharesK", "pwSharesKm1"] },
  { name: "password OR shares OR passkey", input: { keyFile: false, shares: TWO_OF_THREE, sharesNeedPassword: false, passkey: true }, opens: ["pw", "sharesK", "pwSharesK", "pwSharesKm1", "passkey"], skip: ["pwNoKeyFile", "pwWrongKeyFile", "pwNoKeyFileSharesK"] },
  { name: "password AND shares, passkey switch left on", input: { keyFile: false, shares: TWO_OF_THREE, sharesNeedPassword: true, passkey: true }, opens: ["pwSharesK"], skip: ["pwNoKeyFile", "pwWrongKeyFile", "pwNoKeyFileSharesK"] },
];
const ALL: Attempt[] = ["pw", "pwNoKeyFile", "pwWrongKeyFile", "wrongPw", "sharesK", "sharesKm1", "pwSharesK", "pwSharesKm1", "pwNoKeyFileSharesK", "passkey"];

for (const row of rows) {
  const policy = accessPolicy(row.input);
  // Exactly the request the page builds (use-encryptor-state.ts, processData).
  const enc = await send({
    op: "encrypt",
    data: buf(new TextEncoder().encode(PLAINTEXT)),
    password: PASSWORD,
    keyFile: row.input.keyFile ? buf(KEY_FILE) : null,
    options: OPTIONS,
    shamir: shamirRequestOf(policy),
    passkey: enrolsPasskey(policy) ? { prfOutput: PRF.slice(), salt: PRF_SALT.slice() } : undefined,
  });
  check(`[${row.name}] the worker writes it`, enc?.ok === true, enc?.message);
  if (!enc?.ok) continue;
  const container = new Uint8Array(enc.data);
  const shares: string[] = enc.shares ?? [];
  check(`[${row.name}] shares issued only when the policy has a share set`, (shares.length > 0) === (sharesOf(policy) !== null), `${shares.length} shares`);

  const slots = inspectKeym2(container)?.slots;
  check(`[${row.name}] slots written = ways in the inspector draws`, slots === policy.waysIn.length, `written ${slots}, policy ${policy.waysIn.length}`);

  const kf = row.input.keyFile ? KEY_FILE : null;
  const attempt: Record<Attempt, { password: string; keyFile: Uint8Array | null; shares?: string[]; prfOutput?: Uint8Array }> = {
    pw: { password: PASSWORD, keyFile: kf },
    pwNoKeyFile: { password: PASSWORD, keyFile: null },
    pwWrongKeyFile: { password: PASSWORD, keyFile: WRONG_KEY_FILE },
    wrongPw: { password: PASSWORD + "x", keyFile: kf },
    sharesK: { password: "", keyFile: null, shares: shares.slice(0, K) },
    sharesKm1: { password: "", keyFile: null, shares: shares.slice(0, K - 1) },
    pwSharesK: { password: PASSWORD, keyFile: kf, shares: shares.slice(0, K) },
    pwSharesKm1: { password: PASSWORD, keyFile: kf, shares: shares.slice(0, K - 1) },
    pwNoKeyFileSharesK: { password: PASSWORD, keyFile: null, shares: shares.slice(0, K) },
    passkey: { password: "", keyFile: null, prfOutput: PRF },
  };
  const opened = new Set<Attempt>();
  for (const a of ALL) {
    if (row.skip?.includes(a)) continue;
    const creds = attempt[a];
    const dec = await send({
      op: "decrypt",
      data: buf(container),
      password: creds.password,
      keyFile: creds.keyFile ? buf(creds.keyFile) : null,
      shares: creds.shares,
      prfOutput: creds.prfOutput ? creds.prfOutput.slice() : undefined,
    });
    const ok = dec?.ok === true && new TextDecoder().decode(dec.data) === PLAINTEXT;
    if (ok) opened.add(a);
    const expected = row.opens.includes(a);
    check(`[${row.name}] ${a} ${expected ? "opens" : "is refused"}`, ok === expected, dec?.ok ? "opened" : dec?.message);
  }

  // The policy's claims, against what just happened.
  for (const way of policy.waysIn) {
    const needed: Attempt =
      way.kind === "password" ? "pw" : way.kind === "shares" ? "sharesK" : way.kind === "passkey" ? "passkey" : "pwSharesK";
    check(`[${row.name}] advertised way in "${describeWayIn(way)}" opens it`, opened.has(needed));
  }
  if (sharesOf(policy)) {
    check(`[${row.name}] "the shares open it on their own" matches reality`, policy.sharesOpenAlone === opened.has("sharesK"), `policy ${policy.sharesOpenAlone}, observed ${opened.has("sharesK")}`);
  }
}

// ---------------------------------------------------------------------------
// 3. The combination the format rules out is refused by the worker itself.
// ---------------------------------------------------------------------------
{
  const refused = await send({
    op: "encrypt",
    data: buf(new TextEncoder().encode(PLAINTEXT)),
    password: PASSWORD,
    keyFile: null,
    options: OPTIONS,
    shamir: { threshold: 2, count: 3, withPassword: true },
    passkey: { prfOutput: PRF.slice(), salt: PRF_SALT.slice() },
  });
  check("worker refuses §4.8 with a passkey", refused?.ok === false && refused?.code === "invalid-input", JSON.stringify({ ok: refused?.ok, code: refused?.code }));
  check("worker writes nothing when it refuses", refused?.data === undefined);
}

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) {
  console.log("Access policy test FAILED.");
  process.exit(1);
}
console.log("Access policy agrees with the worker.");
