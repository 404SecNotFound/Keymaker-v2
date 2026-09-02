#!/usr/bin/env node
/**
 * Execute docs/VERIFYING.md's mirroring recipe against a local copy of `out/`.
 *
 * The recipe was `wget -r`, and it did not work. A crawler follows links, and a
 * deployment contains files nothing links to, the error page, the service
 * worker, and the router payloads the app fetches at runtime. On the build this
 * was written against, **23 of 58 manifest entries were unreachable that way**,
 * so the documented procedure reported a third of an honest deployment as
 * FAILED. A verification step that cries wolf is worse than none: the first
 * thing it teaches is to ignore it.
 *
 * It is replaced by reading the manifest and fetching exactly what it names,
 * and this runs that block rather than a re-typed copy of it — the same reason
 * reference/recovery_test.py executes RECOVERY.md. The one substitution is the
 * base URL, which points at a local server here instead of the live site; the
 * fetch loop and the `sha256sum -c` line are the document's, verbatim.
 *
 * Not covered: the signature half. `out/` carries no SHA256SUMS.sigstore —
 * that is produced by the deploy workflow — so the bundle fetch in the block is
 * expected to fail here and is tolerated. What this pins is the file list and
 * the hashes, which is the half that silently broke.
 */
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const PORT = 8123;

let failures = 0;
function check(ok, label, detail = "") {
  console.log(`  ${ok ? "ok  " : "FAIL"} ${label}${ok || !detail ? "" : ` — ${detail}`}`);
  if (!ok) failures++;
}

/** The one fenced bash block containing the manifest check. */
function recipeBlock() {
  const doc = readFileSync(join(ROOT, "docs", "VERIFYING.md"), "utf8");
  const blocks = [...doc.matchAll(/```bash\n([\s\S]*?)```/g)].map((m) => m[1]);
  const found = blocks.filter((b) => b.includes("sha256sum -c SHA256SUMS"));
  if (found.length !== 1) {
    console.error(`expected exactly one bash block with the manifest check, found ${found.length}`);
    process.exit(1);
  }
  return found[0];
}

const block = recipeBlock();
check(!/wget\s+-r/.test(block), "the recipe no longer crawls the site with wget -r",
      "wget -r cannot reach files nothing links to");
check(block.includes("SHA256SUMS"), "the recipe reads the manifest");

const server = spawn("node", [join(ROOT, "scripts", "static-server.mjs"), join(ROOT, "out"), String(PORT)],
                     { stdio: "ignore" });
await new Promise((r) => setTimeout(r, 1500));

const work = mkdtempSync(join(tmpdir(), "keym-recipe-"));
try {
  // The document's block, with only the base URL redirected at the local copy.
  const local = block.replace(/^BASE=.*$/m, `BASE=http://127.0.0.1:${PORT}`);
  const run = spawnSync("bash", ["-c", local], { cwd: work, encoding: "utf8" });
  const okLines = (run.stdout.match(/: OK$/gm) || []).length;
  const manifest = readFileSync(join(ROOT, "out", "SHA256SUMS"), "utf8").trim().split("\n").length;

  check(run.status === 0,
        "the documented recipe reproduces the deployment and verifies clean",
        `exit ${run.status}: ${(run.stderr || "").split("\n").filter((l) => !l.includes("sigstore")).slice(-3).join(" | ")}`);
  check(okLines === manifest,
        `all ${manifest} manifest entries were fetched and matched`,
        `${okLines} of ${manifest} reported OK`);
} finally {
  server.kill();
  rmSync(work, { recursive: true, force: true });
}

console.log(failures === 0
  ? "\nVERIFYING.md's mirroring recipe works against a real build."
  : `\n${failures} check(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
