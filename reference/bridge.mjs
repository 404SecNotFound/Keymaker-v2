/**
 * esbuild runner for bridge.mts.
 *
 * Same reason as scripts/keymaker-test.mjs: the crypto core lazy-imports
 * hash-wasm and @noble/ciphers, which needs real ESM semantics, so the entry
 * point is bundled to a single ESM file and executed.
 */
import { build } from "esbuild";
import { pathToFileURL, fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const outfile = join(HERE, ".bridge.build.mjs");

await build({
  entryPoints: [join(HERE, "bridge.mts")],
  outfile,
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node20",
  logLevel: "warning",
});

await import(pathToFileURL(outfile).href);
