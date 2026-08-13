/**
 * Runner for the Keymaker crypto tests.
 *
 * The crypto core uses lazy `import()` of hash-wasm / @noble/ciphers, which
 * needs real ESM semantics; Node 20 cannot execute .mts directly and tsx's
 * CJS interop breaks those dynamic imports. So we bundle the entry point
 * with esbuild (already a transitive dep via tsx) into a single ESM file
 * and execute that.
 *
 *   node scripts/keymaker-test.mjs            → run the regression suite
 *   node scripts/keymaker-test.mjs generate   → regenerate fixtures
 */
import { build } from "esbuild";
import { pathToFileURL, fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
const HERE = dirname(fileURLToPath(import.meta.url));
const generate = process.argv[2] === "generate";
const entry = join(
  HERE,
  generate ? "keymaker-generate-fixtures.mts" : "keymaker-regression.mts"
);
// Output lives next to the entries so import.meta.url-based fixture paths
// (scripts/, scripts/fixtures/) keep working in the bundle.
const outfile = join(HERE, generate ? ".generate.build.mjs" : ".regression.build.mjs");

await build({
  entryPoints: [entry],
  outfile,
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node20",
  logLevel: "warning",
});

await import(pathToFileURL(outfile).href);
