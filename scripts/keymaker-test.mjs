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
 *   node scripts/keymaker-test.mjs fuzz       → run the parser fuzzer
 *   node scripts/keymaker-test.mjs generate   → regenerate fixtures
 */
import { build } from "esbuild";
import { pathToFileURL, fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
const HERE = dirname(fileURLToPath(import.meta.url));

const ENTRY_BY_MODE = {
  generate: "keymaker-generate-fixtures.mts",
  fuzz: "keymaker-fuzz.mts",
  regression: "keymaker-regression.mts",
};
const mode = ENTRY_BY_MODE[process.argv[2]] ? process.argv[2] : "regression";
const entry = join(HERE, ENTRY_BY_MODE[mode]);
// Output lives next to the entries so import.meta.url-based fixture paths
// (scripts/, scripts/fixtures/) keep working in the bundle.
const outfile = join(HERE, `.${mode}.build.mjs`);

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
