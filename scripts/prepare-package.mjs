#!/usr/bin/env node
/**
 * Post-build fixup for the wasm-pack output in pkg/.
 *
 * - renames the package to <scope>/tari-l1-wasm
 * - ensures LICENSE/README/files are declared
 * - sanity-checks the .wasm artifact exists
 *
 * Usage: node scripts/prepare-package.mjs --scope @your-scope [--out-dir pkg]
 */
import { readFileSync, writeFileSync, existsSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const crateDir = join(dirname(fileURLToPath(import.meta.url)), "..");

function parseArgs() {
  const args = process.argv.slice(2);
  const get = (flag) => {
    const i = args.indexOf(flag);
    return i >= 0 ? args[i + 1] : undefined;
  };
  const scope = get("--scope");
  if (!scope || !/^@[a-z0-9-_.]+$/.test(scope)) {
    console.error("Usage: prepare-package.mjs --scope @your-npm-scope [--out-dir pkg]");
    process.exit(1);
  }
  return { scope, outDir: get("--out-dir") ?? "pkg" };
}

const { scope, outDir } = parseArgs();
const pkgPath = join(crateDir, outDir, "package.json");
if (!existsSync(pkgPath)) {
  console.error(`No ${pkgPath} found. Run wasm-pack build first.`);
  process.exit(1);
}

const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
pkg.name = `${scope}/tari-l1-wasm`;
pkg.description =
  pkg.description ?? "WebAssembly bindings for Tari L1 core primitives";
pkg.files = Array.from(
  new Set([
    ...(pkg.files ?? []),
    "tari_l1_wasm_bg.wasm",
    "tari_l1_wasm.js",
    "tari_l1_wasm_bg.js",
    "tari_l1_wasm.d.ts",
    "tari_l1_wasm_bg.wasm.d.ts",
    "LICENSE",
    "README.md",
  ]),
);
pkg.repository = {
  type: "git",
  url: "https://github.com/tari-project/tari",
  directory: "base_layer/tari_l1_wasm",
};
pkg.keywords = ["tari", "minotari", "wasm", "webassembly", "blockchain", "crypto"];
pkg.publishConfig = { access: "public" };

// Verify the wasm binary is present and non-trivial
const wasmPath = join(crateDir, outDir, "tari_l1_wasm_bg.wasm");
if (!existsSync(wasmPath)) {
  console.error("Missing tari_l1_wasm_bg.wasm — incomplete build?");
  process.exit(1);
}
const size = statSync(wasmPath).size;
if (size < 100_000) {
  console.error(`wasm suspiciously small (${size} bytes) — refusing to publish`);
  process.exit(1);
}

writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + "\n");
console.log(`Prepared ${pkg.name} v${pkg.version} (${(size / 1024).toFixed(0)} KB wasm)`);
