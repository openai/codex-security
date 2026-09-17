#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const root = fileURLToPath(new URL("../../native/", import.meta.url));

await build({
  entryPoints: (await readdir(root))
    .filter((name) => name.endsWith(".mts"))
    .map((name) => join(root, name)),
  outdir: root,
  outExtension: { ".js": ".mjs" },
  format: "esm",
  platform: "node",
  target: "node20"
});

execFileSync("cargo", ["fetch", "--locked"], {
  cwd: root,
  stdio: "inherit"
});

for (const script of ["build.mjs", "notices.mjs"]) {
  execFileSync(process.execPath, [join(root, script)], {
    cwd: root,
    stdio: "inherit"
  });
}
