#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { join, resolve } from "node:path";
import { build } from "esbuild";

const root = resolve(import.meta.dirname, "../../native");

await build({
  absWorkingDir: root,
  entryPoints: ["*.mts"],
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
