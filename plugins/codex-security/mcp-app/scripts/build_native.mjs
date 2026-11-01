#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { join, resolve } from "node:path";
import { buildNativeWrappers } from "./build_native_wrappers.mjs";

const root = resolve(import.meta.dirname, "../../native");

await buildNativeWrappers();

execFileSync("cargo", ["fetch", "--locked"], {
  cwd: root,
  stdio: "inherit",
});

for (const script of ["build.mjs", "notices.mjs"]) {
  execFileSync(process.execPath, [join(root, script)], {
    cwd: root,
    stdio: "inherit",
  });
}
