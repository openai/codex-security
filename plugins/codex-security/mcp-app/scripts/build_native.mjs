#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { join, resolve } from "node:path";

const app = resolve(import.meta.dirname, "..");
const native = join(app, "../native");

execFileSync(
  process.execPath,
  [
    join(app, "node_modules/typescript/bin/tsc"),
    "--project",
    join(app, "tsconfig.native.json"),
  ],
  { cwd: app, stdio: "inherit" },
);

execFileSync(process.execPath, ["build.mjs"], {
  cwd: native,
  stdio: "inherit",
});
// Notices include every locked dependency, including those for other targets.
execFileSync("cargo", ["fetch", "--locked"], { cwd: native, stdio: "inherit" });
execFileSync(process.execPath, ["notices.mjs"], {
  cwd: native,
  stdio: "inherit",
});
