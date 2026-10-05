#!/usr/bin/env node
import assert from "node:assert/strict";
import childProcess from "node:child_process";
import path from "node:path";

const evalDir = path.join(import.meta.dirname, "..");
const scriptPath = path.join(
  evalDir,
  "scripts",
  "hydrate-calibration-repos.mts",
);

function runHydrator(args: string[]) {
  return childProcess.execFileSync(
    process.execPath,
    ["--experimental-strip-types", scriptPath, ...args],
    {
      cwd: evalDir,
      encoding: "utf8",
    },
  );
}

const allOutput = runHydrator(["--dry-run"]);
assert.match(allOutput, /would hydrate 16 calibration variants/);
assert.match(allOutput, /oss-mantisbt-ghsa-73vx-49mv-v8w5\/vulnerable/);
assert.match(allOutput, /https:\/\/github\.com\/mantisbt\/mantisbt/);
assert.match(allOutput, /80990f43153167c73f11eb4b2bc7108d0c3d6b46/);

const filteredOutput = runHydrator([
  "--dry-run",
  "--case",
  "oss-mantisbt-ghsa-73vx-49mv-v8w5",
  "--variant",
  "fixed",
]);
assert.match(filteredOutput, /would hydrate 1 calibration variant/);
assert.match(filteredOutput, /oss-mantisbt-ghsa-73vx-49mv-v8w5\/fixed/);
assert.doesNotMatch(
  filteredOutput,
  /oss-mantisbt-ghsa-73vx-49mv-v8w5\/vulnerable/,
);

console.log("calibration hydration dry-run tests passed");
