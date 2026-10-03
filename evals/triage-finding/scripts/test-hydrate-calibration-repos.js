#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const childProcess = require("node:child_process");
const path = require("node:path");

const evalDir = path.join(__dirname, "..");
const scriptPath = path.join(evalDir, "scripts", "hydrate-calibration-repos.js");

function runHydrator(args) {
  return childProcess.execFileSync(process.execPath, [scriptPath, ...args], {
    cwd: evalDir,
    encoding: "utf8",
  });
}

const allOutput = runHydrator(["--dry-run"]);
assert.match(allOutput, /would hydrate 16 calibration variants/);
assert.match(allOutput, /oss-mantisbt-ghsa-73vx-49mv-v8w5\/vulnerable/);
assert.match(allOutput, /https:\/\/github\.com\/mantisbt\/mantisbt/);
assert.match(allOutput, /80990f43153167c73f11eb4b2bc7108d0c3d6b46/);

const filteredOutput = runHydrator(["--dry-run", "--case", "oss-mantisbt-ghsa-73vx-49mv-v8w5", "--variant", "fixed"]);
assert.match(filteredOutput, /would hydrate 1 calibration variant/);
assert.match(filteredOutput, /oss-mantisbt-ghsa-73vx-49mv-v8w5\/fixed/);
assert.doesNotMatch(filteredOutput, /oss-mantisbt-ghsa-73vx-49mv-v8w5\/vulnerable/);

console.log("calibration hydration dry-run tests passed");
