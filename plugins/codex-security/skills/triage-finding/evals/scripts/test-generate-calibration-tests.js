#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const evalDir = path.resolve(__dirname, "..");
const generator = path.join(evalDir, "scripts", "generate-calibration-tests.js");
const dataset = path.join(evalDir, "datasets", "triage-calibration-seed.json");
const trackedTests = path.join(evalDir, "tests", "calibration-oss.yaml");

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triage-calibration-tests-"));
const generated = path.join(tmpDir, "calibration-oss.yaml");
const generatedSmoke = path.join(tmpDir, "calibration-smoke.yaml");

execFileSync(process.execPath, [generator, "--dataset", dataset, "--output", generated], {
  cwd: evalDir,
  stdio: "pipe",
});

const generatedYaml = fs.readFileSync(generated, "utf8");
const trackedYaml = fs.readFileSync(trackedTests, "utf8");

assert.equal(generatedYaml, trackedYaml, "tracked calibration tests are stale; run calibration:generate");
assert.match(generatedYaml, /case_id: oss-mantisbt-ghsa-73vx-49mv-v8w5-vulnerable/);
assert.match(generatedYaml, /case_id: oss-mantisbt-ghsa-73vx-49mv-v8w5-fixed/);
assert.match(generatedYaml, /expected_verdicts: confirmed/);
assert.match(generatedYaml, /expected_verdicts: not_actionable/);
assert.match(generatedYaml, /target_repo: plugins\/codex-security\/skills\/triage-finding\/evals\/artifacts\/calibration-repos\//);
assert.doesNotMatch(
  generatedYaml,
  /expected_evidence_terms:\n\s+- /,
  "Promptfoo expands array-valued vars into extra test cases; evidence terms must be a scalar",
);

execFileSync(
  process.execPath,
  [
    generator,
    "--dataset",
    dataset,
    "--output",
    generatedSmoke,
    "--case",
    "oss-dompurify-ghsa-v8jm-5vwx-cfxm",
    "--variant",
    "vulnerable",
  ],
  {
    cwd: evalDir,
    stdio: "pipe",
  },
);

const smokeYaml = fs.readFileSync(generatedSmoke, "utf8");
assert.equal((smokeYaml.match(/^- description:/gm) || []).length, 1);
assert.match(smokeYaml, /case_id: oss-dompurify-ghsa-v8jm-5vwx-cfxm-vulnerable/);
assert.doesNotMatch(smokeYaml, /case_id: oss-dompurify-ghsa-v8jm-5vwx-cfxm-fixed/);

console.log("calibration test generation matches tracked YAML and supports filtered smoke output");
