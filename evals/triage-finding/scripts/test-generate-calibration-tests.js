#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { findingInput, variantCaseId } = require("./generate-calibration-tests");
const { plannedJobs } = require("./hydrate-calibration-repos");

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
const cases = JSON.parse(fs.readFileSync(dataset, "utf8")).cases;
const identities = new Set();
for (const testCase of cases) {
  for (const variant of testCase.variants) {
    const caseId = variantCaseId(testCase, variant);
    assert.match(caseId, /^calibration-[a-f0-9]{16}$/);
    assert.ok(!identities.has(caseId));
    identities.add(caseId);
    assert.equal(variantCaseId(testCase, { ...variant, variant_id: "renamed", expected_verdict: "needs_review" }), caseId);
    const input = findingInput(testCase, variant);
    assert.ok(!input.includes(variant.checkout_ref));
    assert.ok(!input.includes(testCase.finding.fix_patch_ref));
    assert.doesNotMatch(input, /-(?:vulnerable|fixed)\b/);
    const repoRoot = path.join(tmpDir, "targets");
    const [job] = plannedJobs({ cases: [{ ...testCase, variants: [variant] }] }, { repoRoot });
    assert.equal(job.targetDir, path.join(repoRoot, caseId));
    assert.ok(generatedYaml.includes(`    calibration_repo: ${caseId}`));
  }
}
assert.match(generatedYaml, /expected_verdicts: confirmed/);
assert.match(generatedYaml, /expected_verdicts: not_actionable/);
assert.match(generatedYaml, /calibration_repo_root: ""/);
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
    "--repo-root",
    path.join(tmpDir, "custom targets # space"),
  ],
  {
    cwd: evalDir,
    stdio: "pipe",
  },
);

const smokeYaml = fs.readFileSync(generatedSmoke, "utf8");
assert.equal((smokeYaml.match(/^- description:/gm) || []).length, 1);
assert.ok(smokeYaml.includes(`calibration_repo_root: ${JSON.stringify(path.join(tmpDir, "custom targets # space"))}`));
const smokeCase = cases.find((testCase) => testCase.case_id === "oss-dompurify-ghsa-v8jm-5vwx-cfxm");
assert.ok(smokeYaml.includes(`case_id: ${variantCaseId(smokeCase, smokeCase.variants.find((variant) => variant.variant_id === "vulnerable"))}`));
assert.ok(!smokeYaml.includes(`case_id: ${variantCaseId(smokeCase, smokeCase.variants.find((variant) => variant.variant_id === "fixed"))}`));
fs.rmSync(tmpDir, { recursive: true, force: true });

console.log("calibration test generation matches tracked YAML and supports filtered smoke output");
