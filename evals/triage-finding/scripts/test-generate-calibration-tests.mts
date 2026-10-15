#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import { createRequire } from "node:module";
import runtimeVars from "./runtime-vars.mts";
import path from "node:path";
import { findingInput, variantCaseId } from "./generate-calibration-tests.mts";
import type { CalibrationCase } from "../types.ts";
import { plannedJobs } from "./hydrate-calibration-repos.mts";

const evalDir = path.resolve(import.meta.dirname, "..");
const generator = path.join(
  evalDir,
  "scripts",
  "generate-calibration-tests.mts",
);
const dataset = path.join(evalDir, "datasets", "triage-calibration-seed.json");
const require = createRequire(import.meta.url);
const { parse } = createRequire(require.resolve("promptfoo"))("yaml");
const trackedTests = path.join(evalDir, "tests", "calibration-oss.yaml");

const tmpDir = fs.realpathSync(
  fs.mkdtempSync(path.join(os.tmpdir(), "triage-calibration-tests-")),
);
const generated = path.join(tmpDir, "calibration-oss.yaml");
const generatedSmoke = path.join(tmpDir, "calibration-smoke.yaml");

execFileSync(
  process.execPath,
  [
    "--experimental-strip-types",
    generator,
    "--dataset",
    dataset,
    "--output",
    generated,
  ],
  {
    cwd: evalDir,
    stdio: "pipe",
  },
);

const generatedYaml = fs.readFileSync(generated, "utf8");
const trackedYaml = fs.readFileSync(trackedTests, "utf8");

assert.equal(
  generatedYaml,
  trackedYaml,
  "tracked calibration tests are stale; run calibration:generate",
);
const rows: {
  metadata: Record<string, string>;
  vars: Record<string, string>;
}[] = parse(generatedYaml);
assert.equal(rows.length, 16);
assert.equal(new Set(rows.map((row) => row.vars.case_id)).size, rows.length);
for (const row of rows) {
  assert.equal(row.metadata.case_id, row.vars.case_id);
  assert.equal(row.vars.expected_ids, row.vars.case_id);
  assert.equal(row.vars.calibration_repo, row.vars.case_id);
  assert.ok(row.vars.finding_input.includes(`input_id: ${row.vars.case_id}`));
}
const cases: CalibrationCase[] = JSON.parse(
  fs.readFileSync(dataset, "utf8"),
).cases;
const identities = new Set();
for (const testCase of cases) {
  for (const variant of testCase.variants) {
    const caseId = variantCaseId(testCase, variant);
    assert.match(caseId, /^calibration-[a-f0-9]{16}$/);
    assert.ok(!identities.has(caseId));
    identities.add(caseId);
    assert.equal(
      variantCaseId(testCase, {
        ...variant,
        variant_id: "renamed",
        expected_verdict: "needs_review",
      }),
      caseId,
    );
    const input = findingInput(testCase, variant);
    assert.ok(!input.includes(variant.checkout_ref));
    assert.ok(!input.includes(testCase.finding.fix_patch_ref!));
    assert.doesNotMatch(input, /-(?:vulnerable|fixed)\b/);
    const repoRoot = path.join(tmpDir, "targets");
    const [job] = plannedJobs(
      { cases: [{ ...testCase, variants: [variant] }] },
      { repoRoot },
    );
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
    "--experimental-strip-types",
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
    "custom targets # space",
  ],
  {
    cwd: tmpDir,
    stdio: "pipe",
  },
);

const smokeYaml = fs.readFileSync(generatedSmoke, "utf8");
assert.equal((smokeYaml.match(/^- description:/gm) || []).length, 1);
assert.ok(
  smokeYaml.includes(
    `calibration_repo_root: ${JSON.stringify(path.join(tmpDir, "custom targets # space"))}`,
  ),
);
const smokeCase = cases.find(
  (testCase) => testCase.case_id === "oss-dompurify-ghsa-v8jm-5vwx-cfxm",
)!;
assert.ok(
  smokeYaml.includes(
    `case_id: ${variantCaseId(
      smokeCase,
      smokeCase.variants.find(
        (variant) => variant.variant_id === "vulnerable",
      )!,
    )}`,
  ),
);
assert.ok(
  !smokeYaml.includes(
    `case_id: ${variantCaseId(
      smokeCase,
      smokeCase.variants.find((variant) => variant.variant_id === "fixed")!,
    )}`,
  ),
);
const smokeRows = parse(smokeYaml) as typeof rows;
const hydration = execFileSync(
  process.execPath,
  [
    "--experimental-strip-types",
    path.join(evalDir, "scripts", "hydrate-calibration-repos.mts"),
    "--case",
    "oss-dompurify-ghsa-v8jm-5vwx-cfxm",
    "--variant",
    "vulnerable",
    "--repo-root",
    path.join(tmpDir, "custom targets # space"),
    "--dry-run",
  ],
  { encoding: "utf8" },
);
assert.deepEqual(
  smokeRows.map((row) => runtimeVars(row.vars).target_repo),
  hydration
    .split("\n")
    .filter((line) => line.startsWith("  "))
    .map((line) => line.slice(2)),
);
fs.rmSync(tmpDir, { recursive: true, force: true });

console.log(
  "calibration test generation matches tracked YAML and supports filtered smoke output",
);
