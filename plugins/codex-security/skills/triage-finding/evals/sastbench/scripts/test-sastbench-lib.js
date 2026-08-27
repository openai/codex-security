#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");

const {
  REPRESENTATIVE_SAMPLE_SPEC,
  buildPromptVars,
  buildStateJobs,
  generatePromptfooTests,
  generateRepresentativeSampleTests,
  opaqueCaseId,
  repositoryStateId,
  selectRepresentativeSample,
  validateDataset,
} = require("./sastbench-lib");
const { generateSampleTests, generateTests } = require("./generate-sastbench-tests");

assert.deepEqual(REPRESENTATIVE_SAMPLE_SPEC, {
  profile: "representative-100-v1",
  seed: "sastbench-representative-v1",
  labelCounts: {
    true_positive: 40,
    false_positive: 60,
  },
});

function benchmarkRecord(overrides = {}) {
  return {
    finding_id: "upstream-label-bearing-id",
    repo_name: "example/project",
    repo_url: "https://github.com/example/project",
    commit_hash: "0123456789abcdef0123456789abcdef01234567",
    ground_truth: "true_positive",
    metadata: {
      source: "cve",
      cwe_id: "CWE-79",
    },
    to_analyzer: {
      vulnerability_type: "CWE-79",
      vulnerability_name: "Cross-site Scripting",
      description: "Untrusted text may be rendered without context-aware escaping.",
      locations: [
        {
          file: "src/render.js",
          function: "renderComment",
          line_start: 41,
          line_end: 47,
        },
      ],
      commit_context: {
        repo: "example/project",
        commit: "0123456789abcdef0123456789abcdef01234567",
      },
    },
    ...overrides,
  };
}

const positive = benchmarkRecord();
const negative = benchmarkRecord({
  finding_id: "another-label-bearing-id",
  ground_truth: "false_positive",
});
const targetRoot = path.resolve("/tmp/sastbench-targets");

validateDataset([positive, negative], {
  caseCount: 2,
  labelCounts: { true_positive: 1, false_positive: 1 },
});

const sparseScannerRecord = benchmarkRecord({
  to_analyzer: {
    ...positive.to_analyzer,
    vulnerability_name: "",
    description: "",
    locations: [
      {
        file: "src/file-level.js",
        function: "*global*",
        line_start: 0,
        line_end: 100,
      },
      {
        file: "src/zero-width.js",
        function: "construct",
        line_start: 54,
        line_end: 53,
      },
    ],
  },
});
validateDataset([sparseScannerRecord], {
  caseCount: 1,
  labelCounts: { true_positive: 1, false_positive: 0 },
});
const sparsePromptVars = buildPromptVars(sparseScannerRecord, 0, targetRoot);
assert.match(sparsePromptVars.finding_input, /title: CWE-79\n/);
assert.doesNotMatch(sparsePromptVars.finding_input, /claim:\s*\n/);
assert.match(sparsePromptVars.finding_input, /src\/file-level\.js:0-100/);
assert.match(sparsePromptVars.finding_input, /src\/zero-width\.js:54-53/);

assert.equal(opaqueCaseId(0), "sastbench-000000");
assert.equal(opaqueCaseId(2736), "sastbench-002736");
assert.throws(() => opaqueCaseId(-1), /non-negative integer/);

const stateId = repositoryStateId(positive);
assert.match(stateId, /^state-[a-f0-9]{16}$/);
assert.equal(repositoryStateId(negative), stateId);

const jobs = buildStateJobs([positive, negative], targetRoot);
assert.equal(jobs.length, 1);
assert.equal(jobs[0].cases.length, 2);
assert.equal(jobs[0].repoUrl, positive.repo_url);
assert.equal(jobs[0].commitHash, positive.commit_hash);
assert.equal(jobs[0].targetDir, path.join(targetRoot, stateId));

const promptVars = buildPromptVars(positive, 0, targetRoot);
assert.equal(promptVars.case_id, "sastbench-000000");
assert.equal(promptVars.target_repo, path.join(targetRoot, stateId));
assert.match(promptVars.finding_input, /CWE-79/);
assert.match(promptVars.finding_input, /src\/render\.js:41-47/);
assert.equal("invocation_preamble" in promptVars, false);
assert.equal("eval_instructions" in promptVars, false);
assert.equal("source_type_under_test" in promptVars, false);
assert.equal("expected_input_id" in promptVars, false);

const renderedModelInput = JSON.stringify({
  case_id: promptVars.case_id,
  target_repo: promptVars.target_repo,
  finding_input: promptVars.finding_input,
});
assert.doesNotMatch(
  renderedModelInput,
  /true_positive|false_positive|ground_truth|upstream-label-bearing-id|"source":"cve"/,
);

const tests = generatePromptfooTests([positive, negative], targetRoot);
assert.equal(tests.length, 2);
assert.equal(tests[0].metadata.ground_truth, "true_positive");
assert.equal(tests[1].metadata.ground_truth, "false_positive");
assert.equal("expected_ground_truth" in tests[0].vars, false);
assert.equal(tests[0].metadata.case_id, "sastbench-000000");
assert.deepEqual(Object.keys(tests[0].vars).sort(), ["case_id", "finding_input", "target_repo"]);

const generatedTests = generateTests({ dataset: [positive, negative], targetRoot });
assert.deepEqual(generatedTests, tests);

const sampleDataset = Array.from({ length: 20 }, (_, index) => {
  const groundTruth = index % 5 < 2 ? "true_positive" : "false_positive";
  const locationCount = (index % 4) + 1;
  return benchmarkRecord({
    finding_id: `sample-${index}`,
    repo_name: `example/project-${index % 5}`,
    repo_url: `https://github.com/example/project-${index % 5}`,
    ground_truth: groundTruth,
    metadata: {
      source: groundTruth === "true_positive" ? "cve" : "semgrep",
      cwe_id: `CWE-${79 + (index % 3)}`,
      languages: [index % 2 === 0 ? "JavaScript" : "Python"],
    },
    to_analyzer: {
      ...positive.to_analyzer,
      locations: Array.from({ length: locationCount }, (_, locationIndex) => ({
        file: `src/file-${index}-${locationIndex}.js`,
        function: "handle",
        line_start: locationIndex + 1,
        line_end: locationIndex + 2,
      })),
    },
  });
});
const sampleSpec = {
  profile: "test-representative",
  seed: "test-seed",
  labelCounts: { true_positive: 4, false_positive: 6 },
};
const selectedSample = selectRepresentativeSample(sampleDataset, sampleSpec);
const selectedAgain = selectRepresentativeSample(sampleDataset, sampleSpec);

assert.equal(selectedSample.length, 10);
assert.deepEqual(
  selectedSample.map(({ index }) => index),
  selectedAgain.map(({ index }) => index),
);
assert.equal(new Set(selectedSample.map(({ index }) => index)).size, selectedSample.length);
assert.equal(
  selectedSample.filter(({ record }) => record.ground_truth === "true_positive").length,
  4,
);
assert.equal(
  selectedSample.filter(({ record }) => record.ground_truth === "false_positive").length,
  6,
);
for (const label of ["true_positive", "false_positive"]) {
  const populationCount = sampleDataset.filter((record) => record.ground_truth === label).length;
  const representedPopulation = selectedSample
    .filter(({ record }) => record.ground_truth === label)
    .reduce((total, entry) => total + entry.sampleWeight, 0);
  assert.ok(Math.abs(representedPopulation - populationCount) < 1e-9);
}

const representativeTests = generateRepresentativeSampleTests(
  sampleDataset,
  targetRoot,
  sampleSpec,
);
assert.equal(representativeTests.length, 10);
assert.ok(
  representativeTests.some(
    (test) => Number(test.metadata.case_id.replace("sastbench-", "")) >= 10,
  ),
);
assert.ok(representativeTests.every((test) => test.metadata.sample_profile === sampleSpec.profile));
assert.ok(representativeTests.every((test) => test.metadata.sample_weight > 0));
assert.ok(representativeTests.every((test) => "sample_stratum" in test.metadata));
assert.ok(representativeTests.every((test) => !("sample_weight" in test.vars)));

const generatedSampleTests = generateSampleTests({
  dataset: sampleDataset,
  targetRoot,
  sampleSpec,
});
assert.deepEqual(generatedSampleTests, representativeTests);

assert.throws(
  () =>
    validateDataset([benchmarkRecord({ ground_truth: "unknown" })], {
      caseCount: 1,
      labelCounts: { true_positive: 0, false_positive: 1 },
    }),
  /unsupported ground_truth/,
);
assert.throws(
  () =>
    validateDataset(
      [
        benchmarkRecord({
          to_analyzer: {
            ...positive.to_analyzer,
            commit_context: { repo: "example/project", commit: "different" },
          },
        }),
      ],
      { caseCount: 1, labelCounts: { true_positive: 1, false_positive: 0 } },
    ),
  /commit_context\.commit/,
);

console.log("sastbench dataset and prompt tests passed");
