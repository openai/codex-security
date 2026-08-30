#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");

const { verifyInstallation } = require("./install-sastbench");
const {
  EXPECTED_CASE_COUNT,
  EXPECTED_LABEL_COUNTS,
  SASTBENCH_COMMIT,
  SASTBENCH_DATASET_SHA256,
  SASTBENCH_REPOSITORY_URL,
} = require("./sastbench-lib");

function validInspection(overrides = {}) {
  return {
    origin: SASTBENCH_REPOSITORY_URL,
    head: SASTBENCH_COMMIT,
    clean: true,
    datasetSha256: SASTBENCH_DATASET_SHA256,
    caseCount: EXPECTED_CASE_COUNT,
    labelCounts: { ...EXPECTED_LABEL_COUNTS },
    ...overrides,
  };
}

assert.deepEqual(verifyInstallation(validInspection()), validInspection());
assert.throws(
  () => verifyInstallation(validInspection({ origin: "https://example.test/wrong.git" })),
  /origin mismatch/,
);
assert.throws(
  () => verifyInstallation(validInspection({ head: "0".repeat(40) })),
  /commit mismatch/,
);
assert.throws(() => verifyInstallation(validInspection({ clean: false })), /local changes/);
assert.throws(
  () => verifyInstallation(validInspection({ datasetSha256: "0".repeat(64) })),
  /dataset SHA-256 mismatch/,
);
assert.throws(
  () => verifyInstallation(validInspection({ caseCount: EXPECTED_CASE_COUNT - 1 })),
  /case count mismatch/,
);
assert.throws(
  () =>
    verifyInstallation(
      validInspection({
        labelCounts: { true_positive: 300, false_positive: 2437 },
      }),
    ),
  /true_positive count mismatch/,
);

console.log("sastbench installer verification tests passed");
