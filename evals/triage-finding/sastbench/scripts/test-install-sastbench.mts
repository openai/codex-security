#!/usr/bin/env node
import assert from "node:assert/strict";

import { verifyInstallation } from "./install-sastbench.mts";
import {
  EXPECTED_CASE_COUNT,
  EXPECTED_LABEL_COUNTS,
  SASTBENCH_COMMIT,
  SASTBENCH_DATASET_SHA256,
  SASTBENCH_REPOSITORY_URL,
} from "./sastbench-lib.mts";

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
  () =>
    verifyInstallation(
      validInspection({ origin: "https://example.test/wrong.git" }),
    ),
  /origin mismatch/,
);
assert.throws(
  () => verifyInstallation(validInspection({ head: "0".repeat(40) })),
  /commit mismatch/,
);
assert.throws(
  () => verifyInstallation(validInspection({ clean: false })),
  /local changes/,
);
assert.throws(
  () => verifyInstallation(validInspection({ datasetSha256: "0".repeat(64) })),
  /dataset SHA-256 mismatch/,
);

console.log("sastbench installer verification tests passed");
