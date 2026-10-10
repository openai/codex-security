#!/usr/bin/env node
import assert from "node:assert/strict";

import { syncBuiltinESMExports } from "node:module";
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

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import childProcess from "node:child_process";
import { installSastBench } from "./install-sastbench.mts";
const root = fs.mkdtempSync(path.join(os.tmpdir(), "sastbench-install-"));
const target = path.join(root, "checkout");
const originalExec = childProcess.execFileSync;
let fetches = 0;
try {
  childProcess.execFileSync = ((
    _command: string,
    args: string[],
    options: { cwd: string },
  ) => {
    if (args.includes("init")) fs.mkdirSync(path.join(options.cwd, ".git"));
    if (args.includes("fetch")) {
      fetches++;
      throw new Error("synthetic fetch failed");
    }
    return "";
  }) as typeof originalExec;
  syncBuiltinESMExports();
  for (let attempt = 0; attempt < 2; attempt++) {
    assert.throws(() => installSastBench(target), /synthetic fetch failed/);
    assert.equal(fs.existsSync(target), false);
  }
  assert.equal(
    fetches,
    2,
    "a retry must fetch again instead of inspecting an incomplete checkout",
  );
  fs.mkdirSync(target);
  fs.writeFileSync(path.join(target, "keep.txt"), "existing work");
  assert.throws(() => installSastBench(target), /not a Git checkout/);
  assert.equal(
    fs.readFileSync(path.join(target, "keep.txt"), "utf8"),
    "existing work",
  );
} finally {
  childProcess.execFileSync = originalExec;
  syncBuiltinESMExports();
  fs.rmSync(root, { recursive: true, force: true });
}

const raceRoot = fs.mkdtempSync(path.join(os.tmpdir(), "sastbench-race-"));
const raceTarget = path.join(raceRoot, "checkout");
const competingFile = path.join(raceTarget, "other-install.txt");
const originalExists = fs.existsSync;
try {
  fs.existsSync = (candidate) => {
    if (candidate === raceTarget && !originalExists(candidate)) {
      fs.mkdirSync(raceTarget);
      fs.writeFileSync(competingFile, "concurrent installation");
      return false;
    }
    return originalExists(candidate);
  };
  assert.throws(() => installSastBench(raceTarget), { code: "EEXIST" });
  assert.equal(
    fs.readFileSync(competingFile, "utf8"),
    "concurrent installation",
  );
} finally {
  fs.existsSync = originalExists;
  fs.rmSync(raceRoot, { recursive: true, force: true });
}
