#!/usr/bin/env node
"use strict";

const childProcess = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const {
  DEFAULT_INSTALL_ROOT,
  EXPECTED_CASE_COUNT,
  EXPECTED_LABEL_COUNTS,
  SASTBENCH_COMMIT,
  SASTBENCH_DATASET_RELATIVE_PATH,
  SASTBENCH_DATASET_SHA256,
  SASTBENCH_REPOSITORY_URL,
  sha256File,
  validateDataset,
} = require("./sastbench-lib");

function parseArgs(argv) {
  const args = { target: DEFAULT_INSTALL_ROOT, dryRun: false };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--") {
      continue;
    } else if (arg === "--target") {
      args.target = argv[++index];
    } else if (arg === "--dry-run") {
      args.dryRun = true;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return { ...args, target: path.resolve(args.target) };
}

function runGit(args, cwd) {
  return childProcess.execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function gitOutput(args, cwd) {
  return runGit(args, cwd).trim();
}

function inspectInstallation(target) {
  const resolvedTarget = path.resolve(target);
  if (!fs.existsSync(path.join(resolvedTarget, ".git"))) {
    throw new Error(`SastBench target is not a Git checkout: ${resolvedTarget}`);
  }
  const datasetPath = path.join(resolvedTarget, SASTBENCH_DATASET_RELATIVE_PATH);
  if (!fs.existsSync(datasetPath)) {
    throw new Error(`SastBench dataset is missing: ${datasetPath}`);
  }
  const records = JSON.parse(fs.readFileSync(datasetPath, "utf8"));
  const datasetSummary = validateDataset(records);
  return {
    origin: gitOutput(["remote", "get-url", "origin"], resolvedTarget),
    head: gitOutput(["rev-parse", "HEAD"], resolvedTarget),
    clean: gitOutput(["status", "--porcelain", "--untracked-files=all"], resolvedTarget) === "",
    datasetSha256: sha256File(datasetPath),
    caseCount: datasetSummary.caseCount,
    labelCounts: datasetSummary.labelCounts,
  };
}

function verifyInstallation(inspection) {
  if (inspection.origin !== SASTBENCH_REPOSITORY_URL) {
    throw new Error(
      `SastBench origin mismatch: expected ${SASTBENCH_REPOSITORY_URL}, got ${inspection.origin}`,
    );
  }
  if (inspection.head !== SASTBENCH_COMMIT) {
    throw new Error(
      `SastBench commit mismatch: expected ${SASTBENCH_COMMIT}, got ${inspection.head}`,
    );
  }
  if (!inspection.clean) {
    throw new Error("SastBench checkout has local changes; refusing to replace or discard them");
  }
  if (inspection.datasetSha256 !== SASTBENCH_DATASET_SHA256) {
    throw new Error(
      `SastBench dataset SHA-256 mismatch: expected ${SASTBENCH_DATASET_SHA256}, got ${inspection.datasetSha256}`,
    );
  }
  if (inspection.caseCount !== EXPECTED_CASE_COUNT) {
    throw new Error(
      `SastBench case count mismatch: expected ${EXPECTED_CASE_COUNT}, got ${inspection.caseCount}`,
    );
  }
  for (const [label, expected] of Object.entries(EXPECTED_LABEL_COUNTS)) {
    const actual = inspection.labelCounts?.[label];
    if (actual !== expected) {
      throw new Error(`SastBench ${label} count mismatch: expected ${expected}, got ${actual}`);
    }
  }
  return inspection;
}

function createInstallation(target) {
  fs.mkdirSync(target, { recursive: true });
  if (fs.readdirSync(target).length !== 0) {
    throw new Error(`Refusing to install into non-empty directory: ${target}`);
  }
  runGit(["init"], target);
  runGit(["remote", "add", "origin", SASTBENCH_REPOSITORY_URL], target);
  runGit(["fetch", "--depth", "1", "origin", SASTBENCH_COMMIT], target);
  runGit(["checkout", "--detach", "FETCH_HEAD"], target);
}

function installSastBench(target = DEFAULT_INSTALL_ROOT) {
  const resolvedTarget = path.resolve(target);
  if (!fs.existsSync(resolvedTarget)) {
    fs.mkdirSync(path.dirname(resolvedTarget), { recursive: true });
    createInstallation(resolvedTarget);
  }
  return verifyInstallation(inspectInstallation(resolvedTarget));
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.dryRun) {
    console.log(`would install SastBench ${SASTBENCH_COMMIT} into ${args.target}`);
    return;
  }
  const inspection = installSastBench(args.target);
  console.log(
    `verified SastBench ${inspection.head}: ${inspection.caseCount} cases ` +
      `(${inspection.labelCounts.true_positive} true_positive, ` +
      `${inspection.labelCounts.false_positive} false_positive)`,
  );
}

if (require.main === module) {
  main();
}

module.exports = {
  parseArgs,
  inspectInstallation,
  verifyInstallation,
  installSastBench,
};
