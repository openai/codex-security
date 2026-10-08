#!/usr/bin/env node
import { hash } from "node:crypto";
import { runGit } from "./hydrate-sastbench-repos.mts";
import fs from "node:fs";
import path from "node:path";

import {
  DEFAULT_INSTALL_ROOT,
  SASTBENCH_COMMIT,
  SASTBENCH_DATASET_RELATIVE_PATH,
  SASTBENCH_DATASET_SHA256,
  SASTBENCH_REPOSITORY_URL,
  validateDataset,
} from "./sastbench-lib.mts";

export function parseArgs(argv: string[]) {
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

export function inspectInstallation(target: string) {
  const resolvedTarget = path.resolve(target);
  if (!fs.existsSync(path.join(resolvedTarget, ".git"))) {
    throw new Error(
      `SastBench target is not a Git checkout: ${resolvedTarget}`,
    );
  }
  const datasetPath = path.join(
    resolvedTarget,
    SASTBENCH_DATASET_RELATIVE_PATH,
  );
  if (!fs.existsSync(datasetPath)) {
    throw new Error(`SastBench dataset is missing: ${datasetPath}`);
  }
  const records = JSON.parse(fs.readFileSync(datasetPath, "utf8"));
  const datasetSummary = validateDataset(records);
  return {
    origin: runGit(["remote", "get-url", "origin"], resolvedTarget),
    head: runGit(["rev-parse", "HEAD"], resolvedTarget),
    clean:
      runGit(
        ["status", "--porcelain", "--untracked-files=all"],
        resolvedTarget,
      ) === "",
    datasetSha256: hash("sha256", fs.readFileSync(datasetPath)),
    caseCount: datasetSummary.caseCount,
    labelCounts: datasetSummary.labelCounts,
  };
}

export function verifyInstallation(
  inspection: ReturnType<typeof inspectInstallation>,
) {
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
    throw new Error(
      "SastBench checkout has local changes; refusing to replace or discard them",
    );
  }
  if (inspection.datasetSha256 !== SASTBENCH_DATASET_SHA256) {
    throw new Error(
      `SastBench dataset SHA-256 mismatch: expected ${SASTBENCH_DATASET_SHA256}, got ${inspection.datasetSha256}`,
    );
  }
  return inspection;
}

function createInstallation(target: string) {
  fs.mkdirSync(target, { recursive: true });
  if (fs.readdirSync(target).length !== 0) {
    throw new Error(`Refusing to install into non-empty directory: ${target}`);
  }
  runGit(["init"], target);
  runGit(["remote", "add", "origin", SASTBENCH_REPOSITORY_URL], target);
  runGit(["fetch", "--depth", "1", "origin", SASTBENCH_COMMIT], target);
  runGit(["checkout", "--detach", "FETCH_HEAD"], target);
}

export function installSastBench(target: string = DEFAULT_INSTALL_ROOT) {
  const resolvedTarget = path.resolve(target);
  if (!fs.existsSync(resolvedTarget)) {
    fs.mkdirSync(path.dirname(resolvedTarget), { recursive: true });
    createInstallation(resolvedTarget);
  }
  return verifyInstallation(inspectInstallation(resolvedTarget));
}

if (import.meta.filename === fs.realpathSync(process.argv[1])) {
  const args = parseArgs(process.argv.slice(2));
  if (args.dryRun) {
    console.log(
      `would install SastBench ${SASTBENCH_COMMIT} into ${args.target}`,
    );
  } else {
    const inspection = installSastBench(args.target);
    console.log(
      `verified SastBench ${inspection.head}: ${inspection.caseCount} cases ` +
        `(${inspection.labelCounts.true_positive} true_positive, ` +
        `${inspection.labelCounts.false_positive} false_positive)`,
    );
  }
}
