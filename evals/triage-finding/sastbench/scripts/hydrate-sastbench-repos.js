#!/usr/bin/env node
"use strict";

const childProcess = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const {
  DEFAULT_DATASET_PATH,
  DEFAULT_TARGET_ROOT,
  EVAL_ROOT,
  buildStateJobs,
  loadDataset,
  sha256Text,
} = require("./sastbench-lib");

const DEFAULT_CACHE_ROOT = path.join(EVAL_ROOT, "artifacts", "sastbench-git-cache");

function parseArgs(argv) {
  const args = {
    dataset: DEFAULT_DATASET_PATH,
    cacheRoot: DEFAULT_CACHE_ROOT,
    targetRoot: DEFAULT_TARGET_ROOT,
    dryRun: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--") {
      continue;
    } else if (arg === "--dataset") {
      args.dataset = argv[++index];
    } else if (arg === "--cache-root") {
      args.cacheRoot = argv[++index];
    } else if (arg === "--target-root") {
      args.targetRoot = argv[++index];
    } else if (arg === "--dry-run") {
      args.dryRun = true;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return {
    ...args,
    dataset: path.resolve(args.dataset),
    cacheRoot: path.resolve(args.cacheRoot),
    targetRoot: path.resolve(args.targetRoot),
  };
}

function repositoryCacheId(repoUrl) {
  return `repo-${sha256Text(repoUrl).slice(0, 16)}`;
}

function assertRepositoryNamesAreUnambiguous(records) {
  const urlsByName = new Map();
  for (const record of records) {
    const previous = urlsByName.get(record.repo_name);
    if (previous && previous !== record.repo_url) {
      throw new Error(
        `SastBench repository ${record.repo_name} maps to multiple repository URLs: ${previous}, ${record.repo_url}`,
      );
    }
    urlsByName.set(record.repo_name, record.repo_url);
  }
}

function buildHydrationPlan(records, { cacheRoot = DEFAULT_CACHE_ROOT, targetRoot = DEFAULT_TARGET_ROOT } = {}) {
  assertRepositoryNamesAreUnambiguous(records);
  const resolvedCacheRoot = path.resolve(cacheRoot);
  return buildStateJobs(records, targetRoot).map((job) => ({
    ...job,
    cacheId: repositoryCacheId(job.repoUrl),
    cacheDir: path.join(resolvedCacheRoot, `${repositoryCacheId(job.repoUrl)}.git`),
  }));
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

function bareGit(cacheDir, args) {
  return gitOutput([`--git-dir=${cacheDir}`, ...args], path.dirname(cacheDir));
}

function ensureRepositoryCache(job) {
  fs.mkdirSync(path.dirname(job.cacheDir), { recursive: true });
  if (!fs.existsSync(job.cacheDir)) {
    runGit(["init", "--bare", job.cacheDir], path.dirname(job.cacheDir));
    bareGit(job.cacheDir, ["remote", "add", "origin", job.repoUrl]);
  }
  if (bareGit(job.cacheDir, ["rev-parse", "--is-bare-repository"]) !== "true") {
    throw new Error(`SastBench Git cache is not bare: ${job.cacheDir}`);
  }
  const origin = bareGit(job.cacheDir, ["remote", "get-url", "origin"]);
  if (origin !== job.repoUrl) {
    throw new Error(
      `SastBench Git cache origin mismatch for ${job.repoName}: expected ${job.repoUrl}, got ${origin}`,
    );
  }
  bareGit(job.cacheDir, ["fetch", "--depth", "1", "origin", job.commitHash]);
  const fetchedCommit = bareGit(job.cacheDir, ["rev-parse", "FETCH_HEAD"]);
  if (fetchedCommit !== job.commitHash) {
    throw new Error(
      `SastBench fetched commit mismatch for ${job.repoName}: expected ${job.commitHash}, got ${fetchedCommit}`,
    );
  }
}

function inspectTarget(job) {
  const head = gitOutput(["rev-parse", "HEAD"], job.targetDir);
  const clean = gitOutput(["status", "--porcelain", "--untracked-files=all"], job.targetDir) === "";
  const origin = gitOutput(["remote", "get-url", "origin"], job.targetDir);
  if (head !== job.commitHash) {
    throw new Error(
      `SastBench target commit mismatch for ${job.stateId}: expected ${job.commitHash}, got ${head}`,
    );
  }
  if (!clean) {
    throw new Error(`SastBench target has local changes: ${job.targetDir}`);
  }
  if (origin !== job.repoUrl) {
    throw new Error(
      `SastBench target origin mismatch for ${job.stateId}: expected ${job.repoUrl}, got ${origin}`,
    );
  }
}

function ensureTarget(job) {
  if (fs.existsSync(job.targetDir)) {
    inspectTarget(job);
    return "already current";
  }
  fs.mkdirSync(path.dirname(job.targetDir), { recursive: true });
  bareGit(job.cacheDir, ["worktree", "add", "--detach", job.targetDir, job.commitHash]);
  inspectTarget(job);
  return "hydrated";
}

function hydrateJobs(jobs) {
  console.log(`hydrating ${jobs.length} unique SastBench repository states`);
  jobs.forEach((job, index) => {
    ensureRepositoryCache(job);
    const status = ensureTarget(job);
    console.log(
      `[${index + 1}/${jobs.length}] ${status}: ${job.repoName} @ ${job.commitHash} (${job.cases.length} cases)`,
    );
  });
}

function printPlan(jobs) {
  console.log(`would hydrate ${jobs.length} unique SastBench repository states`);
  for (const job of jobs) {
    console.log(`${job.repoName} @ ${job.commitHash} -> ${job.targetDir} (${job.cases.length} cases)`);
  }
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const records = loadDataset(args.dataset);
  const jobs = buildHydrationPlan(records, args);
  if (args.dryRun) {
    printPlan(jobs);
  } else {
    hydrateJobs(jobs);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  DEFAULT_CACHE_ROOT,
  parseArgs,
  repositoryCacheId,
  buildHydrationPlan,
  hydrateJobs,
};
