#!/usr/bin/env node
import { hash } from "node:crypto";
import type { SastBenchRecord } from "../../types.ts";

import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import {
  DEFAULT_DATASET_PATH,
  DEFAULT_TARGET_ROOT,
  EVAL_ROOT,
  repositoryStateId,
  loadDataset,
} from "./sastbench-lib.mts";

export const DEFAULT_CACHE_ROOT = path.join(
  EVAL_ROOT,
  "artifacts",
  "sastbench-git-cache",
);

export function parseArgs(argv: string[]) {
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
      args.dataset = path.resolve(argv[++index]);
    } else if (arg === "--cache-root") {
      args.cacheRoot = path.resolve(argv[++index]);
    } else if (arg === "--target-root") {
      args.targetRoot = path.resolve(argv[++index]);
    } else if (arg === "--dry-run") {
      args.dryRun = true;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return args;
}

export function buildHydrationPlan(
  records: Pick<SastBenchRecord, "repo_name" | "repo_url" | "commit_hash">[],
  { cacheRoot = DEFAULT_CACHE_ROOT, targetRoot = DEFAULT_TARGET_ROOT } = {},
) {
  const urlsByName = new Map();
  const groups = Map.groupBy(records, (record) => {
    const previous = urlsByName.get(record.repo_name);
    if (previous && previous !== record.repo_url) {
      throw new Error(
        `SastBench repository ${record.repo_name} maps to multiple repository URLs: ${previous}, ${record.repo_url}`,
      );
    }
    urlsByName.set(record.repo_name, record.repo_url);
    return `${record.repo_url}\0${record.commit_hash}`;
  });
  const resolvedCacheRoot = path.resolve(cacheRoot);
  return [...groups.values()].map((group) => {
    const record = group[0];
    const stateId = repositoryStateId(record);
    return {
      stateId,
      repoName: record.repo_name,
      repoUrl: record.repo_url,
      commitHash: record.commit_hash,
      targetDir: path.join(path.resolve(targetRoot), stateId),
      caseCount: group.length,
      cacheDir: path.join(
        resolvedCacheRoot,
        `repo-${hash("sha256", record.repo_url).slice(0, 16)}.git`,
      ),
    };
  });
}

export function runGit(
  args: string[],
  cwd: string,
  stderr: "pipe" | "ignore" = "pipe",
) {
  return childProcess
    .execFileSync("git", args, {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", stderr],
    })
    .trim();
}

function bareGit(cacheDir: string, args: string[]) {
  return runGit([`--git-dir=${cacheDir}`, ...args], path.dirname(cacheDir));
}

function ensureRepositoryCache(
  job: ReturnType<typeof buildHydrationPlan>[number],
) {
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

function inspectTarget(job: ReturnType<typeof buildHydrationPlan>[number]) {
  const head = runGit(["rev-parse", "HEAD"], job.targetDir);
  const clean =
    runGit(
      ["status", "--porcelain", "--untracked-files=all"],
      job.targetDir,
    ) === "";
  const origin = runGit(["remote", "get-url", "origin"], job.targetDir);
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

function ensureTarget(job: ReturnType<typeof buildHydrationPlan>[number]) {
  if (fs.existsSync(job.targetDir)) {
    inspectTarget(job);
    return "already current";
  }
  fs.mkdirSync(path.dirname(job.targetDir), { recursive: true });
  bareGit(job.cacheDir, [
    "worktree",
    "add",
    "--detach",
    job.targetDir,
    job.commitHash,
  ]);
  inspectTarget(job);
  return "hydrated";
}

if (import.meta.filename === fs.realpathSync(process.argv[1])) {
  const args = parseArgs(process.argv.slice(2));
  const records = loadDataset(args.dataset);
  const jobs = buildHydrationPlan(records, args);
  console.log(
    `${args.dryRun ? "would hydrate" : "hydrating"} ${jobs.length} unique SastBench repository states`,
  );
  for (const [index, job] of jobs.entries()) {
    if (args.dryRun) {
      console.log(
        `${job.repoName} @ ${job.commitHash} -> ${job.targetDir} (${job.caseCount} cases)`,
      );
    } else {
      ensureRepositoryCache(job);
      const status = ensureTarget(job);
      console.log(
        `[${index + 1}/${jobs.length}] ${status}: ${job.repoName} @ ${job.commitHash} (${job.caseCount} cases)`,
      );
    }
  }
}
