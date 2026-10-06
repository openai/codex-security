#!/usr/bin/env node
import assert from "node:assert/strict";
import path from "node:path";

import { buildHydrationPlan, parseArgs } from "./hydrate-sastbench-repos.mts";

const repoUrl = "https://github.com/example/project";
const firstCommit = "1".repeat(40);
const secondCommit = "2".repeat(40);
const baseRecord = {
  repo_name: "example/project",
  repo_url: repoUrl,
  commit_hash: firstCommit,
  ground_truth: "true_positive",
};
const records = [
  { ...baseRecord },
  { ...baseRecord, ground_truth: "false_positive" },
  { ...baseRecord, commit_hash: secondCommit },
];
const cacheRoot = path.resolve("/tmp/sastbench-git-cache");
const targetRoot = path.resolve("/tmp/sastbench-targets");

assert.equal(parseArgs(["--", "--dry-run"]).dryRun, true);

const jobs = buildHydrationPlan(records, { cacheRoot, targetRoot });
assert.equal(
  buildHydrationPlan(records, { cacheRoot, targetRoot })[0].cacheDir,
  jobs[0].cacheDir,
);
assert.equal(jobs.length, 2);
assert.equal(jobs[0].caseCount, 2);
assert.equal(jobs[1].caseCount, 1);
assert.equal(
  jobs[0].cacheDir,
  path.join(cacheRoot, "repo-acb9cf7430784a93.git"),
);
for (const job of jobs) {
  assert.equal(
    path.relative(targetRoot, job.targetDir).startsWith(".."),
    false,
  );
  assert.equal(path.relative(cacheRoot, job.cacheDir).startsWith(".."), false);
  assert.equal(job.repoUrl, repoUrl);
}

assert.throws(
  () =>
    buildHydrationPlan(
      [
        {
          ...baseRecord,
          repo_name: "same/name",
          repo_url: "https://github.com/example/one",
        },
        {
          ...baseRecord,
          repo_name: "same/name",
          repo_url: "https://github.com/example/two",
          commit_hash: secondCommit,
        },
      ],
      { cacheRoot, targetRoot },
    ),
  /maps to multiple repository URLs/,
);

console.log("sastbench hydration planning tests passed");
