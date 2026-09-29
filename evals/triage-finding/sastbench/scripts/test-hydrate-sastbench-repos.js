#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");

const {
  buildHydrationPlan,
  parseArgs,
  repositoryCacheId,
} = require("./hydrate-sastbench-repos");

function record({ repoName = "example/project", repoUrl, commit, label = "true_positive" }) {
  return {
    finding_id: "hidden",
    repo_name: repoName,
    repo_url: repoUrl,
    commit_hash: commit,
    ground_truth: label,
    metadata: { source: "cve" },
    to_analyzer: {
      vulnerability_type: "CWE-79",
      vulnerability_name: "Cross-site Scripting",
      description: "A claim.",
      locations: [{ file: "src/a.js", function: "a", line_start: 1, line_end: 2 }],
      commit_context: { repo: repoName, commit },
    },
  };
}

const repoUrl = "https://github.com/example/project";
const firstCommit = "1".repeat(40);
const secondCommit = "2".repeat(40);
const records = [
  record({ repoUrl, commit: firstCommit }),
  record({ repoUrl, commit: firstCommit, label: "false_positive" }),
  record({ repoUrl, commit: secondCommit }),
];
const cacheRoot = path.resolve("/tmp/sastbench-git-cache");
const targetRoot = path.resolve("/tmp/sastbench-targets");

assert.equal(parseArgs(["--", "--dry-run"]).dryRun, true);

const cacheId = repositoryCacheId(repoUrl);
assert.match(cacheId, /^repo-[a-f0-9]{16}$/);
assert.equal(repositoryCacheId(repoUrl), cacheId);

const jobs = buildHydrationPlan(records, { cacheRoot, targetRoot });
assert.equal(jobs.length, 2);
assert.equal(jobs[0].cases.length, 2);
assert.equal(jobs[1].cases.length, 1);
assert.equal(jobs[0].cacheDir, path.join(cacheRoot, `${cacheId}.git`));
for (const job of jobs) {
  assert.equal(path.relative(targetRoot, job.targetDir).startsWith(".."), false);
  assert.equal(path.relative(cacheRoot, job.cacheDir).startsWith(".."), false);
  assert.equal(job.repoUrl, repoUrl);
}

assert.throws(
  () =>
    buildHydrationPlan(
      [
        record({ repoName: "same/name", repoUrl: "https://github.com/example/one", commit: firstCommit }),
        record({ repoName: "same/name", repoUrl: "https://github.com/example/two", commit: secondCommit }),
      ],
      { cacheRoot, targetRoot },
    ),
  /maps to multiple repository URLs/,
);

console.log("sastbench hydration planning tests passed");
