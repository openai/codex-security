#!/usr/bin/env node
"use strict";

const childProcess = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const DEFAULT_DATASET = path.join(__dirname, "..", "datasets", "triage-calibration-seed.json");
const DEFAULT_REPO_ROOT = path.join(__dirname, "..", "artifacts", "calibration-repos");

function parseArgs(argv) {
  const args = {
    dataset: DEFAULT_DATASET,
    repoRoot: DEFAULT_REPO_ROOT,
    caseId: null,
    variantId: null,
    dryRun: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--dataset") {
      args.dataset = argv[++index];
    } else if (arg === "--repo-root") {
      args.repoRoot = argv[++index];
    } else if (arg === "--case") {
      args.caseId = argv[++index];
    } else if (arg === "--variant") {
      args.variantId = argv[++index];
    } else if (arg === "--dry-run") {
      args.dryRun = true;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return {
    ...args,
    dataset: path.resolve(args.dataset),
    repoRoot: path.resolve(args.repoRoot),
  };
}

function plannedJobs(dataset, args) {
  const jobs = [];

  for (const testCase of dataset.cases) {
    if (args.caseId && testCase.case_id !== args.caseId) {
      continue;
    }

    for (const variant of testCase.variants) {
      if (args.variantId && variant.variant_id !== args.variantId) {
        continue;
      }

      jobs.push({
        caseId: testCase.case_id,
        variantId: variant.variant_id,
        repoUrl: testCase.repo.url,
        checkoutRef: variant.checkout_ref,
        targetDir: path.join(args.repoRoot, testCase.case_id, variant.variant_id),
      });
    }
  }

  return jobs;
}

function runGit(args, cwd) {
  childProcess.execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function gitOutput(args, cwd) {
  try {
    return childProcess.execFileSync("git", args, {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return null;
  }
}

function isGitCheckout(directory) {
  return fs.existsSync(path.join(directory, ".git"));
}

function ensureGitCheckout(job) {
  fs.mkdirSync(path.dirname(job.targetDir), { recursive: true });

  if (!fs.existsSync(job.targetDir)) {
    fs.mkdirSync(job.targetDir, { recursive: true });
  }

  if (!isGitCheckout(job.targetDir)) {
    const entries = fs.readdirSync(job.targetDir);
    if (entries.length > 0) {
      throw new Error(`Refusing to hydrate into non-empty non-git directory: ${job.targetDir}`);
    }
    runGit(["init"], job.targetDir);
    runGit(["remote", "add", "origin", job.repoUrl], job.targetDir);
  } else {
    const originUrl = gitOutput(["remote", "get-url", "origin"], job.targetDir);
    if (!originUrl) {
      runGit(["remote", "add", "origin", job.repoUrl], job.targetDir);
    } else if (originUrl !== job.repoUrl) {
      runGit(["remote", "set-url", "origin", job.repoUrl], job.targetDir);
    }
  }

  const currentHead = gitOutput(["rev-parse", "HEAD"], job.targetDir);
  if (currentHead === job.checkoutRef) {
    return "already current";
  }

  runGit(["fetch", "--depth", "1", "origin", job.checkoutRef], job.targetDir);
  runGit(["checkout", "--detach", "FETCH_HEAD"], job.targetDir);
  return "hydrated";
}

function printPlan(jobs) {
  const variantWord = jobs.length === 1 ? "variant" : "variants";
  console.log(`would hydrate ${jobs.length} calibration ${variantWord}`);
  for (const job of jobs) {
    console.log(`${job.caseId}/${job.variantId} <- ${job.repoUrl} @ ${job.checkoutRef}`);
    console.log(`  ${job.targetDir}`);
  }
}

function hydrate(jobs) {
  const variantWord = jobs.length === 1 ? "variant" : "variants";
  console.log(`hydrating ${jobs.length} calibration ${variantWord}`);
  for (const job of jobs) {
    const status = ensureGitCheckout(job);
    console.log(`${status}: ${job.caseId}/${job.variantId} @ ${job.checkoutRef}`);
  }
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const dataset = JSON.parse(fs.readFileSync(args.dataset, "utf8"));
  const jobs = plannedJobs(dataset, args);

  if (jobs.length === 0) {
    throw new Error("No calibration variants matched the requested filters.");
  }

  if (args.dryRun) {
    printPlan(jobs);
  } else {
    hydrate(jobs);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  plannedJobs,
};
