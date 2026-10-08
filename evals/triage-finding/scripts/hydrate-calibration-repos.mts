#!/usr/bin/env node
import { runGit } from "../sastbench/scripts/hydrate-sastbench-repos.mts";

import {
  DEFAULT_DATASET,
  selectedVariants,
  variantCaseId,
} from "./generate-calibration-tests.mts";

import fs from "node:fs";
import path from "node:path";

const DEFAULT_REPO_ROOT = path.join(
  import.meta.dirname,
  "..",
  "artifacts",
  "calibration-repos",
);

function parseArgs(argv: string[]) {
  const args = {
    dataset: DEFAULT_DATASET,
    repoRoot: DEFAULT_REPO_ROOT,
    caseId: null as string | null,
    variantId: null as string | null,
    dryRun: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--dataset") {
      args.dataset = path.resolve(argv[++index]);
    } else if (arg === "--repo-root") {
      args.repoRoot = path.resolve(argv[++index]);
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

  return args;
}

function gitOutput(args: string[], cwd: string) {
  try {
    return runGit(args, cwd, "ignore");
  } catch {
    return null;
  }
}

function ensureGitCheckout(job: ReturnType<typeof plannedJobs>[number]) {
  fs.mkdirSync(path.dirname(job.targetDir), { recursive: true });

  if (!fs.existsSync(job.targetDir)) {
    fs.mkdirSync(job.targetDir, { recursive: true });
  }

  if (
    !fs.existsSync(path.join(job.targetDir, ".git")) ||
    gitOutput(["rev-parse", "--show-prefix"], job.targetDir) !== ""
  ) {
    const entries = fs.readdirSync(job.targetDir);
    if (entries.length > 0) {
      throw new Error(
        `Refusing to hydrate into non-empty non-git directory: ${job.targetDir}`,
      );
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

  if (fs.lstatSync(path.join(job.targetDir, ".git")).isDirectory()) {
    runGit(
      ["init", "--separate-git-dir", `${job.targetDir}.git`],
      job.targetDir,
    );
  }

  const currentHead = gitOutput(["rev-parse", "HEAD"], job.targetDir);
  if (currentHead === job.checkoutRef) {
    return "already current";
  }

  runGit(["fetch", "--depth", "1", "origin", job.checkoutRef], job.targetDir);
  runGit(["checkout", "--detach", "FETCH_HEAD"], job.targetDir);
  return "hydrated";
}

export function plannedJobs(
  dataset: Parameters<typeof selectedVariants>[0],
  args: Parameters<typeof selectedVariants>[1] & { repoRoot: string },
) {
  return selectedVariants(dataset, args).map(({ testCase, variant }) => ({
    repoUrl: testCase.repo.url,
    checkoutRef: variant.checkout_ref,
    targetDir: path.join(args.repoRoot, variantCaseId(testCase, variant)),
    label: `${testCase.case_id}/${variant.variant_id}`,
  }));
}

if (import.meta.filename === fs.realpathSync(process.argv[1])) {
  const args = parseArgs(process.argv.slice(2));
  const dataset = JSON.parse(fs.readFileSync(args.dataset, "utf8"));
  const jobs = plannedJobs(dataset, args);
  const variantWord = jobs.length === 1 ? "variant" : "variants";
  console.log(
    `${args.dryRun ? "would hydrate" : "hydrating"} ${jobs.length} calibration ${variantWord}`,
  );
  for (const job of jobs) {
    if (args.dryRun) {
      console.log(`${job.label} <- ${job.repoUrl} @ ${job.checkoutRef}`);
      console.log(`  ${job.targetDir}`);
    } else {
      const status = ensureGitCheckout(job);
      console.log(`${status}: ${job.label} @ ${job.checkoutRef}`);
    }
  }
}
