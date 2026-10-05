#!/usr/bin/env node
import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { EVAL_ROOT, DEFAULT_TARGET_ROOT } from "./sastbench-lib.mts";
import { DEFAULT_CACHE_ROOT } from "./hydrate-sastbench-repos.mts";
const PLUGIN_ROOT = path.resolve(
  EVAL_ROOT,
  "..",
  "..",
  "plugins",
  "codex-security",
);
const TRIAGE_SKILL_ROOT = path.join(PLUGIN_ROOT, "skills", "triage-finding");
const PROMPTFOO_BIN = path.join(EVAL_ROOT, "node_modules", ".bin", "promptfoo");

function copyDirectory(
  sourceRoot: string,
  targetRoot: string,
  excludedNames: Set<string> = new Set(),
) {
  fs.mkdirSync(targetRoot, { recursive: true });
  for (const entry of fs.readdirSync(sourceRoot, { withFileTypes: true })) {
    if (excludedNames.has(entry.name)) {
      continue;
    }
    const sourcePath = path.join(sourceRoot, entry.name);
    const targetPath = path.join(targetRoot, entry.name);
    if (entry.isDirectory()) {
      copyDirectory(sourcePath, targetPath, excludedNames);
      continue;
    }
    if (!entry.isFile()) {
      throw new Error(
        "Refusing to stage non-file runtime entry: " + sourcePath,
      );
    }
    fs.copyFileSync(sourcePath, targetPath);
  }
}

/**
 * Give Codex a throwaway working directory that contains only the skill files
 * it needs. The label-bearing dataset and Promptfoo harness stay in EVAL_ROOT.
 */
const promptfooArgs = process.argv.slice(2);
if (promptfooArgs.length === 0) {
  throw new Error("Expected Promptfoo arguments");
}
const runtimeRoot = fs.mkdtempSync(
  path.join(os.tmpdir(), "codex-security-triage-finding-sastbench-"),
);
const stagedPluginRoot = path.join(runtimeRoot, "plugins", "codex-security");
copyDirectory(
  TRIAGE_SKILL_ROOT,
  path.join(stagedPluginRoot, "skills", "triage-finding"),
  new Set(["evals"]),
);
for (const sharedDirectory of ["references", "schemas"]) {
  const sourcePath = path.join(PLUGIN_ROOT, sharedDirectory);
  if (fs.existsSync(sourcePath)) {
    copyDirectory(sourcePath, path.join(stagedPluginRoot, sharedDirectory));
  }
}
const env = {
  ...process.env,
  SASTBENCH_RUNTIME_ROOT: runtimeRoot,
  SASTBENCH_TARGET_ROOT: DEFAULT_TARGET_ROOT,
  SASTBENCH_GIT_CACHE_ROOT: DEFAULT_CACHE_ROOT,
};
try {
  childProcess.execFileSync(PROMPTFOO_BIN, promptfooArgs, {
    cwd: EVAL_ROOT,
    env,
    stdio: "inherit",
  });
} finally {
  fs.rmSync(runtimeRoot, { recursive: true, force: true });
}
