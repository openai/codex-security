#!/usr/bin/env node
"use strict";

const childProcess = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const EVAL_ROOT = path.resolve(__dirname, "..", "..");
const TRIAGE_SKILL_ROOT = path.resolve(EVAL_ROOT, "..");
const PLUGIN_ROOT = path.resolve(TRIAGE_SKILL_ROOT, "..", "..");
const DEFAULT_TARGET_ROOT = path.join(EVAL_ROOT, "artifacts", "sastbench-targets");
const DEFAULT_GIT_CACHE_ROOT = path.join(EVAL_ROOT, "artifacts", "sastbench-git-cache");
const PROMPTFOO_BIN = path.join(EVAL_ROOT, "node_modules", ".bin", "promptfoo");

function copyDirectory(sourceRoot, targetRoot, excludedNames = new Set()) {
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
      throw new Error("Refusing to stage non-file runtime entry: " + sourcePath);
    }
    fs.mkdirSync(path.dirname(targetPath), { recursive: true });
    fs.copyFileSync(sourcePath, targetPath);
  }
}

/**
 * Give Codex a throwaway working directory that contains only the skill files
 * it needs. The label-bearing dataset and Promptfoo harness stay in EVAL_ROOT.
 */
function stageSkillRuntime() {
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
  return runtimeRoot;
}

function runPromptfoo(promptfooArgs) {
  const runtimeRoot = stageSkillRuntime();
  const env = {
    ...process.env,
    SASTBENCH_RUNTIME_ROOT: runtimeRoot,
    SASTBENCH_TARGET_ROOT: DEFAULT_TARGET_ROOT,
    SASTBENCH_GIT_CACHE_ROOT: DEFAULT_GIT_CACHE_ROOT,
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
}

function main(argv = process.argv.slice(2)) {
  if (argv.length === 0) {
    throw new Error("Expected Promptfoo arguments");
  }
  runPromptfoo(argv);
}

if (require.main === module) {
  main();
}

module.exports = {
  runPromptfoo,
  stageSkillRuntime,
};
