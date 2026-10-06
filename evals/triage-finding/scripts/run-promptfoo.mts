#!/usr/bin/env node

import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const EVAL_ROOT = path.resolve(import.meta.dirname, "..");
const PLUGIN_ROOT = path.resolve(
  EVAL_ROOT,
  "..",
  "..",
  "plugins",
  "codex-security",
);
const TRIAGE_SKILL_ROOT = path.join(PLUGIN_ROOT, "skills", "triage-finding");
const DEFAULT_TARGET_ROOT = path.join(
  EVAL_ROOT,
  "artifacts",
  "sastbench-targets",
);
const DEFAULT_GIT_CACHE_ROOT = path.join(
  EVAL_ROOT,
  "artifacts",
  "sastbench-git-cache",
);
const PROMPTFOO_ROOT = path.join(EVAL_ROOT, "node_modules", "promptfoo");

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
 * Give Codex a throwaway working directory containing the checkout skill and
 * synthetic fixture. The label-bearing dataset and harness stay in EVAL_ROOT.
 */
export function stageSkillRuntime() {
  const helperRoot = path.join(PLUGIN_ROOT, "mcp");
  if (!fs.existsSync(path.join(helperRoot, "helpers.mjs"))) {
    throw new Error(
      "Build the plugin helper runtime first; see evals/triage-finding/README.md.",
    );
  }
  const helperFiles = fs
    .readdirSync(helperRoot)
    .filter(
      (name) =>
        name === "helpers.mjs" || name.startsWith("helpers.mjs.br.part-"),
    );
  const runtimeRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "codex-security-triage-finding-"),
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
  copyDirectory(
    path.join(EVAL_ROOT, "fixtures"),
    path.join(runtimeRoot, "evals", "triage-finding", "fixtures"),
  );
  const stagedScripts = path.join(stagedPluginRoot, "scripts");
  fs.mkdirSync(stagedScripts, { recursive: true });
  for (const name of [
    "launch_codex_security_mcp",
    "launch_codex_security_mcp.cmd",
  ]) {
    fs.copyFileSync(
      path.join(PLUGIN_ROOT, "scripts", name),
      path.join(stagedScripts, name),
    );
  }
  const stagedHelpers = path.join(stagedPluginRoot, "mcp");
  fs.mkdirSync(stagedHelpers, { recursive: true });
  for (const name of helperFiles) {
    fs.copyFileSync(
      path.join(helperRoot, name),
      path.join(stagedHelpers, name),
    );
  }
  copyDirectory(
    path.join(helperRoot, "native"),
    path.join(stagedHelpers, "native"),
  );
  return runtimeRoot;
}

export function runPromptfoo(promptfooArgs: string[]) {
  const runtimeRoot = stageSkillRuntime();
  const env = {
    ...process.env,
    TRIAGE_RUNTIME_ROOT: runtimeRoot,
    CALIBRATION_TARGET_ROOT: path.join(
      EVAL_ROOT,
      "artifacts",
      "calibration-repos",
    ),
    SASTBENCH_RUNTIME_ROOT: runtimeRoot,
    SASTBENCH_TARGET_ROOT: DEFAULT_TARGET_ROOT,
    SASTBENCH_GIT_CACHE_ROOT: DEFAULT_GIT_CACHE_ROOT,
  };
  try {
    const { bin } = JSON.parse(
      fs.readFileSync(path.join(PROMPTFOO_ROOT, "package.json"), "utf8"),
    );
    const promptfooBin = path.resolve(PROMPTFOO_ROOT, bin.promptfoo);
    childProcess.execFileSync(
      process.execPath,
      [promptfooBin, ...promptfooArgs],
      {
        cwd: EVAL_ROOT,
        env,
        stdio: "inherit",
      },
    );
    return 0;
  } catch (error) {
    const status = (error as { status?: number }).status;
    if (!Number.isInteger(status)) throw error;
    return status!;
  } finally {
    fs.rmSync(runtimeRoot, { recursive: true, force: true });
  }
}

function main(argv = process.argv.slice(2)) {
  if (argv.length === 0) {
    throw new Error("Expected Promptfoo arguments");
  }
  process.exitCode = runPromptfoo(argv);
}

if (import.meta.filename === fs.realpathSync(process.argv[1])) {
  main();
}
