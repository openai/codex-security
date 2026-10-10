#!/usr/bin/env node
import childProcess, { type ChildProcess } from "node:child_process";
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
const PROMPTFOO_ENTRYPOINT = path.join(
  EVAL_ROOT,
  "node_modules",
  "promptfoo",
  "dist",
  "src",
  "entrypoint.js",
);

function copyDirectory(
  sourceRoot: string,
  targetRoot: string,
  excludedNames = new Set<string>(),
) {
  fs.cpSync(sourceRoot, targetRoot, {
    recursive: true,
    filter: (source) => !excludedNames.has(path.basename(source)),
  });
}

/**
 * Give Codex a throwaway working directory that contains only the skill files
 * it needs. The label-bearing dataset and Promptfoo harness stay in EVAL_ROOT.
 */
function stageSkillRuntime() {
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
    copyDirectory(
      path.join(PLUGIN_ROOT, sharedDirectory),
      path.join(stagedPluginRoot, sharedDirectory),
    );
  }
  fs.mkdirSync(path.join(stagedPluginRoot, "scripts"));
  for (const launcher of [
    "launch_codex_security_mcp",
    "launch_codex_security_mcp.cmd",
  ]) {
    fs.copyFileSync(
      path.join(PLUGIN_ROOT, "scripts", launcher),
      path.join(stagedPluginRoot, "scripts", launcher),
    );
  }
  copyDirectory(
    path.join(EVAL_ROOT, "fixtures"),
    path.join(runtimeRoot, "evals", "triage-finding", "fixtures"),
  );
  return fs.realpathSync(runtimeRoot);
}

async function runPromptfoo(
  promptfooArgs: string[],
  environment: NodeJS.ProcessEnv = {},
) {
  const runtimeRoot = stageSkillRuntime();
  const artifacts = path.join(EVAL_ROOT, "artifacts");
  const env = {
    TRIAGE_CALIBRATION_ROOT: path.join(artifacts, "calibration-repos"),
    SASTBENCH_GIT_CACHE_ROOT: path.join(artifacts, "sastbench-git-cache"),
    ...process.env,
    ...environment,
    // Promptfoo persists this stable harness path for retry, resume, and viewer replay.
    TRIAGE_PROVIDER_PATH: path.join(import.meta.dirname, "triage-provider.mts"),
    TRIAGE_RUNTIME_ROOT: runtimeRoot,
  };
  let child: ChildProcess | undefined;
  let interrupted: NodeJS.Signals | undefined;
  const handlers = (["SIGINT", "SIGTERM"] as const).map((signal) => {
    const handler = () => {
      interrupted = signal;
      if (!child?.pid) return;
      if (process.platform === "win32") {
        // Console Ctrl+C already reaches the inherited child. Node's kill()
        // would terminate it before Promptfoo can save its progress.
        if (signal !== "SIGINT") child.kill(signal);
      } else {
        try {
          process.kill(-child.pid, signal);
        } catch (error) {
          // The process group can exit before Node emits the close event.
          if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
        }
      }
    };
    process.on(signal, handler);
    return [signal, handler] as const;
  });
  function runChild(args: string[], cwd: string) {
    return new Promise<number>((resolve, reject) => {
      child = childProcess.spawn(process.execPath, args, {
        cwd,
        env,
        stdio: "inherit",
        detached: process.platform !== "win32",
      });
      child.once("error", reject);
      child.once("close", (code, signal) => {
        child = undefined;
        const stoppedBy = interrupted || signal;
        resolve(
          stoppedBy === "SIGINT"
            ? 130
            : stoppedBy === "SIGTERM"
              ? 143
              : (code ?? 1),
        );
      });
    });
  }
  try {
    const built = await runChild(
      [
        path.join(PLUGIN_ROOT, "mcp-app", "scripts", "build_mcp_app.mjs"),
        "--output",
        path.join(runtimeRoot, "plugins", "codex-security", "mcp"),
        "--native",
        "host",
      ],
      path.join(PLUGIN_ROOT, "mcp-app"),
    );
    if (built !== 0) return built;
    return await runChild([PROMPTFOO_ENTRYPOINT, ...promptfooArgs], EVAL_ROOT);
  } finally {
    for (const [signal, handler] of handlers) process.off(signal, handler);
    fs.rmSync(runtimeRoot, { recursive: true, force: true });
  }
}

function runMain(filename: string, environment: NodeJS.ProcessEnv = {}) {
  try {
    if (!process.argv[1] || fs.realpathSync(process.argv[1]) !== filename)
      return;
  } catch {
    // A virtual entry point imports this module without invoking the runner.
    return;
  }
  runPromptfoo(process.argv.slice(2), environment)
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error) => {
      console.error(error);
      process.exitCode = 1;
    });
}

runMain(import.meta.filename);

export { runMain, runPromptfoo, stageSkillRuntime };
