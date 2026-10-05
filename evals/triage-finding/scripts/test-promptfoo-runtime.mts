#!/usr/bin/env node

import assert from "node:assert/strict";
import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { runPromptfoo, stageSkillRuntime } from "./run-promptfoo.mts";
import runtimeVars from "./runtime-vars.mts";

const evalRoot = path.resolve(import.meta.dirname, "..");
const sourceRoot = path.resolve(evalRoot, "../..");
const skill = "plugins/codex-security/skills/triage-finding/SKILL.md";
const ambient = fs.mkdtempSync(path.join(os.tmpdir(), "ambient-eval-plugin-"));
const previousHome = process.env.CODEX_HOME;
const previousRuntime = process.env.TRIAGE_RUNTIME_ROOT;
const previousTargets = process.env.CALIBRATION_TARGET_ROOT;
const originalExec = childProcess.execFileSync;
let runtime: string | undefined;
let launchedRuntime: string | undefined;
try {
  fs.mkdirSync(path.dirname(path.join(ambient, skill)), { recursive: true });
  fs.writeFileSync(
    path.join(ambient, skill),
    "Use an unrelated ambient skill.",
  );
  process.env.CODEX_HOME = ambient;
  runtime = stageSkillRuntime();
  assert.equal(
    fs.readFileSync(path.join(runtime, skill), "utf8"),
    fs.readFileSync(path.join(sourceRoot, skill), "utf8"),
  );
  assert.ok(
    fs.existsSync(
      path.join(runtime, "evals/triage-finding/fixtures/repo/src/server.js"),
    ),
  );
  for (const entry of fs.readdirSync(runtime, {
    recursive: true,
    encoding: "utf8",
  })) {
    assert.ok(
      !/^evals[\\/]triage-finding[\\/](?:datasets|assertions|tests|artifacts)(?:[\\/]|$)/.test(
        entry,
      ),
      entry,
    );
  }
  const prompt = fs.readFileSync(
    path.join(evalRoot, "prompts/triage-request.txt"),
    "utf8",
  );
  assert.ok(prompt.startsWith(`Read and follow ${skill} from this checkout`));
  for (const configName of [
    "promptfooconfig.yaml",
    "promptfooconfig.calibration.yaml",
    "promptfooconfig.calibration-smoke.yaml",
  ]) {
    const config = fs.readFileSync(path.join(evalRoot, configName), "utf8");
    assert.match(config, /working_dir: "\{\{triage_runtime_root\}\}"/);
    assert.match(
      config,
      /transformVars: file:\/\/\.\/scripts\/runtime-vars\.mts/,
    );
    assert.match(config, /default_permissions: triage_runtime_only/);
    assert.match(config, /":minimal": read\n\s+":workspace_roots": read/);
    assert.match(config, /plugins: false/);
    assert.match(config, /memories: false/);
    assert.doesNotMatch(config, /sandbox_mode|network_access_enabled/);
    if (configName.includes("calibration")) {
      assert.match(
        config,
        /additional_directories:\n\s+- "\{\{target_repo\}\}"/,
      );
    }
    assert.match(config, /- "\{\{triage_node_root\}\}"/);
    assert.match(config, /CODEX_MCP_NODE_PATH: "\{\{triage_node_path\}\}"/);
  }
  process.env.CALIBRATION_TARGET_ROOT = path.join(ambient, "default targets");
  for (const customRoot of ["", path.join(ambient, "custom targets # space")]) {
    let vars: Record<string, unknown> = {
      calibration_repo: "calibration-0123456789abcdef",
      calibration_repo_root: customRoot,
    };
    for (const runtimeName of ["first", "retry"]) {
      process.env.TRIAGE_RUNTIME_ROOT = path.join(ambient, runtimeName);
      vars = runtimeVars(vars);
      assert.equal(vars.triage_runtime_root, process.env.TRIAGE_RUNTIME_ROOT);
      assert.equal(vars.triage_node_path, fs.realpathSync(process.execPath));
      assert.equal(
        vars.triage_node_root,
        path.dirname(vars.triage_node_path as string),
      );
      assert.equal(
        vars.target_repo,
        path.join(
          customRoot || process.env.CALIBRATION_TARGET_ROOT,
          vars.calibration_repo as string,
        ),
      );
    }
  }
  assert.equal(
    runtimeVars({ target_repo: "synthetic/fixture" }).target_repo,
    "synthetic/fixture",
  );
  childProcess.execFileSync = ((
    command: string,
    args: string[],
    options: childProcess.ExecFileSyncOptionsWithStringEncoding,
  ) => {
    assert.equal(
      command,
      path.join(evalRoot, "node_modules", ".bin", "promptfoo"),
    );
    assert.deepEqual(args, ["eval", "--filter-range", "0:1"]);
    assert.equal(options.cwd, evalRoot);
    launchedRuntime = options.env!.TRIAGE_RUNTIME_ROOT;
    assert.equal(options.env!.SASTBENCH_RUNTIME_ROOT, launchedRuntime);
    assert.equal(
      options.env!.CALIBRATION_TARGET_ROOT,
      path.join(evalRoot, "artifacts", "calibration-repos"),
    );
    assert.equal(
      options.env!.SASTBENCH_TARGET_ROOT,
      path.join(evalRoot, "artifacts", "sastbench-targets"),
    );
    assert.equal(
      options.env!.SASTBENCH_GIT_CACHE_ROOT,
      path.join(evalRoot, "artifacts", "sastbench-git-cache"),
    );
    assert.equal(
      fs.readFileSync(path.join(launchedRuntime!, skill), "utf8"),
      fs.readFileSync(path.join(sourceRoot, skill), "utf8"),
    );
    throw new Error("Synthetic evaluation failed");
  }) as unknown as typeof childProcess.execFileSync;
  assert.throws(
    () => runPromptfoo(["eval", "--filter-range", "0:1"]),
    /Synthetic evaluation failed/,
  );
  assert.ok(!fs.existsSync(launchedRuntime!));
  childProcess.execFileSync = originalExec;
  const preload = path.join(ambient, "failed-promptfoo.cjs");
  fs.writeFileSync(
    preload,
    `require("node:child_process").execFileSync = (_command, _args, options) => {
    require("node:fs").writeFileSync(process.env.EVAL_TEST_RUNTIME, options.env.TRIAGE_RUNTIME_ROOT);
    throw Object.assign(new Error("Child evaluation failed"), { status: Number(process.env.EVAL_TEST_EXIT_CODE) });
  };`,
  );
  for (const status of [100, 17]) {
    const marker = path.join(ambient, "runtime.txt");
    const result = childProcess.spawnSync(
      process.execPath,
      [
        "--experimental-strip-types",
        "--require",
        preload,
        path.join(import.meta.dirname, "run-promptfoo.mts"),
        "eval",
      ],
      {
        env: {
          ...process.env,
          EVAL_TEST_RUNTIME: marker,
          EVAL_TEST_EXIT_CODE: String(status),
        },
        encoding: "utf8",
      },
    );
    assert.equal(result.status, status, result.stderr);
    assert.doesNotMatch(result.stderr, /Error: Child evaluation failed/);
    assert.ok(!fs.existsSync(fs.readFileSync(marker, "utf8")));
  }
} finally {
  childProcess.execFileSync = originalExec;
  if (runtime) fs.rmSync(runtime, { recursive: true, force: true });
  fs.rmSync(ambient, { recursive: true, force: true });
  if (previousRuntime === undefined) delete process.env.TRIAGE_RUNTIME_ROOT;
  else process.env.TRIAGE_RUNTIME_ROOT = previousRuntime;
  if (previousTargets === undefined) delete process.env.CALIBRATION_TARGET_ROOT;
  else process.env.CALIBRATION_TARGET_ROOT = previousTargets;
  if (previousHome === undefined) delete process.env.CODEX_HOME;
  else process.env.CODEX_HOME = previousHome;
}

console.log("triage Promptfoo runtime isolation tests passed");
