#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const childProcess = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { runPromptfoo, stageSkillRuntime } = require("./run-promptfoo");

const evalRoot = path.resolve(__dirname, "..");
const sourceRoot = path.resolve(evalRoot, "../..");
const skill = "plugins/codex-security/skills/triage-finding/SKILL.md";
const ambient = fs.mkdtempSync(path.join(os.tmpdir(), "ambient-eval-plugin-"));
const previousHome = process.env.CODEX_HOME;
const originalExec = childProcess.execFileSync;
let runtime;
let launchedRuntime;
try {
  fs.mkdirSync(path.dirname(path.join(ambient, skill)), { recursive: true });
  fs.writeFileSync(path.join(ambient, skill), "Use an unrelated ambient skill.");
  process.env.CODEX_HOME = ambient;
  runtime = stageSkillRuntime();
  assert.equal(fs.readFileSync(path.join(runtime, skill), "utf8"), fs.readFileSync(path.join(sourceRoot, skill), "utf8"));
  assert.ok(fs.existsSync(path.join(runtime, "evals/triage-finding/fixtures/repo/src/server.js")));
  for (const entry of fs.readdirSync(runtime, { recursive: true })) {
    assert.ok(!/^evals[\\/]triage-finding[\\/](?:datasets|assertions|tests|artifacts)(?:[\\/]|$)/.test(entry), entry);
  }
  const prompt = fs.readFileSync(path.join(evalRoot, "prompts/triage-request.txt"), "utf8");
  assert.ok(prompt.startsWith(`Read and follow ${skill} from this checkout`));
  for (const configName of ["promptfooconfig.yaml", "promptfooconfig.calibration.yaml", "promptfooconfig.calibration-smoke.yaml"]) {
    const config = fs.readFileSync(path.join(evalRoot, configName), "utf8");
    assert.match(config, /working_dir: "\{\{env\.TRIAGE_RUNTIME_ROOT\}\}"/);
    assert.match(config, /default_permissions: triage_runtime_only/);
    assert.match(config, /":minimal": read\n\s+":workspace_roots": read/);
    assert.match(config, /plugins: false/);
    assert.match(config, /memories: false/);
    assert.doesNotMatch(config, /sandbox_mode|network_access_enabled/);
    if (configName.includes("calibration")) {
      assert.match(config, /additional_directories:\n\s+- "\{\{calibration_repo_root or env\.CALIBRATION_TARGET_ROOT\}\}\/\{\{calibration_repo\}\}"/);
    } else {
      assert.doesNotMatch(config, /additional_directories/);
    }
  }
  childProcess.execFileSync = (command, args, options) => {
    assert.equal(command, path.join(evalRoot, "node_modules", ".bin", "promptfoo"));
    assert.deepEqual(args, ["eval", "--filter-range", "0:1"]);
    assert.equal(options.cwd, evalRoot);
    launchedRuntime = options.env.TRIAGE_RUNTIME_ROOT;
    assert.equal(options.env.SASTBENCH_RUNTIME_ROOT, launchedRuntime);
    assert.equal(options.env.CALIBRATION_TARGET_ROOT, path.join(evalRoot, "artifacts", "calibration-repos"));
    assert.equal(options.env.SASTBENCH_TARGET_ROOT, path.join(evalRoot, "artifacts", "sastbench-targets"));
    assert.equal(options.env.SASTBENCH_GIT_CACHE_ROOT, path.join(evalRoot, "artifacts", "sastbench-git-cache"));
    assert.equal(fs.readFileSync(path.join(launchedRuntime, skill), "utf8"), fs.readFileSync(path.join(sourceRoot, skill), "utf8"));
    throw new Error("Synthetic evaluation failed");
  };
  assert.throws(() => runPromptfoo(["eval", "--filter-range", "0:1"]), /Synthetic evaluation failed/);
  assert.ok(!fs.existsSync(launchedRuntime));
} finally {
  childProcess.execFileSync = originalExec;
  if (runtime) fs.rmSync(runtime, { recursive: true, force: true });
  fs.rmSync(ambient, { recursive: true, force: true });
  if (previousHome === undefined) delete process.env.CODEX_HOME;
  else process.env.CODEX_HOME = previousHome;
}

console.log("triage Promptfoo runtime isolation tests passed");
