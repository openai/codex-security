#!/usr/bin/env node

import assert from "node:assert/strict";
import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { stageSkillRuntime } from "./run-promptfoo.mts";
import runtimeVars from "./runtime-vars.mts";

const evalRoot = path.resolve(import.meta.dirname, "..");
const sourceRoot = path.resolve(evalRoot, "../..");
const skill = "plugins/codex-security/skills/triage-finding/SKILL.md";
const ambient = fs.mkdtempSync(path.join(os.tmpdir(), "ambient-eval-plugin-"));
const previousHome = process.env.CODEX_HOME;
const previousRuntime = process.env.TRIAGE_RUNTIME_ROOT;
const previousTargets = process.env.CALIBRATION_TARGET_ROOT;
let runtime: string | undefined;
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
  const fixtureEval = path.join(runtime, "evals", "triage-finding");
  const fixtureScript = path.join(fixtureEval, "scripts", "run-promptfoo.mts");
  fs.mkdirSync(path.dirname(fixtureScript), { recursive: true });
  fs.copyFileSync(
    path.join(import.meta.dirname, "run-promptfoo.mts"),
    fixtureScript,
  );
  const packageRoot = path.join(fixtureEval, "node_modules", "promptfoo");
  fs.mkdirSync(packageRoot, { recursive: true });
  fs.writeFileSync(
    path.join(packageRoot, "package.json"),
    JSON.stringify({ bin: { promptfoo: "cli entrypoint.cjs" } }),
  );
  fs.writeFileSync(
    path.join(packageRoot, "cli entrypoint.cjs"),
    `
    const fs = require("node:fs");
    const path = require("node:path");
    const env = process.env;
    fs.writeFileSync(env.EVAL_TEST_RECORD, JSON.stringify({
      args: process.argv.slice(2), cwd: process.cwd(),
      runtime: env.TRIAGE_RUNTIME_ROOT,
      sastbenchRuntime: env.SASTBENCH_RUNTIME_ROOT,
      calibrationTargets: env.CALIBRATION_TARGET_ROOT,
      sastbenchTargets: env.SASTBENCH_TARGET_ROOT,
      gitCache: env.SASTBENCH_GIT_CACHE_ROOT,
      skill: fs.readFileSync(path.join(env.TRIAGE_RUNTIME_ROOT, ${JSON.stringify(skill)}), "utf8"),
    }));
    process.exitCode = Number(env.EVAL_TEST_EXIT_CODE);
  `,
  );
  const temporary = path.join(ambient, "child temporary");
  fs.mkdirSync(temporary);
  const marker = path.join(ambient, "launch.json");
  const args = [
    "eval",
    "--filter-range",
    "0:1",
    "-c",
    'config with spaces & "quotes".yaml',
  ];
  const launch = (status: number) =>
    childProcess.spawnSync(
      process.execPath,
      ["--experimental-strip-types", fixtureScript, ...args],
      {
        env: {
          ...process.env,
          TMPDIR: temporary,
          TMP: temporary,
          TEMP: temporary,
          EVAL_TEST_RECORD: marker,
          EVAL_TEST_EXIT_CODE: String(status),
        },
        encoding: "utf8",
      },
    );
  for (const status of [0, 100, 17]) {
    const result = launch(status);
    assert.equal(result.status, status, result.stderr);
    const record = JSON.parse(fs.readFileSync(marker, "utf8"));
    assert.deepEqual(record.args, args);
    assert.equal(record.cwd, fixtureEval);
    assert.equal(record.sastbenchRuntime, record.runtime);
    assert.equal(
      record.calibrationTargets,
      path.join(fixtureEval, "artifacts", "calibration-repos"),
    );
    assert.equal(
      record.sastbenchTargets,
      path.join(fixtureEval, "artifacts", "sastbench-targets"),
    );
    assert.equal(
      record.gitCache,
      path.join(fixtureEval, "artifacts", "sastbench-git-cache"),
    );
    assert.equal(
      record.skill,
      fs.readFileSync(path.join(sourceRoot, skill), "utf8"),
    );
    assert.ok(!fs.existsSync(record.runtime));
    assert.deepEqual(fs.readdirSync(temporary), []);
  }
  fs.rmSync(path.join(packageRoot, "package.json"));
  const missing = launch(0);
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /ENOENT/);
  assert.deepEqual(fs.readdirSync(temporary), []);
} finally {
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
