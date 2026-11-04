#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { parse } from "yaml";
import runtimeVars from "./runtime-vars.mts";

const evalRoot = path.resolve(import.meta.dirname, "..");

// Saved native configs have no startup hook during viewer replay. Their
// plugin-relative working directory and fixture bindings must stay usable.
const originalRuntime = process.env.TRIAGE_RUNTIME_ROOT;
try {
  for (const staged of [
    undefined,
    path.join(evalRoot, "synthetic staged runtime"),
  ] as const) {
    if (staged === undefined) delete process.env.TRIAGE_RUNTIME_ROOT;
    else process.env.TRIAGE_RUNTIME_ROOT = staged;
    const root = path.resolve(evalRoot, "../..");
    const bindings = runtimeVars({ triage_runtime_root: "old runtime" });
    assert.equal(
      bindings.triage_runtime_root,
      path.join(root, "plugins", "codex-security"),
    );
    assert.equal(
      bindings.triage_fixture_root,
      path.join(root, "evals", "triage-finding", "fixtures"),
    );
    assert.equal(bindings.triage_node_path, fs.realpathSync(process.execPath));
    assert.equal(
      bindings.triage_node_root,
      path.dirname(bindings.triage_node_path),
    );
    assert.equal(
      bindings.sastbench_git_cache_root,
      path.join(evalRoot, "artifacts", "sastbench-git-cache"),
    );
    for (const target of [
      "evals/triage-finding/fixtures/repo",
      "evals/triage-finding/fixtures/policy-repo",
    ]) {
      assert.equal(
        runtimeVars({ target_repo: target }).target_repo,
        path.join(root, target),
      );
    }
  }
} finally {
  if (originalRuntime === undefined) delete process.env.TRIAGE_RUNTIME_ROOT;
  else process.env.TRIAGE_RUNTIME_ROOT = originalRuntime;
}
for (const target of [
  path.join(evalRoot, "artifacts", "sastbench-targets", "opaque-target"),
  "https://github.com/example/repository",
  "No explicit repository supplied by the user.",
]) {
  assert.equal(runtimeVars({ target_repo: target }).target_repo, target);
}

const calibrationRepo = "calibration-0123456789abcdef";
const originalCalibrationRoot = process.env.TRIAGE_CALIBRATION_ROOT;
const defaultCalibrationRoot = path.join(
  evalRoot,
  "artifacts",
  "calibration-repos",
);
const environmentCalibrationRoot = path.join(
  evalRoot,
  "environment targets # space",
);
const explicitCalibrationRoot = path.join(evalRoot, "case targets # space");
try {
  for (const [environmentRoot, caseRoot, expectedRoot] of [
    ["", "", defaultCalibrationRoot],
    [environmentCalibrationRoot, "", environmentCalibrationRoot],
    ["", explicitCalibrationRoot, explicitCalibrationRoot],
    [
      environmentCalibrationRoot,
      explicitCalibrationRoot,
      explicitCalibrationRoot,
    ],
  ]) {
    process.env.TRIAGE_CALIBRATION_ROOT = environmentRoot;
    const replayed = runtimeVars({
      calibration_repo: calibrationRepo,
      calibration_repo_root: caseRoot,
      target_repo: "old checkout",
    });
    assert.equal(
      replayed.target_repo,
      path.join(expectedRoot, calibrationRepo),
    );
  }
} finally {
  if (originalCalibrationRoot === undefined)
    delete process.env.TRIAGE_CALIBRATION_ROOT;
  else process.env.TRIAGE_CALIBRATION_ROOT = originalCalibrationRoot;
}

for (const name of [
  "promptfooconfig.yaml",
  "promptfooconfig.calibration.yaml",
  "promptfooconfig.sastbench.yaml",
]) {
  const suite = parse(fs.readFileSync(path.join(evalRoot, name), "utf8"));
  const providerPath = path.resolve(evalRoot, suite.providers[0].$ref);
  const { id, config } = parse(fs.readFileSync(providerPath, "utf8"));
  assert.match(id, /^openai:codex-sdk:/);
  assert.deepEqual(
    config.cli_config.permissions[config.cli_config.default_permissions],
    {
      filesystem: { ":minimal": "read", ":workspace_roots": "read" },
      network: { enabled: false },
    },
  );
  assert.deepEqual(config.cli_config.features, {
    plugins: false,
    memories: false,
  });
  assert.equal(config.skip_git_repo_check, true);
  assert.equal(config.approval_policy, "never");
  assert.equal(config.working_dir, undefined);
  assert.equal(config.cli_env?.CODEX_MCP_NODE_PATH, undefined);
  assert.equal(config.sandbox_mode, undefined);
  assert.equal(config.network_access_enabled, undefined);
  if (name !== "promptfooconfig.sastbench.yaml") {
    for (const proxy of [
      "HTTP_PROXY",
      "HTTPS_PROXY",
      "ALL_PROXY",
      "NO_PROXY",
    ]) {
      assert.equal(config.cli_env[proxy], `{{env.${proxy}}}`);
    }
  }
  if (name === "promptfooconfig.calibration.yaml") {
    assert.ok(
      config.additional_directories[0].includes("{{calibration_repo}}"),
    );
    assert.equal(
      suite.defaultTest.options.transformVars,
      "file://./scripts/runtime-vars.mts",
    );
  }
}
assert.equal(
  parse(
    fs.readFileSync(
      path.join(evalRoot, "promptfooconfig.calibration-smoke.yaml"),
      "utf8",
    ),
  ).$ref,
  "./promptfooconfig.calibration.yaml",
);
assert.ok(
  fs
    .readFileSync(path.join(evalRoot, "prompts/triage-request.txt"), "utf8")
    .startsWith(
      "Read and follow plugins/codex-security/skills/triage-finding/SKILL.md",
    ),
);
console.log("triage Promptfoo runtime tests passed");
