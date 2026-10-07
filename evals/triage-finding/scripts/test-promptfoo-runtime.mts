#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import runtimeVars from "./runtime-vars.mts";
import { DEFAULT_CACHE_ROOT } from "../sastbench/scripts/hydrate-sastbench-repos.mts";

const evalRoot = path.resolve(import.meta.dirname, "..");
const sourceRoot = path.resolve(evalRoot, "../..");
const pluginRoot = path.join(sourceRoot, "plugins", "codex-security");
const vars = runtimeVars({});
assert.equal(vars.triage_runtime_root, pluginRoot);
assert.equal(vars.triage_fixture_root, path.join(evalRoot, "fixtures"));
assert.equal(vars.triage_node_path, fs.realpathSync(process.execPath));
assert.equal(vars.triage_node_root, path.dirname(vars.triage_node_path));
assert.equal(vars.sastbench_git_cache_root, DEFAULT_CACHE_ROOT);
assert.ok(
  fs.existsSync(path.join(pluginRoot, "skills/triage-finding/SKILL.md")),
);

for (const fixture of ["repo", "policy-repo"]) {
  const target = runtimeVars({
    target_repo: `evals/triage-finding/fixtures/${fixture}`,
  }).target_repo;
  assert.equal(target, path.join(evalRoot, "fixtures", fixture));
  assert.ok(fs.existsSync(target as string));
}
for (const target of [
  path.join(evalRoot, "artifacts", "sastbench-targets", "opaque-target"),
  "https://github.com/example/repository",
  "No explicit repository supplied by the user.",
]) {
  assert.equal(runtimeVars({ target_repo: target }).target_repo, target);
}

const calibrationRepo = "calibration-0123456789abcdef";
for (const customRoot of ["", path.join(evalRoot, "custom targets # space")]) {
  const replayed = runtimeVars({
    calibration_repo: calibrationRepo,
    calibration_repo_root: customRoot,
    target_repo: "old checkout",
    triage_runtime_root: "old plugin",
  });
  assert.equal(replayed.triage_runtime_root, pluginRoot);
  assert.equal(
    replayed.target_repo,
    path.join(
      customRoot || path.join(evalRoot, "artifacts", "calibration-repos"),
      calibrationRepo,
    ),
  );
}

for (const name of [
  "promptfooconfig.yaml",
  "promptfooconfig.calibration.yaml",
  "promptfooconfig.calibration-smoke.yaml",
  "sastbench/promptfooconfig.sastbench.yaml",
]) {
  const config = fs.readFileSync(path.join(evalRoot, name), "utf8");
  assert.match(config, /working_dir: "\{\{triage_runtime_root\}\}"/);
  assert.match(config, /":minimal": read\n\s+":workspace_roots": read/);
  assert.match(config, /plugins: false/);
  assert.match(config, /memories: false/);
  assert.ok(config.includes('"{{triage_node_root}}"'));
  assert.ok(
    config.includes(
      name === "promptfooconfig.yaml"
        ? '"{{triage_fixture_root}}"'
        : '"{{target_repo}}"',
    ),
  );
}
assert.ok(
  fs
    .readFileSync(path.join(evalRoot, "prompts/triage-request.txt"), "utf8")
    .startsWith("Read and follow skills/triage-finding/SKILL.md"),
);
console.log("triage Promptfoo checkout path tests passed");
