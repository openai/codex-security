#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const sastbenchRoot = path.resolve(__dirname, "..");
const evalRoot = path.resolve(sastbenchRoot, "..");
const config = fs.readFileSync(path.join(sastbenchRoot, "promptfooconfig.sastbench.yaml"), "utf8");
const sampleConfig = fs.readFileSync(
  path.join(sastbenchRoot, "promptfooconfig.sastbench-sample.yaml"),
  "utf8",
);
const packageJson = JSON.parse(fs.readFileSync(path.join(evalRoot, "package.json"), "utf8"));

assert.match(config, /working_dir:\s+"\{\{env\.SASTBENCH_RUNTIME_ROOT\}\}"/);
assert.match(config, /skip_git_repo_check:\s+true/);
assert.doesNotMatch(config, /working_dir:\s+\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\./);
assert.match(
  config,
  /additional_directories:\n\s+- "\{\{env\.SASTBENCH_TARGET_ROOT\}\}"\n\s+- "\{\{env\.SASTBENCH_GIT_CACHE_ROOT\}\}"/,
);
assert.doesNotMatch(config, /sandbox_mode:/);
assert.doesNotMatch(config, /network_access_enabled:/);
assert.match(config, /default_permissions:\s+sastbench_runtime_only/);
assert.match(config, /sastbench_runtime_only:\n\s+filesystem:/);
assert.match(config, /":minimal":\s+read/);
assert.match(config, /":workspace_roots":\s+read/);
assert.match(config, /network:\n\s+enabled:\s+false/);
assert.match(config, /id:\s+openai:codex-sdk:gpt-5\.5/);
assert.match(config, /label:\s+"Codex SDK triage-finding SastBench \(gpt-5\.5\)"/);
assert.doesNotMatch(config, /gpt-5\.6/);
assert.match(
  config,
  /tests:\s+file:\/\/\.\/scripts\/generate-sastbench-tests\.js:generateTests/,
);
assert.match(config, /metric:\s+schema_valid/);
assert.match(config, /metric:\s+strict_case_correct/);
assert.match(
  config,
  /extensions:\n\s+- file:\/\/\.\/assertions\/sastbench-metrics\.js:afterEach/,
);
for (const metric of [
  "strict_precision",
  "strict_recall",
  "strict_f1",
  "strict_f2",
  "strict_mcc",
  "decided_coverage",
  "true_positive_retention",
  "unsafe_closure_rate",
  "false_alert_auto_closure_rate",
  "false_alert_escalation_rate",
  "confirmed_precision",
  "abstention_rate",
  "remaining_analyst_workload",
  "execution_or_parse_error_rate",
]) {
  assert.match(config, new RegExp(`name:\\s+${metric}`));
}
assert.doesNotMatch(config, /HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY/);
assert.doesNotMatch(config, /maxConcurrency/);
assert.doesNotMatch(config, /__count/);
assert.match(
  config,
  /strict_accuracy\n\s+value:\s+"\(strict_tp \+ strict_tn\) \/ max\(positive_cases \+ negative_cases, 1\)"/,
);
assert.match(sampleConfig, /^\$ref:\s+\.\/sastbench\/promptfooconfig\.sastbench\.yaml/m);
assert.match(
  sampleConfig,
  /tests:\s+file:\/\/\.\/scripts\/generate-sastbench-tests\.js:generateSampleTests/,
);
assert.doesNotMatch(sampleConfig, /providers:/);
assert.doesNotMatch(sampleConfig, /derivedMetrics:/);

assert.match(packageJson.scripts["eval:sastbench"], /run-sastbench-promptfoo\.js eval/);
assert.match(packageJson.scripts["eval:sastbench"], /--no-cache/);
assert.match(packageJson.scripts["eval:sastbench"], /--no-share/);
assert.doesNotMatch(packageJson.scripts["eval:sastbench"], /--filter-range/);
assert.doesNotMatch(packageJson.scripts["eval:sastbench"], /--max-concurrency/);
assert.equal("score:sastbench" in packageJson.scripts, false);
assert.equal("report:sastbench" in packageJson.scripts, false);
assert.doesNotMatch(packageJson.scripts["eval:sastbench"], /PROMPTFOO_FAILED_TEST_EXIT_CODE/);
assert.match(
  packageJson.scripts["validate:sastbench:sample"],
  /run-sastbench-promptfoo\.js validate config -c .\/sastbench\/promptfooconfig\.sastbench-sample\.yaml/,
);
assert.match(
  packageJson.scripts["eval:sastbench:sample"],
  /run-sastbench-promptfoo\.js eval -c .\/sastbench\/promptfooconfig\.sastbench-sample\.yaml/,
);
assert.match(packageJson.scripts["eval:sastbench:sample"], /--no-cache/);
assert.match(packageJson.scripts["eval:sastbench:sample"], /--no-share/);
assert.match(packageJson.scripts["eval:sastbench:sample"], /--max-concurrency 32/);
assert.equal("sastbench:generate" in packageJson.scripts, false);
assert.equal(fs.existsSync(path.join(__dirname, "run-sastbench-promptfoo.js")), true);
assert.equal(
  fs.existsSync(path.join(sastbenchRoot, "docs", "2026-06-22-sastbench-triage-finding-eval.md")),
  false,
);

console.log("sastbench native Promptfoo harness tests passed");
