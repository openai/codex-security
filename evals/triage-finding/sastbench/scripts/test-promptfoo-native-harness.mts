#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import os from "node:os";
import { pathToFileURL } from "node:url";
import fs from "node:fs";
import path from "node:path";

const sastbenchRoot = path.resolve(import.meta.dirname, "..");
const evalRoot = path.resolve(sastbenchRoot, "..");
const config = fs.readFileSync(
  path.join(sastbenchRoot, "promptfooconfig.sastbench.yaml"),
  "utf8",
);
const sampleConfig = fs.readFileSync(
  path.join(sastbenchRoot, "promptfooconfig.sastbench-sample.yaml"),
  "utf8",
);
const packageJson = JSON.parse(
  fs.readFileSync(path.join(evalRoot, "package.json"), "utf8"),
);

assert.doesNotMatch(config, /working_dir:/);
assert.match(config, /skip_git_repo_check:\s+true/);
assert.doesNotMatch(
  config,
  /working_dir:\s+\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\./,
);
assert.match(
  config,
  /additional_directories:\n\s+- "\{\{env\.SASTBENCH_GIT_CACHE_ROOT\}\}"\n\s+- "\{\{target_repo\}\}"/,
);
assert.doesNotMatch(config, /sandbox_mode:/);
assert.doesNotMatch(config, /network_access_enabled:/);
assert.match(config, /default_permissions:\s+sastbench_runtime_only/);
assert.match(config, /sastbench_runtime_only:\n\s+filesystem:/);
assert.match(config, /":minimal":\s+read/);
assert.match(config, /":workspace_roots":\s+read/);
assert.match(config, /network:\n\s+enabled:\s+false/);
assert.match(config, /id:\s+openai:codex-sdk:gpt-5\.5/);
assert.match(
  config,
  /label:\s+"Codex SDK triage-finding SastBench \(gpt-5\.5\)"/,
);
assert.doesNotMatch(config, /gpt-5\.6/);
assert.match(
  config,
  /tests:\s+file:\/\/\.\/scripts\/sastbench-lib\.mts:generateTests/,
);
assert.match(config, /metric:\s+schema_valid/);
assert.match(config, /metric:\s+strict_case_correct/);
assert.match(
  config,
  /extensions:\n\s+- file:\/\/\{\{env\.TRIAGE_PROVIDER_PATH\}\}:beforeAll\n\s+- file:\/\/\.\/assertions\/sastbench-metrics\.mts:afterEach/,
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
assert.match(
  sampleConfig,
  /^\$ref:\s+\.\/sastbench\/promptfooconfig\.sastbench\.yaml/m,
);
assert.match(
  sampleConfig,
  /tests:\s+file:\/\/\.\/scripts\/sastbench-lib\.mts:generateSampleTests/,
);
assert.doesNotMatch(sampleConfig, /providers:/);
assert.doesNotMatch(sampleConfig, /derivedMetrics:/);

assert.match(packageJson.scripts["eval:sastbench"], /run-promptfoo\.mts eval/);
assert.match(packageJson.scripts["eval:sastbench"], /--no-cache/);
assert.match(packageJson.scripts["eval:sastbench"], /--no-share/);
assert.doesNotMatch(packageJson.scripts["eval:sastbench"], /--filter-range/);
assert.doesNotMatch(packageJson.scripts["eval:sastbench"], /--max-concurrency/);
assert.equal("score:sastbench" in packageJson.scripts, false);
assert.equal("report:sastbench" in packageJson.scripts, false);
assert.doesNotMatch(
  packageJson.scripts["eval:sastbench"],
  /PROMPTFOO_FAILED_TEST_EXIT_CODE/,
);
assert.match(
  packageJson.scripts["validate:sastbench:sample"],
  /run-promptfoo\.mts validate config -c .\/sastbench\/promptfooconfig\.sastbench-sample\.yaml/,
);
assert.match(
  packageJson.scripts["eval:sastbench:sample"],
  /run-promptfoo\.mts eval -c .\/sastbench\/promptfooconfig\.sastbench-sample\.yaml/,
);
assert.match(packageJson.scripts["eval:sastbench:sample"], /--no-cache/);
assert.match(packageJson.scripts["eval:sastbench:sample"], /--no-share/);
assert.match(
  packageJson.scripts["eval:sastbench:sample"],
  /--max-concurrency 32/,
);
assert.equal("sastbench:generate" in packageJson.scripts, false);
assert.equal(
  fs.existsSync(path.join(import.meta.dirname, "run-sastbench-promptfoo.mts")),
  false,
);
assert.equal(
  fs.existsSync(
    path.join(
      sastbenchRoot,
      "docs",
      "2026-06-22-sastbench-triage-finding-eval.md",
    ),
  ),
  false,
);

console.log("sastbench native Promptfoo harness tests passed");

const dispatchRoot = fs.mkdtempSync(
  path.join(os.tmpdir(), "sastbench-dispatch-"),
);
try {
  const runner = path.join(evalRoot, "scripts", "run-promptfoo.mts");
  for (const module of [runner]) {
    for (const entry of ["-", path.join(dispatchRoot, "virtual-entry.mts")]) {
      const imported = execFileSync(
        process.execPath,
        [
          "--experimental-strip-types",
          "--input-type=module",
          "--eval",
          `process.argv[1] = ${JSON.stringify(entry)}; await import(${JSON.stringify(pathToFileURL(module).href)}); console.log("imported");`,
        ],
        { encoding: "utf8" },
      );
      assert.equal(imported.trim(), "imported");
    }
  }
  if (process.platform !== "win32") {
    const link = path.join(dispatchRoot, "sastbench-runner.mts");
    fs.symlinkSync(runner, link);
    const version = execFileSync(
      process.execPath,
      ["--experimental-strip-types", link, "--version"],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          PROMPTFOO_DISABLE_TELEMETRY: "1",
          PROMPTFOO_DISABLE_UPDATE: "1",
        },
      },
    );
    assert.match(version, /0\.123\.1/);
  }
} finally {
  fs.rmSync(dispatchRoot, { recursive: true, force: true });
}
