#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import os from "node:os";
import { pathToFileURL } from "node:url";
import fs from "node:fs";
import path from "node:path";
import { parse } from "yaml";

const sastbenchRoot = path.resolve(import.meta.dirname, "..");
const evalRoot = path.resolve(sastbenchRoot, "..");
const entryConfig = parse(
  fs.readFileSync(
    path.join(sastbenchRoot, "promptfooconfig.sastbench.yaml"),
    "utf8",
  ),
);
assert.equal(entryConfig.$ref, "./promptfooconfig.sastbench.yaml");
const config = parse(
  fs.readFileSync(path.resolve(evalRoot, entryConfig.$ref), "utf8"),
);
const sampleConfig = parse(
  fs.readFileSync(
    path.join(sastbenchRoot, "promptfooconfig.sastbench-sample.yaml"),
    "utf8",
  ),
);
const packageJson = JSON.parse(
  fs.readFileSync(path.join(evalRoot, "package.json"), "utf8"),
);

const providerPath = path.resolve(evalRoot, config.providers[0].$ref);
const provider = parse(fs.readFileSync(providerPath, "utf8"));
assert.match(provider.id, /^openai:codex-sdk:/);
assert.deepEqual(provider.config.additional_directories, [
  "{{env.SASTBENCH_GIT_CACHE_ROOT}}",
  "{{target_repo}}",
]);
assert.equal(provider.config.cli_env, undefined);
assert.equal(config.evaluateOptions?.maxConcurrency, undefined);
assert.equal(config.tests, "file://./scripts/sastbench-lib.mts:generateTests");
assert.deepEqual(
  config.defaultTest.assert.map(
    (assertion: { metric: string }) => assertion.metric,
  ),
  ["schema_valid", "strict_case_correct"],
);
assert.ok(
  config.extensions.includes(
    "file://./assertions/sastbench-metrics.mts:afterEach",
  ),
);
const derivedMetrics = new Map<string, string>(
  config.derivedMetrics.map(
    ({ name, value }: { name: string; value: string }) => [name, value],
  ),
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
  assert.ok(derivedMetrics.has(metric), `Missing aggregate metric: ${metric}`);
}
assert.equal(
  derivedMetrics.get("strict_accuracy"),
  "(strict_tp + strict_tn) / max(positive_cases + negative_cases, 1)",
);
assert.equal(sampleConfig.$ref, entryConfig.$ref);
assert.equal(
  sampleConfig.tests,
  "file://./scripts/sastbench-lib.mts:generateSampleTests",
);
assert.equal(sampleConfig.providers, undefined);
assert.equal(sampleConfig.derivedMetrics, undefined);

assert.match(packageJson.scripts["eval:sastbench"], /run-promptfoo\.mts eval/);
assert.match(packageJson.scripts["eval:sastbench"], /--no-cache/);
assert.match(packageJson.scripts["eval:sastbench"], /--no-share/);
assert.doesNotMatch(packageJson.scripts["eval:sastbench"], /--filter-range/);
assert.doesNotMatch(packageJson.scripts["eval:sastbench"], /--max-concurrency/);
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
          PROMPTFOO_CONFIG_DIR: path.resolve(dispatchRoot),
          PROMPTFOO_DISABLE_TELEMETRY: "1",
          PROMPTFOO_DISABLE_UPDATE: "1",
        },
      },
    );
    assert.equal(version.trim(), packageJson.dependencies.promptfoo);
  }
} finally {
  fs.rmSync(dispatchRoot, { recursive: true, force: true });
}
