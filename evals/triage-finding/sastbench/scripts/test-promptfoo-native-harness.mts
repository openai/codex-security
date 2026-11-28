#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import os from "node:os";
import { pathToFileURL } from "node:url";
import fs from "node:fs";
import path from "node:path";
import config from "../promptfooconfig.sastbench.mts";
import sampleConfig from "../promptfooconfig.sastbench-sample.mts";

const sastbenchRoot = path.resolve(import.meta.dirname, "..");
const evalRoot = path.resolve(sastbenchRoot, "..");
const packageJson = JSON.parse(
  fs.readFileSync(path.join(evalRoot, "package.json"), "utf8"),
);

const [provider] = config.providers;
assert.match(provider.id, /^openai:codex-sdk:/);
assert.deepEqual(provider.config.additional_directories, [
  "{{env.SASTBENCH_GIT_CACHE_ROOT}}",
  "{{target_repo}}",
]);
assert.equal(provider.config.cli_env, undefined);
assert.equal("evaluateOptions" in config, false);
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
const derivedMetrics = new Map(
  config.derivedMetrics.map(({ name, value }) => [name, value] as const),
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
const strict = { strict_tp: 2, strict_tn: 3, strict_fp: 1, strict_fn: 2 };
assert.equal(
  derivedMetrics.get("strict_accuracy")?.({
    ...strict,
    positive_cases: 4,
    negative_cases: 4,
  }),
  5 / 8,
);
assert.equal(derivedMetrics.get("strict_mcc")?.(strict), 4 / Math.sqrt(240));
assert.equal(
  derivedMetrics.get("strict_mcc")?.({
    strict_tp: 0,
    strict_tn: 0,
    strict_fp: 0,
    strict_fn: 0,
  }),
  0,
);
assert.equal(
  sampleConfig.tests,
  "file://./scripts/sastbench-lib.mts:generateSampleTests",
);
assert.equal(sampleConfig.providers, config.providers);
assert.equal(sampleConfig.derivedMetrics, config.derivedMetrics);

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
  /run-promptfoo\.mts validate config -c .\/sastbench\/promptfooconfig\.sastbench-sample\.mts/,
);
assert.match(
  packageJson.scripts["eval:sastbench:sample"],
  /run-promptfoo\.mts eval -c .\/sastbench\/promptfooconfig\.sastbench-sample\.mts/,
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
  const modules = [
    runner,
    path.join(evalRoot, "scripts", "generate-calibration-tests.mts"),
    path.join(evalRoot, "scripts", "hydrate-calibration-repos.mts"),
    path.join(sastbenchRoot, "scripts", "install-sastbench.mts"),
    path.join(sastbenchRoot, "scripts", "hydrate-sastbench-repos.mts"),
  ].map((module) => pathToFileURL(module).href);
  for (const entry of [
    undefined,
    "-",
    path.join(dispatchRoot, "virtual-entry.mts"),
  ]) {
    const imported = execFileSync(
      process.execPath,
      [
        "--experimental-strip-types",
        "--input-type=module",
        "--eval",
        `process.argv[1] = ${JSON.stringify(entry)};
         for (const module of ${JSON.stringify(modules)}) await import(module);
         console.log("imported");`,
      ],
      { encoding: "utf8" },
    );
    assert.equal(imported.trim(), "imported");
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
