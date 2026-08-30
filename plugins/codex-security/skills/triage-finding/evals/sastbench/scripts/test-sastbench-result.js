#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");

const {
  extractTriageResult,
  normalizePromptfooResult,
  parseCaseOutcome,
} = require("./sastbench-result");
const { afterEach: addSastBenchMetrics } = require("../assertions/sastbench-metrics");
const verdictAssertion = require("../assertions/sastbench-verdict");

function triageResult(verdict, inputId = "sastbench-000000") {
  return {
    schema_version: "triage-finding/v0",
    repository: { path: "/target", revision: "a".repeat(40) },
    findings: [
      {
        input_id: inputId,
        source_type: "scanner_ticket",
        verdict,
      },
    ],
  };
}

const fenced = `Summary\n\n\`\`\`json\n${JSON.stringify(triageResult("confirmed"), null, 2)}\n\`\`\``;
assert.equal(extractTriageResult(fenced).findings[0].verdict, "confirmed");
assert.equal(
  extractTriageResult(JSON.stringify(triageResult("not_actionable"))).findings[0].verdict,
  "not_actionable",
);
assert.throws(() => extractTriageResult("no json"), /triage-finding\/v0/);
assert.throws(
  () => parseCaseOutcome(JSON.stringify(triageResult("confirmed", "wrong")), "sastbench-000000"),
  /input_id mismatch/,
);
assert.throws(
  () => parseCaseOutcome(JSON.stringify({ ...triageResult("confirmed"), findings: [] }), "sastbench-000000"),
  /exactly one finding/,
);
assert.throws(
  () => parseCaseOutcome(JSON.stringify(triageResult("unexpected")), "sastbench-000000"),
  /unsupported verdict/,
);

assert.equal(
  verdictAssertion(fenced, {
    vars: { case_id: "sastbench-000000" },
    test: { metadata: { ground_truth: "true_positive" } },
  }).pass,
  true,
);
assert.equal(
  verdictAssertion(fenced, {
    vars: { case_id: "sastbench-000000" },
    test: { metadata: { ground_truth: "false_positive" } },
  }).pass,
  false,
);

function extensionContext({ caseId, expectedGroundTruth, output, error, sampleWeight }) {
  return {
    test: {
      vars: { case_id: caseId },
      metadata: {
        ground_truth: expectedGroundTruth,
        ...(sampleWeight === undefined ? {} : { sample_weight: sampleWeight }),
      },
    },
    result: {
      namedScores: { existing_metric: 1 },
      response: output === undefined ? { error } : { output },
      failureReason: error ? "error" : undefined,
    },
  };
}

function sumNamedScores(rows) {
  const totals = {};
  for (const row of rows) {
    for (const [name, value] of Object.entries(row.result.namedScores)) {
      totals[name] = (totals[name] || 0) + value;
    }
  }
  return totals;
}

const outcomes = [
  { caseId: "tp-confirmed", expectedGroundTruth: "true_positive", verdict: "confirmed" },
  { caseId: "tp-closed", expectedGroundTruth: "true_positive", verdict: "not_actionable" },
  { caseId: "tp-review", expectedGroundTruth: "true_positive", verdict: "needs_review" },
  { caseId: "fp-closed", expectedGroundTruth: "false_positive", verdict: "not_actionable" },
  { caseId: "fp-confirmed", expectedGroundTruth: "false_positive", verdict: "confirmed" },
  { caseId: "fp-review", expectedGroundTruth: "false_positive", verdict: "needs_review" },
];
const nativeMetricRows = outcomes.map((outcome) =>
  addSastBenchMetrics(
    extensionContext({
      caseId: outcome.caseId,
      expectedGroundTruth: outcome.expectedGroundTruth,
      output: JSON.stringify(triageResult(outcome.verdict, outcome.caseId)),
    }),
  ),
);
const totals = sumNamedScores(nativeMetricRows);

assert.deepEqual(
  {
    tp: totals.strict_tp,
    tn: totals.strict_tn,
    fp: totals.strict_fp,
    fn: totals.strict_fn,
  },
  { tp: 1, tn: 1, fp: 2, fn: 2 },
);
assert.deepEqual(
  {
    tp: totals.decided_tp,
    tn: totals.decided_tn,
    fp: totals.decided_fp,
    fn: totals.decided_fn,
  },
  { tp: 1, tn: 1, fp: 1, fn: 1 },
);
assert.equal(totals.decided_cases, 4);
assert.equal(totals.positive_cases, 3);
assert.equal(totals.negative_cases, 3);
assert.equal(totals.retained_positive, 2);
assert.equal(totals.unsafe_closure, 1);
assert.equal(totals.false_alert_auto_closure, 1);
assert.equal(totals.false_alert_escalation, 1);
assert.equal(totals.confirmed_true, 1);
assert.equal(totals.confirmed_total, 2);
assert.equal(totals.abstention, 2);
assert.equal(totals.remaining_analyst_work, 4);
assert.equal(totals.execution_or_parse_error, 0);
assert.equal(totals.existing_metric, 6);

const positiveProviderError = addSastBenchMetrics(
  extensionContext({
    caseId: "tp-error",
    expectedGroundTruth: "true_positive",
    error: "provider failed",
  }),
);
assert.equal(positiveProviderError.result.namedScores.strict_fn, 1);
assert.equal(positiveProviderError.result.namedScores.execution_or_parse_error, 1);
assert.equal(positiveProviderError.result.namedScores.remaining_analyst_work, 1);
assert.equal(positiveProviderError.result.metadata.sastbench.status, "model_error");

const negativeInvalidOutput = addSastBenchMetrics(
  extensionContext({
    caseId: "fp-invalid",
    expectedGroundTruth: "false_positive",
    output: "not a triage result",
  }),
);
assert.equal(negativeInvalidOutput.result.namedScores.strict_fp, 1);
assert.equal(negativeInvalidOutput.result.namedScores.execution_or_parse_error, 1);
assert.equal(negativeInvalidOutput.result.metadata.sastbench.status, "invalid_output");

const weightedPositive = addSastBenchMetrics(
  extensionContext({
    caseId: "weighted-tp",
    expectedGroundTruth: "true_positive",
    output: JSON.stringify(triageResult("confirmed", "weighted-tp")),
    sampleWeight: 2.5,
  }),
);
assert.equal(weightedPositive.result.namedScores.strict_tp, 2.5);
assert.equal(weightedPositive.result.namedScores.positive_cases, 2.5);
assert.equal(weightedPositive.result.namedScores.existing_metric, 1);

const normalized = normalizePromptfooResult({
  latencyMs: 1234,
  cost: 0.25,
  vars: { case_id: "sastbench-000000" },
  testCase: { metadata: { ground_truth: "true_positive" } },
  response: {
    output: fenced,
    tokenUsage: { prompt: 10, completion: 5, total: 15, cached: 2 },
  },
});
assert.equal(normalized.status, "ok");
assert.equal(normalized.verdict, "confirmed");
assert.equal(normalized.latencyMs, 1234);
assert.equal(normalized.cost, 0.25);
assert.equal(normalized.tokenUsage.total, 15);

const invalid = normalizePromptfooResult({
  vars: { case_id: "sastbench-000001" },
  testCase: { metadata: { ground_truth: "false_positive" } },
  response: { output: "invalid" },
});
assert.equal(invalid.status, "invalid_output");
assert.match(invalid.error, /triage-finding\/v0/);

const modelError = normalizePromptfooResult({
  vars: { case_id: "sastbench-000002" },
  testCase: { metadata: { ground_truth: "true_positive" } },
  response: { error: "provider failed" },
});
assert.equal(modelError.status, "model_error");
assert.equal(modelError.error, "provider failed");

console.log("sastbench result and native metric tests passed");
