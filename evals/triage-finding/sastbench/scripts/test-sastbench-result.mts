#!/usr/bin/env node
import assert from "node:assert/strict";

import { extractTriageResult, parseCaseOutcome } from "./sastbench-result.mts";
import { afterEach as addSastBenchMetrics } from "../assertions/sastbench-metrics.mts";
import verdictAssertion from "../assertions/sastbench-verdict.mts";

function triageResult(verdict: string, inputId = "sastbench-000000") {
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
  extractTriageResult(JSON.stringify(triageResult("not_actionable")))
    .findings[0].verdict,
  "not_actionable",
);
assert.equal(
  extractTriageResult("```json\ninvalid\n```\n" + fenced).findings[0].verdict,
  "confirmed",
);
assert.throws(
  () =>
    extractTriageResult(
      "```json\ninvalid\n```\n" + JSON.stringify(triageResult("confirmed")),
    ),
  { message: "Could not find a parseable triage-finding/v0 JSON result" },
);
assert.throws(
  () =>
    parseCaseOutcome(
      JSON.stringify(triageResult("confirmed", "wrong")),
      "sastbench-000000",
    ),
  /input_id mismatch/,
);
assert.throws(
  () =>
    parseCaseOutcome(
      JSON.stringify({ ...triageResult("confirmed"), findings: [] }),
      "sastbench-000000",
    ),
  /exactly one finding/,
);
assert.throws(
  () =>
    parseCaseOutcome(
      JSON.stringify(triageResult("unexpected")),
      "sastbench-000000",
    ),
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

function extensionContext({
  caseId,
  expectedGroundTruth,
  output,
  error,
  sampleWeight,
}: {
  caseId: string;
  expectedGroundTruth: string;
  output?: string;
  error?: string;
  sampleWeight?: number;
}) {
  return {
    test: {
      metadata: {
        ground_truth: expectedGroundTruth,
        ...(sampleWeight === undefined ? {} : { sample_weight: sampleWeight }),
      },
    },
    result: {
      vars: { case_id: caseId },
      latencyMs: 1234,
      cost: 0.25,
      namedScores: { existing_metric: 1 },
      response:
        output === undefined
          ? { error }
          : {
              output,
              tokenUsage: { prompt: 10, completion: 5, total: 15, cached: 2 },
              sessionId: "session",
            },
      failureReason: error ? "error" : undefined,
    },
  };
}

const outcomes = [
  {
    caseId: "tp-confirmed",
    expectedGroundTruth: "true_positive",
    verdict: "confirmed",
  },
  {
    caseId: "tp-closed",
    expectedGroundTruth: "true_positive",
    verdict: "not_actionable",
  },
  {
    caseId: "tp-review",
    expectedGroundTruth: "true_positive",
    verdict: "needs_review",
  },
  {
    caseId: "fp-closed",
    expectedGroundTruth: "false_positive",
    verdict: "not_actionable",
  },
  {
    caseId: "fp-confirmed",
    expectedGroundTruth: "false_positive",
    verdict: "confirmed",
  },
  {
    caseId: "fp-review",
    expectedGroundTruth: "false_positive",
    verdict: "needs_review",
  },
];
const nativeContexts = outcomes.map((outcome) =>
  extensionContext({
    caseId: outcome.caseId,
    expectedGroundTruth: outcome.expectedGroundTruth,
    output: JSON.stringify(triageResult(outcome.verdict, outcome.caseId)),
  }),
);
const nativeMetricRows = nativeContexts.map(addSastBenchMetrics);
const totals: Record<string, number> = {};
for (const row of nativeMetricRows) {
  for (const [name, value] of Object.entries(row.result.namedScores)) {
    totals[name] = (totals[name] || 0) + value;
  }
}

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
assert.equal(
  positiveProviderError.result.namedScores.execution_or_parse_error,
  1,
);
assert.equal(
  positiveProviderError.result.namedScores.remaining_analyst_work,
  1,
);
assert.equal(
  positiveProviderError.result.metadata.sastbench.status,
  "model_error",
);

const negativeInvalidOutput = addSastBenchMetrics(
  extensionContext({
    caseId: "fp-invalid",
    expectedGroundTruth: "false_positive",
    output: "not a triage result",
  }),
);
assert.equal(negativeInvalidOutput.result.namedScores.strict_fp, 1);
assert.equal(
  negativeInvalidOutput.result.namedScores.execution_or_parse_error,
  1,
);
assert.equal(
  negativeInvalidOutput.result.metadata.sastbench.status,
  "invalid_output",
);

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

const firstResult = nativeMetricRows[0].result;
assert.equal(firstResult.metadata.sastbench.status, "ok");
assert.equal(firstResult.metadata.sastbench.verdict, "confirmed");
assert.equal(firstResult.latencyMs, 1234);
assert.equal(firstResult.cost, 0.25);
assert.equal(firstResult.response, nativeContexts[0].result.response);
assert.match(
  negativeInvalidOutput.result.metadata.sastbench.error!,
  /triage-finding\/v0/,
);
assert.equal(
  positiveProviderError.result.metadata.sastbench.error,
  "provider failed",
);

console.log("sastbench result and native metric tests passed");
