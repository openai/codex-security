import assert from "node:assert/strict";
import test from "node:test";
import { summarizeRuns } from "./summary.mts";
import { createFixture } from "./fixtures.mts";
import { gradeResult } from "./grade.mts";
import type { CompletedRunRecord, RunReport, Variant } from "./experiment.mts";

function attempt(pair: number, variant: Variant) {
  return {
    pair,
    variant,
    elapsedMs: 100,
    startedAt: "2026-01-01T00:00:00.000Z",
    advisoryBudgetMinutes: variant === "time-aware" ? 5 : null,
    promptSha256: null,
    usage: null,
  };
}

function completed(
  pair: number,
  variant: Variant,
  overrides: Partial<RunReport> = {},
): CompletedRunRecord {
  return {
    ...attempt(pair, variant),
    status: "completed",
    usage: { input_tokens: 100, cached_input_tokens: 40, output_tokens: 20 },
    report: {
      ...gradeResult({ findings: [] }, createFixture()),
      recall: 0.5,
      foundCount: 1,
      expectedCount: 2,
      safeControlFindings: 0,
      unmatchedFindings: [],
      evidenceErrors: [],
      ...overrides,
    },
  };
}

test("pairs runs by identifier and reports time-aware minus baseline", () => {
  const result = summarizeRuns([
    completed(2, "time-aware", { recall: 1, foundCount: 2 }),
    completed(1, "baseline"),
    completed(2, "baseline"),
    {
      ...completed(1, "time-aware", {
        recall: 0,
        foundCount: 0,
        safeControlFindings: 1,
        unmatchedFindings: [
          { findingIndex: 0, title: "unmatched", reason: "unknown source" },
        ],
        evidenceErrors: [
          { reason: "bad source" },
          { reason: "missing evidence" },
        ],
      }),
      elapsedMs: 300,
    },
  ]);
  assert.equal(result.arms.baseline.attempted, 2);
  assert.equal(result.arms.baseline.successRate, 1);
  assert.equal(result.arms["time-aware"].meanElapsedMs, 200);
  assert.equal(result.arms["time-aware"].meanRecall, 0.5);
  assert.equal(result.arms["time-aware"].foundCount, 2);
  assert.equal(result.arms["time-aware"].expectedCount, 4);
  assert.equal(result.arms["time-aware"].safeControlFindings, 1);
  assert.equal(result.arms["time-aware"].unmatchedFindings, 1);
  assert.equal(result.arms["time-aware"].evidenceErrors, 2);
  assert.equal(result.paired.completedPairs, 2);
  assert.equal(result.paired.excludedPairs, 0);
  assert.equal(result.paired.meanDelta.recall, 0);
  assert.equal(result.paired.meanDelta.elapsedMs, 100);
  assert.equal(result.paired.meanDelta.safeControlFindings, 0.5);
  assert.equal(result.paired.meanDelta.evidenceErrors, 1);
});

test("shows failures and missing arms alongside completed-pair improvements", () => {
  const result = summarizeRuns([
    completed(1, "baseline"),
    completed(1, "time-aware", { recall: 1, foundCount: 2 }),
    completed(2, "baseline"),
    {
      ...attempt(2, "time-aware"),
      status: "failed",
      error: "scan failed",
      elapsedMs: 900,
    },
    completed(3, "baseline"),
  ]);
  assert.equal(result.arms["time-aware"].attempted, 2);
  assert.equal(result.arms["time-aware"].completed, 1);
  assert.equal(result.arms["time-aware"].failed, 1);
  assert.equal(result.arms["time-aware"].successRate, 0.5);
  assert.equal(result.arms["time-aware"].meanElapsedMs, 500);
  assert.equal(result.arms["time-aware"].meanRecall, 1);
  assert.equal(result.paired.totalPairs, 3);
  assert.equal(result.paired.completedPairs, 1);
  assert.equal(result.paired.excludedPairs, 2);
  assert.equal(result.paired.meanDelta.recall, 0.5);
  assert.equal(result.arms["time-aware"].usage.input_tokens, null);
  assert.equal(result.arms["time-aware"].usage.total_tokens, null);
  assert.equal(result.arms["time-aware"].usage.missingUsageRuns, 1);
});

test("cached input tokens are a subset and never added to total tokens", () => {
  const result = summarizeRuns([
    completed(1, "baseline"),
    {
      ...completed(1, "time-aware"),
      usage: { input_tokens: 150, cached_input_tokens: 80, output_tokens: 40 },
    },
  ]);
  assert.deepEqual(result.arms.baseline.usage, {
    input_tokens: 100,
    cached_input_tokens: 40,
    output_tokens: 20,
    total_tokens: 120,
    missingUsageRuns: 0,
  });
  assert.equal(result.paired.meanDelta.input_tokens, 50);
  assert.equal(result.paired.meanDelta.cached_input_tokens, 40);
  assert.equal(result.paired.meanDelta.output_tokens, 20);
  assert.equal(result.paired.meanDelta.total_tokens, 70);
});

test("missing usage remains unknown without discarding completed pairs", () => {
  const result = summarizeRuns([
    completed(1, "baseline"),
    { ...completed(1, "time-aware"), usage: null },
    completed(2, "baseline"),
    completed(2, "time-aware"),
  ]);
  assert.equal(result.arms["time-aware"].usage.input_tokens, null);
  assert.equal(result.arms["time-aware"].usage.cached_input_tokens, null);
  assert.equal(result.arms["time-aware"].usage.output_tokens, null);
  assert.equal(result.arms["time-aware"].usage.total_tokens, null);
  assert.equal(result.arms["time-aware"].usage.missingUsageRuns, 1);
  assert.equal(result.paired.completedPairs, 2);
  assert.equal(result.paired.meanDelta.total_tokens, null);
  assert.equal(result.paired.meanDelta.recall, 0);
});

test("a missing cache count does not hide known input and output totals", () => {
  const result = summarizeRuns([
    {
      ...completed(1, "baseline"),
      usage: { input_tokens: 100, output_tokens: 20 },
    },
  ]);
  assert.equal(result.arms.baseline.usage.input_tokens, 100);
  assert.equal(result.arms.baseline.usage.cached_input_tokens, null);
  assert.equal(result.arms.baseline.usage.total_tokens, 120);
  assert.equal(result.arms.baseline.usage.missingUsageRuns, 1);
});

test("empty and entirely failed arms have no measured quality or deltas", () => {
  const empty = summarizeRuns([]);
  assert.equal(empty.arms.baseline.attempted, 0);
  assert.equal(empty.arms.baseline.successRate, null);
  assert.equal(empty.arms.baseline.meanElapsedMs, null);
  assert.equal(empty.arms.baseline.usage.total_tokens, null);
  assert.equal(empty.paired.totalPairs, 0);
  assert.equal(empty.paired.meanDelta.recall, null);
  const failed = summarizeRuns([
    { ...attempt(1, "baseline"), status: "failed", error: "scan failed" },
    {
      ...attempt(1, "time-aware"),
      status: "failed",
      error: "scan failed",
      elapsedMs: 200,
    },
  ]);
  assert.equal(failed.arms.baseline.successRate, 0);
  assert.equal(failed.arms.baseline.meanRecall, null);
  assert.equal(failed.arms.baseline.safeControlFindings, null);
  assert.equal(failed.paired.completedPairs, 0);
  assert.equal(failed.paired.excludedPairs, 1);
  assert.equal(failed.paired.meanDelta.elapsedMs, null);
});

test("duplicate arms cannot silently bias results", () => {
  assert.throws(
    () => summarizeRuns([completed(1, "baseline"), completed(1, "baseline")]),
    /Duplicate run for pair 1\/baseline/,
  );
});
