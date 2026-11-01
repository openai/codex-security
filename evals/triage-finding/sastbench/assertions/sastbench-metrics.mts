import type { PromptfooRow, PromptfooTest } from "../../types.ts";

import { parseCaseOutcome } from "../scripts/sastbench-result.mts";

const VALID_LABELS = new Set(["true_positive", "false_positive"]);

/**
 * Add benchmark counters after every Promptfoo row, including provider errors
 * for which normal assertions do not run. Sample rows scale the counters by
 * their population weight so the shared derived metrics estimate the full
 * benchmark without a second scoring implementation. Promptfoo sums these
 * named scores before evaluating the YAML derived metrics.
 */
export function afterEach(context: {
  result: PromptfooRow;
  test: PromptfooTest;
}) {
  const row = context.result;
  const caseId = String(row.vars.case_id || "");
  const expectedGroundTruth = String(context.test.metadata?.ground_truth || "");
  const output = row.response?.output;
  let status = "model_error";
  let verdict: string | null = null;
  let error: string | null = null;
  if (typeof output !== "string" || output.trim().length === 0) {
    error = String(
      row.response?.error ||
        row.error ||
        row.failureReason ||
        "Model returned no output",
    );
  } else {
    try {
      verdict = parseCaseOutcome(output, caseId).verdict;
      status = "ok";
    } catch (cause) {
      status = "invalid_output";
      error = cause instanceof Error ? cause.message : String(cause);
    }
  }
  const rawSampleWeight = context.test.metadata?.sample_weight;
  const sampleWeight =
    rawSampleWeight === undefined ? 1 : Number(rawSampleWeight);
  if (!Number.isFinite(sampleWeight) || sampleWeight <= 0) {
    throw new Error(
      `SastBench sample_weight must be a positive number, got ${rawSampleWeight}`,
    );
  }
  if (!VALID_LABELS.has(expectedGroundTruth)) {
    throw new Error(
      `Unsupported expected ground truth: ${expectedGroundTruth}`,
    );
  }
  const positive = expectedGroundTruth === "true_positive";
  const confirmed = verdict === "confirmed";
  const closed = verdict === "not_actionable";
  const review = verdict === "needs_review";
  const scores: Record<string, number> = {
    ...context.result.namedScores,
    strict_tp: positive && confirmed ? sampleWeight : 0,
    strict_tn: !positive && closed ? sampleWeight : 0,
    strict_fp: !positive && !closed ? sampleWeight : 0,
    strict_fn: positive && !confirmed ? sampleWeight : 0,
    decided_tp: positive && confirmed ? sampleWeight : 0,
    decided_tn: !positive && closed ? sampleWeight : 0,
    decided_fp: !positive && confirmed ? sampleWeight : 0,
    decided_fn: positive && closed ? sampleWeight : 0,
    decided_cases: confirmed || closed ? sampleWeight : 0,
    positive_cases: positive ? sampleWeight : 0,
    negative_cases: !positive ? sampleWeight : 0,
    verdict_confirmed: confirmed ? sampleWeight : 0,
    verdict_not_actionable: closed ? sampleWeight : 0,
    verdict_needs_review: review ? sampleWeight : 0,
    retained_positive: positive && (confirmed || review) ? sampleWeight : 0,
    unsafe_closure: positive && closed ? sampleWeight : 0,
    false_alert_auto_closure: !positive && closed ? sampleWeight : 0,
    false_alert_escalation: !positive && review ? sampleWeight : 0,
    confirmed_true: positive && confirmed ? sampleWeight : 0,
    confirmed_total: confirmed ? sampleWeight : 0,
    abstention: review ? sampleWeight : 0,
    remaining_analyst_work: !closed ? sampleWeight : 0,
    execution_or_parse_error: status !== "ok" ? sampleWeight : 0,
    model_error: status === "model_error" ? sampleWeight : 0,
    invalid_output: status === "invalid_output" ? sampleWeight : 0,
  };
  return {
    test: context.test,
    result: {
      ...context.result,
      namedScores: scores,
      metadata: {
        ...context.result.metadata,
        sastbench: {
          status,
          verdict,
          error,
          sampleWeight,
        },
      },
    },
  };
}
