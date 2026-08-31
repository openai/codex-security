"use strict";

const VALID_VERDICTS = new Set(["confirmed", "not_actionable", "needs_review"]);
const VALID_LABELS = new Set(["true_positive", "false_positive"]);

function extractTriageResult(output) {
  const text = typeof output === "string" ? output : JSON.stringify(output);
  const fencedBlocks = [...text.matchAll(/```(?:json)?\s*([\s\S]*?)```/gi)].map((match) =>
    match[1].trim(),
  );
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  const candidates =
    fencedBlocks.length > 0
      ? fencedBlocks
      : start >= 0 && end >= start
        ? [text.slice(start, end + 1)]
        : [];
  for (const candidate of candidates) {
    try {
      const parsed = JSON.parse(candidate);
      if (parsed && parsed.schema_version === "triage-finding/v0") {
        return parsed;
      }
    } catch {
      // The response may contain more than one fenced block. Try the next one.
    }
  }
  throw new Error("Could not find a parseable triage-finding/v0 JSON result");
}

function parseCaseOutcome(output, expectedInputId) {
  const result = extractTriageResult(output);
  if (!Array.isArray(result.findings) || result.findings.length !== 1) {
    throw new Error("SastBench triage output must contain exactly one finding");
  }
  const finding = result.findings[0];
  if (finding.input_id !== expectedInputId) {
    throw new Error(
      `SastBench input_id mismatch: expected ${expectedInputId}, got ${finding.input_id}`,
    );
  }
  if (finding.source_type !== "scanner_ticket") {
    throw new Error(
      `SastBench source_type mismatch: expected scanner_ticket, got ${finding.source_type}`,
    );
  }
  if (!VALID_VERDICTS.has(finding.verdict)) {
    throw new Error(`SastBench output has unsupported verdict: ${finding.verdict}`);
  }
  return { verdict: finding.verdict, result };
}

function normalizePromptfooResult(row, shardFile = null) {
  const caseId = String(row.vars?.case_id || "");
  const expectedGroundTruth = String(
    row.testCase?.metadata?.ground_truth || row.test?.metadata?.ground_truth || "",
  );
  const base = {
    caseId,
    expectedGroundTruth,
    shardFile,
    latencyMs: Number.isFinite(row.latencyMs) ? row.latencyMs : null,
    cost: Number.isFinite(row.cost) ? row.cost : null,
    tokenUsage: row.response?.tokenUsage || row.tokenUsage || null,
    sessionId: row.response?.sessionId || row.vars?.sessionId || null,
  };
  const output = row.response?.output;
  if (typeof output !== "string" || output.trim().length === 0) {
    return {
      ...base,
      status: "model_error",
      verdict: null,
      error: String(
        row.response?.error || row.error || row.failureReason || "Model returned no output",
      ),
    };
  }
  try {
    const parsed = parseCaseOutcome(output, caseId);
    return { ...base, status: "ok", verdict: parsed.verdict, error: null };
  } catch (error) {
    return {
      ...base,
      status: "invalid_output",
      verdict: null,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

function emptyNamedScores() {
  return {
    strict_tp: 0,
    strict_tn: 0,
    strict_fp: 0,
    strict_fn: 0,
    decided_tp: 0,
    decided_tn: 0,
    decided_fp: 0,
    decided_fn: 0,
    decided_cases: 0,
    positive_cases: 0,
    negative_cases: 0,
    verdict_confirmed: 0,
    verdict_not_actionable: 0,
    verdict_needs_review: 0,
    retained_positive: 0,
    unsafe_closure: 0,
    false_alert_auto_closure: 0,
    false_alert_escalation: 0,
    confirmed_true: 0,
    confirmed_total: 0,
    abstention: 0,
    remaining_analyst_work: 0,
    execution_or_parse_error: 0,
    model_error: 0,
    invalid_output: 0,
  };
}

/**
 * Convert one normalized case into additive counters for Promptfoo.
 * Promptfoo sums these named scores before evaluating the YAML derived metrics.
 */
function namedScoresForOutcome(outcome) {
  if (!VALID_LABELS.has(outcome.expectedGroundTruth)) {
    throw new Error(`Unsupported expected ground truth: ${outcome.expectedGroundTruth}`);
  }

  const scores = emptyNamedScores();
  const isPositive = outcome.expectedGroundTruth === "true_positive";
  scores[isPositive ? "positive_cases" : "negative_cases"] = 1;

  if (outcome.status !== "ok" || outcome.verdict === "needs_review") {
    scores[isPositive ? "strict_fn" : "strict_fp"] = 1;
  } else if (isPositive) {
    scores[outcome.verdict === "confirmed" ? "strict_tp" : "strict_fn"] = 1;
  } else {
    scores[outcome.verdict === "not_actionable" ? "strict_tn" : "strict_fp"] = 1;
  }

  if (outcome.status !== "ok") {
    scores.execution_or_parse_error = 1;
    scores[outcome.status] = 1;
    scores.remaining_analyst_work = 1;
    return scores;
  }

  scores[`verdict_${outcome.verdict}`] = 1;
  if (outcome.verdict !== "needs_review") {
    scores.decided_cases = 1;
    if (isPositive) {
      scores[outcome.verdict === "confirmed" ? "decided_tp" : "decided_fn"] = 1;
    } else {
      scores[outcome.verdict === "not_actionable" ? "decided_tn" : "decided_fp"] = 1;
    }
  }
  if (outcome.verdict === "needs_review") {
    scores.abstention = 1;
  }
  if (outcome.verdict === "confirmed") {
    scores.confirmed_total = 1;
    scores.confirmed_true = isPositive ? 1 : 0;
  }
  if (isPositive && (outcome.verdict === "confirmed" || outcome.verdict === "needs_review")) {
    scores.retained_positive = 1;
  }
  if (isPositive && outcome.verdict === "not_actionable") {
    scores.unsafe_closure = 1;
  }
  if (!isPositive && outcome.verdict === "not_actionable") {
    scores.false_alert_auto_closure = 1;
  }
  if (!isPositive && outcome.verdict === "needs_review") {
    scores.false_alert_escalation = 1;
  }
  if (outcome.verdict === "confirmed" || outcome.verdict === "needs_review") {
    scores.remaining_analyst_work = 1;
  }
  return scores;
}

module.exports = {
  extractTriageResult,
  parseCaseOutcome,
  normalizePromptfooResult,
  namedScoresForOutcome,
};
