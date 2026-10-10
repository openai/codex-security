"use strict";

const {
  normalizePromptfooResult,
  EXPECTED,
} = require("../scripts/sca-result.js");

// afterEach also receives provider errors that never reach normal assertions.
function afterEach(context) {
  const outcome = normalizePromptfooResult({
    ...context.result,
    vars: context.result.vars || context.test.vars,
  });
  const valid = outcome.status === "ok";
  const decisive = valid && outcome.verdict !== "needs_review";
  const scores = {
    attempted: 1,
    affected_cases: Number(outcome.goldLabel === "affected"),
    unresolved_cases: Number(outcome.goldLabel === "unresolved"),
    confirmed: Number(valid && outcome.verdict === "confirmed"),
    correctly_confirmed: Number(
      valid &&
        outcome.verdict === "confirmed" &&
        outcome.goldLabel === "affected",
    ),
    incorrect_dismissals: Number(
      valid &&
        outcome.verdict === "not_actionable" &&
        outcome.goldLabel === "affected",
    ),
    correctly_unresolved: Number(
      valid &&
        outcome.verdict === "needs_review" &&
        outcome.goldLabel === "unresolved",
    ),
    decisive: Number(decisive),
    correctly_decided: Number(
      decisive && outcome.verdict === EXPECTED[outcome.goldLabel],
    ),
    execution_errors: Number(outcome.status === "model_error"),
    invalid_outputs: Number(outcome.status === "invalid_output"),
    unsupported_citations: Number(valid && outcome.evidenceFailures.length > 0),
  };
  return {
    test: context.test,
    result: {
      ...context.result,
      namedScores: { ...context.result.namedScores, ...scores },
      metadata: { ...context.result.metadata, sca: outcome },
    },
  };
}

module.exports = { afterEach };
