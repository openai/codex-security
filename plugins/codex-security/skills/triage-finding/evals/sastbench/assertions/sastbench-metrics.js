"use strict";

const {
  namedScoresForOutcome,
  normalizePromptfooResult,
} = require("../scripts/sastbench-result");

/**
 * Add benchmark counters after every Promptfoo row, including provider errors
 * for which normal assertions do not run. Sample rows scale the counters by
 * their population weight so the shared derived metrics estimate the full
 * benchmark without a second scoring implementation.
 */
function afterEach(context) {
  const row = {
    ...context.result,
    vars: context.result.vars || context.test.vars,
    testCase: context.result.testCase || context.test,
  };
  const outcome = normalizePromptfooResult(row);
  const rawSampleWeight = context.test.metadata?.sample_weight;
  const sampleWeight = rawSampleWeight === undefined ? 1 : Number(rawSampleWeight);
  if (!Number.isFinite(sampleWeight) || sampleWeight <= 0) {
    throw new Error(`SastBench sample_weight must be a positive number, got ${rawSampleWeight}`);
  }
  const weightedScores = Object.fromEntries(
    Object.entries(namedScoresForOutcome(outcome)).map(([name, value]) => [
      name,
      value * sampleWeight,
    ]),
  );
  return {
    test: context.test,
    result: {
      ...context.result,
      namedScores: {
        ...context.result.namedScores,
        ...weightedScores,
      },
      metadata: {
        ...context.result.metadata,
        sastbench: {
          status: outcome.status,
          verdict: outcome.verdict,
          error: outcome.error,
          sampleWeight,
        },
      },
    },
  };
}

module.exports = { afterEach };
