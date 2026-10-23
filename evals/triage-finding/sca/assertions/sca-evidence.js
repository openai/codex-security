"use strict";

const {
  caseById,
  EXPECTED,
  parseOutcome,
} = require("../scripts/sca-result.js");

module.exports = (output, context) => {
  try {
    const testCase = caseById(context.vars.case_id);
    const parsed = parseOutcome(output, testCase);
    const failures = [...parsed.evidenceFailures];
    if (parsed.finding.verdict !== EXPECTED[testCase.gold_label]) {
      failures.push(
        `Expected ${EXPECTED[testCase.gold_label]}, received ${parsed.finding.verdict}`,
      );
    }
    return {
      pass: failures.length === 0,
      score: failures.length === 0 ? 1 : 0,
      reason:
        failures.length === 0
          ? "Correct synthetic verdict and source-backed citations; human evidence review is still separate."
          : failures.join("; "),
    };
  } catch (error) {
    return { pass: false, score: 0, reason: error.message };
  }
};
