"use strict";

const { outputText, parseExpected } = require("./output");

module.exports = (output, context) => {
  const expectedTerms = parseExpected(
    context.vars.expected_evidence_terms,
    true,
  );
  if (expectedTerms.length === 0) {
    return {
      pass: true,
      score: 1,
      reason: "No required calibration evidence terms were configured.",
    };
  }

  const normalizedOutput = outputText(output).toLowerCase();
  const missingTerms = expectedTerms.filter((term) => !normalizedOutput.includes(term.toLowerCase()));

  return {
    pass: missingTerms.length === 0,
    score: (expectedTerms.length - missingTerms.length) / expectedTerms.length,
    reason:
      missingTerms.length === 0
        ? "All required calibration evidence terms were cited."
        : `Missing required calibration evidence terms: ${missingTerms.join(", ")}`,
  };
};
