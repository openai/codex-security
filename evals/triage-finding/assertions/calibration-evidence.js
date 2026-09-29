"use strict";

function outputText(output) {
  return typeof output === "string" ? output : JSON.stringify(output);
}

function parseExpectedTerms(value) {
  if (Array.isArray(value)) {
    return value.map(String).map((term) => term.trim()).filter(Boolean);
  }
  if (typeof value === "string") {
    return value
      .split(",")
      .map((term) => term.trim())
      .filter(Boolean);
  }
  return [];
}

module.exports = (output, context) => {
  const expectedTerms = parseExpectedTerms(context.vars.expected_evidence_terms);
  if (expectedTerms.length === 0) {
    return {
      pass: true,
      score: 1,
      reason: "No required calibration evidence terms were configured.",
    };
  }

  const normalizedOutput = outputText(output).toLowerCase();
  const missingTerms = expectedTerms.filter((term) => !normalizedOutput.includes(term.toLowerCase()));
  const foundCount = expectedTerms.length - missingTerms.length;

  return {
    pass: missingTerms.length === 0,
    score: foundCount / expectedTerms.length,
    reason:
      missingTerms.length === 0
        ? "All required calibration evidence terms were cited."
        : `Missing required calibration evidence terms: ${missingTerms.join(", ")}`,
  };
};
