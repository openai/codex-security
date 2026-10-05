const { extractTriageResult } = require("../sastbench/scripts/sastbench-result");

function outputText(output) {
  return typeof output === "string" ? output : JSON.stringify(output);
}

function hasTriageJson(text) {
  try {
    extractTriageResult(text);
    return true;
  } catch {
    return false;
  }
}

function parseExpected(value, trim = typeof value === "string") {
  if (typeof value === "string") {
    value = value.split(",");
  }
  const terms = Array.isArray(value) ? value.map(String) : [];
  return trim ? terms.flatMap((term) => term.trim() || []) : terms;
}

module.exports = { outputText, hasTriageJson, parseExpected };
