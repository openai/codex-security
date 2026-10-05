function outputText(output) {
  return typeof output === "string" ? output : JSON.stringify(output);
}

function hasTriageJson(text) {
  let findings = false;
  let verdict = false;
  for (const [, key, literal] of text.matchAll(/("(?:\\.|[^"\\])*")\s*:\s*("(?:\\.|[^"\\])*"|\[)/g)) {
    try {
      const name = JSON.parse(key);
      const value = literal === "[" ? [] : JSON.parse(literal);
      if (name === "schema_version" && value === "triage-finding/v0") return true;
      findings ||= name === "findings" && Array.isArray(value);
      verdict ||= name === "verdict" && ["confirmed", "needs_review", "not_actionable"].includes(value);
    } catch {
      // Ignore quoted prose that is not a JSON field.
    }
  }
  return findings && verdict;
}

function parseExpected(value, trim = typeof value === "string") {
  if (typeof value === "string") {
    value = value.split(",");
  }
  const terms = Array.isArray(value) ? value.map(String) : [];
  return trim ? terms.flatMap((term) => term.trim() || []) : terms;
}

module.exports = { outputText, hasTriageJson, parseExpected };
