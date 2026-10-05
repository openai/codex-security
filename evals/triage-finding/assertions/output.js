function outputText(output) {
  return typeof output === "string" ? output : JSON.stringify(output);
}

function hasTriageJson(text) {
  return /"schema_version"\s*:\s*"triage-finding\/v0"/.test(text);
}

function parseExpected(value, trim = typeof value === "string") {
  if (typeof value === "string") {
    value = value.split(",");
  }
  const terms = Array.isArray(value) ? value.map(String) : [];
  return trim ? terms.flatMap((term) => term.trim() || []) : terms;
}

module.exports = { outputText, hasTriageJson, parseExpected };
