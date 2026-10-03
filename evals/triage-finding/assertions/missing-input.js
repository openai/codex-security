function outputText(output) {
  return typeof output === "string" ? output : JSON.stringify(output);
}

function matchedFormatNames(text) {
  const supportedFormats = [
    ["SARIF", /\bSARIF\b/i],
    ["CVE", /\bCVE\b/i],
    ["advisory", /\badvisor(?:y|ies)\b/i],
    ["scanner ticket", /\bscanner\b|\bticket\b/i],
    ["bug bounty report", /\bbug bounty\b/i],
    ["Codex Security finding", /\bCodex Security\b|\bfinding artifact\b/i],
    ["freeform claim", /\bfreeform\b|\bplain[- ]language\b|\bvulnerability claim\b/i],
  ];

  return supportedFormats
    .filter(([, pattern]) => pattern.test(text))
    .map(([name]) => name);
}

module.exports = (output) => {
  const text = outputText(output);
  const failures = [];
  const promptForInputPattern =
    /\b(provide|paste|share|send|supply|include)\b[\s\S]{0,120}\b(finding|input|SARIF|CVE|advisory|scanner|ticket|bug bounty|report|artifact|claim)\b/i;
  const inputBeforeVerbPattern =
    /\b(finding|input|SARIF|CVE|advisory|scanner|ticket|bug bounty|report|artifact|claim)\b[\s\S]{0,120}\b(provide|paste|share|send|supply|include)\b/i;

  if (!promptForInputPattern.test(text) && !inputBeforeVerbPattern.test(text)) {
    failures.push("response must ask the user to provide, paste, share, send, or include a finding/input");
  }

  const formats = matchedFormatNames(text);
  if (formats.length < 4) {
    failures.push(
      `response must mention at least four supported input formats; matched ${formats.length}: ${formats.join(", ")}`,
    );
  }

  if (/```(?:json)?\s*[\s\S]*?```/i.test(text)) {
    failures.push("response must not return a fenced JSON block when no finding was supplied");
  }

  for (const pattern of [
    /schema_version\s*["']?\s*:\s*["']?triage-finding\/v0/i,
    /["']findings["']\s*:/i,
    /["']verdict["']\s*:/i,
  ]) {
    if (pattern.test(text)) {
      failures.push("response must not emit a triage result JSON object when no finding was supplied");
      break;
    }
  }

  return {
    pass: failures.length === 0,
    score: failures.length === 0 ? 1 : 0,
    reason:
      failures.length === 0
        ? "Missing-input response asks for a finding and names supported formats without triage JSON."
        : failures.join("; "),
  };
};
