function outputText(output) {
  return typeof output === "string" ? output : JSON.stringify(output);
}

function hasTriageJson(text) {
  return (
    /```(?:json)?\s*[\s\S]*?```/i.test(text) ||
    /schema_version\s*["']?\s*:\s*["']?triage-finding\/v0/i.test(text) ||
    /["']findings["']\s*:/i.test(text) ||
    /["']verdict["']\s*:/i.test(text)
  );
}

const expectedPatterns = {
  unavailable: [/connector|Linear/i, /connect|authenticate|reauthorize/i, /paste|provide.*content/i],
  permission: [/permission|access/i, /request.*access|ask.*access/i, /paste|provide.*content/i],
  not_found: [/not found|inaccessible|identifier/i, /verify|check/i, /paste|provide.*content/i],
  transient: [/retr(?:y|ied)|try again/i, /once|one time|second attempt/i, /paste|provide.*content/i],
};

const expectedSubissuePatterns = {
  direct_confirmation: [/SEC-294/i, /SEC-295/i, /2\s+(?:direct\s+)?sub-issues|two\s+(?:direct\s+)?sub-issues/i, /include|import/i, /ask|would you|do you want/i],
  next_depth: [/SEC-296/i, /next (?:level|depth)|deeper|grandchild/i, /include|import/i, /ask|would you|do you want/i],
  ambiguous_parent: [/parent/i, /independent|standalone|separate/i, /include|triage/i, /ask|would you|do you want/i],
  over_limit: [/250/i, /narrow|smaller|filter|depth|status|label/i, /not.*truncate|cannot.*truncate|stop/i],
};

module.exports = (output, context) => {
  const text = outputText(output);
  const behavior = String(context.vars.expected_ticket_failure || "");
  const subissueBehavior = String(context.vars.expected_linear_subissues || "");
  const patterns = expectedPatterns[behavior] || [];
  const subissuePatterns = expectedSubissuePatterns[subissueBehavior] || [];
  const failures = [];

  for (const pattern of patterns) {
    if (!pattern.test(text)) failures.push(`missing recovery detail matching ${pattern}`);
  }
  for (const pattern of subissuePatterns) {
    if (!pattern.test(text)) failures.push(`missing Linear sub-issue detail matching ${pattern}`);
  }
  if (hasTriageJson(text)) failures.push("must not emit triage JSON when ticket retrieval failed");
  if (/inspected the repository|repository analysis (?:is )?complete|verdict:\s*(?:confirmed|needs_review|not_actionable)/i.test(text)) {
    failures.push("must stop before repository analysis or verdicting");
  }

  return {
    pass: failures.length === 0,
    score: failures.length === 0 ? 1 : 0,
    reason: failures.length === 0 ? "Ticket connector failure produced recovery guidance without triage output." : failures.join("; "),
  };
};
