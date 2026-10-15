import { outputText, hasTriageJson } from "./output.mts";
import type { AssertionContext } from "../types.ts";

const expectedPatterns: Record<string, RegExp[]> = {
  unavailable: [
    /connector|Linear/i,
    /connect|authenticate|reauthorize/i,
    /paste|provide.*content/i,
  ],
  permission: [
    /permission|access/i,
    /request.*access|ask.*access/i,
    /paste|provide.*content/i,
  ],
  not_found: [
    /not found|inaccessible|identifier/i,
    /verify|check/i,
    /paste|provide.*content/i,
  ],
  transient: [
    /retr(?:y|ied)|try again/i,
    /once|one time|second attempt/i,
    /paste|provide.*content/i,
  ],
};

const expectedSubissuePatterns: Record<string, RegExp[]> = {
  direct_confirmation: [
    /SEC-294/i,
    /SEC-295/i,
    /(?:2|two)\s+(?:direct\s+)?(?:sub-issues|children)/i,
    /include|import/i,
    /ask|would you|do you want/i,
  ],
  next_depth: [
    /SEC-296/i,
    /next (?:level|depth)|deeper|grandchild/i,
    /include|import/i,
    /ask|would you|do you want/i,
  ],
  ambiguous_parent: [
    /parent/i,
    /independent|standalone|separate/i,
    /include|triage/i,
    /ask|would you|do you want/i,
  ],
};

export default (output: unknown, context: AssertionContext) => {
  const text = outputText(output);
  const behavior = String(context.vars.expected_ticket_failure || "");
  const subissueBehavior = String(context.vars.expected_linear_subissues || "");
  const patterns = Object.hasOwn(expectedPatterns, behavior)
    ? expectedPatterns[behavior]
    : [];
  const subissuePatterns = Object.hasOwn(
    expectedSubissuePatterns,
    subissueBehavior,
  )
    ? expectedSubissuePatterns[subissueBehavior]
    : [];
  const failures = [];

  if (
    (!behavior && !subissueBehavior) ||
    (behavior && !Object.hasOwn(expectedPatterns, behavior))
  ) {
    failures.push(`unknown expected_ticket_failure: ${behavior}`);
  }
  if (
    subissueBehavior &&
    !Object.hasOwn(expectedSubissuePatterns, subissueBehavior)
  ) {
    failures.push(`unknown expected_linear_subissues: ${subissueBehavior}`);
  }

  for (const pattern of patterns) {
    if (!pattern.test(text))
      failures.push(`missing recovery detail matching ${pattern}`);
  }
  for (const pattern of subissuePatterns) {
    if (!pattern.test(text))
      failures.push(`missing Linear sub-issue detail matching ${pattern}`);
  }
  if (hasTriageJson(text))
    failures.push("must not emit triage JSON when ticket retrieval failed");
  if (
    /inspected the repository|repository analysis (?:is )?complete|verdict:\s*(?:confirmed|needs_review|not_actionable)/i.test(
      text,
    )
  ) {
    failures.push("must stop before repository analysis or verdicting");
  }

  return {
    pass: failures.length === 0,
    score: failures.length === 0 ? 1 : 0,
    reason:
      failures.length === 0
        ? "Ticket connector failure produced recovery guidance without triage output."
        : failures.join("; "),
  };
};
