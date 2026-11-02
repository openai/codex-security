import type { TriageResult } from "../types.ts";

export function gradeFailures(failures: string[], successReason: string) {
  const pass = failures.length === 0;
  return {
    pass,
    score: pass ? 1 : 0,
    reason: pass ? successReason : failures.join("; "),
  };
}

export function outputText(output: unknown) {
  return typeof output === "string" ? output : JSON.stringify(output);
}

export function hasTriageJson(text: string) {
  for (const [, key, literal] of text.matchAll(
    /("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|(?<=[{,])\s*(?:schema_version|verdict))\s*:\s*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|(?:triage-finding\/v0|confirmed|needs_review|not_actionable)(?=\s*[,}]))/g,
  )) {
    try {
      const name = /^["']/.test(key)
        ? JSON.parse(key.replace(/^'|'$/g, '"'))
        : key.trim();
      const value = /^["']/.test(literal)
        ? JSON.parse(literal.replace(/^'|'$/g, '"'))
        : literal;
      if (name === "schema_version" && value === "triage-finding/v0")
        return true;
      if (
        name === "verdict" &&
        ["confirmed", "needs_review", "not_actionable"].includes(value)
      )
        return true;
    } catch {
      // Ignore quoted prose that is not a JSON field.
    }
  }
  let depth = 0;
  let start = 0;
  for (const match of text.matchAll(
    /"(?:\\.|[^"\\])*"|(?<!\w)'(?:\\.|[^'\\])*'|[{}]/g,
  )) {
    if (match[0] === "{") {
      if (depth++ === 0) start = match.index;
    } else if (match[0] === "}" && depth > 0 && --depth === 0) {
      try {
        const result = JSON.parse(text.slice(start, match.index + 1));
        if (
          !("schema_version" in result) &&
          Array.isArray(result.findings) &&
          (result.findings.length === 0 ||
            result.findings.some(
              (finding: { message?: unknown } | null) =>
                typeof finding?.message !== "string",
            ))
        )
          return true;
      } catch {
        // Keep prose and incomplete JSON out of the findings-envelope check.
      }
    }
  }
  return false;
}

export function parseExpected(
  value: unknown,
  trim = typeof value === "string",
) {
  if (typeof value === "string") {
    value = value.split(",");
  }
  const terms = Array.isArray(value) ? value.map(String) : [];
  return trim ? terms.flatMap((term) => term.trim() || []) : terms;
}

function parseTriageJson(candidate: string) {
  try {
    const result = JSON.parse(candidate) as TriageResult;
    if (result?.schema_version === "triage-finding/v0") return result;
  } catch {
    // The output may contain other text or invalid fenced blocks.
  }
}

export function extractTriageResult(
  output: unknown,
  failureMessage = "Could not find a parseable triage-finding/v0 JSON result",
) {
  const text = outputText(output);
  const plain = parseTriageJson(text);
  if (plain) return plain;
  let fenceStart = -1;
  for (const match of text.matchAll(/^[\t ]*```([^\r\n]*)\r?$/gm)) {
    if (fenceStart < 0) {
      fenceStart = match.index + match[0].length;
    } else if (/^[\t ]*$/.test(match[1])) {
      const parsed = parseTriageJson(text.slice(fenceStart, match.index));
      if (parsed) return parsed;
      fenceStart = -1;
    }
  }
  throw new Error(failureMessage);
}
