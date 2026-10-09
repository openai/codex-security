import type { TriageResult } from "../types.ts";

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

export function extractTriageResult(
  output: unknown,
  failureMessage = "Could not find a parseable triage-finding/v0 JSON result",
) {
  const text = outputText(output);
  try {
    const parsed = JSON.parse(text) as TriageResult;
    if (parsed && parsed.schema_version === "triage-finding/v0") return parsed;
  } catch {
    // The result may be surrounded by prose or Markdown fences.
  }
  const fencedBlocks: [number, string][] = [];
  const openingFence = /```(?:json)?\s*/gi;
  // Complete JSON strings may contain backticks, but never literal line breaks.
  const tokens = /"|```/g;
  const quoted = /"(?:\\.|[^"\\\r\n])*(")?/y;
  // Escaped quotes within an unterminated string cannot start complete strings.
  let unterminatedUntil = 0;
  let opening;
  while ((opening = openingFence.exec(text))) {
    const start = openingFence.lastIndex;
    tokens.lastIndex = start;
    let token;
    while ((token = tokens.exec(text)) && token[0] !== "```") {
      if (token.index < unterminatedUntil) continue;
      quoted.lastIndex = token.index;
      const string = quoted.exec(text)!;
      if (string[1]) tokens.lastIndex = quoted.lastIndex;
      else unterminatedUntil = quoted.lastIndex;
    }
    if (!token) break;
    fencedBlocks.push([opening.index, text.slice(start, token.index).trim()]);
    openingFence.lastIndex = tokens.lastIndex;
  }
  // Preserve legacy inline framing when malformed quoted text hides a later fence.
  for (const match of text.matchAll(/```(?:json)?\s*([\s\S]*?)```/gi)) {
    fencedBlocks.push([match.index, match[1].trim()]);
  }
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  const candidates =
    fencedBlocks.length > 0
      ? fencedBlocks
          .sort((left, right) => left[0] - right[0])
          .map(([, body]) => body)
      : [text.slice(start, end + 1)];
  for (const candidate of candidates) {
    try {
      const parsed = JSON.parse(candidate) as TriageResult;
      if (parsed && parsed.schema_version === "triage-finding/v0") {
        return parsed;
      }
    } catch {
      // The response may contain more than one fenced block. Try the next one.
    }
  }
  throw new Error(failureMessage);
}
