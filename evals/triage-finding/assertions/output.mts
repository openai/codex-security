import type { TriageResult } from "../types.ts";

export function outputText(output: unknown) {
  return typeof output === "string" ? output : JSON.stringify(output);
}

export function hasTriageJson(text: string) {
  return (
    /```(?:json)?\s*[\s\S]*?```/i.test(text) ||
    /schema_version\s*["']?\s*:\s*["']?triage-finding\/v0/i.test(text) ||
    /["']findings["']\s*:/i.test(text) ||
    /["']verdict["']\s*:/i.test(text)
  );
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
  const fencedBlocks = [...text.matchAll(/```(?:json)?\s*([\s\S]*?)```/gi)].map(
    (match) => match[1].trim(),
  );
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  const candidates =
    fencedBlocks.length > 0 ? fencedBlocks : [text.slice(start, end + 1)];
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
