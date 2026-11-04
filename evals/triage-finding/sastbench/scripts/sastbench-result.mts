import { extractTriageResult } from "../../assertions/output.mts";

export { extractTriageResult };

const VALID_VERDICTS = new Set(["confirmed", "not_actionable", "needs_review"]);

export function parseCaseOutcome(output: unknown, expectedInputId: string) {
  const result = extractTriageResult(output);
  if (!Array.isArray(result.findings) || result.findings.length !== 1) {
    throw new Error("SastBench triage output must contain exactly one finding");
  }
  const finding = result.findings[0];
  if (finding.input_id !== expectedInputId) {
    throw new Error(
      `SastBench input_id mismatch: expected ${expectedInputId}, got ${finding.input_id}`,
    );
  }
  if (finding.source_type !== "scanner_ticket") {
    throw new Error(
      `SastBench source_type mismatch: expected scanner_ticket, got ${finding.source_type}`,
    );
  }
  if (!VALID_VERDICTS.has(finding.verdict)) {
    throw new Error(
      `SastBench output has unsupported verdict: ${finding.verdict}`,
    );
  }
  return { verdict: finding.verdict, result };
}
