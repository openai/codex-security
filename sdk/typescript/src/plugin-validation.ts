import { validationProviderFromConfiguration } from "./validation-providers.js";
import {
  unavailableAssessment,
  type ValidationProviderAssessment,
  type ValidationProviderConfiguration,
  type ValidationProviderContext,
  type ValidationItemRecord,
} from "./validation-provider.js";

export { validationProviderFromConfiguration };
export type { ValidationProviderConfiguration };

function itemConclusion(record: ValidationItemRecord): string {
  const bases = [...new Set(record.reasons.map((reason) => reason.basis))];
  if (record.resultScope === "issue") {
    const others =
      record.issueFindingCount === undefined
        ? "other findings"
        : `${record.issueFindingCount - 1} other findings`;
    const reachability = record.reasons.find((reason) =>
      reason.reason.startsWith("Basis:"),
    );
    const exposure =
      record.reachableFromAttacker === true
        ? "reachable from attacker"
        : record.reachableFromAttacker === false
          ? "not reachable from attacker"
          : "unknown";
    return `Item ${record.itemId}: Codex severity ${record.severityBefore} retained. Continuum grouped this finding with ${others} into an issue. Issue-level verdict: ${record.verdict}; issue severity: ${record.providerSeverity ?? "not returned"}. Not individually validated. Issue reachability: ${exposure}.${reachability ? ` Context: ${reachability.reason}` : ""}${record.joinedValidatedIssue ? " This finding joined an issue Continuum had already validated." : ""}${bases.length ? ` Reason bases: ${bases.join(", ")}.` : ""}${record.freshness.stale ? " Evidence predates this submission." : ""}`;
  }
  return `Item ${record.itemId}: ${record.severityBefore} → ${record.severityAfter}. Verdict: ${record.verdict}.${record.providerSeverity ? ` Provider severity: ${record.providerSeverity}.` : ""}${bases.length ? ` Reason bases: ${bases.join(", ")}.` : ""} Claim match: ${record.claimMatch}.${record.freshness.stale ? " Evidence predates this submission." : ""}${record.unavailable ? ` Unavailable: ${record.unavailable}` : ""}`;
}

export async function assessPluginFindings(
  configuration: ValidationProviderConfiguration,
  findings: Record<string, unknown>[],
  context: ValidationProviderContext,
  resolveProvider = validationProviderFromConfiguration,
) {
  const provider = resolveProvider(configuration);
  const assessments: ValidationProviderAssessment[] = provider.validateBatch
    ? await provider
        .validateBatch(findings, context)
        .catch((error: unknown) =>
          findings.map(() => unavailableAssessment(provider, error)),
        )
    : await Promise.all(
        findings.map(async (finding: Record<string, unknown>) => {
          try {
            return await provider.validate(finding, context);
          } catch (error) {
            return unavailableAssessment(provider, error);
          }
        }),
      );
  const summary = assessments
    .map((assessment) =>
      assessment.record ? itemConclusion(assessment.record) : assessment.report,
    )
    .join("\n");
  const report = assessments
    .map(
      (assessment, index) =>
        `## ${findings[index]?.["occurrenceId"] ?? findings[index]?.["id"] ?? `item-${index + 1}`}\n\nDisposition: ${assessment.disposition}\n\n${assessment.report}\n`,
    )
    .join("\n---\n\n");
  const records = {
    schemaVersion: 1,
    findings: findings.length,
    summary,
    items: assessments.flatMap((assessment) =>
      assessment.record ? [assessment.record] : [],
    ),
  };
  return { providerName: provider.name, summary, report, records };
}
