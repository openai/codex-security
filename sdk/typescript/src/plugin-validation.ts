import { validationProviderFromConfiguration } from "./validation-providers.js";
import {
  supplementalValidationStatus,
  unavailableAssessment,
  type ValidationProviderAssessment,
  type ValidationProviderConfiguration,
  type ValidationProviderContext,
  type ValidationItemRecord,
} from "./validation-provider.js";

export { validationProviderFromConfiguration };
export { continuumAssessmentVersion } from "./continuum-assessment-store.js";
export { savedContinuumAssessments } from "./saved-continuum-assessment.js";
export { withPublicationLock } from "./publication-state.js";
export type { ValidationProviderConfiguration };

function itemConclusion(record: ValidationItemRecord): string {
  const verdict = record.terminalStatus
    ? `${record.verdict} (validation run ${record.terminalStatus})`
    : record.verdict;
  const detail = record.statusMessage ? ` ${record.statusMessage}` : "";
  const severity =
    record.severityBefore === record.severityAfter
      ? `Codex severity ${record.severityBefore} retained`
      : `${record.severityBefore} → ${record.severityAfter}`;
  const bases = [...new Set(record.reasons.map((reason) => reason.basis))];
  if (record.resultScope === "issue") {
    const reachability = record.reasons.find((reason) =>
      reason.reason.startsWith("Basis:"),
    );
    const exposure =
      record.reachableFromAttacker === true
        ? "reachable from attacker"
        : record.reachableFromAttacker === false
          ? "not reachable from attacker"
          : "unknown";
    return `Item ${record.itemId}: Codex severity ${record.severityBefore} retained. Findings in issue: ${record.issueFindingCount ?? "unknown"}. Issue-level verdict: ${verdict}; issue severity: ${record.providerSeverity ?? "not returned"}. Not individually validated. Issue reachability: ${exposure}.${reachability ? ` Context: ${reachability.reason}` : ""}${record.joinedValidatedIssue ? " This finding joined an issue Continuum had already validated." : ""}${bases.length ? ` Reason bases: ${bases.join(", ")}.` : ""}${record.freshness.stale ? " Evidence predates this submission." : ""}`;
  }
  return `Item ${record.itemId}: ${severity}. Verdict: ${verdict}.${detail}${record.providerSeverity ? ` Provider severity: ${record.providerSeverity}.` : ""}${bases.length ? ` Reason bases: ${bases.join(", ")}.` : ""} Claim match: ${record.claimMatch}.${record.freshness.stale ? " Evidence predates this submission." : ""}${record.unavailable && !record.terminalStatus ? ` Unavailable: ${record.unavailable}` : ""}`;
}

function retryable(item: ValidationProviderAssessment) {
  // A terminal validation failure is distinct from a transport failure.
  return Boolean(item.unavailable && !item.record?.terminalStatus);
}

export async function assessPluginFindings(
  configuration: ValidationProviderConfiguration,
  findings: Record<string, unknown>[],
  context: ValidationProviderContext,
  resolveProvider = validationProviderFromConfiguration,
  previous: ValidationProviderAssessment[] = [],
) {
  const provider = resolveProvider(configuration);
  // Each assessment corresponds to the same position in the sealed findings.
  const pending = findings.filter(
    (_, index) => !previous[index] || retryable(previous[index]),
  );
  const updates = provider.validateBatch
    ? await provider
        .validateBatch(pending, context)
        .catch((error: unknown) =>
          pending.map(() => unavailableAssessment(provider, error)),
        )
    : await Promise.all(
        pending.map(async (finding) => {
          try {
            return await provider.validate(finding, context);
          } catch (error) {
            return unavailableAssessment(provider, error);
          }
        }),
      );
  let next = 0;
  const assessments = findings.map((_, index) => {
    const saved = previous[index];
    if (saved && !retryable(saved)) return saved;
    const update = updates[next++]!;
    // A retry that fails before reaching AWS still has an accepted finding.
    if (
      saved?.record?.findingArn &&
      !update.record?.findingArn &&
      retryable(update)
    ) {
      update.record = { ...saved.record, unavailable: update.unavailable };
    }
    return update;
  });
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
  // Continuum persists requests and receipts before polling. It is safe to
  // retry transport failures while reusing each definitive provider result.
  const retry =
    provider.name === "continuum" && assessments.some(retryable)
      ? assessments
      : null;
  const status = supplementalValidationStatus(provider, assessments);
  return {
    providerName: provider.name,
    status,
    summary,
    report,
    records,
    retry,
  };
}
