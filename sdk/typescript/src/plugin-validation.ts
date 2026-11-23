import { validationSummary } from "./validation-provider-report.js";
import { validationProviderFromConfiguration } from "./validation-providers.js";
import {
  supplementalValidationStatus,
  retryableAssessment,
  unavailableAssessment,
  type ValidationProviderAssessment,
  type ValidationProviderConfiguration,
  type ValidationProviderContext,
} from "./validation-provider.js";

export { validationProviderFromConfiguration };
export { codexSecurityStateDirectory } from "./runtime.js";
export const continuumAssessmentVersion = 4;
export { withPublicationLock } from "./publication-state.js";
export type { ValidationProviderConfiguration };

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
    (_, index) => !previous[index] || retryableAssessment(previous[index]),
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
    if (saved && !retryableAssessment(saved)) return saved;
    const update = updates[next++]!;
    // A transport failure cannot undo acceptance, or erase a verdict
    // waiting on a score.
    if (
      update.unavailable &&
      (!update.record || update.record.verdict === "UNAVAILABLE")
    ) {
      const prior = saved?.record;
      if (
        prior?.findingArn &&
        (!update.record?.findingArn ||
          (prior.scoringPending &&
            prior.findingArn === update.record.findingArn &&
            (!update.record.issueArn ||
              prior.issueArn === update.record.issueArn) &&
            prior.submittedAt === update.record.submittedAt))
      ) {
        update.record = { ...prior, unavailable: update.unavailable };
        if (prior.scoringPending) update.report = validationSummary([update]);
      }
    }
    return update;
  });
  const summary = validationSummary(assessments);
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
    provider.name === "continuum" && assessments.some(retryableAssessment)
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
