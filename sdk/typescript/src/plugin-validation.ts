import { compareTimestamps } from "./timestamps.js";
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
export { continuumAssessmentVersion } from "./continuum-assessment-store.js";
export { savedContinuumAssessments } from "./saved-continuum-assessment.js";
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
    const prior = saved?.record;
    const current = update.record;
    const sameAdmission =
      prior?.findingArn &&
      prior.findingArn === current?.findingArn &&
      prior.submittedAt === current.submittedAt;
    // A replica may return just one of two disputed scores on retry.
    // Only a newer score can settle the dispute for this validation.
    if (
      sameAdmission &&
      prior.issueArn === current.issueArn &&
      prior.validationArtifactId === current.validationArtifactId &&
      prior.scoringPending &&
      prior.freshness.scoredAt &&
      !(
        compareTimestamps(
          current.freshness.scoredAt ?? "",
          prior.freshness.scoredAt,
        ) > 0
      )
    ) {
      if (current.scoringPending)
        current.freshness.scoredAt = prior.freshness.scoredAt;
      else if (current.scoringArtifactId) {
        update.disposition = "deferred";
        update.unavailable =
          "Continuum has not returned a newer score to resolve the earlier conflict. Retry validation.";
        update.record = { ...prior, unavailable: update.unavailable };
        update.report = validationSummary([update]);
        return update;
      }
    }

    // A failed lookup cannot undo acceptance or a confirmed change of issue.
    // A successful lookup with no issue must drop the previous issue's verdict.
    if (update.unavailable && (!current || current.verdict === "UNAVAILABLE")) {
      // Keep a newly observed link visible without reviving detached evidence.
      if (sameAdmission && prior.issueUnlinked && current.issueArn)
        current.issueUnlinked = true;
      if (
        prior?.findingArn &&
        (!current?.findingArn ||
          (sameAdmission &&
            !current.issueUnlinked &&
            (!current.issueArn || prior.issueArn === current.issueArn)))
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
