import { compareTimestamps } from "./timestamps.js";
import { validationSummary } from "./validation-provider-report.js";
import { verifiedAdmissions } from "./saved-continuum-assessment.js";
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
  legacyRecords: readonly unknown[] = [],
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
  const pins = verifiedAdmissions(legacyRecords, configuration);
  const assessments = findings.map((finding, index) => {
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
      if (
        prior?.findingArn &&
        (!current?.findingArn ||
          (sameAdmission &&
            !current.issueUnlinked &&
            (prior.issueUnlinked ||
              !current.issueArn ||
              prior.issueArn === current.issueArn)))
      ) {
        update.record = { ...prior, unavailable: update.unavailable };
        if (prior.scoringPending) update.report = validationSummary([update]);
      } else if (!current?.findingArn) {
        const itemId = String(finding["occurrenceId"]);
        const pin = pins.get(itemId);
        const conflict = prior?.admissionConflict || pin === null;
        if (pin || conflict) {
          if (conflict) {
            const reason =
              "Saved Continuum submission identity is ambiguous. Refresh this occurrence before using its assessment for remediation.";
            update.unavailable += " " + reason;
            update.report += "\n\n" + reason;
          }
          update.record = {
            verdict: "UNAVAILABLE",
            claimMatch: "unknown",
            severityBefore: "unknown",
            severityAfter: "unknown",
            reasons: [],
            freshness: { stale: false, reasons: [] },
            ...current,
            ...(pin ?? {
              provider: "continuum",
              itemId,
              admissionConflict: true as const,
            }),
            unavailable: update.unavailable,
          };
        }
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
