import { compareTimestamps } from "./timestamps.js";
import { validationSummary } from "./validation-provider-report.js";
import {
  evidenceTime,
  verifiedAdmissions,
} from "./saved-continuum-assessment.js";
import { validationProviderFromConfiguration } from "./validation-providers.js";
import {
  supplementalValidationStatus,
  retryableAssessment,
  unavailableAssessment,
  type ValidationItemRecord,
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

// While membership is uncertain, keep the disputed evidence in private retry
// state. Previously saved full assessments also have these fields.
type Dispute = { record: ValidationItemRecord; reconfirmAfter?: number };
type PluginRetry = ValidationProviderAssessment & {
  disputes?: Record<string, Dispute>;
};

// Keep disputed evidence, but refresh issue metadata and the reason for deferral.
function deferAssessment(
  update: ValidationProviderAssessment,
  record: ValidationItemRecord,
  unavailable = record.unavailable ??
    "Retry when a newer validation is available.",
) {
  const current = update.record!;
  update.disposition = "deferred";
  update.unavailable = unavailable;
  update.provenance = {
    ...update.provenance,
    validatedAt: record.freshness.validatedAt,
  };
  update.record = {
    ...record,
    disposition: "deferred",
    unavailable,
    issueFindingCount: current.issueFindingCount,
    providerSeverity: current.providerSeverity,
    issueUrl: current.issueUrl,
    reasons: record.reasons.map((item) =>
      item.reason === record.unavailable
        ? { ...item, reason: unavailable }
        : item,
    ),
  };
  update.report = validationSummary([update]);
}

/** Only a detached score dispute needs a separate record after this poll. */
function reconcileDispute(
  { record: tied, reconfirmAfter }: Dispute,
  update: ValidationProviderAssessment,
  prior?: ValidationItemRecord,
): Dispute | undefined {
  const current = update.record!;
  const scoreConflict =
    "Continuum has not returned a newer score to resolve the earlier conflict. Retry validation.";
  if (
    tied.scoringPending &&
    current.validationArtifactId === tied.validationArtifactId
  ) {
    const scoredAt = tied.freshness.scoredAt!;
    if (compareTimestamps(current.freshness.scoredAt ?? "", scoredAt) > 0)
      return;
    if (current.scoringPending) current.freshness.scoredAt = scoredAt;
    else if (current.scoringArtifactId)
      deferAssessment(update, tied, scoreConflict);
    return;
  }

  const time = evidenceTime(tied);
  const delta = compareTimestamps(evidenceTime(current), time);
  if (delta > 0) return;
  if (!tied.scoringPending) {
    deferAssessment(update, tied);
    return;
  }
  // A validation tie reported by the provider supersedes a score dispute.
  if (delta === 0 && !current.validationArtifactId) return;

  const linked = prior?.issueArn === current.issueArn && !prior?.issueUnlinked;
  if (
    delta < 0 &&
    linked &&
    prior?.validationArtifactId === tied.validationArtifactId
  ) {
    deferAssessment(update, tied, scoreConflict);
    return;
  }

  // When neither artifact supplies a verdict, keep only the submission and issue.
  const unavailable =
    delta === 0
      ? `Continuum returned conflicting validations (${tied.validationArtifactId}, ${current.validationArtifactId}). Retry when a newer validation is available.`
      : "Continuum returned older validation evidence. Retry to confirm the current validation.";
  const unknown: ValidationItemRecord = {
    itemId: current.itemId,
    provider: current.provider,
    submittedAt: current.submittedAt,
    findingId: current.findingId,
    findingArn: current.findingArn,
    issueId: current.issueId,
    issueArn: current.issueArn,
    severityBefore: current.severityBefore,
    severityAfter: current.severityAfter,
    verdict: "UNKNOWN",
    claimMatch: "unknown",
    resultScope: "issue",
    freshness: {
      stale: tied.freshness.stale,
      reasons: tied.freshness.reasons,
      evidenceCreatedAt: time,
    },
    reasons: [],
  };
  deferAssessment(update, unknown, unavailable);
  // Equal-time validations need a newer run. After a move, a fresh poll
  // can instead reconfirm the original validation and settle its score.
  if (delta !== 0)
    return {
      record: tied,
      reconfirmAfter:
        linked && reconfirmAfter !== undefined
          ? reconfirmAfter
          : performance.timeOrigin + performance.now(),
    };
}

/** One admission can visit several issues while a retry is pending. */
function retainDisputes(saved: PluginRetry, update: PluginRetry) {
  const disputes = { ...saved.disputes };
  const prior = saved.record;
  if (
    prior?.issueArn &&
    ((prior.verdict === "UNKNOWN" &&
      !prior.validationArtifactId &&
      prior.freshness.evidenceCreatedAt) ||
      (prior.scoringPending && prior.freshness.scoredAt))
  )
    disputes[prior.issueArn] ??= { record: prior };

  const current = update.record;
  const issue = current?.issueArn;
  const dispute = issue && disputes[issue];
  if (dispute && !current.issueUnlinked) {
    if (current.verdict === "UNAVAILABLE") {
      if (prior?.issueArn !== issue) current.issueUnlinked = true;
    } else {
      const detached = reconcileDispute(dispute, update, prior);
      if (detached) disputes[issue] = detached;
      else delete disputes[issue];
    }
  }
  if (Object.keys(disputes).length) update.disputes = disputes;
}

export async function assessPluginFindings(
  configuration: ValidationProviderConfiguration,
  findings: Record<string, unknown>[],
  context: ValidationProviderContext,
  resolveProvider = validationProviderFromConfiguration,
  previous: PluginRetry[] = [],
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
    const update = { ...updates[next++]! };
    const prior = saved?.record;
    const current = update.record;
    const sameAdmission =
      prior?.findingArn &&
      prior.findingArn === current?.findingArn &&
      prior.submittedAt === current.submittedAt;
    if (saved && (sameAdmission || !current?.findingArn))
      retainDisputes(saved, update);
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
