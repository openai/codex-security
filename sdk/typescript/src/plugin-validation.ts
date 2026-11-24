import { compareTimestamps } from "./timestamps.js";
import { validationSummary } from "./validation-provider-report.js";
import {
  evidenceTime,
  verifiedAdmissions,
  type WorkbenchPoll,
} from "./saved-continuum-assessment.js";
import {
  continuumObservations,
  type ContinuumObservation,
} from "./continuum-validation-evidence.js";
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
type Dispute = {
  record: ValidationItemRecord;
  reconfirmAfter?: number;
  siblingOnly?: boolean;
};
type PluginRetry = ValidationProviderAssessment &
  ContinuumObservation & {
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
  { record: tied, siblingOnly }: Dispute,
  update: PluginRetry,
  linkedValidation?: string,
): Dispute | undefined {
  const current = update.record!;
  // Runs explicitly for other findings are fallbacks, regardless of their date.
  if (
    tied.validationArtifactId &&
    update.siblingArtifacts?.includes(tied.validationArtifactId)
  )
    siblingOnly = true;
  if (siblingOnly && !update.siblingOnly) return;
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
  const delta =
    update.siblingOnly &&
    (siblingOnly === false || tied.resultScope === "finding")
      ? -1
      : compareTimestamps(evidenceTime(current), time);
  if (delta > 0) return;
  update.siblingOnly = siblingOnly;
  if (!tied.scoringPending) {
    deferAssessment(update, tied);
    return;
  }
  // A validation tie reported by the provider supersedes a score dispute.
  if (delta === 0 && !current.validationArtifactId) return;

  if (
    delta < 0 &&
    linkedValidation &&
    linkedValidation === tied.validationArtifactId
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
  if (delta !== 0) return { record: tied, siblingOnly };
}

/** One admission can visit several issues while a retry is pending. */
function reconcileRetry(
  saved: PluginRetry | undefined,
  update: PluginRetry,
  poll: WorkbenchPoll,
) {
  const disputes = { ...saved?.disputes };
  const prior = saved?.record;
  if (
    prior?.issueArn &&
    ((prior.verdict === "UNKNOWN" &&
      !prior.validationArtifactId &&
      prior.freshness.evidenceCreatedAt) ||
      (prior.scoringPending && prior.freshness.scoredAt))
  )
    disputes[prior.issueArn] ??= {
      record: prior,
      siblingOnly: saved?.siblingOnly,
    };

  const current = update.record;
  const issue = current?.issueArn;
  if (issue && !current.issueUnlinked) {
    const dispute = disputes[issue];
    const now = performance.timeOrigin + performance.now();
    const moved =
      update.issueChanged ||
      prior?.issueUnlinked ||
      (prior?.issueArn && prior.issueArn !== issue);
    if (moved) {
      poll.changedAt = now;
      delete poll.requestedAt;
    }
    // Earlier retries stored the return time on the dispute.
    poll.changedAt ??= dispute?.reconfirmAfter;
    if (current.verdict === "UNAVAILABLE") {
      if (dispute && (update.issueChanged || prior?.issueArn !== issue))
        current.issueUnlinked = true;
    } else if (dispute) {
      const detached = reconcileDispute(
        dispute,
        update,
        moved ? undefined : prior?.validationArtifactId,
      );
      if (detached) {
        disputes[issue] = detached;
        poll.changedAt ??= now;
      } else delete disputes[issue];
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
  previousPolls: Record<string, WorkbenchPoll> = {},
) {
  const provider = resolveProvider(configuration);
  // Each assessment corresponds to the same position in the sealed findings.
  const pending = findings.filter(
    (_, index) => !previous[index] || retryableAssessment(previous[index]),
  );
  const requestedAt = performance.timeOrigin + performance.now();
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
  const polls = new Map(Object.entries(previousPolls));
  const assessments = findings.map((finding, index) => {
    const saved = previous[index];
    if (saved && !retryableAssessment(saved)) return saved;
    const update: PluginRetry = { ...updates[next++]! };
    const prior = saved?.record;
    const current = update.record;
    if (current) Object.assign(update, continuumObservations.get(current));
    const sameAdmission =
      prior?.findingArn &&
      prior.findingArn === current?.findingArn &&
      prior.submittedAt === current.submittedAt;
    const poll: WorkbenchPoll = sameAdmission
      ? { ...polls.get(current.itemId) }
      : {};
    reconcileRetry(
      sameAdmission || !current?.findingArn ? saved : undefined,
      update,
      poll,
    );
    if (current?.findingArn) polls.set(current.itemId, poll);
    if (current && current.verdict !== "UNAVAILABLE") {
      poll.siblingOnly = update.siblingOnly;
      poll.siblingArtifacts = update.siblingArtifacts;
      delete update.siblingArtifacts;
      // Deferring a disputed score can still confirm the validation it belongs to.
      const confirmed =
        current === update.record ||
        (current.validationArtifactId &&
          current.validationArtifactId === update.record?.validationArtifactId);
      if (confirmed) poll.requestedAt = requestedAt;
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
            !update.issueChanged &&
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
    polls: polls.size ? Object.fromEntries(polls) : undefined,
  };
}
