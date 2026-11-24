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

// Keep disputed results from detached issues only in the private retry list.
type Disputes = Record<
  string,
  ValidationProviderAssessment & { reconfirmAfter?: number }
>;
type PluginRetry = ValidationProviderAssessment & { disputes?: Disputes };

/** A replica returning just one of two tied artifacts cannot settle a dispute. */
function resolveDispute(
  { reconfirmAfter, ...dispute }: Disputes[string],
  update: ValidationProviderAssessment,
  disputes: Disputes,
  prior: ValidationProviderAssessment["record"],
): ValidationProviderAssessment {
  const tied = dispute.record!;
  const current = update.record!;
  const linked =
    prior && prior.issueArn === current.issueArn && !prior.issueUnlinked;
  const stillConfirmed =
    linked && prior.validationArtifactId === tied.validationArtifactId;
  const validation = compareTimestamps(
    evidenceTime(current),
    evidenceTime(tied),
  );
  // Membership and issue severity change independently of the evidence.
  const live = {
    issueFindingCount: current.issueFindingCount,
    providerSeverity: current.providerSeverity,
    issueUrl: current.issueUrl,
  };
  if (!tied.scoringPending) {
    if (validation > 0) return update;
    const held = { ...dispute, record: { ...tied, ...live } };
    return { ...held, report: validationSummary([held]) };
  }

  if (current.validationArtifactId === tied.validationArtifactId) {
    const scoredAt = tied.freshness.scoredAt!;
    if (compareTimestamps(current.freshness.scoredAt ?? "", scoredAt) > 0)
      return update;
    if (current.scoringPending) {
      current.freshness.scoredAt = scoredAt;
      return update;
    }
    if (!current.scoringArtifactId) return update;
  } else if (!(stillConfirmed && validation < 0)) {
    // A newer run supersedes the score dispute. A tie in validation
    // itself takes precedence over a tie in scoring at the same time.
    if (validation > 0 || (validation === 0 && !current.validationArtifactId))
      return update;
    // Distinct validations at the same time are ambiguous even across
    // polls. An older run also cannot re-establish the disputed verdict.
    if (validation !== 0)
      disputes[current.issueArn!] = {
        ...dispute,
        reconfirmAfter:
          linked && reconfirmAfter !== undefined
            ? reconfirmAfter
            : performance.timeOrigin + performance.now(),
      };
    const unavailable =
      validation === 0
        ? `Continuum returned conflicting validations (${tied.validationArtifactId}, ${current.validationArtifactId}). Retry when a newer validation is available.`
        : "Continuum returned older validation evidence. Retry to confirm the current validation.";
    const { validatedAt, ...provenance } = update.provenance;
    return {
      disposition: "deferred",
      report: unavailable,
      unavailable,
      provenance,
      record: {
        itemId: current.itemId,
        provider: current.provider,
        submittedAt: current.submittedAt,
        findingId: current.findingId,
        findingArn: current.findingArn,
        issueId: current.issueId,
        issueArn: current.issueArn,
        ...live,
        severityBefore: current.severityBefore,
        severityAfter: current.severityAfter,
        verdict: "UNKNOWN",
        disposition: "deferred",
        claimMatch: "unknown",
        resultScope: "issue",
        freshness: {
          stale: tied.freshness.stale,
          reasons: tied.freshness.reasons,
          evidenceCreatedAt: evidenceTime(tied),
        },
        reasons: [],
        unavailable,
      },
    };
  }
  // An older replica cannot undo a still-linked validation. Refresh the
  // diagnostic in case the saved retry also carries a lookup error.
  const unavailable =
    "Continuum has not returned a newer score to resolve the earlier conflict. Retry validation.";
  const deferred = {
    ...dispute,
    unavailable,
    record: {
      ...tied,
      ...live,
      unavailable,
      reasons: tied.reasons.map((reason) =>
        reason.reason === tied.unavailable
          ? { ...reason, reason: unavailable }
          : reason,
      ),
    },
  };
  return { ...deferred, report: validationSummary([deferred]) };
}

/** One admission can visit several issues while a retry is pending. */
function retainDisputes(saved: PluginRetry, update: PluginRetry) {
  const { disputes: detached, ...last } = saved;
  const disputes = { ...detached };
  const prior = last.record;
  if (
    prior?.issueArn &&
    ((prior.verdict === "UNKNOWN" &&
      !prior.validationArtifactId &&
      prior.freshness.evidenceCreatedAt) ||
      (prior.scoringPending && prior.freshness.scoredAt))
  )
    disputes[prior.issueArn] ??= last;

  const current = update.record;
  const issue = current?.issueArn;
  const dispute = issue && disputes[issue];
  if (dispute && !current.issueUnlinked) {
    if (current.verdict === "UNAVAILABLE") {
      if (prior?.issueArn !== issue) current.issueUnlinked = true;
    } else {
      delete disputes[issue];
      update = resolveDispute(dispute, update, disputes, prior);
    }
  }
  if (Object.keys(disputes).length) update.disputes = disputes;
  return update;
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
    let update = updates[next++]!;
    const prior = saved?.record;
    const current = update.record;
    const sameAdmission =
      prior?.findingArn &&
      prior.findingArn === current?.findingArn &&
      prior.submittedAt === current.submittedAt;
    if (saved && (sameAdmission || !current?.findingArn))
      update = retainDisputes(saved, update);
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
