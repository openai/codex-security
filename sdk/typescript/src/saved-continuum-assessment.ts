import { isDeepStrictEqual } from "node:util";
import { z } from "zod";
import { assessmentStore } from "./continuum-assessment-store.js";
import { compareTimestamps } from "./timestamps.js";
import type { ProcessEnvironment } from "./runtime.js";
import type {
  ValidationProviderConfiguration,
  ValidationItemRecord,
} from "./validation-provider.js";

// The protected provider cache contains host settings and retry receipts as
// well as conclusions. Only this allowlist crosses into model input.
const id = z.string().regex(/^[a-zA-Z0-9_-]+$/);
const text = z.string();
const conclusion = z.object({
  itemId: id,
  provider: z.literal("continuum"),
  findingId: id,
  findingArn: text,
  submittedAt: z.string().datetime(),
  issueId: id.optional(),
  issueArn: text.optional(),
  validationArtifactId: id.optional(),
  scoringArtifactId: id.optional(),
  proofObservation: z
    .object({
      kind: z.enum(["execution", "source_analysis"]),
      effect: text.optional(),
      summary: text.optional(),
    })
    .optional(),
  verdict: text,
  terminalStatus: text.optional(),
  statusMessage: text.optional(),
  providerSeverity: text.optional(),
  resultScope: z.enum(["finding", "issue"]).optional(),
  issueFindingCount: z.number().int().nonnegative().optional(),
  joinedValidatedIssue: z.boolean().optional(),
  reachableFromAttacker: z.boolean().optional(),
  claimMatch: z.enum([
    "on_target",
    "on_target_escalated",
    "different_flaw",
    "unknown",
  ]),
  freshness: z.object({
    validatedAt: text.optional(),
    evidenceCreatedAt: text.optional(),
    stale: z.boolean(),
    reasons: z.array(text),
  }),
  reasons: z.array(z.object({ basis: text, reason: text })),
}) satisfies z.ZodType<
  Omit<ValidationItemRecord, "severityBefore" | "severityAfter">
>;
type Conclusion = z.infer<typeof conclusion>;
const binding = z.object({
  provider: z.string().trim().toLowerCase().pipe(z.literal("continuum")),
  continuum: z.object({
    environment_id: z.string().trim().pipe(id),
    aws_region: z.string().trim().optional(),
  }),
});
const cached = z.object({
  configuration: z.unknown(),
  repositoryPath: z.string(),
  result: z.object({ provider: z.literal("continuum") }),
  records: z.object({
    schemaVersion: z.literal(1),
    items: z.array(z.looseObject({ itemId: text.min(1) })),
  }),
  // The retry field distinguishes caches supporting terminal status from legacy results.
  retry: z.array(z.unknown()).nullable(),
});

// The provider owns attribution. Only forward a stored observation consistent
// with its own identifiers, scope, run status and evidence time.
function hasCurrentProof(item: Conclusion) {
  const { validatedAt, evidenceCreatedAt, stale } = item.freshness;
  return (
    item.terminalStatus === "COMPLETED" &&
    (item.verdict === "EXPLOITABLE" || item.verdict === "NOT_EXPLOITABLE") &&
    (item.claimMatch === "on_target" ||
      item.claimMatch === "on_target_escalated") &&
    item.resultScope === "finding" &&
    item.issueFindingCount === 1 &&
    !item.joinedValidatedIssue &&
    !stale &&
    !!item.issueId &&
    !!item.validationArtifactId &&
    !!item.scoringArtifactId &&
    !!validatedAt &&
    compareTimestamps(validatedAt, item.submittedAt) >= 0 &&
    (evidenceCreatedAt === undefined ||
      compareTimestamps(evidenceCreatedAt, validatedAt) === 0)
  );
}

function project(raw: unknown, environmentId: string, region?: string) {
  const item = conclusion.safeParse(raw);
  if (!item.success) return undefined;
  const record = item.data;
  const arn =
    /^(arn:[^:]+:continuum:([^:]+):[0-9]{12}:environments\/([a-zA-Z0-9_-]+))\/code-findings\/([a-zA-Z0-9_-]+)$/.exec(
      record.findingArn,
    );
  if (!arn) return;
  const [, scope, awsRegion, destination, findingId] = arn;
  const issueArn = record.issueId && scope + "/code-issues/" + record.issueId;
  if (
    findingId !== record.findingId ||
    destination !== environmentId ||
    (region && region !== awsRegion) ||
    record.issueArn !== issueArn
  )
    return;
  if (record.proofObservation && !hasCurrentProof(record))
    delete record.proofObservation;
  return record;
}

/** Persist the same conclusions exposed to remediation. A polling timeout is
 * transient, but a terminal failed validation is itself a provider outcome. */
export async function saveCliContinuumAssessments(
  environment: ProcessEnvironment,
  repositoryPath: string,
  scanId: string,
  configuration: ValidationProviderConfiguration,
  records: readonly (ValidationItemRecord | undefined)[],
) {
  if (configuration.provider.trim().toLowerCase() !== "continuum") return;
  const { environment_id, aws_region } = binding.parse(configuration).continuum;
  const terminal: Conclusion[] = [];
  for (const raw of records) {
    const value = project(raw, environment_id, aws_region);
    if (value && value.verdict !== "UNAVAILABLE") terminal.push(value);
  }
  if (!terminal.length) return;
  const store = await assessmentStore(environment, scanId, repositoryPath);
  await store.writeSnapshots(environment_id, terminal);
}

function sameAdmission(a: Conclusion, b: Conclusion) {
  return a.findingArn === b.findingArn && a.submittedAt === b.submittedAt;
}

function evidenceTime(item: Conclusion) {
  return item.freshness.evidenceCreatedAt ?? item.freshness.validatedAt ?? "";
}

/** A bound plugin result pins the submission. Compare terminal results by AWS
 * artifact creation time within that submission and issue. A tie is ambiguous. */
function selectConclusion(plugin: Conclusion | undefined, cli: Conclusion[]) {
  let newest = plugin?.verdict === "UNAVAILABLE" ? undefined : plugin;
  let tied = false;
  for (const record of cli) {
    if (plugin && !sameAdmission(plugin, record)) continue;
    if (!newest) {
      newest = record;
      continue;
    }
    if (isDeepStrictEqual(newest, record)) continue;
    if (
      !sameAdmission(newest, record) ||
      !newest.issueArn ||
      newest.issueArn !== record.issueArn
    )
      return;
    const delta = compareTimestamps(evidenceTime(record), evidenceTime(newest));
    if (!Number.isFinite(delta)) return;
    if (delta === 0) tied = true;
    if (delta > 0) {
      newest = record;
      tied = false;
    }
  }
  return tied ? undefined : (newest ?? plugin);
}

export async function savedContinuumAssessments(
  environment: ProcessEnvironment,
  scanId: string,
  repositoryPath: string,
  occurrenceIds: readonly string[],
) {
  const assessments = new Map<string, Conclusion>();
  if (!occurrenceIds.length) return assessments;
  const store = await assessmentStore(
    environment,
    scanId,
    repositoryPath,
  ).catch(() => undefined);
  if (!store) return assessments;
  const config = await store.readBinding();
  const bound = binding.safeParse(config);
  if (config !== undefined && !bound.success) return assessments;
  const destination = bound.data?.continuum;
  const requested = new Set(occurrenceIds);
  const result = destination && (await store.readPluginResult());
  if (destination && result !== undefined) {
    const saved = cached.safeParse(result).data;
    // A damaged bound result can hide the original AWS finding ID. Do not
    // substitute a CLI result for a potentially different submission.
    if (
      saved?.repositoryPath !== repositoryPath ||
      JSON.stringify(config) !== JSON.stringify(saved.configuration)
    )
      return assessments;
    for (const raw of saved.records.items) {
      if (!requested.has(raw.itemId)) continue;
      const record = project(
        raw,
        destination.environment_id,
        destination.aws_region,
      );
      if (!record || assessments.has(raw.itemId)) {
        requested.delete(raw.itemId);
        assessments.delete(raw.itemId);
      } else assessments.set(raw.itemId, record);
    }
  }
  const snapshots = await store.readSnapshots(
    requested,
    destination?.environment_id,
  );
  for (const [occurrence, items] of snapshots) {
    const candidates = items?.flatMap(({ record, environmentId }) => {
      const item = project(record, environmentId, destination?.aws_region);
      return item && item.verdict !== "UNAVAILABLE" ? [item] : [];
    });
    const selected =
      candidates && selectConclusion(assessments.get(occurrence), candidates);
    if (selected) assessments.set(occurrence, selected);
    else assessments.delete(occurrence);
  }
  return assessments;
}
