import { isDeepStrictEqual } from "node:util";
import { z } from "zod";
import {
  assessmentStore,
  continuumAssessmentVersion,
} from "./continuum-assessment-store.js";
import { compareTimestamps } from "./timestamps.js";
import type { ProcessEnvironment } from "./runtime.js";
import type {
  ValidationProviderConfiguration,
  ValidationItemRecord,
} from "./validation-provider.js";

const id = z.string().regex(/^[a-zA-Z0-9_-]+$/);
const admission = z.object({
  itemId: id,
  provider: z.literal("continuum"),
  findingId: id,
  findingArn: z.string(),
  submittedAt: z.iso.datetime(),
});
type Admission = z.infer<typeof admission>;
const time = z.iso.datetime({ offset: true });
const verdict = z.enum([
  "EXPLOITABLE",
  "NOT_EXPLOITABLE",
  "UNCERTAIN",
  "UNKNOWN",
  "UNAVAILABLE",
  "DISCARDED",
  "NOT_PURSUED",
]);
// Keep the live issue member count in reports. It can change independently of the verdict.
const conclusion = admission.extend({
  issueId: id.optional(),
  issueArn: z.string().optional(),
  issueUnlinked: z.literal(true).optional(),
  validationArtifactId: id.optional(),
  scoringArtifactId: id.optional(),
  scoringPending: z.boolean().optional(),
  verdict,
  issueVerdict: verdict.optional(),
  terminalStatus: z
    .enum(["COMPLETED", "PARTIAL", "FAILED", "NO_SOURCE_AVAILABLE"])
    .optional(),
  providerSeverity: z
    .enum(["critical", "high", "medium", "low", "informational", "unknown"])
    .optional(),
  resultScope: z.enum(["finding", "issue"]).optional(),
  joinedValidatedIssue: z.boolean().optional(),
  reachableFromAttacker: z.boolean().optional(),
  claimMatch: z.literal("unknown"),
  freshness: z.object({
    validatedAt: time.optional(),
    evidenceCreatedAt: time.optional(),
    scoredAt: time.optional(),
    stale: z.boolean(),
  }),
});
type Conclusion = z.infer<typeof conclusion>;
const binding = z.object({
  provider: z.string().trim().toLowerCase().pipe(z.literal("continuum")),
  continuum: z.object({
    environment_id: z.string().trim().pipe(id),
    aws_region: z.string().trim().optional(),
  }),
});
type Destination = z.infer<typeof binding>["continuum"];
const cached = z.object({
  schemaVersion: z
    .literal([2, 3, 4, 5, 6, continuumAssessmentVersion])
    .optional(),
  configuration: z.unknown(),
  repositoryPath: z.string(),
  result: z.object({ provider: z.literal("continuum") }),
  records: z.object({
    schemaVersion: z.literal(1),
    items: z.array(z.looseObject({ itemId: id })),
  }),
  retry: z.array(z.unknown()).nullable().optional(),
});

function scopeOf(record: Admission, destination?: Destination) {
  const arn =
    /^(arn:[^:]+:continuum:([^:]+):[0-9]{12}:environments\/([a-zA-Z0-9_-]+))\/code-findings\/([a-zA-Z0-9_-]+)$/.exec(
      record.findingArn,
    );
  if (!arn) return;
  const [, scope, region, environment, finding] = arn;
  if (
    finding !== record.findingId ||
    (destination && destination.environment_id !== environment) ||
    (destination?.aws_region && destination.aws_region !== region)
  )
    return;
  return scope;
}

/** A null admission is ambiguous. Only an absent or unsubmitted occurrence is unbound. */
export function verifiedAdmissions(
  records: readonly unknown[],
  configuration: unknown,
) {
  const destination = binding.safeParse(configuration).data?.continuum;
  const pins = new Map<string, Admission | null | undefined>();
  if (!destination) return pins;
  for (const raw of records) {
    const item = raw as Record<string, unknown> | null;
    const itemId = item?.["itemId"];
    if (!item || typeof itemId !== "string") continue;
    const pin = admission.safeParse(raw).data;
    if (pins.has(itemId) || item["admissionConflict"]) pins.set(itemId, null);
    else if (pin && scopeOf(pin, destination)) pins.set(itemId, pin);
    else pins.set(itemId, unsubmitted(item) ? undefined : null);
  }
  return pins;
}

/** A failure before acceptance leaves the occurrence unbound. */
function unsubmitted(item: Record<string, unknown>) {
  return (
    item["provider"] === "continuum" &&
    item["verdict"] === "UNAVAILABLE" &&
    ![
      "admissionConflict",
      "findingId",
      "findingArn",
      "submittedAt",
      "issueId",
      "issueArn",
      "validationArtifactId",
      "scoringArtifactId",
    ].some((key) => Object.hasOwn(item, key))
  );
}

function project(raw: unknown, destination: Destination) {
  const item = conclusion.safeParse(raw).data;
  if (!item) return;
  const scope = scopeOf(item, destination);
  const issueArn = item.issueId && scope + "/code-issues/" + item.issueId;
  if (scope && item.issueArn === issueArn) return item;
}

/** Provider identifiers and prose stay on the host. Scores describe the issue. */
function forRemediation(item: Conclusion) {
  const linked =
    item.issueId &&
    item.scoringArtifactId &&
    item.validationArtifactId &&
    item.freshness.scoredAt &&
    !item.scoringPending &&
    !item.freshness.stale;
  const {
    findingId,
    findingArn,
    issueId,
    issueArn,
    issueUnlinked,
    validationArtifactId,
    scoringArtifactId,
    submittedAt,
    providerSeverity,
    reachableFromAttacker,
    ...context
  } = item;
  return {
    ...context,
    ...(linked && providerSeverity && { issueSeverity: providerSeverity }),
    ...(linked &&
      reachableFromAttacker !== undefined && {
        issueReachableFromAttacker: reachableFromAttacker,
      }),
  };
}

export async function saveCliContinuumAssessments(
  environment: ProcessEnvironment,
  repositoryPath: string,
  scanId: string,
  configuration: ValidationProviderConfiguration,
  records: readonly (ValidationItemRecord | undefined)[],
  requestedAt = performance.timeOrigin + performance.now(),
) {
  if (configuration.provider.trim().toLowerCase() !== "continuum") return;
  const destination = binding.parse(configuration).continuum;
  const accepted = records.flatMap((raw) => project(raw, destination) ?? []);
  if (!accepted.length) return;
  const store = await assessmentStore(environment, scanId, repositoryPath);
  await store.writeSnapshots(destination.environment_id, accepted, requestedAt);
  const active = await readAssessments(
    store,
    repositoryPath,
    accepted.map((item) => item.itemId),
  );
  const skipped = accepted.filter((item) => {
    const selected = active.get(item.itemId);
    return !selected || !sameAdmission(selected, item);
  });
  if (skipped.length)
    return `Patch and verify cannot use this Continuum submission for ${skipped.map((item) => item.itemId).join(", ")}. A newer request, a different workbench submission, or conflicting assessments prevented selection. Check the original destination and submission before retrying. Local findings remain available.`;
}

function sameAdmission(a: Admission, b: Admission) {
  return a.findingArn === b.findingArn && a.submittedAt === b.submittedAt;
}

function evidenceTime(item: Conclusion) {
  return item.freshness.evidenceCreatedAt ?? item.freshness.validatedAt ?? "";
}

function withoutScore(item: Conclusion) {
  const {
    scoringArtifactId,
    scoringPending,
    providerSeverity,
    reachableFromAttacker,
    freshness,
    ...result
  } = item;
  const { scoredAt, ...validationTime } = freshness;
  return { ...result, freshness: validationTime };
}

/** Compare validation first. A later scorer can update the same verdict.
 * Conflicting scores alone do not invalidate an undisputed verdict. */
function selectConclusion(
  records: Conclusion[],
  plugin: Conclusion | undefined,
) {
  // A successful lookup without an issue supersedes earlier CLI verdicts.
  // CLI polls and the workbench cache have no common ordering.
  const unlink = records.findLastIndex((item) => item.issueUnlinked);
  if (unlink >= 0) records = records.slice(unlink);
  if (plugin?.issueUnlinked && records.some((item) => item.issueArn)) return;
  if (
    plugin?.issueArn &&
    unlink >= 0 &&
    !records.some(
      (item) =>
        item.issueArn === plugin.issueArn && item.verdict !== "UNAVAILABLE",
    )
  )
    return;
  if (plugin) records.unshift(plugin);
  const terminal = records.filter((item) => item.verdict !== "UNAVAILABLE");
  if (!terminal.length) return records.at(-1);
  // A failed artifact read can still confirm that the finding changed issues.
  const issue = terminal[0]!.issueArn;
  if (records.some(({ issueArn }) => issueArn && issueArn !== issue)) return;
  let latest = [terminal[0]!];
  for (const item of terminal.slice(1)) {
    const prev = latest[0]!;
    if (isDeepStrictEqual(prev, item)) continue;
    if (!prev.issueArn || prev.issueArn !== item.issueArn) return;
    const delta = compareTimestamps(evidenceTime(item), evidenceTime(prev));
    if (!Number.isFinite(delta)) return;
    if (delta > 0) latest = [item];
    if (delta === 0) latest.push(item);
  }
  const first = latest[0]!;
  if (latest.length === 1) return first;
  const validation = withoutScore(first);
  if (
    !first.validationArtifactId ||
    latest.some((item) => !isDeepStrictEqual(validation, withoutScore(item)))
  )
    return;
  // A pending result with a score time records a known conflict. A plain
  // timeout supplies no score evidence and cannot invalidate a linked score.
  const scored = latest.filter(
    (item) =>
      item.freshness.scoredAt &&
      (item.scoringArtifactId || item.scoringPending),
  );
  scored.sort((a, b) =>
    compareTimestamps(b.freshness.scoredAt!, a.freshness.scoredAt!),
  );
  const best = scored[0];
  if (
    best &&
    !best.scoringPending &&
    !scored.some(
      (item) =>
        compareTimestamps(
          item.freshness.scoredAt!,
          best.freshness.scoredAt!,
        ) === 0 && !isDeepStrictEqual(item, best),
    )
  )
    return best;
  return { ...validation, scoringPending: true };
}

async function readAssessments(
  store: Awaited<ReturnType<typeof assessmentStore>>,
  repositoryPath: string,
  occurrenceIds: readonly string[],
) {
  const assessments = new Map<string, Conclusion>();
  const config = await store.readBinding();
  const destination = binding.safeParse(config).data?.continuum;
  if (config !== undefined && !destination) return assessments;
  const result = destination && (await store.readPluginResult());
  const saved = cached.safeParse(result).data;
  if (
    result !== undefined &&
    (saved?.repositoryPath !== repositoryPath ||
      !isDeepStrictEqual(config, saved.configuration) ||
      (saved.schemaVersion === continuumAssessmentVersion &&
        saved.retry === undefined))
  )
    return assessments;
  const items = saved?.records.items ?? [];
  const grouped = Map.groupBy(items, ({ itemId }) => itemId);
  const legacy =
    saved && saved.schemaVersion !== continuumAssessmentVersion
      ? verifiedAdmissions(items, config)
      : undefined;
  const requested = new Set(occurrenceIds);
  const snapshots = await store.readSnapshots(
    requested,
    destination?.environment_id,
  );
  for (const occurrence of requested) {
    const group = grouped.get(occurrence);
    const entries = snapshots.get(occurrence);
    if ((group && group.length !== 1) || entries === null) continue;
    const item = group?.[0];
    if (item?.["admissionConflict"]) continue;
    const plugin =
      !legacy && destination && item ? project(item, destination) : undefined;
    const pin = plugin ?? legacy?.get(occurrence);
    if (item && !pin && !unsubmitted(item)) continue;
    const candidates = (entries ?? []).flatMap(
      ({ record, environmentId }) =>
        project(record, destination ?? { environment_id: environmentId }) ?? [],
    );
    const selected = pin ?? candidates.at(-1);
    if (!selected) continue;
    // Only a CLI-only scan can switch admissions on explicit validation.
    // Never pick between distinct AWS accounts, regions or environments.
    if (
      !pin &&
      candidates.some((item) =>
        destination
          ? !sameAdmission(item, selected)
          : scopeOf(item) !== scopeOf(selected),
      )
    )
      continue;
    const active = selectConclusion(
      candidates.filter((item) => sameAdmission(item, selected)),
      plugin,
    );
    if (active) assessments.set(occurrence, active);
  }
  return assessments;
}

export async function savedContinuumAssessments(
  environment: ProcessEnvironment,
  scanId: string,
  repositoryPath: string,
  occurrenceIds: readonly string[],
) {
  const assessments = new Map<string, ReturnType<typeof forRemediation>>();
  if (!occurrenceIds.length) return assessments;
  const store = await assessmentStore(
    environment,
    scanId,
    repositoryPath,
  ).catch(() => undefined);
  if (!store) return assessments;
  const active = await readAssessments(store, repositoryPath, occurrenceIds);
  for (const [itemId, record] of active)
    assessments.set(itemId, forRemediation(record));
  return assessments;
}
