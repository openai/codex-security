import { isDeepStrictEqual } from "node:util";
import { z } from "zod";
import {
  assessmentStore,
  continuumAssessmentVersion,
} from "./continuum-assessment-store.js";
import { continuumObservations } from "./continuum-validation-evidence.js";
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
const memberScope = {
  siblingOnly: z.boolean().optional(),
  siblingArtifacts: z.array(z.string()).optional(),
};
// Keep the live issue member count in reports. It can change independently of the verdict.
const conclusion = admission.extend({
  issueId: id.optional(),
  issueArn: z.string().optional(),
  issueUnlinked: z.literal(true).optional(),
  ...memberScope,
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
// A failed assessment may have no record. Reports omit those positions.
const retryItem = z
  .object({
    record: z.object({ itemId: id }),
    disputes: z.record(z.string(), z.unknown()).optional(),
  })
  .nullable()
  .catch(null);
const workbenchPoll = z.object({
  requestedAt: z.number().optional(),
  changedAt: z.number().optional(),
  ...memberScope,
});
export type WorkbenchPoll = z.infer<typeof workbenchPoll>;
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
  retry: z.array(retryItem).nullable().optional(),
  polls: z.record(id, workbenchPoll).optional(),
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
  if (!scope || item.issueArn !== issueArn) return;
  // An unconfirmed link is useful in reports but cannot establish membership.
  if (item.issueUnlinked) {
    delete item.issueId;
    delete item.issueArn;
  }
  return item;
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
    siblingOnly,
    siblingArtifacts,
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
  const accepted = records.flatMap((record) => {
    const item = project(record, destination);
    return record && item
      ? [{ ...item, ...continuumObservations.get(record) }]
      : [];
  });
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
    return (
      !selected ||
      !sameAdmission(selected, item) ||
      (item.issueArn && item.issueArn !== selected.issueArn)
    );
  });
  if (skipped.length)
    return `Patch and verify cannot use this Continuum assessment for ${skipped.map((item) => item.itemId).join(", ")}. A newer request, a different workbench submission, or conflicting assessments prevented selection. Check the original destination and submission before retrying. Local findings remain available.`;
}

function sameAdmission(a: Admission, b: Admission) {
  return a.findingArn === b.findingArn && a.submittedAt === b.submittedAt;
}

export function evidenceTime(item: Pick<Conclusion, "freshness">) {
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

// The workbench saw older evidence on return to a disputed issue. Its
// public UNKNOWN result alone cannot distinguish this from a validation tie.
const disputedScore = z.object({
  reconfirmAfter: z.number().optional(),
  record: conclusion,
});
function pendingScore(
  plugin: Conclusion | undefined,
  retries?: z.infer<typeof retryItem>[],
) {
  if (
    !plugin?.issueArn ||
    plugin.verdict !== "UNKNOWN" ||
    plugin.validationArtifactId ||
    retries?.length !== 1
  )
    return;
  const raw = retries[0]?.disputes?.[plugin.issueArn];
  const pending = disputedScore.safeParse(raw).data;
  const tied = pending?.record;
  if (tied) tied.siblingOnly = plugin.siblingOnly;
  if (
    tied?.scoringPending &&
    tied.freshness.scoredAt &&
    tied.validationArtifactId &&
    tied.itemId === plugin.itemId &&
    sameAdmission(tied, plugin) &&
    tied.issueArn === plugin.issueArn &&
    evidenceTime(tied) === evidenceTime(plugin)
  )
    return pending;
}

function after(requestedAt: number | undefined, change: number | undefined) {
  return (
    change === undefined || (requestedAt !== undefined && requestedAt > change)
  );
}

/** CLI requests establish membership in start order. Evidence from previous
 * visits can reveal disputes but cannot restore a verdict or a score. */
function selectConclusion(
  cli: {
    item: Conclusion;
    requestedAt?: number;
    completedAt?: number;
    issueChanged: boolean;
  }[],
  plugin: Conclusion | undefined,
  pending: z.infer<typeof disputedScore> | undefined,
  poll?: WorkbenchPoll,
) {
  const membership = cli.findLast(
    ({ item }) => item.issueArn || item.issueUnlinked,
  );
  const issue = membership?.item.issueArn;
  const departures = cli.filter(
    ({ item, issueChanged }) =>
      issueChanged ||
      item.issueUnlinked ||
      (item.issueArn && item.issueArn !== issue),
  );
  const change = departures.at(-1);
  if (plugin?.issueUnlinked && issue) return;
  if (membership && plugin?.issueArn && plugin.issueArn !== issue) return;

  // Missing or equal request times cannot confirm a return.
  const cliChangedAt = change && (change.requestedAt ?? Infinity);
  const changedAt = poll?.changedAt ?? pending?.reconfirmAfter;
  const current: Conclusion[] = [];
  const history: Conclusion[] = [];
  for (const entry of cli) {
    const { item, requestedAt } = entry;
    // One request can observe both a departure and a confirmed return.
    const returned =
      entry === change && entry.issueChanged && item.issueArn === issue;
    if (
      (entry === change && !issue) ||
      (after(requestedAt, changedAt) &&
        (returned || after(requestedAt, cliChangedAt)))
    )
      current.push(item);
    else if (issue && item.issueArn === issue && evidenceTime(item))
      history.push(item);
  }
  if (issue && pending && changedAt !== undefined) history.push(pending.record);
  // CLI requests can finish out of order. The poll must follow every departure.
  else if (
    plugin?.issueArn &&
    departures.some(
      ({ completedAt }) => !after(poll?.requestedAt, completedAt ?? Infinity),
    )
  )
    history.push(plugin);
  else if (plugin) current.unshift(plugin);

  const terminal = current.find((item) => item.verdict !== "UNAVAILABLE");
  if (
    (change || changedAt !== undefined) &&
    issue &&
    terminal?.issueArn !== issue
  )
    return;
  if (!terminal) return current.at(-1);
  // A failed artifact read can still confirm that the finding changed issues.
  if (
    current.some(({ issueArn }) => issueArn && issueArn !== terminal.issueArn)
  )
    return;

  return selectEvidence(current, history);
}

/** Keep the first copy of identical evidence and any ties at the newest time. */
function newest(items: Conclusion[], timeOf: (item: Conclusion) => string) {
  let latest = items.slice(0, 1);
  for (const item of items.slice(1)) {
    const prev = latest[0]!;
    if (isDeepStrictEqual(prev, item)) continue;
    if (!prev.issueArn || prev.issueArn !== item.issueArn) return [];
    const delta = compareTimestamps(timeOf(item), timeOf(prev));
    if (!Number.isFinite(delta)) return [];
    if (delta > 0) latest = [item];
    if (delta === 0) latest.push(item);
  }
  return latest;
}

function selectEvidence(current: Conclusion[], history: Conclusion[]) {
  // Put current evidence first so identical historical copies cannot displace it.
  const evidence = current
    .concat(history)
    .filter((item) => item.verdict !== "UNAVAILABLE");
  // Older snapshots did not distinguish issue runs from bundles for other
  // members. A later poll can identify those bundles by artifact ID.
  const siblings = new Set(
    evidence.flatMap((item) => item.siblingArtifacts ?? []),
  );
  const applicable: Conclusion[] = [];
  let confirmed = false;
  for (const item of evidence) {
    if (!item.siblingOnly && !siblings.has(item.validationArtifactId ?? "")) {
      applicable.push(item);
      if (item.siblingOnly === false || item.resultScope === "finding")
        confirmed = true;
    }
    delete item.siblingOnly;
    delete item.siblingArtifacts;
  }
  const latest = newest(confirmed ? applicable : evidence, evidenceTime);
  const first = latest[0];
  if (!first || history.includes(first)) return;
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
  const [best, conflict] = newest(scored, (item) => item.freshness.scoredAt!);
  if (best && !conflict && !best.scoringPending && !history.includes(best))
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
  const retries = Map.groupBy(
    saved?.retry ?? [],
    (item) => item?.record.itemId,
  );
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
    const poll = plugin && saved?.polls?.[occurrence];
    if (plugin && poll) {
      plugin.siblingOnly = poll.siblingOnly;
      plugin.siblingArtifacts = poll.siblingArtifacts;
    }
    const pin = plugin ?? legacy?.get(occurrence);
    if (item && !pin && !unsubmitted(item)) continue;
    const candidates = (entries ?? []).flatMap(
      ({ record, environmentId, requestedAt, completedAt }) => {
        const item = project(
          record,
          destination ?? { environment_id: environmentId },
        );
        const issueChanged =
          "issueChanged" in record && record.issueChanged === true;
        return item ? [{ item, requestedAt, completedAt, issueChanged }] : [];
      },
    );
    const selected = pin ?? candidates.at(-1)?.item;
    if (!selected) continue;
    // Only a CLI-only scan can switch admissions on explicit validation.
    // Never pick between distinct AWS accounts, regions or environments.
    if (
      !pin &&
      candidates.some(({ item }) =>
        destination
          ? !sameAdmission(item, selected)
          : scopeOf(item) !== scopeOf(selected),
      )
    )
      continue;
    const active = selectConclusion(
      candidates.filter(({ item }) => sameAdmission(item, selected)),
      plugin,
      pendingScore(plugin, retries.get(occurrence)),
      poll,
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
