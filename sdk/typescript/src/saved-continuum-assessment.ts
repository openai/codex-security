import { realpath } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import {
  readCliSnapshots,
  writeCliSnapshots,
} from "./cli-continuum-assessments.js";
import { commandGitProtectionRoots } from "./local-git-metadata.js";
import { readRegularInputFile } from "./prompt-files.js";
import {
  codexSecurityStateDirectory,
  requireOutputOutsideRepositories,
  type ProcessEnvironment,
} from "./runtime.js";
import type {
  ValidationProviderConfiguration,
  ValidationItemRecord,
} from "./validation-provider.js";
import { nullIfMissingFile } from "./targets.js";

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
});
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
    items: z.array(z.unknown()),
  }),
  // The retry field distinguishes caches supporting terminal status from legacy results.
  retry: z.array(z.unknown()).nullable(),
});

function project(raw: unknown, environmentId: string, region?: string) {
  const item = conclusion.safeParse(raw);
  if (!item.success) return undefined;
  const record = item.data;
  const suffix = "/code-findings/" + record.findingId;
  const scope = record.findingArn.slice(0, -suffix.length);
  if (
    !record.findingArn.endsWith(suffix) ||
    !/^arn:[^:]+:continuum:[^:]+:[0-9]{12}:environments\/[a-zA-Z0-9_-]+$/.test(
      scope,
    ) ||
    (region && scope.split(":")[3] !== region) ||
    !scope.endsWith("/" + environmentId)
  )
    return undefined;
  if (
    record.issueArn !==
    (record.issueId ? scope + "/code-issues/" + record.issueId : undefined)
  )
    return undefined;
  // An observation describes the original validation. A different group,
  // run, or historical member cannot supply occurrence-level evidence.
  if (
    record.proofObservation &&
    (record.terminalStatus !== "COMPLETED" ||
      (record.verdict !== "EXPLOITABLE" &&
        record.verdict !== "NOT_EXPLOITABLE") ||
      !(
        Date.parse(record.freshness.validatedAt ?? "") >=
        Date.parse(record.submittedAt)
      ) ||
      (record.freshness.evidenceCreatedAt !== undefined &&
        Date.parse(record.freshness.evidenceCreatedAt) !==
          Date.parse(record.freshness.validatedAt ?? "")) ||
      record.resultScope !== "finding" ||
      (record.claimMatch !== "on_target" &&
        record.claimMatch !== "on_target_escalated") ||
      !record.scoringArtifactId ||
      !record.validationArtifactId ||
      !record.issueId ||
      record.issueFindingCount !== 1 ||
      record.joinedValidatedIssue ||
      record.freshness.stale)
  ) {
    delete record.proofObservation;
  }
  return record;
}

async function readProtectedJson(
  repositoryPath: string,
  path: string,
): Promise<unknown> {
  try {
    const real = await realpath(path).catch(nullIfMissingFile);
    if (!real) return undefined;
    const repository = await realpath(repositoryPath);
    const roots = [
      repository,
      ...(await commandGitProtectionRoots(repository, process.env)),
    ];
    requireOutputOutsideRepositories(roots, real, "state");
    const contents = await readRegularInputFile(path, repository);
    return JSON.parse(contents) as unknown;
  } catch {
    // Distinguish an invalid binding from an absent one.
    return null;
  }
}

/** The plugin's existing binding directory predates the workbench default. */
export function assessmentStateDirectories(environment: ProcessEnvironment) {
  return {
    plugin:
      environment["CODEX_SECURITY_STATE_DIR"]?.trim() ||
      join(homedir(), ".codex-security"),
    cli: codexSecurityStateDirectory(environment),
  };
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
  const { environment_id, aws_region } = binding.parse(configuration).continuum;
  const terminal: Conclusion[] = [];
  for (const raw of records) {
    const value = project(raw, environment_id, aws_region);
    if (value && value.verdict !== "UNAVAILABLE") terminal.push(value);
  }
  if (!terminal.length) return;
  await writeCliSnapshots(
    codexSecurityStateDirectory(environment),
    repositoryPath,
    scanId,
    environment_id,
    terminal,
  );
}

function sameAdmission(a: Conclusion, b: Conclusion) {
  return a.findingArn === b.findingArn && a.submittedAt === b.submittedAt;
}

function evidenceTime(item: Conclusion) {
  return Date.parse(
    item.freshness.evidenceCreatedAt ?? item.freshness.validatedAt ?? "",
  );
}

/** Use provider evidence creation time, never local completion/write order.
 * Timeouts can be resolved before an issue has even been assigned. */
function selectConclusion(prior: Conclusion | undefined, cli: Conclusion[]) {
  const candidates = prior
    ? cli.filter((item) => sameAdmission(item, prior))
    : cli;
  if (prior && prior.verdict !== "UNAVAILABLE") candidates.push(prior);
  const distinct = [
    ...new Map(candidates.map((item) => [JSON.stringify(item), item])).values(),
  ];
  const first = distinct[0];
  if (!first) return prior;
  if (distinct.length === 1) return first;
  if (!first.issueArn) return;
  let newest: Conclusion | undefined;
  let newestTime = -Infinity;
  for (const item of distinct) {
    const time = evidenceTime(item);
    if (
      !sameAdmission(first, item) ||
      item.issueArn !== first.issueArn ||
      !Number.isFinite(time)
    )
      return;
    if (time > newestTime) {
      newestTime = time;
      newest = item;
    } else if (time === newestTime) newest = undefined;
  }
  return newest;
}

export async function savedContinuumAssessments(
  environment: ProcessEnvironment,
  scanId: string,
  repositoryPath: string,
  occurrenceIds: readonly string[],
) {
  const assessments = new Map<string, Conclusion>();
  if (!id.safeParse(scanId).success || !occurrenceIds.length)
    return assessments;
  const requested = new Set(occurrenceIds);
  let paths;
  try {
    paths = assessmentStateDirectories(environment);
  } catch {
    return assessments;
  }
  const base = join(paths.plugin, "validation-providers", scanId + ".json");
  const config = await readProtectedJson(repositoryPath, base);
  const bound = binding.safeParse(config);
  if (config !== undefined && !bound.success) return assessments;
  const environmentId = bound.data?.continuum.environment_id;
  const region = bound.data?.continuum.aws_region;
  if (environmentId) {
    const parsed = cached.safeParse(
      await readProtectedJson(repositoryPath, base + ".result"),
    );
    if (
      parsed.success &&
      parsed.data.repositoryPath === repositoryPath &&
      JSON.stringify(config) === JSON.stringify(parsed.data.configuration)
    ) {
      for (const raw of parsed.data.records.items) {
        const record = project(raw, environmentId, region);
        if (!record || !requested.has(record.itemId)) continue;
        if (assessments.has(record.itemId)) {
          requested.delete(record.itemId);
          assessments.delete(record.itemId);
          continue;
        }
        assessments.set(record.itemId, record);
      }
    }
  }
  const snapshots = await readCliSnapshots(
    paths.cli,
    repositoryPath,
    scanId,
    requested,
    environmentId,
  ).catch(() => undefined);
  if (!snapshots) return assessments;
  for (const [occurrence, items] of snapshots) {
    if (items === null) {
      assessments.delete(occurrence);
      continue;
    }
    const candidates: Conclusion[] = [];
    for (const item of items) {
      const record = project(item.record, item.environmentId, region);
      if (record && record.verdict !== "UNAVAILABLE") candidates.push(record);
    }
    const selected = selectConclusion(assessments.get(occurrence), candidates);
    if (selected) assessments.set(occurrence, selected);
    else assessments.delete(occurrence);
  }
  return assessments;
}
