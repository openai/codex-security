import { createHash } from "node:crypto";
import { dirname, posix, relative, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";
import type { JsonObject } from "../types.js";
import type { AcceptedDiscovery } from "./worker-runner.js";
import { artifactSourcePath, type ArtifactContext } from "../artifact-io.js";
import { recoverWorkerCandidateReceipts } from "../artifact-worker-receipts.js";
import {
  coverageReceiptComponents,
  validateRetainedCoverage,
} from "../coverage-publication.js";
import { artifactSchemaDocuments } from "../artifact-contracts.js";
import { projectArtifactToolSchema } from "../artifact-schema-loader.js";
import { requireFiniteNumbers } from "../helpers/json.js";
import { isRecord } from "../record.js";
import {
  coverageCandidateKey,
  findingCandidateId,
  findingCandidateOwner,
  resolvedCandidateKeys,
} from "../artifact-candidates.js";
import {
  parsePersistedScanDraft,
  retainRecordedReceiptOwnership,
  preserveFindingDetails,
  saveScanDraftCheckpoint,
  scanFindingIdentity,
  validateFindingSemantics,
  type ScanDraftInput,
} from "../artifact-scan-draft.js";
import { workerCoverageReceiptLocation } from "../artifact-worker-receipts.js";
import {
  readJsonObject,
  requireRegularFile,
  writeJsonAtomic,
} from "./artifacts.js";
import type { DeepScanArtifacts } from "./artifacts.js";

export type UnresolvedCandidate =
  ScanDraftInput["coverage"]["deferred"][number] & {
    candidateId: string;
    sourceWorkerId: string;
  };

export type DeepReductionInput = Omit<ScanDraftInput, "coverage"> & {
  unresolvedCandidates?: UnresolvedCandidate[];
  /** Host-owned accepted coverage, omitted from the legacy persisted reducer format. */
  sourceCoverage?: ScanDraftInput["coverage"];
};
export const deepReductionInputSchema = projectArtifactToolSchema(
  artifactSchemaDocuments["tools/deep-reducer"].$defs.reductionInput,
);

export interface DeepReductionSources {
  discoveries: {
    workerId: string;
    coverage?: ScanDraftInput["coverage"];
    result: DeepReductionInput;
  }[];
  previous: DeepReductionInput | null;
}

export interface ReducerArtifactValidation {
  newFindings: number;
  result: DeepReductionInput;
}

/** Retain candidate state without importing worker-local coverage observations. */
export function discoveryReductionInput(
  input: ScanDraftInput,
  workerId: string,
): DeepReductionInput {
  const { coverage, ...result } = input;
  const resolved = resolvedCandidateKeys(input, workerId);
  const unresolvedCandidates = coverage.deferred
    .filter(
      (item) =>
        typeof item.candidateId === "string" &&
        !resolved.has(coverageCandidateKey(item, workerId)!),
    )
    .map((item) => ({
      ...structuredClone(item),
      candidateId: item.candidateId as string,
      sourceWorkerId: workerId,
    }));
  return {
    ...result,
    findings: result.findings.map((finding) => {
      if (findingCandidateId(finding) === undefined) return finding;
      const normalized = structuredClone(finding);
      normalized.provenance = {
        ...normalized.provenance,
        sourceWorkerId: workerId,
      };
      const previousOwner = findingCandidateOwner(finding);
      const previousSource = (
        finding.provenance as Record<string, unknown> | undefined
      )?.sourceWorkerId;
      if (
        (previousOwner !== undefined && previousOwner !== workerId) ||
        (previousSource !== undefined && previousSource !== workerId)
      )
        preserveFindingDetails(normalized, finding);
      return normalized;
    }),
    ...(unresolvedCandidates.length > 0 ? { unresolvedCandidates } : {}),
  };
}

export function deepReductionToScanDraft(
  input: DeepReductionInput,
): ScanDraftInput {
  const {
    sourceCoverage,
    unresolvedCandidates = [],
    ...result
  } = structuredClone(input);
  const coverage = sourceCoverage ?? unknownSourceCoverage();
  const pending = new Set(
    unresolvedCandidates.map((row) =>
      coverageCandidateKey(row, row.sourceWorkerId),
    ),
  );
  const projected = new Set<string>();
  coverage.deferred = coverage.deferred.filter((row) => {
    const source = row.provenance as JsonObject | undefined;
    if (!source || typeof source.candidateId !== "string") return true;
    const key = coverageCandidateKey(row);
    if (!key || !pending.has(key)) return false;
    projected.add(key);
    return true;
  });
  const usedIds = new Set(coverage.deferred.map((row) => row.id));
  const reservedIds = new Set(unresolvedCandidates.map((row) => row.id));
  for (const row of unresolvedCandidates) {
    if (projected.has(coverageCandidateKey(row, row.sourceWorkerId)!)) continue;
    // Legacy reducer rows retain imported descriptions, but the accepted worker owns the task.
    if (isRecord(row.provenance) && typeof row.sourceWorkerId === "string") {
      delete row.provenance.workerId;
      delete row.provenance.candidateId;
    }
    if (typeof row.id === "string" && usedIds.has(row.id)) {
      const base = row.id;
      let suffix = 2;
      do {
        row.id = `${base}-${suffix++}`;
      } while (usedIds.has(row.id) || reservedIds.has(row.id));
    }
    usedIds.add(row.id);
    coverage.deferred.push(row);
  }
  return { ...result, coverage };
}

/** Keep v1 checkpoints readable by older binaries. */
export function deepReductionForPersistence(
  result: DeepReductionInput,
): Omit<ScanDraftInput, "coverage"> {
  const { sourceCoverage: _coverage, ...persisted } = result;
  return persisted;
}

/** Reduction combines findings; it does not complete the source workers' review. */
export function aggregateDiscoveryCoverage(
  artifacts: DeepScanArtifacts,
  discoveries: Pick<AcceptedDiscovery, "id" | "resultPath" | "result">[],
): ScanDraftInput["coverage"] {
  const coverage: ScanDraftInput["coverage"] = {
    surfaces: [],
    explicitExclusions: [],
    deferred: [],
  };
  for (const worker of discoveries) {
    const source = structuredClone(worker.result.coverage);
    const prefix = relative(artifacts.scanDir, dirname(worker.resultPath))
      .split(sep)
      .join("/");
    const scopedId = (id: string) => `${worker.id}/${id}`;
    for (const field of [
      "surfaces",
      "explicitExclusions",
      "deferred",
    ] as const) {
      const rows = source[field] as JsonObject[];
      const usedIds = new Set(
        rows.flatMap((row) => (typeof row.id === "string" ? [row.id] : [])),
      );
      const emittedIds = new Set<string>();
      for (const [index, row] of rows.entries()) {
        const retained: JsonObject = { ...row, workerId: worker.id };
        // Independent reviews reuse local IDs. Preserve their links without
        // allowing one worker's disposition to stand in for another's work.
        const baseId = typeof row.id === "string" ? row.id : String(index);
        let id = baseId;
        if (typeof row.id !== "string" || emittedIds.has(id)) {
          for (let suffix = 2; usedIds.has(id); suffix++) {
            id = `${baseId}-${suffix}`;
          }
        }
        usedIds.add(id);
        emittedIds.add(id);
        retained.id = scopedId(id);
        if (field === "deferred" && Array.isArray(row.surfaceIds)) {
          retained.surfaceIds = (row.surfaceIds as string[]).map(scopedId);
        }
        if (field === "surfaces" && Array.isArray(row.receiptRefs)) {
          retained.receiptRefs = (row.receiptRefs as string[]).map(
            (ref) => `${prefix}/${coverageReceiptComponents(ref).join("/")}`,
          );
        }
        (coverage[field] as JsonObject[]).push(retained);
      }
    }
    if (Array.isArray(source.openQuestions)) {
      const questions = (coverage.openQuestions ??= []) as JsonObject[];
      for (const question of source.openQuestions) {
        questions.push({
          ...(typeof question === "string"
            ? { question }
            : (question as JsonObject)),
          workerId: worker.id,
        });
      }
    }
  }
  return coverage;
}

export function parseDeepReduction(
  input: unknown,
  persisted = false,
): DeepReductionInput {
  const { unresolvedCandidates, ...semantic } = input as Record<
    string,
    unknown
  >;
  if (persisted) delete semantic.sourceCoverage;
  const parsed = deepReductionInputSchema.parse(semantic);
  validateFindingSemantics(parsed.findings);
  if (!persisted || unresolvedCandidates === undefined) return parsed;
  const { coverage } = parsePersistedScanDraft({
    ...parsed,
    coverage: {
      surfaces: [],
      explicitExclusions: [],
      deferred: unresolvedCandidates,
    },
  });
  return {
    ...parsed,
    ...(coverage.deferred.length > 0
      ? { unresolvedCandidates: coverage.deferred as UnresolvedCandidate[] }
      : {}),
  };
}

/** Admit exactly the complete semantic result written by an ordinary Standard scan. */
export async function validateDiscoveryArtifacts(
  artifacts: DeepScanArtifacts,
  resultPath: string,
  expectedScanId: string,
  boundScope: Pick<ArtifactContext, "scope" | "includePaths" | "filePaths"> & {
    recoverCandidateReceipts?: boolean;
  } = {},
): Promise<ScanDraftInput> {
  await requireRegularFile(resultPath, artifacts.workersRoot);
  const root = dirname(resultPath);
  const context = {
    root,
    repoRoot: root,
    layout: "worker" as const,
    scanId: expectedScanId,
    scope: boundScope.scope,
    includePaths: boundScope.includePaths,
    filePaths: boundScope.filePaths,
  };
  const stored = await readJsonObject(resultPath);
  await retainRecordedReceiptOwnership(context, stored);
  const result = parseStoredScanDraft(
    stored,
    "Standard scan worker",
    expectedScanId,
    parsePersistedScanDraft,
  );
  if (result.complete === false)
    throw new Error(
      "Standard scan worker wrote only a checkpoint; its audit is not complete.",
    );
  if (boundScope.recoverCandidateReceipts)
    await recoverWorkerCandidateReceipts(result.coverage, context);
  validateRetainedCoverage(result.coverage);
  const receiptPaths = new Map<string, string>();
  for (const row of result.coverage.surfaces as JsonObject[]) {
    for (const ref of (row.receiptRefs as string[] | undefined) ?? []) {
      const components = coverageReceiptComponents(ref);
      const normalized = components.join("/");
      const key = normalized.toLowerCase();
      const previous = receiptPaths.get(key);
      if (previous !== undefined && previous !== normalized)
        throw new Error(
          `Standard scan worker coverage receipt: duplicate artifact path: ${previous} and ${normalized}`,
        );
      receiptPaths.set(key, normalized);
      const location = workerCoverageReceiptLocation(context, row, ref);
      await artifactSourcePath(
        location.context,
        location.components,
        "Standard scan worker coverage receipt",
      );
    }
  }
  return result;
}

/** Validate the complete aggregate and derive convergence from retained source ancestry. */
export async function validateReducerArtifacts(
  input: {
    artifacts: DeepScanArtifacts;
    artifactDir: string;
    resultPath: string;
    reducerId: string;
    previousReducerResultPath?: string;
    sources?: DeepReductionSources;
  },
  expectedScanId?: string,
): Promise<ReducerArtifactValidation> {
  const {
    artifacts,
    artifactDir,
    resultPath,
    reducerId,
    previousReducerResultPath,
  } = input;

  await requireRegularFile(resultPath, artifactDir);
  let result = parseStoredScanDraft(
    await readJsonObject(resultPath),
    reducerId,
    expectedScanId,
    (value) => parseDeepReduction(value, true),
  );
  if (result.complete === false)
    throw new Error(
      "Deep reduction wrote only a checkpoint; its audit is not complete.",
    );

  let previous = input.sources?.previous ?? undefined;
  if (!input.sources && previousReducerResultPath) {
    await requireRegularFile(previousReducerResultPath, artifacts.dedupRoot);
    previous = parseStoredScanDraft(
      await readJsonObject(previousReducerResultPath),
      "Previous successful reducer",
      result.scanId,
      (value) => parseDeepReduction(value, true),
    );
  }

  if (input.sources) {
    result = reconcileDeepReduction(
      result,
      input.sources.discoveries,
      input.sources.previous,
    );
    const persisted = deepReductionForPersistence(result);
    await saveScanDraftCheckpoint(
      { root: artifactDir, repoRoot: artifacts.scanDir, layout: "reducer" },
      persisted,
    );
    await writeJsonAtomic(resultPath, persisted);
  } else {
    validateRetainedFindings(result, [], previous);
  }
  const previousFindingIds = new Set(
    input.sources
      ? (previous?.findings ?? [])
          .flatMap(retainedFindingSources)
          .map((source) => source.id)
      : (previous?.findings ?? []).map(scanFindingIdentity),
  );
  return {
    result,
    newFindings: result.findings.filter((finding) =>
      input.sources
        ? !findingSourceIds(finding).some((id) => previousFindingIds.has(id))
        : !previousFindingIds.has(scanFindingIdentity(finding)),
    ).length,
  };
}

/** Reconcile a reducer output against the immutable inputs captured before dispatch. */
export function reconcileDeepReduction(
  input: DeepReductionInput,
  discoveries: DeepReductionSources["discoveries"],
  previous: DeepReductionInput | null,
): DeepReductionInput {
  // Check retained fresh data before merging historical sources. The host
  // replaces submitted sourceFindings with the original source payloads below.
  requireFiniteNumbers({
    ...input,
    findings: input.findings.map((finding) => ({
      ...finding,
      provenance: {
        ...(finding.provenance as JsonObject),
        sourceFindings: undefined,
      },
    })),
  });
  const result = structuredClone(input);
  result.sourceCoverage = aggregateSourceCoverage(discoveries, previous);
  if (result.complete === false)
    throw new Error(
      "Deep reduction is only a checkpoint, not a complete result.",
    );
  for (const source of [
    ...discoveries.map((discovery) => discovery.result),
    ...(previous ? [previous] : []),
  ]) {
    if (source.scanId !== result.scanId)
      throw new Error("Deep reduction source belongs to a different scan.");
    if (source.complete === false)
      throw new Error(
        "Deep reduction source is only a checkpoint, not a complete result.",
      );
  }
  const pending = collectUnresolvedCandidates(discoveries, previous);
  delete result.unresolvedCandidates;
  if (pending.length > 0) result.unresolvedCandidates = pending;
  validateRetainedFindings(
    result,
    discoveries.map((discovery) => discovery.result),
    previous ?? undefined,
  );
  retainSourceFindings(result, { discoveries, previous });
  for (const [index, finding] of (previous?.findings ?? []).entries()) {
    const previousRefs = retainedFindingSources(finding, index).map(
      (source) => source.id,
    );
    const retained = result.findings.find((current) =>
      findingSourceIds(current).some((ref) => previousRefs.includes(ref)),
    );
    if (retained) {
      const sourceIds = findingSourceIds(retained);
      preserveFindingDetails(retained, finding);
      (retained.provenance as Record<string, unknown>).sourceFindingIds =
        sourceIds;
    }
  }
  retainSourceFindings(result, { discoveries, previous });
  for (const [field, label] of [
    ["threatModel", "threat models"],
    ["scope", "scopes"],
  ] as const) {
    if (result[field] !== undefined) continue;
    const sourceValues = [
      ...discoveries.map((discovery) => discovery.result[field]),
      previous?.[field],
    ].filter((value) => value !== undefined);
    if (
      sourceValues.some((value) => !isDeepStrictEqual(sourceValues[0], value))
    ) {
      throw new Error(
        `Deep reduction has ambiguous ${label}; provide the reconciled ${field} explicitly.`,
      );
    }
    if (sourceValues[0] !== undefined) {
      Object.assign(result, { [field]: structuredClone(sourceValues[0]) });
    }
  }
  return result;
}

export function collectUnresolvedCandidates(
  discoveries: DeepReductionSources["discoveries"],
  previous: DeepReductionInput | null,
): UnresolvedCandidate[] {
  const currentWorkers = new Set(discoveries.map((source) => source.workerId));
  const pending: UnresolvedCandidate[] = [];
  for (const candidate of [
    ...(previous?.unresolvedCandidates ?? []).filter(
      (candidate) => !currentWorkers.has(candidate.sourceWorkerId),
    ),
    ...discoveries.flatMap(
      (source) => source.result.unresolvedCandidates ?? [],
    ),
  ]) {
    if (!pending.some((previous) => isDeepStrictEqual(previous, candidate)))
      pending.push(structuredClone(candidate));
  }
  return pending;
}

/** Keep independent reviews separate: matching labels do not resolve another pass's proof gap. */
export function aggregateSourceCoverage(
  discoveries: DeepReductionSources["discoveries"],
  previous: DeepReductionInput | null,
): ScanDraftInput["coverage"] {
  const sources = [
    ...(previous ? [previous.sourceCoverage ?? unknownSourceCoverage()] : []),
    ...discoveries.map((source) => source.coverage ?? unknownSourceCoverage()),
  ];
  const result: ScanDraftInput["coverage"] = {
    surfaces: [],
    explicitExclusions: [],
    deferred: [],
    reviews: [],
  };
  for (const field of [
    "surfaces",
    "explicitExclusions",
    "deferred",
    "resolvedDeferred",
    "openQuestions",
    "reviews",
  ]) {
    const entries = sources.flatMap(
      (source) => (source[field] as unknown[] | undefined) ?? [],
    );
    if (
      entries.length ||
      (field !== "openQuestions" && field !== "resolvedDeferred")
    )
      result[field] = structuredClone(entries);
  }
  return result;
}

function unknownSourceCoverage(): ScanDraftInput["coverage"] {
  return {
    surfaces: [],
    explicitExclusions: [],
    deferred: [],
  };
}

/** Qualify worker-local IDs and receipt paths before combining accepted coverage. */
export function projectDiscoveryCoverage(
  coverage: ScanDraftInput["coverage"],
  worker: { id: string; attempt?: number },
  artifactPrefix: string,
  scanReceiptRefs: ReadonlyMap<number, ReadonlySet<string>> = new Map(),
): ScanDraftInput["coverage"] {
  const archivePrefix = `${posix.dirname(artifactPrefix)}/attempts/`;
  const provenance = {
    workerId: worker.id,
    ...(worker.attempt === undefined ? {} : { attempt: worker.attempt }),
  };
  const prefix = `${worker.id}-attempt-${worker.attempt ?? "unknown"}`;
  const surfaces = coverage.surfaces;
  const surfaceIds = new Map<unknown, string>();
  for (const [index, surface] of surfaces.entries()) {
    if (!surfaceIds.has(surface.id)) {
      surfaceIds.set(surface.id, `${prefix}-surface-${index + 1}`);
    }
  }
  const receiptRef = (value: string, shared?: ReadonlySet<string>) => {
    const ref = posix.normalize(value);
    return ref.startsWith(archivePrefix) ||
      ref.startsWith(`${artifactPrefix}/`) ||
      shared?.has(ref)
      ? ref
      : `${artifactPrefix}/${ref}`;
  };
  const project = <T extends Record<string, unknown>>(
    item: T,
    qualifyReceipts = false,
  ): T => {
    const result = structuredClone(item);
    const descriptions = result.provenance;
    const projected =
      typeof descriptions === "object" &&
      descriptions !== null &&
      !Array.isArray(descriptions)
        ? (descriptions as Record<string, unknown>)
        : {};
    for (const key of [
      "workerId",
      "attempt",
      "sourceId",
      "candidateId",
      "scanReceiptRefs",
    ])
      delete projected[key];
    Object.assign(result, {
      provenance: {
        ...projected,
        ...provenance,
        ...(item.id === undefined ? {} : { sourceId: item.id }),
        ...(item.candidateId === undefined
          ? {}
          : { candidateId: item.candidateId }),
      },
    });
    if (typeof item.candidateId === "string" && item.candidateId.trim()) {
      if (
        qualifyReceipts &&
        Array.isArray(item.receiptRefs) &&
        item.receiptRefs.every((ref) => typeof ref === "string")
      ) {
        Object.assign(result, {
          receiptRefs: item.receiptRefs.map((ref) => receiptRef(ref)),
        });
      }
      Object.assign(result, {
        candidateId: `${prefix}-candidate-${createHash("sha256").update(item.candidateId).digest("hex")}`,
      });
    }
    return result;
  };
  return {
    reviews: [provenance],
    surfaces: surfaces.map((surface, index) => ({
      ...project(surface),
      id: `${prefix}-surface-${index + 1}`,
      receiptRefs: ((surface.receiptRefs as string[] | undefined) ?? []).map(
        (ref) => receiptRef(ref, scanReceiptRefs.get(index)),
      ),
    })),
    explicitExclusions: coverage.explicitExclusions.map((item) =>
      project(item, true),
    ),
    deferred: coverage.deferred.map((item, index) => ({
      ...project(item, true),
      id: `${prefix}-deferred-${index + 1}`,
      ...(item.surfaceIds === undefined
        ? {}
        : {
            surfaceIds: (item.surfaceIds as string[]).map(
              (id) => surfaceIds.get(id) ?? id,
            ),
          }),
    })),
    ...(coverage.resolvedDeferred === undefined
      ? {}
      : {
          resolvedDeferred: coverage.resolvedDeferred.map(({ id, reason }) => ({
            id: `${prefix}-resolved-${id}`,
            reason,
          })),
        }),
    ...(coverage.openQuestions === undefined
      ? {}
      : {
          openQuestions: coverage.openQuestions.map((question) =>
            project(typeof question === "string" ? { question } : question),
          ),
        }),
  };
}

function findingSourceIds(finding: Record<string, unknown>): string[] {
  const { sourceFindingIds, sourceFindings } = finding.provenance as {
    sourceFindingIds?: string[];
    sourceFindings?: { id: string }[];
  };
  return sourceFindingIds ?? sourceFindings?.map((source) => source.id) ?? [];
}

function retainedFindingSources(
  finding: Record<string, unknown>,
  index: number,
) {
  const originals = (finding.provenance as Record<string, unknown>)
    .sourceFindings as
    Array<{ id: string; finding: Record<string, unknown> }> | undefined;
  return originals?.length ? originals : [{ id: `previous:${index}`, finding }];
}

function retainSourceFindings(
  result: DeepReductionInput,
  inputs: DeepReductionSources,
): void {
  type Finding = Record<string, unknown>;
  const sources = new Map<string, Finding>();
  const owners = new Map<string, string | undefined>();
  for (const discovery of inputs.discoveries) {
    for (const [index, finding] of discovery.result.findings.entries()) {
      const original = structuredClone(finding);
      delete (original.provenance as Finding).sourceFindingIds;
      const id = `${discovery.workerId}:${index}`;
      sources.set(id, original);
      owners.set(id, discovery.workerId);
    }
  }
  for (const original of (inputs.previous?.findings ?? []).flatMap(
    retainedFindingSources,
  )) {
    sources.set(original.id, original.finding);
    // Persisted source IDs are opaque; ownership travels with the finding.
    owners.set(original.id, findingCandidateOwner(original.finding));
  }
  const claimed = new Set<string>();
  for (const finding of result.findings) {
    const provenance = finding.provenance as Finding;
    let refs = provenance.sourceFindingIds as string[] | undefined;
    if (refs === undefined) {
      const matches = [...sources].filter(
        ([, source]) =>
          scanFindingIdentity(source) === scanFindingIdentity(finding),
      );
      if (
        new Set(matches.map(([, source]) => JSON.stringify(source))).size > 1
      ) {
        throw new Error(
          "Deep reduction has ambiguous source findings; preserve each sourceFindingIds reference explicitly.",
        );
      }
      refs = matches.map(([id]) => id);
    }
    if (refs.length === 0)
      throw new Error(
        "Deep reduction contains a finding with no assigned source finding.",
      );
    for (const id of refs) {
      if (!sources.has(id))
        throw new Error(
          `Deep reduction references unknown source finding ${id}.`,
        );
      if (claimed.has(id))
        throw new Error(
          `Deep reduction attributes source finding ${id} more than once.`,
        );
      claimed.add(id);
    }
    provenance.sourceFindingIds = refs;
    provenance.sourceFindings = refs.map((id) => ({
      id,
      finding: structuredClone(sources.get(id)!),
    }));
    const candidateId = findingCandidateId(finding);
    const owner = findingCandidateOwner(finding);
    const associations = refs.flatMap((id) => {
      const original = sources.get(id)!;
      const candidateId = findingCandidateId(original);
      if (candidateId === undefined) return [];
      return [{ candidateId, owner: owners.get(id) }];
    });
    const association =
      associations.find(
        (source) =>
          source.candidateId === candidateId && source.owner === owner,
      ) ??
      associations.find((source) => source.candidateId === candidateId) ??
      associations[0];
    if (association !== undefined) {
      const previous = structuredClone(finding);
      provenance.candidateId = association.candidateId;
      if (
        result.unresolvedCandidates?.some(
          (candidate) =>
            candidate.candidateId === association.candidateId &&
            candidate.sourceWorkerId === association.owner,
        )
      )
        provenance.candidateReopened = true;
      else if (provenance.candidateReopened === true)
        delete provenance.candidateReopened;
      if (association.owner !== undefined)
        provenance.sourceWorkerId = association.owner;
      else if (owner !== undefined) {
        for (const field of ["sourceWorkerId", "workerId"])
          if (typeof provenance[field] === "string") delete provenance[field];
        if (
          typeof (finding.extensions as Finding | undefined)?.sourceWorkerId ===
          "string"
        )
          delete (finding.extensions as Finding).sourceWorkerId;
      }
      if (
        candidateId !== association.candidateId ||
        owner !== association.owner
      )
        preserveFindingDetails(finding, previous);
    } else if (candidateId !== undefined) {
      throw new Error(
        "Deep reduction associates a candidate with no assigned source candidate.",
      );
    }
  }
  const missing = [...sources.keys()].filter((id) => !claimed.has(id));
  if (missing.length)
    throw new Error(
      `Deep reduction left unaccounted source findings: ${missing.join(", ")}.`,
    );
}

/** Preserve previously accepted identities and never discard every reported finding. */
export function validateRetainedFindings(
  result: DeepReductionInput,
  sources: DeepReductionInput[],
  previous?: DeepReductionInput,
): void {
  if (
    result.findings.length === 0 &&
    (sources.some((source) => source.findings.length > 0) ||
      (previous?.findings.length ?? 0) > 0)
  ) {
    throw new Error(
      "Deep reduction discarded every accepted Standard scan finding.",
    );
  }

  const currentFindingIds = new Set(result.findings.map(scanFindingIdentity));
  for (const finding of previous?.findings ?? []) {
    if (currentFindingIds.has(scanFindingIdentity(finding))) continue;
    throw Object.assign(
      new Error(
        "Deep reduction discarded or changed a previously accepted finding identity.",
      ),
      {
        code: "merge_traceability_unstable_candidate_id",
      },
    );
  }
}

export function parseStoredScanDraft<Result extends DeepReductionInput>(
  value: Record<string, unknown>,
  label: string,
  expectedScanId: string | undefined,
  parse: (input: Record<string, unknown>) => Result,
  invalidResultMessage = " returned an invalid Standard scan result: ",
  differentScanMessage = " returned a result for a different scan.",
): Result {
  let parsed: Result;
  try {
    parsed = parse(value);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(label + invalidResultMessage + detail, {
      cause: error,
    });
  }
  if (expectedScanId !== undefined && parsed.scanId !== expectedScanId) {
    throw new Error(label + differentScanMessage);
  }
  return parsed;
}
