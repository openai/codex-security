import { isDeepStrictEqual } from "node:util";
import { dirname, relative, sep } from "node:path";
import type { JsonObject } from "../types.js";
import type { AcceptedDiscovery } from "./worker-runner.js";
import { artifactSourcePath } from "../artifact-io.js";
import { recoverWorkerCandidateReceipts } from "../artifact-worker-receipts.js";
import {
  coverageReceiptComponents,
  validateRetainedCoverage,
} from "../coverage-publication.js";
import { artifactSchemaDocuments } from "../artifact-contracts.js";
import { projectArtifactToolSchema } from "../artifact-schema-loader.js";
import { requireFiniteNumbers } from "../helpers/json.js";
import {
  coverageCandidateKey,
  findingCandidateId,
  findingCandidateOwner,
  resolvedCandidateKeys,
} from "../artifact-candidates.js";
import {
  parsePersistedScanDraft,
  preserveFindingDetails,
  saveScanDraftCheckpoint,
  scanFindingIdentity,
  validateFindingSemantics,
  type ScanDraftInput,
} from "../artifact-scan-draft.js";
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
};
export const deepReductionInputSchema = projectArtifactToolSchema(
  artifactSchemaDocuments["tools/deep-reducer"].$defs.reductionInput,
);

export interface DeepReductionSources {
  discoveries: { workerId: string; result: DeepReductionInput }[];
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

export function deepReductionScanDraft(
  input: DeepReductionInput,
): ScanDraftInput {
  const { unresolvedCandidates = [], ...result } = structuredClone(input);
  const reservedIds = new Set(
    unresolvedCandidates.flatMap((item) =>
      typeof item.id === "string" ? [item.id] : [],
    ),
  );
  const usedIds = new Set<string>();
  const deferred = unresolvedCandidates.map((item) => {
    if (typeof item.id !== "string") return item;
    const baseId = item.id;
    let id = baseId;
    let suffix = 2;
    if (usedIds.has(id)) {
      do {
        id = `${baseId}-${suffix++}`;
      } while (usedIds.has(id) || reservedIds.has(id));
    }
    usedIds.add(id);
    return id === baseId ? item : { ...item, id };
  });
  return {
    ...result,
    coverage: {
      surfaces: [],
      explicitExclusions: [],
      deferred,
    },
  };
}

/** Reduction combines findings; it does not complete the source workers' review. */
export function aggregateDiscoveryCoverage(
  artifacts: DeepScanArtifacts,
  discoveries: Pick<AcceptedDiscovery, "id" | "resultPath" | "result">[],
  unresolvedCandidates?: UnresolvedCandidate[],
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
      const rows =
        field === "deferred" && unresolvedCandidates !== undefined
          ? [
              ...source.deferred.filter(
                (row) => coverageCandidateKey(row, worker.id) === undefined,
              ),
              ...unresolvedCandidates.filter(
                (row) => row.sourceWorkerId === worker.id,
              ),
            ]
          : source[field];
      const usedIds = new Set(
        rows.flatMap((row) => (typeof row.id === "string" ? [row.id] : [])),
      );
      const emittedIds = new Set<string>();
      for (const [index, row] of (rows as JsonObject[]).entries()) {
        const retained: JsonObject = {
          ...row,
          workerId: worker.id,
          ...(coverageCandidateKey(row, worker.id) === undefined
            ? {}
            : { sourceWorkerId: worker.id }),
        };
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
        if (
          (field === "surfaces" ||
            coverageCandidateKey(row, worker.id) !== undefined) &&
          Array.isArray(row.receiptRefs)
        ) {
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
  options: { recoverCandidateReceipts?: boolean } = {},
): Promise<ScanDraftInput> {
  await requireRegularFile(resultPath, artifacts.workersRoot);
  const result = parseStoredScanDraft(
    await readJsonObject(resultPath),
    "Standard scan worker",
    expectedScanId,
    parsePersistedScanDraft,
  );
  if (result.complete === false)
    throw new Error(
      "Standard scan worker wrote only a checkpoint; its audit is not complete.",
    );
  const root = dirname(resultPath);
  if (options.recoverCandidateReceipts) {
    await recoverWorkerCandidateReceipts(result.coverage, {
      root,
      repoRoot: root,
      layout: "worker",
    });
  }
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
      await artifactSourcePath(
        { root, repoRoot: root, layout: "worker" },
        components,
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
    await saveScanDraftCheckpoint(
      { root: artifactDir, repoRoot: artifacts.scanDir, layout: "reducer" },
      result,
    );
    await writeJsonAtomic(resultPath, result);
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
