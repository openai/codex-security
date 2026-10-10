import { dirname } from "node:path";
import { isDeepStrictEqual } from "node:util";
import {
  parsePersistedScanDraft,
  readCurrentScanDraftCheckpoint,
  parseScanDraft,
  preserveFindingDetails,
  saveScanDraftCheckpoint,
  scanFindingIdentity,
  type ScanDraftInput,
} from "../artifact-scan-draft.js";
import {
  readJsonObject,
  requireRegularFile,
  writeJsonAtomic,
} from "./artifacts.js";
import type { DeepScanArtifacts } from "./artifacts.js";

export type DeepReductionInput = Omit<ScanDraftInput, "coverage"> & {
  /** Host projection of accepted source coverage; never supplied by the reducer. */
  sourceCoverage?: ScanDraftInput["coverage"];
};

export interface DeepReductionSources {
  discoveries: {
    workerId: string;
    attempt?: number;
    coverage?: ScanDraftInput["coverage"];
    result: DeepReductionInput;
  }[];
  previous: DeepReductionInput | null;
}

export interface ReducerArtifactValidation {
  newFindings: number;
  result: DeepReductionInput;
}

export function deepReductionToScanDraft(
  result: DeepReductionInput,
): ScanDraftInput {
  const { sourceCoverage, ...draft } = structuredClone(result);
  return { ...draft, coverage: sourceCoverage ?? unknownSourceCoverage() };
}

/** Older workflow readers reject the host field; retain their persisted shape. */
export function deepReductionForPersistence(
  result: DeepReductionInput,
  persistSourceCoverage = false,
): DeepReductionInput {
  if (persistSourceCoverage) return result;
  const { sourceCoverage: _coverage, ...legacy } = result;
  return legacy;
}

/**
 * Check reducer findings with the Standard scan validator.
 * It requires coverage, so add an empty value and remove it after validation.
 */
export function parseDeepReduction(
  input: Record<string, unknown>,
  persisted = false,
): DeepReductionInput {
  const { sourceCoverage, ...submitted } = input;
  const standard = {
    ...submitted,
    coverage: {
      completeness: "complete",
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
    },
  };
  const { coverage: _coverage, ...parsed } = persisted
    ? parsePersistedScanDraft(standard)
    : parseScanDraft(standard as unknown as ScanDraftInput);
  if (persisted && sourceCoverage !== undefined) {
    return {
      ...parsed,
      sourceCoverage: parsePersistedScanDraft({
        ...standard,
        coverage: sourceCoverage,
      }).coverage,
    };
  }
  return parsed;
}

/** Admit exactly the complete semantic result written by an ordinary Standard scan. */
export async function validateDiscoveryArtifacts(
  artifacts: DeepScanArtifacts,
  resultPath: string,
  expectedScanId: string,
): Promise<ScanDraftInput> {
  const result = await readDiscoveryAuditDraft(
    artifacts,
    resultPath,
    expectedScanId,
  );
  if (result.complete === false)
    throw new Error(
      "Standard scan worker wrote only a checkpoint; its audit is not complete.",
    );
  return result;
}

export async function readDiscoveryAuditDraft(
  artifacts: DeepScanArtifacts,
  resultPath: string,
  expectedScanId: string,
): Promise<ScanDraftInput> {
  await requireRegularFile(resultPath, artifacts.workersRoot);
  const saved = await readJsonObject(resultPath);
  const result = parseStoredScanDraft(
    saved,
    "Standard scan worker",
    expectedScanId,
    parsePersistedScanDraft,
  );
  const checkpoint = await readCurrentScanDraftCheckpoint({
    root: dirname(resultPath),
    repoRoot: artifacts.scanDir,
    layout: "worker",
    scanId: expectedScanId,
  });
  const { handoffClaimToken: _claim, ...semantic } = saved;
  if (checkpoint !== undefined && !isDeepStrictEqual(checkpoint, semantic))
    throw new Error(
      "The worker result does not match its current checkpoint head.",
    );
  return result;
}

/** Validate the complete aggregate and derive convergence from stable finding identities. */
export async function validateReducerArtifacts(
  input: {
    artifacts: DeepScanArtifacts;
    artifactDir: string;
    resultPath: string;
    reducerId: string;
    previousReducerResultPath?: string;
    sources?: DeepReductionSources;
    persistSourceCoverage?: boolean;
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
    const persisted = deepReductionForPersistence(
      result,
      input.persistSourceCoverage,
    );
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
    ].filter((value): value is Record<string, unknown> => value !== undefined);
    if (
      sourceValues.some((value) => !isDeepStrictEqual(sourceValues[0], value))
    ) {
      throw new Error(
        `Deep reduction has ambiguous ${label}; provide the reconciled ${field} explicitly.`,
      );
    }
    if (sourceValues[0] !== undefined) {
      result[field] = structuredClone(sourceValues[0]);
    }
  }
  return result;
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
    completeness: "complete",
    surfaces: [],
    explicitExclusions: [],
    deferred: [],
    reviews: [],
  };
  for (const field of [
    "surfaces",
    "explicitExclusions",
    "deferred",
    "openQuestions",
    "reviews",
  ]) {
    const entries = sources.flatMap(
      (source) => (source[field] as unknown[] | undefined) ?? [],
    );
    if (entries.length || field !== "openQuestions")
      result[field] = structuredClone(entries);
  }
  if (
    sources.some((source) => source.completeness === "partial") ||
    (result.deferred as unknown[]).length > 0 ||
    (result.surfaces as Record<string, unknown>[]).some(
      (surface) => surface.disposition === "needs_follow_up",
    )
  ) {
    result.completeness = "partial";
  } else if (sources.some((source) => source.completeness === "unknown")) {
    result.completeness = "unknown";
  }
  return result;
}

function unknownSourceCoverage(): ScanDraftInput["coverage"] {
  return {
    completeness: "unknown",
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
): ScanDraftInput["coverage"] {
  const provenance = {
    workerId: worker.id,
    ...(worker.attempt === undefined ? {} : { attempt: worker.attempt }),
  };
  const prefix = `${worker.id}-attempt-${worker.attempt ?? "unknown"}`;
  const surfaces = coverage.surfaces as Record<string, unknown>[];
  const surfaceIds = new Map(
    surfaces.map((surface, index) => [
      surface.id,
      `${prefix}-surface-${index + 1}`,
    ]),
  );
  const project = (item: Record<string, unknown>) => ({
    ...structuredClone(item),
    provenance: {
      ...provenance,
      ...(item.id === undefined ? {} : { sourceId: item.id }),
      ...(item.candidateId === undefined
        ? {}
        : { candidateId: item.candidateId }),
    },
  });
  return {
    completeness: coverage.completeness,
    reviews: [{ ...provenance, completeness: coverage.completeness }],
    surfaces: surfaces.map((surface, index) => ({
      ...project(surface),
      id: `${prefix}-surface-${index + 1}`,
      receiptRefs: ((surface.receiptRefs as string[] | undefined) ?? []).map(
        (ref) => `${artifactPrefix}/${ref}`,
      ),
    })),
    explicitExclusions: (
      coverage.explicitExclusions as Record<string, unknown>[]
    ).map(project),
    deferred: (coverage.deferred as Record<string, unknown>[]).map(
      (item, index) => ({
        ...project(item),
        id: `${prefix}-deferred-${index + 1}`,
        ...(item.candidateId === undefined
          ? {}
          : { candidateId: `${prefix}-candidate-${index + 1}` }),
        ...(item.surfaceIds === undefined
          ? {}
          : {
              surfaceIds: (item.surfaceIds as string[]).map(
                (id) => surfaceIds.get(id) ?? id,
              ),
            }),
      }),
    ),
    ...(coverage.openQuestions === undefined
      ? {}
      : {
          openQuestions: (
            coverage.openQuestions as (string | Record<string, unknown>)[]
          ).map((question) =>
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
  for (const discovery of inputs.discoveries) {
    for (const [index, finding] of discovery.result.findings.entries()) {
      const original = structuredClone(finding);
      delete (original.provenance as Finding).sourceFindingIds;
      sources.set(`${discovery.workerId}:${index}`, original);
    }
  }
  for (const original of (inputs.previous?.findings ?? []).flatMap(
    retainedFindingSources,
  ))
    sources.set(original.id, original.finding);
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
