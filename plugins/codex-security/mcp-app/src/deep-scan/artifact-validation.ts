import { isRecord } from "../record.js";
import { posix } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { artifactSchemaDocuments } from "../artifact-contracts.js";
import { projectArtifactToolSchema } from "../artifact-schema-loader.js";
import {
  parsePersistedScanDraft,
  matchesSavedCoverageSource,
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

export type DeepReductionInput = Omit<ScanDraftInput, "coverage"> & {
  /** Host projection of accepted source coverage; never supplied by the reducer. */
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

/** Validate reducer findings while retaining host-owned persisted coverage. */
export function parseDeepReduction(
  input: unknown,
  persisted = false,
): DeepReductionInput {
  const sourceCoverage = isRecord(input) ? input.sourceCoverage : undefined;
  const submitted = isRecord(input)
    ? Object.fromEntries(
        Object.entries(input).filter(([key]) => key !== "sourceCoverage"),
      )
    : input;
  const parsed = deepReductionInputSchema.parse(submitted);
  validateFindingSemantics(parsed.findings);
  if (persisted && sourceCoverage !== undefined) {
    return {
      ...parsed,
      sourceCoverage: parsePersistedScanDraft({
        ...parsed,
        coverage: sourceCoverage,
      }).coverage,
    };
  }
  return parsed;
}

/** Older accepted reducers may contain coverage that was never source accounting. */
export function parsePreviousDeepReduction(input: unknown): DeepReductionInput {
  if (!isRecord(input)) return parseDeepReduction(input, true);
  const { coverage: _legacyCoverage, ...previous } = input;
  return parseDeepReduction(previous, true);
}

/** Admit exactly the complete semantic result written by an ordinary Standard scan. */
export async function validateDiscoveryArtifacts(
  artifacts: DeepScanArtifacts,
  resultPath: string,
  expectedScanId: string,
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
      parsePreviousDeepReduction,
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
      !["openQuestions", "resolvedDeferred"].includes(field)
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

export { matchesSavedCoverageSource } from "../artifact-scan-draft.js";

/** Qualify worker-local IDs and receipt paths before combining accepted coverage. */
export function projectDiscoveryCoverage(
  coverage: ScanDraftInput["coverage"],
  worker: { id: string; attempt?: number },
  artifactPrefix: string,
  archived: { attempt: number; coverage: ScanDraftInput["coverage"] }[] = [],
  originalCoverage:
    ScanDraftInput["coverage"] | ScanDraftInput["coverage"][] = coverage,
  receiptDigests?: ReadonlyMap<string, string>,
): ScanDraftInput["coverage"] {
  const archivePrefix = `${posix.dirname(artifactPrefix)}/attempts/`;
  const provenance = {
    workerId: worker.id,
    ...(worker.attempt === undefined ? {} : { attempt: worker.attempt }),
  };
  const reviews = [
    {
      ...provenance,
      ...(coverage.completeness === undefined
        ? {}
        : { completeness: coverage.completeness }),
    },
  ];
  const history = [...archived].sort(
    (left, right) => left.attempt - right.attempt,
  );
  // Each historical occurrence accounts for one current row in its collection.
  const matchedHistoricalRows = new Map<
    string,
    Map<(typeof history)[number], Set<number>>
  >();
  const surfaces = coverage.surfaces;
  const prefix = (item: Record<string, unknown>) =>
    `${worker.id}-attempt-${(item.provenance as Record<string, unknown>).attempt ?? "unknown"}`;
  const project = <T extends Record<string, unknown>>(
    field: string,
    item: T,
  ) => {
    const matches = (saved: unknown) =>
      matchesSavedCoverageSource(
        field,
        item,
        saved,
        archivePrefix,
        receiptDigests,
      );
    let original: (typeof history)[number] | undefined;
    const matchedHistory = matchedHistoricalRows.get(field) ?? new Map();
    matchedHistoricalRows.set(field, matchedHistory);
    for (const historical of history) {
      const rows = (historical.coverage[field] as unknown[] | undefined) ?? [];
      const matched = matchedHistory.get(historical) ?? new Set<number>();
      const index = rows.findIndex(
        (saved, index) => !matched.has(index) && matches(saved),
      );
      if (index < 0) continue;
      matched.add(index);
      matchedHistory.set(historical, matched);
      original ??= historical;
    }
    const currentSources = (
      Array.isArray(originalCoverage) ? originalCoverage : [originalCoverage]
    ).flatMap((source) => (source[field] as unknown[] | undefined) ?? []);
    const savedSource =
      currentSources.find(
        (saved) =>
          isRecord(saved) &&
          typeof saved.id === "string" &&
          saved.id === item.id,
      ) ??
      currentSources.find(matches) ??
      ((original?.coverage[field] as unknown[] | undefined) ?? []).find(
        matches,
      );
    const source = isRecord(savedSource) ? savedSource : {};
    const origin = original
      ? { workerId: worker.id, attempt: original.attempt }
      : provenance;
    if (
      original &&
      !reviews.some((review) => review.attempt === original.attempt)
    )
      reviews.push({
        ...origin,
        ...(original.coverage.completeness === undefined
          ? {}
          : { completeness: original.coverage.completeness }),
      });
    const result = structuredClone(item);
    const descriptions = result.provenance;
    const projected =
      typeof descriptions === "object" &&
      descriptions !== null &&
      !Array.isArray(descriptions)
        ? (descriptions as Record<string, unknown>)
        : {};
    for (const key of ["workerId", "attempt", "sourceId", "candidateId"])
      delete projected[key];
    return {
      ...result,
      provenance: {
        ...projected,
        ...origin,
        // Normalized IDs help compare history; provenance describes the saved source.
        ...(source.id === undefined ? {} : { sourceId: source.id }),
        ...(item.candidateId === undefined
          ? {}
          : { candidateId: item.candidateId }),
      },
    };
  };
  const projectedSurfaces = surfaces.map((surface, index) => {
    const item = project("surfaces", surface);
    return {
      ...item,
      id: `${prefix(item)}-surface-${index + 1}`,
      receiptRefs: ((surface.receiptRefs as string[] | undefined) ?? []).map(
        (ref) =>
          ref.startsWith(archivePrefix) ? ref : `${artifactPrefix}/${ref}`,
      ),
    };
  });
  const surfaceIds = new Map<unknown, string[]>();
  for (const [index, surface] of surfaces.entries()) {
    surfaceIds.set(surface.id, [
      ...(surfaceIds.get(surface.id) ?? []),
      projectedSurfaces[index]!.id,
    ]);
  }
  return {
    reviews,
    surfaces: projectedSurfaces,
    explicitExclusions: coverage.explicitExclusions.map((item) =>
      project("explicitExclusions", item),
    ),
    deferred: coverage.deferred.map((item, index) => {
      const projected = project("deferred", item);
      return {
        ...projected,
        id: `${prefix(projected)}-deferred-${index + 1}`,
        ...(item.candidateId === undefined
          ? {}
          : { candidateId: `${prefix(projected)}-candidate-${index + 1}` }),
        ...(item.surfaceIds === undefined
          ? {}
          : {
              surfaceIds: (item.surfaceIds as string[]).flatMap(
                (id) => surfaceIds.get(id) ?? [id],
              ),
            }),
      };
    }),
    ...(coverage.resolvedDeferred === undefined
      ? {}
      : {
          resolvedDeferred: coverage.resolvedDeferred.map((item) => {
            const projected = project("resolvedDeferred", item);
            return {
              ...item,
              id: `${prefix(projected)}-resolved-${item.id}`,
            };
          }),
        }),
    ...(coverage.openQuestions === undefined
      ? {}
      : {
          openQuestions: coverage.openQuestions.map((question) =>
            project(
              "openQuestions",
              typeof question === "string" ? { question } : question,
            ),
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
