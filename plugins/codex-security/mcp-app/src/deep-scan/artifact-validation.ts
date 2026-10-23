import { isRecord } from "../record.js";
import { isDeepStrictEqual } from "node:util";
import { dirname, join, relative, sep } from "node:path";
import type { JsonObject } from "../types.js";
import type { AcceptedDiscovery } from "./worker-runner.js";
import { artifactSourcePath } from "../artifact-io.js";
import {
  coverageReceiptComponents,
  validateRetainedCoverage,
} from "../coverage-publication.js";
import { artifactSchemaDocuments } from "../artifact-contracts.js";
import { projectArtifactToolSchema } from "../artifact-schema-loader.js";
import { requireFiniteNumbers } from "../helpers/json.js";
import {
  parsePersistedScanDraft,
  readCurrentScanDraftCheckpoint,
  parseScanDraft,
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
  const record = isRecord(input) ? input : {};
  const { sourceCoverage, ...submitted } = record;
  const parsed = deepReductionInputSchema.parse(submitted);
  validateFindingSemantics(parsed.findings);
  if (persisted && sourceCoverage !== undefined) {
    return {
      ...parsed,
      sourceCoverage: parsePersistedScanDraft({
        ...submitted,
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
  artifactDir = dirname(resultPath),
): Promise<ScanDraftInput> {
  const result = await readDiscoveryAuditDraft(
    artifacts,
    resultPath,
    expectedScanId,
    artifactDir,
  );
  if (result.complete === false)
    throw new Error(
      "Standard scan worker wrote only a checkpoint; its audit is not complete.",
    );
  return result;
}

async function validateDiscoveryCoverage(
  root: string,
  result: ScanDraftInput,
): Promise<void> {
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
}

export async function readDiscoveryAuditDraft(
  artifacts: DeepScanArtifacts,
  resultPath: string,
  expectedScanId: string,
  artifactDir = dirname(resultPath),
): Promise<ScanDraftInput> {
  await requireRegularFile(resultPath, artifacts.workersRoot);
  const saved = await readJsonObject(resultPath);
  const result = parseStoredScanDraft(
    saved,
    "Standard scan worker",
    expectedScanId,
    parsePersistedScanDraft,
  );
  const checkpoint =
    resultPath === join(artifactDir, "result.json")
      ? await readCurrentScanDraftCheckpoint({
          root: artifactDir,
          repoRoot: artifacts.scanDir,
          layout: "worker",
          scanId: expectedScanId,
        })
      : undefined;
  const { handoffClaimToken: _claim, ...semantic } = saved;
  if (checkpoint !== undefined && !isDeepStrictEqual(checkpoint, semantic))
    throw new Error(
      "The worker result does not match its current checkpoint head.",
    );
  if (result.complete !== false)
    await validateDiscoveryCoverage(artifactDir, result);
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
    parseDeepReduction,
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

export function projectDiscoveryCoverage(
  coverage: ScanDraftInput["coverage"],
  worker: { id: string; attempt?: number },
  artifactPrefix: string,
): ScanDraftInput["coverage"] {
  const provenance = {
    workerId: worker.id,
    ...(worker.attempt === undefined ? {} : { attempt: worker.attempt }),
  };
  const project = <T extends Record<string, unknown>>(item: T) => ({
    ...structuredClone(item),
    workerId: worker.id,
    provenance: {
      ...provenance,
      ...(item.id === undefined ? {} : { sourceId: item.id }),
      ...(item.candidateId === undefined
        ? {}
        : { candidateId: item.candidateId }),
    },
  });
  const qualify = <T extends Record<string, unknown>>(rows: T[]) => {
    const reserved = new Set(
      rows.flatMap((row) => (typeof row.id === "string" ? [row.id] : [])),
    );
    const emitted = new Set<string>();
    return rows.map((row, index) => {
      const base = typeof row.id === "string" ? row.id : String(index);
      let id = base;
      if (typeof row.id !== "string" || emitted.has(id)) {
        for (let suffix = 2; reserved.has(id); suffix++)
          id = `${base}-${suffix}`;
      }
      reserved.add(id);
      emitted.add(id);
      return { ...project(row), id: `${worker.id}/${id}` };
    });
  };
  return {
    ...(coverage.completeness === undefined
      ? {}
      : { completeness: coverage.completeness }),
    reviews: [
      {
        ...provenance,
        ...(coverage.completeness === undefined
          ? {}
          : { completeness: coverage.completeness }),
      },
    ],
    surfaces: qualify(coverage.surfaces).map((surface, index) => ({
      ...surface,
      receiptRefs: (
        (coverage.surfaces[index]!.receiptRefs as string[] | undefined) ?? []
      ).map(
        (ref) =>
          `${artifactPrefix}/${coverageReceiptComponents(ref).join("/")}`,
      ),
    })),
    explicitExclusions: qualify(coverage.explicitExclusions),
    deferred: qualify(coverage.deferred).map((item, index) => ({
      ...item,
      ...(coverage.deferred[index]!.surfaceIds === undefined
        ? {}
        : {
            surfaceIds: (coverage.deferred[index]!.surfaceIds as string[]).map(
              (id) => `${worker.id}/${id}`,
            ),
          }),
    })),
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
