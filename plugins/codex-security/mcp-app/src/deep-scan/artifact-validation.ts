import { createReadStream } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join, posix, relative, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { asRecord } from "../record.js";
import type { JsonObject } from "../types.js";
import { artifactSourcePath, type ArtifactContext } from "../artifact-io.js";
import {
  validateRetainedCoverage,
  validateWorkerReport,
} from "../coverage-publication.js";
import {
  parsePersistedScanDraft,
  matchesSavedCoverageSource,
  comparableSavedCoverageSource,
  surfaceNormalization,
  normalizedSurfacePair,
  type SurfaceNormalization,
  readAcceptedWorkerCheckpoints,
  recordedScanReceiptRefs,
  reconcileAcceptedWorkerHistory,
  readArchivedWorkerCheckpoints,
  scanDraftInputSchema,
  retainRecordedReceiptOwnership,
  workerCoverageReceiptLocation,
  validateFindingSemantics,
  type ScanDraftInput,
} from "../artifact-scan-draft.js";
import { readJsonObject, requireRegularFile } from "./artifacts.js";
import type { DeepScanArtifacts } from "./artifacts.js";
import { errorMessage } from "./errors.js";
import type { AcceptedDiscovery } from "./worker-runner.js";

export type ScanUnion = Omit<ScanDraftInput, "reviewState"> & {
  /** Host-owned accepted coverage, omitted from the legacy persisted reducer format. */
  sourceCoverage?: ScanDraftInput["reviewState"];
};
const aggregateSchema = scanDraftInputSchema.omit({ reviewState: true });

export function scanUnionToDraft(result: ScanUnion): ScanDraftInput {
  const { sourceCoverage, ...draft } = structuredClone(result);
  for (const finding of draft.findings)
    delete finding.provenance.deepScanRepairGroups;
  return {
    ...draft,
    reviewState: sourceCoverage ?? {
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
    },
  };
}

/** Keep v1 checkpoints readable by older binaries. */
export function persistedScanUnion(
  result: ScanUnion,
): Omit<ScanDraftInput, "reviewState"> {
  const { sourceCoverage: _coverage, ...persisted } = result;
  return persisted;
}

export function parseScanUnion(input: unknown): ScanUnion {
  const parsed = aggregateSchema.parse(input);
  validateFindingSemantics(parsed.findings);
  if (parsed.complete === false)
    throw new Error("Saved Deep Scan iteration is incomplete.");
  return parsed;
}

type WorkerAdmission = "new" | "previously-accepted";
type WorkerScope = Pick<
  ArtifactContext,
  "scope" | "includePaths" | "filePaths" | "excludePaths"
>;

/** Admit exactly the complete semantic result written by an ordinary Standard scan. */
export async function validateDiscoveryArtifacts(
  artifacts: DeepScanArtifacts,
  resultPath: string,
  expectedScanId: string,
  boundScope: WorkerScope = {},
  admission: WorkerAdmission = "new",
): Promise<ScanDraftInput> {
  const { context, result } = await readWorkerDraft(
    artifacts,
    resultPath,
    expectedScanId,
    boundScope,
    admission,
  );
  await validateWorkerReceipts(artifacts.workersRoot, context, result);
  return result;
}

async function readWorkerDraft(
  artifacts: DeepScanArtifacts,
  resultPath: string,
  expectedScanId: string,
  boundScope: WorkerScope,
  admission: WorkerAdmission,
) {
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
    excludePaths: boundScope.excludePaths,
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
  // Preserve the existing publication of previously accepted historical payloads.
  if (admission === "new") validateWorkerReport(result);
  validateRetainedCoverage(result.reviewState);
  // Check the worker's own task IDs before qualifying active and closed tasks.
  const closures = result.reviewState.resolvedDeferred ?? [];
  if (closures.length) {
    const active = new Set(
      result.reviewState.deferred.flatMap((row) => [row.id, row.candidateId]),
    );
    const closed = new Set<string>();
    for (const { id } of closures) {
      if (active.has(id))
        throw new Error(
          `Standard scan worker deferred work is still active: ${id}`,
        );
      if (closed.has(id))
        throw new Error(
          `Standard scan worker repeats resolved deferred id: ${id}`,
        );
      closed.add(id);
    }
  }
  return { context, result };
}

async function validateWorkerReceipts(
  workersRoot: string,
  context: ArtifactContext,
  result: ScanDraftInput,
) {
  const receiptPaths = new Map<string, string>();
  for (const row of result.reviewState.surfaces as JsonObject[]) {
    for (const ref of (row.receiptRefs as string[] | undefined) ?? []) {
      const location = workerCoverageReceiptLocation(context, row, ref);
      const normalized = relative(
        workersRoot,
        join(location.context.root, ...location.components),
      );
      const key = normalized.toLowerCase();
      const previous = receiptPaths.get(key);
      if (previous === normalized) continue;
      if (previous !== undefined)
        throw new Error(
          `Standard scan worker coverage receipt: duplicate artifact path: ${previous} and ${normalized}`,
        );
      receiptPaths.set(key, normalized);
      await artifactSourcePath(
        location.context,
        location.components,
        "Standard scan worker coverage receipt",
      );
    }
  }
}

// Discard worker claims about host-assigned origins before reconciling occurrences.
function clearWorkerOriginClaims(coverage: ScanDraftInput["reviewState"]) {
  for (const field of [
    "surfaces",
    "deferred",
    "explicitExclusions",
    "openQuestions",
    "resolvedDeferred",
  ] as const) {
    for (const value of coverage[field] ?? []) {
      const row = asRecord(value);
      const provenance = asRecord(row?.provenance);
      if (!row || !provenance) continue;
      for (const key of ["workerId", "attempt", "sourceId", "candidateId"])
        delete provenance[key];
      if (!Object.keys(provenance).length) delete row.provenance;
    }
  }
}

export async function readAcceptedDiscovery(
  artifacts: DeepScanArtifacts,
  worker: Omit<AcceptedDiscovery, "result" | "coverage">,
  scanId: string,
  boundScope: WorkerScope = {},
  admission: WorkerAdmission = "new",
): Promise<AcceptedDiscovery> {
  const draft = await readWorkerDraft(
    artifacts,
    worker.resultPath,
    scanId,
    boundScope,
    admission,
  );
  const { context } = draft;
  let result = draft.result;
  let deferredSurfaceTargets = new Map<number, (number | undefined)[]>();
  const surfaceIdentities = [
    ...surfaceNormalization(result.reviewState.surfaces).values(),
  ];
  clearWorkerOriginClaims(result.reviewState);
  function usableCheckpoint({ input }: { input: ScanDraftInput }) {
    try {
      if (admission === "new") validateWorkerReport(input);
      validateRetainedCoverage(input.reviewState);
    } catch {
      return false;
    }
    clearWorkerOriginClaims(input.reviewState);
    return true;
  }
  const archived = (
    await readArchivedWorkerCheckpoints(context, true).catch(() => [])
  ).filter(usableCheckpoint);
  const current = (await readAcceptedWorkerCheckpoints(context, result)).filter(
    usableCheckpoint,
  );
  const snapshots = [...current, ...archived];
  // Same-thread retries copy checkpoints without creating a new observation.
  // fs.cp preserves times through Date values, which have millisecond precision.
  const history = snapshots.filter(
    (source, index) =>
      source.snapshot === undefined ||
      !snapshots.some(
        (earlier, earlierIndex) =>
          earlierIndex > index &&
          earlier.attempt !== source.attempt &&
          Math.round(source.modifiedMs) <= Math.round(earlier.modifiedMs) &&
          isDeepStrictEqual(source.snapshot, earlier.snapshot),
      ),
  );
  const receiptDigests = new Map<string, string>();
  const receiptSources = history.length
    ? [result, ...history.map(({ input }) => input)]
    : [];
  for (const source of receiptSources) {
    for (const surface of source.reviewState.surfaces) {
      for (const value of (surface.receiptRefs as string[] | undefined) ?? []) {
        const ref = posix.normalize(value);
        const shared = recordedScanReceiptRefs(surface).includes(ref);
        const key = JSON.stringify([shared, ref]);
        if (receiptDigests.has(key)) continue;
        try {
          const location = workerCoverageReceiptLocation(context, surface, ref);
          const path = await artifactSourcePath(
            location.context,
            location.components,
            "Saved discovery receipt",
          );
          const digest = createHash("sha256");
          for await (const chunk of createReadStream(path))
            digest.update(chunk);
          receiptDigests.set(key, digest.digest("hex"));
        } catch {
          // Missing evidence cannot establish an earlier receipt origin.
        }
      }
    }
  }
  if (history.length) {
    const reconciled = await reconcileAcceptedWorkerHistory(
      context,
      result,
      history,
      receiptDigests,
      admission === "previously-accepted",
    );
    result = reconciled.result;
    deferredSurfaceTargets = reconciled.deferredSurfaceTargets;
    if (admission === "new") validateWorkerReport(result);
    validateRetainedCoverage(result.reviewState);
  }
  await validateWorkerReceipts(artifacts.workersRoot, context, result);
  const accepted = { ...worker, result };
  return {
    ...accepted,
    coverage: scanCoverage(
      accepted,
      artifacts.scanDir,
      archived.flatMap(({ input, attempt, result, surfaceIdentities }) => {
        const number = /^attempt-(\d+)$/.exec(attempt ?? "")?.[1];
        return number === undefined
          ? []
          : [
              {
                attempt: Number(number),
                coverage: input.reviewState,
                result,
                surfaceIdentities,
              },
            ];
      }),
      receiptDigests,
      [
        { coverage: draft.result.reviewState, surfaceIdentities },
        ...current.map(({ input, surfaceIdentities }) => ({
          coverage: input.reviewState,
          surfaceIdentities,
        })),
      ],
      deferredSurfaceTargets,
    ),
  };
}

/** Qualify worker-local IDs and receipt paths before combining accepted coverage. */
export function scanCoverage(
  worker: AcceptedDiscovery,
  scanDir: string,
  archived: {
    attempt: number;
    coverage: ScanDraftInput["reviewState"];
    result?: boolean;
    surfaceIdentities?: SurfaceNormalization[];
  }[] = [],
  receiptDigests: ReadonlyMap<string, string> = new Map(),
  currentSources: {
    coverage: ScanDraftInput["reviewState"];
    surfaceIdentities?: SurfaceNormalization[];
  }[] = [{ coverage: worker.result.reviewState }],
  deferredSurfaceTargets: ReadonlyMap<
    number,
    readonly (number | undefined)[]
  > = new Map(),
): ScanDraftInput["reviewState"] {
  const coverage = worker.result.reviewState;
  const artifactPrefix = relative(scanDir, dirname(worker.resultPath))
    .split(sep)
    .join("/");
  const archivePrefix = `${posix.dirname(artifactPrefix)}/attempts/`;
  const provenance = {
    workerId: worker.id,
    ...(worker.attempt === undefined ? {} : { attempt: worker.attempt }),
  };
  const prefix = `${worker.id}-attempt-${worker.attempt ?? "unknown"}`;
  const reviews = [provenance];
  const namedFirst = (left: JsonObject, right: JsonObject) =>
    Number(right.id !== undefined) - Number(left.id !== undefined);
  const matchingCoverage = (
    coverage: ScanDraftInput["reviewState"],
  ): ScanDraftInput["reviewState"] => ({
    ...coverage,
    // Consume explicitly named rows before an otherwise identical anonymous row.
    surfaces: [...coverage.surfaces].sort(namedFirst),
    deferred: [...coverage.deferred].sort(namedFirst),
  });
  const authored = currentSources.map(({ coverage, surfaceIdentities }) => ({
    coverage: matchingCoverage(coverage),
    surfaces: surfaceNormalization(coverage.surfaces, surfaceIdentities),
  }));
  const normalizedOutput = surfaceNormalization(coverage.surfaces);
  const history = [...archived].sort(
    // Admission projects the direct result before retained checkpoint rows.
    (left, right) =>
      left.attempt - right.attempt ||
      Number(right.result ?? false) - Number(left.result ?? false),
  );
  const matchedRows = new Map<
    string,
    Map<ScanDraftInput["reviewState"], Set<number>>
  >();
  type Origin = {
    row: JsonObject;
    attempt: number;
    surface?: SurfaceNormalization;
  };
  const origins = new Map<string, Origin[]>();
  const comparableRows = new Map<
    string,
    Map<unknown, JsonObject | undefined>
  >();
  const comparable = (field: string, row: unknown) => {
    let rows = comparableRows.get(field);
    if (rows === undefined) {
      rows = new Map();
      comparableRows.set(field, rows);
    }
    if (!rows.has(row))
      rows.set(
        row,
        comparableSavedCoverageSource(
          field,
          row,
          artifactPrefix,
          receiptDigests,
        ),
      );
    return rows.get(row);
  };
  const matchesOrigin = (
    field: string,
    item: JsonObject,
    origin: Origin,
    reserved: Set<unknown>,
    form: "raw" | "normalized" | "group",
    currentSurface: SurfaceNormalization | undefined,
  ) => {
    let previous = comparable(field, origin.row)!;
    if (form !== "raw") {
      const pair = normalizedSurfacePair(
        previous,
        item,
        origin.surface,
        currentSurface,
        form,
      );
      if (pair === undefined) return false;
      [previous, item] = pair;
    }
    if (
      item.id === undefined &&
      typeof previous.id === "string" &&
      !reserved.has(previous.id) &&
      (field === "surfaces" ||
        (field === "deferred" &&
          !["candidateId", "candidate", "finding"].some((key) => key in item)))
    )
      item = { ...item, id: previous.id };
    return matchesSavedCoverageSource(item, previous);
  };
  const findOrigin = (
    field: string,
    item: JsonObject,
    occurrences: Origin[],
    reserved: Set<unknown>,
    currentSurface: SurfaceNormalization | undefined,
  ) => {
    const forms =
      field === "surfaces"
        ? (["raw", "normalized", "group"] as const)
        : (["raw"] as const);
    for (const named of [true, false]) {
      for (const form of forms) {
        const index = occurrences.findIndex(
          (origin) =>
            (typeof origin.row.id === "string") === named &&
            matchesOrigin(field, item, origin, reserved, form, currentSurface),
        );
        if (index >= 0) return index;
      }
    }
    return -1;
  };
  const savedOrigins = (field: string): Origin[] => {
    const cached = origins.get(field);
    if (cached !== undefined) return cached;
    const occurrences: Origin[] = [];
    for (const saved of history) {
      const normalized =
        field === "surfaces"
          ? surfaceNormalization(
              saved.coverage.surfaces,
              saved.surfaceIdentities,
            )
          : undefined;
      const rows = ((saved.coverage[field] as unknown[] | undefined) ?? []).map(
        (row) =>
          typeof row === "string" ? { question: row } : (asRecord(row) ?? {}),
      );
      const reserved = new Set(rows.map((row) => row.id));
      // Preserve each snapshot's occurrence count before assigning its later names.
      const unmatched = [...occurrences];
      const added: Origin[] = [];
      for (const row of rows) {
        const index = findOrigin(
          field,
          comparable(field, row)!,
          unmatched,
          reserved,
          normalized?.get(row),
        );
        if (index < 0)
          added.push({
            row,
            attempt: saved.attempt,
            surface: normalized?.get(row),
          });
        else {
          const [origin] = unmatched.splice(index, 1);
          if (row.id !== undefined) {
            origin!.row = row;
            origin!.surface = normalized?.get(row);
          }
        }
      }
      occurrences.push(...added);
    }
    origins.set(field, occurrences);
    return occurrences;
  };
  const project = <T extends Record<string, unknown>>(
    field: string,
    item: T,
  ): T => {
    const matchedHistory = matchedRows.get(field) ?? new Map();
    matchedRows.set(field, matchedHistory);
    const match = (coverage: ScanDraftInput["reviewState"]) => {
      const matched = matchedHistory.get(coverage) ?? new Set<number>();
      const rows = (coverage[field] as unknown[] | undefined) ?? [];
      const index = rows.findIndex(
        (row, index) =>
          !matched.has(index) &&
          matchesSavedCoverageSource(
            comparable(field, item),
            comparable(field, row),
          ),
      );
      if (index < 0) return undefined;
      matched.add(index);
      matchedHistory.set(coverage, matched);
      return asRecord(rows[index]) ?? {};
    };
    let source: Record<string, unknown> | undefined;
    let sourceSurface = normalizedOutput.get(item);
    let reserved = new Set<unknown>();
    for (const { coverage, surfaces } of authored) {
      const row = match(coverage);
      if (source === undefined && row !== undefined) {
        source = row;
        sourceSurface = surfaces.get(row);
        reserved = new Set(
          ((coverage[field] as JsonObject[] | undefined) ?? []).map(
            (row) => row.id,
          ),
        );
      }
    }
    let origin = provenance;
    const previous = savedOrigins(field);
    const comparison = { ...comparable(field, item)! };
    if (source !== undefined && source.id === undefined) delete comparison.id;
    const index = findOrigin(
      field,
      comparison,
      previous,
      reserved,
      sourceSurface,
    );
    if (index >= 0) {
      const [saved] = previous.splice(index, 1);
      origin = { workerId: worker.id, attempt: saved!.attempt };
      source ??= saved!.row;
    }
    if (!reviews.some((review) => review.attempt === origin.attempt))
      reviews.push(origin);
    const result = structuredClone(item);
    const projected = asRecord(result.provenance) ?? {};
    for (const key of [
      "workerId",
      "attempt",
      "sourceId",
      "candidateId",
      "scanReceiptRefs",
    ])
      delete projected[key];
    const sourceId = (source ?? item).id;
    return {
      ...result,
      provenance: {
        ...projected,
        ...origin,
        ...(sourceId === undefined ? {} : { sourceId }),
        ...(item.candidateId === undefined
          ? {}
          : { candidateId: item.candidateId }),
      },
      ...(typeof item.candidateId === "string" && {
        candidateId: `${prefix}-candidate-${createHash("sha256").update(item.candidateId).digest("hex")}`,
      }),
    };
  };
  const surfaceIds = new Map<unknown, string>();
  const surfaces = coverage.surfaces.map((surface, index) => {
    const id = `${prefix}-surface-${index + 1}`;
    if (!surfaceIds.has(surface.id)) surfaceIds.set(surface.id, id);
    const shared = asRecord(surface.provenance)?.scanReceiptRefs as
      string[] | undefined;
    const scanRefs = new Set(shared);
    return {
      ...project("surfaces", surface),
      id,
      receiptRefs: ((surface.receiptRefs as string[] | undefined) ?? []).map(
        (receipt) => {
          const ref = posix.normalize(receipt);
          return ref.startsWith(archivePrefix) ||
            ref.startsWith(`${artifactPrefix}/`) ||
            scanRefs.has(receipt)
            ? ref
            : `${artifactPrefix}/${ref}`;
        },
      ),
    };
  });
  return {
    reviews,
    surfaces,
    explicitExclusions: coverage.explicitExclusions.map((item) =>
      project("explicitExclusions", item),
    ),
    deferred: coverage.deferred.map((item, index) => ({
      ...project("deferred", item),
      id: `${prefix}-deferred-${index + 1}`,
      ...(item.surfaceIds === undefined
        ? {}
        : {
            surfaceIds: (item.surfaceIds as string[]).map((id, linkIndex) => {
              const target = deferredSurfaceTargets.get(index)?.[linkIndex];
              return target === undefined
                ? (surfaceIds.get(id) ?? id)
                : surfaces[target]!.id;
            }),
          }),
    })),
    ...(coverage.resolvedDeferred === undefined
      ? {}
      : {
          resolvedDeferred: coverage.resolvedDeferred.map((item) => {
            const projected = project("resolvedDeferred", item);
            const origin = (projected as Record<string, unknown>)
              .provenance as Record<string, unknown>;
            return {
              id: `${worker.id}-attempt-${origin.attempt ?? "unknown"}-resolved-${item.id}`,
              reason: item.reason,
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

export function addScanCoverage(
  aggregate: ScanUnion,
  worker: AcceptedDiscovery,
  scanDir: string,
): void {
  const model = worker.result.threatModel;
  aggregate.threatModel ??= model;
  const additionalModel =
    model && !isDeepStrictEqual(model, aggregate.threatModel)
      ? model
      : undefined;
  const projected = worker.coverage ?? scanCoverage(worker, scanDir);
  const coverage =
    additionalModel && Array.isArray(projected.reviews)
      ? {
          ...projected,
          reviews: projected.reviews.map((review, index) =>
            index === 0
              ? { ...asRecord(review), threatModel: additionalModel }
              : review,
          ),
        }
      : projected;
  const previous = aggregate.sourceCoverage;
  if (!previous) {
    aggregate.sourceCoverage = worker.coverage
      ? structuredClone(coverage)
      : coverage;
    return;
  }
  for (const field of [
    "surfaces",
    "explicitExclusions",
    "deferred",
    "reviews",
    "resolvedDeferred",
    "openQuestions",
  ] as const) {
    const rows = coverage[field];
    if (!Array.isArray(rows)) continue;
    const retained = previous[field];
    if (Array.isArray(retained)) {
      for (const row of rows) retained.push(row);
    } else Object.assign(previous, { [field]: rows });
  }
}

export function parseStoredScanDraft<Result extends ScanUnion>(
  value: Record<string, unknown>,
  label: string,
  expectedScanId: string,
  parse: (input: Record<string, unknown>) => Result,
): Result {
  let parsed: Result;
  try {
    parsed = parse(value);
  } catch (error) {
    throw new Error(
      `${label} returned an invalid Standard scan result: ${errorMessage(error)}`,
      {
        cause: error,
      },
    );
  }
  if (parsed.scanId !== expectedScanId) {
    throw new Error(`${label} returned a result for a different scan.`);
  }
  return parsed;
}
