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

/** Admit exactly the complete semantic result written by an ordinary Standard scan. */
export async function validateDiscoveryArtifacts(
  artifacts: DeepScanArtifacts,
  resultPath: string,
  expectedScanId: string,
  boundScope: Pick<
    ArtifactContext,
    "scope" | "includePaths" | "filePaths"
  > = {},
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
  boundScope: Pick<ArtifactContext, "scope" | "includePaths" | "filePaths">,
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
  boundScope: Pick<
    ArtifactContext,
    "scope" | "includePaths" | "filePaths"
  > = {},
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
  const history = [...current, ...archived];
  const receiptDigests = new Map<string, string>();
  const receiptSources = archived.length
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
          for await (const chunk of createReadStream(path)) digest.update(chunk);
          receiptDigests.set(key, digest.digest("hex"));
        } catch {
          // Missing evidence cannot establish an earlier receipt origin.
        }
      }
    }
  }
  if (history.length) {
    result = await reconcileAcceptedWorkerHistory(
      context,
      result,
      history,
      receiptDigests,
    );
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
      archived.flatMap(({ input, attempt }) => {
        const number = /^attempt-(\d+)$/.exec(attempt ?? "")?.[1];
        return number === undefined
          ? []
          : [{ attempt: Number(number), coverage: input.reviewState }];
      }),
      receiptDigests,
    ),
  };
}

/** Qualify worker-local IDs and receipt paths before combining accepted coverage. */
export function scanCoverage(
  worker: AcceptedDiscovery,
  scanDir: string,
  archived: { attempt: number; coverage: ScanDraftInput["reviewState"] }[] = [],
  receiptDigests: ReadonlyMap<string, string> = new Map(),
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
  const history = [...archived].sort(
    (left, right) => left.attempt - right.attempt,
  );
  // Each occurrence in one snapshot can account for only one current record.
  const matchedRows = new Map<
    string,
    Map<(typeof history)[number], Set<number>>
  >();
  const project = <T extends Record<string, unknown>>(
    field: string,
    item: T,
  ): T => {
    const matchedHistory = matchedRows.get(field) ?? new Map();
    matchedRows.set(field, matchedHistory);
    let origin = provenance;
    for (const saved of history) {
      const matched = matchedHistory.get(saved) ?? new Set<number>();
      const rows = (saved.coverage[field] as unknown[] | undefined) ?? [];
      const index = rows.findIndex(
        (row, index) =>
          !matched.has(index) &&
          matchesSavedCoverageSource(
            field,
            item,
            row,
            artifactPrefix,
            receiptDigests,
          ),
      );
      if (index < 0) continue;
      matched.add(index);
      matchedHistory.set(saved, matched);
      if (origin === provenance)
        origin = { workerId: worker.id, attempt: saved.attempt };
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
    return {
      ...result,
      provenance: {
        ...projected,
        ...origin,
        ...(item.id === undefined ? {} : { sourceId: item.id }),
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
            surfaceIds: (item.surfaceIds as string[]).map(
              (id) => surfaceIds.get(id) ?? id,
            ),
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

/** Compare accepted content and readable receipt bytes, never authored origin claims. */
function matchesSavedCoverageSource(
  field: string,
  item: Record<string, unknown>,
  saved: unknown,
  artifactPrefix: string,
  receiptDigests: ReadonlyMap<string, string>,
): boolean {
  const original =
    typeof saved === "string" ? { question: saved } : structuredClone(saved);
  const current = structuredClone(item);
  if (
    typeof original !== "object" ||
    original === null ||
    Array.isArray(original)
  )
    return false;
  const previous = original as Record<string, unknown>;
  if (previous.id === undefined) delete current.id;
  if (field === "surfaces") {
    const archivePrefix = `${posix.dirname(artifactPrefix)}/attempts/`;
    for (const row of [previous, current]) {
      const provenance = row.provenance as Record<string, unknown> | undefined;
      const sharedRefs = provenance?.scanReceiptRefs as string[] | undefined;
      row.receiptRefs = [
        ...new Set(
          ((row.receiptRefs as string[] | undefined) ?? []).map((ref) => {
            ref = posix.normalize(ref);
            const shared = sharedRefs?.includes(ref) ?? false;
            const digest = receiptDigests.get(JSON.stringify([shared, ref]));
            let path = ref;
            // Without readable bytes, only the exact accepted reference can match.
            if (digest !== undefined && !shared) {
              if (path.startsWith(`${artifactPrefix}/`))
                path = path.slice(artifactPrefix.length + 1);
              else if (path.startsWith(archivePrefix)) {
                const archived = path.slice(archivePrefix.length);
                if (/^attempt-[0-9]+\//u.test(archived))
                  path = archived.slice(archived.indexOf("/") + 1);
              }
              while (
                /^artifacts\/archived-receipts\/attempt-[0-9]+\//u.test(path)
              ) {
                path = path.replace(
                  /^artifacts\/archived-receipts\/attempt-[0-9]+\//u,
                  "",
                );
              }
            }
            return JSON.stringify([shared, path, digest]);
          }),
        ),
      ];
      if (provenance) {
        delete provenance.scanReceiptRefs;
        if (Object.keys(provenance).length === 0) delete row.provenance;
      }
    }
  }
  return isDeepStrictEqual(previous, current);
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
