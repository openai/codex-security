import { createHash } from "node:crypto";
import { dirname, join, posix, relative, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { asRecord, isRecord } from "../record.js";
import {
  coverageCandidateKey,
  findingCandidateId,
  findingCandidateKey,
  findingCandidateOwner,
  resolvedCandidateKeys,
} from "../artifact-candidates.js";
import {
  recoverWorkerCandidateReceipts,
  workerCoverageReceiptLocation,
} from "../artifact-worker-receipts.js";
import type { JsonObject } from "../types.js";
import { artifactSourcePath, type ArtifactContext } from "../artifact-io.js";
import {
  coverageReceiptComponents,
  validateRetainedCoverage,
  validateWorkerReport,
} from "../coverage-publication.js";
import {
  parsePersistedScanDraft,
  scanDraftInputSchema,
  retainRecordedReceiptOwnership,
  requiresWorkerReceipt,
  preserveFindingDetails,
  validateFindingSemantics,
  type ScanDraftInput,
} from "../artifact-scan-draft.js";
import { readJsonObject, requireRegularFile } from "./artifacts.js";
import type { DeepScanArtifacts } from "./artifacts.js";
import { errorMessage } from "./errors.js";
import type { AcceptedDiscovery } from "./worker-runner.js";

export type UnresolvedCandidate =
  ScanDraftInput["reviewState"]["deferred"][number] & {
    candidateId: string;
    sourceWorkerId: string;
  };

export type ScanUnion = Omit<ScanDraftInput, "reviewState"> & {
  unresolvedCandidates?: UnresolvedCandidate[];
  /** Host-owned accepted coverage, omitted from the legacy persisted reducer format. */
  sourceCoverage?: ScanDraftInput["reviewState"];
};
const aggregateSchema = scanDraftInputSchema.omit({ reviewState: true });

export function scanUnionToDraft(input: ScanUnion): ScanDraftInput {
  const {
    sourceCoverage,
    unresolvedCandidates = [],
    ...result
  } = structuredClone(input);
  const coverage = sourceCoverage ?? {
    surfaces: [],
    explicitExclusions: [],
    deferred: [],
  };
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
  for (const finding of result.findings)
    delete finding.provenance.deepScanRepairGroups;
  return { ...result, reviewState: coverage };
}

/** Keep v1 checkpoints readable by older binaries. */
export function persistedScanUnion(
  result: ScanUnion,
): Omit<ScanDraftInput, "reviewState"> {
  const { sourceCoverage: _coverage, ...persisted } = result;
  return persisted;
}

export function parseScanUnion(input: Record<string, unknown>): ScanUnion {
  // Old reducers stored worker-owned gaps alongside findings. Coverage is
  // always rebuilt from the accepted worker artifacts on resume.
  const {
    unresolvedCandidates,
    sourceCoverage: _coverage,
    ...semantic
  } = input;
  const parsed = aggregateSchema.parse(semantic);
  validateFindingSemantics(parsed.findings);
  if (parsed.complete === false)
    throw new Error("Saved Deep Scan iteration is incomplete.");
  if (unresolvedCandidates === undefined) return parsed;
  const { reviewState } = parsePersistedScanDraft({
    ...parsed,
    reviewState: {
      surfaces: [],
      explicitExclusions: [],
      deferred: unresolvedCandidates,
    },
  });
  const pending = reviewState.deferred.map((item) => {
    if (
      typeof item.candidateId !== "string" ||
      typeof item.sourceWorkerId !== "string" ||
      !item.sourceWorkerId.trim()
    )
      throw new Error(
        "Saved Deep Scan candidate is missing its worker identity.",
      );
    return {
      ...item,
      candidateId: item.candidateId,
      sourceWorkerId: item.sourceWorkerId,
    };
  });
  return pending.length ? { ...parsed, unresolvedCandidates: pending } : parsed;
}

/** Admit exactly the complete semantic result written by an ordinary Standard scan. */
export async function validateDiscoveryArtifacts(
  artifacts: DeepScanArtifacts,
  resultPath: string,
  expectedScanId: string,
  boundScope: Pick<ArtifactContext, "scope" | "includePaths" | "filePaths"> & {
    workerId?: string;
  } = {},
  admission: "new" | "previously-accepted" = "new",
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
  // Preserve the existing publication of previously accepted historical payloads.
  if (admission === "new") validateWorkerReport(result);
  if (boundScope.workerId !== undefined) {
    await recoverWorkerCandidateReceipts(result.reviewState, context);
    for (const finding of result.findings) {
      if (findingCandidateId(finding) === undefined) continue;
      const previousOwner = findingCandidateOwner(finding);
      const previousSource = finding.provenance.sourceWorkerId;
      const previous =
        (previousOwner !== undefined &&
          previousOwner !== boundScope.workerId) ||
        (previousSource !== undefined && previousSource !== boundScope.workerId)
          ? structuredClone(finding)
          : undefined;
      finding.provenance.sourceWorkerId = boundScope.workerId;
      if (previous) preserveFindingDetails(finding, previous);
    }
  }
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
  const receiptPaths = new Map<string, string>();
  const label = "Standard scan worker coverage receipt";
  async function verifyReceipt(context: ArtifactContext, components: string[]) {
    const path = relative(
      artifacts.workersRoot,
      join(context.root, ...components),
    );
    const key = path.toLowerCase();
    const previous = receiptPaths.get(key);
    if (previous === path) return;
    if (previous !== undefined)
      throw new Error(
        `${label}: duplicate artifact path: ${previous} and ${path}`,
      );
    await artifactSourcePath(context, components, label);
    receiptPaths.set(key, path);
  }
  for (const row of result.reviewState.surfaces as JsonObject[]) {
    for (const ref of (row.receiptRefs as string[] | undefined) ?? []) {
      const location = workerCoverageReceiptLocation(context, row, ref);
      try {
        await verifyReceipt(location.context, location.components);
      } catch (error) {
        // Older workers wrote generic review receipts under the parent scan.
        // Only a missing worker-local file can fall back to that location.
        if (
          location.context.root !== root ||
          requiresWorkerReceipt(row) ||
          !(error instanceof Error) ||
          error.message !== `${label}: the requested artifact is unavailable.`
        )
          throw error;
        await verifyReceipt(
          { ...context, root: artifacts.scanDir },
          coverageReceiptComponents(ref),
        );
        const provenance = asRecord(row.provenance) ?? {};
        row.provenance = {
          ...provenance,
          scanReceiptRefs: [
            ...new Set([
              ...((provenance.scanReceiptRefs as string[] | undefined) ?? []),
              ref,
            ]),
          ],
        };
      }
    }
  }
  return result;
}

/** Qualify worker-local IDs and receipt paths before combining accepted coverage. */
export function scanCoverage(
  worker: AcceptedDiscovery,
  scanDir: string,
  additionalModel?: ScanDraftInput["threatModel"],
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
  const receiptRef = (receipt: string, scanRefs?: Set<string>) => {
    const ref = posix.normalize(receipt);
    return ref.startsWith(archivePrefix) ||
      ref.startsWith(`${artifactPrefix}/`) ||
      scanRefs?.has(receipt) ||
      scanRefs?.has(ref)
      ? ref
      : `${artifactPrefix}/${ref}`;
  };
  const project = <T extends Record<string, unknown>>(
    item: T,
    candidateReceipts = false,
  ): T => {
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
      ...(candidateReceipts &&
        typeof item.candidateId === "string" &&
        Array.isArray(item.receiptRefs) &&
        item.receiptRefs.every((ref) => typeof ref === "string") && {
          receiptRefs: item.receiptRefs.map((ref: string) => receiptRef(ref)),
        }),
      provenance: {
        ...projected,
        ...provenance,
        ...(item.id === undefined ? {} : { sourceId: item.id }),
        ...(item.candidateId === undefined
          ? {}
          : { candidateId: item.candidateId }),
      },
      ...(typeof item.candidateId === "string" &&
        item.candidateId.trim() && {
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
      ...project(surface),
      id,
      receiptRefs: ((surface.receiptRefs as string[] | undefined) ?? []).map(
        (receipt) => receiptRef(receipt, scanRefs),
      ),
    };
  });
  return {
    reviews: [
      additionalModel
        ? { ...provenance, threatModel: additionalModel }
        : provenance,
    ],
    surfaces,
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

export function addScanCoverage(
  aggregate: ScanUnion,
  worker: AcceptedDiscovery,
  scanDir: string,
): void {
  const resolved = resolvedCandidateKeys(worker.result, worker.id);
  const pending = (aggregate.unresolvedCandidates ?? []).filter(
    (item) => item.sourceWorkerId !== worker.id,
  );
  for (const item of worker.result.reviewState.deferred) {
    if (
      typeof item.candidateId === "string" &&
      !resolved.has(coverageCandidateKey(item, worker.id)!)
    ) {
      const candidate = {
        ...item,
        candidateId: item.candidateId,
        sourceWorkerId: worker.id,
      };
      if (!pending.some((previous) => isDeepStrictEqual(previous, candidate))) {
        pending.push(structuredClone(candidate));
      }
    }
  }
  if (pending.length) aggregate.unresolvedCandidates = pending;
  else delete aggregate.unresolvedCandidates;
  const model = worker.result.threatModel;
  aggregate.threatModel ??= model;
  const additionalModel =
    model && !isDeepStrictEqual(model, aggregate.threatModel)
      ? model
      : undefined;
  const coverage = scanCoverage(worker, scanDir, additionalModel);
  const previous = aggregate.sourceCoverage;
  if (!previous) {
    aggregate.sourceCoverage = coverage;
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

/** Mark a retained finding as historical while its own worker is missing proof. */
export function refreshCandidateFindingState(aggregate: ScanUnion): void {
  const pending = new Set(
    aggregate.unresolvedCandidates?.map((row) =>
      coverageCandidateKey(row, row.sourceWorkerId),
    ),
  );
  for (const finding of aggregate.findings) {
    const key = findingCandidateKey(finding);
    if (key === undefined) continue;
    if (pending.has(key)) finding.provenance.candidateReopened = true;
    else delete finding.provenance.candidateReopened;
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
