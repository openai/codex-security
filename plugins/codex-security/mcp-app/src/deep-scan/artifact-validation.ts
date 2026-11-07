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
  parseAcceptedDiscoveryDraft,
  parseAcceptedDeepScanDraft,
  parsePersistedScanDraft,
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
  const { sourceCoverage, ...stored } = asRecord(input) ?? {};
  const { reviewState, ...result } = parseAcceptedDeepScanDraft({
    ...stored,
    reviewState: sourceCoverage ?? {
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
    },
  });
  validateFindingSemantics(result.findings, true);
  if (result.complete === false)
    throw new Error("Saved Deep Scan iteration is incomplete.");
  return sourceCoverage === undefined
    ? result
    : { ...result, sourceCoverage: reviewState };
}

interface DiscoveryAuditOptions extends Pick<
  ArtifactContext,
  "scope" | "includePaths" | "filePaths"
> {
  accepted?: boolean;
  validateWriteups?: boolean;
  artifactDir?: string;
  resultSha256?: string;
  onDigest?: (digest: string) => void;
}

/** Admit exactly the complete semantic result written by an ordinary Standard scan. */
export async function validateDiscoveryArtifacts(
  artifacts: DeepScanArtifacts,
  resultPath: string,
  expectedScanId: string,
  options: DiscoveryAuditOptions = {},
): Promise<ScanDraftInput> {
  const result = await readDiscoveryAuditDraft(
    artifacts,
    resultPath,
    expectedScanId,
    options,
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
  options: DiscoveryAuditOptions = {},
): Promise<ScanDraftInput> {
  await requireRegularFile(resultPath, artifacts.workersRoot);
  const root = options.artifactDir ?? dirname(resultPath);
  const context = {
    root,
    repoRoot: root,
    layout: "worker" as const,
    scanId: expectedScanId,
    scope: options.scope,
    includePaths: options.includePaths,
    filePaths: options.filePaths,
  };
  const stored = await readJsonObject(resultPath, {
    scanRoot: artifacts.scanDir,
    sha256: options.resultSha256,
    onDigest: options.onDigest,
  });
  await retainRecordedReceiptOwnership(context, stored);
  const result = parseStoredScanDraft(
    stored,
    "Standard scan worker",
    expectedScanId,
    options.accepted ? parseAcceptedDiscoveryDraft : parsePersistedScanDraft,
  );
  // Unfinished drafts remain resumable; complete drafts must retain their evidence.
  if (result.complete === false) return result;
  if (options.validateWriteups !== false)
    await validateWriteupFiles(artifacts, result);
  if (!options.accepted) validateWorkerReport(result);
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
  for (const row of result.reviewState.surfaces as JsonObject[]) {
    for (const ref of (row.receiptRefs as string[] | undefined) ?? []) {
      const location = workerCoverageReceiptLocation(context, row, ref);
      const normalized = relative(
        artifacts.workersRoot,
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
  return result;
}

async function validateWriteupFiles(
  artifacts: DeepScanArtifacts,
  result: Pick<ScanDraftInput, "findings">,
): Promise<void> {
  for (const [index, finding] of result.findings.entries()) {
    const reportPath = (finding.writeup as { reportPath: string } | undefined)
      ?.reportPath;
    if (!reportPath) continue;
    try {
      await requireRegularFile(
        join(artifacts.scanDir, reportPath),
        artifacts.scanDir,
      );
    } catch (cause) {
      throw new Error(
        `findings[${index}].writeup.reportPath: expected a file inside the scan directory: ${reportPath}`,
        { cause },
      );
    }
  }
}

export function scanCoverage(
  worker: AcceptedDiscovery,
  scanDir: string,
  additionalModel?: ScanDraftInput["threatModel"],
): ScanDraftInput["reviewState"] {
  const coverage = worker.result.reviewState;
  const artifactPrefix = relative(
    scanDir,
    worker.artifactDir ?? dirname(worker.resultPath),
  )
    .split(sep)
    .join("/");
  const archivePrefix = `${posix.dirname(artifactPrefix)}/attempts/`;
  const provenance = {
    workerId: worker.id,
    ...(worker.attempt === undefined ? {} : { attempt: worker.attempt }),
  };
  const prefix = `${worker.id}-attempt-${worker.attempt ?? "unknown"}`;
  const project = <T extends Record<string, unknown>>(item: T): T => {
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
        ...provenance,
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
      ...project(surface),
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
    reviews: [
      additionalModel
        ? { ...provenance, threatModel: additionalModel }
        : provenance,
    ],
    surfaces,
    explicitExclusions: coverage.explicitExclusions.map(project),
    deferred: coverage.deferred.map((item, index) => ({
      ...project(item),
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
