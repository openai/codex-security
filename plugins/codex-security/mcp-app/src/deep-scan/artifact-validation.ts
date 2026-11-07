import { createHash } from "node:crypto";
import { dirname, join, posix, relative, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { asRecord, isNonEmptyString } from "../record.js";
import type { JsonObject } from "../types.js";
import { artifactSourcePath, type ArtifactContext } from "../artifact-io.js";
import {
  validateRetainedCoverage,
  validateWorkerReport,
} from "../coverage-publication.js";
import {
  parsePersistedScanDraft,
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

/** Admit exactly the complete semantic result written by an ordinary Standard scan. */
export async function validateDiscoveryArtifacts(
  artifacts: DeepScanArtifacts,
  resultPath: string,
  expectedScanId: string,
  boundScope: Pick<
    ArtifactContext,
    "scope" | "includePaths" | "filePaths"
  > = {},
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
  // Historical worker inputs are immutable. The host repairs their evidence on resume.
  if (admission === "new") {
    validateWorkerReport(result);
    validateCompletedFindingEvidence(result.findings);
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

/** Match the finalizer's evidence gate while worker validation can still retry. */
export function validateCompletedFindingEvidence(findings: JsonObject[]): void {
  for (const [index, finding] of findings.entries()) {
    const requireText = (value: unknown, field: string) => {
      if (!isNonEmptyString(value))
        throw new Error(
          `findings[${index}].${field}: include the supporting analysis before completing the worker.`,
        );
    };
    if (
      !Array.isArray(finding.codeEvidence) ||
      finding.codeEvidence.length === 0
    )
      throw new Error(
        `findings[${index}].codeEvidence: include the source snippets used as proof.`,
      );
    requireText(
      asRecord(finding.rootCause)?.summary ?? finding.rootCause,
      "rootCause",
    );
    const dataflow = asRecord(finding.attackPath)?.dataflow;
    const flow = asRecord(dataflow);
    if (flow) {
      if (!flow.summary) {
        requireText(flow.source, "attackPath.dataflow.source");
        requireText(flow.sink, "attackPath.dataflow.sink");
      }
    } else {
      requireText(dataflow, "attackPath.dataflow");
    }
    const validation = asRecord(finding.validation);
    requireText(validation?.method, "validation.method");
    if (!validation?.result)
      requireText(validation?.summary, "validation.summary");
    const hasEvidence = [validation?.evidence, validation?.evidenceRefs].some(
      (value) =>
        Array.isArray(value) ? value.length > 0 : isNonEmptyString(value),
    );
    if (!hasEvidence)
      throw new Error(
        `findings[${index}].validation: include observed evidence or evidenceRefs to the source proof.`,
      );
  }
}
