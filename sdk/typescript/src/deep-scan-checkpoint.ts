import { resolve } from "node:path";
import { readScanFile } from "./contract.js";
import type { ScanCost } from "./cost.js";
import type { ScanArtifactRestorer } from "./runtime.js";
import type { SemanticCoverage } from "./semantic-models.js";
import { hydrateScanAggregate, type ScanAggregate } from "./scan-merge.js";

export const DEEP_SCAN_CHECKPOINT = "artifacts/deep-scan/checkpoint.json";

export interface DeepScanPass {
  directory: string;
  scanId?: string;
  /** Completion time for a consumed reservation that never acquired a SQL row. */
  failedBeforeRegistration?: string;
  [extension: string]: unknown;
}

interface CompositionMetadata {
  version: 3;
  startedAt: string;
  passes: DeepScanPass[];
  mergedScanIds: string[];
  noNewStreak: number;
  consecutiveErrors: number;
  mergeFailures?: number;
  /** Set before the first paid merge request; deterministic grouping stays free. */
  mergeStarted?: true;
  /** Final total captured after all work drains, before artifact sealing. */
  finalCost?: ScanCost | null;
  /** Prior session accounting was lost; later sessions cannot reconstruct its cost. */
  costUnavailable?: true;
  /** A stop decision awaiting durable retirement of interrupted children. */
  pendingStop?: {
    reason: "capped" | "failed" | "canceled";
    message: string;
    costs: Record<string, ScanCost>;
  };
  /** A discovery stop decision. Sealing and publication belong to the parent. */
  terminalReason?: "saturated" | "capped" | "failed" | "canceled";
  [extension: string]: unknown;
}

/** Version 3 stores aggregates separately from polling metadata. */
export interface DeepScanCheckpoint extends CompositionMetadata {
  aggregate: (ScanAggregate & { coverage: SemanticCoverage }) | null;
}

/** Resume metadata omits finding and coverage payloads. */
export interface DeepScanCheckpointSummary extends CompositionMetadata {
  aggregate?: never;
}

export function newDeepScanCheckpoint(startedAt: string): DeepScanCheckpoint {
  return {
    version: 3,
    startedAt,
    passes: [],
    mergedScanIds: [],
    aggregate: null,
    noNewStreak: 0,
    consecutiveErrors: 0,
  };
}

/** The local workbench owns this document. */
export function decodeDeepScanCheckpoint(value: unknown): DeepScanCheckpoint {
  const checkpoint = value as DeepScanCheckpoint;
  requireCheckpointVersion(checkpoint);
  return checkpoint;
}

function requireCheckpointVersion(checkpoint: { version: unknown }): void {
  if (checkpoint.version !== 3)
    throw new Error(
      "Unsupported saved Deep Scan checkpoint; use its original version or start a new scan.",
    );
}

export function compositionCheckpointFromWorkbench(
  response: Record<string, unknown>,
): DeepScanCheckpointSummary | null {
  const checkpoint = response["compositionCheckpoint"] as
    DeepScanCheckpointSummary | null | undefined;
  if (checkpoint == null) return null;
  return checkpoint;
}

/** Read checkpoint metadata without loading aggregate findings or evidence. */
export async function loadDeepScanCheckpointSummary(
  scanDir: string,
): Promise<DeepScanCheckpointSummary | null> {
  try {
    return JSON.parse(
      (
        await readScanFile(
          scanDir,
          DEEP_SCAN_CHECKPOINT,
          "Deep Scan checkpoint",
        )
      ).toString("utf8"),
    ) as DeepScanCheckpointSummary;
  } catch (error) {
    // Only an absent checkpoint starts a new composition. Preserve read/parse
    // errors, including the artifact reader's existing path protections.
    const cause =
      error instanceof Error
        ? (error.cause as
            (NodeJS.ErrnoException & { path?: string }) | undefined)
        : undefined;
    if (cause?.code === "ENOENT" && cause.path !== resolve(scanDir))
      return null;
    throw error;
  }
}

export async function loadDeepScanCheckpoint(
  scanDir: string,
): Promise<DeepScanCheckpoint | null> {
  const saved = await loadDeepScanCheckpointSummary(scanDir);
  if (saved === null) return null;
  const checkpoint = decodeDeepScanCheckpoint(saved);
  if (typeof checkpoint["aggregatePath"] === "string") {
    checkpoint.aggregate = await hydrateScanAggregate(
      scanDir,
      JSON.parse(
        (
          await readScanFile(
            scanDir,
            checkpoint["aggregatePath"],
            "Deep Scan aggregate",
          )
        ).toString("utf8"),
      ),
    );
  } else {
    checkpoint.aggregate = null;
  }
  return checkpoint;
}

/** Save a finalized total without reading the aggregate or its source evidence. */
export async function finalizeDeepScanCost(
  scanDir: string,
  writer: ScanArtifactRestorer,
  finalCost: ScanCost | null,
): Promise<void> {
  const checkpoint = JSON.parse(
    (
      await readScanFile(scanDir, DEEP_SCAN_CHECKPOINT, "Deep Scan checkpoint")
    ).toString("utf8"),
  ) as DeepScanCheckpointSummary;
  requireCheckpointVersion(checkpoint);
  await writer.restore(
    DEEP_SCAN_CHECKPOINT,
    Buffer.from(JSON.stringify({ ...checkpoint, finalCost })),
  );
}
