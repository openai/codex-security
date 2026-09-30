import { lstat } from "node:fs/promises";
import { join } from "node:path";
import type { ScanArtifactRestorer } from "./runtime.js";
import { ScanAccounting } from "./scan-accounting.js";
import {
  loadContract,
  readScanFile,
  requireScanFile,
  type ScanExpectation,
} from "./contract.js";
import {
  CodexSecurityError,
  IncompleteScanError,
  OutputDirectoryError,
} from "./errors.js";
import { ScanPermissionError } from "./scan-execution.js";
import { ScanResult, type TurnResultMetadata } from "./result.js";
import { scanCostUsage, ScanCostTracker, type ScanCost } from "./cost.js";
import { ScanCostTrackingError } from "./deep-scan.js";
import { type DeepScanCheckpointSummary } from "./deep-scan-checkpoint.js";
import type { SavedScanRecord } from "./workbench-types.js";
import { throwIfAborted } from "./scan-events.js";
import type { JsonObject } from "./config.js";
import { findScanSession } from "./scan-logs.js";

export interface CompletedScanTurn {
  threadId: string | null;
  turnResult: TurnResultMetadata;
}

interface ScanResultContext {
  scanDir: string;
  pluginRoot: string;
  expectation: ScanExpectation;
  signal: AbortSignal;
}

export interface ScanPublicationContext extends ScanResultContext {
  scanId: string;
  workbench: (args: readonly string[]) => Promise<JsonObject>;
}

/** This is only a read-path hint; the workbench still validates the complete seal and binding. */
export async function hasSealedScanArtifacts(
  scanDir: string,
  signal: AbortSignal,
): Promise<boolean> {
  let manifest: unknown;
  try {
    manifest = JSON.parse(
      (
        await readScanFile(
          scanDir,
          "scan-manifest.json",
          "scan-manifest.json",
          signal,
        )
      ).toString("utf8"),
    );
  } catch (error) {
    if (
      error instanceof Error &&
      isRecord(error.cause) &&
      error.cause["code"] === "ENOENT"
    )
      return false;
    throw error;
  }
  const scan = isRecord(manifest) ? manifest["scan"] : undefined;
  return (
    isRecord(scan) &&
    (scan["sealedAt"] != null ||
      (Array.isArray(scan["artifacts"]) && scan["artifacts"].length > 0))
  );
}

/** Missing continuation metadata does not establish zero prior work. */
export async function restorePriorScanCosts(
  costs: ScanAccounting,
  checkpoint: DeepScanCheckpointSummary | null,
  resumeThreadId: unknown,
  scanDir: string,
  maxCostUsd?: number,
): Promise<void> {
  if (checkpoint?.legacy)
    costs.record("legacy", checkpoint.legacy.cost ?? null);
  if (
    checkpoint?.costUnavailable ||
    (typeof resumeThreadId !== "string" &&
      checkpoint !== null &&
      (checkpoint.mergeStarted === true ||
        (checkpoint.mergeStarted !== false &&
          checkpoint.mergedScanIds.length > 0) ||
        // The host saves merge inputs before launching a merge. A completed
        // discovery alone can still be waiting for the rest of its batch.
        (await lstat(
          join(scanDir, "artifacts/deep-scan/merge-inputs.json"),
        ).then(
          () => true,
          (error: NodeJS.ErrnoException) => {
            if (error.code === "ENOENT") return false;
            throw error;
          },
        ))))
  ) {
    costs.record("previous-work", null);
    if (maxCostUsd !== undefined)
      throw new ScanCostTrackingError(
        "A prior scan session is unavailable; its cost limit cannot be verified.",
        scanDir,
      );
  }
}

/** Recover publication accounting from saved records and logs without creating a model session. */
export async function readSealedScanTurn(
  context: Omit<ScanPublicationContext, "pluginRoot"> & {
    codexHome: string;
    model: string;
    startedAt: unknown;
    checkpoint: DeepScanCheckpointSummary | null;
    maxCostUsd?: number;
    onTrackingError(error: unknown): void;
    onCost(cost: Readonly<ScanCost>): void;
  },
): Promise<
  CompletedScanTurn & { cost: ScanCost | null; resumeThreadId: string | null }
> {
  const { scanId, scanDir, expectation, model, codexHome, workbench, signal } =
    context;
  const mode = expectation.mode;
  const costs = new ScanAccounting();
  const measure = async (threadId: string | null, directory: string) => {
    const tracker = new ScanCostTracker({
      codexHome,
      model,
      repository: expectation.repository,
      scanDirectory: directory,
    });
    if (threadId !== null) tracker.start(threadId);
    const snapshot = await tracker.stop().catch((error: unknown) => {
      context.onTrackingError(error);
      return { cost: null, usage: null };
    });
    throwIfAborted(signal, scanDir);
    return snapshot;
  };
  const saved = await workbench(["get-scan", "--scan-id", scanId]);
  const savedScan = saved["scan"] as SavedScanRecord;
  const checkpoint = context.checkpoint;
  let resumeThreadId = savedScan.continuationThreadId;
  const historicalCost = async (threadId: string) => {
    const session = await findScanSession(codexHome, threadId).catch(
      (error: unknown) => {
        context.onTrackingError(error);
        return null;
      },
    );
    const startedAt =
      typeof context.startedAt === "string"
        ? Date.parse(context.startedAt)
        : NaN;
    // Native owners can include earlier conversation work, even from this directory.
    if (
      session?.workingDirectory !== scanDir ||
      session.startedAt === null ||
      !Number.isFinite(startedAt) ||
      session.startedAt < startedAt
    )
      return null;
    return (await measure(threadId, scanDir)).cost;
  };
  await restorePriorScanCosts(
    costs,
    checkpoint,
    resumeThreadId,
    scanDir,
    context.maxCostUsd,
  );
  // Legacy cost already includes its origin session; do not count that session again.
  const threadId =
    typeof resumeThreadId === "string"
      ? resumeThreadId
      : (checkpoint?.legacy?.originThreadId ?? null);
  const emptyComposition =
    mode === "deep" &&
    checkpoint?.terminalReason === "capped" &&
    checkpoint.mergedScanIds.length === 0 &&
    Array.isArray(savedScan["findings"]) &&
    savedScan["findings"].length === 0;
  if (
    threadId === null &&
    !emptyComposition &&
    checkpoint?.mergeStarted !== false &&
    !costs.has("previous-work")
  )
    throw new CodexSecurityError(
      "The sealed scan has no saved execution session.",
    );
  if (checkpoint?.legacy)
    costs.record(
      "legacy",
      checkpoint.legacy.cost ??
        (checkpoint.legacy.originThreadId
          ? await historicalCost(checkpoint.legacy.originThreadId)
          : null),
    );
  if (checkpoint !== null) {
    const children = await workbench([
      "list-scans",
      "--scan-root",
      join(scanDir, "artifacts/deep-scan/passes"),
    ]);
    for (const child of children["scans"] as SavedScanRecord[]) {
      if (child.parentScanId === scanId)
        costs.record(child.scanId, child.cost ?? null);
    }
  }
  let cost: ScanCost | null = null;
  if (mode === "deep" && checkpoint === null) {
    cost = (await historicalCost(threadId!)) ?? savedScan.cost ?? null;
    costs.record("legacy", cost);
    // This retired origin was measured above; it is not a composed merge session.
    resumeThreadId = null;
  }
  if (
    !costs.has("previous-work") &&
    (savedScan.progress.status === "complete" || !costs.hasUnknown)
  )
    cost ??= savedScan.cost ?? null;
  if (
    typeof resumeThreadId !== "string" &&
    (emptyComposition ||
      checkpoint?.mergeStarted === false ||
      checkpoint?.legacy)
  )
    cost ??= costs.complete;
  if (cost === null && context.maxCostUsd !== undefined && costs.hasUnknown)
    throw new ScanCostTrackingError(
      "The saved child scan cost is unavailable; its cost limit cannot be verified.",
      scanDir,
    );
  const snapshot = await measure(
    resumeThreadId ?? null,
    mode === "deep"
      ? join(scanDir, "artifacts", "deep-scan", "merge")
      : scanDir,
  );
  if (snapshot.cost !== null) costs.record("merge", snapshot.cost);
  const measuredCost = snapshot.cost === null ? null : costs.complete;
  if (measuredCost && (!cost || measuredCost.estimatedUsd > cost.estimatedUsd))
    cost = measuredCost;
  if (cost !== null) context.onCost(cost);
  throwIfAborted(signal, scanDir);
  return {
    cost,
    threadId,
    resumeThreadId: resumeThreadId ?? null,
    turnResult: {
      status: "completed",
      model,
      usage: cost
        ? scanCostUsage(cost)
        : mode === "deep"
          ? null
          : snapshot.usage,
    },
  };
}

/** Seal and load the same contract for ordinary, composed and already-sealed scans. */
export async function publishScan(
  context: ScanPublicationContext,
  turn: CompletedScanTurn,
  cost: ScanCost | null,
  sealed: boolean,
): Promise<{
  result: ScanResult;
  warnings: { message: string; targetChanged: boolean }[];
}> {
  const { scanId, workbench } = context;
  let preparation: JsonObject = {};
  if (!sealed) {
    try {
      preparation = await workbench([
        "prepare-scan-completion",
        "--scan-id",
        scanId,
      ]);
    } catch (error) {
      const saved = await workbench(["get-scan", "--scan-id", scanId]).catch(
        () => null,
      );
      const scan = isRecord(saved) ? saved["scan"] : undefined;
      const progress = isRecord(scan) ? scan["progress"] : undefined;
      const message = isRecord(scan) ? scan["failureMessage"] : undefined;
      if (
        isRecord(progress) &&
        progress["status"] === "failed" &&
        typeof message === "string" &&
        message.trim() !== ""
      ) {
        throw new IncompleteScanError(message);
      }
      throw error;
    }
  }
  const result = await collectResult(context, turn, true);
  const completion = await workbench([
    "complete-scan",
    "--scan-id",
    scanId,
    ...(cost === null ? [] : ["--cost-json", JSON.stringify(cost)]),
  ]);
  return { result, warnings: publicationWarnings(completion, preparation) };
}

/** Load a result that the workbench has already completed, without completing it again. */
export async function loadPublishedScanResult(
  context: ScanResultContext,
  turn: CompletedScanTurn,
  completion: JsonObject,
): Promise<{
  result: ScanResult;
  warnings: { message: string; targetChanged: boolean }[];
}> {
  const result = await collectResult(context, turn, true);
  return { result, warnings: publicationWarnings(completion) };
}

function publicationWarnings(
  completion: JsonObject,
  preparation: JsonObject = {},
) {
  const targetWarnings = new Set([
    ...strings(preparation["targetWarnings"]),
    ...strings(completion["targetWarnings"]),
  ]);
  const scan = completion["scan"];
  return strings(isRecord(scan) ? scan["warnings"] : undefined).map(
    (message) => ({
      message,
      targetChanged: targetWarnings.has(message),
    }),
  );
}

function strings(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export async function collectResult(
  context: ScanResultContext,
  turn: CompletedScanTurn,
  workbenchValidated = false,
): Promise<ScanResult> {
  const { scanDir, pluginRoot, expectation, signal } = context;
  const { threadId, turnResult } = turn;
  const required = [
    "scan-manifest.json",
    "findings.json",
    "coverage.json",
    "report.md",
  ];
  const missing: string[] = [];
  for (const name of required) {
    try {
      await requireScanFile(scanDir, name, name, signal);
    } catch (error) {
      if (signal.aborted) throw signal.reason ?? error;
      missing.push(name);
    }
  }
  if (missing.length > 0) {
    throw new IncompleteScanError(
      `Codex Security scan completed without required artifacts: ${missing.join(", ")}`,
    );
  }
  const { manifest, findings, coverage } = await loadContract(scanDir, {
    pluginRoot,
    expectation,
    workbenchValidated,
    signal,
  });
  let sarifPath: string | null = null;
  try {
    sarifPath = await requireScanFile(
      scanDir,
      "exports/results.sarif",
      "exports/results.sarif",
      signal,
    );
  } catch (error) {
    if (signal.aborted) throw signal.reason ?? error;
  }
  return new ScanResult({
    manifest,
    findings,
    coverage,
    scanDir,
    threadId,
    turnResult,
    sarifPath,
  });
}

export {
  writeSemanticScanDraft,
  writePreparedScanDraft,
} from "./scan-draft-publication.js";

/** Optional post-scan work may fail, but cannot replace the completed artifacts. */
export async function preservePublishedArtifacts(
  context: {
    result: ScanResult;
    pluginRoot: string;
    expectation: ScanExpectation;
    signal: AbortSignal;
    onRestorationError: (error: OutputDirectoryError) => void;
  },
  prepareRestorer: () => Promise<ScanArtifactRestorer>,
  run: () => Promise<void>,
): Promise<{ error: unknown } | undefined> {
  const { result, signal } = context;
  const scanDir = result.scanDir;
  const artifacts = await Promise.all(
    [
      ...new Set([
        "scan-manifest.json",
        "findings.json",
        "coverage.json",
        "report.md",
        ...result.manifest.scan.artifacts.map((artifact) => artifact.path),
      ]),
    ].map(async (name) => ({
      name,
      contents: await readScanFile(scanDir, name, name, signal),
    })),
  );
  let restorer: ScanArtifactRestorer | null = null;
  try {
    restorer = await prepareRestorer();
    await run();
  } catch (error) {
    if (restorer !== null) {
      for (const artifact of artifacts) {
        try {
          await restorer.restore(artifact.name, artifact.contents);
        } catch (cause) {
          const failure = new OutputDirectoryError(
            "Cannot restore an artifact outside the scan directory.",
            { cause },
          );
          context.onRestorationError(failure);
          throw failure;
        }
      }
    }
    if (signal.aborted || error instanceof ScanPermissionError) throw error;
    await collectResult({ ...context, scanDir }, result, true);
    return { error };
  }
}
