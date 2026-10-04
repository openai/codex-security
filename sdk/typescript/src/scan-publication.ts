import {
  prepareSemanticScanDraft,
  type SemanticScan,
} from "./scan-semantics.js";
import { relative, sep } from "node:path";
import { createHash } from "node:crypto";
import { readThreatModelPath } from "./artifact-export.js";
import type { ScanArtifactRestorer } from "./runtime.js";
import {
  loadContract,
  readScanFile,
  requireScanFile,
  type ScanExpectation,
} from "./contract.js";
import { IncompleteScanError, OutputDirectoryError } from "./errors.js";
import { ScanResult, type TurnResultMetadata } from "./result.js";
import { scanCostUsage, ScanCostTracker, type ScanCost } from "./cost.js";
import { tokenUsage } from "./cost-model.js";
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
  pythonPath?: string;
  protectedRoot?: string;
  expectation: ScanExpectation;
  signal: AbortSignal;
}

export interface ScanPublicationContext extends ScanResultContext {
  scanId: string;
  workbench: (args: readonly string[], input?: string) => Promise<JsonObject>;
}

/** This is only a read-path hint; the workbench still validates the complete seal and binding. */
export async function hasSealedScanArtifacts(
  scanDir: string,
  signal?: AbortSignal,
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

/** Read finalized receipts without authenticating or creating a model session. */
export async function readSealedScanTurn(
  context: Omit<ScanPublicationContext, "pluginRoot"> & {
    codexHome: string;
    model: string;
    startedAt: unknown;
    checkpoint: DeepScanCheckpointSummary | null;
    maxCostUsd?: number;
    requireCost?: boolean;
    onTrackingError(error: unknown): void;
    onCost(cost: Readonly<ScanCost>): void;
  },
): Promise<
  CompletedScanTurn & { cost: ScanCost | null; resumeThreadId: string | null }
> {
  const { scanId, scanDir, model, codexHome, workbench, signal } = context;
  const saved = await workbench(["get-scan", "--scan-id", scanId]);
  const record = saved["scan"] as SavedScanRecord;
  const threadId = record.continuationThreadId ?? null;
  let cost =
    record.progress.status === "complete"
      ? (record.cost ?? null)
      : (context.checkpoint?.finalCost ?? null);
  const savedUsage = record["usage"];
  let usage: unknown =
    record.progress.status === "complete" &&
    isRecord(savedUsage) &&
    savedUsage["coverage"] === "complete"
      ? tokenUsage({
          input_tokens: savedUsage["inputTokens"],
          cached_input_tokens: savedUsage["cachedInputTokens"],
          cache_write_input_tokens: savedUsage["cacheWriteInputTokens"],
          cache_write_input_tokens_reported:
            cost === null ? false : cost.cacheWriteInputTokensReported,
          output_tokens: savedUsage["outputTokens"],
          reasoning_output_tokens: savedUsage["reasoningOutputTokens"],
        })
      : null;
  if (
    record.progress.status !== "complete" &&
    context.expectation.mode !== "deep" &&
    threadId !== null
  ) {
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
    // Native owner sessions may contain earlier conversation work, even in this directory.
    if (
      session?.workingDirectory === scanDir &&
      session.startedAt !== null &&
      Number.isFinite(startedAt) &&
      session.startedAt >= startedAt
    ) {
      const tracker = new ScanCostTracker({
        codexHome,
        includeArchivedSessions: true,
        model,
        repository: context.expectation.repository,
        scanDirectory: scanDir,
      });
      tracker.start(threadId);
      const snapshot = await tracker.stop().catch((error: unknown) => {
        context.onTrackingError(error);
        return null;
      });
      if (snapshot !== null && cost === null) usage = snapshot.usage;
      if (
        snapshot?.cost &&
        (cost === null || snapshot.cost.estimatedUsd > cost.estimatedUsd)
      ) {
        cost = snapshot.cost;
        usage = snapshot.usage;
      }
    }
  }
  throwIfAborted(signal, scanDir);
  if (
    (context.maxCostUsd !== undefined || context.requireCost) &&
    cost === null
  )
    throw new ScanCostTrackingError(
      "The sealed scan has no verified cost receipt. Older Deep Scans require their original version for cost recovery.",
      scanDir,
    );
  if (cost !== null) context.onCost(cost);
  return {
    cost,
    threadId,
    resumeThreadId: threadId,
    turnResult: {
      status: "completed",
      model,
      usage: usage ?? (cost === null ? null : scanCostUsage(cost)),
    },
  };
}

/** Seal and load the same contract for ordinary, composed and already-sealed scans. */
export async function publishScan(
  context: ScanPublicationContext,
  turn: CompletedScanTurn,
  cost: ScanCost | null,
  sealed = false,
): Promise<{
  result: ScanResult;
  warnings: { message: string; targetChanged: boolean }[];
}> {
  const { scanId, scanDir, expectation, signal, workbench } = context;
  let preparation: JsonObject = {};
  if (!sealed) {
    try {
      // Ordinary SDK turns author canonical files after their last MCP checkpoint.
      // Commit those final documents before completion reads the saved draft.
      if (expectation.mode !== "deep") {
        const contents = new Map<string, Buffer>();
        const read = async (name: string) => {
          const bytes = await readScanFile(scanDir, name, name, signal);
          contents.set(name, bytes);
          return JSON.parse(bytes.toString("utf8"));
        };
        const committed = await read("artifacts/scan-draft.json").catch(
          (error: unknown) => {
            if (
              error instanceof Error &&
              isRecord(error.cause) &&
              error.cause["code"] === "ENOENT"
            )
              return null;
            throw error;
          },
        );
        const manifest = await read("scan-manifest.json").catch(
          (error: unknown) => {
            if (
              committed !== null &&
              error instanceof Error &&
              isRecord(error.cause) &&
              error.cause["code"] === "ENOENT"
            )
              return null;
            throw error;
          },
        );
        if (manifest !== null && manifest.scan?.sealedAt == null) {
          for (const name of ["findings.json", "coverage.json"]) {
            try {
              contents.set(
                name,
                await readScanFile(scanDir, name, name, signal),
              );
            } catch (error) {
              if (
                committed !== null &&
                error instanceof Error &&
                isRecord(error.cause) &&
                error.cause["code"] === "ENOENT"
              )
                continue;
              throw error;
            }
          }
          const exportState = committed?.canonicalExport;
          // Every old/new document mixture is an interrupted export. Any other
          // bytes are a later authored result, including a changed timestamp or
          // findings/coverage written without changing the manifest.
          const unchangedExport = exportState
            ? ["scan-manifest.json", "findings.json", "coverage.json"].every(
                (name) => {
                  const bytes = contents.get(name);
                  if (bytes === undefined) return true;
                  const digest = createHash("sha256")
                    .update(bytes)
                    .digest("hex");
                  return (
                    digest === exportState.current?.[name] ||
                    digest === exportState.previous?.[name]
                  );
                },
              )
            : committed !== null &&
              manifest.scan?.completedAt !==
                committed.manifest?.scan?.completedAt;
          if (
            !unchangedExport &&
            contents.has("findings.json") &&
            contents.has("coverage.json")
          )
            await writePreparedScanDraft(workbench, scanId, {
              manifest,
              findings: JSON.parse(
                contents.get("findings.json")!.toString("utf8"),
              ),
              coverage: JSON.parse(
                contents.get("coverage.json")!.toString("utf8"),
              ),
            });
        }
      }
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
  const result = await collectResult(context, turn, true, cost);
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
  const scan = completion["scan"] as SavedScanRecord;
  const result = await collectResult(context, turn, true, scan.cost ?? null);
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
  cost?: Readonly<ScanCost> | null,
): Promise<ScanResult> {
  const {
    scanDir,
    pluginRoot,
    pythonPath,
    protectedRoot,
    expectation,
    signal,
  } = context;
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
    cost,
    sarifPath,
    threatModelPath: await readThreatModelPath(scanDir, {
      pluginRoot,
      pythonPath,
      protectedRoot,
      signal,
    }),
  });
}

/** Let the workbench own the committed snapshot and canonical documents. */
export async function writePreparedScanDraft(
  workbench: (args: readonly string[], input?: string) => Promise<unknown>,
  scanId: string,
  documents: { manifest: unknown; findings: unknown; coverage: unknown },
  checkpoint?: SemanticScan,
): Promise<void> {
  await workbench(
    ["write-scan-draft", "--scan-id", scanId],
    JSON.stringify({ documents, checkpoint }),
  );
}

/** Publish documents and their semantic checkpoint through one checked operation. */
export async function writeSemanticScanDraft(
  options: {
    contract: Parameters<typeof prepareSemanticScanDraft>[0];
    workbench: (args: readonly string[], input?: string) => Promise<unknown>;
  },
  draft: SemanticScan,
): Promise<void> {
  await writePreparedScanDraft(
    options.workbench,
    draft.scanId,
    prepareSemanticScanDraft(options.contract, draft),
    draft,
  );
}

/** Optional post-scan work may fail, but cannot replace the completed artifacts. */
export async function preservePublishedArtifacts(
  context: {
    result: ScanResult;
    onRestoreFailure?: (error: OutputDirectoryError) => void;
    pluginRoot: string;
    pythonPath?: string;
    protectedRoot?: string;
    expectation: ScanExpectation;
    signal: AbortSignal;
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
        ...(result.threatModelPath === null
          ? []
          : [relative(scanDir, result.threatModelPath).split(sep).join("/")]),
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
          context.onRestoreFailure?.(failure);
          throw failure;
        }
      }
    }
    if (signal.aborted) throw error;
    await collectResult({ ...context, scanDir }, result, true);
    return { error };
  }
}
