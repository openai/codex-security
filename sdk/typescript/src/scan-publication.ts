import { relative, sep } from "node:path";
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
import type { ScanCost } from "./cost.js";
import type { JsonObject } from "./config.js";

export interface CompletedScanTurn {
  threadId: string;
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
  workbench: (args: readonly string[]) => Promise<JsonObject>;
}

/** Seal, validate and record the completed scan. */
export async function publishScan(
  context: ScanPublicationContext,
  turn: CompletedScanTurn,
  cost: ScanCost | null,
  sealed = false,
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
    sarifPath,
    threatModelPath: await readThreatModelPath(scanDir, {
      pluginRoot,
      pythonPath,
      protectedRoot,
      signal,
    }),
  });
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
