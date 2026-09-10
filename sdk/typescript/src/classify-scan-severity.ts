import { randomUUID } from "node:crypto";
import { rename, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import {
  classifySeverityInternal,
  reportSeverityProgress,
  SeverityClassificationError,
  validateSeverityClassification,
  type ClassifySeverityOptions,
  type SeverityClassification,
  type SeverityClassificationProgress,
} from "./classify-severity.js";
import { loadContractWithScanDirectory } from "./contract.js";
import { CodexSecurityError, safeErrorMessage } from "./errors.js";
import type { Finding } from "./models.js";
import {
  bundledPluginRoot,
  codexSecurityStateDirectory,
  resolvePluginPython,
  runWorkbench,
} from "./runtime.js";
import {
  resolveCompletedScan,
  type SavedScanDependencies,
} from "./saved-scan.js";
import { SeverityStore } from "./severity-store.js";

const CLASSIFICATION_FILE = "severity-classification.json";
export interface ScanSeverityClassification extends SeverityClassification {
  scanId: string;
}

export interface ClassifyScanSeverityOptions extends ClassifySeverityOptions {
  /** Exact selection, such as dedupe's uniqueFindingIds. Omit to classify all findings. */
  findingIds?: readonly string[];
  /** Reclassify selected findings even when their saved assessment matches the inputs. */
  reprocess?: boolean;
  expectedScanId?: string;
}

/** Resolve a saved scan ID, unique prefix, or latest and save its classification. */
export async function classifyScanSeverity(
  scanId: string,
  options: ClassifyScanSeverityOptions = {},
): Promise<ScanSeverityClassification> {
  return classifyScanSeverityInternal(scanId, options);
}

/** @internal */
export async function classifyScanSeverityInternal(
  scanId: string,
  options: ClassifyScanSeverityOptions = {},
  dependencies: Partial<SavedScanDependencies> = {},
  surface: "sdk" | "cli" = "sdk",
): Promise<ScanSeverityClassification> {
  options.signal?.throwIfAborted();
  const environment = options.environment ?? process.env;
  const pluginRoot = await bundledPluginRoot();
  const scan = await resolveCompletedScan(scanId, {
    currentDirectory: dependencies.currentDirectory ?? (() => process.cwd()),
    runWorkbench:
      dependencies.runWorkbench ??
      (async (args) => {
        const stateEnvironment = {
          ...environment,
          CODEX_SECURITY_STATE_DIR: codexSecurityStateDirectory(environment),
        };
        return runWorkbench(
          {
            environment: stateEnvironment,
            pluginRoot,
            python: await resolvePluginPython({
              environment: stateEnvironment,
            }),
            signal: options.signal,
            failureMessage: "Could not read Codex Security scan history",
          },
          args,
        );
      }),
  });
  if (
    options.expectedScanId !== undefined &&
    options.expectedScanId !== scan.scanId
  ) {
    throw new CodexSecurityError("Saved scan does not match expectedScanId.");
  }
  return classifyScanDirectorySeverityInternal(
    scan.scanDir,
    { ...options, expectedScanId: scan.scanId },
    surface,
  );
}

/** Classify a sealed scan directory and save a separate assessment without changing its artifacts. */
export async function classifyScanDirectorySeverity(
  scanDirectory: string,
  options: ClassifyScanSeverityOptions = {},
): Promise<ScanSeverityClassification> {
  return classifyScanDirectorySeverityInternal(scanDirectory, options);
}

/** @internal */
export async function classifyScanDirectorySeverityInternal(
  requestedDirectory: string,
  options: ClassifyScanSeverityOptions = {},
  surface: "sdk" | "cli" = "sdk",
): Promise<ScanSeverityClassification> {
  const { contract, scanDirectory } = await loadContractWithScanDirectory(
    requestedDirectory,
    {
      pluginRoot: await bundledPluginRoot(),
      expectedScanId: options.expectedScanId,
      signal: options.signal,
    },
  );
  const findings = selectClassificationFindings(
    contract.findings.findings,
    options.findingIds,
  );
  const store = new SeverityStore(
    options.environment ?? process.env,
    scanDirectory,
    options.signal,
  );
  const scanId = contract.manifest.scan.id;
  let registeredScan = false;
  const retryArguments = [
    ...(options.rubricPath === undefined
      ? []
      : [
          "--rubric",
          resolve(
            options.workingDirectory ?? process.cwd(),
            options.rubricPath,
          ),
        ]),
    ...(options.knowledgeBasePaths ?? []).flatMap((path) => [
      "--knowledge-base",
      resolve(options.workingDirectory ?? process.cwd(), path),
    ]),
    ...(options.findingIds ?? []).flatMap((id) => ["--finding-id", id]),
    ...(options.model === undefined ? [] : ["--model", options.model]),
    ...(options.reasoningEffort === undefined
      ? []
      : ["--effort", options.reasoningEffort]),
  ];
  let progress: SeverityClassificationProgress = {
    status: "running",
    phase: "classification",
    total: findings.length,
    completed: 0,
    reused: 0,
    remaining: findings.length,
    scanId,
    scanDirectory,
    runId: store.runId,
  };
  const bindProgress = (
    update: SeverityClassificationProgress,
  ): SeverityClassificationProgress => ({
    ...update,
    scanId,
    scanDirectory,
    runId: store.runId,
    ...(surface === "cli"
      ? {
          retryArguments: [
            "classify-severity",
            ...(registeredScan
              ? ["--scan", scanId]
              : ["--scan-dir", scanDirectory]),
            ...retryArguments,
            ...(options.reprocess && update.phase === "classification"
              ? ["--reprocess"]
              : []),
          ],
        }
      : {}),
  });
  const report = async (
    update: SeverityClassificationProgress,
    checkpointed = false,
  ): Promise<void> => {
    const newlyReused = update.reused - progress.reused;
    const cachedOnly =
      newlyReused > 0 &&
      update.completed - progress.completed === newlyReused &&
      update.status === progress.status &&
      update.phase === progress.phase;
    const noModelStart =
      options.rubricPath === undefined &&
      update.findingId !== undefined &&
      update.completed === progress.completed &&
      update.status === "running" &&
      update.phase === "classification";
    progress = bindProgress(update);
    if (!cachedOnly && !checkpointed && !noModelStart)
      await store
        .progress(scanId, progress, registeredScan)
        .catch(() => undefined);
    reportSeverityProgress(options.onProgress, progress);
  };
  const checkpoint = store.checkpoint(
    scanId,
    findings.map(({ findingId }) => findingId),
    options.reprocess ?? false,
    (update) => ({ progress: bindProgress(update), registeredScan }),
  );
  checkpoint.progress = async (update, checkpointed) =>
    report(
      update.status === "completed"
        ? { ...update, status: "running", phase: "export" }
        : update.status === "canceled" && update.remaining === 0
          ? {
              ...update,
              phase: "export",
              ...(update.failure
                ? { failure: { ...update.failure, stage: "export" } }
                : {}),
            }
          : update,
      checkpointed,
    );
  const temporary = join(
    scanDirectory,
    `.severity-classification-${randomUUID()}.json`,
  );
  try {
    registeredScan = await store.isRegisteredScan(scanId);
    const result: ScanSeverityClassification = {
      ...(await classifySeverityInternal(
        findings,
        { ...options, onProgress: undefined },
        surface,
        checkpoint,
      )),
      scanId,
    };
    options.signal?.throwIfAborted();
    await writeFile(temporary, `${JSON.stringify(result, null, 2)}\n`, {
      flag: "wx",
      mode: 0o600,
      signal: options.signal,
    });
    options.signal?.throwIfAborted();
    await rename(temporary, join(scanDirectory, CLASSIFICATION_FILE));
    await report({ ...progress, status: "completed" });
    return result;
  } catch (error) {
    if (error instanceof SeverityClassificationError) {
      throw new SeverityClassificationError(progress, error.cause);
    }
    await report({
      ...progress,
      status: options.signal?.aborted ? "canceled" : "failed",
      failure: {
        stage: progress.phase === "export" ? "export" : "preparation",
        message: safeErrorMessage(error),
      },
    });
    throw new SeverityClassificationError(progress, error);
  } finally {
    await rm(temporary, { force: true });
  }
}

/** @internal */
export function selectClassificationFindings(
  findings: readonly Finding[],
  findingIds?: readonly string[],
): readonly Finding[] {
  if (findingIds === undefined) return findings;
  const selected = new Set(findingIds);
  const result = findings.filter((finding) => selected.has(finding.findingId));
  if (result.length !== selected.size) {
    throw new CodexSecurityError(
      "Selected finding IDs must belong to the supplied scan.",
    );
  }
  return result;
}

/** @internal */
export async function readScanSeverityClassification(
  scanDirectory: string,
  scanId: string,
  findings: readonly Finding[],
  signal?: AbortSignal,
  environment: NodeJS.ProcessEnv = process.env,
): Promise<SeverityClassification | undefined> {
  const classification = await new SeverityStore(
    environment,
    scanDirectory,
    signal,
  ).read(scanId);
  return classification === undefined
    ? undefined
    : validateSeverityClassification(classification, findings);
}
