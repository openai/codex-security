import { join, relative } from "node:path";
import { lstat, stat } from "node:fs/promises";
import type { BigIntStats } from "node:fs";
import { readScanFile } from "./contract.js";
import { setTimeout as delay } from "node:timers/promises";
import type { CodexSecurity, ScanOptions } from "./api.js";
import type { JsonObject } from "./config.js";
import type { ScanCost, ScanUsageMeasurement } from "./cost.js";
import type { ScanTokenUsage } from "./cost-model.js";
import {
  ScanCostLimitExceededError,
  ScanInterruptedError,
  errorMessage,
  isCodexNonRetryableFailure,
} from "./errors.js";
import type { DeepScanOptions } from "./scan-settings.js";
import {
  combineScanCoverage,
  confirmScanMerge,
  mergeExactScanFindings,
  validateScanMerge,
  unchangedScanGroups,
  unconfirmedScanGroups,
  scanMergePrompt,
  type ScanMergeInput,
} from "./scan-merge.js";
import { exceedsComparisonContext } from "./same-fix.js";
import type { ScanArtifactRestorer } from "./runtime.js";
import type { SemanticScan } from "./scan-semantics.js";
import type { ScanResult } from "./result.js";
import {
  ScanPermissionError,
  ScanTransportClosedError,
} from "./scan-execution.js";

import {
  DEEP_SCAN_CHECKPOINT,
  loadDeepScanCheckpoint,
  newDeepScanCheckpoint,
  type DeepScanCheckpoint,
} from "./deep-scan-checkpoint.js";
import {
  acceptMerge,
  discoveryStopReason,
  exhaustPassRetries,
  observePassCompletion,
  observePassFailure,
  passDirectory,
  registerPass,
  reservePass,
  stopDiscovery,
} from "./deep-scan-lifecycle.js";
import { type SavedScanRecord } from "./workbench-types.js";
export {
  DEEP_SCAN_CHECKPOINT,
  type DeepScanCheckpoint,
} from "./deep-scan-checkpoint.js";

export type DeepScanDiagnostic = Readonly<Record<string, string | number>>;

/** Every worker in one live composition uses the executable admitted for its first launch. */
export function bindDeepScanExecutable(
  path: string,
  scanDir: string,
): () => Promise<void> {
  let binding: Promise<BigIntStats> | undefined;
  const inspect = async () => {
    const file = await stat(path, { bigint: true });
    if (!file.isFile() || file.size === 0n)
      throw new Error("Codex executable is not a non-empty file.");
    return file;
  };
  return async () => {
    if (binding === undefined) {
      binding = inspect().catch((error) => {
        binding = undefined;
        throw error;
      });
      await binding;
      return;
    }
    const original = await binding;
    const current = await inspect().catch(() => null);
    if (
      !current ||
      original.dev !== current.dev ||
      original.ino !== current.ino ||
      original.mtimeNs !== current.mtimeNs ||
      original.ctimeNs !== current.ctimeNs ||
      original.size !== current.size
    ) {
      throw new DeepScanRecoveryError(
        `The Codex executable "${path}" changed after this Deep Scan started. Retry after the update finishes.`,
        scanDir,
      );
    }
  };
}

/** Required usage tracking must stop the entire composition before another pass. */
export class ScanCostTrackingError extends ScanInterruptedError {}

/** Saved input failures retain accepted work for a corrected continuation. */
export class DeepScanRecoveryError extends ScanInterruptedError {}

/** The wrapper rejected saved inputs before attempting this thread's execution. */
export class DeepScanInputRecoveryError extends DeepScanRecoveryError {
  constructor(
    message: string,
    scanDir: string,
    readonly neverStarted: boolean,
    options?: ErrorOptions,
  ) {
    super(message, scanDir, options);
  }
}

/** A terminal checkpoint rejects execution without changing saved results. */
export class TerminalDeepScanError extends ScanInterruptedError {}

export interface DeepScanComposition {
  scanId: string;
  scanDir: string;
  repository: string;
  pluginRoot: string;
  startedAt: string;
  settings: Required<DeepScanOptions>;
  scanOptions: ScanOptions;
  signal: AbortSignal;
  createClient(): Pick<CodexSecurity, "run" | "close">;
  workbench(
    args: readonly string[],
    input?: string,
    signal?: AbortSignal,
  ): Promise<JsonObject>;
  merge(
    prompt: string,
    signal: AbortSignal,
    outputSchema?: Record<string, unknown>,
  ): Promise<unknown>;
  onDiagnostic?(event: DeepScanDiagnostic): void;
  onRetry?(message: string): void;
  onCleanupError?(error: unknown): void;
  onMergeCommitted?(event: {
    scanId: string;
    sourceScanIds: string[];
    newFindings: number;
    retainedFindings: number;
  }): void;
  writer: ScanArtifactRestorer & {
    remove(relativePath: string): Promise<void>;
    reserveDirectory?(relativePath: string): Promise<boolean>;
  };
  projectChild(
    sourceScanId: string,
    sourceDirectory: string,
    signal: AbortSignal,
  ): Promise<ScanMergeInput>;
  publish(draft: SemanticScan): Promise<void>;
  onCost(key: string, cost: Readonly<ScanCost> | null): void;
  onUsage?(key: string, usage: Readonly<ScanTokenUsage>): void;
  onMeasurement?(
    key: string,
    measurement: Readonly<ScanUsageMeasurement>,
  ): void;
  historicalCost?(
    threadId: string,
    scanDirectory?: string,
    usageOnly?: boolean,
  ): Promise<ScanCost | null>;
  restoreMergeCost?(): Promise<void>;
  costUnavailable?: boolean;
}

function validatePassDirectories(state: DeepScanCheckpoint): number {
  const directories = new Set<string>();
  let maximum = 0;
  for (const pass of state.passes) {
    const number = Number(pass.directory.split("pass-").at(-1));
    if (
      !Number.isSafeInteger(number) ||
      number < 1 ||
      pass.directory !== passDirectory(number - 1) ||
      directories.has(pass.directory)
    )
      throw new Error("Saved scan pass escaped its parent.");
    directories.add(pass.directory);
    maximum = Math.max(maximum, number);
  }
  return maximum;
}

function savedPassIndex(
  input: Pick<DeepScanComposition, "scanId" | "scanDir" | "repository">,
  state: DeepScanCheckpoint,
  record: SavedScanRecord,
): number {
  const index = state.passes.findIndex(
    (pass) =>
      relative(join(input.scanDir, pass.directory), record.scanDir) === "",
  );
  if (index < 0) return index;
  if (
    record.parentScanId !== input.scanId ||
    record.targetPath !== input.repository
  )
    throw new Error("Saved scan pass belongs to another parent or target.");
  const pass = state.passes[index]!;
  if (pass.scanId !== undefined && pass.scanId !== record.scanId)
    throw new Error("Saved scan pass registration changed.");
  return index;
}

function missingRunningSession(record: SavedScanRecord): boolean {
  return record.progress.status === "running" && !record.continuationThreadId;
}

/** Reject stopped discovery without writes, worker startup or cost notifications. */
export async function terminalDeepScanError(
  input: Pick<DeepScanComposition, "scanDir">,
  checkpoint?: DeepScanCheckpoint,
): Promise<TerminalDeepScanError | null> {
  const state = checkpoint ?? (await loadDeepScanCheckpoint(input.scanDir));
  if (
    state?.version !== 2 ||
    (state.terminalReason !== "failed" && state.terminalReason !== "canceled")
  )
    return null;
  return new TerminalDeepScanError(
    `The saved Deep Scan is ${state.terminalReason}; its retained results remain available.`,
    input.scanDir,
  );
}

/** Compose complete ordinary scans; only accepted merge state belongs to the parent. */
export async function runDeepScans(
  input: DeepScanComposition,
): Promise<DeepScanCheckpoint> {
  const { scanId, scanDir, settings, signal, workbench } = input;
  const state =
    (await loadDeepScanCheckpoint(scanDir)) ??
    newDeepScanCheckpoint(input.startedAt);
  if (state.legacy)
    throw new Error(
      "Saved legacy Deep Scans cannot be resumed; their reports remain available.",
    );
  if (input.costUnavailable) state.costUnavailable = true;
  const terminal = await terminalDeepScanError(input, state);
  if (terminal !== null) throw terminal;
  let lastDirectory = validatePassDirectories(state);
  const diagnostic = (event: DeepScanDiagnostic) => {
    try {
      void Promise.resolve(input.onDiagnostic?.(event)).catch(() => {});
    } catch {
      // An optional observer cannot interrupt retained scan work.
    }
  };
  diagnostic({ event: "coordinator_started", scanId });
  if (state.discoveryUserContext === undefined)
    state.discoveryUserContext = input.scanOptions.scanPrompt ?? null;
  let saveTail = Promise.resolve();
  let savedSnapshot: string | undefined;
  let queuedSave: { snapshot: string; pending: Promise<void> } | undefined;
  const save = async (): Promise<void> => {
    const snapshot = JSON.stringify(state);
    // A newer complete snapshot includes the changes of every queued caller.
    // All callers share its durability barrier; an in-flight write is unchanged.
    if (queuedSave) {
      queuedSave.snapshot = snapshot;
      return queuedSave.pending;
    }
    const queued = { snapshot, pending: Promise.resolve() };
    queued.pending = saveTail.then(async () => {
      queuedSave = undefined;
      const snapshot = queued.snapshot;
      // Reuse only a successful write, after all earlier saves have settled.
      if (snapshot === savedSnapshot) return;
      savedSnapshot = undefined;
      await workbench(
        [
          "save-scan-artifact",
          "--scan-id",
          scanId,
          "--artifact-path",
          DEEP_SCAN_CHECKPOINT,
        ],
        snapshot,
      );
      savedSnapshot = snapshot;
    });
    queuedSave = queued;
    saveTail = queued.pending.catch(() => undefined);
    return queued.pending;
  };
  await save();
  const completed = new Map<string, ScanMergeInput>();
  const saved = new Map<string, SavedScanRecord>();
  const coverage = new Map<string, SemanticScan["reviewState"]>();
  const updateAggregateCoverage = (): void => {
    if (state.aggregate === null) return;
    const merged = new Set(state.mergedScanIds);
    state.aggregate = {
      ...state.aggregate,
      reviewState: combineScanCoverage(
        [...coverage].filter(([id]) => merged.has(id)).map(([, pass]) => pass),
        state.passes
          .filter((pass) => !pass.scanId || !merged.has(pass.scanId))
          .map((pass) => pass.directory),
        state.mergedScanIds.some((id) => !coverage.has(id))
          ? state.aggregate.reviewState
          : undefined,
      ),
    };
  };
  const reportPassCost = (key: string, cost: Readonly<ScanCost> | null) => {
    input.onCost(key, cost);
    if (cost === null && input.scanOptions.requireCost)
      throw new ScanCostTrackingError(
        "The child scan cost is unavailable; its cost limit cannot be verified.",
        scanDir,
      );
  };
  const refreshPasses = async (
    recoverOutcomes = false,
    restoreMergeCost?: () => Promise<void>,
  ): Promise<void> => {
    const listed = await workbench([
      "list-scans",
      "--scan-root",
      join(scanDir, "artifacts/deep-scan/passes"),
    ]);
    const records = listed["scans"] as SavedScanRecord[];
    if (recoverOutcomes)
      records.sort((a, b) =>
        (a.completedAt ?? "").localeCompare(b.completedAt ?? ""),
      );
    const passes = records.flatMap((record) => {
      const index = savedPassIndex(input, state, record);
      if (index < 0) return [];
      const pass = state.passes[index]!;
      registerPass(pass, record.scanId);
      saved.set(record.scanId, record);
      return [{ record, pass }];
    });
    const costs = new Map<string, Readonly<ScanCost> | null>();
    for (const { record, pass } of passes) {
      const missingSession = missingRunningSession(record);
      if (pass.executionNotStarted === true) {
        if (missingSession) continue;
        delete pass.executionNotStarted;
      }
      if (missingSession) state.costUnavailable = true;
      costs.set(pass.directory, missingSession ? null : (record.cost ?? null));
      input.onCost(pass.directory, null);
    }
    // Recover every receipt before budget callbacks can abort another recovery.
    for (const { record, pass } of passes) {
      if (record.progress.status === "running" && record.continuationThreadId) {
        costs.set(
          pass.directory,
          (await input.historicalCost?.(
            record.continuationThreadId,
            record.scanDir,
          )) ?? null,
        );
      } else if (
        (input.onUsage !== undefined ||
          input.onMeasurement !== undefined ||
          input.scanOptions.onWorkerEvent !== undefined) &&
        record.continuationThreadId &&
        record.progress.status === "complete"
      ) {
        await input.historicalCost?.(
          record.continuationThreadId,
          record.scanDir,
          true,
        );
      }
    }
    if (state.costUnavailable) await save();
    // Merge polling may stop the budget; every child receipt must be ready first.
    await restoreMergeCost?.();
    for (const [directory, cost] of costs)
      if (cost !== null) reportPassCost(directory, cost);
    if (state.costUnavailable) reportPassCost("previous-work", null);
    for (const [directory, cost] of costs)
      if (cost === null) reportPassCost(directory, cost);
    let recoveredSuccess = false;
    let recoveredFailure = false;
    let reachedErrorLimit = false;
    for (const { record, pass } of passes) {
      if (recoverOutcomes && record.progress.status === "failed") {
        recoveredFailure ||= !pass.failed;
        if (!reachedErrorLimit) {
          observePassFailure(state, pass, recoveredSuccess);
          reachedErrorLimit =
            state.consecutiveErrors >= settings.stopAfterConsecutiveErrors;
        } else pass.failed = true;
      }
      if (
        record.progress.status === "complete" &&
        !coverage.has(record.scanId)
      ) {
        const projected = await input.projectChild(
          record.scanId,
          record.scanDir,
          signal,
        );
        coverage.set(record.scanId, projected.draft.reviewState);
        if (!state.mergedScanIds.includes(record.scanId))
          completed.set(record.scanId, projected);
        if (recoverOutcomes && !reachedErrorLimit)
          recoveredSuccess = observePassCompletion(
            state,
            pass,
            recoveredSuccess || recoveredFailure,
          );
        else pass.completed = true;
      }
    }
    await save();
  };
  const deadline =
    Date.parse(state.startedAt) + settings.maxTimeHours * 3_600_000;
  const deadlineController = new AbortController();
  let deadlineTimer: ReturnType<typeof setTimeout> | undefined;
  const tick = (): void => {
    const remaining = deadline - Date.now();
    if (remaining <= 0)
      deadlineController.abort(
        new Error("deep_scan_discovery_deadline_reached"),
      );
    else deadlineTimer = setTimeout(tick, Math.min(remaining, 2_147_483_647));
  };
  tick();
  const externalStop = new AbortController();
  const consecutiveErrorLimit = new Error(
    "Deep Scan reached its consecutive error limit.",
  );
  const executionSignal = AbortSignal.any([signal, externalStop.signal]);
  const discoverySignal = AbortSignal.any([
    executionSignal,
    deadlineController.signal,
  ]);
  let polling = false;
  const cancellationTimer = setInterval(() => {
    if (polling) return;
    polling = true;
    void workbench(["get-scan", "--scan-id", scanId])
      .then((result) => {
        const { progress } = result["scan"] as SavedScanRecord;
        if (
          progress["status"] === "canceled" ||
          progress["status"] === "failed"
        ) {
          externalStop.abort(new Error("The saved parent scan stopped."));
        }
      })
      .catch(() => undefined)
      .finally(() => {
        polling = false;
      });
  }, 1_000);
  cancellationTimer.unref();
  let stoppedDuringComparison = false;
  const commitMerge = async (
    merged: ReturnType<typeof validateScanMerge>,
    pending: ScanMergeInput[],
  ) => {
    const sourceScanIds = pending.map((result) => result.scanId);
    acceptMerge(
      state,
      merged,
      sourceScanIds,
      combineScanCoverage([...coverage.values()]),
    );
    await save();
    input.onMergeCommitted?.({
      scanId,
      sourceScanIds,
      newFindings: merged.newFindingCount,
      retainedFindings: merged.aggregate.findings.length,
    });
    for (const result of pending) completed.delete(result.scanId);
  };
  const mergePending = async (allowEmpty = false): Promise<void> => {
    if ((state.mergeFailures ?? 0) >= settings.stopAfterConsecutiveErrors)
      throw new Error("Deep Scan reached its consecutive merge error limit.");
    const pending = state.passes.flatMap((pass) => {
      const result =
        pass.scanId === undefined ? undefined : completed.get(pass.scanId);
      return result && !state.mergedScanIds.includes(result.scanId)
        ? [result]
        : [];
    });
    if (!pending.length && (!allowEmpty || state.aggregate !== null)) return;
    if (!pending.length) {
      state.aggregate = {
        ...validateScanMerge({ scanId, groups: [] }, [], null).aggregate,
        reviewState: combineScanCoverage([]),
      };
      await save();
      return;
    }
    const clean = pending.every((input) => input.draft.findings.length === 0);
    const previousMergeStarted = state.mergeStarted;
    const mergeInputsPath = "artifacts/deep-scan/merge-inputs.json";
    let previousMergeInputs: Buffer | null = null;
    if (!clean && previousMergeStarted !== true) {
      const exists = await lstat(join(scanDir, mergeInputsPath)).then(
        () => true,
        (error: NodeJS.ErrnoException) => {
          if (error.code === "ENOENT") return false;
          throw error;
        },
      );
      if (exists)
        previousMergeInputs = await readScanFile(
          scanDir,
          mergeInputsPath,
          "Deep Scan merge inputs",
        );
    }
    const prompt = clean
      ? ""
      : await scanMergePrompt(
          scanId,
          pending,
          state.aggregate,
          scanDir,
          input.writer,
        );
    if (!clean && state.mergeStarted !== true) {
      state.mergeStarted = true;
      try {
        await save();
      } catch (error) {
        throw new DeepScanRecoveryError(errorMessage(error), scanDir, {
          cause: error,
        });
      }
    }
    let merged: ReturnType<typeof validateScanMerge>;
    let validationError: unknown;
    for (;;) {
      executionSignal.throwIfAborted();
      try {
        const response = clean
          ? unchangedScanGroups(scanId, state.aggregate)
          : await input
              .merge(
                validationError === undefined
                  ? prompt
                  : `${prompt}\n\nYour previous merge response failed validation: ${errorMessage(validationError)}\nReturn a complete corrected JSON object using the same source findings and schema.`,
                executionSignal,
              )
              .catch((error) => {
                executionSignal.throwIfAborted();
                if (!exceedsComparisonContext(error)) throw error;
                input.onRetry?.(
                  "Deep Scan is comparing smaller groups after the merge exceeded the model context.",
                );
                return unconfirmedScanGroups(scanId, pending, state.aggregate);
              });
        try {
          merged = validateScanMerge(response, pending, state.aggregate);
        } catch (error) {
          validationError = error;
          throw error;
        }
        merged = await confirmScanMerge(
          merged,
          pending,
          state.aggregate,
          (prompt, schema) => input.merge(prompt, executionSignal, schema),
          (error) => {
            executionSignal.throwIfAborted();
            if (
              error instanceof DeepScanInputRecoveryError &&
              error.neverStarted
            ) {
              // The grouping turn already ran. A rejected confirmation turn cannot roll it back.
              throw new DeepScanInputRecoveryError(
                error.message,
                scanDir,
                false,
                { cause: error },
              );
            }
            if (
              error instanceof DeepScanRecoveryError ||
              error instanceof ScanTransportClosedError ||
              error instanceof ScanPermissionError ||
              isCodexNonRetryableFailure(error)
            )
              throw error;
            diagnostic({
              event: "finding_comparison_failed",
              reason: errorMessage(error),
            });
            input.onRetry?.(
              `Deep Scan kept disputed findings separate: ${errorMessage(error)}`,
            );
          },
        );
        break;
      } catch (error) {
        if (
          error instanceof DeepScanInputRecoveryError &&
          error.neverStarted &&
          previousMergeStarted !== true
        ) {
          try {
            if (previousMergeInputs === null)
              await input.writer.remove(mergeInputsPath);
            else
              await input.writer.restore(mergeInputsPath, previousMergeInputs);
            if (previousMergeStarted === undefined) delete state.mergeStarted;
            else state.mergeStarted = previousMergeStarted;
            await save();
          } catch (cause) {
            throw new DeepScanRecoveryError(errorMessage(cause), scanDir, {
              cause,
            });
          }
        }
        if (error instanceof DeepScanRecoveryError) throw error;
        if (error instanceof SyntaxError) validationError = error;
        if (error !== validationError && isCodexNonRetryableFailure(error)) {
          stoppedDuringComparison = true;
          throw error;
        }
        if (executionSignal.aborted || error instanceof ScanPermissionError)
          throw error;
        const failures = (state.mergeFailures = (state.mergeFailures ?? 0) + 1);
        await save();
        if (failures >= settings.stopAfterConsecutiveErrors) throw error;
      }
    }
    executionSignal.throwIfAborted();
    await commitMerge(merged, pending);
  };
  const runPass = async (
    pass: DeepScanCheckpoint["passes"][number],
  ): Promise<void> => {
    const provenUnstarted = pass.executionNotStarted === true;
    const newPass = pass.scanId === undefined;
    if (provenUnstarted) {
      delete pass.executionNotStarted;
      try {
        await save();
      } catch (cause) {
        throw new DeepScanRecoveryError(errorMessage(cause), scanDir, {
          cause,
        });
      }
    }
    const client = input.createClient();
    let clientInvoked = false;
    let latestCost: Readonly<ScanCost> | undefined;
    // Publication retries reuse the child already accepted by its own workbench.
    let acceptedResult: ScanResult | undefined;
    const failPass = async (error: unknown): Promise<void> => {
      if (pass.scanId === undefined || acceptedResult !== undefined) return;
      await workbench([
        "fail-scan",
        "--scan-id",
        pass.scanId,
        "--message",
        errorMessage(error),
        ...(latestCost ? ["--cost-json", JSON.stringify(latestCost)] : []),
      ]);
    };
    try {
      // These existing retry delays do not create another logical scan.
      const retries = [60_000, 180_000, 540_000];
      for (let attempt = 0; ; attempt += 1) {
        discoverySignal.throwIfAborted();
        try {
          const resuming = pass.scanId !== undefined;
          if (acceptedResult === undefined) {
            clientInvoked = true;
            diagnostic({
              event: "worker_started",
              directory: pass.directory,
              attempt: attempt + 1,
            });
          }
          acceptedResult ??= await client.run(input.repository, {
            ...input.scanOptions,
            scanPrompt: state.discoveryUserContext ?? undefined,
            mode: "standard",
            outputDir: join(scanDir, pass.directory),
            ...(resuming
              ? { resumeScanId: pass.scanId, parentScanId: undefined }
              : { parentScanId: scanId }),
            deepScanPass: true,
            signal: discoverySignal,
            onRegisteredScan: async (registration) => {
              registerPass(pass, registration["scanId"] as string);
              input.onCost(pass.directory, null);
              if (
                resuming &&
                registration["threadId"] === null &&
                !(provenUnstarted && attempt === 0)
              )
                state.costUnavailable = true;
              await save();
              if (state.costUnavailable) reportPassCost("previous-work", null);
            },
            onMeasurement:
              input.onMeasurement === undefined
                ? input.scanOptions.onMeasurement
                : (measurement) =>
                    input.onMeasurement!(pass.directory, measurement),
            onUsage:
              input.onUsage === undefined
                ? input.scanOptions.onUsage
                : (usage) => input.onUsage!(pass.directory, usage),
            onCost: (cost) => {
              latestCost = cost;
              input.onCost(pass.directory, cost);
            },
          });
          const result = acceptedResult;
          const projected = await input.projectChild(
            result.manifest.scan.id,
            result.scanDir,
            signal,
          );
          completed.set(result.manifest.scan.id, projected);
          coverage.set(result.manifest.scan.id, projected.draft.reviewState);
          reportPassCost(pass.directory, result.cost);
          executionSignal.throwIfAborted();
          observePassCompletion(state, pass);
          await save();
          return;
        } catch (error) {
          if (
            error instanceof DeepScanInputRecoveryError &&
            error.neverStarted &&
            attempt === 0 &&
            (newPass || provenUnstarted) &&
            pass.scanId !== undefined
          ) {
            pass.executionNotStarted = true;
            try {
              await save();
            } catch (cause) {
              throw new DeepScanRecoveryError(errorMessage(cause), scanDir, {
                cause,
              });
            }
          }
          if (error instanceof DeepScanRecoveryError) throw error;
          if (
            error instanceof ScanCostTrackingError ||
            error instanceof ScanPermissionError ||
            isCodexNonRetryableFailure(error)
          )
            externalStop.abort(error);
          if (discoverySignal.aborted) throw error;
          if (attempt >= retries.length) {
            if (acceptedResult !== undefined) throw error;
            await failPass(error);
            if (
              exhaustPassRetries(
                state,
                pass,
                settings.stopAfterConsecutiveErrors,
              )
            )
              externalStop.abort(consecutiveErrorLimit);
            await save();
            return;
          }
          input.onRetry?.(
            `Deep Scan pass ${state.passes.indexOf(pass) + 1} will retry: ${errorMessage(error)}`,
          );
          await delay(retries[attempt], undefined, { signal: discoverySignal });
        }
      }
    } catch (error) {
      if (error instanceof DeepScanRecoveryError) throw error;
      if (provenUnstarted && !clientInvoked && discoverySignal.aborted) {
        pass.executionNotStarted = true;
        try {
          await save();
        } catch (cause) {
          throw new DeepScanRecoveryError(errorMessage(cause), scanDir, {
            cause,
          });
        }
        throw error;
      }
      if (
        discoverySignal.aborted &&
        !(discoverySignal.reason instanceof ScanTransportClosedError)
      )
        await failPass(discoverySignal.reason).catch(() => undefined);
      throw error;
    } finally {
      try {
        await client.close();
      } catch (error) {
        input.onCleanupError?.(error);
      }
    }
  };
  try {
    await refreshPasses(
      state.terminalReason === undefined && Date.now() < deadline,
      input.restoreMergeCost,
    );
    if (state.mergedScanIds.some((id) => !coverage.has(id))) {
      throw new Error(
        "An accepted merge input is no longer a sealed child scan.",
      );
    }
    if (state.consecutiveErrors >= settings.stopAfterConsecutiveErrors)
      throw consecutiveErrorLimit;
    while (state.terminalReason === undefined) {
      executionSignal.throwIfAborted();
      const previousAggregate = state.aggregate;
      await mergePending();
      const discoveryDeadlineReached =
        deadlineController.signal.aborted || Date.now() >= deadline;
      const unfinished = state.passes.filter(
        (pass) =>
          !pass.failed &&
          (pass.scanId === undefined ||
            saved.get(pass.scanId)?.progress.status === "running"),
      );
      const stop = discoveryStopReason(state, {
        deadlineReached: discoveryDeadlineReached,
        hasUnfinishedPasses: unfinished.length > 0,
        maxDiscoveryRuns: settings.maxDiscoveryRuns,
        stopAfterNoNew: settings.stopAfterNoNew,
      });
      if (stop !== undefined) {
        if (
          stop === "capped" &&
          !discoveryDeadlineReached &&
          state.aggregate === null &&
          state.consecutiveErrors > 0
        )
          throw new Error(
            "Deep Scan stopped because every discovery run failed.",
          );
        stopDiscovery(state, stop);
        break;
      }
      if (state.aggregate !== null && state.aggregate !== previousAggregate)
        await input.publish(state.aggregate);
      if (
        state.aggregate === null &&
        !state.mergeStarted &&
        state.passes.every(
          (pass) =>
            !pass.failed &&
            !pass.completed &&
            (!pass.scanId || pass.executionNotStarted),
        )
      ) {
        try {
          await workbench(
            ["check-deep-scan-target", "--scan-id", scanId],
            undefined,
            discoverySignal,
          );
        } catch (error) {
          if (!discoverySignal.aborted) throw error;
        }
        if (discoverySignal.aborted || Date.now() >= deadline) continue;
      }
      const batch = unfinished.slice(0, settings.workers);
      while (
        batch.length < settings.workers &&
        state.passes.length < settings.maxDiscoveryRuns &&
        state.noNewStreak < settings.stopAfterNoNew
      ) {
        const pass = reservePass(state);
        pass.directory = passDirectory(lastDirectory++);
        batch.push(pass);
      }
      if (input.writer.reserveDirectory) {
        // Reserve labels in dispatch order before publishing them. Existing
        // directories may belong to a coordinator finishing a handoff.
        for (const pass of batch) {
          if (pass.scanId !== undefined) continue;
          while (!(await input.writer.reserveDirectory(pass.directory))) {
            if (!Number.isSafeInteger(++lastDirectory))
              throw new Error("No Deep Scan pass directory is available.");
            pass.directory = passDirectory(lastDirectory - 1);
          }
          lastDirectory = Math.max(
            lastDirectory,
            Number(pass.directory.split("pass-").at(-1)),
          );
        }
      }
      await save();
      const results = await Promise.allSettled(batch.map(runPass));
      executionSignal.throwIfAborted();
      for (const result of results)
        if (
          result.status === "rejected" &&
          (!deadlineController.signal.aborted ||
            (result.reason instanceof DeepScanRecoveryError &&
              !(result.reason instanceof DeepScanInputRecoveryError)))
        )
          throw result.reason;
      await refreshPasses();
    }
    await workbench([
      "update-progress",
      "--scan-id",
      scanId,
      "--phase",
      "reporting",
    ]).catch(() => undefined);
    await mergePending(true);
    updateAggregateCoverage();
    await save();
    await input.publish(state.aggregate!);
    return state;
  } catch (error) {
    if (error instanceof DeepScanRecoveryError) throw error;
    if (
      (!signal.aborted && error instanceof ScanTransportClosedError) ||
      signal.reason instanceof ScanTransportClosedError
    )
      throw error;
    stopDiscovery(
      state,
      externalStop.signal.reason === consecutiveErrorLimit
        ? "failed"
        : signal.reason instanceof ScanCostLimitExceededError
          ? "capped"
          : executionSignal.aborted &&
              executionSignal.reason !== consecutiveErrorLimit &&
              !(executionSignal.reason instanceof ScanCostTrackingError) &&
              !(executionSignal.reason instanceof ScanPermissionError) &&
              !isCodexNonRetryableFailure(executionSignal.reason)
            ? "canceled"
            : "failed",
    );
    if (
      !signal.aborted &&
      (stoppedDuringComparison || error === consecutiveErrorLimit)
    ) {
      const pending = state.passes.flatMap((pass) => {
        const child =
          pass.completed && pass.scanId
            ? completed.get(pass.scanId)
            : undefined;
        return child && !state.mergedScanIds.includes(child.scanId)
          ? [child]
          : [];
      });
      if (pending.length) {
        try {
          await commitMerge(
            await mergeExactScanFindings(scanId, pending, state.aggregate),
            pending,
          );
        } catch (cause) {
          input.onCleanupError?.(cause);
        }
      }
    }
    updateAggregateCoverage();
    await save().catch(() => undefined);
    if (state.aggregate !== null)
      await input.publish(state.aggregate).catch(() => undefined);
    throw error;
  } finally {
    if (deadlineTimer !== undefined) clearTimeout(deadlineTimer);
    clearInterval(cancellationTimer);
  }
}
