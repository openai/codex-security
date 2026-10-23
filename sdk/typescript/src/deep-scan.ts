import { tokenUsage, type ScanTokenUsage } from "./cost-model.js";
import { isRecord } from "./record.js";
import { createHash } from "node:crypto";
import { join, relative } from "node:path";
import type { CodexSecurity, ScanOptions } from "./api.js";
import type { JsonObject } from "./config.js";
import { scanCostUsage, type ScanCost } from "./cost.js";
import {
  ScanCostLimitExceededError,
  ScanInterruptedError,
  errorMessage,
} from "./errors.js";
import type { DeepScanOptions } from "./scan-settings.js";
import {
  combineScanCoverage,
  materializeScanAggregate,
  serializeScanAggregate,
  scanAggregateRevisionArtifacts,
  createScanMerger,
  reconcileScanMerge,
  ScanMergeValidationError,
  saveScanMergeSources,
  type ScanMergeInput,
} from "./scan-merge.js";
import type { ScanArtifactRestorer } from "./runtime.js";
import type { SemanticScan } from "./scan-semantics.js";
import {
  ScanFailedError,
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
  passDirectory,
  registerPass,
  reservePass,
  stopDiscovery,
} from "./deep-scan-lifecycle.js";
import type { SavedScanRecord } from "./workbench-types.js";
export {
  DEEP_SCAN_CHECKPOINT,
  type DeepScanCheckpoint,
} from "./deep-scan-checkpoint.js";

/** Required usage tracking must stop the entire composition before another pass. */
export class ScanCostTrackingError extends ScanInterruptedError {}

/** Accepted output can retry publication without rediscovering completed passes. */
export class DeepScanPublicationError extends ScanInterruptedError {}

/** Completed work remains accepted when projection or publication needs a retry. */
export class DeepScanRecoveryError extends ScanInterruptedError {}

/** A saved-input check rejected before this wrapped thread could execute. */
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
  workbench(args: readonly string[], input?: string): Promise<JsonObject>;
  merge(
    prompt: string,
    signal: AbortSignal,
    outputSchema?: unknown,
  ): Promise<unknown>;
  onCleanupError?(error: unknown): void;
  writer: ScanArtifactRestorer;
  projectChild(
    sourceScanId: string,
    sourceDirectory: string,
    signal: AbortSignal,
  ): Promise<ScanMergeInput>;
  publish(draft: SemanticScan): Promise<void>;
  onCost(key: string, cost: Readonly<ScanCost> | null): void;
  /** Used only when retiring a child proven never to have executed. */
  unstartedCost?: Readonly<ScanCost> | null;
  onUsage?(
    key: string,
    usage: Readonly<ScanTokenUsage>,
    source?: "receipt",
  ): void;
  /** Restore parent accounting after every saved child receipt is reported. */
  onCostsRecovered?(): Promise<void>;
  historicalCost?(
    threadId: string,
    scanDirectory?: string,
    optionalUsageOnly?: boolean,
  ): Promise<ScanCost | null>;
  costUnavailable?: boolean;
}

function validatePassDirectories(state: DeepScanCheckpoint): void {
  for (const [index, pass] of state.passes.entries()) {
    if (pass.directory !== passDirectory(index))
      throw new Error("Saved scan pass escaped its parent.");
  }
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
  if (record.parentScanRole !== "deep_pass")
    throw new Error("Saved scan is not an assigned Deep Scan pass.");
  const pass = state.passes[index]!;
  if (pass.scanId !== undefined && pass.scanId !== record.scanId)
    throw new Error("Saved scan pass registration changed.");
  return index;
}

function missingRunningSession(record: SavedScanRecord): boolean {
  return record.progress.status === "running" && !record.continuationThreadId;
}

/** Reject stopped discovery without changing its artifacts or accounting. */
export async function terminalDeepScanError(
  input: Pick<DeepScanComposition, "scanDir">,
  checkpoint?: DeepScanCheckpoint,
): Promise<ScanInterruptedError | null> {
  const state = checkpoint ?? (await loadDeepScanCheckpoint(input.scanDir));
  if (
    state?.version !== 3 ||
    state.pendingStop !== undefined ||
    (state.terminalReason !== "failed" && state.terminalReason !== "canceled")
  )
    return null;
  return new ScanInterruptedError(
    `The saved Deep Scan is ${state.terminalReason}; its retained results remain available.`,
    input.scanDir,
  );
}

/** Compose complete ordinary scans; only accepted merge state belongs to the parent. */
export async function runDeepScans(
  input: DeepScanComposition,
): Promise<DeepScanCheckpoint> {
  const { scanId, scanDir, settings, signal, workbench } = input;
  const requireCost =
    input.scanOptions.requireCost === true ||
    input.scanOptions.maxCostUsd !== undefined;
  const state =
    (await loadDeepScanCheckpoint(scanDir)) ??
    newDeepScanCheckpoint(input.startedAt);
  if (input.costUnavailable) state.costUnavailable = true;
  const terminal = await terminalDeepScanError(input, state);
  if (terminal !== null) throw terminal;
  validatePassDirectories(state);
  if (state.discoveryUserContext === undefined)
    state.discoveryUserContext = input.scanOptions.scanPrompt ?? null;
  const deadlineController = new AbortController();
  const externalStop = new AbortController();
  const executionSignal = AbortSignal.any([signal, externalStop.signal]);
  const discoverySignal = AbortSignal.any([
    executionSignal,
    deadlineController.signal,
  ]);
  const persist = async (write: () => Promise<unknown>): Promise<void> => {
    try {
      await write();
    } catch (cause) {
      if (
        executionSignal.aborted ||
        cause instanceof DeepScanRecoveryError ||
        cause instanceof ScanTransportClosedError ||
        cause instanceof ScanCostTrackingError ||
        cause instanceof ScanCostLimitExceededError ||
        cause instanceof ScanPermissionError
      )
        throw cause;
      throw new DeepScanRecoveryError(
        `Could not retain Deep Scan progress; resume to retry: ${errorMessage(cause)}`,
        scanDir,
        { cause },
      );
    }
  };
  let saveTail = Promise.resolve();
  let savedSnapshot: string | undefined;
  let savedAggregate = state.aggregate;
  let savedAggregatePath =
    typeof state["aggregatePath"] === "string" ? state["aggregatePath"] : null;
  const persistedRevisions = new Set(
    Object.keys(state.aggregate?.revisions ?? {}),
  );
  const save = async (): Promise<void> => {
    const { aggregate, ...metadata } = state;
    // Pass registrations can change while an earlier write is still pending.
    const metadataSnapshot = JSON.stringify(metadata);
    const pending = saveTail.then(async () => {
      const aggregateChanged = aggregate !== savedAggregate;
      const contents =
        aggregateChanged && aggregate !== null
          ? JSON.stringify(serializeScanAggregate(aggregate))
          : undefined;
      const aggregatePath =
        aggregate === null
          ? null
          : contents === undefined
            ? savedAggregatePath
            : `artifacts/deep-scan/aggregates/${createHash("sha256").update(contents).digest("hex")}.json`;
      const snapshot = JSON.stringify({
        ...JSON.parse(metadataSnapshot),
        aggregatePath,
      });
      // Reuse only a successful write, after all earlier saves have settled.
      if (snapshot === savedSnapshot) {
        savedAggregate = aggregate;
        return;
      }
      savedSnapshot = undefined;
      const revisions =
        aggregateChanged && aggregate !== null
          ? scanAggregateRevisionArtifacts(aggregate, persistedRevisions)
          : [];
      for (const artifact of [
        ...revisions,
        ...(contents === undefined || aggregatePath === savedAggregatePath
          ? []
          : [{ path: aggregatePath!, contents: Buffer.from(contents) }]),
        { path: DEEP_SCAN_CHECKPOINT, contents: Buffer.from(snapshot) },
      ]) {
        await persist(() =>
          workbench(
            [
              "save-scan-artifact",
              "--scan-id",
              scanId,
              "--artifact-path",
              artifact.path,
            ],
            Buffer.from(artifact.contents).toString("utf8"),
          ),
        );
      }
      if (aggregateChanged)
        for (const id of Object.keys(aggregate?.revisions ?? {}))
          persistedRevisions.add(id);
      savedAggregate = aggregate;
      savedAggregatePath = aggregatePath;
      savedSnapshot = snapshot;
    });
    saveTail = pending.catch(() => undefined);
    return pending;
  };
  const retirementCost = (
    pass: DeepScanCheckpoint["passes"][number],
    record: SavedScanRecord,
    cost?: Readonly<ScanCost> | null,
  ): Readonly<ScanCost> | null | undefined =>
    cost ??
    record.cost ??
    (pass.executionNotStarted === true && missingRunningSession(record)
      ? input.unstartedCost
      : undefined);
  const retireChild = async (
    childId: string,
    message: string,
    cost?: Readonly<ScanCost> | null,
  ): Promise<void> => {
    await workbench([
      "fail-scan",
      "--scan-id",
      childId,
      "--message",
      message,
      ...(cost ? ["--cost-json", JSON.stringify(cost)] : []),
    ]);
  };
  const finishStop = async (): Promise<void> => {
    if (state.pendingStop === undefined) return;
    stopDiscovery(state, state.pendingStop.reason);
    delete state.pendingStop;
    try {
      await save();
    } catch (cause) {
      if (cause instanceof ScanTransportClosedError) throw cause;
      throw new DeepScanRecoveryError(
        `Could not save interrupted child retirement; resume to retry: ${errorMessage(cause)}`,
        scanDir,
        { cause },
      );
    }
  };
  const retirePendingStop = async (): Promise<void> => {
    if (state.pendingStop === undefined) return;
    try {
      const listed = await workbench([
        "list-scans",
        "--scan-root",
        join(scanDir, "artifacts/deep-scan/passes"),
      ]);
      for (const record of listed["scans"] as SavedScanRecord[]) {
        const index = savedPassIndex(input, state, record);
        if (index < 0) continue;
        const pass = state.passes[index]!;
        registerPass(pass, record.scanId);
        if (record.progress.status === "running")
          await retireChild(
            record.scanId,
            state.pendingStop.message,
            retirementCost(
              pass,
              record,
              state.pendingStop.costs[pass.directory],
            ),
          );
      }
      await finishStop();
    } catch (cause) {
      if (
        cause instanceof ScanTransportClosedError ||
        cause instanceof DeepScanRecoveryError
      )
        throw cause;
      throw new DeepScanRecoveryError(
        `Could not retire the interrupted child scan; resume to retry: ${errorMessage(cause)}`,
        scanDir,
        { cause },
      );
    }
  };
  // Cleanup must precede accounting and projection: the saved stop may already
  // have exhausted the budget or made required accounting unavailable.
  if (state.pendingStop !== undefined) {
    await retirePendingStop();
    const terminal = await terminalDeepScanError(input, state);
    if (terminal !== null) throw terminal;
  }
  await save();
  await workbench([
    "update-progress",
    "--scan-id",
    scanId,
    "--phase",
    "discovery",
  ]).catch(() => undefined);
  const mergeScans = await createScanMerger(input.pluginRoot);
  const completed = new Map<string, ScanMergeInput>();
  const saved = new Map<string, SavedScanRecord>();
  const recoveredCosts = new Map<string, Readonly<ScanCost> | null>();
  const updateAggregateCoverage = (): void => {
    if (state.aggregate === null) return;
    const merged = new Set(state.mergedScanIds);
    state.aggregate = {
      ...state.aggregate,
      coverage: combineScanCoverage(
        [...completed.values()]
          .filter((pass) => merged.has(pass.scanId))
          .map((pass) => pass.draft.coverage),
        [
          ...state.passes
            .filter((pass) => !pass.scanId || !merged.has(pass.scanId))
            .map((pass) => pass.directory),
          ...(state.passes.length === 0 && deadlineController.signal.aborted
            ? [
                "The configured discovery time limit elapsed before any source review completed.",
              ]
            : []),
        ],
        state.mergedScanIds.some((id) => !completed.has(id))
          ? state.aggregate.coverage
          : undefined,
      ),
    };
  };
  const reportPassCost = (key: string, cost: Readonly<ScanCost> | null) => {
    input.onCost(key, cost);
    if (cost === null && requireCost)
      throw new ScanCostTrackingError(
        "The child scan cost is unavailable; its cost limit cannot be verified.",
        scanDir,
      );
  };
  const recoverCost = async <T>(
    recover: () => Promise<T>,
  ): Promise<T | null> => {
    try {
      return await recover();
    } catch (cause) {
      executionSignal.throwIfAborted();
      if (cause instanceof ScanTransportClosedError) throw cause;
      if (requireCost)
        throw new ScanCostTrackingError(
          `Could not recover Deep Scan cost: ${errorMessage(cause)}`,
          scanDir,
          { cause },
        );
      return null;
    }
  };
  const projectChild = async (childId: string, childDir: string) => {
    try {
      return await input.projectChild(childId, childDir, executionSignal);
    } catch (cause) {
      executionSignal.throwIfAborted();
      if (cause instanceof ScanTransportClosedError) throw cause;
      throw new DeepScanRecoveryError(
        `Could not project completed child results; resume to retry: ${errorMessage(cause)}`,
        scanDir,
        { cause },
      );
    }
  };
  const hydratePasses = async (): Promise<void> => {
    const listed = await workbench([
      "list-scans",
      "--scan-root",
      join(scanDir, "artifacts/deep-scan/passes"),
    ]);
    const records = listed["scans"] as unknown as SavedScanRecord[];
    const passes = records.flatMap((record) => {
      const index = savedPassIndex(input, state, record);
      if (index < 0) return [];
      const pass = state.passes[index]!;
      registerPass(pass, record.scanId);
      saved.set(record.scanId, record);
      return [{ record, pass }];
    });
    const costs = new Map<string, Readonly<ScanCost> | null>();
    let recoveryMetadataChanged = false;
    for (const { record, pass } of passes) {
      const missingSession = missingRunningSession(record);
      const executionNotStarted =
        pass.executionNotStarted === true && missingSession;
      if (pass.executionNotStarted === true && !executionNotStarted) {
        delete pass.executionNotStarted;
        recoveryMetadataChanged = true;
      }
      if (missingSession && !executionNotStarted) state.costUnavailable = true;
      if (!executionNotStarted) {
        costs.set(
          pass.directory,
          missingSession ? null : (record.cost ?? null),
        );
        recoveredCosts.set(pass.directory, costs.get(pass.directory)!);
      }
      input.onCost(pass.directory, null);
      const savedUsage = record["usage"];
      let usage: ScanTokenUsage | null = null;
      // A completed child's cost receipt covers all of its work. A partial
      // usage projection cannot replace those saved counters.
      if (
        isRecord(savedUsage) &&
        (record.progress.status !== "complete" ||
          record.cost == null ||
          savedUsage["coverage"] === "complete")
      ) {
        usage = tokenUsage({
          input_tokens: savedUsage["inputTokens"],
          cached_input_tokens: savedUsage["cachedInputTokens"],
          cache_write_input_tokens: savedUsage["cacheWriteInputTokens"],
          cache_write_input_tokens_reported:
            record.cost == null
              ? false
              : record.cost.cacheWriteInputTokensReported,
          output_tokens: savedUsage["outputTokens"],
          reasoning_output_tokens: savedUsage["reasoningOutputTokens"],
        });
      }
      if (usage === null && !missingSession && record.cost != null)
        usage = tokenUsage(scanCostUsage(record.cost));
      if (usage !== null) input.onUsage?.(pass.directory, usage);
    }
    // Recover every receipt before budget callbacks can abort another recovery.
    for (const { record, pass } of passes) {
      if (record.progress.status === "running" && record.continuationThreadId) {
        costs.set(
          pass.directory,
          (await recoverCost(async () =>
            input.historicalCost?.(
              record.continuationThreadId!,
              record.scanDir,
            ),
          )) ?? null,
        );
        recoveredCosts.set(pass.directory, costs.get(pass.directory)!);
      } else if (
        input.onUsage !== undefined &&
        record.continuationThreadId &&
        record.progress.status === "complete"
      ) {
        // Saved cost remains authoritative; optional token refresh cannot invalidate it.
        await input
          .historicalCost?.(record.continuationThreadId, record.scanDir, true)
          .catch(() => undefined);
        executionSignal.throwIfAborted();
      }
    }
    if (state.costUnavailable || recoveryMetadataChanged) await save();
    for (const [directory, cost] of costs)
      if (cost !== null) reportPassCost(directory, cost);
    if (state.costUnavailable) reportPassCost("previous-work", null);
    for (const [directory, cost] of costs)
      if (cost === null) reportPassCost(directory, cost);
    if (input.onCostsRecovered) await recoverCost(input.onCostsRecovered);
    if (discoveryActive) {
      const outcomes = [
        ...passes.flatMap(({ record }) =>
          record.progress.status === "failed" ||
          record.progress.status === "canceled" ||
          record.progress.status === "complete"
            ? [
                {
                  status: record.progress.status,
                  completedAt: record.completedAt ?? "",
                },
              ]
            : [],
        ),
        ...state.passes.flatMap((pass) =>
          pass.failedBeforeRegistration
            ? [{ status: "failed", completedAt: pass.failedBeforeRegistration }]
            : [],
        ),
      ].sort((a, b) => {
        const milliseconds =
          Date.parse(a.completedAt) - Date.parse(b.completedAt);
        if (milliseconds !== 0) return milliseconds;
        const fractions = [a.completedAt, b.completedAt].map(
          (value) => /\.(\d+)/u.exec(value)?.[1] ?? "",
        );
        const precision = Math.max(...fractions.map((value) => value.length));
        return fractions[0]!
          .padEnd(precision, "0")
          .localeCompare(fractions[1]!.padEnd(precision, "0"));
      });
      state.consecutiveErrors = 0;
      for (const outcome of outcomes) {
        if (outcome.status !== "complete") state.consecutiveErrors += 1;
        if (outcome.status === "complete") state.consecutiveErrors = 0;
      }
    }
    for (const { record } of passes) {
      if (record.progress.status === "complete") {
        completed.set(
          record.scanId,
          await projectChild(record.scanId, record.scanDir),
        );
      }
    }
    await save();
  };
  const deadline =
    Date.parse(state.startedAt) + settings.maxTimeHours * 3_600_000;
  const discoveryActive =
    state.terminalReason === undefined && Date.now() < deadline;
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
  const consecutiveErrorLimit = new Error(
    "Deep Scan reached its consecutive error limit.",
  );
  const stopReason = (): "failed" | "capped" | "canceled" =>
    externalStop.signal.reason === consecutiveErrorLimit
      ? "failed"
      : executionSignal.reason instanceof ScanCostLimitExceededError
        ? "capped"
        : executionSignal.aborted &&
            !(executionSignal.reason instanceof ScanCostTrackingError) &&
            !(executionSignal.reason instanceof ScanPermissionError) &&
            !(executionSignal.reason instanceof ScanFailedError) &&
            !isCodexNonRetryableFailure(executionSignal.reason)
          ? "canceled"
          : "failed";
  let polling = false;
  let parentStopped = false;
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
          parentStopped = true;
          externalStop.abort(
            progress["status"] === "failed"
              ? new ScanFailedError("The saved parent scan stopped.")
              : new Error("The saved parent scan stopped."),
          );
        }
      })
      .catch(() => undefined)
      .finally(() => {
        polling = false;
      });
  }, 1_000);
  cancellationTimer.unref();
  const publish = async (): Promise<void> => {
    executionSignal.throwIfAborted();
    try {
      await input.publish(
        materializeScanAggregate(state.aggregate!) as SemanticScan,
      );
      executionSignal.throwIfAborted();
    } catch (cause) {
      executionSignal.throwIfAborted();
      if (cause instanceof ScanTransportClosedError) throw cause;
      throw new DeepScanPublicationError(
        `Could not publish accepted Deep Scan results; resume to retry publication: ${errorMessage(cause)}`,
        scanDir,
        { cause },
      );
    }
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
        ...reconcileScanMerge(scanId, [], [], null).aggregate,
        coverage: combineScanCoverage([]),
      };
      await save();
      return;
    }
    const contextPath = join(
      scanDir,
      await saveScanMergeSources(
        pending,
        {
          ...input.writer,
          restoreMany: (artifacts) =>
            persist(() => input.writer.restoreMany(artifacts)),
        },
        state.aggregate,
      ),
    );
    let merged: Awaited<ReturnType<typeof mergeScans>>;
    let validationError: unknown;
    const retryMerge = async () => {
      state.mergeFailures = (state.mergeFailures ?? 0) + 1;
      await save();
      return state.mergeFailures < settings.stopAfterConsecutiveErrors;
    };
    for (;;) {
      executionSignal.throwIfAborted();
      try {
        merged = await mergeScans(
          scanId,
          pending,
          state.aggregate,
          executionSignal,
          async (prompt, signal, outputSchema) => {
            const previousMergeStarted = state.mergeStarted;
            if (previousMergeStarted !== true) {
              state.mergeStarted = true;
              await save();
            }
            try {
              return await input.merge(prompt, signal, outputSchema);
            } catch (error) {
              if (
                previousMergeStarted !== true &&
                error instanceof DeepScanInputRecoveryError &&
                error.neverStarted
              ) {
                if (previousMergeStarted === undefined)
                  delete state.mergeStarted;
                else state.mergeStarted = previousMergeStarted;
                try {
                  await save();
                } catch (cause) {
                  throw new DeepScanRecoveryError(
                    `Could not restore the unstarted reducer checkpoint: ${errorMessage(cause)}`,
                    scanDir,
                    { cause },
                  );
                }
              }
              throw error;
            }
          },
          { contextPath, onInvalidResponse: retryMerge, validationError },
        );
        break;
      } catch (error) {
        if (
          error instanceof SyntaxError ||
          error instanceof ScanMergeValidationError
        )
          validationError = error;
        if (
          error instanceof ScanCostTrackingError ||
          error instanceof ScanCostLimitExceededError
        )
          externalStop.abort(error);
        if (
          executionSignal.aborted ||
          error instanceof DeepScanRecoveryError ||
          error instanceof ScanTransportClosedError ||
          error instanceof ScanPermissionError ||
          (state.mergeFailures ?? 0) >= settings.stopAfterConsecutiveErrors ||
          (error !== validationError && isCodexNonRetryableFailure(error))
        )
          throw error;
        if (!(await retryMerge())) throw error;
      }
    }
    executionSignal.throwIfAborted();
    acceptMerge(
      state,
      merged,
      pending.map((result) => result.scanId),
      combineScanCoverage(
        [...completed.values()].map((pass) => pass.draft.coverage),
      ),
    );
    updateAggregateCoverage();
    await save();
    await publish();
  };
  const runPass = async (
    pass: DeepScanCheckpoint["passes"][number],
  ): Promise<void> => {
    const client = input.createClient();
    let latestCost = recoveredCosts.get(pass.directory) ?? undefined;
    let childCompleted = false;
    const failPass = async (error: unknown): Promise<void> => {
      if (pass.scanId === undefined || childCompleted) return;
      const response = await workbench(["get-scan", "--scan-id", pass.scanId]);
      const record = response["scan"] as unknown as SavedScanRecord;
      if (record.progress.status === "complete") {
        childCompleted = true;
        state.consecutiveErrors = 0;
        if (!executionSignal.aborted) {
          completed.set(
            record.scanId,
            await projectChild(record.scanId, record.scanDir),
          );
          reportPassCost(pass.directory, record.cost ?? null);
        }
        return;
      }
      await retireChild(
        pass.scanId,
        errorMessage(error),
        retirementCost(pass, record, latestCost),
      );
    };
    try {
      discoverySignal.throwIfAborted();
      const resuming = pass.scanId !== undefined;
      const executionNotStarted = pass.executionNotStarted === true;
      if (executionNotStarted) {
        delete pass.executionNotStarted;
        try {
          await save();
        } catch (cause) {
          throw new DeepScanRecoveryError(
            `Could not consume the unstarted discovery checkpoint: ${errorMessage(cause)}`,
            scanDir,
            { cause },
          );
        }
      }
      let result;
      try {
        result = await client.run(input.repository, {
          ...input.scanOptions,
          scanPrompt: state.discoveryUserContext ?? undefined,
          mode: "standard",
          workflowId: undefined,
          postScanPrompt: undefined,
          postScanPromptFile: undefined,
          outputDir: join(scanDir, pass.directory),
          resumeScanId: pass.scanId,
          parentScanId: resuming ? undefined : scanId,
          deepScanPass: true,
          signal: discoverySignal,
          onRegisteredScan: async (registration) => {
            registerPass(pass, registration["scanId"] as string);
            input.onCost(pass.directory, null);
            if (
              resuming &&
              !executionNotStarted &&
              registration["threadId"] === null
            )
              state.costUnavailable = true;
            await save();
            if (state.costUnavailable) reportPassCost("previous-work", null);
          },
          onUsage:
            input.onUsage === undefined
              ? input.scanOptions.onUsage
              : (usage) => input.onUsage!(pass.directory, usage),
          onCost: (cost) => {
            latestCost = cost;
            input.onCost(pass.directory, cost);
          },
        });
      } catch (error) {
        if (
          error instanceof DeepScanInputRecoveryError &&
          error.neverStarted &&
          (!resuming || executionNotStarted) &&
          pass.scanId !== undefined
        ) {
          pass.executionNotStarted = true;
          try {
            await save();
          } catch (cause) {
            throw new DeepScanRecoveryError(
              `Could not save the unstarted discovery checkpoint: ${errorMessage(cause)}`,
              scanDir,
              { cause },
            );
          }
        }
        if (error instanceof DeepScanRecoveryError) throw error;
        if (
          error instanceof ScanCostTrackingError ||
          error instanceof ScanCostLimitExceededError ||
          error instanceof ScanTransportClosedError ||
          error instanceof ScanPermissionError ||
          isCodexNonRetryableFailure(error)
        )
          externalStop.abort(error);
        if (discoverySignal.aborted) throw error;
        await failPass(error);
        if (childCompleted) return;
        let receipt: Readonly<ScanCost> | null = null;
        if (pass.scanId === undefined) {
          // No child row exists to record this consumed reservation.
          pass.failedBeforeRegistration = new Date().toISOString();
        } else {
          const response = await workbench([
            "get-scan",
            "--scan-id",
            pass.scanId,
          ]);
          const record = response["scan"] as unknown as SavedScanRecord;
          saved.set(pass.scanId, record);
          receipt = record.cost ?? null;
        }
        state.consecutiveErrors += 1;
        if (pass.scanId !== undefined) reportPassCost(pass.directory, receipt);
        if (state.consecutiveErrors >= settings.stopAfterConsecutiveErrors) {
          stopDiscovery(state, "failed");
          externalStop.abort(consecutiveErrorLimit);
        }
        await save();
        return;
      }
      childCompleted = true;
      state.consecutiveErrors = 0;
      if (input.onUsage !== undefined) {
        const usage =
          tokenUsage(result.turnResult.usage) ??
          (result.cost === null
            ? null
            : tokenUsage(scanCostUsage(result.cost)));
        if (usage !== null) input.onUsage(pass.directory, usage, "receipt");
      }
      completed.set(
        result.manifest.scan.id,
        await projectChild(result.manifest.scan.id, result.scanDir),
      );
      reportPassCost(pass.directory, result.cost);
      executionSignal.throwIfAborted();
      await save();
    } catch (error) {
      if (
        error instanceof ScanTransportClosedError ||
        error instanceof ScanCostTrackingError ||
        error instanceof ScanCostLimitExceededError
      )
        externalStop.abort(error);
      if (
        !childCompleted &&
        !parentStopped &&
        discoverySignal.aborted &&
        !(discoverySignal.reason instanceof ScanTransportClosedError)
      ) {
        try {
          const reason =
            executionSignal.aborted &&
            !(executionSignal.reason instanceof ScanTransportClosedError)
              ? stopReason()
              : "capped";
          state.pendingStop ??= {
            reason,
            message: errorMessage(discoverySignal.reason),
            costs: {},
          };
          if (state.pendingStop.reason !== "failed")
            state.pendingStop.reason = reason;
          if (latestCost) state.pendingStop.costs[pass.directory] = latestCost;
          await save();
          await failPass(discoverySignal.reason);
        } catch (cause) {
          if (cause instanceof ScanTransportClosedError) throw cause;
          throw new DeepScanRecoveryError(
            `Could not retire the interrupted child scan; resume to retry: ${errorMessage(cause)}`,
            scanDir,
            { cause },
          );
        }
      }
      if (error instanceof ScanCostTrackingError) state.costUnavailable = true;
      if (discoverySignal.aborted && pass.scanId !== undefined) {
        input.onCost(pass.directory, null);
        if (!(error instanceof ScanCostTrackingError)) {
          let cost: Readonly<ScanCost> | null = null;
          try {
            const response = await workbench([
              "get-scan",
              "--scan-id",
              pass.scanId,
            ]);
            const record = response["scan"] as unknown as SavedScanRecord;
            cost = record.cost ?? null;
          } finally {
            if (executionSignal.aborted) input.onCost(pass.directory, cost);
            else reportPassCost(pass.directory, cost);
          }
        }
      }
      if (error instanceof DeepScanRecoveryError) throw error;
      if (deadlineController.signal.aborted && !executionSignal.aborted)
        throw deadlineController.signal.reason;
      throw error;
    } finally {
      try {
        await client.close();
      } catch (error) {
        void Promise.resolve()
          .then(() => input.onCleanupError?.(error))
          .catch(() => {});
      }
    }
  };
  const settlePasses = async (
    passes: DeepScanCheckpoint["passes"],
  ): Promise<void> => {
    const results = await Promise.allSettled(passes.map(runPass));
    // Keep unfinished persistence resumable even when a sibling observed the abort.
    for (const result of results) {
      if (
        (state.terminalReason === undefined ||
          state.pendingStop !== undefined) &&
        result.status === "rejected" &&
        (result.reason instanceof DeepScanRecoveryError ||
          result.reason instanceof ScanTransportClosedError)
      )
        throw result.reason;
    }
    for (const result of results) {
      if (
        !executionSignal.aborted &&
        result.status === "rejected" &&
        result.reason !== deadlineController.signal.reason
      )
        throw result.reason;
    }
    await finishStop();
    executionSignal.throwIfAborted();
  };
  try {
    await hydratePasses();
    if (state.mergedScanIds.some((id) => !completed.has(id))) {
      throw new Error(
        "An accepted merge input is no longer a sealed child scan.",
      );
    }
    if (
      discoveryActive &&
      state.consecutiveErrors >= settings.stopAfterConsecutiveErrors
    )
      throw consecutiveErrorLimit;
    while (state.terminalReason === undefined) {
      executionSignal.throwIfAborted();
      await mergePending();
      const discoveryDeadlineReached =
        deadlineController.signal.aborted || Date.now() >= deadline;
      const unfinished = state.passes.filter(
        (pass) =>
          (pass.scanId === undefined && !pass.failedBeforeRegistration) ||
          (pass.scanId !== undefined &&
            !completed.has(pass.scanId) &&
            saved.get(pass.scanId)?.progress.status === "running"),
      );
      const stop = discoveryStopReason(state, {
        deadlineReached: discoveryDeadlineReached,
        hasUnfinishedPasses: unfinished.length > 0,
        maxDiscoveryRuns: settings.maxDiscoveryRuns,
        stopAfterNoNew: settings.stopAfterNoNew,
      });
      if (stop !== undefined) {
        if (discoveryDeadlineReached) {
          if (!deadlineController.signal.aborted) tick();
          await settlePasses(unfinished);
        }
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
      const batch = unfinished.slice(0, settings.workers);
      while (
        batch.length < settings.workers &&
        state.passes.length < settings.maxDiscoveryRuns
      ) {
        batch.push(reservePass(state));
      }
      await save();
      await settlePasses(batch);
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
    await publish();
    return state;
  } catch (error) {
    // The workbench already retired the children and froze the parent's files.
    if (parentStopped) throw externalStop.signal.reason;
    if (
      error instanceof DeepScanRecoveryError ||
      error instanceof DeepScanPublicationError ||
      error instanceof ScanTransportClosedError ||
      executionSignal.reason instanceof ScanTransportClosedError
    )
      throw error;
    if (
      error instanceof ScanCostTrackingError ||
      error instanceof ScanCostLimitExceededError ||
      error instanceof ScanPermissionError ||
      isCodexNonRetryableFailure(error)
    )
      externalStop.abort(error);
    if (
      state.terminalReason === undefined ||
      state.terminalReason === "capped" ||
      state.terminalReason === "saturated"
    ) {
      state.pendingStop ??= {
        reason: stopReason(),
        message: errorMessage(error),
        costs: Object.fromEntries(
          [...recoveredCosts].filter(
            (entry): entry is [string, Readonly<ScanCost>] => entry[1] !== null,
          ),
        ),
      };
      if (executionSignal.aborted && state.pendingStop.reason !== "failed")
        state.pendingStop.reason = stopReason();
      try {
        await save();
        await retirePendingStop();
      } catch (cause) {
        if (
          cause instanceof ScanTransportClosedError ||
          cause instanceof DeepScanRecoveryError
        )
          throw cause;
        throw new DeepScanRecoveryError(
          `Could not retain interrupted child retirement; resume to retry: ${errorMessage(cause)}`,
          scanDir,
          { cause },
        );
      }
    }
    updateAggregateCoverage();
    await save().catch(() => undefined);
    throw error;
  } finally {
    clearInterval(cancellationTimer);
    if (deadlineTimer !== undefined) clearTimeout(deadlineTimer);
  }
}

export function isCodexCybersecurityPolicyRefusal(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  // SDK diagnostics can include repository text; match complete runtime refusals.
  return [
    "cyber_policy",
    "Request rejected: cyber_policy.",
    "Request flagged for possible cybersecurity risk.",
    "Request flagged for potentially high-risk cyber activity.",
    "Request blocked by cyberPolicy.",
    "Request blocked by a safety policy violation.",
    "This content was flagged for possible cybersecurity risk.",
    "This content was flagged for potentially high-risk cyber activity.",
    "This request has been flagged for possible cybersecurity risk.",
    "This request has been flagged for potentially high-risk cyber activity.",
    "Request blocked by a cybersecurity_policy_violation.",
    "Request refused under cybersecurity policy.",
    "Cybersecurity policy has refused the request.",
  ].includes(message);
}

/** Terminal native account limits cannot be fixed by retrying discovery. */
export function isCodexNonRetryableFailure(error: unknown): boolean {
  if (isCodexCybersecurityPolicyRefusal(error)) return true;
  const message = error instanceof Error ? error.message : String(error);
  if (
    message.startsWith("You’ve hit your usage limit.") ||
    message.startsWith("You’ve hit your usage limit for ")
  )
    return true;
  return [
    "Quota exceeded. Check your plan and billing details.",
    "Your workspace is out of credits. Add credits to continue.",
    "Your workspace is out of credits. Ask your workspace owner to refill in order to continue.",
    "You hit your spend cap set in your workspace. Increase your spend cap to continue.",
    "You hit your spend cap set by the owner of your workspace. Ask an owner to increase your spend cap to continue.",
  ].includes(message);
}
