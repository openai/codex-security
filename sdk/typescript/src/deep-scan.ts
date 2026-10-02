import { join, relative } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import type { CodexSecurity, ScanOptions } from "./api.js";
import type { JsonObject } from "./config.js";
import type { ScanCost } from "./cost.js";
import {
  ScanCostLimitExceededError,
  ScanInterruptedError,
  errorMessage,
} from "./errors.js";
import type { DeepScanOptions } from "./scan-settings.js";
import {
  combineScanCoverage,
  validateScanMerge,
  unchangedScanGroups,
  scanMergePrompt,
  type ScanMergeInput,
} from "./scan-merge.js";
import type { ScanArtifactRestorer } from "./runtime.js";
import type { SemanticScan } from "./scan-semantics.js";
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

/** Required usage tracking must stop the entire composition before another pass. */
export class ScanCostTrackingError extends ScanInterruptedError {}

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
  workbench(args: readonly string[], input?: string): Promise<JsonObject>;
  merge(prompt: string, signal: AbortSignal): Promise<unknown>;
  onRetry?(message: string): void;
  onCleanupError?(error: unknown): void;
  writer: ScanArtifactRestorer;
  projectChild(
    sourceScanId: string,
    sourceDirectory: string,
    signal: AbortSignal,
  ): Promise<ScanMergeInput>;
  publish(draft: SemanticScan): Promise<void>;
  onCost(key: string, cost: Readonly<ScanCost> | null): void;
  historicalCost?(
    threadId: string,
    scanDirectory?: string,
  ): Promise<ScanCost | null>;
  restoreMergeCost?(): Promise<void>;
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
  validatePassDirectories(state);
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
  const coverage = new Map<string, SemanticScan["coverage"]>();
  const updateAggregateCoverage = (): void => {
    if (state.aggregate === null) return;
    const merged = new Set(state.mergedScanIds);
    state.aggregate = {
      ...state.aggregate,
      coverage: combineScanCoverage(
        [...coverage].filter(([id]) => merged.has(id)).map(([, pass]) => pass),
        state.passes
          .filter((pass) => !pass.scanId || !merged.has(pass.scanId))
          .map((pass) => pass.directory),
        state.mergedScanIds.some((id) => !coverage.has(id))
          ? state.aggregate.coverage
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
      if (missingSession) state.costUnavailable = true;
      costs.set(pass.directory, missingSession ? null : (record.cost ?? null));
      input.onCost(pass.directory, null);
    }
    // Recover every receipt before budget callbacks can abort another recovery.
    for (const { record, pass } of passes) {
      if (record.progress.status === "running" && record.continuationThreadId)
        costs.set(
          pass.directory,
          (await input.historicalCost?.(
            record.continuationThreadId,
            record.scanDir,
          )) ?? null,
        );
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
    for (const { record, pass } of passes) {
      if (recoverOutcomes && record.progress.status === "failed") {
        recoveredFailure ||= !pass.failed;
        observePassFailure(state, pass, recoveredSuccess);
      }
      if (
        record.progress.status === "complete" &&
        !coverage.has(record.scanId)
      ) {
        const projected = await input.projectChild(
          record.scanId,
          record.scanDir,
          executionSignal,
        );
        coverage.set(record.scanId, projected.draft.coverage);
        if (!state.mergedScanIds.includes(record.scanId))
          completed.set(record.scanId, projected);
        if (recoverOutcomes)
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
        coverage: combineScanCoverage([]),
      };
      await save();
      return;
    }
    const clean = pending.every((input) => input.draft.findings.length === 0);
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
      await save();
    }
    let merged: ReturnType<typeof validateScanMerge>;
    let validationError: unknown;
    for (;;) {
      executionSignal.throwIfAborted();
      try {
        const response = clean
          ? unchangedScanGroups(scanId, state.aggregate)
          : await input.merge(
              validationError === undefined
                ? prompt
                : `${prompt}\n\nYour previous merge response failed validation: ${errorMessage(validationError)}\nReturn a complete corrected JSON object using the same source findings and schema.`,
              executionSignal,
            );
        try {
          merged = validateScanMerge(response, pending, state.aggregate);
        } catch (error) {
          validationError = error;
          throw error;
        }
        break;
      } catch (error) {
        if (error instanceof SyntaxError) validationError = error;
        if (
          executionSignal.aborted ||
          error instanceof ScanTransportClosedError ||
          error instanceof ScanPermissionError ||
          (error !== validationError &&
            isCodexCybersecurityPolicyRefusal(error))
        )
          throw error;
        const failures = (state.mergeFailures = (state.mergeFailures ?? 0) + 1);
        await save();
        if (failures >= settings.stopAfterConsecutiveErrors) throw error;
      }
    }
    executionSignal.throwIfAborted();
    acceptMerge(
      state,
      merged,
      pending.map((result) => result.scanId),
      combineScanCoverage([...coverage.values()]),
    );
    await save();
    for (const result of pending) completed.delete(result.scanId);
  };
  const runPass = async (
    pass: DeepScanCheckpoint["passes"][number],
  ): Promise<void> => {
    const client = input.createClient();
    let latestCost: Readonly<ScanCost> | undefined;
    const failPass = async (error: unknown): Promise<void> => {
      if (pass.scanId === undefined) return;
      await workbench([
        "fail-scan",
        "--scan-id",
        pass.scanId,
        "--message",
        errorMessage(error).slice(0, 2400),
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
          const result = await client.run(input.repository, {
            ...input.scanOptions,
            mode: "standard",
            workflowId: undefined,
            outputDir: join(scanDir, pass.directory),
            ...(resuming
              ? { resumeScanId: pass.scanId, parentScanId: undefined }
              : { parentScanId: scanId }),
            deepScanPass: true,
            signal: discoverySignal,
            onRegisteredScan: async (registration) => {
              registerPass(pass, registration["scanId"] as string);
              input.onCost(pass.directory, null);
              if (resuming && registration["threadId"] === null)
                state.costUnavailable = true;
              await save();
              if (state.costUnavailable) reportPassCost("previous-work", null);
            },
            onCost: (cost) => {
              latestCost = cost;
              input.onCost(pass.directory, cost);
            },
          });
          const projected = await input.projectChild(
            result.manifest.scan.id,
            result.scanDir,
            executionSignal,
          );
          completed.set(result.manifest.scan.id, projected);
          coverage.set(result.manifest.scan.id, projected.draft.coverage);
          reportPassCost(pass.directory, result.cost);
          executionSignal.throwIfAborted();
          observePassCompletion(state, pass);
          await save();
          return;
        } catch (error) {
          if (
            error instanceof ScanCostTrackingError ||
            error instanceof ScanTransportClosedError ||
            error instanceof ScanPermissionError ||
            isCodexCybersecurityPolicyRefusal(error)
          )
            externalStop.abort(error);
          if (discoverySignal.aborted) throw error;
          if (attempt >= retries.length) {
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
  const settlePasses = async (
    passes: DeepScanCheckpoint["passes"],
  ): Promise<void> => {
    const results = await Promise.allSettled(passes.map(runPass));
    executionSignal.throwIfAborted();
    if (!deadlineController.signal.aborted) {
      for (const result of results)
        if (result.status === "rejected") throw result.reason;
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
      if (state.aggregate !== null && state.aggregate !== previousAggregate)
        await input.publish(state.aggregate);
      const batch = unfinished.slice(0, settings.workers);
      while (
        batch.length < settings.workers &&
        state.passes.length < settings.maxDiscoveryRuns
      ) {
        batch.push(reservePass(state));
      }
      await save();
      await settlePasses(batch);
      await refreshPasses();
    }
    await mergePending(true);
    updateAggregateCoverage();
    await save();
    await input.publish(state.aggregate!);
    return state;
  } catch (error) {
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
              !isCodexCybersecurityPolicyRefusal(executionSignal.reason)
            ? "canceled"
            : "failed",
    );
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

function isCodexCybersecurityPolicyRefusal(error: unknown): boolean {
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
