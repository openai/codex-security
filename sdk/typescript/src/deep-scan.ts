import { createHash } from "node:crypto";
import { join, relative } from "node:path";
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
  /** Restore parent accounting after every saved child receipt is reported. */
  onCostsRecovered?(): Promise<void>;
  historicalCost?(
    threadId: string,
    scanDirectory?: string,
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
  return state?.terminalReason === "failed" ||
    state?.terminalReason === "canceled"
    ? new ScanInterruptedError(
        `The saved Deep Scan is ${state.terminalReason}; its retained results remain available.`,
        input.scanDir,
      )
    : null;
}

/** Compose complete ordinary scans; only accepted merge state belongs to the parent. */
export async function runDeepScans(
  input: DeepScanComposition,
): Promise<DeepScanCheckpoint> {
  const { scanId, scanDir, settings, signal, workbench } = input;
  const state =
    (await loadDeepScanCheckpoint(scanDir)) ??
    newDeepScanCheckpoint(input.startedAt);
  if (input.costUnavailable) state.costUnavailable = true;
  const terminal = await terminalDeepScanError(input, state);
  if (terminal !== null) throw terminal;
  validatePassDirectories(state);
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
      ])
        await workbench(
          [
            "save-scan-artifact",
            "--scan-id",
            scanId,
            "--artifact-path",
            artifact.path,
          ],
          Buffer.from(artifact.contents).toString("utf8"),
        );
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
  const updateAggregateCoverage = (): void => {
    if (state.aggregate === null) return;
    const merged = new Set(state.mergedScanIds);
    state.aggregate = {
      ...state.aggregate,
      coverage: combineScanCoverage(
        [...completed.values()]
          .filter((pass) => merged.has(pass.scanId))
          .map((pass) => pass.draft.coverage),
        state.passes
          .filter((pass) => !pass.scanId || !merged.has(pass.scanId))
          .map((pass) => pass.directory),
        state.mergedScanIds.some((id) => !completed.has(id))
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
    for (const [directory, cost] of costs)
      if (cost !== null) reportPassCost(directory, cost);
    if (state.costUnavailable) reportPassCost("previous-work", null);
    for (const [directory, cost] of costs)
      if (cost === null) reportPassCost(directory, cost);
    await input.onCostsRecovered?.();
    if (discoveryActive) {
      const outcomes = [
        ...passes.flatMap(({ record }) =>
          record.progress.status === "failed" ||
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
      ].sort((a, b) => Date.parse(a.completedAt) - Date.parse(b.completedAt));
      state.consecutiveErrors = 0;
      for (const outcome of outcomes) {
        if (outcome.status === "failed") state.consecutiveErrors += 1;
        if (outcome.status === "complete") state.consecutiveErrors = 0;
      }
    }
    for (const { record } of passes) {
      if (record.progress.status === "complete") {
        completed.set(
          record.scanId,
          await input.projectChild(
            record.scanId,
            record.scanDir,
            executionSignal,
          ),
        );
      }
    }
    await save();
  };
  const deadline =
    Date.parse(state.startedAt) + settings.maxTimeHours * 3_600_000;
  const discoveryActive =
    state.terminalReason === undefined && Date.now() < deadline;
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
  const publish = async (): Promise<void> => {
    try {
      await input.publish(
        materializeScanAggregate(state.aggregate!) as SemanticScan,
      );
    } catch (cause) {
      executionSignal.throwIfAborted();
      throw new DeepScanPublicationError(
        "Could not publish accepted Deep Scan results; resume to retry publication.",
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
      await saveScanMergeSources(pending, input.writer, state.aggregate),
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
            if (state.mergeStarted !== true) {
              state.mergeStarted = true;
              await save();
            }
            return input.merge(prompt, signal, outputSchema);
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
          executionSignal.aborted ||
          error instanceof ScanTransportClosedError ||
          error instanceof ScanPermissionError ||
          (state.mergeFailures ?? 0) >= settings.stopAfterConsecutiveErrors ||
          (error !== validationError &&
            isCodexCybersecurityPolicyRefusal(error))
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
    await save();
    await publish();
  };
  const runPass = async (
    pass: DeepScanCheckpoint["passes"][number],
  ): Promise<void> => {
    const client = input.createClient();
    const failPass = async (error: unknown): Promise<void> => {
      if (pass.scanId === undefined) return;
      await workbench([
        "fail-scan",
        "--scan-id",
        pass.scanId,
        "--message",
        errorMessage(error).slice(0, 2400),
      ]);
    };
    try {
      discoverySignal.throwIfAborted();
      const resuming = pass.scanId !== undefined;
      let result;
      try {
        result = await client.run(input.repository, {
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
            input.onCost(pass.directory, cost);
          },
        });
      } catch (error) {
        if (
          error instanceof ScanCostTrackingError ||
          error instanceof ScanTransportClosedError ||
          error instanceof ScanPermissionError ||
          isCodexCybersecurityPolicyRefusal(error)
        )
          externalStop.abort(error);
        if (discoverySignal.aborted) throw error;
        await failPass(error);
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
      completed.set(
        result.manifest.scan.id,
        await input.projectChild(
          result.manifest.scan.id,
          result.scanDir,
          executionSignal,
        ),
      );
      reportPassCost(pass.directory, result.cost);
      executionSignal.throwIfAborted();
      state.consecutiveErrors = 0;
      await save();
    } catch (error) {
      if (error instanceof ScanCostTrackingError) externalStop.abort(error);
      if (
        discoverySignal.aborted &&
        !(discoverySignal.reason instanceof ScanTransportClosedError)
      )
        await failPass(discoverySignal.reason).catch(() => undefined);
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
    for (const result of results)
      if (
        result.status === "rejected" &&
        (!deadlineController.signal.aborted ||
          result.reason instanceof ScanCostTrackingError)
      )
        throw result.reason;
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
    await mergePending(true);
    updateAggregateCoverage();
    await save();
    await publish();
    return state;
  } catch (error) {
    if (
      error instanceof DeepScanPublicationError ||
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
    throw error;
  } finally {
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
