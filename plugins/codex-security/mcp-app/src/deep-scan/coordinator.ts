import { randomUUID } from "node:crypto";
import { promises as fs } from "node:fs";
import { basename, dirname, join } from "node:path";
import {
  createDeepScanArtifacts,
  ensureDeepScanDirectories
} from "./artifacts.js";
import { validateDiscoveryArtifacts, validateReducerArtifacts, type DeepReductionInput } from "./artifact-validation.js";
import {
  scanDraftInputSchema,
  type ScanDraftInput
} from "../artifact-scan-draft.js";
import type { DeepScanArtifacts } from "./artifacts.js";
import {
  DeepScanWorkerRunner,
  sha256
} from "./worker-runner.js";
import type {
  AcceptedDiscovery,
  DedupOutcome,
  DiscoveryOutcome,
  SuccessfulDedupOutcome,
  WorkerExecutionAudit
} from "./worker-runner.js";
import {
  boundedDeepScanErrorPair,
  boundedDeepScanErrorMessage,
  isStaleCoordinatorGenerationError
} from "./errors.js";
import type {
  CodexWorkerExecutor,
  DeepScanClock,
  DeepScanLogger,
  DeepScanReplaceableFailureKind,
  DeepScanRunState,
  DeepScanStore,
  DeepScanTerminalReason,
  PersistedDeepScanWorker
} from "./types.js";

const RETRY_DELAYS_MS = [60_000, 180_000, 540_000] as const;
const COORDINATOR_HEARTBEAT_INTERVAL_MS = 5_000;
const DEFAULT_DISCOVERY_TIMEOUT_HOURS = 96;

type SchedulerOutcome = DiscoveryOutcome | DedupOutcome;

type SchedulerSettlement =
  | { status: "fulfilled"; outcome: SchedulerOutcome }
  | { status: "rejected"; error: unknown };

type AcceptedReducer = Omit<SuccessfulDedupOutcome, "result">;

interface SchedulerResult {
  reason: DeepScanTerminalReason;
  omittedWorkerIds: string[];
  canceledWorkerIds: string[];
  accepted: AcceptedDiscovery[];
  mergedWorkerIds: string[];
  reducers: AcceptedReducer[];
  result?: DeepReductionInput;
}

type CoordinatorPhase = "setup" | "discovery" | "terminal";

interface SchedulerAudit {
  accepted: AcceptedDiscovery[];
  mergedWorkerIds: string[];
  omittedWorkerIds: string[];
  canceledWorkerIds: string[];
  bufferedWorkerIds: string[];
  reducers: AcceptedReducer[];
  executions: WorkerExecutionAudit[];
}

export interface CoordinatorOptions {
  run: DeepScanRunState;
  store: DeepScanStore;
  executor: CodexWorkerExecutor;
  pluginRoot: string;
  clock?: DeepScanClock;
  random?: () => number;
  log?: DeepScanLogger;
  retryDelaysMs?: readonly number[];
  discoveryTimeoutMs?: number;
  handoffClaimToken?: string;
  threadId?: string;
  heartbeatIntervalMs?: number;
  observeReplacement?: (run: DeepScanRunState) => Promise<DeepScanRunState>;
  onComplete?: (draft: ScanDraftInput, signal: AbortSignal) => Promise<void>;
  onStopped?: (run: DeepScanRunState) => Promise<void>;
}

export { DeepScanNonRetryableError } from "./errors.js";

/** Runs setup, keeps the discovery/reducer queue moving, and closes the scan. */
export class DeepScanCoordinator {
  private readonly abortController = new AbortController();
  private readonly discoveryAbortController = new AbortController();
  private readonly publicationAbortController = new AbortController();
  private readonly clock: DeepScanClock;
  private readonly log: DeepScanLogger;
  private readonly artifacts: DeepScanArtifacts;
  private readonly workers: DeepScanWorkerRunner;
  private readonly discoveryWorkers: DeepScanWorkerRunner;
  private readonly terminalPromise: Promise<DeepScanRunState>;
  private readonly schedulerWork = new Set<Promise<unknown>>();
  private heartbeatTimeout: ReturnType<typeof setTimeout> | undefined;
  private discoveryTimeout: ReturnType<typeof setTimeout> | undefined;
  private ownershipCheck: Promise<boolean> | undefined;
  private resolveTerminal!: (state: DeepScanRunState) => void;
  private rejectTerminal!: (error: unknown) => void;
  private resolveCancellationReady!: () => void;
  private readonly cancellationReady = new Promise<void>((resolvePromise) => {
    this.resolveCancellationReady = resolvePromise;
  });
  private cancellationPersistence?: {
    promise: Promise<void>;
    resolve: () => void;
    reject: (error: unknown) => void;
  };
  private started = false;
  private terminal = false;
  private canceled = false;
  private externallyFailed = false;
  private phase: CoordinatorPhase = "setup";
  private discoveryDeadlineReached = false;
  private readonly audit: SchedulerAudit = {
    accepted: [],
    mergedWorkerIds: [],
    omittedWorkerIds: [],
    canceledWorkerIds: [],
    bufferedWorkerIds: [],
    reducers: [],
    executions: []
  };
  private state: DeepScanRunState;

  constructor(private readonly options: CoordinatorOptions) {
    this.state = cloneState(options.run);
    this.clock = options.clock ?? systemClock;
    this.log = options.log ?? (() => undefined);
    this.artifacts = createDeepScanArtifacts(this.state.scanDir);
    const workerOptions = {
      run: this.state,
      store: options.store,
      executor: options.executor,
      artifacts: this.artifacts,
      pluginRoot: options.pluginRoot,
      clock: this.clock,
      random: options.random ?? Math.random,
      log: this.log,
      retryDelaysMs: options.retryDelaysMs ?? RETRY_DELAYS_MS,
      recordExecution: (execution) => {
        this.audit.executions.push(execution);
      }
    } satisfies Omit<ConstructorParameters<typeof DeepScanWorkerRunner>[0], "signal">;
    this.workers = new DeepScanWorkerRunner({
      ...workerOptions,
      signal: this.abortController.signal
    });
    this.discoveryWorkers = new DeepScanWorkerRunner({
      ...workerOptions,
      signal: this.discoveryAbortController.signal
    });
    this.abortController.signal.addEventListener("abort", () => {
      this.discoveryAbortController.abort(this.abortController.signal.reason);
    }, { once: true });
    this.terminalPromise = new Promise((resolvePromise, rejectPromise) => {
      this.resolveTerminal = resolvePromise;
      this.rejectTerminal = rejectPromise;
    });
  }

  start(): void {
    if (this.started) return;
    this.started = true;
    this.log({ event: "coordinator_started", scanId: this.state.scanId });
    this.scheduleDiscoveryDeadline();
    this.scheduleHeartbeat();
    void this.run().catch((error: unknown) => {
      this.log({
        event: "coordinator_unhandled_error",
        scanId: this.state.scanId,
        reason: errorKind(error)
      });
      this.failLocally(error);
    });
  }

  snapshot(): DeepScanRunState {
    return cloneState(this.state);
  }

  settled(): Promise<DeepScanRunState> {
    return this.terminalPromise.then(cloneState);
  }

  async wait(signal: AbortSignal | undefined): Promise<DeepScanRunState>;
  async wait(
    signal: AbortSignal | undefined,
    timeoutMs: number
  ): Promise<DeepScanRunState | undefined>;
  async wait(
    signal: AbortSignal | undefined,
    timeoutMs?: number
  ): Promise<DeepScanRunState | undefined> {
    if (this.terminal) return await this.settled();
    if (signal?.aborted) throw abortError(signal.reason);
    return await new Promise<DeepScanRunState | undefined>((resolvePromise, rejectPromise) => {
      const timeout = timeoutMs === undefined
        ? undefined
        : setTimeout(() => {
          cleanup();
          resolvePromise(undefined);
        }, timeoutMs);
      const onAbort = (): void => {
        cleanup();
        rejectPromise(abortError(signal?.reason));
      };
      const cleanup = (): void => {
        if (timeout !== undefined) clearTimeout(timeout);
        signal?.removeEventListener("abort", onAbort);
      };
      signal?.addEventListener("abort", onAbort, { once: true });
      void this.terminalPromise.then(
        (state) => {
          cleanup();
          resolvePromise(cloneState(state));
        },
        (error: unknown) => {
          cleanup();
          rejectPromise(error);
        }
      );
    });
  }

  cancel(reason: string): void {
    if (this.canceled || this.terminal) return;
    this.canceled = true;
    this.state = { ...this.state, status: "canceled" };
    this.log({ event: "coordinator_cancel_requested", scanId: this.state.scanId, reason });
    this.abortController.abort(reason);
    this.publicationAbortController.abort(reason);
    // The cancel operation returns promptly. Terminal waiters remain attached
    // until worker cleanup and stopped-result publication settle.
  }

  async cancelAfterPersistence(
    reason: string,
    persistCancellation: () => Promise<void>
  ): Promise<DeepScanRunState> {
    if (this.terminal) return await this.settled();
    if (!this.cancellationPersistence) {
      let resolve!: () => void;
      let reject!: (error: unknown) => void;
      const promise = new Promise<void>((resolvePromise, rejectPromise) => {
        resolve = resolvePromise;
        reject = rejectPromise;
      });
      this.cancellationPersistence = { promise, resolve, reject };
    }
    this.cancel(reason);
    await this.cancellationReady;
    try {
      await persistCancellation();
      this.cancellationPersistence.resolve();
    } catch (error) {
      this.cancellationPersistence.reject(error);
      throw error;
    }
    return await this.settled();
  }

  failExternallyPersisted(reason: string): void {
    if (this.externallyFailed || this.terminal) return;
    this.externallyFailed = true;
    this.state = { ...this.state, status: "failed", error: reason };
    this.log({ event: "coordinator_external_failure", scanId: this.state.scanId, reason });
    this.abortController.abort(reason);
    this.publicationAbortController.abort(reason);
    // The caller already persisted this failure. Keep that stable state while
    // run() waits for workers instead of rewriting it as cancellation.
  }

  private async run(): Promise<void> {
    try {
      await ensureDeepScanDirectories(this.artifacts);
      if (this.canceled || this.externallyFailed) return;

      this.phase = "discovery";
      const schedulerResult = await this.runScheduler();
      if (this.canceled || this.externallyFailed) return;
      this.phase = "terminal";
      const draft = schedulerResult.result
        ? {
            ...structuredClone(schedulerResult.result),
            // Readers require coverage.json. The coordinator has accepted this
            // result, so mark it complete and leave review notes empty.
            coverage: {
              completeness: "complete",
              surfaces: [],
              explicitExclusions: [],
              deferred: []
            }
          }
        : scanDraftInputSchema.parse({
            scanId: this.state.scanId,
            findings: [],
            coverage: {
              completeness: "partial",
              surfaces: [],
              explicitExclusions: [],
              deferred: [{
                reason: "The configured discovery time limit elapsed before any source review completed."
              }]
            }
          });
      if (draft.scanId !== this.state.scanId) {
        throw new Error("Deep Scan aggregate does not match its authoritative scan identity.");
      }
      await this.options.onComplete?.(draft, this.publicationAbortController.signal);
      if (this.canceled || this.externallyFailed) return;
      this.state = await this.finishWithReplay(schedulerResult);
      if (this.canceled || this.externallyFailed) return;
      this.log({
        event: "coordinator_terminal",
        scanId: this.state.scanId,
        reason: schedulerResult.reason
      });
      this.finishLocally(this.state);
    } catch (error) {
      if (this.canceled || this.externallyFailed) {
        await this.settleSchedulerWork();
        return;
      }
      if (await this.stopAfterOwnershipChange(
        this.options.threadId,
        isStaleCoordinatorGenerationError(error)
      )) {
        await this.settleSchedulerWork();
        return;
      }
      const message = errorMessage(error);
      const persistedMessage = boundedDeepScanErrorMessage(error);
      if (this.phase === "setup") {
        this.log({ event: "setup_failed", scanId: this.state.scanId, reason: errorKind(error) });
      }
      this.abortController.abort(message);
      await this.settleSchedulerWork();
      try {
        this.state = await this.options.store.fail(
          this.state.scanId,
          persistedMessage,
          "failed"
        );
      } catch (persistError) {
        this.state = { ...this.state, status: "failed", error: persistedMessage };
        this.log({
          event: "coordinator_failure_persistence_error",
          scanId: this.state.scanId,
          reason: errorKind(persistError)
        });
      }
      this.log({
        event: "coordinator_failed",
        scanId: this.state.scanId,
        reason: errorKind(error)
      });
    } finally {
      // A worker can finish an atomic draft write while cancellation is being
      // persisted. Publish saved output only after every local writer settles.
      await this.settleSchedulerWork();
      this.resolveCancellationReady();
      await this.cancellationPersistence?.promise;
      if (this.options.onStopped && this.options.threadId) {
        let current: DeepScanRunState | undefined;
        try {
          current = await this.options.store.get(this.state.scanId, this.options.threadId);
        } catch (error) {
          this.log({
            event: "coordinator_terminal_state_read_failed",
            scanId: this.state.scanId,
            reason: errorKind(error)
          });
        }
        if (
          current
          && (current.status === "failed" || current.status === "canceled")
          && current.coordinatorGeneration === this.options.run.coordinatorGeneration
        ) {
          try {
            await this.options.onStopped(current);
          } catch (error) {
            const publicationFailure = boundedDeepScanErrorMessage(
              `Saved result publication failed: ${boundedDeepScanErrorMessage(error)}`,
            );
            const originalFailure = current.error?.trim();
            const diagnostic = originalFailure
              ? boundedDeepScanErrorPair(
                publicationFailure,
                "\nOriginal Deep Scan failure:\n",
                originalFailure
              )
              : publicationFailure;
            const localState = {
              ...this.state,
              error: diagnostic
            };
            try {
              this.state = await this.options.store.recordStoppedPublicationFailure(
                this.state.scanId,
                publicationFailure,
                current.coordinatorGeneration
              );
            } catch (persistError) {
              this.state = localState;
              this.log({
                event: "coordinator_result_preservation_failure_persistence_error",
                scanId: this.state.scanId,
                reason: errorKind(persistError)
              });
            }
            this.log({
              event: "coordinator_result_preservation_failed",
              scanId: this.state.scanId,
              reason: errorKind(error)
            });
          }
        }
      }
      if (this.canceled || this.externallyFailed) {
        this.log({ event: "coordinator_cleanup_settled", scanId: this.state.scanId });
      }
      if (this.canceled) this.state = { ...this.state, status: "canceled" };
      this.finishLocally(this.state);
    }
  }

  private finishLocally(state: DeepScanRunState): void {
    if (this.terminal) return;
    this.terminal = true;
    if (this.heartbeatTimeout !== undefined) {
      clearTimeout(this.heartbeatTimeout);
      this.heartbeatTimeout = undefined;
    }
    if (this.discoveryTimeout !== undefined) {
      clearTimeout(this.discoveryTimeout);
      this.discoveryTimeout = undefined;
    }
    this.resolveTerminal(cloneState(state));
  }

  private failLocally(error: unknown): void {
    if (this.terminal) return;
    this.terminal = true;
    if (this.heartbeatTimeout !== undefined) {
      clearTimeout(this.heartbeatTimeout);
      this.heartbeatTimeout = undefined;
    }
    if (this.discoveryTimeout !== undefined) {
      clearTimeout(this.discoveryTimeout);
      this.discoveryTimeout = undefined;
    }
    this.rejectTerminal(error);
  }

  private scheduleDiscoveryDeadline(): void {
    const now = this.clock.now();
    const createdAt = this.state.createdAt === undefined
      ? now
      : Date.parse(this.state.createdAt);
    const startedAt = Number.isFinite(createdAt) ? createdAt : now;
    const discoveryTimeoutMs = this.options.discoveryTimeoutMs
      ?? (this.state.config.maxTimeHours ?? DEFAULT_DISCOVERY_TIMEOUT_HOURS) * 60 * 60 * 1_000;
    const remainingMs = startedAt + discoveryTimeoutMs - now;
    if (remainingMs <= 0) {
      this.stopDiscoveryAtDeadline();
      return;
    }
    this.discoveryTimeout = setTimeout(() => {
      this.discoveryTimeout = undefined;
      this.stopDiscoveryAtDeadline();
    }, remainingMs);
    this.discoveryTimeout.unref?.();
  }

  private stopDiscoveryAtDeadline(): void {
    if (this.terminal || this.discoveryDeadlineReached) return;
    this.discoveryDeadlineReached = true;
    this.log({ event: "discovery_deadline_reached", scanId: this.state.scanId });
    this.discoveryAbortController.abort("deep_scan_discovery_deadline_reached");
  }

  private scheduleHeartbeat(): void {
    if (
      this.terminal
      || !this.options.threadId
      || !this.state.coordinatorGeneration
    ) {
      return;
    }
    this.heartbeatTimeout = setTimeout(() => {
      void this.renewHeartbeat();
    }, this.options.heartbeatIntervalMs ?? COORDINATOR_HEARTBEAT_INTERVAL_MS);
    this.heartbeatTimeout.unref?.();
  }

  private async renewHeartbeat(): Promise<void> {
    const threadId = this.options.threadId;
    if (this.terminal || !threadId) return;
    try {
      const renewed = await this.options.store.heartbeatCoordinator({
        scanId: this.state.scanId,
        threadId,
        handoffClaimToken: this.options.handoffClaimToken
      });
      this.state = {
        ...this.state,
        updatedAt: renewed.updatedAt
      };
    } catch (error) {
      this.log({
        event: "coordinator_heartbeat_failed",
        scanId: this.state.scanId,
        reason: errorKind(error)
      });
    }
    this.scheduleHeartbeat();
    if (this.terminal || this.ownershipCheck) return;
    const ownershipCheck = this.stopAfterOwnershipChange(threadId, false);
    this.ownershipCheck = ownershipCheck;
    try {
      await ownershipCheck;
    } finally {
      if (this.ownershipCheck === ownershipCheck) this.ownershipCheck = undefined;
    }
  }

  private async stopAfterOwnershipChange(
    threadId: string | undefined,
    leaseLossConfirmed: boolean
  ): Promise<boolean> {
    if (this.externallyFailed || this.terminal || !threadId) return this.externallyFailed;
    let current: DeepScanRunState;
    try {
      current = await this.options.store.get(this.state.scanId, threadId);
    } catch (readError) {
      this.log({
        event: "coordinator_ownership_read_failed",
        scanId: this.state.scanId,
        reason: errorKind(readError)
      });
      if (!leaseLossConfirmed) return false;
      current = this.state;
    }
    const replacementConfirmed = leaseLossConfirmed || (
      current.status === "running"
      && current.coordinatorGeneration !== undefined
      && this.state.coordinatorGeneration !== undefined
      && current.coordinatorGeneration > this.state.coordinatorGeneration
    );
    if (current.status === "running" && !replacementConfirmed) return false;

    this.externallyFailed = true;
    this.abortController.abort("deep_scan_coordinator_lease_lost");
    this.publicationAbortController.abort("deep_scan_coordinator_lease_lost");
    if (replacementConfirmed && this.options.observeReplacement) {
      try {
        this.state = await this.options.observeReplacement(current);
      } catch (observeError) {
        this.log({
          event: "coordinator_replacement_observation_failed",
          scanId: this.state.scanId,
          reason: errorKind(observeError)
        });
        this.state = {
          ...current,
          status: "failed",
          error: `Deep Scan replacement observation failed: ${errorMessage(observeError)}`
        };
      }
    } else {
      this.state = current;
    }
    this.finishLocally(this.state);
    return true;
  }

  /**
   * Keep the discovery pool full until the reducer establishes convergence or
   * the configured run cap is exhausted. Completed discoveries enter a stable
   * FIFO buffer. One reducer claims the current buffer snapshot; discoveries
   * that finish during that reduction wait for the next one.
   */
  private async runScheduler(): Promise<SchedulerResult> {
    const config = this.state.config;
    const active = new Map<string, Promise<DiscoveryOutcome>>();
    const recovered = await this.recoverAcceptedDiscoveries();
    const accepted: AcceptedDiscovery[] = [...recovered];
    const mergedIds = new Set(
      (this.state.persistedWorkers ?? [])
        .filter((worker) => worker.kind === "discovery" && worker.mergeState === "merged")
        .map((worker) => worker.id)
    );
    const mergedDiscoveries: AcceptedDiscovery[] = recovered.filter((worker) => (
      mergedIds.has(worker.id)
    ));
    const canceledWorkerIds = (this.state.persistedWorkers ?? [])
      .filter((worker) => worker.kind === "discovery" && worker.status === "canceled")
      .map((worker) => worker.id);
    const omittedWorkerIds: string[] = [];
    this.audit.accepted = [...accepted];
    this.audit.mergedWorkerIds = mergedDiscoveries.map((worker) => worker.id);
    this.audit.canceledWorkerIds = [...canceledWorkerIds];
    this.audit.executions = await this.recoverPersistedExecutions();
    const recoveredReducers = await this.recoverCompletedReducers(recovered);
    const reducerOutcomes = recoveredReducers.reducers;
    let latestResult = recoveredReducers.result;
    let buffer: AcceptedDiscovery[] = recovered.filter((worker) => !mergedIds.has(worker.id));
    let reducer: Promise<DedupOutcome> | undefined;
    let previousReducerResultPath = reducerOutcomes.at(-1)?.resultPath;
    let dispatched = this.state.dispatchedCount;
    let workerSequence = Math.max(
      dispatched,
      ...(this.state.persistedWorkers ?? [])
        .filter((worker) => worker.kind === "discovery")
        .map((worker) => workerLabelSequence(worker, "discovery"))
    );
    let reducerSequence = Math.max(
      0,
      ...(this.state.persistedWorkers ?? [])
        .filter((worker) => worker.kind === "dedup")
        .map((worker) => workerLabelSequence(worker, "dedup"))
    );
    let stopReason: DeepScanTerminalReason | undefined;
    let lastReplaceableFailure: Extract<DiscoveryOutcome, { status: "failed" }> | undefined;

    this.audit.bufferedWorkerIds = buffer.map((worker) => worker.id);
    this.audit.reducers = [...reducerOutcomes];
    const errorLimit = config.stopAfterConsecutiveErrors ?? config.stopAfterNoNew;
    let reducerFailures = persistedReducerFailureStreak(this.state.persistedWorkers ?? []);
    if (this.state.consecutiveErrors >= errorLimit) {
      const failure = latestPersistedReplaceableFailure(this.state.persistedWorkers ?? []);
      throw discoveryErrorLimitError(
        this.state.consecutiveErrors,
        errorLimit,
        failure?.kind ?? "transient_error",
        failure?.message ?? "persisted failure evidence is unavailable"
      );
    }
    if (reducerFailures >= errorLimit) {
      const failure = [...(this.state.persistedWorkers ?? [])]
        .reverse()
        .find((worker) => worker.kind === "dedup" && worker.status === "failed");
      throw reducerErrorLimitError(
        reducerFailures,
        errorLimit,
        failure?.error ?? "persisted reducer failure evidence is unavailable"
      );
    }
    if (
      !this.discoveryDeadlineReached
      && previousReducerResultPath
      && this.state.noNewStreak >= config.stopAfterNoNew
      && buffer.length === 0
    ) {
      stopReason = "saturated";
    }

    // Each worker or reducer appends one entry. Reading this FIFO preserves real
    // completion order; rebuilding Promise.race from fulfilled promises could
    // otherwise let discoveries repeatedly jump ahead of a finished reducer.
    const settlements: SchedulerSettlement[] = [];
    let wakeScheduler: (() => void) | undefined;
    const observe = (promise: Promise<SchedulerOutcome>): void => {
      void promise.then(
        (outcome) => {
          settlements.push({ status: "fulfilled", outcome });
          wakeScheduler?.();
          wakeScheduler = undefined;
        },
        (error: unknown) => {
          settlements.push({ status: "rejected", error });
          wakeScheduler?.();
          wakeScheduler = undefined;
        }
      );
    };
    const nextSettlement = async (): Promise<SchedulerSettlement> => {
      if (settlements.length === 0) {
        await new Promise<void>((resolvePromise) => {
          wakeScheduler = resolvePromise;
        });
      }
      const settlement = settlements.shift();
      if (!settlement) throw new Error("Deep Scan scheduler woke without a settled task.");
      return settlement;
    };
    const reconcileRemainingDiscoveries = async (
      succeededState: "buffered" | "omitted"
    ): Promise<unknown | undefined> => {
      const entries = [...active.entries()];
      const results = await Promise.allSettled(entries.map(([, promise]) => promise));
      let firstFailure: unknown | undefined;
      for (const [index, result] of results.entries()) {
        const workerId = entries[index]?.[0];
        if (workerId) active.delete(workerId);
        if (result.status === "rejected") {
          if (workerId) removeValue(canceledWorkerIds, workerId);
          firstFailure ??= result.reason;
          continue;
        }
        const outcome = result.value;
        if (outcome.status === "failed") {
          if (outcome.replaceableFailureKind) {
            canceledWorkerIds.push(outcome.workerId);
          } else {
            removeValue(canceledWorkerIds, outcome.workerId);
            firstFailure ??= outcome.error;
          }
        } else if (outcome.status === "succeeded") {
          if (!accepted.some((worker) => worker.id === outcome.worker.id)) {
            accepted.push(outcome.worker);
          }
          if (succeededState === "omitted") {
            omittedWorkerIds.push(outcome.worker.id);
          } else if (!buffer.some((worker) => worker.id === outcome.worker.id)) {
            buffer.push(outcome.worker);
          }
          removeValue(canceledWorkerIds, outcome.worker.id);
        } else {
          canceledWorkerIds.push(outcome.workerId);
        }
      }
      this.audit.accepted = [...accepted];
      this.audit.omittedWorkerIds = unique(omittedWorkerIds);
      this.audit.canceledWorkerIds = unique(canceledWorkerIds);
      this.audit.bufferedWorkerIds = buffer.map((worker) => worker.id);
      return firstFailure;
    };
    const reconcileReducerSettlement = async (): Promise<unknown | undefined> => {
      if (!reducer) return undefined;
      const pendingReducer = reducer;
      reducer = undefined;
      const [result] = await Promise.allSettled([pendingReducer]);
      if (!result || result.status === "rejected") {
        return result?.status === "rejected" ? result.reason : undefined;
      }
      const outcome = result.value;
      if ("status" in outcome) {
        buffer = [...outcome.consumed, ...buffer].sort(compareCompletionSequence);
        this.audit.bufferedWorkerIds = buffer.map((worker) => worker.id);
        return outcome.error;
      }
      this.state = outcome.run;
      previousReducerResultPath = outcome.resultPath;
      mergedDiscoveries.push(...outcome.consumed);
      const { result: acceptedResult, ...metadata } = outcome;
      latestResult = acceptedResult;
      reducerOutcomes.push(metadata);
      this.audit.reducers = [...reducerOutcomes];
      this.audit.mergedWorkerIds = unique(mergedDiscoveries.map((worker) => worker.id));
      this.audit.bufferedWorkerIds = buffer.map((worker) => worker.id);
      return undefined;
    };

    await this.options.store.updateProgress({
      scanId: this.state.scanId,
      phase: "discovery",
      handoffClaimToken: this.options.handoffClaimToken
    });
    this.logProgress(accepted.length);

    while (!stopReason) {
      if (this.abortController.signal.aborted) {
        await Promise.allSettled([...active.values(), ...(reducer ? [reducer] : [])]);
        throw abortError(this.abortController.signal.reason);
      }
      if (settlements.length === 0) {
        while (
          !this.discoveryDeadlineReached
          && (!previousReducerResultPath || this.state.noNewStreak < config.stopAfterNoNew)
          && active.size < config.workers
          && dispatched < config.maxDiscoveryRuns
        ) {
          dispatched += 1;
          workerSequence += 1;
          const workerLabel = `discovery-${String(workerSequence).padStart(4, "0")}`;
          const workerId = randomUUID();
          const workerPromise = this.trackSchedulerWork(
            this.discoveryWorkers.runDiscoveryWorker(workerId, workerLabel)
          );
          active.set(workerId, workerPromise);
          observe(workerPromise);
          this.state = { ...this.state, dispatchedCount: dispatched };
        }

        if (!reducer && this.reducerReady(
          buffer,
          previousReducerResultPath,
          active.size,
          dispatched
        )) {
          const consumed = [...buffer].sort(compareCompletionSequence);
          buffer = [];
          reducerSequence += 1;
          reducer = this.trackSchedulerWork(this.workers.runReducer({
            id: randomUUID(),
            label: `dedup-${String(reducerSequence).padStart(4, "0")}`,
            consumed,
            previousReducerResultPath
          }));
          observe(reducer);
        }
      }

      if (active.size === 0 && !reducer) {
        if (buffer.length > 0) continue;
        if (!previousReducerResultPath && lastReplaceableFailure) {
          throw new Error(
            "Deep Scan reached its configured discovery limit without accepting a "
              + "complete discovery; last failure "
              + `(${lastReplaceableFailure.replaceableFailureKind}): `
              + lastReplaceableFailure.error.message,
            { cause: lastReplaceableFailure.error }
          );
        }
        stopReason = "capped";
        break;
      }

      const settlement = await nextSettlement();
      if (settlement.status === "rejected") {
        this.abortController.abort(errorMessage(settlement.error));
        await reconcileReducerSettlement();
        await reconcileRemainingDiscoveries("buffered");
        throw settlement.error;
      }
      const outcome = settlement.outcome;
      if (outcome.type === "discovery") {
        active.delete(outcome.status === "succeeded" ? outcome.worker.id : outcome.workerId);
        if (outcome.status === "failed") {
          if (outcome.replaceableFailureKind) {
            lastReplaceableFailure = outcome;
            const consecutiveErrors = outcome.consecutiveErrors
              ?? (this.state.consecutiveErrors ?? 0) + 1;
            this.state = { ...this.state, consecutiveErrors };
            canceledWorkerIds.push(outcome.workerId);
            this.audit.canceledWorkerIds = unique(canceledWorkerIds);
            this.log({
              event: "discovery_worker_replaced",
              scanId: this.state.scanId,
              workerId: outcome.workerId,
              reason: outcome.replaceableFailureKind,
              count: consecutiveErrors
            });
            if (consecutiveErrors < errorLimit) continue;
            const thresholdError = discoveryErrorLimitError(
              consecutiveErrors,
              errorLimit,
              outcome.replaceableFailureKind,
              outcome.error.message,
              outcome.error
            );
            this.abortController.abort(thresholdError.message);
            await reconcileReducerSettlement();
            await reconcileRemainingDiscoveries("buffered");
            throw thresholdError;
          }
          this.abortController.abort(outcome.error.message);
          await reconcileReducerSettlement();
          await reconcileRemainingDiscoveries("buffered");
          throw outcome.error;
        }
        if (outcome.status === "canceled") {
          canceledWorkerIds.push(outcome.workerId);
          this.audit.canceledWorkerIds = unique(canceledWorkerIds);
          if (
            !this.abortController.signal.aborted
            && !this.discoveryAbortController.signal.aborted
          ) {
            throw new Error(`Discovery worker ${outcome.workerId} was canceled unexpectedly.`);
          }
          continue;
        }
        accepted.push(outcome.worker);
        this.state = { ...this.state, consecutiveErrors: 0 };
        buffer.push(outcome.worker);
        this.audit.accepted = [...accepted];
        this.audit.bufferedWorkerIds = buffer.map((worker) => worker.id);
        this.logProgress(accepted.length);
        continue;
      }

      reducer = undefined;
      if ("status" in outcome) {
        buffer = [...outcome.consumed, ...buffer].sort(compareCompletionSequence);
        this.audit.bufferedWorkerIds = buffer.map((worker) => worker.id);
        reducerFailures += 1;
        this.log({
          event: "dedup_worker_replaced",
          scanId: this.state.scanId,
          workerId: outcome.id,
          reason: errorKind(outcome.error),
          count: reducerFailures
        });
        if (reducerFailures < errorLimit) continue;
        const thresholdError = reducerErrorLimitError(
          reducerFailures,
          errorLimit,
          outcome.error.message,
          outcome.error
        );
        this.abortController.abort(thresholdError.message);
        await reconcileRemainingDiscoveries("buffered");
        throw thresholdError;
      }
      reducerFailures = 0;
      this.state = outcome.run;
      previousReducerResultPath = outcome.resultPath;
      mergedDiscoveries.push(...outcome.consumed);
      const { result: acceptedResult, ...metadata } = outcome;
      latestResult = acceptedResult;
      reducerOutcomes.push(metadata);
      this.audit.reducers = [...reducerOutcomes];
      this.audit.mergedWorkerIds = unique(mergedDiscoveries.map((worker) => worker.id));
      this.audit.bufferedWorkerIds = buffer.map((worker) => worker.id);
      if (
        !this.discoveryDeadlineReached
        && outcome.run.noNewStreak >= config.stopAfterNoNew
        && buffer.length === 0
      ) {
        stopReason = "saturated";
        canceledWorkerIds.push(...active.keys());
        this.audit.canceledWorkerIds = unique(canceledWorkerIds);
        this.audit.bufferedWorkerIds = [];
        this.abortController.abort("deep_scan_saturated");
      }
    }

    // Convergence cancels active workers, but their promises must settle before
    // the manifest records which results completed and which were canceled.
    const lateFailure = await reconcileRemainingDiscoveries("omitted");

    this.audit.accepted = [...accepted];
    this.audit.mergedWorkerIds = unique(mergedDiscoveries.map((worker) => worker.id));
    this.audit.omittedWorkerIds = unique(omittedWorkerIds);
    this.audit.canceledWorkerIds = unique(canceledWorkerIds);
    this.audit.bufferedWorkerIds = buffer.map((worker) => worker.id);

    // Once Deep reaches saturation, late worker errors cannot fail the scan.
    if (lateFailure && stopReason !== "saturated") throw lateFailure;

    if (
      !previousReducerResultPath
      && !(this.discoveryDeadlineReached && accepted.length === 0)
    ) {
      throw new Error("Deep Scan ended without a successfully reduced Standard scan.");
    }
    return {
      reason: stopReason ?? "capped",
      omittedWorkerIds: unique(omittedWorkerIds),
      canceledWorkerIds: unique(canceledWorkerIds),
      accepted,
      mergedWorkerIds: unique(mergedDiscoveries.map((worker) => worker.id)),
      reducers: reducerOutcomes,
      result: latestResult,
    };
  }

  private async recoverAcceptedDiscoveries(): Promise<AcceptedDiscovery[]> {
    const recovered: AcceptedDiscovery[] = [];
    for (const worker of this.state.persistedWorkers ?? []) {
      if (worker.kind !== "discovery" || worker.status !== "succeeded") continue;
      if (!worker.resultManifestPath || !worker.completionSequence) {
        throw new Error(`Accepted discovery ${worker.id} has incomplete persisted evidence.`);
      }
      await validateDiscoveryArtifacts(
        this.artifacts,
        worker.resultManifestPath,
        this.state.scanId
      );
      const evidence = await persistedWorkerEvidence(worker);
      recovered.push({
        id: worker.id,
        label: basename(dirname(worker.promptPath)),
        artifactDir: worker.artifactDir,
        resultPath: worker.resultManifestPath,
        completionSequence: worker.completionSequence,
        attempt: worker.attempt,
        ...(worker.threadId ? { threadId: worker.threadId } : {}),
        ...evidence
      });
    }
    return recovered.sort(compareCompletionSequence);
  }

  private async recoverCompletedReducers(
    discoveries: AcceptedDiscovery[]
  ): Promise<{ reducers: AcceptedReducer[]; result?: DeepReductionInput }> {
    const discoveriesById = new Map(discoveries.map((worker) => [worker.id, worker]));
    const inputs = this.state.persistedDedupInputs ?? [];
    const outcomes: AcceptedReducer[] = [];
    let latestResult: DeepReductionInput | undefined;
    const completedReducers = (this.state.persistedWorkers ?? [])
      .filter((worker) => worker.kind === "dedup" && worker.status === "succeeded")
      .sort((left, right) => (
        workerLabelSequence(left, "dedup") - workerLabelSequence(right, "dedup")
        || left.id.localeCompare(right.id)
      ));
    let noNewStreak = 0;
    for (const worker of completedReducers) {
      if (!worker.resultManifestPath) {
        throw new Error(`Completed reducer ${worker.id} has no persisted result manifest.`);
      }
      const consumed = inputs
        .filter((input) => input.dedupWorkerId === worker.id)
        .sort((left, right) => left.inputOrder - right.inputOrder)
        .map((input) => discoveriesById.get(input.discoveryWorkerId));
      if (consumed.length === 0 || consumed.some((value) => !value)) {
        throw new Error(`Completed reducer ${worker.id} has incomplete persisted inputs.`);
      }
      const accepted = consumed as AcceptedDiscovery[];
      const { newFindings, result } = await validateReducerArtifacts({
        artifacts: this.artifacts,
        artifactDir: worker.artifactDir,
        resultPath: worker.resultManifestPath,
        reducerId: worker.id,
        previousReducerResultPath: outcomes.at(-1)?.resultPath
      }, this.state.scanId);
      latestResult = result;
      noNewStreak = newFindings > 0 ? 0 : noNewStreak + accepted.length;
      const evidence = await persistedWorkerEvidence(worker);
      outcomes.push({
        type: "dedup",
        id: worker.id,
        consumed: accepted,
        resultPath: worker.resultManifestPath,
        newFindings,
        attempt: worker.attempt,
        ...(worker.threadId ? { threadId: worker.threadId } : {}),
        ...evidence,
        run: { ...this.state, noNewStreak }
      });
    }
    return { reducers: outcomes, result: latestResult };
  }

  private async recoverPersistedExecutions(): Promise<WorkerExecutionAudit[]> {
    const executions: WorkerExecutionAudit[] = [];
    for (const worker of this.state.persistedWorkers ?? []) {
      if (
        worker.kind === "setup"
        || worker.status === "queued"
        || worker.status === "running"
        || (worker.status === "canceled" && worker.attempt === 0)
      ) {
        continue;
      }
      const replaceableFailure = persistedReplaceableFailure(worker);
      const status = replaceableFailure || worker.status === "failed"
        ? "failed"
        : worker.status;
      executions.push({
        id: worker.id,
        label: basename(dirname(worker.promptPath)),
        kind: worker.kind,
        status,
        attempt: worker.attempt,
        ...(worker.threadId ? { threadId: worker.threadId } : {}),
        promptPath: worker.promptPath,
        artifactDir: worker.artifactDir,
        ...await persistedWorkerEvidence(worker),
        ...(status === "failed" && worker.error
          ? { error: replaceableFailure?.message ?? worker.error }
          : {}),
        ...(replaceableFailure ? { failureKind: replaceableFailure.kind } : {})
      });
    }
    return executions;
  }

  private reducerReady(
    buffer: AcceptedDiscovery[],
    previousReducerResultPath: string | undefined,
    activeCount: number,
    dispatched: number
  ): boolean {
    if (buffer.length === 0) return false;
    // Two independent discoveries establish the first semantic reduction. A
    // later reduction or a final worker at the configured cap may stand alone.
    if (previousReducerResultPath) return true;
    if (buffer.length >= 2) return true;
    return activeCount === 0 && (
      dispatched >= this.state.config.maxDiscoveryRuns || this.discoveryDeadlineReached
    );
  }

  private trackSchedulerWork<T>(promise: Promise<T>): Promise<T> {
    this.schedulerWork.add(promise);
    void promise.then(
      () => this.schedulerWork.delete(promise),
      () => this.schedulerWork.delete(promise)
    );
    return promise;
  }

  private async settleSchedulerWork(): Promise<void> {
    await Promise.allSettled([...this.schedulerWork]);
  }

  private logProgress(count: number): void {
    this.log({
      event: "progress_updated",
      scanId: this.state.scanId,
      count,
      completed: count
    });
  }

  /**
   * A workbench process can commit SQLite and still lose its stdout response.
   * Replay the exact idempotent finish once before treating the run as failed;
   * otherwise we could overwrite a successful terminal state after durable success.
   */
  private async finishWithReplay(result: SchedulerResult): Promise<DeepScanRunState> {
    const input = {
      scanId: this.state.scanId,
      reason: result.reason,
      manifestPath: join(this.state.scanDir, "scan-manifest.json"),
      omittedWorkerIds: result.omittedWorkerIds
    };
    try {
      return await this.options.store.finish(input);
    } catch (firstError) {
      this.log({
        event: "coordinator_finish_replay",
        scanId: this.state.scanId,
        reason: errorKind(firstError)
      });
      try {
        return await this.options.store.finish(input);
      } catch (replayError) {
        throw new Error(
          `Deep Scan terminal persistence replay failed: ${errorMessage(replayError)}`,
          { cause: firstError }
        );
      }
    }
  }
}

const systemClock: DeepScanClock = {
  now: () => Date.now(),
  sleep: async (delayMs, signal) => {
    if (signal.aborted) throw abortError(signal.reason);
    await new Promise<void>((resolvePromise, rejectPromise) => {
      const timeout = setTimeout(() => {
        cleanup();
        resolvePromise();
      }, delayMs);
      const onAbort = (): void => {
        cleanup();
        rejectPromise(abortError(signal.reason));
      };
      const cleanup = (): void => {
        clearTimeout(timeout);
        signal.removeEventListener("abort", onAbort);
      };
      signal.addEventListener("abort", onAbort, { once: true });
    });
  }
};

function compareCompletionSequence(left: AcceptedDiscovery, right: AcceptedDiscovery): number {
  return left.completionSequence - right.completionSequence || left.id.localeCompare(right.id);
}

function workerLabelSequence(worker: PersistedDeepScanWorker, kind: "discovery" | "dedup"): number {
  const match = worker.promptPath.match(new RegExp(`${kind}-(\\d+)`));
  return match ? Number(match[1]) : 0;
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

function removeValue(values: string[], value: string): void {
  for (let index = values.length - 1; index >= 0; index -= 1) {
    if (values[index] === value) values.splice(index, 1);
  }
}

function cloneState(state: DeepScanRunState): DeepScanRunState {
  return { ...state, config: { ...state.config } };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function latestPersistedReplaceableFailure(
  workers: PersistedDeepScanWorker[]
): { kind: DeepScanReplaceableFailureKind; message: string } | undefined {
  for (const worker of [...workers].reverse()) {
    const failure = persistedReplaceableFailure(worker);
    if (failure) return failure;
  }
  return undefined;
}

function persistedReducerFailureStreak(workers: PersistedDeepScanWorker[]): number {
  let consecutiveFailures = 0;
  for (const worker of workers) {
    if (worker.kind !== "dedup") continue;
    if (worker.status === "succeeded") consecutiveFailures = 0;
    else if (worker.status === "failed") consecutiveFailures += 1;
  }
  return consecutiveFailures;
}

function persistedReplaceableFailure(
  worker: PersistedDeepScanWorker
): { kind: DeepScanReplaceableFailureKind; message: string } | undefined {
  if (worker.kind !== "discovery" || worker.status !== "canceled" || !worker.error) return undefined;
  const kinds: DeepScanReplaceableFailureKind[] = [
    "policy_refusal",
    "transient_error",
    "invalid_discovery_artifacts"
  ];
  for (const kind of kinds) {
    const prefix = `${kind}:`;
    if (worker.error.startsWith(prefix)) {
      return { kind, message: worker.error.slice(prefix.length).trim() };
    }
  }
  return undefined;
}

async function persistedWorkerEvidence(worker: PersistedDeepScanWorker): Promise<{
  basePromptSha256: string;
  attemptPromptPaths: string[];
}> {
  const attemptPromptPaths = [worker.promptPath];
  for (let attempt = 2; attempt <= worker.attempt; attempt += 1) {
    const promptPath = join(
      dirname(worker.promptPath),
      "prompts",
      `attempt-${String(attempt).padStart(2, "0")}.md`
    );
    try {
      await fs.access(promptPath);
      attemptPromptPaths.push(promptPath);
    } catch {
      // Transient execution retries reuse the original prompt.
    }
  }
  return {
    basePromptSha256: sha256(await fs.readFile(worker.promptPath, "utf8")),
    attemptPromptPaths
  };
}

function discoveryErrorLimitError(
  count: number,
  limit: number,
  kind: DeepScanReplaceableFailureKind,
  message: string,
  cause?: Error
): Error {
  const detail = `Deep Scan stopped after ${count} consecutive unsuccessful discovery workers `
    + `(limit: ${limit}); last failure (${kind}): ${message}`;
  return cause ? new Error(detail, { cause }) : new Error(detail);
}

function reducerErrorLimitError(
  count: number,
  limit: number,
  message: string,
  cause?: Error
): Error {
  const detail = `Deep Scan stopped after ${count} consecutive unsuccessful reducer workers `
    + `(limit: ${limit}); last failure: ${message}`;
  return cause ? new Error(detail, { cause }) : new Error(detail);
}

function errorKind(error: unknown): string {
  if (!(error instanceof Error)) return typeof error;
  const code = "code" in error && typeof error.code === "string" ? error.code : undefined;
  return code ? `${error.name}:${code}` : error.name;
}

function abortError(reason?: unknown): Error {
  const error = new Error("Deep Scan worker was aborted.", { cause: reason });
  error.name = "AbortError";
  return error;
}
