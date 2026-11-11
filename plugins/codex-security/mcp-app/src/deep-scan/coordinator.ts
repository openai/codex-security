/// <reference lib="es2023.array" />
import { randomUUID } from "node:crypto";
import { promises as fs } from "node:fs";
import { basename, dirname, join, relative, sep } from "node:path";
import {
  writeWorkerUsageReceipt,
  type WorkerUsageReceipt,
} from "./usage-receipt.js";
import { mergeBatch } from "./iteration.js";
import { setTimeout as delay } from "node:timers/promises";
import {
  createDeepScanArtifacts,
  ensureDeepScanDirectories,
  readJsonObject,
  requireRegularFile,
  writeJsonAtomic,
} from "./artifacts.js";
import {
  persistedScanUnion,
  parseScanUnion,
  addScanCoverage,
  parseStoredScanDraft,
  scanUnionToDraft,
  validateDiscoveryArtifacts,
  type ScanUnion,
} from "./artifact-validation.js";
import {
  scanDraftInputSchema,
  type DeepScanPublication,
  findingsWithinScope,
  type ScanDraftInput,
} from "../artifact-scan-draft.js";
import type { DeepScanArtifacts } from "./artifacts.js";
import { DeepScanWorkerRunner } from "./worker-runner.js";
import type { AcceptedDiscovery, DiscoveryOutcome } from "./worker-runner.js";
import {
  confirmedOwnershipChange,
  errorNameWithCode,
  abortError,
  errorMessage,
  deepScanErrorMessage,
  DeepScanNonRetryableError,
} from "./errors.js";
import type {
  CodexWorkerExecutor,
  DeepScanClock,
  DeepScanLogger,
  DeepScanReplaceableFailureKind,
  DeepScanRunState,
  DeepScanStore,
  DeepScanTerminalReason,
  PersistedDeepScanWorker,
} from "./types.js";

const RETRY_DELAYS_MS = [60_000, 180_000, 540_000] as const;
const COORDINATOR_HEARTBEAT_INTERVAL_MS = 5_000;
const DEFAULT_DISCOVERY_TIMEOUT_HOURS = 96;
const NO_REVIEW_BEFORE_DEADLINE =
  "The configured discovery time limit elapsed before any source review completed.";

interface LoopResult {
  reason: DeepScanTerminalReason;
  result?: ScanUnion;
  resultPath?: string;
}

export interface ParentScanState {
  status: string | undefined;
  failureMessage?: string;
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
  observeReplacement?: (
    run: DeepScanRunState,
    signal: AbortSignal,
  ) => Promise<DeepScanRunState>;
  checkFreshTarget?: (
    run: DeepScanRunState,
    signal: AbortSignal,
  ) => Promise<void>;
  onComplete?: (
    draft: ScanDraftInput,
    signal: AbortSignal,
    publication: DeepScanPublication,
  ) => Promise<void>;
  onStopped?: (run: DeepScanRunState) => Promise<void>;
  onStart?: (coordinator: DeepScanCoordinator) => void;
}

export { DeepScanNonRetryableError } from "./errors.js";

/** Runs independent Standard scans and publishes their union. */
export class DeepScanCoordinator {
  private readonly abortController = new AbortController();
  private readonly discoveryAbortController = new AbortController();
  private readonly publicationAbortController = new AbortController();
  private readonly observationAbortController = new AbortController();
  private readonly clock: DeepScanClock;
  private readonly log: DeepScanLogger;
  private readonly artifacts: DeepScanArtifacts;
  private readonly discoveryWorkers: DeepScanWorkerRunner;
  private readonly terminalResult: PromiseWithResolvers<DeepScanRunState>;
  private heartbeatTimeout: ReturnType<typeof setTimeout> | undefined;
  private discoveryTimeout: ReturnType<typeof setTimeout> | undefined;
  private ownershipCheck: Promise<boolean> | undefined;
  private readonly cancellationReady = Promise.withResolvers<void>();
  private cancellationPersistence?: {
    promise: Promise<void>;
    failure?: { error: unknown };
  };
  private started = false;
  private terminal = false;
  private canceled = false;
  private externallyFailed = false;
  private failurePersisted = false;
  private setupComplete = false;
  private discoveryDeadlineReached = false;
  private state: DeepScanRunState;

  constructor(private readonly options: CoordinatorOptions) {
    this.state = cloneState(options.run);
    this.clock = options.clock ?? systemClock;
    this.log = (event) => {
      try {
        void Promise.resolve(options.log?.(event)).catch(() => {});
      } catch {
        // Optional logging must not interrupt scan control flow.
      }
    };
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
      onNonRetryableError: (error: Error) => this.abortController.abort(error),
    } satisfies Omit<
      ConstructorParameters<typeof DeepScanWorkerRunner>[0],
      "signal"
    >;
    this.discoveryWorkers = new DeepScanWorkerRunner({
      ...workerOptions,
      signal: this.discoveryAbortController.signal,
    });
    this.abortController.signal.addEventListener(
      "abort",
      () => {
        this.discoveryAbortController.abort(this.abortController.signal.reason);
      },
      { once: true },
    );
    this.terminalResult = Promise.withResolvers<DeepScanRunState>();
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
        reason: errorKind(error),
      });
      if (this.stopLocally()) this.terminalResult.reject(error);
    });
  }

  get owningThreadId(): string | undefined {
    return this.options.threadId;
  }

  snapshot(): DeepScanRunState {
    return cloneState(this.state);
  }

  settled(): Promise<DeepScanRunState> {
    return this.terminalResult.promise.then(cloneState);
  }

  async wait(signal: AbortSignal | undefined): Promise<DeepScanRunState>;
  async wait(
    signal: AbortSignal | undefined,
    timeoutMs: number,
  ): Promise<DeepScanRunState | undefined>;
  async wait(
    signal: AbortSignal | undefined,
    timeoutMs?: number,
  ): Promise<DeepScanRunState | undefined> {
    if (this.terminal) return await this.settled();
    if (signal?.aborted) throw abortError(signal.reason);
    return await new Promise<DeepScanRunState | undefined>(
      (resolvePromise, rejectPromise) => {
        const timeout =
          timeoutMs === undefined
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
        void this.terminalResult.promise.then(
          (state) => {
            cleanup();
            resolvePromise(cloneState(state));
          },
          (error: unknown) => {
            cleanup();
            rejectPromise(error);
          },
        );
      },
    );
  }

  cancel(reason: string): void {
    if (this.canceled || this.terminal) return;
    this.canceled = true;
    this.state = { ...this.state, status: "canceled" };
    this.log({
      event: "coordinator_cancel_requested",
      scanId: this.state.scanId,
      reason,
    });
    this.abortController.abort(reason);
    this.publicationAbortController.abort(reason);
    this.observationAbortController.abort(reason);
    // The cancel operation returns promptly. Terminal waiters remain attached
    // until worker cleanup and stopped-result publication settle.
  }

  async cancelAfterPersistence(
    reason: string,
    persistCancellation: () => Promise<void>,
    readParentState: () => Promise<ParentScanState>,
  ): Promise<DeepScanRunState> {
    const existing = this.cancellationPersistence;
    if (existing) {
      try {
        await existing.promise;
      } catch (error) {
        if (existing.failure) await this.settled();
        throw error;
      }
      return await this.settled();
    }
    if (
      this.terminal ||
      this.canceled ||
      this.failurePersisted ||
      this.state.status === "canceled" ||
      this.state.status === "interrupted"
    )
      return await this.settled();
    const { promise, resolve, reject } = Promise.withResolvers<void>();
    // Cancellation callers share operation errors; terminal waiters inspect only
    // persistence failures below. Handle a rejection even with no joined caller.
    void promise.catch(() => {});
    const persistence: NonNullable<typeof this.cancellationPersistence> = {
      promise,
    };
    this.cancellationPersistence = persistence;
    try {
      const parent = await readParentState();
      const parentStatus = parent.status;
      if (parentStatus === "failed")
        this.failExternallyPersisted(parent.failureMessage);
      if (parentStatus === "canceled") this.cancel(reason);
      if (
        parentStatus === "running" &&
        !this.failurePersisted &&
        !["canceled", "interrupted"].includes(this.state.status)
      ) {
        // Terminal discovery has no active writers to stop. Keep its outcome
        // until the parent actually accepts cancellation.
        if (this.state.status === "running") this.cancel(reason);
        await this.cancellationReady.promise;
        if (!this.failurePersisted) {
          try {
            await persistCancellation();
            this.cancel(reason);
          } catch (error) {
            let parentStopped = false;
            if (this.state.status === "succeeded") {
              try {
                parentStopped = ["complete", "failed"].includes(
                  (await readParentState()).status ?? "",
                );
              } catch {
                // Preserve the cancellation diagnostic if reconciliation fails.
              }
            }
            if (!parentStopped) persistence.failure = { error };
            throw error;
          }
        }
      }
    } catch (error) {
      reject(error);
      if (!persistence.failure) {
        this.cancellationPersistence = undefined;
        throw error;
      }
    } finally {
      // Cleanup still inspects durable state and preserves results when the
      // process lost a committed response, then reports the persistence failure.
      resolve();
    }
    const settled = await this.settled();
    if (persistence.failure) throw persistence.failure.error;
    return settled;
  }

  failExternallyPersisted(reason: string | undefined): void {
    if (this.externallyFailed || this.terminal) return;
    this.externallyFailed = true;
    this.failurePersisted = true;
    this.state = { ...this.state, status: "failed", error: reason };
    this.log({
      event: "coordinator_external_failure",
      scanId: this.state.scanId,
      reason,
    });
    this.abortController.abort(reason);
    this.publicationAbortController.abort(reason);
    // The caller already persisted this failure. Keep that stable state while
    // run() waits for workers instead of rewriting it as cancellation.
  }

  private async run(): Promise<void> {
    try {
      // A replacement coordinator must honor a worker failure committed before handoff.
      if (this.state.error) throw new Error(this.state.error);
      await ensureDeepScanDirectories(this.artifacts);
      if (this.canceled || this.externallyFailed) return;

      if (this.options.checkFreshTarget && isFreshRun(this.state)) {
        await this.options.checkFreshTarget(
          this.state,
          this.discoveryAbortController.signal,
        );
      }
      if (this.canceled || this.externallyFailed) return;

      this.setupComplete = true;
      const loopResult = await this.runIterations();
      if (this.canceled || this.externallyFailed) return;
      this.abortController.signal.throwIfAborted();
      const draft = loopResult.result
        ? scanUnionToDraft(loopResult.result)
        : scanDraftInputSchema.parse({
            scanId: this.state.scanId,
            findings: [],
            scope: { limitations: [NO_REVIEW_BEFORE_DEADLINE] },
            reviewState: {
              surfaces: [],
              explicitExclusions: [],
              deferred: [{ reason: NO_REVIEW_BEFORE_DEADLINE }],
            },
          });
      if (draft.scanId !== this.state.scanId) {
        throw new Error(
          "Deep Scan aggregate does not match its authoritative scan identity.",
        );
      }
      // Publish the current scope without rewriting accepted source artifacts.
      draft.findings = findingsWithinScope(
        draft.findings,
        this.state.includePaths ?? [this.state.scope],
        this.state.filePaths,
      );
      await this.options.onComplete?.(
        draft,
        this.publicationAbortController.signal,
        {
          coordinatorGeneration: this.state.coordinatorGeneration,
          resultPath: loopResult.resultPath ?? null,
        },
      );
      if (this.canceled || this.externallyFailed) return;
      const completed = await this.options.store.finish({
        scanId: this.state.scanId,
        reason: loopResult.reason,
        manifestPath: join(this.state.scanDir, "scan-manifest.json"),
        omittedWorkerIds: [],
      });
      if (this.canceled || this.externallyFailed) return;
      this.state = completed;
      this.log({
        event: "coordinator_terminal",
        scanId: this.state.scanId,
        reason: loopResult.reason,
      });
    } catch (error) {
      if (this.canceled || this.externallyFailed) {
        return;
      }
      if (await this.stopAfterOwnershipChange(this.options.threadId, error)) {
        return;
      }
      if (
        this.abortController.signal.reason instanceof DeepScanNonRetryableError
      ) {
        error = this.abortController.signal.reason;
      }
      const message = errorMessage(error);
      const persistedMessage = deepScanErrorMessage(error);
      if (!this.setupComplete && !this.state.error) {
        this.log({
          event: "setup_failed",
          scanId: this.state.scanId,
          reason: errorKind(error),
        });
      }
      this.abortController.abort(message);
      if (this.canceled || this.externallyFailed) return;
      try {
        const failed = await this.options.store.fail(
          this.state.scanId,
          persistedMessage,
          "failed",
        );
        if (this.canceled || this.externallyFailed) return;
        this.state = failed;
        this.failurePersisted ||= this.state.status === "failed";
      } catch (persistError) {
        if (this.canceled || this.externallyFailed) return;
        if (
          confirmedOwnershipChange(persistError, this.state.scanId) &&
          (await this.stopAfterOwnershipChange(
            this.options.threadId,
            persistError,
          ))
        )
          return;
        this.state = {
          ...this.state,
          status: "failed",
          error: persistedMessage,
        };
        this.log({
          event: "coordinator_failure_persistence_error",
          scanId: this.state.scanId,
          reason: errorKind(persistError),
        });
      }
      this.log({
        event: "coordinator_failed",
        scanId: this.state.scanId,
        reason: errorKind(error),
      });
    } finally {
      // A worker can finish an atomic draft write while cancellation is being
      // persisted. Publish saved output only after every local writer settles.
      await this.ownershipCheck;
      this.cancellationReady.resolve();
      if (this.options.onStopped && this.options.threadId) {
        let current: DeepScanRunState | undefined;
        let persistence: Promise<void> | undefined;
        do {
          persistence = this.cancellationPersistence?.promise;
          await persistence?.catch(() => {});
          current = undefined;
          try {
            current = await this.options.store.get(
              this.state.scanId,
              this.options.threadId,
            );
          } catch (error) {
            this.log({
              event: "coordinator_terminal_state_read_failed",
              scanId: this.state.scanId,
              reason: errorKind(error),
            });
          }
        } while (persistence !== this.cancellationPersistence?.promise);
        if (current?.status === "failed" || current?.status === "canceled") {
          this.state = current;
          this.failurePersisted = current.status === "failed";
        }
        if (
          current &&
          (current.status === "failed" || current.status === "canceled") &&
          current.coordinatorGeneration ===
            this.options.run.coordinatorGeneration
        ) {
          try {
            await this.options.onStopped(current);
          } catch (error) {
            const publicationFailure = `Saved result publication failed: ${deepScanErrorMessage(error)}`;
            const originalFailure = current.error?.trim();
            const diagnostic = originalFailure
              ? `${publicationFailure}\nOriginal Deep Scan failure:\n${originalFailure}`
              : publicationFailure;
            const localState = {
              ...this.state,
              error: diagnostic,
            };
            try {
              this.state =
                await this.options.store.recordStoppedPublicationFailure(
                  this.state.scanId,
                  publicationFailure,
                  current.coordinatorGeneration,
                );
            } catch (persistError) {
              this.state = localState;
              this.log({
                event:
                  "coordinator_result_preservation_failure_persistence_error",
                scanId: this.state.scanId,
                reason: errorKind(persistError),
              });
            }
            this.log({
              event: "coordinator_result_preservation_failed",
              scanId: this.state.scanId,
              reason: errorKind(error),
            });
          }
        }
      }
      if (this.canceled || this.externallyFailed) {
        this.log({
          event: "coordinator_cleanup_settled",
          scanId: this.state.scanId,
        });
      }
      if (this.cancellationPersistence)
        await this.cancellationPersistence.promise.catch(() => {});
      if (this.cancellationPersistence?.failure && !this.failurePersisted) {
        throw this.cancellationPersistence.failure.error;
      }
      if (this.canceled && !this.failurePersisted)
        this.state = { ...this.state, status: "canceled" };
      if (this.stopLocally())
        this.terminalResult.resolve(cloneState(this.state));
    }
  }

  private stopLocally(): boolean {
    if (this.terminal) return false;
    this.terminal = true;
    clearTimeout(this.heartbeatTimeout);
    this.heartbeatTimeout = undefined;
    clearTimeout(this.discoveryTimeout);
    this.discoveryTimeout = undefined;
    return true;
  }

  private scheduleDiscoveryDeadline(): void {
    const now = this.clock.now();
    const createdAt =
      this.state.createdAt === undefined
        ? now
        : Date.parse(this.state.createdAt);
    const startedAt = Number.isFinite(createdAt) ? createdAt : now;
    const discoveryTimeoutMs =
      this.options.discoveryTimeoutMs ??
      (this.state.config.maxTimeHours ?? DEFAULT_DISCOVERY_TIMEOUT_HOURS) *
        60 *
        60 *
        1_000;
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
    this.log({
      event: "discovery_deadline_reached",
      scanId: this.state.scanId,
    });
    this.discoveryAbortController.abort("deep_scan_discovery_deadline_reached");
  }

  private scheduleHeartbeat(): void {
    if (
      this.terminal ||
      this.externallyFailed ||
      !this.options.threadId ||
      !this.state.coordinatorGeneration
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
        handoffClaimToken: this.options.handoffClaimToken,
      });
      this.state = {
        ...this.state,
        updatedAt: renewed.updatedAt,
      };
    } catch (error) {
      this.log({
        event: "coordinator_heartbeat_failed",
        scanId: this.state.scanId,
        reason: errorKind(error),
      });
    }
    this.scheduleHeartbeat();
    if (this.terminal || this.ownershipCheck) return;
    const ownershipCheck = this.stopAfterOwnershipChange(threadId);
    this.ownershipCheck = ownershipCheck;
    try {
      await ownershipCheck;
    } finally {
      if (this.ownershipCheck === ownershipCheck)
        this.ownershipCheck = undefined;
    }
  }

  private async stopAfterOwnershipChange(
    threadId: string | undefined,
    error?: unknown,
  ): Promise<boolean> {
    if (this.externallyFailed || this.terminal || !threadId)
      return this.externallyFailed;
    let current = confirmedOwnershipChange(error, this.state.scanId)?.run;
    try {
      current ??= await this.options.store.get(this.state.scanId, threadId);
      this.failurePersisted ||= current.status === "failed";
    } catch (readError) {
      this.log({
        event: "coordinator_ownership_read_failed",
        scanId: this.state.scanId,
        reason: errorKind(readError),
      });
      return this.externallyFailed;
    }
    if (this.externallyFailed || this.terminal) return this.externallyFailed;
    const replacementConfirmed =
      current.status === "running" &&
      current.coordinatorGeneration !== undefined &&
      this.state.coordinatorGeneration !== undefined &&
      current.coordinatorGeneration > this.state.coordinatorGeneration;
    if (current.status === "running" && !replacementConfirmed) return false;

    this.externallyFailed = true;
    this.state = current;
    clearTimeout(this.heartbeatTimeout);
    this.heartbeatTimeout = undefined;
    this.abortController.abort("deep_scan_coordinator_lease_lost");
    this.publicationAbortController.abort("deep_scan_coordinator_lease_lost");
    if (replacementConfirmed && this.options.observeReplacement) {
      try {
        this.state = await this.options.observeReplacement(
          current,
          this.observationAbortController.signal,
        );
        this.failurePersisted ||= this.state.status === "failed";
      } catch (observeError) {
        this.log({
          event: "coordinator_replacement_observation_failed",
          scanId: this.state.scanId,
          reason: errorKind(observeError),
        });
        this.state = {
          ...current,
          status: "failed",
          error: `Deep Scan replacement observation failed: ${errorMessage(observeError)}`,
        };
      }
    } else {
      this.state = current;
    }
    return true;
  }

  private async runIterations(): Promise<LoopResult> {
    const { scanId, config } = this.state;
    const signal = this.abortController.signal;
    const accepted = await this.recoverAcceptedDiscoveries();
    let acceptedCount = accepted.length;
    const persisted = this.state.persistedWorkers ?? [];
    const merged = new Set(
      persisted.filter((w) => w.mergeState === "merged").map((w) => w.id),
    );
    let batch = accepted.filter((w) => !merged.has(w.id));
    const checkpointNumber = (resultPath: string) =>
      workerLabelSequence(
        relative(this.artifacts.dedupRoot, resultPath).split(sep)[0]!,
        "dedup",
      );
    let resultPath = persisted
      .flatMap((worker) =>
        worker.kind === "dedup" &&
        worker.status === "succeeded" &&
        worker.resultManifestPath
          ? [worker.resultManifestPath]
          : [],
      )
      .sort((a, b) => Number(checkpointNumber(b) - checkpointNumber(a)))[0];
    const result = await this.restoreUnion(
      resultPath,
      accepted.filter((w) => merged.has(w.id)),
    );
    const scanLabel = await nextWorkerLabel(
      this.artifacts.workersRoot,
      "discovery",
      persisted,
      this.state.dispatchedCount,
    );
    const checkpointLabel = await nextWorkerLabel(
      this.artifacts.dedupRoot,
      "dedup",
      persisted,
    );
    let pass = persisted.filter(
      (w) => w.kind === "dedup" && w.status === "succeeded",
    ).length;
    let dispatched = this.state.dispatchedCount;
    let streak = this.state.noNewStreak;
    let errors = this.state.consecutiveErrors;
    let failure = latestPersistedReplaceableFailure(persisted);
    const recordOutcome = (error?: typeof failure) => {
      if (errors >= config.stopAfterConsecutiveErrors) return;
      errors = error ? errors + 1 : 0;
      if (error) failure = error;
    };
    if (batch.length) {
      // SQLite observed completion order. Replay the uncheckpointed outcomes
      // in dispatch order, including failures before a later accepted worker.
      const lastMerged = accepted.findLast((worker) => merged.has(worker.id));
      const boundary = lastMerged
        ? discoverySequence(dirname(lastMerged.resultPath))
        : -1n;
      const pending = persisted
        .filter(
          (w) =>
            w.kind === "discovery" &&
            discoverySequence(w.artifactDir) > boundary,
        )
        .sort((a, b) =>
          Number(
            discoverySequence(a.artifactDir) - discoverySequence(b.artifactDir),
          ),
        );
      errors = 0;
      for (const worker of pending) {
        const error = persistedReplaceableFailure(worker);
        if (error || worker.status === "succeeded") recordOutcome(error);
      }
    }
    await this.options.store.updateProgress({
      scanId,
      phase: "discovery",
      handoffClaimToken: this.options.handoffClaimToken,
    });

    this.logProgress(acceptedCount);

    for (;;) {
      signal.throwIfAborted();
      if (batch.length) {
        // Newly dispatched scans arrive in launch order. Recovery uses the same labels.
        const { counts: newCounts, stop } = await this.mergeAcceptedBatch(
          result,
          batch,
        );
        for (const count of newCounts) {
          streak = count ? 0 : streak + 1;
        }
        resultPath = join(
          await reserveWorkerDirectory(
            this.artifacts.dedupRoot,
            checkpointLabel,
          ),
          "output",
          "result.json",
        );
        await writeJsonAtomic(resultPath, persistedScanUnion(result));
        const iterationId = randomUUID();
        const saved = await this.options.store.recordIteration({
          id: iterationId,
          scanId,
          workerIds: batch.map((w) => w.id),
          resultPath,
          noNewStreak: streak,
          consecutiveErrors: errors,
        });
        signal.throwIfAborted();
        this.state = saved;
        this.log({
          event: "dedup_committed",
          scanId,
          workerId: iterationId,
          pass: ++pass,
          count: batch.length,
          newFindings: newCounts.reduce((sum, count) => sum + count, 0),
          retainedFindings: result.findings.length,
        });
        this.logProgress(acceptedCount);
        if (stop) throw stop;
      }
      if (errors >= config.stopAfterConsecutiveErrors && failure) {
        throw discoveryErrorLimitError(
          errors,
          config.stopAfterConsecutiveErrors,
          failure.kind,
          failure.message,
        );
      }
      if (
        this.discoveryDeadlineReached ||
        streak >= config.stopAfterNoNew ||
        dispatched >= config.maxDiscoveryRuns
      ) {
        if (!resultPath && !this.discoveryDeadlineReached) {
          throw new Error(
            "Deep Scan reached its configured discovery limit without accepting a complete discovery" +
              (failure
                ? `; last failure (${failure.kind}): ${failure.message}`
                : "."),
          );
        }
        const reason =
          !this.discoveryDeadlineReached && streak >= config.stopAfterNoNew
            ? "saturated"
            : "capped";
        return { reason, result: resultPath ? result : undefined, resultPath };
      }

      const count = Math.min(
        config.workers,
        config.maxDiscoveryRuns - dispatched,
      );
      dispatched += count;
      this.state = { ...this.state, dispatchedCount: dispatched };
      const previousFindings = result.findings.map(({ title, locations }) => {
        const site =
          locations.find(({ role }) => role === "root_control") ?? locations[0];
        return `${site.path}:${site.startLine} ${title}`;
      });
      const outcomes = await this.scanBatch(count, scanLabel, previousFindings);
      signal.throwIfAborted();
      batch = [];
      for (const outcome of outcomes) {
        if (outcome.status === "succeeded") {
          recordOutcome();
          batch.push(outcome.worker);
          acceptedCount++;
        } else if (outcome.status === "failed") {
          if (!outcome.replaceableFailureKind) throw outcome.error;
          recordOutcome({
            kind: outcome.replaceableFailureKind,
            message: outcome.error.message,
          });
          this.log({
            event: "discovery_worker_replaced",
            scanId,
            workerId: outcome.workerId,
            reason: outcome.replaceableFailureKind,
          });
        } else if (!this.discoveryDeadlineReached) {
          throw new Error(
            `Discovery worker ${outcome.workerId} was canceled unexpectedly.`,
          );
        }
      }
    }
  }

  private async mergeAcceptedBatch(
    result: ScanUnion,
    batch: AcceptedDiscovery[],
  ) {
    let stop: DeepScanNonRetryableError | undefined;
    const counts = await mergeBatch(
      result,
      batch,
      this.artifacts.scanDir,
      async (prompt, schema) => {
        if (stop) throw stop;
        try {
          return await this.compareReports(prompt, schema);
        } catch (error) {
          // Finish checkpointing accepted workers before stopping discovery.
          if (error instanceof DeepScanNonRetryableError) stop = error;
          throw error;
        }
      },
      (error) => {
        this.abortController.signal.throwIfAborted();
        this.log({
          event: "finding_comparison_failed",
          scanId: this.state.scanId,
          reason: errorMessage(error),
        });
      },
    );
    return { counts, stop };
  }

  private async compareReports(
    prompt: string,
    schema: Record<string, unknown>,
  ): Promise<string> {
    const { executor } = this.options;
    if (!executor.compareFindings)
      throw new Error("No Deep Scan finding comparison executor");
    const { scanId, workerUsageDirectory } = this.state;
    const signal = this.abortController.signal;
    const startedAt = new Date(this.clock.now()).toISOString();
    const attemptId = randomUUID();
    const receipt: WorkerUsageReceipt = {
      schemaVersion: 1,
      source: "codex_sdk",
      usageScope: "thread_cumulative",
      scanId,
      workerId: attemptId,
      kind: "compare",
      attemptId,
      attempt: 1,
      resumed: false,
      startedAt,
      observedAt: startedAt,
      outcome: "running",
      usage: null,
    };
    const persist = async () => {
      if (!workerUsageDirectory) return;
      receipt.observedAt = new Date(this.clock.now()).toISOString();
      try {
        await writeWorkerUsageReceipt(workerUsageDirectory, receipt);
      } catch (error) {
        this.log({
          event: "worker_usage_unavailable",
          scanId,
          attemptId,
          reason: errorMessage(error),
        });
      }
    };
    await persist();
    try {
      const report = await executor.compareFindings(
        prompt,
        this.artifacts.deepRoot,
        signal,
        schema,
        {
          attemptId,
          workerUsageDirectory,
          onThreadStarted: async (id) => {
            receipt.threadId = id;
            await persist();
          },
          onUsage: async (usage, turnId) => {
            receipt.usage = usage;
            receipt.turnId = turnId;
            await persist();
          },
        },
      );
      receipt.outcome = "succeeded";
      return report;
    } catch (error) {
      receipt.outcome = signal.aborted ? "canceled" : "failed";
      throw error;
    } finally {
      await persist();
    }
  }

  private async restoreUnion(
    resultPath: string | undefined,
    merged: AcceptedDiscovery[],
  ): Promise<ScanUnion> {
    if (!resultPath) {
      if (merged.length)
        throw new Error("Deep Scan is missing its saved iteration result.");
      return { scanId: this.state.scanId, findings: [] };
    }
    await requireRegularFile(resultPath, this.artifacts.dedupRoot);
    const result = parseStoredScanDraft(
      await readJsonObject(resultPath),
      "Saved Deep Scan iteration",
      this.state.scanId,
      parseScanUnion,
    );
    for (const worker of merged)
      addScanCoverage(result, worker, this.artifacts.scanDir);
    return result;
  }

  private async scanBatch(
    count: number,
    nextLabel: () => string,
    previousFindings: string[],
  ): Promise<DiscoveryOutcome[]> {
    // Reserve in dispatch order. Another coordinator may create one of these
    // labels after our directory listing but before we write its prompt.
    const labels: string[] = [];
    for (let i = 0; i < count; i++) {
      labels.push(
        basename(
          await reserveWorkerDirectory(this.artifacts.workersRoot, nextLabel),
        ),
      );
    }
    const scans = labels.map(async (label) => {
      try {
        const outcome = await this.discoveryWorkers.runDiscoveryWorker(
          randomUUID(),
          label,
          previousFindings,
        );
        if (outcome.status === "failed" && !outcome.replaceableFailureKind)
          throw outcome.error;
        return outcome;
      } catch (error) {
        this.abortController.abort(error);
        throw error;
      }
    });
    // Wait for sibling cleanup before publishing a failure or starting another batch.
    const settled = await Promise.allSettled(scans);
    for (const scan of settled) {
      if (
        scan.status === "rejected" &&
        confirmedOwnershipChange(scan.reason, this.state.scanId)
      )
        throw scan.reason;
    }
    return settled.map((scan) => {
      if (scan.status === "rejected") throw scan.reason;
      return scan.value;
    });
  }

  private async recoverAcceptedDiscoveries(): Promise<AcceptedDiscovery[]> {
    const recovered: AcceptedDiscovery[] = [];
    for (const worker of this.state.persistedWorkers ?? []) {
      if (worker.kind !== "discovery" || worker.status !== "succeeded")
        continue;
      if (!worker.resultManifestPath || !worker.completionSequence) {
        throw new Error(
          `Accepted discovery ${worker.id} has incomplete persisted evidence.`,
        );
      }
      const result = await validateDiscoveryArtifacts(
        this.artifacts,
        worker.resultManifestPath,
        this.state.scanId,
        this.state,
        "previously-accepted",
      );
      recovered.push({
        id: worker.id,
        resultPath: worker.resultManifestPath,
        result,
        attempt: worker.attempt,
      });
    }
    return recovered.sort((a, b) =>
      Number(
        discoverySequence(dirname(a.resultPath)) -
          discoverySequence(dirname(b.resultPath)),
      ),
    );
  }

  private logProgress(count: number): void {
    this.log({
      event: "progress_updated",
      scanId: this.state.scanId,
      count,
      completed: count,
    });
  }
}

const systemClock: DeepScanClock = {
  now: () => Date.now(),
  sleep: async (delayMs, signal) => {
    try {
      await delay(delayMs, undefined, { signal });
    } catch (error) {
      throw signal.aborted ? abortError(signal.reason) : error;
    }
  },
};

async function reserveWorkerDirectory(
  root: string,
  nextLabel: () => string,
): Promise<string> {
  for (;;) {
    const directory = join(root, nextLabel());
    try {
      // A coordinator being replaced can still be reserving its last directory.
      await fs.mkdir(directory);
      return directory;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
  }
}

async function nextWorkerLabel(
  root: string,
  kind: "dedup" | "discovery",
  persisted: PersistedDeepScanWorker[],
  minimum = 0,
): Promise<() => string> {
  const labels = [
    ...(await fs.readdir(root)),
    ...persisted
      .filter((worker) => worker.kind === kind)
      .map((worker) => basename(dirname(worker.artifactDir))),
  ];
  let last = labels.reduce((n, name) => {
    const sequence = workerLabelSequence(name, kind);
    return sequence > n ? sequence : n;
  }, BigInt(minimum));
  return () => `${kind}-${String(++last).padStart(4, "0")}`;
}

function workerLabelSequence(
  label: string,
  kind: "discovery" | "dedup",
): bigint {
  const match = label.match(new RegExp(`^${kind}-(\\d+)$`));
  return match ? BigInt(match[1]!) : 0n;
}

function cloneState(state: DeepScanRunState): DeepScanRunState {
  return { ...state, config: { ...state.config } };
}

function isFreshRun(state: DeepScanRunState): boolean {
  // A coordinator can persist the discovery phase before dispatching its first worker.
  return (
    state.dispatchedCount === 0 &&
    !state.persistedWorkers?.some((worker) => worker.kind !== "setup") &&
    (state.persistedDedupInputs?.length ?? 0) === 0
  );
}

function discoverySequence(artifactDir: string): bigint {
  return workerLabelSequence(basename(dirname(artifactDir)), "discovery");
}

function latestPersistedReplaceableFailure(
  workers: PersistedDeepScanWorker[],
): { kind: DeepScanReplaceableFailureKind; message: string } | undefined {
  for (const worker of [...workers].reverse()) {
    const failure = persistedReplaceableFailure(worker);
    if (failure) return failure;
  }
  return undefined;
}

function persistedReplaceableFailure(
  worker: PersistedDeepScanWorker,
): { kind: DeepScanReplaceableFailureKind; message: string } | undefined {
  if (
    worker.kind !== "discovery" ||
    worker.status !== "canceled" ||
    !worker.error
  )
    return undefined;
  const kinds: DeepScanReplaceableFailureKind[] = [
    "policy_refusal",
    "transient_error",
    "invalid_discovery_artifacts",
  ];
  for (const kind of kinds) {
    const prefix = `${kind}:`;
    if (worker.error.startsWith(prefix)) {
      return { kind, message: worker.error.slice(prefix.length).trim() };
    }
  }
  return undefined;
}

function discoveryErrorLimitError(
  count: number,
  limit: number,
  kind: DeepScanReplaceableFailureKind,
  message: string,
  cause?: Error,
): Error {
  const detail =
    `Deep Scan stopped after ${count} consecutive unsuccessful discovery workers ` +
    `(limit: ${limit}); last failure (${kind}): ${message}`;
  return cause ? new Error(detail, { cause }) : new Error(detail);
}

function errorKind(error: unknown): string {
  if (!(error instanceof Error)) return typeof error;
  return errorNameWithCode(error);
}
