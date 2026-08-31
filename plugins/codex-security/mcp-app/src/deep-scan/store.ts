import { availableParallelism } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { writeJsonAtomic } from "./artifacts.js";
import {
  boundedDeepScanErrorMessage,
  DeepScanNonRetryableError,
  isStaleCoordinatorGenerationError
} from "./errors.js";
import type {
  BeginDeepScanResult,
  DedupCommit,
  DeepScanCoordinatorClaim,
  DeepScanCoordinatorLeaseInput,
  DeepScanConfig,
  DeepScanMergeState,
  DeepScanRunState,
  DeepScanRunStatus,
  DeepScanStore,
  DeepScanTerminalReason,
  DeepScanWorkerKind,
  DeepScanWorkerMutation,
  DeepScanWorkerStatus,
  PersistedDeepScanDedupInput,
  PersistedDeepScanWorker
} from "./types.js";

type JsonObject = Record<string, unknown>;
export type WorkbenchRunner = (
  args: string[],
  input?: string
) => Promise<JsonObject>;

const WORKFLOW_VERSION = "deep-scan-mcp/v1";
const MAX_IDEMPOTENT_PERSISTENCE_ATTEMPTS = 3;
const PERSISTENCE_RETRY_BASE_DELAY_MS = 100;

type PersistenceErrorRecord = {
  cause?: unknown;
  code?: unknown;
  exitCode?: unknown;
  killed?: unknown;
  message?: unknown;
  name?: unknown;
  signal?: unknown;
  stderr?: unknown;
  timeout?: unknown;
  timeoutMs?: unknown;
};

class DeepScanPersistenceError extends Error {
  readonly attempts: number;
  readonly elapsedMs: number;
  readonly operation: string;
  readonly scanId: string | undefined;
  readonly workerId: string | undefined;
  readonly code: string | number | undefined;
  readonly exitCode: number | undefined;
  readonly signal: string | undefined;
  readonly killed: boolean | undefined;
  readonly timeoutMs: number | undefined;

  constructor(args: string[], error: unknown, attempts: number, elapsedMs: number) {
    const operation = args[0] ?? "unknown";
    const scanId = argumentValue(args, "--scan-id");
    const workerId = argumentValue(args, "--worker-id");
    const diagnostic = boundedDeepScanErrorMessage(error);
    super(
      `Deep Scan persistence operation ${operation} failed after ${attempts} attempts`
      + `${scanId ? ` for scan ${scanId}` : ""}`
      + `${workerId ? ` and worker ${workerId}` : ""}: ${diagnostic}`,
      { cause: error }
    );
    this.name = "DeepScanPersistenceError";
    this.operation = operation;
    this.scanId = scanId;
    this.workerId = workerId;
    this.attempts = attempts;
    this.elapsedMs = elapsedMs;

    for (const record of persistenceErrorRecords(error)) {
      if (this.code === undefined && (typeof record.code === "string" || typeof record.code === "number")) {
        this.code = record.code;
      }
      if (this.exitCode === undefined) {
        if (typeof record.exitCode === "number") this.exitCode = record.exitCode;
        else if (typeof record.code === "number") this.exitCode = record.code;
      }
      if (this.signal === undefined && typeof record.signal === "string") {
        this.signal = record.signal;
      }
      if (this.killed === undefined && typeof record.killed === "boolean") {
        this.killed = record.killed;
      }
      if (this.timeoutMs === undefined) {
        if (typeof record.timeoutMs === "number") this.timeoutMs = record.timeoutMs;
        else if (typeof record.timeout === "number") this.timeoutMs = record.timeout;
      }
    }
  }
}

export class WorkbenchDeepScanStore implements DeepScanStore {
  private writeTail: Promise<void> = Promise.resolve();
  private readonly coordinatorLeases = new Map<string, {
    input: DeepScanCoordinatorLeaseInput;
    run: DeepScanRunState;
  }>();

  constructor(private readonly runWorkbench: WorkbenchRunner) {}

  async begin(input: {
    scanId?: string;
    targetPath?: string;
    scope?: string;
    userContext?: string;
    handoffClaimToken?: string;
    model?: string;
    reasoningEffort?: string;
    threadId: string;
    scanRoot: string;
  }): Promise<BeginDeepScanResult> {
    const userContext = input.userContext;
    const result = await this.enqueueWrite([
      "begin-deep-scan",
      "--thread-id",
      input.threadId,
      ...(input.scanId ? ["--scan-id", input.scanId] : []),
      ...(input.targetPath ? ["--target-path", input.targetPath] : []),
      ...(input.scope ? ["--scope", input.scope] : []),
      ...(userContext ? ["--user-context-stdin"] : []),
      ...(input.handoffClaimToken ? ["--claim-token", input.handoffClaimToken] : []),
      ...(input.model ? ["--model", input.model] : []),
      ...(input.reasoningEffort ? ["--reasoning-effort", input.reasoningEffort] : []),
      "--scan-root",
      input.scanRoot,
      "--available-parallelism",
      String(availableParallelism()),
      "--workflow-version",
      WORKFLOW_VERSION
    ], false, userContext);
    const run = parseDeepScan(result);
    const startDisposition = result.startDisposition;
    if (startDisposition !== "created" && startDisposition !== "joined") {
      throw new Error("Codex Security workbench returned an invalid Deep Scan start disposition.");
    }
    return { run, shouldStart: startDisposition === "created" };
  }

  async get(scanId: string, threadId: string): Promise<DeepScanRunState> {
    const run = parseDeepScan(await this.runWorkbench([
      "get-deep-scan",
      "--scan-id",
      scanId,
      "--thread-id",
      threadId
    ]));
    const generation = this.coordinatorLeases.get(scanId)?.run.coordinatorGeneration;
    if (
      run.status !== "running"
      || (generation !== undefined
        && run.coordinatorGeneration !== undefined
        && run.coordinatorGeneration > generation)
    ) {
      this.coordinatorLeases.delete(scanId);
    }
    return run;
  }

  async claimCoordinator(input: DeepScanCoordinatorLeaseInput): Promise<DeepScanCoordinatorClaim> {
    const result = await this.enqueueWrite([
      "claim-deep-scan-coordinator",
      "--scan-id",
      input.scanId,
      "--thread-id",
      input.threadId,
      ...this.coordinatorLeaseArgs(input.scanId),
      ...(input.handoffClaimToken ? ["--claim-token", input.handoffClaimToken] : [])
    ]);
    const run = parseDeepScan(result);
    const disposition = result.coordinatorDisposition;
    if (disposition !== "claimed" && disposition !== "adopted" && disposition !== "observing") {
      throw new Error("Codex Security workbench returned an invalid coordinator disposition.");
    }
    const acquired = disposition !== "observing";
    if (acquired) {
      if (!run.coordinatorGeneration || run.coordinatorGeneration <= 1) {
        throw new Error("Codex Security workbench returned an invalid coordinator lease.");
      }
      this.coordinatorLeases.set(input.scanId, { input, run });
    }
    return { run, acquired };
  }

  async heartbeatCoordinator(input: DeepScanCoordinatorLeaseInput): Promise<DeepScanRunState> {
    const lease = this.coordinatorLeases.get(input.scanId);
    if (!lease?.run.coordinatorGeneration) {
      throw new Error("A coordinator heartbeat requires a claimed Deep Scan lease.");
    }
    if (
      input.threadId !== lease.input.threadId
      || input.handoffClaimToken !== lease.input.handoffClaimToken
    ) {
      throw new Error("Deep Scan coordinator lease belongs to another continuation.");
    }
    const updatedAt = new Date().toISOString();
    await writeJsonAtomic(join(
      lease.run.scanDir,
      "artifacts",
      "deep_discovery",
      `coordinator-heartbeat-${lease.run.coordinatorGeneration}.json`
    ), { coordinatorGeneration: lease.run.coordinatorGeneration, updatedAt });
    return { ...lease.run, updatedAt };
  }

  async cancel(scanId: string, threadId: string): Promise<JsonObject> {
    return this.enqueueWrite([
      "cancel-scan",
      "--scan-id",
      scanId,
      "--thread-id",
      threadId
    ]);
  }

  async updateWorker(update: DeepScanWorkerMutation): Promise<PersistedDeepScanWorker> {
    const result = await this.enqueueWrite([
      "upsert-deep-scan-worker",
      "--scan-id",
      update.scanId,
      "--worker-id",
      update.id,
      "--kind",
      update.kind,
      "--status",
      update.status,
      "--prompt-path",
      update.promptPath,
      "--artifact-dir",
      update.artifactDir,
      "--attempt",
      String(update.attempt),
      ...this.coordinatorLeaseArgs(update.scanId),
      ...(update.resultManifestPath
        ? ["--result-manifest-path", update.resultManifestPath]
        : []),
      ...(update.threadId ? ["--sdk-thread-id", update.threadId] : []),
      ...(update.error ? ["--error-message", update.error] : []),
      ...(update.replaceableFailureKind
        ? ["--replaceable-failure-kind", update.replaceableFailureKind]
        : [])
    ], true);
    const worker = parseWorker(result, update.id);
    const state = objectValue(result.deepScan, "deepScan");
    return state.consecutiveErrors === undefined
      ? worker
      : {
          ...worker,
          consecutiveErrors: nonNegativeInteger(
            state.consecutiveErrors,
            "deepScan.consecutiveErrors"
          )
        };
  }

  async claimDedup(input: {
    id: string;
    scanId: string;
    workerIds: string[];
    promptPath: string;
    artifactDir: string;
  }): Promise<void> {
    await this.enqueueWrite([
      "claim-deep-scan-dedup",
      "--scan-id",
      input.scanId,
      "--worker-id",
      input.id,
      "--prompt-path",
      input.promptPath,
      "--artifact-dir",
      input.artifactDir,
      ...this.coordinatorLeaseArgs(input.scanId),
      ...input.workerIds.flatMap((workerId) => ["--input-worker-id", workerId])
    ], true);
  }

  async commitDedup(commit: DedupCommit): Promise<DeepScanRunState> {
    return parseDeepScan(await this.enqueueWrite([
      "commit-deep-scan-dedup",
      "--scan-id",
      commit.scanId,
      "--worker-id",
      commit.id,
      ...this.coordinatorLeaseArgs(commit.scanId),
      "--result-manifest-path",
      commit.resultManifestPath,
      ...(commit.candidateLedgerPath
        ? ["--candidate-ledger-path", commit.candidateLedgerPath]
        : []),
      "--new-findings-count",
      String(commit.newFindings)
    ], true));
  }

  async finish(input: {
    scanId: string;
    reason: DeepScanTerminalReason;
    manifestPath: string;
    stagedManifestPath?: string;
    omittedWorkerIds: string[];
  }): Promise<DeepScanRunState> {
    return parseDeepScan(await this.enqueueWrite([
      "finish-deep-scan",
      "--scan-id",
      input.scanId,
      ...this.coordinatorLeaseArgs(input.scanId),
      "--terminal-reason",
      input.reason,
      "--manifest-path",
      input.manifestPath,
      ...(input.stagedManifestPath
        ? ["--staged-manifest-path", input.stagedManifestPath]
        : []),
      ...input.omittedWorkerIds.flatMap((workerId) => ["--omitted-worker-id", workerId])
    ], true));
  }

  async fail(
    scanId: string,
    message: string,
    status: "failed" | "interrupted" = "failed",
    manifestPath?: string,
    stagedManifestPath?: string
  ): Promise<DeepScanRunState> {
    return parseDeepScan(await this.enqueueWrite([
      "fail-deep-scan",
      "--scan-id",
      scanId,
      ...this.coordinatorLeaseArgs(scanId),
      "--message",
      message,
      ...(manifestPath ? ["--manifest-path", manifestPath] : []),
      ...(stagedManifestPath ? ["--staged-manifest-path", stagedManifestPath] : []),
      ...(status === "interrupted" ? ["--deep-status", "interrupted"] : [])
    ]));
  }

  async recordStoppedPublicationFailure(
    scanId: string,
    message: string,
    coordinatorGeneration?: number
  ): Promise<DeepScanRunState> {
    return parseDeepScan(await this.enqueueWrite([
      "record-deep-scan-publication-failure",
      "--scan-id",
      scanId,
      ...(coordinatorGeneration === undefined
        ? this.coordinatorLeaseArgs(scanId)
        : ["--coordinator-generation", String(coordinatorGeneration)]),
      "--message",
      message
    ], true));
  }

  async updateProgress(input: {
    scanId: string;
    handoffClaimToken?: string;
    phase?: "preflight" | "discovery";
    deepReviewPass?: number;
    reviewItemsTotal?: number;
    reviewItemsCompleted?: number;
  }): Promise<void> {
    await this.enqueueWrite([
      "update-progress",
      "--scan-id",
      input.scanId,
      ...this.coordinatorLeaseArgs(input.scanId),
      ...(input.handoffClaimToken ? ["--claim-token", input.handoffClaimToken] : []),
      ...(input.phase ? ["--phase", input.phase] : []),
      ...(input.deepReviewPass === undefined
        ? []
        : ["--deep-review-pass", String(input.deepReviewPass)]),
      ...(input.reviewItemsTotal === undefined
        ? []
        : ["--review-items-total", String(input.reviewItemsTotal)]),
      ...(input.reviewItemsCompleted === undefined
        ? []
        : ["--review-items-completed", String(input.reviewItemsCompleted)])
    ]);
  }

  /**
   * Run mutations in call order. Callers receive their own operation's result
   * or error, while the stored tail always resolves so one failed write cannot
   * prevent later cancellation or cleanup from reaching the workbench.
   *
   * This orders one Node store instance; SQLite still provides transactions for
   * other workbench processes. Reads remain concurrent and observe a committed
   * state before or after each mutation.
   */
  coordinatorLeaseArgs(scanId: string): string[] {
    const generation = this.coordinatorLeases.get(scanId)?.run.coordinatorGeneration;
    return generation === undefined ? [] : ["--coordinator-generation", String(generation)];
  }

  private enqueueWrite(
    args: string[],
    retryTransientFailure = false,
    input?: string
  ): Promise<JsonObject> {
    const operation = this.writeTail.then(async () => {
      try {
        return retryTransientFailure
          ? await this.runIdempotentPersistence(args)
          : await this.runWorkbench(args, input);
      } catch (error) {
        const scanId = argumentValue(args, "--scan-id");
        if (scanId && isStaleCoordinatorGenerationError(error)) {
          this.coordinatorLeases.delete(scanId);
        }
        throw error;
      }
    });
    this.writeTail = operation.then(
      () => undefined,
      () => undefined
    );
    return operation;
  }

  /** Replay only existing, same-identity workbench mutations after transient failures. */
  private async runIdempotentPersistence(args: string[]): Promise<JsonObject> {
    const startedAt = Date.now();
    for (let attempt = 1; attempt <= MAX_IDEMPOTENT_PERSISTENCE_ATTEMPTS; attempt += 1) {
      try {
        return await this.runWorkbench(args);
      } catch (error) {
        if (!isTransientPersistenceError(error)) {
          throw error;
        }
        if (attempt === MAX_IDEMPOTENT_PERSISTENCE_ATTEMPTS) {
          const failure = new DeepScanPersistenceError(
            args,
            error,
            attempt,
            Math.max(0, Date.now() - startedAt)
          );
          console.error(JSON.stringify({
            component: "codex_security_deep_scan",
            event: "persistence_retry_exhausted",
            operation: failure.operation,
            scanId: failure.scanId,
            workerId: failure.workerId,
            attempts: failure.attempts,
            elapsedMs: failure.elapsedMs,
            ...(failure.code === undefined ? {} : { code: failure.code }),
            ...(failure.exitCode === undefined ? {} : { exitCode: failure.exitCode }),
            ...(failure.signal === undefined ? {} : { signal: failure.signal }),
            ...(failure.killed === undefined ? {} : { killed: failure.killed }),
            ...(failure.timeoutMs === undefined ? {} : { timeoutMs: failure.timeoutMs }),
            error: boundedDeepScanErrorMessage(error)
          }));
          throw failure;
        }
        const delayMs = PERSISTENCE_RETRY_BASE_DELAY_MS * (3 ** (attempt - 1))
          + Math.floor(Math.random() * PERSISTENCE_RETRY_BASE_DELAY_MS);
        await delay(delayMs);
      }
    }
    throw new Error("Deep Scan persistence retry loop exited unexpectedly.");
  }
}

export function isTransientPersistenceError(error: unknown): boolean {
  if (error instanceof DeepScanNonRetryableError) return false;

  for (const record of persistenceErrorRecords(error)) {
    if (
      record.name === "AbortError"
      || record.name === "CanceledError"
      || record.name === "DeepScanNonRetryableError"
      || record.code === "ABORT_ERR"
    ) {
      return false;
    }
    if (
      typeof record.code === "string"
      && /^SQLITE_(?:CORRUPT|NOTADB|READONLY|AUTH|PERM|CONSTRAINT|MISUSE|CANTOPEN|FULL)(?:_[A-Z]+)?$/i.test(record.code)
    ) {
      return false;
    }
    for (const diagnostic of [record.message, record.stderr]) {
      if (typeof diagnostic !== "string") continue;
      if (
        /\bSQLITE_(?:CORRUPT|NOTADB|READONLY|AUTH|PERM|CONSTRAINT|MISUSE|CANTOPEN|FULL)(?:_[A-Z]+)?\b/i.test(diagnostic)
        || /\b(?:database disk image is malformed|file is not a database|no such table|attempt to write a readonly database|permission denied|operation not permitted)\b/i.test(diagnostic)
      ) {
        return false;
      }
    }
  }

  for (const record of persistenceErrorRecords(error)) {
    if (
      typeof record.code === "string"
      && /^(?:SQLITE_BUSY(?:_[A-Z]+)?|SQLITE_LOCKED(?:_[A-Z]+)?|SQLITE_IOERR(?:_[A-Z]+)?|EAGAIN|EBUSY|EINTR|ETIMEDOUT|ETIME)$/i.test(record.code)
    ) {
      return true;
    }
    if (record.killed === true && typeof record.signal === "string") {
      return true;
    }
    for (const diagnostic of [record.message, record.stderr]) {
      if (typeof diagnostic !== "string") continue;
      if (
        /\bSQLITE_(?:BUSY|LOCKED|IOERR)(?:_[A-Z]+)?\b/i.test(diagnostic)
        || /\bdatabase(?: table| schema)? is (?:locked|busy)\b/i.test(diagnostic)
        || /\bsqlite3\.OperationalError:\s*disk I\/O error\b/i.test(diagnostic)
        || /\b(?:timed? out|deadline exceeded)\b/i.test(diagnostic)
      ) {
        return true;
      }
    }
  }
  return false;
}

function persistenceErrorRecords(error: unknown): PersistenceErrorRecord[] {
  const records: PersistenceErrorRecord[] = [];
  const observed = new Set<object>();
  let current = error;
  for (let index = 0; index < 4; index += 1) {
    if (typeof current !== "object" || current === null || observed.has(current)) break;
    observed.add(current);
    const record = current as PersistenceErrorRecord;
    records.push(record);
    current = record.cause;
  }
  return records;
}

function argumentValue(args: string[], flag: string): string | undefined {
  const index = args.indexOf(flag);
  return index < 0 ? undefined : args[index + 1];
}

export function parseDeepScan(result: JsonObject): DeepScanRunState {
  const value = objectValue(result.deepScan, "deepScan");
  const configValue = objectValue(value.config, "deepScan.config");
  const status = requiredString(value.status, "deepScan.status") as DeepScanRunStatus;
  if (![
    "running",
    "succeeded",
    "canceled",
    "failed",
    "interrupted"
  ].includes(status)) {
    throw new Error(`Unsupported Deep Scan status: ${status}`);
  }
  const stopAfterNoNew = positiveInteger(
    configValue.stopAfterNoNew,
    "deepScan.config.stopAfterNoNew"
  );
  const config: DeepScanConfig = {
    workers: positiveInteger(configValue.workers, "deepScan.config.workers"),
    subagents: nonNegativeInteger(configValue.subagents, "deepScan.config.subagents"),
    stopAfterNoNew,
    stopAfterConsecutiveErrors: positiveInteger(
      configValue.stopAfterConsecutiveErrors ?? stopAfterNoNew,
      "deepScan.config.stopAfterConsecutiveErrors"
    ),
    maxDiscoveryRuns: positiveInteger(
      configValue.maxDiscoveryRuns,
      "deepScan.config.maxDiscoveryRuns"
    ),
    ...(configValue.maxTimeHours === undefined
      ? {}
      : {
          maxTimeHours: boundedPositiveNumber(
            configValue.maxTimeHours,
            "deepScan.config.maxTimeHours",
            96
          )
        })
  };
  return {
    scanId: requiredString(value.scanId, "deepScan.scanId"),
    status,
    phase: deepScanPhase(value.phase),
    coordinatorGeneration: optionalPositiveInteger(value.coordinatorGeneration),
    createdAt: optionalString(value.createdAt),
    updatedAt: optionalString(value.updatedAt),
    targetPath: requiredString(value.targetPath, "deepScan.targetPath"),
    scope: requiredString(value.scope, "deepScan.scope"),
    userContext: optionalString(value.userContext),
    scanDir: requiredString(value.scanDir, "deepScan.scanDir"),
    config,
    dispatchedCount: nonNegativeInteger(value.dispatchedCount, "deepScan.dispatchedCount"),
    noNewStreak: nonNegativeInteger(value.noNewStreak, "deepScan.noNewStreak"),
    consecutiveErrors: nonNegativeInteger(
      value.consecutiveErrors ?? 0,
      "deepScan.consecutiveErrors"
    ),
    canonicalArtifacts: parseCanonicalArtifacts(value.canonicalArtifacts),
    manifestPath: optionalString(value.manifestPath),
    terminalReason: value.terminalReason === "saturated" || value.terminalReason === "capped"
      ? value.terminalReason
      : undefined,
    error: optionalString(value.error),
    persistedWorkers: parsePersistedWorkers(value.workers),
    persistedDedupInputs: parsePersistedDedupInputs(value.dedupInputs)
  };
}

function parsePersistedDedupInputs(value: unknown): PersistedDeepScanDedupInput[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) {
    throw new Error("Codex Security workbench returned invalid deepScan.dedupInputs.");
  }
  return value.map((candidate) => {
    const input = objectValue(candidate, "deepScan.dedupInput");
    return {
      dedupWorkerId: requiredString(
        input.dedupWorkerId,
        "deepScan.dedupInput.dedupWorkerId"
      ),
      discoveryWorkerId: requiredString(
        input.discoveryWorkerId,
        "deepScan.dedupInput.discoveryWorkerId"
      ),
      inputOrder: nonNegativeInteger(
        input.inputOrder,
        "deepScan.dedupInput.inputOrder"
      )
    };
  });
}

function deepScanPhase(value: unknown): DeepScanRunState["phase"] {
  if (value === undefined || value === null) return undefined;
  if (value === "setup" || value === "discovery" || value === "reducing" || value === "terminal") {
    return value;
  }
  throw new Error("Codex Security workbench returned invalid deepScan.phase.");
}

function parsePersistedWorkers(value: unknown): PersistedDeepScanWorker[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) {
    throw new Error("Codex Security workbench returned invalid deepScan.workers.");
  }
  return value.map((candidate) => parsePersistedWorker(
    objectValue(candidate, "deepScan.worker")
  ));
}

function parseCanonicalArtifacts(value: unknown): DeepScanRunState["canonicalArtifacts"] {
  if (value === null || value === undefined) return undefined;
  const artifacts = objectValue(value, "deepScan.canonicalArtifacts");
  return {
    inScopeFilesPath: requiredString(
      artifacts.inScopeFilesPath,
      "deepScan.canonicalArtifacts.inScopeFilesPath"
    ),
    candidateLedgerPath: requiredString(
      artifacts.candidateLedgerPath,
      "deepScan.canonicalArtifacts.candidateLedgerPath"
    )
  };
}

function parseWorker(result: JsonObject, workerId: string): PersistedDeepScanWorker {
  const deepScan = objectValue(result.deepScan, "deepScan");
  if (!Array.isArray(deepScan.workers)) {
    throw new Error("Codex Security workbench did not return deepScan.workers.");
  }
  const value = deepScan.workers.find((candidate) => (
    candidate
    && typeof candidate === "object"
    && !Array.isArray(candidate)
    && (candidate as JsonObject).id === workerId
  )) as JsonObject | undefined;
  if (!value) {
    throw new Error(`Codex Security workbench did not return Deep Scan worker ${workerId}.`);
  }
  return parsePersistedWorker(value);
}

function parsePersistedWorker(value: JsonObject): PersistedDeepScanWorker {
  return {
    id: requiredString(value.id, "deepScan.worker.id"),
    kind: workerKind(value.kind),
    status: workerStatus(value.status),
    mergeState: mergeState(value.mergeState),
    promptPath: requiredString(value.promptPath, "deepScan.worker.promptPath"),
    artifactDir: requiredString(value.artifactDir, "deepScan.worker.artifactDir"),
    attempt: nonNegativeInteger(value.attempt, "deepScan.worker.attempt"),
    threadId: optionalString(value.sdkThreadId),
    resultManifestPath: optionalString(value.resultManifestPath),
    completionSequence: optionalPositiveInteger(value.completionSequence),
    error: optionalString(value.error)
  };
}

function mergeState(value: unknown): DeepScanMergeState {
  if (value === "none" || value === "buffered" || value === "merging" || value === "merged") {
    return value;
  }
  throw new Error("Codex Security workbench returned invalid deepScan.worker.mergeState.");
}

function workerKind(value: unknown): DeepScanWorkerKind {
  if (value === "setup" || value === "discovery" || value === "dedup") return value;
  throw new Error("Codex Security workbench returned invalid deepScan.worker.kind.");
}

function workerStatus(value: unknown): DeepScanWorkerStatus {
  if (
    value === "queued"
    || value === "running"
    || value === "succeeded"
    || value === "failed"
    || value === "canceled"
  ) {
    return value;
  }
  throw new Error("Codex Security workbench returned invalid deepScan.worker.status.");
}

function objectValue(value: unknown, field: string): JsonObject {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Codex Security workbench did not return ${field}.`);
  }
  return value as JsonObject;
}

function requiredString(value: unknown, field: string): string {
  if (typeof value !== "string" || !value) {
    throw new Error(`Codex Security workbench returned invalid ${field}.`);
  }
  return value;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value ? value : undefined;
}

function positiveInteger(value: unknown, field: string): number {
  if (!Number.isInteger(value) || Number(value) < 1) {
    throw new Error(`Codex Security workbench returned invalid ${field}.`);
  }
  return Number(value);
}

function boundedPositiveNumber(value: unknown, field: string, maximum: number): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0 || value > maximum) {
    throw new Error(`Codex Security workbench returned invalid ${field}.`);
  }
  return value;
}

function optionalPositiveInteger(value: unknown): number | undefined {
  return Number.isInteger(value) && Number(value) >= 1 ? Number(value) : undefined;
}

function nonNegativeInteger(value: unknown, field: string): number {
  if (!Number.isInteger(value) || Number(value) < 0) {
    throw new Error(`Codex Security workbench returned invalid ${field}.`);
  }
  return Number(value);
}
