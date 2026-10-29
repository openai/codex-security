import { workbenchArgs } from "../workbench-arguments.js";
import { readDeepScanProjectConfig } from "./project-config.js";
import { availableParallelism } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { writeJsonAtomic } from "./artifacts.js";
import { parseDeepScan, parseWorker } from "./response.js";

export { parseDeepScan };
import {
  deepScanErrorMessage,
  DeepScanNonRetryableError,
  DeepScanOwnershipChangedError,
  isStaleCoordinatorGenerationError,
} from "./errors.js";
import type {
  DeepScanCoordinatorClaim,
  DeepScanCoordinatorLeaseInput,
  DeepScanRunState,
  DeepScanTerminalReason,
  DeepScanWorkerMutation,
  PersistedDeepScanWorker,
} from "./types.js";

type JsonObject = Record<string, unknown>;
export type WorkbenchRunner = (
  args: string[],
  input?: string,
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

  constructor(
    args: string[],
    error: unknown,
    attempts: number,
    elapsedMs: number,
  ) {
    const operation = args[0] ?? "unknown";
    const scanId = argumentValue(args, "--scan-id");
    const workerId = argumentValue(args, "--worker-id");
    const diagnostic = deepScanErrorMessage(error);
    super(
      `Deep Scan persistence operation ${operation} failed after ${attempts} attempts` +
        `${scanId ? ` for scan ${scanId}` : ""}` +
        `${workerId ? ` and worker ${workerId}` : ""}: ${diagnostic}`,
      { cause: error },
    );
    this.name = "DeepScanPersistenceError";
    this.operation = operation;
    this.scanId = scanId;
    this.workerId = workerId;
    this.attempts = attempts;
    this.elapsedMs = elapsedMs;

    for (const record of persistenceErrorRecords(error)) {
      if (
        this.code === undefined &&
        (typeof record.code === "string" || typeof record.code === "number")
      ) {
        this.code = record.code;
      }
      if (this.exitCode === undefined) {
        if (typeof record.exitCode === "number")
          this.exitCode = record.exitCode;
        else if (typeof record.code === "number") this.exitCode = record.code;
      }
      if (this.signal === undefined && typeof record.signal === "string") {
        this.signal = record.signal;
      }
      if (this.killed === undefined && typeof record.killed === "boolean") {
        this.killed = record.killed;
      }
      if (this.timeoutMs === undefined) {
        if (typeof record.timeoutMs === "number")
          this.timeoutMs = record.timeoutMs;
        else if (typeof record.timeout === "number")
          this.timeoutMs = record.timeout;
      }
    }
  }
}

const RETRYABLE_PERSISTENCE_COMMANDS = new Set([
  "upsert-deep-scan-worker",
  "record-deep-scan-iteration",
  "finish-deep-scan",
  "record-deep-scan-publication-failure",
]);

export class WorkbenchDeepScanStore {
  private writeTail: Promise<void> = Promise.resolve();
  private readonly coordinatorLeases = new Map<
    string,
    {
      input: DeepScanCoordinatorLeaseInput;
      run: DeepScanRunState;
    }
  >();

  constructor(private readonly runWorkbench: WorkbenchRunner) {}

  async begin(input: {
    scanId?: string;
    targetPath?: string;
    scope?: string;
    userContext?: string;
    projectConfigPath?: string;
    handoffClaimToken?: string;
    model?: string;
    reasoningEffort?: string;
    threadId: string;
    scanRoot: string;
  }): Promise<DeepScanRunState> {
    const userContext = input.userContext;
    const args = {
      threadId: input.threadId,
      scanId: input.scanId || undefined,
      targetPath: input.targetPath || undefined,
      projectConfigPath: input.projectConfigPath,
      scope: input.scope || undefined,
      userContextStdin: Boolean(userContext),
      claimToken: input.handoffClaimToken || undefined,
      model: input.model || undefined,
      reasoningEffort: input.reasoningEffort || undefined,
      scanRoot: input.scanRoot,
      availableParallelism: availableParallelism(),
      workflowVersion: WORKFLOW_VERSION,
    };
    let result = await this.enqueueWrite(
      workbenchArgs("begin-deep-scan", {
        ...args,
        joinOnly: input.projectConfigPath !== undefined,
      }),
      userContext,
    );
    if (
      input.projectConfigPath !== undefined &&
      typeof result.newScanTarget === "string"
    ) {
      const project = await readDeepScanProjectConfig(
        input.projectConfigPath,
        result.newScanTarget,
      );
      result = await this.enqueueWrite(
        workbenchArgs("begin-deep-scan", {
          ...args,
          targetPath: result.newScanTarget,
          deepScanProjectJson: JSON.stringify(project),
        }),
        userContext,
      );
    }
    const run = parseDeepScan(result);
    const startDisposition = result.startDisposition;
    if (startDisposition !== "created" && startDisposition !== "joined") {
      throw new Error(
        "Codex Security workbench returned an invalid Deep Scan start disposition.",
      );
    }
    return run;
  }

  async get(scanId: string, threadId: string): Promise<DeepScanRunState> {
    const run = parseDeepScan(
      await this.runWorkbench(
        workbenchArgs("get-deep-scan", { scanId, threadId }),
      ),
    );
    const generation =
      this.coordinatorLeases.get(scanId)?.run.coordinatorGeneration;
    if (
      run.status !== "running" ||
      (generation !== undefined &&
        run.coordinatorGeneration !== undefined &&
        run.coordinatorGeneration > generation)
    ) {
      this.coordinatorLeases.delete(scanId);
    }
    return run;
  }

  async claimCoordinator(
    input: DeepScanCoordinatorLeaseInput,
  ): Promise<DeepScanCoordinatorClaim> {
    const result = await this.enqueueWrite(
      workbenchArgs("claim-deep-scan-coordinator", {
        scanId: input.scanId,
        threadId: input.threadId,
        coordinatorGeneration: this.coordinatorGeneration(input.scanId),
        claimToken: input.handoffClaimToken || undefined,
      }),
    );
    const run = parseDeepScan(result);
    const disposition = result.coordinatorDisposition;
    if (
      disposition !== "claimed" &&
      disposition !== "adopted" &&
      disposition !== "observing"
    ) {
      throw new Error(
        "Codex Security workbench returned an invalid coordinator disposition.",
      );
    }
    const acquired = disposition !== "observing";
    if (acquired) {
      if (!run.coordinatorGeneration || run.coordinatorGeneration <= 1) {
        throw new Error(
          "Codex Security workbench returned an invalid coordinator lease.",
        );
      }
      this.coordinatorLeases.set(input.scanId, { input, run });
    }
    return { run, acquired };
  }

  async heartbeatCoordinator(
    input: DeepScanCoordinatorLeaseInput,
  ): Promise<DeepScanRunState> {
    const lease = this.coordinatorLeases.get(input.scanId);
    if (!lease?.run.coordinatorGeneration) {
      throw new Error(
        "A coordinator heartbeat requires a claimed Deep Scan lease.",
      );
    }
    if (
      input.threadId !== lease.input.threadId ||
      input.handoffClaimToken !== lease.input.handoffClaimToken
    ) {
      throw new Error(
        "Deep Scan coordinator lease belongs to another continuation.",
      );
    }
    const updatedAt = new Date().toISOString();
    await writeJsonAtomic(
      join(
        lease.run.scanDir,
        "artifacts",
        "deep_discovery",
        `coordinator-heartbeat-${lease.run.coordinatorGeneration}.json`,
      ),
      { coordinatorGeneration: lease.run.coordinatorGeneration, updatedAt },
    );
    return { ...lease.run, updatedAt };
  }

  async updateWorker(
    update: DeepScanWorkerMutation,
  ): Promise<PersistedDeepScanWorker> {
    const result = await this.enqueueWrite([
      ...workbenchArgs("upsert-deep-scan-worker", {
        scanId: update.scanId,
        workerId: update.id,
        kind: update.kind,
        status: update.status,
        promptPath: update.promptPath,
        artifactDir: update.artifactDir,
        attempt: update.attempt,
        coordinatorGeneration: this.coordinatorGeneration(update.scanId),
        resultManifestPath: update.resultManifestPath || undefined,
        sdkThreadId: update.threadId || undefined,
      }),
      ...(update.error ? [`--error-message=${update.error}`] : []),
      ...(update.replaceableFailureKind
        ? ["--replaceable-failure-kind", update.replaceableFailureKind]
        : []),
    ]);
    return parseWorker(result, update.id);
  }

  async recordIteration(input: {
    scanId: string;
    id: string;
    workerIds: string[];
    resultPath: string;
    noNewStreak: number;
    consecutiveErrors: number;
  }): Promise<DeepScanRunState> {
    return parseDeepScan(
      await this.enqueueWrite(
        workbenchArgs("record-deep-scan-iteration", {
          scanId: input.scanId,
          workerId: input.id,
          inputWorkerId: input.workerIds,
          resultManifestPath: input.resultPath,
          noNewStreak: input.noNewStreak,
          consecutiveErrors: input.consecutiveErrors,
          coordinatorGeneration: this.coordinatorGeneration(input.scanId),
        }),
      ),
    );
  }

  async finish(input: {
    scanId: string;
    reason: DeepScanTerminalReason;
    manifestPath: string;
    stagedManifestPath?: string;
    omittedWorkerIds: string[];
  }): Promise<DeepScanRunState> {
    return parseDeepScan(
      await this.enqueueWrite(
        workbenchArgs("finish-deep-scan", {
          scanId: input.scanId,
          coordinatorGeneration: this.coordinatorGeneration(input.scanId),
          terminalReason: input.reason,
          manifestPath: input.manifestPath,
          stagedManifestPath: input.stagedManifestPath || undefined,
          omittedWorkerId: input.omittedWorkerIds,
        }),
      ),
    );
  }

  async fail(
    scanId: string,
    message: string,
    status: "failed" | "interrupted" = "failed",
    manifestPath?: string,
    stagedManifestPath?: string,
  ): Promise<DeepScanRunState> {
    return parseDeepScan(
      await this.enqueueWrite([
        ...workbenchArgs("fail-deep-scan", {
          scanId,
          coordinatorGeneration: this.coordinatorGeneration(scanId),
        }),
        `--message=${message}`,
        ...(manifestPath ? ["--manifest-path", manifestPath] : []),
        ...(stagedManifestPath
          ? ["--staged-manifest-path", stagedManifestPath]
          : []),
        ...(status === "interrupted" ? ["--deep-status", "interrupted"] : []),
      ]),
    );
  }

  async recordStoppedPublicationFailure(
    scanId: string,
    message: string,
    coordinatorGeneration?: number,
  ): Promise<DeepScanRunState> {
    return parseDeepScan(
      await this.enqueueWrite([
        ...workbenchArgs("record-deep-scan-publication-failure", {
          scanId,
          coordinatorGeneration:
            coordinatorGeneration === undefined
              ? this.coordinatorGeneration(scanId)
              : coordinatorGeneration,
        }),
        `--message=${message}`,
      ]),
    );
  }

  async updateProgress(input: {
    scanId: string;
    handoffClaimToken?: string;
    phase?: "preflight" | "discovery";
    deepReviewPass?: number;
    reviewItemsTotal?: number;
    reviewItemsCompleted?: number;
  }): Promise<void> {
    await this.enqueueWrite(
      workbenchArgs("update-progress", {
        scanId: input.scanId,
        coordinatorGeneration: this.coordinatorGeneration(input.scanId),
        claimToken: input.handoffClaimToken || undefined,
        phase: input.phase || undefined,
        deepReviewPass: input.deepReviewPass,
        reviewItemsTotal: input.reviewItemsTotal,
        reviewItemsCompleted: input.reviewItemsCompleted,
      }),
    );
  }

  private coordinatorGeneration(scanId: string): number | undefined {
    return this.coordinatorLeases.get(scanId)?.run.coordinatorGeneration;
  }

  /**
   * Run mutations in call order. Callers receive their own operation's result
   * or error, while the stored tail always resolves so one failed write cannot
   * prevent later persistence or cleanup from reaching the workbench.
   *
   * This orders one Node store instance; SQLite still provides transactions for
   * other workbench processes. Reads remain concurrent and observe a committed
   * state before or after each mutation.
   */
  coordinatorLeaseArgs(scanId: string): string[] {
    const generation = this.coordinatorGeneration(scanId);
    return generation === undefined
      ? []
      : ["--coordinator-generation", String(generation)];
  }

  private enqueueWrite(args: string[], input?: string): Promise<JsonObject> {
    const operation = this.writeTail.then(async () => {
      try {
        return RETRYABLE_PERSISTENCE_COMMANDS.has(args[0])
          ? await this.runIdempotentPersistence(args)
          : await this.runWorkbench(args, input);
      } catch (error) {
        const scanId = argumentValue(args, "--scan-id");
        const lease = scanId ? this.coordinatorLeases.get(scanId) : undefined;
        if (lease && isStaleCoordinatorGenerationError(error)) {
          // Diagnostics can contain paths or user text; only state establishes ownership.
          const current = await this.get(
            lease.input.scanId,
            lease.input.threadId,
          ).catch(() => undefined);
          if (
            current &&
            (current.status !== "running" ||
              (current.coordinatorGeneration !== undefined &&
                lease.run.coordinatorGeneration !== undefined &&
                current.coordinatorGeneration >
                  lease.run.coordinatorGeneration))
          ) {
            throw new DeepScanOwnershipChangedError(current, error);
          }
        }
        throw error;
      }
    });
    this.writeTail = operation.then(
      () => undefined,
      () => undefined,
    );
    return operation;
  }

  /** Replay only existing, same-identity workbench mutations after transient failures. */
  private async runIdempotentPersistence(args: string[]): Promise<JsonObject> {
    const startedAt = Date.now();
    for (let attempt = 1; ; attempt += 1) {
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
            Math.max(0, Date.now() - startedAt),
          );
          console.error(
            JSON.stringify({
              component: "codex_security_deep_scan",
              event: "persistence_retry_exhausted",
              operation: failure.operation,
              scanId: failure.scanId,
              workerId: failure.workerId,
              attempts: failure.attempts,
              elapsedMs: failure.elapsedMs,
              code: failure.code,
              exitCode: failure.exitCode,
              signal: failure.signal,
              killed: failure.killed,
              timeoutMs: failure.timeoutMs,
              error: deepScanErrorMessage(error),
            }),
          );
          throw failure;
        }
        const delayMs =
          PERSISTENCE_RETRY_BASE_DELAY_MS * 3 ** (attempt - 1) +
          Math.floor(Math.random() * PERSISTENCE_RETRY_BASE_DELAY_MS);
        await delay(delayMs);
      }
    }
  }
}

export function isTransientPersistenceError(error: unknown): boolean {
  if (error instanceof DeepScanNonRetryableError) return false;

  for (const record of persistenceErrorRecords(error)) {
    if (
      record.name === "AbortError" ||
      record.name === "CanceledError" ||
      record.name === "DeepScanNonRetryableError" ||
      record.code === "ABORT_ERR"
    ) {
      return false;
    }
    if (
      typeof record.code === "string" &&
      /^SQLITE_(?:CORRUPT|NOTADB|READONLY|AUTH|PERM|CONSTRAINT|MISUSE|CANTOPEN|FULL)(?:_[A-Z]+)?$/i.test(
        record.code,
      )
    ) {
      return false;
    }
    for (const diagnostic of [record.message, record.stderr]) {
      if (typeof diagnostic !== "string") continue;
      if (
        /\bSQLITE_(?:CORRUPT|NOTADB|READONLY|AUTH|PERM|CONSTRAINT|MISUSE|CANTOPEN|FULL)(?:_[A-Z]+)?\b/i.test(
          diagnostic,
        ) ||
        /\b(?:database disk image is malformed|file is not a database|no such table|attempt to write a readonly database|permission denied|operation not permitted)\b/i.test(
          diagnostic,
        )
      ) {
        return false;
      }
    }
  }

  for (const record of persistenceErrorRecords(error)) {
    // A committed workbench mutation can lose or truncate its JSON stdout.
    if (record.name === "SyntaxError") return true;
    if (
      typeof record.code === "string" &&
      /^(?:SQLITE_BUSY(?:_[A-Z]+)?|SQLITE_LOCKED(?:_[A-Z]+)?|SQLITE_IOERR(?:_[A-Z]+)?|EAGAIN|EBUSY|EINTR|ETIMEDOUT|ETIME)$/i.test(
        record.code,
      )
    ) {
      return true;
    }
    if (record.killed === true && typeof record.signal === "string") {
      return true;
    }
    for (const diagnostic of [record.message, record.stderr]) {
      if (typeof diagnostic !== "string") continue;
      if (
        /\bSQLITE_(?:BUSY|LOCKED|IOERR)(?:_[A-Z]+)?\b/i.test(diagnostic) ||
        /\bdatabase(?: table| schema)? is (?:locked|busy)\b/i.test(
          diagnostic,
        ) ||
        /\bsqlite3\.OperationalError:\s*disk I\/O error\b/i.test(diagnostic) ||
        /\b(?:timed? out|deadline exceeded)\b/i.test(diagnostic)
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
    if (
      typeof current !== "object" ||
      current === null ||
      observed.has(current)
    )
      break;
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
