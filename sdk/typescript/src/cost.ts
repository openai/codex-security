import { open, readdir } from "node:fs/promises";
import { isAbsolute, join, relative, sep } from "node:path";
import {
  scanActivityFromSessionEvent,
  type ScanActivity,
} from "./scan-activity.js";
import {
  scanProgressUpdatesFromEvent,
  type ScanProgress,
} from "./worker-progress.js";

export interface ScanCost {
  model: string;
  inputTokens: number;
  cachedInputTokens: number;
  cacheWriteInputTokens: number;
  outputTokens: number;
  estimatedUsd: number;
}

export interface ScanSessionEvent {
  threadId: string;
  parentThreadId: string | null;
  worker?: number;
  event: Record<string, unknown>;
}

type ModelPricing = readonly [
  input: number,
  cachedInput: number,
  cacheWriteInput: number,
  output: number,
];

interface ScanTokenUsage {
  input_tokens: number;
  cached_input_tokens: number;
  cache_write_input_tokens: number;
  output_tokens: number;
  reasoning_output_tokens: number;
  total_tokens: number;
}

interface SessionReasoning {
  id: string;
  text: string;
  raw: boolean;
  activity: ScanActivity | null;
}

interface SessionUsage {
  offset: number;
  pendingLine: Buffer[];
  pendingLineBytes: number;
  unreadable: { error: unknown } | null;
  threadId: string | null;
  parentThreadId: string | null;
  workingDirectory: string | null;
  startedAt: number | null;
  inheritedUsage: ScanTokenUsage | null;
  previousRawUsage: ScanTokenUsage | null;
  accumulatedOwnUsage: ScanTokenUsage | null;
  replaying: boolean;
  accounting: { usage: ScanTokenUsage; cost: ScanCost | null } | null;
  accountingError: Error | null;
  taskCompleted: boolean;
  calls: Map<string, ScanActivity>;
  activities: ScanActivity[];
  progress: ScanProgress[];
  filesCompleted: number;
  filesTotal: number | null;
  prose: Set<string>;
  reasoning: SessionReasoning | null;
  reasoningCount: number;
  events?: Record<string, unknown>[];
}

interface ScanCostTrackerOptions {
  codexHome: string;
  model: string;
  repository?: string;
  scanDirectory?: string;
  maxCostUsd?: number;
  expectedFilesTotal?: number;
  onCost?: (cost: Readonly<ScanCost>, usage: unknown) => void;
  onActivity?: (activity: ScanActivity) => void;
  onProgress?: (progress: ScanProgress) => void;
  onSessionEvent?: (event: ScanSessionEvent) => void;
  onError?: (error: unknown) => void;
}

interface ScanCostSnapshot {
  usage: unknown;
  cost: ScanCost | null;
}

interface ObservedSessionUsage {
  root: ScanTokenUsage | null;
  workers: ScanTokenUsage | null;
  completedRoot: ScanTokenUsage | null;
  rootCompleted: boolean;
  unverified: boolean;
  unfinishedWorkers: boolean;
}

const MODEL_PRICING_NANODOLLARS: Readonly<Record<string, ModelPricing>> = {
  "gpt-5.6": [5_000, 500, 6_250, 30_000],
  "gpt-5.6-sol": [5_000, 500, 6_250, 30_000],
  "gpt-5.6-terra": [2_000, 200, 2_500, 12_000],
  "gpt-5.6-luna": [200, 20, 250, 1_200],
};

const COST_POLL_INTERVAL_MS = 100;
const SESSION_READ_SIZE = 64 * 1_024;

function createSessionUsage(): SessionUsage {
  return {
    offset: 0,
    pendingLine: [],
    pendingLineBytes: 0,
    unreadable: null,
    threadId: null,
    parentThreadId: null,
    workingDirectory: null,
    startedAt: null,
    inheritedUsage: null,
    previousRawUsage: null,
    accumulatedOwnUsage: null,
    replaying: false,
    accounting: null,
    accountingError: null,
    taskCompleted: false,
    calls: new Map(),
    activities: [],
    progress: [],
    filesCompleted: 0,
    filesTotal: null,
    prose: new Set(),
    reasoning: null,
    reasoningCount: 0,
  };
}

export class ScanCostTracker {
  readonly #options: ScanCostTrackerOptions;
  readonly #sessions = new Map<string, SessionUsage>();
  readonly #workers = new Map<string, number>();
  readonly #workerProgress = new Map<string, number>();
  readonly #reportedProgress = new Set<string>();
  #threadId: string | null = null;
  #timer: NodeJS.Timeout | null = null;
  #pending: Promise<void> = Promise.resolve();
  #snapshot: ScanCostSnapshot = { usage: null, cost: null };
  #finalSnapshot: ScanCostSnapshot | null = null;
  #observedUsage: ObservedSessionUsage = {
    root: null,
    workers: null,
    completedRoot: null,
    rootCompleted: false,
    unverified: false,
    unfinishedWorkers: false,
  };
  #lastCost: number | null = null;
  #rootOnlyReadError = false;
  #highestFilesCompleted = 0;
  #expectedFilesTotal: number | undefined;

  public constructor(options: ScanCostTrackerOptions) {
    this.#options = options;
    this.#expectedFilesTotal = options.expectedFilesTotal;
  }

  public setExpectedFilesTotal(filesTotal: number): void {
    this.#expectedFilesTotal = filesTotal;
  }

  public start(threadId: string): void {
    if (this.#threadId !== null) return;
    this.#threadId = threadId;
    if (
      this.#options.maxCostUsd === undefined &&
      this.#options.onCost === undefined &&
      this.#options.onActivity === undefined &&
      this.#options.onProgress === undefined &&
      this.#options.onSessionEvent === undefined
    ) {
      return;
    }
    let polling = false;
    let rerun = false;
    const poll = () => {
      if (polling) {
        rerun = true;
        return;
      }
      polling = true;
      void this.refresh()
        .catch((error: unknown) => {
          this.#options.onError?.(error);
        })
        .finally(() => {
          polling = false;
          if (rerun && this.#timer !== null) {
            rerun = false;
            poll();
          }
        });
    };
    this.#timer = setInterval(poll, COST_POLL_INTERVAL_MS);
    this.#timer.unref();
    poll();
  }

  public async refresh(): Promise<ScanCostSnapshot> {
    const update = this.#pending.then(async () => {
      await this.#readSessions();
    });
    this.#pending = update.catch(() => {});
    await update;
    return this.#snapshot;
  }

  public async stop(fallbackUsage?: unknown): Promise<ScanCostSnapshot> {
    const finalizing = arguments.length > 0;
    if (this.#finalSnapshot !== null) return this.#finalSnapshot;
    if (this.#timer !== null) {
      clearInterval(this.#timer);
      this.#timer = null;
    }
    const suppliedRoot = tokenUsage(fallbackUsage);
    let refreshFailure: { error: unknown } | null = null;
    try {
      await this.refresh();
    } catch (error) {
      refreshFailure = { error };
    }
    const observed = this.#observedUsage;
    const completedRoot = higherCostUsage(
      this.#options.model,
      observed.completedRoot,
      suppliedRoot,
    );
    observed.completedRoot = completedRoot;
    const rootUsage = higherCostUsage(
      this.#options.model,
      observed.root,
      completedRoot,
    );
    let completedUsage: unknown =
      rootUsage === suppliedRoot ? fallbackUsage : rootUsage;
    const workerUsage = observed.workers;
    if (workerUsage !== null) {
      completedUsage =
        rootUsage === null
          ? workerUsage
          : addTokenUsage(workerUsage, rootUsage);
    }
    const cost = estimateScanCost(this.#options.model, completedUsage);
    const snapshot =
      this.#snapshot.usage !== null &&
      ((rootUsage === null && workerUsage === null) ||
        (this.#snapshot.cost !== null &&
          (cost === null ||
            this.#snapshot.cost.estimatedUsd > cost.estimatedUsd)))
        ? this.#snapshot
        : { usage: completedUsage ?? null, cost };
    this.#snapshot = snapshot;
    if (
      this.#options.maxCostUsd !== undefined &&
      snapshot.cost !== null &&
      snapshot.cost.estimatedUsd > this.#options.maxCostUsd
    ) {
      this.#reportCost(snapshot.cost);
      if (!finalizing) return snapshot;
    }
    if (refreshFailure !== null) {
      if (
        fallbackUsage === undefined ||
        (this.#options.maxCostUsd !== undefined &&
          (completedRoot === null || !this.#rootOnlyReadError))
      ) {
        throw refreshFailure.error;
      }
      if (this.#options.maxCostUsd === undefined) {
        this.#options.onError?.(refreshFailure.error);
      }
    }
    if (
      this.#options.maxCostUsd !== undefined &&
      (rootUsage === null ||
        cost === null ||
        observed.unverified ||
        (finalizing &&
          ((completedRoot === null && !observed.rootCompleted) ||
            observed.unfinishedWorkers)))
    ) {
      throw (
        refreshFailure?.error ??
        new Error(
          "The scan cost limit could not be verified because model pricing or token usage is unavailable.",
        )
      );
    }
    if (finalizing) this.#finalSnapshot = snapshot;
    this.#reportCost(snapshot.cost);
    return snapshot;
  }

  async #readSessions(): Promise<void> {
    const rootThreadId = this.#threadId;
    if (rootThreadId === null) return;
    this.#rootOnlyReadError = false;
    const presentSessions = new Set<string>();
    const unreadable: Array<{ session: SessionUsage; error: unknown }> = [];
    for await (const path of sessionFiles(
      join(this.#options.codexHome, "sessions"),
    )) {
      let session = this.#sessions.get(path);
      if (session === undefined) {
        session = createSessionUsage();
        this.#sessions.set(path, session);
      }
      try {
        presentSessions.add(path);
        if (
          !(await readSessionUsage(
            path,
            session,
            this.#options.model,
            this.#options.repository,
            this.#options.maxCostUsd !== undefined,
          ))
        ) {
          presentSessions.delete(path);
        }
      } catch (error) {
        if (session.threadId === null) throw error;
        unreadable.push({ session, error });
      }
    }

    const parents = new Map<string, string | null>();
    const conflictingParents = new Set<string>();
    for (const session of this.#sessions.values()) {
      if (session.threadId === null) continue;
      const previous = parents.get(session.threadId);
      if (previous !== undefined && previous !== session.parentThreadId) {
        conflictingParents.add(session.threadId);
      } else {
        parents.set(session.threadId, session.parentThreadId);
      }
    }
    const knownOwner = (threadId: string): string | null => {
      const seen = new Set<string>();
      while (threadId !== rootThreadId) {
        if (seen.has(threadId) || conflictingParents.has(threadId)) return null;
        seen.add(threadId);
        const parent = parents.get(threadId);
        if (parent === undefined) return null;
        if (parent === null) return threadId;
        threadId = parent;
      }
      return rootThreadId;
    };

    const included = new Set([rootThreadId]);
    const ambiguousWorkers = new Set<string>();
    if (this.#options.scanDirectory !== undefined) {
      const scanStartedAt =
        [...this.#sessions.values()].find(
          (session) => session.threadId === rootThreadId,
        )?.startedAt ?? null;
      const artifactsDirectory = join(this.#options.scanDirectory, "artifacts");
      const workersDirectory = join(
        artifactsDirectory,
        "deep_discovery",
        "workers",
      );
      for (const session of this.#sessions.values()) {
        if (
          session.threadId === null ||
          session.threadId === rootThreadId ||
          session.workingDirectory === null
        ) {
          continue;
        }
        const workerDirectory = relative(
          workersDirectory,
          session.workingDirectory,
        );
        const components = workerDirectory.split(sep);
        const isWorkerDirectory =
          !isAbsolute(workerDirectory) &&
          components.length === 2 &&
          components[0] !== ".." &&
          relative(
            join(workersDirectory, components[0]!, "output"),
            session.workingDirectory,
          ) === "";
        if (
          relative(artifactsDirectory, session.workingDirectory) !== "" &&
          !isWorkerDirectory
        ) {
          continue;
        }
        if (
          scanStartedAt !== null &&
          session.startedAt !== null &&
          session.startedAt < scanStartedAt
        ) {
          continue;
        }
        const owner = knownOwner(session.threadId);
        if (owner === null) {
          ambiguousWorkers.add(session.threadId);
          continue;
        }
        if (owner !== session.threadId) continue;
        if (scanStartedAt === null || session.startedAt === null) {
          ambiguousWorkers.add(session.threadId);
          continue;
        }
        included.add(session.threadId);
      }
    }
    let changed = true;
    while (changed) {
      changed = false;
      for (const session of this.#sessions.values()) {
        if (
          session.threadId !== null &&
          session.parentThreadId !== null &&
          included.has(session.parentThreadId) &&
          !included.has(session.threadId)
        ) {
          if (conflictingParents.has(session.threadId)) {
            ambiguousWorkers.add(session.threadId);
            continue;
          }
          included.add(session.threadId);
          changed = true;
        }
      }
    }
    const hasUnverifiedWorkerAttribution = [...ambiguousWorkers].some(
      (threadId) => !included.has(threadId),
    );
    const readFailures: Array<{
      session: SessionUsage;
      error: unknown;
      rootOnlyRecoverable: boolean;
    }> = [];
    if (this.#options.maxCostUsd !== undefined) {
      for (const [path, session] of this.#sessions) {
        if (
          session.threadId !== null &&
          included.has(session.threadId) &&
          !presentSessions.has(path)
        ) {
          readFailures.push({
            session,
            error: new Error(
              "A tracked scan session disappeared before its cost could be verified.",
            ),
            rootOnlyRecoverable: false,
          });
        }
      }
    }
    for (const { session, error } of unreadable) {
      if (included.has(session.threadId!)) {
        readFailures.push({ session, error, rootOnlyRecoverable: true });
      } else if (isSessionAccessDenied(error)) {
        quarantineSession(session, error);
      }
    }

    const observed: ObservedSessionUsage = {
      root: null,
      workers: null,
      completedRoot: this.#observedUsage.completedRoot,
      rootCompleted: false,
      unverified: hasUnverifiedWorkerAttribution,
      unfinishedWorkers: false,
    };
    for (const [path, session] of this.#sessions) {
      if (session.threadId !== null && included.has(session.threadId)) {
        await this.#reportSessionEvents(path, session);
        if (
          this.#options.maxCostUsd !== undefined &&
          session.accountingError !== null
        ) {
          readFailures.push({
            session,
            error: session.accountingError,
            rootOnlyRecoverable: true,
          });
        }
        if (session.pendingLineBytes > 0) observed.unverified = true;
        const usage = session.accounting?.usage ?? null;
        if (session.threadId === this.#threadId) {
          observed.rootCompleted = session.taskCompleted;
          if (usage !== null) {
            observed.root = addTokenUsage(observed.root, usage);
          }
        } else {
          if (usage === null) {
            observed.unverified = true;
          } else {
            observed.workers = addTokenUsage(observed.workers, usage);
          }
          if (!session.taskCompleted) observed.unfinishedWorkers = true;
        }
      }
    }
    this.#observedUsage = observed;
    const usage =
      observed.root === null
        ? observed.workers
        : observed.workers === null
          ? observed.root
          : addTokenUsage(observed.root, observed.workers);
    if (usage !== null) {
      const cost = estimateScanCost(this.#options.model, usage);
      if (
        this.#snapshot.cost === null ||
        (cost !== null && cost.estimatedUsd >= this.#snapshot.cost.estimatedUsd)
      ) {
        this.#snapshot = { usage, cost };
      }
      this.#reportCost(this.#snapshot.cost);
    }
    const readFailure = readFailures[0];
    if (readFailure !== undefined) {
      this.#rootOnlyReadError =
        readFailures.every(
          (failure) =>
            failure.rootOnlyRecoverable &&
            failure.session.threadId === rootThreadId,
        ) && !hasUnverifiedWorkerAttribution;
      throw readFailure.error;
    }
  }

  async #reportSessionEvents(
    path: string,
    session: SessionUsage,
  ): Promise<void> {
    const threadId = session.threadId;
    if (threadId === null) return;
    if (
      this.#options.onSessionEvent !== undefined &&
      session.events === undefined
    ) {
      const replay = createSessionUsage();
      replay.events = [];
      try {
        // Replay only bytes already accounted for, without replacing cost state.
        await readSessionUsage(
          path,
          replay,
          this.#options.model,
          this.#options.repository,
          false,
          session.offset,
        );
      } catch {
        // Detail replay is optional. The accounting reader retains its own errors.
      }
      session.events = replay.threadId === threadId ? replay.events : [];
    }
    let worker: number | undefined;
    if (threadId !== this.#threadId) {
      worker = this.#workers.get(threadId) ?? this.#workers.size + 1;
      this.#workers.set(threadId, worker);
    }
    for (const event of session.events?.splice(0) ?? []) {
      this.#options.onSessionEvent?.({
        threadId,
        parentThreadId: session.parentThreadId,
        worker,
        event,
      });
    }
    if (worker === undefined) return;
    for (const activity of session.activities.splice(0)) {
      this.#options.onActivity?.({
        ...activity,
        id: `${threadId}:${activity.id}`,
        worker,
      });
    }
    this.#reportWorkerProgress(session);
  }

  #reportWorkerProgress(session: SessionUsage): void {
    if (this.#options.onProgress === undefined || session.threadId === null) {
      return;
    }
    for (const progress of session.progress.splice(0)) {
      const expectedFilesTotal = this.#expectedFilesTotal;
      if (
        (expectedFilesTotal !== undefined &&
          progress.filesTotal > expectedFilesTotal) ||
        (session.filesTotal !== null &&
          progress.filesTotal !== session.filesTotal) ||
        progress.filesCompleted < session.filesCompleted
      ) {
        continue;
      }
      session.filesTotal = progress.filesTotal;
      session.filesCompleted = progress.filesCompleted;
      this.#workerProgress.set(session.threadId, progress.filesCompleted);
      const filesCompleted = Math.min(
        expectedFilesTotal ?? Number.MAX_SAFE_INTEGER,
        [...this.#workerProgress.values()].reduce(
          (total, reviewed) => total + reviewed,
          0,
        ),
      );
      if (filesCompleted < this.#highestFilesCompleted) continue;
      const update = {
        ...progress,
        filesCompleted,
        filesTotal:
          expectedFilesTotal ?? Math.max(progress.filesTotal, filesCompleted),
      };
      const key = `${update.phase}:${update.filesCompleted}:${update.filesTotal}`;
      if (this.#reportedProgress.has(key)) continue;
      this.#reportedProgress.add(key);
      this.#highestFilesCompleted = update.filesCompleted;
      this.#options.onProgress(update);
    }
  }

  #reportCost(cost: ScanCost | null): void {
    if (cost === null || cost.estimatedUsd === this.#lastCost) return;
    this.#lastCost = cost.estimatedUsd;
    this.#options.onCost?.(cost, this.#snapshot.usage);
  }
}

export async function* sessionFiles(directory: string): AsyncGenerator<string> {
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch (error) {
    if (isMissingFile(error)) return;
    throw error;
  }
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      yield* sessionFiles(path);
    } else if (entry.isFile() && entry.name.endsWith(".jsonl")) {
      yield path;
    }
  }
}

async function readSessionUsage(
  path: string,
  session: SessionUsage,
  model: string,
  repository?: string,
  requireReadableSessions = false,
  endOffset?: number,
): Promise<boolean> {
  if (session.unreadable !== null) {
    if (requireReadableSessions) throw session.unreadable.error;
    return true;
  }
  let file;
  try {
    file = await open(path, "r");
  } catch (error) {
    if (isMissingFile(error)) return false;
    if (session.threadId === null && isSessionAccessDenied(error)) {
      quarantineSession(session, error);
    }
    throw error;
  }
  try {
    const buffer = Buffer.alloc(SESSION_READ_SIZE);
    while (true) {
      const length =
        endOffset === undefined
          ? buffer.length
          : Math.min(buffer.length, endOffset - session.offset);
      if (length <= 0) return true;
      const { bytesRead } = await file.read(buffer, 0, length, session.offset);
      if (bytesRead === 0) return true;
      session.offset += bytesRead;
      try {
        readSessionChunk(
          buffer.subarray(0, bytesRead),
          session,
          model,
          repository,
        );
      } catch (error) {
        quarantineSession(session, error);
        throw error;
      }
    }
  } finally {
    await file.close();
  }
}

function quarantineSession(session: SessionUsage, error: unknown): void {
  session.unreadable = { error };
  session.pendingLine = [];
  session.pendingLineBytes = 0;
}

function readSessionChunk(
  contents: Buffer,
  session: SessionUsage,
  model: string,
  repository?: string,
): void {
  let lineStart = 0;
  while (lineStart < contents.length) {
    const newline = contents.indexOf(0x0a, lineStart);
    const lineEnd = newline === -1 ? contents.length : newline;
    const fragment = contents.subarray(lineStart, lineEnd);
    const lineBytes = session.pendingLineBytes + fragment.length;

    if (newline === -1) {
      if (fragment.length > 0) {
        session.pendingLine.push(Buffer.from(fragment));
        session.pendingLineBytes = lineBytes;
      }
      return;
    }

    if (session.pendingLineBytes === 0) {
      readSessionEvent(fragment.toString("utf8"), session, model, repository);
    } else {
      if (fragment.length > 0) session.pendingLine.push(Buffer.from(fragment));
      readSessionEvent(
        Buffer.concat(session.pendingLine, lineBytes).toString("utf8"),
        session,
        model,
        repository,
      );
      session.pendingLine = [];
      session.pendingLineBytes = 0;
    }
    lineStart = newline + 1;
  }
}

function uuid7Timestamp(value: unknown): number | null {
  if (
    typeof value !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(
      value,
    )
  ) {
    return null;
  }
  return Number.parseInt(value.slice(0, 8) + value.slice(9, 13), 16);
}

function readSessionEvent(
  line: string,
  session: SessionUsage,
  model: string,
  repository?: string,
): void {
  if (line.length === 0) return;
  let event: unknown;
  try {
    event = JSON.parse(line) as unknown;
  } catch {
    if (!session.replaying) {
      session.accountingError ??= new Error(
        "The scan cost limit could not be verified because a tracked session record could not be read.",
      );
    }
    return;
  }
  if (!isRecord(event) || !isRecord(event["payload"])) return;
  const payload = event["payload"];
  if (event["type"] === "session_meta") {
    if (session.threadId !== null) {
      session.replaying = payload["id"] !== session.threadId;
      session.taskCompleted = false;
      if (!session.replaying) session.events?.push(event);
      return;
    }
    if (typeof payload["id"] === "string") {
      session.threadId = payload["id"];
    }
    if (typeof payload["cwd"] === "string") {
      session.workingDirectory = payload["cwd"];
    }
    if (typeof payload["timestamp"] === "string") {
      const startedAt = Date.parse(payload["timestamp"]);
      session.startedAt = Number.isFinite(startedAt)
        ? Math.floor(startedAt / 1_000)
        : null;
    }
    const source = payload["source"];
    const subagent = isRecord(source) ? source["subagent"] : undefined;
    const spawn = isRecord(subagent) ? subagent["thread_spawn"] : undefined;
    const parent =
      payload["parent_thread_id"] ??
      (isRecord(spawn) ? spawn["parent_thread_id"] : undefined);
    if (typeof parent === "string") session.parentThreadId = parent;
    const forkedFrom = payload["forked_from_id"];
    session.replaying = typeof forkedFrom === "string" && forkedFrom.length > 0;
    session.events?.push(event);
    return;
  }
  if (session.replaying) {
    if (event["type"] !== "event_msg") return;
    if (payload["type"] === "token_count" && isRecord(payload["info"])) {
      const usage = tokenUsage(payload["info"]["total_token_usage"]);
      if (usage !== null) {
        session.inheritedUsage = usage;
        session.previousRawUsage = usage;
      }
    }
    if (payload["type"] === "task_started") {
      const threadStartedAt = uuid7Timestamp(session.threadId);
      const turnStartedAt = uuid7Timestamp(payload["turn_id"]);
      const owned =
        threadStartedAt === null
          ? typeof payload["started_at"] === "number" &&
            session.startedAt !== null &&
            payload["started_at"] >= session.startedAt
          : turnStartedAt !== null && turnStartedAt >= threadStartedAt;
      if (owned) {
        session.replaying = false;
        session.taskCompleted = false;
        session.events?.push(event);
      }
    }
    return;
  }
  session.events?.push(event);
  if (event["type"] === "event_msg") {
    if (payload["type"] === "task_started") {
      session.taskCompleted = false;
      return;
    }
    if (
      payload["type"] === "task_complete" ||
      payload["type"] === "turn_complete" ||
      payload["type"] === "turn_aborted"
    ) {
      session.taskCompleted = true;
      return;
    }
  }
  if (event["type"] === "response_item") {
    session.progress.push(...sessionProgressUpdates(payload));
    if (repository === undefined) return;
    if (
      payload["type"] === "reasoning" &&
      typeof payload["id"] === "string" &&
      Array.isArray(payload["summary"]) &&
      payload["summary"].length > 1 &&
      session.reasoning?.raw !== true
    ) {
      for (const [index, summary] of payload["summary"].entries()) {
        const activity = scanActivityFromSessionEvent(
          {
            ...event,
            payload: {
              ...payload,
              id: `${payload["id"]}:${index}`,
              summary: [summary],
            },
          },
          repository,
        );
        if (
          activity === null ||
          session.prose.has(`${activity.kind}:${activity.description}`)
        ) {
          continue;
        }
        session.reasoning = {
          id: activity.id,
          text: activity.description,
          raw: false,
          activity: null,
        };
        recordReasoningActivity(session, activity);
      }
      return;
    }
    const activity = scanActivityFromSessionEvent(event, repository);
    if (activity !== null) {
      if (activity.kind === "reasoning") {
        const reasoning = (session.reasoning ??= {
          id: activity.id,
          text: activity.description,
          raw: false,
          activity: null,
        });
        recordReasoningActivity(session, {
          ...activity,
          id: reasoning.id,
          description:
            reasoning.raw && reasoning.activity !== null
              ? reasoning.activity.description
              : activity.description,
        });
        return;
      }
      session.reasoning = null;
      if (
        activity.kind === "message" &&
        session.prose.has(`${activity.kind}:${activity.description}`)
      ) {
        return;
      }
      if (activity.kind === "message") {
        session.prose.add(`${activity.kind}:${activity.description}`);
      }
      if (activity.status === "running") {
        session.calls.set(activity.id, activity);
      }
      session.activities.push(activity);
      return;
    }
    if (
      (payload["type"] === "function_call_output" ||
        payload["type"] === "custom_tool_call_output") &&
      typeof payload["call_id"] === "string"
    ) {
      const call = session.calls.get(payload["call_id"]);
      if (call !== undefined) {
        session.activities.push({
          ...call,
          status: payload["status"] === "failed" ? "failed" : "completed",
        });
        session.calls.delete(call.id);
      }
    }
    return;
  }
  if (
    event["type"] === "event_msg" &&
    (payload["type"] === "agent_reasoning" ||
      payload["type"] === "agent_reasoning_delta" ||
      payload["type"] === "agent_reasoning_raw_content" ||
      payload["type"] === "agent_reasoning_raw_content_delta" ||
      payload["type"] === "agent_message")
  ) {
    if (
      payload["type"] === "agent_message" &&
      typeof payload["message"] === "string"
    ) {
      session.progress.push(
        ...scanProgressUpdatesFromEvent({
          type: "item.completed",
          item: { type: "agent_message", text: payload["message"] },
        }),
      );
    }
    if (repository === undefined) return;
    if (payload["type"] !== "agent_message") {
      readSessionReasoning(event, payload, session, repository);
      return;
    }
    session.reasoning = null;
    const activity = scanActivityFromSessionEvent(event, repository);
    if (
      activity !== null &&
      !session.prose.has(`${activity.kind}:${activity.description}`)
    ) {
      session.prose.add(`${activity.kind}:${activity.description}`);
      session.activities.push(activity);
    }
    return;
  }
  if (
    event["type"] !== "event_msg" ||
    payload["type"] !== "token_count" ||
    !isRecord(payload["info"])
  ) {
    return;
  }
  const usage = tokenUsage(payload["info"]["total_token_usage"]);
  const accumulated =
    usage === null
      ? null
      : accumulateTokenUsage(
          session.previousRawUsage,
          session.accumulatedOwnUsage,
          usage,
        );
  const ownUsage =
    usage === null
      ? null
      : session.inheritedUsage === null
        ? usage
        : subtractTokenUsage(usage, session.inheritedUsage);
  const cost = ownUsage === null ? null : estimateScanCost(model, ownUsage);
  const accumulatedUsage = accumulated ?? session.accumulatedOwnUsage;
  const accumulatedCost = estimateScanCost(model, accumulatedUsage);
  if (
    accumulated === null ||
    accumulatedCost === null ||
    (ownUsage !== null && cost === null)
  ) {
    session.accountingError ??= new Error(
      "The scan cost limit could not be verified because model pricing or token usage is unavailable.",
    );
  }
  if (usage === null) return;
  session.previousRawUsage = usage;
  if (accumulated !== null) session.accumulatedOwnUsage = accumulated;
  for (const candidate of [
    ownUsage === null ? null : { usage: ownUsage, cost },
    accumulatedUsage === null
      ? null
      : { usage: accumulatedUsage, cost: accumulatedCost },
  ]) {
    if (candidate === null) continue;
    const previous = session.accounting;
    if (
      previous === null ||
      (candidate.cost !== null
        ? previous.cost === null ||
          candidate.cost.estimatedUsd >= previous.cost.estimatedUsd
        : previous.cost === null &&
          higherCostUsage(model, previous.usage, candidate.usage) ===
            candidate.usage)
    ) {
      session.accounting = candidate;
    }
  }
  session.taskCompleted = false;
}

function readSessionReasoning(
  event: Readonly<Record<string, unknown>>,
  payload: Readonly<Record<string, unknown>>,
  session: SessionUsage,
  repository: string,
): void {
  const type = payload["type"];
  const raw =
    type === "agent_reasoning_raw_content" ||
    type === "agent_reasoning_raw_content_delta";
  const delta =
    type === "agent_reasoning_delta" ||
    type === "agent_reasoning_raw_content_delta";
  const text = payload[delta ? "delta" : "text"];
  if (typeof text !== "string") return;

  if (
    !delta &&
    !raw &&
    session.reasoning?.raw !== true &&
    session.reasoning?.activity?.status === "completed" &&
    session.reasoning.text !== text
  ) {
    session.reasoning = null;
  }
  const reasoning = (session.reasoning ??= {
    id: `reasoning-${++session.reasoningCount}`,
    text: "",
    raw: false,
    activity: null,
  });
  if (reasoning.raw && !raw) return;
  if (raw && !reasoning.raw) {
    reasoning.text = "";
    reasoning.raw = true;
  }
  reasoning.text = delta ? `${reasoning.text}${text}` : text;

  const activity = scanActivityFromSessionEvent(
    {
      ...event,
      payload: {
        ...payload,
        [delta ? "delta" : "text"]: reasoning.text,
      },
    },
    repository,
  );
  if (activity === null) return;
  recordReasoningActivity(session, { ...activity, id: reasoning.id });
}

function recordReasoningActivity(
  session: SessionUsage,
  activity: ScanActivity,
): void {
  const reasoning = session.reasoning!;
  if (
    reasoning.activity?.description === activity.description &&
    reasoning.activity.status === activity.status
  ) {
    return;
  }
  reasoning.activity = activity;
  session.prose.add(`${activity.kind}:${activity.description}`);
  session.activities.push(activity);
}

function sessionProgressUpdates(
  payload: Readonly<Record<string, unknown>>,
): ScanProgress[] {
  if (payload["type"] === "message" && payload["role"] === "assistant") {
    const content = payload["content"];
    if (!Array.isArray(content)) return [];
    return scanProgressUpdatesFromEvent({
      type: "item.completed",
      item: {
        type: "agent_message",
        text: sessionContentText(content, false),
      },
    });
  }
  if (
    payload["type"] !== "function_call_output" &&
    payload["type"] !== "custom_tool_call_output" &&
    payload["type"] !== "local_shell_call_output"
  ) {
    return [];
  }
  const value = payload["output"];
  const output =
    typeof value === "string"
      ? value
      : Array.isArray(value)
        ? sessionContentText(value, true)
        : null;
  if (payload["status"] === "failed" || output === null) {
    return [];
  }
  return scanProgressUpdatesFromEvent({
    type: "item.completed",
    item: { type: "command_execution", aggregated_output: output },
  });
}

function sessionContentText(
  content: readonly unknown[],
  includeInputText: boolean,
): string {
  return content
    .filter(
      (item): item is Record<string, unknown> & { text: string } =>
        isRecord(item) &&
        (item["type"] === "output_text" ||
          (includeInputText && item["type"] === "input_text")) &&
        typeof item["text"] === "string",
    )
    .map((item) => item.text)
    .join("\n");
}

function tokenUsage(value: unknown): ScanTokenUsage | null {
  if (!isRecord(value)) return null;
  const input = value["input_tokens"];
  const cached = value["cached_input_tokens"] ?? 0;
  const canonicalCacheWrite = value["cache_write_input_tokens"];
  const legacyCacheWrite = value["cache_write_tokens"];
  const cacheWrite =
    canonicalCacheWrite === 0 &&
    isTokenCount(input) &&
    isTokenCount(cached) &&
    isTokenCount(legacyCacheWrite) &&
    legacyCacheWrite > 0 &&
    cached + legacyCacheWrite <= input
      ? legacyCacheWrite
      : canonicalCacheWrite ?? legacyCacheWrite ?? 0;
  const output = value["output_tokens"];
  const reasoning = value["reasoning_output_tokens"] ?? 0;
  if (
    !isTokenCount(input) ||
    !isTokenCount(cached) ||
    !isTokenCount(cacheWrite) ||
    !isTokenCount(output) ||
    !isTokenCount(reasoning) ||
    cached + cacheWrite > input ||
    reasoning > output
  ) {
    return null;
  }
  return {
    input_tokens: input,
    cached_input_tokens: cached,
    cache_write_input_tokens: cacheWrite,
    output_tokens: output,
    reasoning_output_tokens: reasoning,
    total_tokens: input + output,
  };
}

function higherCostUsage(
  model: string,
  previous: ScanTokenUsage | null,
  next: ScanTokenUsage | null,
): ScanTokenUsage | null {
  if (next === null) return previous;
  const previousCost = estimateScanCost(model, previous);
  const nextCost = estimateScanCost(model, next);
  if (previous !== null && previousCost === null && nextCost === null) {
    const previousTotal =
      BigInt(previous.input_tokens) + BigInt(previous.output_tokens);
    const nextTotal = BigInt(next.input_tokens) + BigInt(next.output_tokens);
    return previousTotal > nextTotal ? previous : next;
  }
  return previousCost !== null &&
    nextCost !== null &&
    previousCost.estimatedUsd > nextCost.estimatedUsd
    ? previous
    : next;
}

function accumulateTokenUsage(
  previousRaw: ScanTokenUsage | null,
  accumulated: ScanTokenUsage | null,
  next: ScanTokenUsage,
): ScanTokenUsage | null {
  const previousTotal =
    BigInt(previousRaw?.input_tokens ?? 0) +
    BigInt(previousRaw?.output_tokens ?? 0);
  const nextTotal = BigInt(next.input_tokens) + BigInt(next.output_tokens);
  const reset = nextTotal < previousTotal;
  const totalDelta = reset ? nextTotal : nextTotal - previousTotal;
  if (totalDelta === 0n) {
    return accumulated ?? tokenUsage({ input_tokens: 0, output_tokens: 0 });
  }
  const addDelta = (
    field: Exclude<keyof ScanTokenUsage, "total_tokens">,
  ): number | null => {
    const previous = BigInt(previousRaw?.[field] ?? 0);
    const value = BigInt(next[field]);
    const delta = reset || value < previous ? value : value - previous;
    const total = BigInt(accumulated?.[field] ?? 0) + delta;
    return total <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(total) : null;
  };
  const usage = {
    input_tokens: addDelta("input_tokens"),
    cached_input_tokens: addDelta("cached_input_tokens"),
    cache_write_input_tokens: addDelta("cache_write_input_tokens"),
    output_tokens: addDelta("output_tokens"),
    reasoning_output_tokens: addDelta("reasoning_output_tokens"),
  };
  return Object.values(usage).some((value) => value === null)
    ? null
    : tokenUsage(usage);
}

function addTokenUsage(
  previous: ScanTokenUsage | null,
  next: ScanTokenUsage,
): ScanTokenUsage {
  if (previous === null) return next;
  return {
    input_tokens: previous.input_tokens + next.input_tokens,
    cached_input_tokens:
      previous.cached_input_tokens + next.cached_input_tokens,
    cache_write_input_tokens:
      previous.cache_write_input_tokens + next.cache_write_input_tokens,
    output_tokens: previous.output_tokens + next.output_tokens,
    reasoning_output_tokens:
      previous.reasoning_output_tokens + next.reasoning_output_tokens,
    total_tokens: previous.total_tokens + next.total_tokens,
  };
}

function subtractTokenUsage(
  usage: ScanTokenUsage,
  inherited: ScanTokenUsage,
): ScanTokenUsage | null {
  return tokenUsage({
    input_tokens: usage.input_tokens - inherited.input_tokens,
    cached_input_tokens:
      usage.cached_input_tokens - inherited.cached_input_tokens,
    cache_write_input_tokens:
      usage.cache_write_input_tokens - inherited.cache_write_input_tokens,
    output_tokens: usage.output_tokens - inherited.output_tokens,
    reasoning_output_tokens:
      usage.reasoning_output_tokens - inherited.reasoning_output_tokens,
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isMissingFile(error: unknown): boolean {
  return isRecord(error) && error["code"] === "ENOENT";
}

function isSessionAccessDenied(error: unknown): boolean {
  return (
    isRecord(error) && (error["code"] === "EACCES" || error["code"] === "EPERM")
  );
}

export function estimateScanCost(
  model: string | undefined,
  usage: unknown,
): ScanCost | null {
  if (model === undefined) return null;
  const pricingModel = model.startsWith("openai.")
    ? model.slice("openai.".length)
    : model;
  const pricing = MODEL_PRICING_NANODOLLARS[pricingModel];
  const normalized = tokenUsage(usage);
  if (pricing === undefined || normalized === null) return null;
  const [inputRate, cachedInputRate, cacheWriteInputRate, outputRate] = pricing;
  const {
    input_tokens: inputTokens,
    cached_input_tokens: cachedInputTokens,
    cache_write_input_tokens: cacheWriteInputTokens,
    output_tokens: outputTokens,
  } = normalized;

  const nanodollars =
    (inputTokens - cachedInputTokens - cacheWriteInputTokens) * inputRate +
    cachedInputTokens * cachedInputRate +
    cacheWriteInputTokens * cacheWriteInputRate +
    outputTokens * outputRate;
  if (!Number.isSafeInteger(nanodollars)) return null;

  return {
    model,
    inputTokens,
    cachedInputTokens,
    cacheWriteInputTokens,
    outputTokens,
    estimatedUsd: nanodollars / 1_000_000_000,
  };
}

export function formatUsd(value: number): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 2,
    maximumFractionDigits: 9,
  }).format(value);
}

function isTokenCount(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}
