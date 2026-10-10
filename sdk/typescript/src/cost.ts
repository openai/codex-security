import { createHash, type Hash } from "node:crypto";
import { open, readdir, realpath, type FileHandle } from "node:fs/promises";
import { pipeline } from "node:stream";
import zlib from "node:zlib";
import { join } from "node:path";
import { isRecord } from "./record.js";
import {
  estimateScanCost,
  tokenUsage,
  type ScanCost,
  type ScanTokenUsage,
} from "./cost-model.js";
import {
  scanActivityFromSessionEvent,
  type ScanActivity,
} from "./scan-activity.js";
import {
  isScanArtifactDirectory,
  sessionOwnsTurn,
  sessionParentThreadId,
  sessionStartedAt,
} from "./scan-sessions.js";
import {
  scanProgressUpdatesFromText,
  type ScanProgress,
} from "./worker-progress.js";

export { estimateScanCost, formatUsd, type ScanCost } from "./cost-model.js";

/** A persisted worker session discovered during this run. Contains no model text. */
export interface ScanWorkerEvent {
  kind: "observed";
  /** Scan-local number shared with activity and session observers. */
  worker: number;
}

export interface ScanSessionEvent {
  threadId: string;
  parentThreadId: string | null;
  worker?: number;
  event: Record<string, unknown>;
}

interface SessionReasoning {
  id: string;
  text: string;
  raw: boolean;
  activity: ScanActivity | null;
}

interface SessionUsage {
  offset: number;
  contentHash: Hash | null;
  pendingLine: Buffer[];
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
  onWorkerEvent?: (event: ScanWorkerEvent) => void;
  onError?: (error: unknown) => void;
  resolveOwnedSessionPaths?: (
    rootThreadId: string,
  ) => Promise<ReadonlyMap<string, string>>;
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
  unidentifiedSessions: Set<string>;
  accountedSessions: Set<string>;
}
const COST_POLL_INTERVAL_MS = 100;
const SESSION_READ_SIZE = 64 * 1_024;

function createSessionUsage(): SessionUsage {
  return {
    offset: 0,
    contentHash: null,
    pendingLine: [],
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
  #observingWorkers = true;
  #timer: NodeJS.Timeout | null = null;
  #pending: Promise<void> = Promise.resolve();
  #snapshot: ScanCostSnapshot = { usage: null, cost: null };
  #finalSnapshot: ScanCostSnapshot | null = null;
  #completedThreadUsage = new Map<string | null, ScanTokenUsage | null>();
  #observedUsage: ObservedSessionUsage = {
    root: null,
    workers: null,
    completedRoot: null,
    rootCompleted: false,
    unverified: false,
    unfinishedWorkers: false,
    unidentifiedSessions: new Set(),
    accountedSessions: new Set(),
  };
  #lastCost: string | null = null;
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

  public recordCompletedThreadUsage(
    threadId: string | null,
    usage: unknown,
  ): void {
    this.#completedThreadUsage.set(threadId, tokenUsage(usage));
  }

  public recordUsage(usage: unknown, threadId = this.#threadId): void {
    this.recordCompletedThreadUsage(threadId, usage);
  }

  public setMaxCostUsd(maxCostUsd: number): void {
    this.#options.maxCostUsd = maxCostUsd;
  }

  public start(threadId: string): void {
    if (this.#threadId !== null) return;
    this.#threadId = threadId;
    if (
      this.#options.maxCostUsd === undefined &&
      this.#options.onCost === undefined &&
      this.#options.onActivity === undefined &&
      this.#options.onProgress === undefined &&
      this.#options.onSessionEvent === undefined &&
      this.#options.onWorkerEvent === undefined
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

  public async refresh(
    ownedPaths?: ReadonlyMap<string, string>,
  ): Promise<ScanCostSnapshot> {
    const update = this.#pending.then(async () => {
      await this.#readSessions(ownedPaths);
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
    if (suppliedRoot !== null) {
      this.#completedThreadUsage.set(
        this.#threadId,
        higherCostUsage(
          this.#options.model,
          this.#completedThreadUsage.get(this.#threadId) ?? null,
          suppliedRoot,
          true,
        ),
      );
    }
    let ownedPaths: ReadonlyMap<string, string> | undefined;
    let ownershipFailure: { error: unknown } | null = null;
    if (
      finalizing &&
      this.#options.maxCostUsd !== undefined &&
      this.#threadId !== null &&
      this.#options.resolveOwnedSessionPaths !== undefined
    ) {
      try {
        ownedPaths = await this.#options.resolveOwnedSessionPaths(
          this.#threadId,
        );
      } catch (error) {
        ownershipFailure = { error };
      }
    }
    let refreshFailure: { error: unknown } | null = null;
    try {
      await this.refresh(ownedPaths);
    } catch (error) {
      refreshFailure = { error };
    } finally {
      this.#observingWorkers = false;
    }
    const observed = this.#observedUsage;
    const completedRoot = higherCostUsage(
      this.#options.model,
      observed.completedRoot,
      suppliedRoot,
      true,
    );
    observed.completedRoot = completedRoot;
    const rootUsage = higherCostUsage(
      this.#options.model,
      observed.root,
      completedRoot,
      true,
    );
    let completedUsage: unknown = rootUsage;
    const workerUsage = observed.workers;
    if (workerUsage !== null) {
      completedUsage = addTokenUsage(rootUsage, workerUsage);
    }
    const cost = estimateScanCost(this.#options.model, completedUsage);
    if (workerUsage === null && rootUsage === suppliedRoot && cost === null) {
      completedUsage = fallbackUsage;
    }
    const snapshot =
      this.#snapshot.usage !== null &&
      !refinesCacheClassification(
        tokenUsage(this.#snapshot.usage),
        tokenUsage(completedUsage),
      ) &&
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
    let unidentifiedOwnedSession = false;
    if (finalizing && this.#options.maxCostUsd !== undefined) {
      if (ownershipFailure !== null) throw ownershipFailure.error;
      if (ownedPaths === undefined) {
        unidentifiedOwnedSession = observed.unidentifiedSessions.size > 0;
      } else {
        const accountedPaths = new Set(
          await Promise.all(
            [...observed.accountedSessions].map(async (path) => realpath(path)),
          ),
        );
        for (const path of ownedPaths.keys()) {
          if (!accountedPaths.has(path)) {
            unidentifiedOwnedSession = true;
            break;
          }
        }
      }
    }
    if (
      this.#options.maxCostUsd !== undefined &&
      (rootUsage === null ||
        cost === null ||
        observed.unverified ||
        unidentifiedOwnedSession ||
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
    const unknownCompletedUsage =
      (finalizing && fallbackUsage === null && rootUsage === null) ||
      [...this.#completedThreadUsage].some(
        ([threadId, usage]) =>
          usage === null &&
          ![...this.#sessions.values()].some(
            (session) =>
              session.threadId === threadId && session.accounting !== null,
          ),
      );
    const result =
      this.#options.maxCostUsd === undefined && unknownCompletedUsage
        ? { usage: null, cost: null }
        : snapshot;
    this.#snapshot = result;
    if (finalizing) this.#finalSnapshot = result;
    this.#reportCost(result.cost);
    return result;
  }

  async #completeCopyPath(
    path: string,
    partial: SessionUsage,
    present: ReadonlySet<string>,
    ownedPaths?: ReadonlyMap<string, string>,
  ): Promise<string | null> {
    if (this.#options.maxCostUsd === undefined) return null;
    for (const [completePath, complete] of this.#sessions) {
      if (
        completePath !== path &&
        (ownedPaths === undefined || ownedPaths.has(completePath)) &&
        present.has(completePath) &&
        complete.threadId === partial.threadId &&
        complete.taskCompleted &&
        complete.pendingLine.length === 0 &&
        complete.accounting !== null &&
        complete.accountingError === null &&
        complete.offset >= partial.offset &&
        (await sessionPrefixMatches(
          path,
          partial,
          completePath,
          present.has(path),
        ))
      )
        return completePath;
    }
    return null;
  }

  async #readSessions(ownedPaths?: ReadonlyMap<string, string>): Promise<void> {
    const rootThreadId = this.#threadId;
    if (rootThreadId === null) return;
    this.#rootOnlyReadError = false;
    const presentSessions = new Set<string>();
    const repository =
      this.#options.onActivity === undefined
        ? undefined
        : this.#options.repository;
    const unreadable: Array<{ session: SessionUsage; error: unknown }> = [];
    const paths = new Set(ownedPaths?.keys());
    for await (const path of sessionFiles(
      join(this.#options.codexHome, "sessions"),
    ))
      paths.add(path);
    for (const path of paths) {
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
            repository,
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

    // Native archival can move a file after polling has already read it.
    if (ownedPaths !== undefined) {
      for (const [path, session] of this.#sessions) {
        const completePath = presentSessions.has(path)
          ? null
          : await this.#completeCopyPath(
              path,
              session,
              presentSessions,
              ownedPaths,
            );
        if (completePath !== null) {
          // Keep drained observer state and read only the new verified suffix.
          await readSessionUsage(
            completePath,
            session,
            this.#options.model,
            repository,
            true,
          );
          this.#sessions.set(completePath, session);
          this.#sessions.delete(path);
        }
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

    const included = new Set([
      rootThreadId,
      ...[...this.#sessions].flatMap(([path, session]) =>
        ownedPaths?.has(path) && session.threadId !== null
          ? [session.threadId]
          : [],
      ),
      ...[...this.#completedThreadUsage.keys()].filter(
        (threadId): threadId is string => threadId !== null,
      ),
    ]);
    const ambiguousWorkers = new Set<string>();
    if (this.#options.scanDirectory !== undefined) {
      const scanStartedAt =
        [...this.#sessions.values()].find(
          (session) => session.threadId === rootThreadId,
        )?.startedAt ?? null;
      for (const session of this.#sessions.values()) {
        if (
          session.threadId === null ||
          session.threadId === rootThreadId ||
          session.workingDirectory === null
        ) {
          continue;
        }
        if (
          !isScanArtifactDirectory(
            this.#options.scanDirectory,
            session.workingDirectory,
          )
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
    let previousSize: number;
    do {
      previousSize = included.size;
      for (const session of this.#sessions.values()) {
        if (
          session.threadId !== null &&
          session.parentThreadId !== null &&
          included.has(session.parentThreadId)
        ) {
          if (conflictingParents.has(session.threadId)) {
            ambiguousWorkers.add(session.threadId);
            continue;
          }
          included.add(session.threadId);
        }
      }
    } while (included.size > previousSize);
    const hasUnverifiedWorkerAttribution = [...ambiguousWorkers].some(
      (threadId) => !included.has(threadId),
    );
    const readFailures: Array<{
      session: SessionUsage;
      error: unknown;
      rootOnlyRecoverable: boolean;
    }> = [];
    let missingSession = false;
    if (this.#options.maxCostUsd !== undefined) {
      for (const [path, session] of this.#sessions) {
        if (
          session.threadId !== null &&
          included.has(session.threadId) &&
          !presentSessions.has(path)
        ) {
          missingSession = true;
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
      unverified:
        hasUnverifiedWorkerAttribution ||
        [...(ownedPaths ?? [])].some(
          ([path, threadId]) => this.#sessions.get(path)?.threadId !== threadId,
        ),
      unfinishedWorkers: false,
      unidentifiedSessions: new Set(),
      accountedSessions: new Set(),
    };
    const accountedThreads = new Set<string | null>();
    const threadUsages = new Map<string, ScanTokenUsage | null>();
    const completedThreads = new Set<string>();
    for (const [path, session] of this.#sessions) {
      if (
        this.#options.maxCostUsd !== undefined &&
        session.threadId === null &&
        presentSessions.has(path)
      ) {
        observed.unidentifiedSessions.add(path);
      }
      if (session.threadId !== null && included.has(session.threadId)) {
        accountedThreads.add(session.threadId);
        if (presentSessions.has(path)) observed.accountedSessions.add(path);
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
        if (
          session.pendingLine.length > 0 &&
          !(await this.#completeCopyPath(
            path,
            session,
            presentSessions,
            ownedPaths,
          ))
        )
          observed.unverified = true;
        const usage = higherCostUsage(
          this.#options.model,
          session.accounting?.usage ?? null,
          this.#completedThreadUsage.get(session.threadId) ?? null,
          true,
        );
        threadUsages.set(
          session.threadId,
          higherCostUsage(
            this.#options.model,
            threadUsages.get(session.threadId) ?? null,
            usage,
          ),
        );
        if (
          this.#completedThreadUsage.has(session.threadId) ||
          (session.taskCompleted &&
            (ownedPaths === undefined ||
              ownedPaths.get(path) === session.threadId))
        )
          completedThreads.add(session.threadId);
      }
    }
    for (const [threadId, usage] of threadUsages) {
      if (threadId === rootThreadId) {
        observed.root = usage;
        observed.rootCompleted = completedThreads.has(threadId);
      } else {
        if (usage === null) observed.unverified = true;
        else observed.workers = addTokenUsage(observed.workers, usage);
        if (!completedThreads.has(threadId)) observed.unfinishedWorkers = true;
      }
    }
    for (const [threadId, usage] of this.#completedThreadUsage) {
      if (accountedThreads.has(threadId)) continue;
      if (usage === null) {
        observed.unverified = true;
      } else if (threadId === rootThreadId) {
        observed.root = addTokenUsage(observed.root, usage);
        observed.rootCompleted = true;
      } else {
        observed.workers = addTokenUsage(observed.workers, usage);
      }
    }
    this.#observedUsage = observed;
    const usage =
      observed.workers === null
        ? observed.root
        : addTokenUsage(observed.root, observed.workers);
    if (usage !== null) {
      const cost = estimateScanCost(this.#options.model, usage);
      if (
        this.#snapshot.cost === null ||
        refinesCacheClassification(tokenUsage(this.#snapshot.usage), usage) ||
        (cost !== null &&
          !refinesCacheClassification(
            usage,
            tokenUsage(this.#snapshot.usage),
            true,
          ) &&
          cost.estimatedUsd >= this.#snapshot.cost.estimatedUsd)
      ) {
        this.#snapshot = { usage, cost };
      }
      this.#reportCost(this.#snapshot.cost);
    }
    const readFailure = readFailures[0];
    if (readFailure !== undefined) {
      if (
        missingSession &&
        ownedPaths === undefined &&
        this.#options.resolveOwnedSessionPaths !== undefined
      ) {
        return await this.#readSessions(
          await this.#options.resolveOwnedSessionPaths(rootThreadId),
        );
      }
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
      worker = this.#workers.get(threadId);
      if (worker === undefined) {
        worker = this.#workers.size + 1;
        this.#workers.set(threadId, worker);
        if (this.#observingWorkers)
          this.#options.onWorkerEvent?.({ kind: "observed", worker });
      }
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
        this.#workerProgress
          .values()
          .reduce((total, reviewed) => total + reviewed, 0),
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
    if (cost === null) return;
    const signature = JSON.stringify(cost);
    if (signature === this.#lastCost) return;
    this.#lastCost = signature;
    this.#options.onCost?.(cost, this.#snapshot.usage);
  }
}

export async function* sessionFiles(
  directory: string,
  compressed = false,
): AsyncGenerator<string> {
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
      yield* sessionFiles(path, compressed);
    } else if (
      entry.isFile() &&
      (entry.name.endsWith(".jsonl") ||
        (compressed && entry.name.endsWith(".jsonl.zst")))
    ) {
      yield path;
    }
  }
}

async function sessionPrefixMatches(
  path: string,
  session: SessionUsage,
  completePath: string,
  present: boolean,
): Promise<boolean> {
  if (!present && session.contentHash === null) return false;
  const partial = present ? await open(path, "r") : null;
  try {
    const complete = await open(completePath, "r");
    try {
      if (path.endsWith(".zst") || completePath.endsWith(".zst")) {
        const left =
          partial === null
            ? session.contentHash!.copy().digest()
            : await sessionPrefixDigest(partial, path, session.offset);
        const right = await sessionPrefixDigest(
          complete,
          completePath,
          session.offset,
        );
        return left !== null && right !== null && left.equals(right);
      }
      const left = Buffer.alloc(SESSION_READ_SIZE);
      const right = Buffer.alloc(SESSION_READ_SIZE);
      const hash = partial === null ? createHash("sha256") : null;
      for (let offset = 0; offset < session.offset;) {
        const size = Math.min(right.length, session.offset - offset);
        const { bytesRead } = await complete.read(right, 0, size, offset);
        if (bytesRead === 0) return false;
        if (partial === null) {
          hash!.update(right.subarray(0, bytesRead));
        } else {
          const compared = await partial.read(left, 0, bytesRead, offset);
          if (
            compared.bytesRead !== bytesRead ||
            !left.subarray(0, bytesRead).equals(right.subarray(0, bytesRead))
          )
            return false;
        }
        offset += bytesRead;
      }
      return (
        hash === null ||
        hash.digest().equals(session.contentHash!.copy().digest())
      );
    } finally {
      await complete.close();
    }
  } finally {
    await partial?.close();
  }
}

async function* compressedSessionChunks(
  file: FileHandle,
): AsyncGenerator<Buffer> {
  const decoder = zlib.createZstdDecompress();
  const source = file.createReadStream({ start: 0, autoClose: false });
  const stream = pipeline(source, decoder, () => {});
  try {
    for await (const chunk of stream) yield chunk as Buffer;
  } finally {
    source.destroy();
    stream.destroy();
  }
}

async function sessionPrefixDigest(
  file: FileHandle,
  path: string,
  length: number,
): Promise<Buffer | null> {
  const hash = createHash("sha256");
  let offset = 0;
  if (path.endsWith(".zst")) {
    for await (const chunk of compressedSessionChunks(file)) {
      const size = Math.min(chunk.length, length - offset);
      hash.update(chunk.subarray(0, size));
      offset += size;
      if (offset === length) return hash.digest();
    }
  } else {
    const buffer = Buffer.alloc(SESSION_READ_SIZE);
    while (offset < length) {
      const { bytesRead } = await file.read(
        buffer,
        0,
        Math.min(buffer.length, length - offset),
        offset,
      );
      if (bytesRead === 0) return null;
      hash.update(buffer.subarray(0, bytesRead));
      offset += bytesRead;
    }
  }
  return offset === length ? hash.digest() : null;
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
    if (
      !requireReadableSessions ||
      !isSessionAccessDenied(session.unreadable.error)
    ) {
      if (requireReadableSessions) throw session.unreadable.error;
      return true;
    }
    session.unreadable = null;
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
    if (path.endsWith(".zst")) {
      if (endOffset !== undefined && session.offset >= endOffset) return true;
      let decodedOffset = 0;
      for await (const chunk of compressedSessionChunks(file)) {
        const start = Math.max(0, session.offset - decodedOffset);
        const end =
          endOffset === undefined
            ? chunk.length
            : Math.min(chunk.length, endOffset - decodedOffset);
        decodedOffset += chunk.length;
        if (start >= end) continue;
        const contents = chunk.subarray(start, end);
        // Archived and live copies share offsets and hashes of their JSONL bytes.
        if (requireReadableSessions) {
          session.contentHash ??= createHash("sha256");
          session.contentHash.update(contents);
        }
        session.offset += contents.length;
        try {
          readSessionChunk(contents, session, model, repository);
        } catch (error) {
          quarantineSession(session, error);
          throw error;
        }
        if (endOffset !== undefined && session.offset >= endOffset) return true;
      }
      return true;
    }
    const buffer = Buffer.alloc(SESSION_READ_SIZE);
    while (true) {
      const length =
        endOffset === undefined
          ? buffer.length
          : Math.min(buffer.length, endOffset - session.offset);
      if (length <= 0) return true;
      const { bytesRead } = await file.read(buffer, 0, length, session.offset);
      if (bytesRead === 0) return true;
      if (requireReadableSessions) {
        // Preserve prefix evidence if native ownership later names an archived path.
        session.contentHash ??= createHash("sha256");
        session.contentHash.update(buffer.subarray(0, bytesRead));
      }
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

    if (newline === -1) {
      if (fragment.length > 0) {
        session.pendingLine.push(Buffer.from(fragment));
      }
      return;
    }

    if (session.pendingLine.length === 0) {
      readSessionEvent(fragment.toString("utf8"), session, model, repository);
    } else {
      if (fragment.length > 0) session.pendingLine.push(Buffer.from(fragment));
      readSessionEvent(
        Buffer.concat(session.pendingLine).toString("utf8"),
        session,
        model,
        repository,
      );
      session.pendingLine = [];
    }
    lineStart = newline + 1;
  }
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
    session.startedAt = sessionStartedAt(payload["timestamp"]);
    session.parentThreadId = sessionParentThreadId(payload);
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
        session.previousRawUsage = retainCacheBaseline(
          session.previousRawUsage,
          usage,
        );
        session.inheritedUsage = session.previousRawUsage;
      }
    }
    if (
      payload["type"] === "task_started" &&
      sessionOwnsTurn(session, payload)
    ) {
      session.replaying = false;
      session.taskCompleted = false;
      session.events?.push(event);
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
      session.progress.push(...scanProgressUpdatesFromText(payload["message"]));
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
  const baseline = retainCacheBaseline(session.previousRawUsage, usage);
  const refinesRaw = refinesCacheClassification(
    session.previousRawUsage,
    baseline,
  );
  session.previousRawUsage = baseline;
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
      refinesCacheClassification(
        previous.usage,
        candidate.usage,
        !refinesRaw,
      ) ||
      (!refinesCacheClassification(candidate.usage, previous.usage, true) &&
        (candidate.cost !== null
          ? previous.cost === null ||
            candidate.cost.estimatedUsd >= previous.cost.estimatedUsd
          : previous.cost === null &&
            higherCostUsage(model, previous.usage, candidate.usage) ===
              candidate.usage))
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
    return scanProgressUpdatesFromText(sessionContentText(content, false));
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
  return scanProgressUpdatesFromText(output);
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

function refinesCacheClassification(
  previous: ScanTokenUsage | null,
  next: ScanTokenUsage | null,
  incompleteOnly = false,
): boolean {
  return (
    previous !== null &&
    (!incompleteOnly || previous.cache_write_input_tokens_reported === false) &&
    next !== null &&
    previous.input_tokens <= next.input_tokens &&
    previous.output_tokens <= next.output_tokens &&
    next.cached_input_tokens >= previous.cached_input_tokens &&
    next.cache_write_input_tokens >= previous.cache_write_input_tokens &&
    ((previous.cache_write_input_tokens_reported === false &&
      next.cache_write_input_tokens_reported !== false) ||
      next.cached_input_tokens > previous.cached_input_tokens ||
      next.cache_write_input_tokens > previous.cache_write_input_tokens)
  );
}

function higherCostUsage(
  model: string,
  previous: ScanTokenUsage | null,
  next: ScanTokenUsage | null,
  nextIsSdkReceipt = false,
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
  // SDK receipts insert zero for omitted cache writes; retain equally counted rollout evidence.
  if (
    nextIsSdkReceipt &&
    previous !== null &&
    next.cache_write_input_tokens === 0 &&
    previous.input_tokens === next.input_tokens &&
    previous.output_tokens === next.output_tokens &&
    previousCost?.estimatedUsd === nextCost?.estimatedUsd
  )
    return previous;
  // Growing receipts can refine reads without establishing omitted cache writes.
  if (
    nextIsSdkReceipt &&
    previous !== null &&
    next.cache_write_input_tokens === 0 &&
    next.input_tokens >= previous.input_tokens &&
    next.output_tokens >= previous.output_tokens &&
    (next.input_tokens > previous.input_tokens ||
      next.output_tokens > previous.output_tokens) &&
    next.cached_input_tokens > previous.cached_input_tokens
  ) {
    const refined = tokenUsage({
      ...next,
      cache_write_input_tokens: previous.cache_write_input_tokens,
      cache_write_input_tokens_reported: false,
    });
    if (refinesCacheClassification(previous, refined)) return refined;
  }
  // A receipt's synthesized zero does not establish complete cache writes.
  if (
    (!nextIsSdkReceipt || next.cache_write_input_tokens > 0) &&
    refinesCacheClassification(previous, next)
  )
    return next;
  if (refinesCacheClassification(next, previous, true)) return previous;
  return previousCost !== null &&
    nextCost !== null &&
    previousCost.estimatedUsd > nextCost.estimatedUsd
    ? previous
    : next;
}

function retainCacheBaseline(
  previous: ScanTokenUsage | null,
  next: ScanTokenUsage,
): ScanTokenUsage {
  // An omitted field does not reset a known cumulative count in this epoch.
  const baseline =
    next.cache_write_input_tokens_reported === false &&
    previous !== null &&
    next.input_tokens >= previous.input_tokens &&
    next.output_tokens >= previous.output_tokens
      ? { ...next, cache_write_input_tokens: previous.cache_write_input_tokens }
      : next;
  // A cache-only decrease is not counted as a new epoch. Retain its whole
  // baseline so a later recovery cannot count the same classified input twice.
  return previous !== null &&
    baseline.input_tokens === previous.input_tokens &&
    baseline.output_tokens === previous.output_tokens &&
    (baseline.cached_input_tokens < previous.cached_input_tokens ||
      baseline.cache_write_input_tokens < previous.cache_write_input_tokens)
    ? {
        ...previous,
        ...(baseline.cache_write_input_tokens_reported === false
          ? { cache_write_input_tokens_reported: false }
          : {}),
      }
    : baseline;
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
  // A cumulative receipt can fill missing cache writes for this epoch, while
  // unknown usage from earlier reset epochs remains unknown.
  const cacheWritesUnreported =
    next.cache_write_input_tokens_reported === false ||
    (accumulated?.cache_write_input_tokens_reported === false &&
      (reset ||
        next.input_tokens < (previousRaw?.input_tokens ?? 0) ||
        next.output_tokens < (previousRaw?.output_tokens ?? 0) ||
        accumulated.total_tokens !== previousRaw?.total_tokens)) ||
    (accumulated === null &&
      previousRaw?.cache_write_input_tokens_reported === false);
  const refinesClassification = refinesCacheClassification(
    previousRaw,
    retainCacheBaseline(previousRaw, next),
  );
  if (
    !refinesClassification &&
    next.input_tokens === (previousRaw?.input_tokens ?? 0) &&
    next.output_tokens === (previousRaw?.output_tokens ?? 0)
  ) {
    const { cache_write_input_tokens_reported: _reported, ...usage } =
      accumulated ?? tokenUsage({ input_tokens: 0, output_tokens: 0 })!;
    return tokenUsage({
      ...usage,
      ...(cacheWritesUnreported ||
      accumulated?.cache_write_input_tokens_reported === false
        ? { cache_write_input_tokens_reported: false }
        : {}),
    });
  }
  type TokenField = Exclude<
    keyof ScanTokenUsage,
    "total_tokens" | "cache_write_input_tokens_reported"
  >;
  const fieldDelta = (field: TokenField): bigint => {
    const previous = BigInt(previousRaw?.[field] ?? 0);
    const value = BigInt(next[field]);
    return reset || value < previous ? value : value - previous;
  };
  const inputDelta = fieldDelta("input_tokens");
  const outputDelta = fieldDelta("output_tokens");
  const cacheWriteRaw = fieldDelta("cache_write_input_tokens");
  // Late cache details can classify input already counted in this epoch.
  // Keep the existing bounds across independent field resets.
  const cacheWriteCapacity = refinesClassification
    ? BigInt(accumulated?.input_tokens ?? 0) +
      inputDelta -
      BigInt(accumulated?.cached_input_tokens ?? 0) -
      BigInt(accumulated?.cache_write_input_tokens ?? 0)
    : inputDelta;
  const cacheWriteDelta =
    cacheWriteRaw > cacheWriteCapacity ? cacheWriteCapacity : cacheWriteRaw;
  const remainingInputDelta =
    cacheWriteCapacity > cacheWriteDelta
      ? cacheWriteCapacity - cacheWriteDelta
      : 0n;
  const cachedRaw = fieldDelta("cached_input_tokens");
  const cachedDelta =
    cachedRaw > remainingInputDelta ? remainingInputDelta : cachedRaw;
  const reasoningRaw = fieldDelta("reasoning_output_tokens");
  const reasoningDelta =
    reasoningRaw > outputDelta ? outputDelta : reasoningRaw;
  const addDelta = (field: TokenField, delta: bigint): number | null => {
    const total = BigInt(accumulated?.[field] ?? 0) + delta;
    return total <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(total) : null;
  };
  const usage = {
    input_tokens: addDelta("input_tokens", inputDelta),
    cached_input_tokens: addDelta("cached_input_tokens", cachedDelta),
    cache_write_input_tokens: addDelta(
      "cache_write_input_tokens",
      cacheWriteDelta,
    ),
    output_tokens: addDelta("output_tokens", outputDelta),
    reasoning_output_tokens: addDelta(
      "reasoning_output_tokens",
      reasoningDelta,
    ),
  };
  return Object.values(usage).some((value) => value === null)
    ? null
    : tokenUsage({
        ...usage,
        ...(cacheWritesUnreported
          ? { cache_write_input_tokens_reported: false }
          : {}),
      });
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
    ...(previous.cache_write_input_tokens_reported === false ||
    next.cache_write_input_tokens_reported === false
      ? { cache_write_input_tokens_reported: false }
      : {}),
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
    ...(usage.cache_write_input_tokens_reported === false ||
    inherited.cache_write_input_tokens_reported === false
      ? { cache_write_input_tokens_reported: false }
      : {}),
    output_tokens: usage.output_tokens - inherited.output_tokens,
    reasoning_output_tokens:
      usage.reasoning_output_tokens - inherited.reasoning_output_tokens,
  });
}

function isMissingFile(error: unknown): boolean {
  return isRecord(error) && error["code"] === "ENOENT";
}

function isSessionAccessDenied(error: unknown): boolean {
  return (
    isRecord(error) && (error["code"] === "EACCES" || error["code"] === "EPERM")
  );
}
