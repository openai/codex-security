import { createHash } from "node:crypto";
import { open, readdir, readFile, realpath } from "node:fs/promises";
import { join } from "node:path";
import {
  estimateScanCost,
  estimateScanCostLowerBound,
  tokenUsage,
  type ScanCost,
  type ScanTokenUsage,
} from "./cost-model.js";
import {
  scanActivityFromSessionEvent,
  type ScanActivity,
} from "./scan-activity.js";
import {
  attributedScanThreads,
  isAttributedScanEvent,
  isScanArtifactDirectory,
  sessionParentThreadId,
  sessionStartedAt,
  type ScanExecutionAttribution,
} from "./scan-sessions.js";
import {
  scanProgressUpdatesFromEvent,
  type ScanProgress,
} from "./worker-progress.js";

export { estimateScanCost, formatUsd, type ScanCost } from "./cost-model.js";

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
  pendingLine: Buffer[];
  pendingLineBytes: number;
  unreadable: boolean;
  threadId: string | null;
  parentThreadId: string | null;
  workingDirectory: string | null;
  startedAt: number | null;
  inheritedUsage: ScanTokenUsage | null;
  replaying: boolean;
  usage: ScanTokenUsage | null;
  counterUsage: ScanTokenUsage | null;
  model: string | null;
  modelUsage: Map<string | null, ScanTokenUsage>;
  currentTurnId: string | null;
  previousUsage: ScanTokenUsage | null;
  responseIds: Set<string>;
  responseUsageObserved: boolean;
  responseTokens: number;
  expectedResponseTokens: number;
  counterRegressed: boolean;
  calls: Map<string, ScanActivity>;
  activities: ScanActivity[];
  progress: ScanProgress[];
  filesCompleted: number;
  filesTotal: number | null;
  prose: Set<string>;
  reasoning: SessionReasoning | null;
  reasoningCount: number;
  eventIndex: number;
  events?: { index: number; event: Record<string, unknown> }[];
}

interface ScanCostTrackerOptions {
  codexHome: string;
  model: string;
  repository?: string;
  scanDirectory?: string;
  maxCostUsd?: number;
  expectedFilesTotal?: number;
  onCost?: (cost: Readonly<ScanCost>) => void;
  // Only reported when the full public estimate is unavailable.
  onCostLowerBound?: (cost: Readonly<ScanCost>) => void;
  onActivity?: (activity: ScanActivity) => void;
  onProgress?: (progress: ScanProgress) => void;
  onSessionEvent?: (event: ScanSessionEvent) => void;
  onError?: (error: unknown) => void;
}

interface ScanCostSnapshot {
  usage: unknown;
  cost: ScanCost | null;
}

const COST_POLL_INTERVAL_MS = 100;
const SESSION_READ_SIZE = 64 * 1_024;

function createSessionUsage(): SessionUsage {
  return {
    offset: 0,
    pendingLine: [],
    pendingLineBytes: 0,
    unreadable: false,
    threadId: null,
    parentThreadId: null,
    workingDirectory: null,
    startedAt: null,
    inheritedUsage: null,
    replaying: false,
    usage: null,
    counterUsage: null,
    model: null,
    modelUsage: new Map(),
    currentTurnId: null,
    previousUsage: null,
    responseIds: new Set(),
    responseUsageObserved: false,
    responseTokens: 0,
    expectedResponseTokens: 0,
    counterRegressed: false,
    calls: new Map(),
    activities: [],
    progress: [],
    filesCompleted: 0,
    filesTotal: null,
    prose: new Set(),
    reasoning: null,
    reasoningCount: 0,
    eventIndex: 0,
  };
}

export class ScanCostTracker {
  readonly #options: ScanCostTrackerOptions;
  readonly #sessions = new Map<string, SessionUsage>();
  readonly #receipts = new Map<string, ScanTokenUsage | null>();
  readonly #workers = new Map<string, number>();
  readonly #workerProgress = new Map<string, number>();
  readonly #reportedProgress = new Set<string>();
  readonly #reportedSessionEvents = new Map<string, Set<string>>();
  #threadId: string | null = null;
  #timer: NodeJS.Timeout | null = null;
  #pending: Promise<void> = Promise.resolve();
  #snapshot: ScanCostSnapshot = { usage: null, cost: null };
  #lastCost: string | null = null;
  #lastCostLowerBound: string | null = null;
  #highestFilesCompleted = 0;
  #expectedFilesTotal: number | undefined;
  #attribution: ScanExecutionAttribution | null = null;
  #readAttribution:
    (() => Promise<ScanExecutionAttribution | null | undefined>) | undefined;

  public constructor(options: ScanCostTrackerOptions) {
    this.#options = options;
    this.#expectedFilesTotal = options.expectedFilesTotal;
  }

  public setExpectedFilesTotal(filesTotal: number): void {
    this.#expectedFilesTotal = filesTotal;
  }

  public setAttributionReader(
    reader: () => Promise<ScanExecutionAttribution | null | undefined>,
  ): void {
    this.#readAttribution = reader;
  }

  public recordUsage(usage: unknown, threadId = this.#threadId): void {
    const normalized = tokenUsage(usage);
    if (threadId !== null) {
      const previous = this.#receipts.get(threadId);
      if (
        previous == null ||
        (normalized !== null &&
          normalized.total_tokens >= previous.total_tokens)
      ) {
        this.#receipts.set(threadId, normalized);
      }
    }
  }

  public start(threadId: string): void {
    if (this.#threadId !== null) return;
    this.#threadId = threadId;
    if (
      this.#options.maxCostUsd === undefined &&
      this.#options.onCost === undefined &&
      this.#options.onCostLowerBound === undefined &&
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
    if (this.#timer !== null) {
      clearInterval(this.#timer);
      this.#timer = null;
    }
    if (fallbackUsage !== undefined) this.recordUsage(fallbackUsage);
    await this.refresh();
    if (
      this.#readAttribution ||
      this.#receipts.size > 0 ||
      this.#snapshot.usage !== null
    )
      return this.#snapshot;
    const cost = estimateScanCost(this.#options.model, fallbackUsage);
    this.#snapshot = { usage: fallbackUsage ?? null, cost };
    this.#reportCost(cost, fallbackUsage);
    return this.#snapshot;
  }

  async #readSessions(): Promise<void> {
    if (this.#threadId === null) return;
    if (this.#readAttribution) {
      const record = await this.#readAttribution();
      if (record === null) return;
      const attribution = record === undefined || record.legacy ? null : record;
      if (
        attribution &&
        (!this.#attribution ||
          attribution.completedAt !== this.#attribution.completedAt)
      ) {
        this.#sessions.clear();
      }
      this.#attribution = attribution;
    }
    const unreadable: Array<{ session: SessionUsage; error: unknown }> = [];
    const homes = new Set([this.#options.codexHome]);
    if (this.#options.scanDirectory !== undefined) {
      try {
        const saved: unknown = JSON.parse(
          await readFile(
            join(
              this.#options.scanDirectory,
              "artifacts",
              "deep_discovery",
              "execution-settings.json",
            ),
            "utf8",
          ),
        );
        if (
          isRecord(saved) &&
          saved["version"] === 1 &&
          isRecord(saved["settings"])
        ) {
          const home = saved["settings"]["codexHome"];
          if (typeof home === "string" && home !== "") homes.add(home);
        }
      } catch (error) {
        if (!isMissingFile(error)) throw error;
      }
    }
    // Recovery restores workers to their recorded home; the SDK parent can
    // continue in the current home. Apply the same scan membership to both.
    const directories = new Set<string>();
    for (const home of homes) {
      let directory: string;
      try {
        directory = await realpath(join(home, "sessions"));
      } catch (error) {
        if (isMissingFile(error)) continue;
        throw error;
      }
      if (directories.has(directory)) continue;
      directories.add(directory);
      for await (const path of sessionFiles(directory)) {
        let session = this.#sessions.get(path);
        if (session === undefined) {
          session = createSessionUsage();
          this.#sessions.set(path, session);
        }
        try {
          await readSessionUsage(
            path,
            session,
            this.#options.repository,
            this.#attribution,
          );
        } catch (error) {
          if (session.threadId === null) throw error;
          unreadable.push({ session, error });
        }
      }
    }

    const included = this.#attribution
      ? attributedScanThreads(this.#sessions.values(), this.#attribution)
      : new Set([this.#threadId, ...this.#receipts.keys()]);
    if (!this.#attribution && this.#options.scanDirectory !== undefined) {
      const scanStartedAt =
        [...this.#sessions.values()].find(
          (session) => session.threadId === this.#threadId,
        )?.startedAt ?? null;
      for (const session of this.#sessions.values()) {
        if (
          session.threadId === null ||
          session.parentThreadId !== null ||
          session.workingDirectory === null ||
          scanStartedAt === null ||
          session.startedAt === null ||
          session.startedAt < scanStartedAt
        ) {
          continue;
        }
        if (
          isScanArtifactDirectory(
            this.#options.scanDirectory,
            session.workingDirectory,
          )
        ) {
          included.add(session.threadId);
        }
      }
    }
    let changed = this.#attribution === null;
    while (changed) {
      changed = false;
      for (const session of this.#sessions.values()) {
        if (
          session.threadId !== null &&
          session.parentThreadId !== null &&
          included.has(session.parentThreadId) &&
          !included.has(session.threadId)
        ) {
          included.add(session.threadId);
          changed = true;
        }
      }
    }
    for (const { session, error } of unreadable) {
      if (included.has(session.threadId!)) throw error;
    }

    let incomplete = false;
    const usages = new Map(
      [...this.#receipts].filter(
        ([threadId]) =>
          included.has(threadId) &&
          (!this.#attribution ||
            this.#attribution.executionThreadIds.includes(threadId)),
      ),
    );
    if (this.#attribution) {
      for (const threadId of included) {
        if (!usages.has(threadId)) usages.set(threadId, null);
      }
    }
    const usageSessions = new Map<string, SessionUsage>();
    for (const [path, tracked] of this.#sessions) {
      const threadId = tracked.threadId;
      if (threadId === null || !included.has(threadId)) continue;
      let session = tracked;
      if (
        this.#options.onSessionEvent !== undefined &&
        session.events === undefined
      ) {
        // Replay only newly associated sessions, including their early events.
        session = createSessionUsage();
        session.events = [];
        await readSessionUsage(
          path,
          session,
          this.#options.repository,
          this.#attribution,
        );
        this.#sessions.set(path, session);
      }
      let worker: number | undefined;
      if (threadId !== this.#threadId) {
        worker = this.#workers.get(threadId) ?? this.#workers.size + 1;
        this.#workers.set(threadId, worker);
      }
      for (const { index, event } of session.events?.splice(0) ?? []) {
        let reported = this.#reportedSessionEvents.get(threadId);
        if (reported === undefined) {
          reported = new Set();
          this.#reportedSessionEvents.set(threadId, reported);
        }
        // A physical copy keeps each event's position, including repeated
        // identical events. Positions count unfiltered records so attribution
        // changes can replay the same log without changing occurrence identity.
        const identity = `${index}:${createHash("sha256")
          .update(JSON.stringify(event))
          .digest("hex")}`;
        if (reported.has(identity)) continue;
        reported.add(identity);
        this.#options.onSessionEvent?.({
          threadId,
          parentThreadId: session.parentThreadId,
          worker,
          event,
        });
      }
      if (worker !== undefined) {
        for (const activity of session.activities.splice(0)) {
          this.#options.onActivity?.({
            ...activity,
            id: `${threadId}:${activity.id}`,
            worker,
          });
        }
        this.#reportWorkerProgress(session);
      }
      // A copied prefix must not supply model usage for a more complete log.
      const previous = usageSessions.get(threadId);
      if (
        previous === undefined ||
        (session.usage?.total_tokens ?? -1) >
          (previous.usage?.total_tokens ?? -1)
      ) {
        usageSessions.set(threadId, session);
      }
      if (
        session.counterUsage &&
        session.counterUsage.total_tokens >
          (usages.get(threadId)?.total_tokens ?? -1)
      ) {
        usages.set(threadId, session.counterUsage);
      }
      const receipt = usages.get(threadId);
      if (
        session.usage !== null &&
        (session.usage.total_tokens > (receipt?.total_tokens ?? -1) ||
          // The SDK inserts zero when the final receipt omits cache writes.
          (session.usage.total_tokens === receipt?.total_tokens &&
            receipt.cache_write_input_tokens === 0))
      ) {
        usages.set(threadId, session.usage);
      }
      if (!usages.has(threadId)) usages.set(threadId, null);
      if (
        (session.counterRegressed && !session.responseUsageObserved) ||
        session.expectedResponseTokens > session.responseTokens
      )
        incomplete = true;
      if (session.pendingLineBytes > 0 && !this.#receipts.get(threadId))
        incomplete = true;
    }
    let usage: ScanTokenUsage | null = null;
    for (const value of usages.values()) {
      if (value === null) {
        if (this.#attribution) {
          incomplete = true;
          continue;
        }
        this.#snapshot = { usage: null, cost: null };
        return;
      }
      usage = addTokenUsage(usage, value);
    }
    if (usage === null) {
      this.#snapshot = { usage: null, cost: null };
      return;
    }
    const modelUsage = new Map<string | null, ScanTokenUsage>();
    let observedModel = false;
    for (const [threadId, value] of usages) {
      if (value === null) continue;
      const session = usageSessions.get(threadId);
      for (const [model, tokens] of session?.modelUsage ?? []) {
        if (model !== null) observedModel = true;
        modelUsage.set(
          model,
          addTokenUsage(modelUsage.get(model) ?? null, tokens),
        );
      }
      const remainder = session?.usage
        ? subtractTokenUsage(value, session.usage)
        : value;
      if (remainder !== null && remainder.total_tokens > 0) {
        const model =
          this.#attribution || (session?.modelUsage.size ?? 0) > 0
            ? null
            : (session?.model ??
              (threadId === this.#threadId ? this.#options.model : null));
        modelUsage.set(
          model,
          addTokenUsage(modelUsage.get(model) ?? null, remainder),
        );
      }
    }
    const reconciled =
      observedModel || this.#attribution !== null
        ? {
            ...usage,
            modelUsage: [...modelUsage].map(([model, tokens]) => ({
              model,
              ...tokens,
            })),
          }
        : usage;
    const measured = incomplete
      ? { ...reconciled, coverage: "partial" }
      : reconciled;
    const cost = estimateScanCost(this.#options.model, measured);
    this.#snapshot = { usage: measured, cost };
    this.#reportCost(cost, measured);
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

  #reportCost(cost: ScanCost | null, usage: unknown): void {
    if (cost === null) {
      if (this.#options.onCostLowerBound === undefined) return;
      const lowerBound = estimateScanCostLowerBound(this.#options.model, usage);
      if (lowerBound === null) return;
      const signature = JSON.stringify(lowerBound);
      if (signature === this.#lastCostLowerBound) return;
      this.#lastCostLowerBound = signature;
      this.#options.onCostLowerBound(lowerBound);
      return;
    }
    const signature = JSON.stringify(cost);
    if (signature === this.#lastCost) return;
    this.#lastCost = signature;
    this.#options.onCost?.(cost);
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
  repository?: string,
  attribution: ScanExecutionAttribution | null = null,
): Promise<void> {
  if (session.unreadable) return;
  let file;
  try {
    file = await open(path, "r");
  } catch (error) {
    if (isMissingFile(error)) return;
    throw error;
  }
  try {
    const buffer = Buffer.alloc(SESSION_READ_SIZE);
    while (true) {
      const { bytesRead } = await file.read(
        buffer,
        0,
        buffer.length,
        session.offset,
      );
      if (bytesRead === 0) return;
      session.offset += bytesRead;
      try {
        readSessionChunk(
          buffer.subarray(0, bytesRead),
          session,
          repository,
          attribution,
        );
      } catch (error) {
        session.unreadable = true;
        session.pendingLine = [];
        session.pendingLineBytes = 0;
        throw error;
      }
    }
  } finally {
    await file.close();
  }
}

function readSessionChunk(
  contents: Buffer,
  session: SessionUsage,
  repository?: string,
  attribution: ScanExecutionAttribution | null = null,
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
      readSessionEvent(
        fragment.toString("utf8"),
        session,
        repository,
        attribution,
      );
    } else {
      if (fragment.length > 0) session.pendingLine.push(Buffer.from(fragment));
      readSessionEvent(
        Buffer.concat(session.pendingLine, lineBytes).toString("utf8"),
        session,
        repository,
        attribution,
      );
      session.pendingLine = [];
      session.pendingLineBytes = 0;
    }
    lineStart = newline + 1;
  }
}

function readSessionEvent(
  line: string,
  session: SessionUsage,
  repository?: string,
  attribution: ScanExecutionAttribution | null = null,
): void {
  if (line.length === 0) return;
  let event: unknown;
  try {
    event = JSON.parse(line) as unknown;
  } catch {
    return;
  }
  if (!isRecord(event) || !isRecord(event["payload"])) return;
  const payload = event["payload"];
  const index = session.eventIndex++;
  if (event["type"] === "session_meta") {
    if (session.threadId !== null) {
      session.replaying = payload["id"] !== session.threadId;
      if (!session.replaying) session.events?.push({ index, event });
      return;
    }
    if (typeof payload["id"] === "string") {
      session.threadId = payload["id"];
    }
    if (typeof payload["cwd"] === "string") {
      session.workingDirectory = payload["cwd"];
    }
    if (typeof payload["model"] === "string") session.model = payload["model"];
    session.startedAt = sessionStartedAt(payload["timestamp"]);
    session.parentThreadId = sessionParentThreadId(payload);
    session.events?.push({ index, event });
    return;
  }
  if (session.replaying) {
    if (event["type"] !== "event_msg") return;
    if (payload["type"] === "token_count" && isRecord(payload["info"])) {
      const usage = tokenUsage(payload["info"]["total_token_usage"]);
      if (usage !== null) session.inheritedUsage = usage;
    }
    if (payload["type"] === "task_started") {
      // Fresh Codex worker thread/turn IDs share a same-process monotonic UUIDv7 generator.
      const threadOrder = uuid7Order(session.threadId);
      const turnOrder = uuid7Order(payload["turn_id"]);
      const owned =
        threadOrder === null
          ? typeof payload["started_at"] === "number" &&
            session.startedAt !== null &&
            payload["started_at"] >= Math.floor(session.startedAt / 1_000)
          : turnOrder !== null && turnOrder >= threadOrder;
      if (owned) {
        session.replaying = false;
        session.events?.push({ index, event });
      }
    }
    return;
  }
  if (
    (event["type"] === "turn_context" || payload["type"] === "task_started") &&
    typeof payload["turn_id"] === "string"
  ) {
    session.currentTurnId = payload["turn_id"];
  }
  if (
    event["type"] === "turn_context" &&
    typeof payload["model"] === "string"
  ) {
    session.model = payload["model"];
  }
  if (event["type"] === "token_usage_record") {
    const responseId = payload["response_id"];
    const usage = tokenUsage(payload["usage"]);
    if (
      typeof responseId !== "string" ||
      usage === null ||
      (typeof payload["thread_id"] === "string" &&
        payload["thread_id"] !== session.threadId) ||
      session.responseIds.has(responseId)
    )
      return;
    session.responseIds.add(responseId);
    const cumulative = tokenUsage(payload["thread_token_usage"]);
    if (cumulative)
      session.expectedResponseTokens = Math.max(
        session.expectedResponseTokens,
        cumulative.total_tokens,
      );
    if (!session.responseUsageObserved) {
      // Exact receipts include compaction and survive counter resets. Keep the
      // legacy counter as an independent lower bound, never add it to receipts.
      session.responseUsageObserved = true;
      session.usage = null;
      session.modelUsage.clear();
    }
    session.responseTokens += usage.total_tokens;
    const turnId =
      typeof payload["turn_id"] === "string"
        ? payload["turn_id"]
        : session.currentTurnId;
    if (
      attribution &&
      !isAttributedScanEvent(
        attribution,
        session.threadId!,
        turnId,
        event["timestamp"],
      )
    )
      return;
    const model =
      typeof payload["model"] === "string" ? payload["model"] : session.model;
    session.usage = addTokenUsage(session.usage, usage);
    session.modelUsage.set(
      model,
      addTokenUsage(session.modelUsage.get(model) ?? null, usage),
    );
    session.events?.push({ index, event });
    return;
  }
  const attributable =
    attribution === null ||
    isAttributedScanEvent(
      attribution,
      session.threadId!,
      session.currentTurnId,
      event["timestamp"],
    );
  if (attributable) session.events?.push({ index, event });
  if (
    !attributable &&
    !(event["type"] === "event_msg" && payload["type"] === "token_count")
  )
    return;
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
  if (usage === null) return;
  const ownUsage =
    session.inheritedUsage === null
      ? usage
      : subtractTokenUsage(usage, session.inheritedUsage);
  if (ownUsage !== null) {
    const delta =
      session.previousUsage === null
        ? ownUsage
        : subtractTokenUsage(ownUsage, session.previousUsage);
    if (
      session.previousUsage !== null &&
      ownUsage.total_tokens < session.previousUsage.total_tokens
    ) {
      session.counterRegressed = true;
      return;
    }
    session.previousUsage = ownUsage;
    if (
      attribution &&
      !isAttributedScanEvent(
        attribution,
        session.threadId!,
        session.currentTurnId,
        event["timestamp"],
      )
    )
      return;
    if (delta !== null && !session.responseUsageObserved) {
      session.modelUsage.set(
        session.model,
        addTokenUsage(session.modelUsage.get(session.model) ?? null, delta),
      );
    }
    session.counterUsage =
      attribution && delta !== null
        ? addTokenUsage(session.counterUsage, delta)
        : ownUsage;
    if (!session.responseUsageObserved) session.usage = session.counterUsage;
  }
}

function uuid7Order(value: unknown): bigint | null {
  if (
    typeof value !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(
      value,
    )
  ) {
    return null;
  }
  return BigInt(`0x${value.replaceAll("-", "")}`);
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isMissingFile(error: unknown): boolean {
  return isRecord(error) && error["code"] === "ENOENT";
}
