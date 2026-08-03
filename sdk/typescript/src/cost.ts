import { open, readdir } from "node:fs/promises";
import { join } from "node:path";

export interface ScanCost {
  model: string;
  inputTokens: number;
  cachedInputTokens: number;
  cacheWriteInputTokens: number;
  outputTokens: number;
  estimatedUsd: number;
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

interface SessionUsage {
  offset: number;
  pendingLine: Buffer[];
  pendingLineBytes: number;
  unreadable: boolean;
  threadId: string | null;
  parentThreadId: string | null;
  usage: ScanTokenUsage | null;
}

interface ScanCostTrackerOptions {
  codexHome: string;
  model: string;
  maxCostUsd?: number;
  onCost?: (cost: Readonly<ScanCost>) => void;
  onError?: (error: unknown) => void;
}

interface ScanCostSnapshot {
  usage: unknown;
  cost: ScanCost | null;
}

const MODEL_PRICING_NANODOLLARS: Readonly<Record<string, ModelPricing>> = {
  "gpt-5.6": [5_000, 500, 6_250, 30_000],
  "gpt-5.6-sol": [5_000, 500, 6_250, 30_000],
  "gpt-5.6-terra": [2_500, 250, 3_125, 15_000],
  "gpt-5.6-luna": [1_000, 100, 1_250, 6_000],
};

// Open failures that keep failing until the file itself changes. Every other
// code (EMFILE, ENFILE, EIO and friends) is treated as transient and retried.
const PERMANENT_ACCESS_ERROR_CODES: ReadonlySet<string> = new Set([
  "EACCES",
  "EPERM",
  "EISDIR",
  "ELOOP",
  "ENAMETOOLONG",
  "ENOTDIR",
]);

const COST_POLL_INTERVAL_MS = 100;
const SESSION_READ_SIZE = 64 * 1_024;
const MAX_SESSION_EVENT_BYTES = 1 * 1_024 * 1_024;

export class ScanCostTracker {
  readonly #options: ScanCostTrackerOptions;
  readonly #sessions = new Map<string, SessionUsage>();
  #threadId: string | null = null;
  #timer: NodeJS.Timeout | null = null;
  #pending: Promise<void> = Promise.resolve();
  #snapshot: ScanCostSnapshot = { usage: null, cost: null };
  #lastCost: number | null = null;

  public constructor(options: ScanCostTrackerOptions) {
    this.#options = options;
  }

  public start(threadId: string): void {
    if (this.#threadId !== null) return;
    this.#threadId = threadId;
    if (this.#options.maxCostUsd === undefined) return;
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
    let refreshed = true;
    try {
      await this.refresh();
    } catch {
      refreshed = false;
    }
    if (refreshed && this.#snapshot.usage !== null) return this.#snapshot;
    // This refresh failed, so the snapshot predates the completed turn. The
    // caller's own usage is authoritative for the scan thread, so it has to be
    // able to win; keeping the stale snapshot would hide spend from `onCost`.
    const cost = estimateScanCost(this.#options.model, fallbackUsage);
    if (
      this.#snapshot.usage !== null &&
      !chargesMore(cost, this.#snapshot.cost)
    ) {
      return this.#snapshot;
    }
    this.#snapshot = { usage: fallbackUsage ?? null, cost };
    this.#reportCost(cost);
    return this.#snapshot;
  }

  async #readSessions(): Promise<void> {
    if (this.#threadId === null) return;
    const unreadable: Array<{ session: SessionUsage; error: unknown }> = [];
    for await (const path of sessionFiles(
      join(this.#options.codexHome, "sessions"),
    )) {
      let session = this.#sessions.get(path);
      if (session === undefined) {
        session = {
          offset: 0,
          pendingLine: [],
          pendingLineBytes: 0,
          unreadable: false,
          threadId: null,
          parentThreadId: null,
          usage: null,
        };
        this.#sessions.set(path, session);
      }
      try {
        await readSessionUsage(path, session);
      } catch (error) {
        if (session.threadId === null) throw error;
        unreadable.push({ session, error });
      }
    }

    const included = new Set([this.#threadId]);
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
          included.add(session.threadId);
          changed = true;
        }
      }
    }
    for (const { session, error } of unreadable) {
      if (included.has(session.threadId!)) throw error;
    }

    let usage: ScanTokenUsage | null = null;
    for (const session of this.#sessions.values()) {
      if (
        session.threadId !== null &&
        included.has(session.threadId) &&
        session.usage !== null
      ) {
        usage = addTokenUsage(usage, session.usage);
      }
    }
    if (usage === null) return;
    const cost = estimateScanCost(this.#options.model, usage);
    this.#snapshot = { usage, cost };
    this.#reportCost(cost);
  }

  #reportCost(cost: ScanCost | null): void {
    if (cost === null || cost.estimatedUsd === this.#lastCost) return;
    this.#lastCost = cost.estimatedUsd;
    this.#options.onCost?.(cost);
  }
}

async function* sessionFiles(directory: string): AsyncGenerator<string> {
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
): Promise<void> {
  if (session.unreadable) return;
  let file;
  try {
    file = await open(path, "r");
  } catch (error) {
    if (isMissingFile(error)) return;
    // A process-wide shortage such as EMFILE clears on its own, so quarantining
    // would stop observing this session's usage for the rest of the scan. Only
    // a persistent, file-specific access failure earns a permanent quarantine.
    if (isPermanentAccessError(error)) quarantineSession(session);
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
        readSessionChunk(buffer.subarray(0, bytesRead), session);
      } catch (error) {
        quarantineSession(session);
        throw error;
      }
    }
  } finally {
    await file.close();
  }
}

function quarantineSession(session: SessionUsage): void {
  session.unreadable = true;
  session.pendingLine = [];
  session.pendingLineBytes = 0;
}

function readSessionChunk(contents: Buffer, session: SessionUsage): void {
  let lineStart = 0;
  while (lineStart < contents.length) {
    const newline = contents.indexOf(0x0a, lineStart);
    const lineEnd = newline === -1 ? contents.length : newline;
    const fragment = contents.subarray(lineStart, lineEnd);
    const lineBytes = session.pendingLineBytes + fragment.length;
    if (lineBytes > MAX_SESSION_EVENT_BYTES) {
      throw new Error("Codex session event exceeds the 1 MiB safety limit.");
    }

    if (newline === -1) {
      if (fragment.length > 0) {
        session.pendingLine.push(Buffer.from(fragment));
        session.pendingLineBytes = lineBytes;
      }
      return;
    }

    if (session.pendingLineBytes === 0) {
      readSessionEvent(fragment.toString("utf8"), session);
    } else {
      if (fragment.length > 0) session.pendingLine.push(Buffer.from(fragment));
      readSessionEvent(
        Buffer.concat(session.pendingLine, lineBytes).toString("utf8"),
        session,
      );
      session.pendingLine = [];
      session.pendingLineBytes = 0;
    }
    lineStart = newline + 1;
  }
}

function readSessionEvent(line: string, session: SessionUsage): void {
  if (line.length === 0) return;
  let event: unknown;
  try {
    event = JSON.parse(line) as unknown;
  } catch {
    return;
  }
  if (!isRecord(event) || !isRecord(event["payload"])) return;
  const payload = event["payload"];
  if (event["type"] === "session_meta") {
    if (typeof payload["id"] === "string") {
      session.threadId = payload["id"];
    }
    const source = payload["source"];
    const subagent = isRecord(source) ? source["subagent"] : undefined;
    const spawn = isRecord(subagent) ? subagent["thread_spawn"] : undefined;
    const parent =
      payload["parent_thread_id"] ??
      (isRecord(spawn) ? spawn["parent_thread_id"] : undefined);
    if (typeof parent === "string") session.parentThreadId = parent;
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
  if (usage !== null) session.usage = usage;
}

function tokenUsage(value: unknown): ScanTokenUsage | null {
  if (!isRecord(value)) return null;
  const input = value["input_tokens"];
  const cached = value["cached_input_tokens"] ?? 0;
  const cacheWrite =
    value["cache_write_input_tokens"] ?? value["cache_write_tokens"] ?? 0;
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isMissingFile(error: unknown): boolean {
  return isRecord(error) && error["code"] === "ENOENT";
}

function isPermanentAccessError(error: unknown): boolean {
  if (!isRecord(error)) return false;
  const code = error["code"];
  return typeof code === "string" && PERMANENT_ACCESS_ERROR_CODES.has(code);
}

function chargesMore(
  cost: ScanCost | null,
  previous: ScanCost | null,
): boolean {
  if (cost === null) return false;
  return previous === null || cost.estimatedUsd > previous.estimatedUsd;
}

export function estimateScanCost(
  model: string | undefined,
  usage: unknown,
): ScanCost | null {
  if (model === undefined) return null;
  const pricing = MODEL_PRICING_NANODOLLARS[model];
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
