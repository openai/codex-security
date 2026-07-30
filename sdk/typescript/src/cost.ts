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
  remainder: Buffer;
  threadId: string | null;
  parentThreadId: string | null;
  usage: ScanTokenUsage | null;
}

interface ScanCostTrackerOptions {
  codexHome: string;
  model?: string;
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

const COST_POLL_INTERVAL_MS = 100;
const SESSION_READ_SIZE = 64 * 1_024;

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
    const poll = () => {
      void this.refresh().catch((error: unknown) => {
        this.#options.onError?.(error);
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
    await this.refresh();
    if (this.#snapshot.usage !== null) return this.#snapshot;
    const cost = estimateScanCost(this.#options.model, fallbackUsage);
    this.#snapshot = { usage: fallbackUsage ?? null, cost };
    this.#reportCost(cost);
    return this.#snapshot;
  }

  async #readSessions(): Promise<void> {
    if (this.#threadId === null) return;
    for await (const path of sessionFiles(
      join(this.#options.codexHome, "sessions"),
    )) {
      let session = this.#sessions.get(path);
      if (session === undefined) {
        session = {
          offset: 0,
          remainder: Buffer.alloc(0),
          threadId: null,
          parentThreadId: null,
          usage: null,
        };
        this.#sessions.set(path, session);
      }
      await readSessionUsage(path, session);
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
      const contents = Buffer.concat([
        session.remainder,
        buffer.subarray(0, bytesRead),
      ]);
      let lineStart = 0;
      while (true) {
        const lineEnd = contents.indexOf(0x0a, lineStart);
        if (lineEnd === -1) break;
        readSessionEvent(
          contents.subarray(lineStart, lineEnd).toString("utf8"),
          session,
        );
        lineStart = lineEnd + 1;
      }
      session.remainder = Buffer.from(contents.subarray(lineStart));
    }
  } finally {
    await file.close();
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
