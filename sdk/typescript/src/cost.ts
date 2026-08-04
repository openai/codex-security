import {
  CodexRolloutReader,
  normalizeTokenUsage,
  type ScanTokenUsage,
} from "./codex-rollouts.js";

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

interface ScanCostTrackerOptions {
  codexHome: string;
  rolloutReader?: CodexRolloutReader;
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

const COST_POLL_INTERVAL_MS = 100;
export class ScanCostTracker {
  readonly #options: ScanCostTrackerOptions;
  readonly #rolloutReader: CodexRolloutReader;
  #threadId: string | null = null;
  #timer: NodeJS.Timeout | null = null;
  #pending: Promise<void> = Promise.resolve();
  #snapshot: ScanCostSnapshot = { usage: null, cost: null };
  #lastCost: number | null = null;

  public constructor(options: ScanCostTrackerOptions) {
    this.#options = options;
    this.#rolloutReader =
      options.rolloutReader ?? new CodexRolloutReader(options.codexHome);
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
    await this.refresh();
    if (this.#snapshot.usage !== null) return this.#snapshot;
    const cost = estimateScanCost(this.#options.model, fallbackUsage);
    this.#snapshot = { usage: fallbackUsage ?? null, cost };
    this.#reportCost(cost);
    return this.#snapshot;
  }

  async #readSessions(): Promise<void> {
    if (this.#threadId === null) return;
    const sessions = await this.#rolloutReader.refresh(this.#threadId);
    let usage: ScanTokenUsage | null = null;
    for (const session of sessions) {
      if (session.usage !== null) {
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

export function estimateScanCost(
  model: string | undefined,
  usage: unknown,
): ScanCost | null {
  if (model === undefined) return null;
  const pricing = MODEL_PRICING_NANODOLLARS[model];
  const normalized = normalizeTokenUsage(usage);
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
