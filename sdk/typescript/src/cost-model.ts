export interface ScanCost {
  model: string;
  inputTokens: number;
  cachedInputTokens: number;
  cacheWriteInputTokens: number;
  cacheWriteInputTokensReported?: boolean;
  outputTokens: number;
  estimatedUsd: number;
  coverage?: "partial";
  modelCosts?: readonly ScanCost[];
  pricing?: {
    source: string;
    asOf: string;
    serviceTier: "standard";
    context: "short";
    usdPerMillionTokens: {
      input: number;
      cacheRead: number;
      cacheWrite: number;
      output: number;
    };
  };
}

type ModelPricing = readonly [
  input: number,
  cachedInput: number,
  cacheWriteInput: number,
  output: number,
];

export interface ScanTokenUsage {
  input_tokens: number;
  cached_input_tokens: number;
  cache_write_input_tokens: number;
  cache_write_input_tokens_reported?: boolean;
  output_tokens: number;
  reasoning_output_tokens: number;
  total_tokens: number;
}

const MODEL_PRICING_NANODOLLARS: Readonly<Record<string, ModelPricing>> = {
  // GPT-5.5 has no additional cache-write charge.
  "gpt-5.5": [5_000, 500, 5_000, 30_000],
  "gpt-5.5-2026-04-23": [5_000, 500, 5_000, 30_000],
  "gpt-6-astra": [10_000, 1_000, 12_500, 50_000],
  "gpt-5.6": [4_000, 400, 5_000, 20_000],
  "gpt-5.6-sol": [4_000, 400, 5_000, 20_000],
  "gpt-5.6-terra": [2_000, 200, 2_500, 12_000],
  "gpt-5.6-luna": [200, 20, 250, 1_200],
  // https://developers.openai.com/api/docs/pricing#cyber-models
  "gpt-daybreak-blue-latest": [4_000, 400, 5_000, 20_000],
  "gpt-daybreak-red-latest": [12_500, 1_250, 15_625, 75_000],
};

export function tokenUsage(value: unknown): ScanTokenUsage | null {
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
      : (canonicalCacheWrite ?? legacyCacheWrite ?? 0);
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
    ...(value["cache_write_input_tokens_reported"] === false ||
    (canonicalCacheWrite == null && legacyCacheWrite == null)
      ? { cache_write_input_tokens_reported: false }
      : {}),
    output_tokens: output,
    reasoning_output_tokens: reasoning,
    total_tokens: input + output,
  };
}

export function estimateScanCost(
  model: string | undefined,
  usage: unknown,
): ScanCost | null {
  if (isRecord(usage) && Array.isArray(usage["modelUsage"])) {
    const total = tokenUsage(usage);
    if (total === null || usage["modelUsage"].length === 0) return null;
    const costs: ScanCost[] = [];
    for (const part of usage["modelUsage"]) {
      if (!isRecord(part) || typeof part["model"] !== "string") return null;
      const cost = estimateModelCost(part["model"], part);
      if (cost === null) return null;
      costs.push(cost);
    }
    const sum = (
      key:
        | "inputTokens"
        | "cachedInputTokens"
        | "cacheWriteInputTokens"
        | "outputTokens"
        | "estimatedUsd",
    ) => costs.reduce((value, cost) => value + cost[key], 0);
    if (
      sum("inputTokens") !== total.input_tokens ||
      sum("cachedInputTokens") !== total.cached_input_tokens ||
      sum("cacheWriteInputTokens") !== total.cache_write_input_tokens ||
      sum("outputTokens") !== total.output_tokens
    )
      return null;
    return {
      model: model ?? costs[0]!.model,
      inputTokens: total.input_tokens,
      cachedInputTokens: total.cached_input_tokens,
      cacheWriteInputTokens: total.cache_write_input_tokens,
      ...(total.cache_write_input_tokens_reported === false
        ? { cacheWriteInputTokensReported: false }
        : {}),
      outputTokens: total.output_tokens,
      estimatedUsd: sum("estimatedUsd"),
      modelCosts: costs,
      ...(costs.length === 1 ? { pricing: costs[0]!.pricing } : {}),
      ...(usage["coverage"] === "partial"
        ? { coverage: "partial" as const }
        : {}),
    };
  }
  const cost = estimateModelCost(model, usage);
  return cost && isRecord(usage) && usage["coverage"] === "partial"
    ? { ...cost, coverage: "partial" }
    : cost;
}

function estimateModelCost(
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
    ...(normalized.cache_write_input_tokens_reported === false
      ? { cacheWriteInputTokensReported: false }
      : {}),
    outputTokens,
    estimatedUsd: nanodollars / 1_000_000_000,
    pricing: {
      source: pricingModel.startsWith("gpt-5.5")
        ? "https://developers.openai.com/api/docs/models/gpt-5.5"
        : "https://developers.openai.com/api/docs/pricing",
      asOf: "2026-09-09",
      serviceTier: "standard",
      context: "short",
      usdPerMillionTokens: {
        input: inputRate / 1_000,
        cacheRead: cachedInputRate / 1_000,
        cacheWrite: cacheWriteInputRate / 1_000,
        output: outputRate / 1_000,
      },
    },
  };
}

export function formatTokenUsage(value: unknown): string | null {
  const usage = tokenUsage(value);
  if (usage === null) return null;
  const writes =
    usage.cache_write_input_tokens_reported === false
      ? null
      : usage.cache_write_input_tokens;
  const uncached =
    writes === null
      ? null
      : usage.input_tokens - usage.cached_input_tokens - writes;
  return (
    [
      [uncached, "uncached input"],
      [usage.cached_input_tokens, "cache reads"],
      [writes, "cache writes"],
      [usage.output_tokens, "output"],
      [usage.total_tokens, "total"],
    ] as const
  )
    .map(
      ([count, label]) =>
        `${count === null ? "unavailable" : count.toLocaleString("en-US")} ${label}`,
    )
    .join(", ");
}

export function formatScanCostTokens(cost: Readonly<ScanCost>): string {
  return formatTokenUsage({
    input_tokens: cost.inputTokens,
    cached_input_tokens: cost.cachedInputTokens,
    cache_write_input_tokens: cost.cacheWriteInputTokens,
    cache_write_input_tokens_reported: cost.cacheWriteInputTokensReported,
    output_tokens: cost.outputTokens,
  })!;
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
