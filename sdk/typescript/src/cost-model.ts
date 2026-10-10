import { isRecord } from "./record.js";
import { isSafeNonNegativeInteger } from "./value.js";

export interface ScanCost {
  model: string;
  inputTokens: number;
  cachedInputTokens: number;
  cacheWriteInputTokens: number;
  cacheWriteInputTokensReported?: boolean;
  outputTokens: number;
  /** Short-context baseline retained for compatibility and spending limits. */
  estimatedUsd: number;
  coverage?: "partial";
  modelCosts?: readonly ScanCost[];
  /** Standard token-cost bounds for the observed usage, not a billing total. */
  estimatedUsdRange?: {
    min: number;
    /** null when a verified upper estimate is unavailable. */
    max: number | null;
    context: "unknown";
  };
  pricing?: {
    source: string;
    asOf: string;
    serviceTier: "standard";
    context: "short";
    /** Short-context rates used by estimatedUsd and the range minimum. */
    usdPerMillionTokens: TokenPrices;
    longContextUsdPerMillionTokens?: TokenPrices;
  };
}

interface TokenPrices {
  input: number;
  cacheRead: number;
  cacheWrite: number;
  output: number;
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

const BEDROCK_MODEL_PRICING: Readonly<
  Record<
    string,
    {
      short: ModelPricing;
      long?: ModelPricing;
      unitsPerUsd: number;
      source: string;
      asOf: string;
    }
  >
> = {
  // AWS commercial in-region Standard prices already include the 10% fee.
  "openai.gpt-daybreak-blue-5.6-sol": {
    short: [4_400, 440, 5_500, 22_000],
    long: [8_800, 880, 11_000, 33_000],
    unitsPerUsd: 1_000_000_000,
    source:
      "https://docs.aws.amazon.com/en_en/bedrock/latest/userguide/model-card-openai-gpt-daybreak-blue-56-sol.html",
    asOf: "2026-10-01",
  },
  "openai.gpt-5.6-cyber": {
    // Half-nanodollar units preserve the $17.1875/M cache-write rate exactly,
    // including an odd number of cache-write tokens.
    short: [27_500, 2_750, 34_375, 165_000],
    unitsPerUsd: 2_000_000_000,
    source:
      "https://docs.aws.amazon.com/en_en/bedrock/latest/userguide/model-card-openai-gpt-56-cyber.html",
    asOf: "2026-10-01",
  },
};

const MODEL_PRICING_NANODOLLARS: Readonly<Record<string, ModelPricing>> = {
  // GPT-5.5 has no additional cache-write charge.
  "gpt-5.5": [5_000, 500, 5_000, 30_000],
  "gpt-5.5-2026-04-23": [5_000, 500, 5_000, 30_000],
  "gpt-6.1-sol": [2_000, 100, 2_500, 10_000],
  "gpt-6-astra": [10_000, 1_000, 12_500, 50_000],
  "gpt-6-luna": [100, 10, 125, 500],
  "gpt-5.6": [4_000, 400, 5_000, 20_000],
  "gpt-5.6-sol": [4_000, 400, 5_000, 20_000],
  "gpt-5.6-terra": [2_000, 200, 2_500, 12_000],
  "gpt-5.6-luna": [200, 20, 250, 1_200],
  // https://developers.openai.com/api/docs/pricing#cyber-models
  "gpt-5.6-cyber": [12_500, 1_250, 15_625, 75_000],
  "gpt-daybreak-blue-latest": [4_000, 400, 5_000, 20_000],
  "gpt-daybreak-red-latest": [12_500, 1_250, 15_625, 75_000],
};

// Verified Standard rates: https://developers.openai.com/api/docs/pricing
// GPT-5.5: https://developers.openai.com/api/docs/models/gpt-5.5
// Do not infer tiers from aggregate scan tokens: the runtime does not report
// which usage received long-context pricing. Cyber/Daybreak Red has no verified
// long-context rate in the pricing table, so its upper estimate stays unavailable.
const LONG_CONTEXT_PRICING_NANODOLLARS: Readonly<Record<string, ModelPricing>> =
  {
    "gpt-5.5": [10_000, 1_000, 10_000, 45_000],
    "gpt-5.5-2026-04-23": [10_000, 1_000, 10_000, 45_000],
    "gpt-6.1-sol": [4_000, 200, 5_000, 15_000],
    "gpt-6-astra": [20_000, 2_000, 25_000, 75_000],
    "gpt-6-luna": [200, 20, 250, 750],
    "gpt-5.6": [8_000, 800, 10_000, 30_000],
    "gpt-5.6-sol": [8_000, 800, 10_000, 30_000],
    "gpt-5.6-terra": [4_000, 400, 5_000, 18_000],
    "gpt-5.6-luna": [400, 40, 500, 1_800],
    "gpt-daybreak-blue-latest": [8_000, 800, 10_000, 30_000],
  };

function usdPerMillionTokens(
  pricing: ModelPricing,
  unitsPerUsd: number,
): TokenPrices {
  const [input, cacheRead, cacheWrite, output] = pricing;
  const unitsPerMillion = unitsPerUsd / 1_000_000;
  return {
    input: input / unitsPerMillion,
    cacheRead: cacheRead / unitsPerMillion,
    cacheWrite: cacheWrite / unitsPerMillion,
    output: output / unitsPerMillion,
  };
}

export function tokenUsage(value: unknown): ScanTokenUsage | null {
  if (!isRecord(value)) return null;
  const input = value["input_tokens"];
  const cached = value["cached_input_tokens"] ?? 0;
  const canonicalCacheWrite = value["cache_write_input_tokens"];
  const legacyCacheWrite = value["cache_write_tokens"];
  const cacheWrite =
    canonicalCacheWrite === 0 &&
    isSafeNonNegativeInteger(input) &&
    isSafeNonNegativeInteger(cached) &&
    isSafeNonNegativeInteger(legacyCacheWrite) &&
    legacyCacheWrite > 0 &&
    cached + legacyCacheWrite <= input
      ? legacyCacheWrite
      : (canonicalCacheWrite ?? legacyCacheWrite ?? 0);
  const output = value["output_tokens"];
  const reasoning = value["reasoning_output_tokens"] ?? 0;
  if (
    !isSafeNonNegativeInteger(input) ||
    !isSafeNonNegativeInteger(cached) ||
    !isSafeNonNegativeInteger(cacheWrite) ||
    !isSafeNonNegativeInteger(output) ||
    !isSafeNonNegativeInteger(reasoning) ||
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
      if (!isRecord(part)) return null;
      const tokens = tokenUsage(part);
      if (tokens === null) return null;
      const cost =
        typeof part["model"] === "string"
          ? estimateModelCost(part["model"], part)
          : null;
      if (cost === null) {
        if (tokens.total_tokens === 0) continue;
        return null;
      }
      costs.push(cost);
    }
    if (costs.length === 0) return null;
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
      estimatedUsdRange: {
        min: sum("estimatedUsd"),
        max: costs.some((cost) => cost.estimatedUsdRange?.max == null)
          ? null
          : costs.reduce(
              (value, cost) => value + cost.estimatedUsdRange!.max!,
              0,
            ),
        context: "unknown",
      },
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

// Internal budget enforcement only. The public estimate remains unavailable
// when some attributed usage has no price.
export function estimateScanCostLowerBound(
  model: string | undefined,
  usage: unknown,
): ScanCost | null {
  if (!isRecord(usage) || !Array.isArray(usage["modelUsage"])) return null;
  const total = tokenUsage(usage);
  if (total === null) return null;
  const keys = [
    "input_tokens",
    "cached_input_tokens",
    "cache_write_input_tokens",
    "output_tokens",
    "reasoning_output_tokens",
  ] as const;
  const observed = Object.fromEntries(keys.map((key) => [key, 0]));
  const priced = Object.fromEntries(keys.map((key) => [key, 0]));
  const parts: Record<string, unknown>[] = [];
  let cacheWritesReported = true;
  for (const part of usage["modelUsage"]) {
    const normalized = tokenUsage(part);
    if (!isRecord(part) || normalized === null) return null;
    for (const key of keys) observed[key]! += normalized[key];
    if (
      typeof part["model"] !== "string" ||
      estimateModelCost(part["model"], part) === null
    )
      continue;
    parts.push(part);
    for (const key of keys) priced[key]! += normalized[key];
    if (normalized.cache_write_input_tokens_reported === false)
      cacheWritesReported = false;
  }
  // A malformed partition is not evidence of an enforceable lower bound.
  if (keys.some((key) => observed[key] !== total[key])) return null;
  return estimateScanCost(model, {
    ...priced,
    cache_write_input_tokens_reported: cacheWritesReported,
    modelUsage: parts,
    coverage: "partial",
  });
}

function estimateModelCost(
  model: string | undefined,
  usage: unknown,
): ScanCost | null {
  if (model === undefined) return null;
  const bedrockPricing = BEDROCK_MODEL_PRICING[model];
  const unitsPerUsd = bedrockPricing?.unitsPerUsd ?? 1_000_000_000;
  const pricingModel = model.startsWith("openai.")
    ? model.slice("openai.".length)
    : model;
  const pricing =
    bedrockPricing?.short ?? MODEL_PRICING_NANODOLLARS[pricingModel];
  const normalized = tokenUsage(usage);
  if (pricing === undefined || normalized === null) return null;
  const [inputRate, cachedInputRate, cacheWriteInputRate, outputRate] = pricing;
  const {
    input_tokens: inputTokens,
    cached_input_tokens: cachedInputTokens,
    cache_write_input_tokens: cacheWriteInputTokens,
    output_tokens: outputTokens,
  } = normalized;

  const costUnits =
    (inputTokens - cachedInputTokens - cacheWriteInputTokens) * inputRate +
    cachedInputTokens * cachedInputRate +
    cacheWriteInputTokens * cacheWriteInputRate +
    outputTokens * outputRate;
  if (!Number.isSafeInteger(costUnits)) return null;

  const longPricing = bedrockPricing
    ? bedrockPricing.long
    : LONG_CONTEXT_PRICING_NANODOLLARS[pricingModel];
  let maximumUnits: number | null = null;
  if (longPricing !== undefined) {
    const [longInput, longRead, longWrite, longOutput] = longPricing;
    // Unclassified input may include additional cache writes. Preserve the
    // reported subtotal, but include that uncertainty in the upper estimate.
    const uncachedRate =
      normalized.cache_write_input_tokens_reported === false
        ? Math.max(longInput, longWrite)
        : longInput;
    const maximum =
      (inputTokens - cachedInputTokens - cacheWriteInputTokens) * uncachedRate +
      cachedInputTokens * longRead +
      cacheWriteInputTokens * longWrite +
      outputTokens * longOutput;
    if (Number.isSafeInteger(maximum)) maximumUnits = maximum;
  }

  return {
    model,
    inputTokens,
    cachedInputTokens,
    cacheWriteInputTokens,
    ...(normalized.cache_write_input_tokens_reported === false
      ? { cacheWriteInputTokensReported: false }
      : {}),
    outputTokens,
    estimatedUsd: costUnits / unitsPerUsd,
    estimatedUsdRange: {
      min: costUnits / unitsPerUsd,
      max: maximumUnits === null ? null : maximumUnits / unitsPerUsd,
      context: "unknown",
    },
    pricing: {
      source: bedrockPricing
        ? bedrockPricing.source
        : pricingModel.startsWith("gpt-5.5")
          ? "https://developers.openai.com/api/docs/models/gpt-5.5"
          : "https://developers.openai.com/api/docs/pricing",
      asOf: bedrockPricing
        ? bedrockPricing.asOf
        : pricingModel === "gpt-5.6-cyber"
          ? "2026-10-06"
          : pricingModel === "gpt-6.1-sol" || pricingModel === "gpt-6-luna"
            ? "2026-09-30"
            : "2026-09-14",
      serviceTier: "standard",
      context: "short",
      usdPerMillionTokens: usdPerMillionTokens(pricing, unitsPerUsd),
      ...(longPricing === undefined
        ? {}
        : {
            longContextUsdPerMillionTokens: usdPerMillionTokens(
              longPricing,
              unitsPerUsd,
            ),
          }),
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

export function formatScanCost(cost: Readonly<ScanCost>): string {
  return formatScanCosts([cost]);
}

export function formatScanCosts(costs: readonly Readonly<ScanCost>[]): string {
  if (costs.some((cost) => cost.estimatedUsdRange === undefined)) {
    return `${formatUsd(costs.reduce((sum, cost) => sum + cost.estimatedUsd, 0))} (legacy estimate, context unknown)`;
  }
  const minimum = costs.reduce(
    (sum, cost) => sum + cost.estimatedUsdRange!.min,
    0,
  );
  const maximum = costs.some((cost) => cost.estimatedUsdRange!.max === null)
    ? null
    : costs.reduce((sum, cost) => sum + cost.estimatedUsdRange!.max!, 0);
  const cacheWrites = costs.some(
    (cost) => cost.cacheWriteInputTokensReported === false,
  )
    ? ", cache writes unknown"
    : "";
  if (maximum === null) {
    return `at least ${formatUsd(minimum)} (standard, upper estimate unavailable${cacheWrites})`;
  }
  const amount =
    minimum === maximum
      ? formatUsd(minimum)
      : `${formatUsd(minimum)}–${formatUsd(maximum)}`;
  return `${amount} (standard, context unknown${cacheWrites})`;
}

export function formatUsd(value: number): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 2,
    maximumFractionDigits: 9,
  }).format(value);
}
