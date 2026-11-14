import { vertexModelPricing } from "./vertex-pricing.js";
import { bedrockModelPricing } from "./bedrock-pricing.js";
import { isRecord } from "./record.js";
import { isSafeNonNegativeInteger } from "./value.js";

export type ScanPricingContext =
  | { provider: "amazon-bedrock"; region: string | null }
  | { provider: "gcp"; managedEndpoint?: boolean };

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

type TokenPrices = ReturnType<typeof usdPerMillionTokens>;

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

// Direct Standard rates in nanodollars per token. Omit the long-context
// rate when there is no verified upper estimate for a model.
function directRate(
  asOf: string,
  short: ModelPricing,
  long?: ModelPricing,
  source = "https://developers.openai.com/api/docs/pricing",
) {
  return { short, long, unitsPerUsd: 1_000_000_000, source, asOf };
}

const gpt55 = directRate(
  "2026-09-14",
  [5_000, 500, 5_000, 30_000],
  [10_000, 1_000, 10_000, 45_000],
  "https://developers.openai.com/api/docs/models/gpt-5.5",
);
const gpt56Sol = directRate(
  "2026-09-14",
  [4_000, 400, 5_000, 20_000],
  [8_000, 800, 10_000, 30_000],
);
const directPricing: Readonly<Record<string, ReturnType<typeof directRate>>> = {
  "gpt-5.5": gpt55,
  "gpt-5.5-2026-04-23": gpt55,
  "gpt-6-sol": directRate(
    "2026-10-10",
    [2_000, 200, 2_500, 10_000],
    [4_000, 400, 5_000, 15_000],
    "https://developers.openai.com/api/docs/models/gpt-6-sol",
  ),
  "gpt-6.1-sol": directRate(
    "2026-09-30",
    [2_000, 100, 2_500, 10_000],
    [4_000, 200, 5_000, 15_000],
  ),
  "gpt-6-astra": directRate(
    "2026-09-14",
    [10_000, 1_000, 12_500, 50_000],
    [20_000, 2_000, 25_000, 75_000],
  ),
  "gpt-6-luna": directRate(
    "2026-09-30",
    [100, 10, 125, 500],
    [200, 20, 250, 750],
  ),
  "gpt-5.6": gpt56Sol,
  "gpt-5.6-sol": gpt56Sol,
  "gpt-5.6-terra": directRate(
    "2026-09-14",
    [2_000, 200, 2_500, 12_000],
    [4_000, 400, 5_000, 18_000],
  ),
  "gpt-5.6-luna": directRate(
    "2026-09-14",
    [200, 20, 250, 1_200],
    [400, 40, 500, 1_800],
  ),
  "gpt-5.6-cyber": directRate("2026-10-06", [12_500, 1_250, 15_625, 75_000]),
  "gpt-6-cyber": directRate("2026-11-05", [20_000, 2_000, 25_000, 100_000]),
};

function usdPerMillionTokens(pricing: ModelPricing, unitsPerUsd: number) {
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

function providerModelPricing(
  model: string,
  context?: ScanPricingContext | string | null,
) {
  if (context === undefined && Object.hasOwn(directPricing, model))
    return directPricing[model];
  if (context == null || typeof context === "string") {
    return bedrockModelPricing(model, context);
  }
  if (context.provider === "amazon-bedrock") {
    return bedrockModelPricing(model, context.region);
  }
  if (context.provider === "gcp" && context.managedEndpoint !== false) {
    return vertexModelPricing(model);
  }
  return undefined;
}

/**
 * Estimates Standard token costs using the selected provider's published rates.
 * A string (or null for an unknown region) selects Bedrock for compatibility.
 * Model-only Bedrock frontier estimates use the commercial in-region price.
 */
export function estimateScanCost(
  model: string | undefined,
  usage: unknown,
  context?: ScanPricingContext | string | null,
): ScanCost | null {
  if (isRecord(usage) && Array.isArray(usage["modelUsage"])) {
    const total = tokenUsage(usage);
    if (total === null || usage["modelUsage"].length === 0) return null;
    const costs: ScanCost[] = [];
    for (const part of usage["modelUsage"]) {
      if (!isRecord(part)) return null;
      const tokens = tokenUsage(part);
      if (tokens === null) return null;
      if (tokens.total_tokens === 0) continue;
      if (typeof part["model"] !== "string") return null;
      const cost = estimateModelCost(part["model"], part, context);
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
    if (costs.length === 0)
      return estimateScanCost(
        model,
        { ...total, coverage: usage["coverage"] },
        context,
      );
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
  const cost = estimateModelCost(model, usage, context);
  return cost && isRecord(usage) && usage["coverage"] === "partial"
    ? { ...cost, coverage: "partial" }
    : cost;
}

// Internal budget enforcement only. The public estimate remains unavailable
// when some attributed usage has no price.
export function estimateScanCostLowerBound(
  model: string | undefined,
  usage: unknown,
  context?: ScanPricingContext | string | null,
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
      estimateModelCost(part["model"], part, context) === null
    )
      continue;
    parts.push(part);
    for (const key of keys) priced[key]! += normalized[key];
    if (normalized.cache_write_input_tokens_reported === false)
      cacheWritesReported = false;
  }
  // A malformed partition is not evidence of an enforceable lower bound.
  if (keys.some((key) => observed[key] !== total[key])) return null;
  return estimateScanCost(
    model,
    {
      ...priced,
      cache_write_input_tokens_reported: cacheWritesReported,
      modelUsage: parts,
      coverage: "partial",
    },
    context,
  );
}

function estimateModelCost(
  model: string | undefined,
  usage: unknown,
  context?: ScanPricingContext | string | null,
): ScanCost | null {
  if (model === undefined) return null;
  const rate = providerModelPricing(model, context);
  const normalized = tokenUsage(usage);
  if (rate === undefined || normalized === null) return null;
  const { short, long, unitsPerUsd, source, asOf } = rate;
  const {
    input_tokens: inputTokens,
    cached_input_tokens: cachedInputTokens,
    cache_write_input_tokens: cacheWriteInputTokens,
    output_tokens: outputTokens,
  } = normalized;

  const uncachedTokens =
    inputTokens - cachedInputTokens - cacheWriteInputTokens;

  function priceInUsd(
    [input, read, write, output]: ModelPricing,
    unknownWrites: boolean,
  ) {
    // Unclassified input may include writes. Account for them only in the upper bound.
    const units =
      uncachedTokens * (unknownWrites ? Math.max(input, write) : input) +
      cachedInputTokens * read +
      cacheWriteInputTokens * write +
      outputTokens * output;
    return Number.isSafeInteger(units) ? units / unitsPerUsd : null;
  }
  const estimatedUsd = priceInUsd(short, false);
  if (estimatedUsd === null) return null;
  const unknownWrites = normalized.cache_write_input_tokens_reported === false;

  return {
    model,
    inputTokens,
    cachedInputTokens,
    cacheWriteInputTokens,
    ...(unknownWrites ? { cacheWriteInputTokensReported: false } : {}),
    outputTokens,
    estimatedUsd,
    estimatedUsdRange: {
      min: estimatedUsd,
      max: long === undefined ? null : priceInUsd(long, unknownWrites),
      context: "unknown",
    },
    pricing: {
      source,
      asOf,
      serviceTier: "standard",
      context: "short",
      usdPerMillionTokens: usdPerMillionTokens(short, unitsPerUsd),
      ...(long === undefined
        ? {}
        : {
            longContextUsdPerMillionTokens: usdPerMillionTokens(
              long,
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
