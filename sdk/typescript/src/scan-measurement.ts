import { addTokenUsage, type ScanUsageMeasurement } from "./cost.js";
import {
  estimateScanCost,
  tokenUsage,
  type ScanPricingContext,
  type ScanTokenUsage,
} from "./cost-model.js";

export function measurementFromUsage(
  value: unknown,
  model: string,
  pricingContext?: ScanPricingContext,
): ScanUsageMeasurement {
  const usage = tokenUsage(value);
  return {
    usage,
    cost: estimateScanCost(model, usage, pricingContext),
    coverage: usage === null ? "unavailable" : "complete",
    observedAt: new Date().toISOString(),
    threadCount: usage === null ? 0 : 1,
    missingThreadCount: usage === null ? 1 : 0,
  };
}

/** Only for disjoint stage invocations, not cumulative observations of one thread. */
export function combineMeasurements(
  values: readonly Readonly<ScanUsageMeasurement>[],
  model: string,
  pricingContext?: ScanPricingContext,
): ScanUsageMeasurement {
  let usage: ScanTokenUsage | null = null;
  for (const value of values) {
    if (value.usage !== null) usage = addTokenUsage(usage, value.usage);
  }
  const warnings = [
    ...new Set(values.flatMap((value) => value.warnings ?? [])),
  ].sort();
  const coverage =
    usage === null
      ? "unavailable"
      : values.every((value) => value.coverage === "complete")
        ? "complete"
        : "partial";
  const missingThreadCount = values.reduce(
    (sum, value) => sum + value.missingThreadCount,
    0,
  );
  // A stage can lack tokens without naming a missing thread.
  if (coverage === "partial" && !missingThreadCount && !warnings.length)
    warnings.push("token_usage_unavailable");
  return {
    ...measurementFromUsage(usage, model, pricingContext),
    ...(warnings.length ? { warnings } : {}),
    coverage,
    threadCount: values.reduce((sum, value) => sum + value.threadCount, 0),
    missingThreadCount,
    ...(values.every((value) => value.coverageScope !== undefined)
      ? {
          coverageScope: [
            ...new Set(values.flatMap((value) => value.coverageScope!)),
          ].sort(),
        }
      : {}),
  };
}

/** Workbench envelope keeps usage even when the selected model has no price. */
export function measuredScanCost(
  measurement: Readonly<ScanUsageMeasurement> | null,
) {
  if (measurement?.usage == null) return null;
  const tokens = measurement.usage;
  return {
    usage: {
      source: "codex_runtime",
      coverage: measurement.coverage,
      observedAt: measurement.observedAt,
      threadCount: measurement.threadCount,
      missingThreadCount: measurement.missingThreadCount,
      // The workbench accepts up to 32 diagnostic codes across all stages.
      ...(measurement.warnings?.length
        ? { warnings: measurement.warnings.slice(0, 32) }
        : {}),
      ...(measurement.coverageScope === undefined
        ? {}
        : { coverageScope: measurement.coverageScope }),
      inputTokens: tokens.input_tokens,
      cachedInputTokens: tokens.cached_input_tokens,
      cacheWriteInputTokens: tokens.cache_write_input_tokens,
      ...(tokens.cache_write_input_tokens_reported === undefined
        ? {}
        : {
            cacheWriteInputTokensReported:
              tokens.cache_write_input_tokens_reported,
          }),
      outputTokens: tokens.output_tokens,
      reasoningOutputTokens: tokens.reasoning_output_tokens,
      totalTokens: tokens.total_tokens,
    },
    ...(measurement.cost === null ? {} : { cost: measurement.cost }),
  };
}
