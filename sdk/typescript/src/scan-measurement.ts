import { addTokenUsage, type ScanUsageMeasurement } from "./cost.js";
import {
  estimateScanCost,
  tokenUsage,
  type ScanTokenUsage,
} from "./cost-model.js";

export function measurementFromUsage(
  value: unknown,
  model: string,
): ScanUsageMeasurement {
  const usage = tokenUsage(value);
  return {
    usage,
    cost: estimateScanCost(model, usage),
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
): ScanUsageMeasurement {
  let usage: ScanTokenUsage | null = null;
  for (const value of values) {
    if (value.usage !== null) usage = addTokenUsage(usage, value.usage);
  }
  return {
    ...measurementFromUsage(usage, model),
    coverage:
      usage === null
        ? "unavailable"
        : values.every((value) => value.coverage === "complete")
          ? "complete"
          : "partial",
    threadCount: values.reduce((sum, value) => sum + value.threadCount, 0),
    missingThreadCount: values.reduce(
      (sum, value) => sum + value.missingThreadCount,
      0,
    ),
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
