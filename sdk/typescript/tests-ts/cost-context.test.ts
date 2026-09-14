import { expect, test } from "bun:test";
import {
  estimateScanCost,
  formatScanCost,
  formatScanCosts,
} from "../src/cost-model.js";

// Standard prices per million: input, cache reads, cache writes, output.
test.each([
  ["gpt-5.5", [5, 0.5, 5, 30], [10, 1, 10, 45]],
  ["gpt-5.5-2026-04-23", [5, 0.5, 5, 30], [10, 1, 10, 45]],
  ["gpt-6-astra", [10, 1, 12.5, 50], [20, 2, 25, 75]],
  ["gpt-5.6", [4, 0.4, 5, 20], [8, 0.8, 10, 30]],
  ["gpt-5.6-sol", [4, 0.4, 5, 20], [8, 0.8, 10, 30]],
  ["gpt-5.6-terra", [2, 0.2, 2.5, 12], [4, 0.4, 5, 18]],
  ["gpt-5.6-luna", [0.2, 0.02, 0.25, 1.2], [0.4, 0.04, 0.5, 1.8]],
  ["gpt-daybreak-blue-latest", [4, 0.4, 5, 20], [8, 0.8, 10, 30]],
] as const)(
  "%s bounds each token category with verified rates",
  (model, short, long) => {
    for (const category of [0, 1, 2, 3] as const) {
      for (const selected of [model, `openai.${model}`]) {
        const cost = estimateScanCost(selected, {
          input_tokens: category === 3 ? 0 : 1_000_000,
          cached_input_tokens: category === 1 ? 1_000_000 : 0,
          cache_write_input_tokens: category === 2 ? 1_000_000 : 0,
          output_tokens: category === 3 ? 1_000_000 : 0,
        })!;
        expect(cost.estimatedUsd).toBe(short[category]);
        expect(cost.estimatedUsdRange).toEqual({
          min: short[category],
          max: long[category],
          context: "unknown",
        });
      }
    }
  },
);

test("reports a range for cache-heavy scans without changing the budget baseline", () => {
  const cost = estimateScanCost("gpt-5.6-sol", {
    input_tokens: 150_000_000,
    cached_input_tokens: 138_000_000,
    cache_write_input_tokens: 11_700_000,
    output_tokens: 900_000,
  })!;
  expect(cost.estimatedUsd).toBe(132.9);
  expect(cost.estimatedUsdRange).toEqual({
    min: 132.9,
    max: 256.8,
    context: "unknown",
  });
  expect(formatScanCost(cost)).toBe(
    "$132.90–$256.80 (standard, context unknown)",
  );
});

test("widens the maximum for unreported cache writes without changing token counts", () => {
  const usage = {
    input_tokens: 1_000_000,
    cached_input_tokens: 200_000,
    output_tokens: 0,
  };
  const missing = estimateScanCost("gpt-5.6-sol", usage)!;
  const zero = estimateScanCost("gpt-5.6-sol", {
    ...usage,
    cache_write_input_tokens: 0,
  })!;
  const partial = estimateScanCost("gpt-5.6-sol", {
    ...usage,
    cache_write_input_tokens: 300_000,
    cache_write_input_tokens_reported: false,
  })!;
  expect(missing.cacheWriteInputTokens).toBe(0);
  expect(missing.estimatedUsdRange).toMatchObject({ min: 3.28, max: 8.16 });
  expect(zero.estimatedUsdRange).toMatchObject({ min: 3.28, max: 6.56 });
  expect(partial.cacheWriteInputTokens).toBe(300_000);
  expect(partial.estimatedUsdRange).toMatchObject({ min: 3.58, max: 8.16 });
  expect(formatScanCost(missing)).toContain("cache writes unknown");
});

test("keeps unverified long-context prices unavailable", () => {
  const cost = estimateScanCost("gpt-daybreak-red-latest", {
    input_tokens: 1_000_000,
    cache_write_input_tokens: 0,
    output_tokens: 0,
  })!;
  expect(cost.estimatedUsdRange).toEqual({
    min: 12.5,
    max: null,
    context: "unknown",
  });
  expect(formatScanCost(cost)).toBe(
    "at least $12.50 (standard, upper estimate unavailable)",
  );
});

test("unavailable upper arithmetic does not disable an existing budget estimate", () => {
  const cost = estimateScanCost("gpt-6-astra", {
    input_tokens: 600_000_000_000,
    cache_write_input_tokens: 0,
    output_tokens: 0,
  })!;
  expect(cost.estimatedUsd).toBe(6_000_000);
  expect(cost.estimatedUsdRange?.max).toBeNull();
});

test("component totals preserve uncertainty and label legacy records without repricing", () => {
  const cost = estimateScanCost("gpt-5.6-sol", {
    input_tokens: 1_000_000,
    cache_write_input_tokens: 0,
    output_tokens: 0,
  })!;
  expect(formatScanCosts([cost, cost])).toBe(
    "$8.00–$16.00 (standard, context unknown)",
  );
  const { estimatedUsdRange: _range, pricing: _pricing, ...legacy } = cost;
  legacy.estimatedUsd = 3;
  expect(formatScanCost(legacy)).toBe(
    "$3.00 (legacy estimate, context unknown)",
  );
  expect(formatScanCosts([legacy, cost])).toBe(
    "$7.00 (legacy estimate, context unknown)",
  );
  expect(
    formatScanCosts([
      cost,
      { ...cost, estimatedUsdRange: { min: 4, max: null, context: "unknown" } },
    ]),
  ).toContain("at least $8.00");
});
