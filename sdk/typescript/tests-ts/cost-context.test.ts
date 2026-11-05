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
  ["gpt-6.1-sol", [2, 0.1, 2.5, 10], [4, 0.2, 5, 15]],
  ["gpt-6-astra", [10, 1, 12.5, 50], [20, 2, 25, 75]],
  ["gpt-6-luna", [0.1, 0.01, 0.125, 0.5], [0.2, 0.02, 0.25, 0.75]],
  ["gpt-5.6", [4, 0.4, 5, 20], [8, 0.8, 10, 30]],
  ["gpt-5.6-sol", [4, 0.4, 5, 20], [8, 0.8, 10, 30]],
  ["gpt-5.6-terra", [2, 0.2, 2.5, 12], [4, 0.4, 5, 18]],
  ["gpt-5.6-luna", [0.2, 0.02, 0.25, 1.2], [0.4, 0.04, 0.5, 1.8]],
] as const)(
  "%s bounds each token category with verified rates",
  (model, short, long) => {
    for (const category of [0, 1, 2, 3] as const) {
      const cost = estimateScanCost(model, {
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
  },
);

test.each(["blue", "red"])(
  "leaves the Daybreak %s latest alias unpriced",
  (program) => {
    const alias = `gpt-daybreak-${program}-latest`;
    const usage = { input_tokens: 1_000_000, output_tokens: 0 };
    expect(estimateScanCost(alias, usage)).toBeNull();
    expect(estimateScanCost(`openai.${alias}`, usage)).toBeNull();
  },
);

test("prices the exact Bedrock Daybreak Blue ID with AWS short and long context rates", () => {
  const usage = {
    input_tokens: 1_000_000,
    cached_input_tokens: 200_000,
    cache_write_input_tokens: 300_000,
    output_tokens: 100_000,
  };
  const cost = estimateScanCost("openai.gpt-daybreak-blue-5.6-sol", usage)!;
  expect(cost).toMatchObject({
    model: "openai.gpt-daybreak-blue-5.6-sol",
    estimatedUsd: 6.138,
    estimatedUsdRange: { min: 6.138, max: 11.176, context: "unknown" },
    pricing: {
      source:
        "https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-openai-gpt-daybreak-blue-56-sol.html",
      asOf: "2026-11-05",
      serviceTier: "standard",
      context: "short",
      usdPerMillionTokens: {
        input: 4.4,
        cacheRead: 0.44,
        cacheWrite: 5.5,
        output: 22,
      },
      longContextUsdPerMillionTokens: {
        input: 8.8,
        cacheRead: 0.88,
        cacheWrite: 11,
        output: 33,
      },
    },
  });
  expect(estimateScanCost("gpt-daybreak-blue-5.6-sol", usage)).toBeNull();
});

test.each([
  {
    model: "gpt-5.6-cyber",
    estimatedUsd: 18.6875,
    asOf: "2026-10-06",
    rates: { input: 12.5, cacheRead: 1.25, cacheWrite: 15.625, output: 75 },
  },
  {
    model: "gpt-6-cyber",
    estimatedUsd: 27.9,
    asOf: "2026-11-05",
    rates: { input: 20, cacheRead: 2, cacheWrite: 25, output: 100 },
  },
])(
  "prices $model without inventing long-context rates",
  ({ model, estimatedUsd, asOf, rates }) => {
    const cost = estimateScanCost(model, {
      input_tokens: 1_000_000,
      cached_input_tokens: 200_000,
      cache_write_input_tokens: 300_000,
      output_tokens: 100_000,
    })!;
    expect(cost).toMatchObject({
      model,
      estimatedUsd,
      estimatedUsdRange: { min: estimatedUsd, max: null, context: "unknown" },
      pricing: {
        source: "https://developers.openai.com/api/docs/pricing",
        asOf,
        serviceTier: "standard",
        context: "short",
        usdPerMillionTokens: rates,
      },
    });
    expect(cost.pricing).not.toHaveProperty("longContextUsdPerMillionTokens");
  },
);

test("prices the exact Bedrock Daybreak Red ID without inventing long-context rates", () => {
  const usage = {
    input_tokens: 1_000_000,
    cached_input_tokens: 200_000,
    cache_write_input_tokens: 300_000,
    output_tokens: 100_000,
  };
  const cost = estimateScanCost("openai.gpt-5.6-cyber", usage)!;
  expect(cost).toMatchObject({
    model: "openai.gpt-5.6-cyber",
    estimatedUsd: 20.55625,
    estimatedUsdRange: { min: 20.55625, max: null, context: "unknown" },
    pricing: {
      source:
        "https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-openai-gpt-56-cyber.html",
      asOf: "2026-11-05",
      serviceTier: "standard",
      context: "short",
      usdPerMillionTokens: {
        input: 13.75,
        cacheRead: 1.375,
        cacheWrite: 17.1875,
        output: 82.5,
      },
    },
  });
  expect(cost.pricing).not.toHaveProperty("longContextUsdPerMillionTokens");
});

test.each([1, 3])(
  "retains a Bedrock Red estimate for %i cache-write tokens",
  (written) => {
    const cost = estimateScanCost("openai.gpt-5.6-cyber", {
      input_tokens: written,
      cache_write_input_tokens: written,
      output_tokens: 0,
    });
    expect(cost?.estimatedUsd).toBe((written * 17.1875) / 1_000_000);
  },
);

// USD per million tokens in the AWS Standard short-context tables.
test.each([
  ["us.openai.gpt-5.4", "us-east-2", 2.75, 0.275, 2.75, 16.5],
  ["us.openai.gpt-5.5", "us-east-1", 5.5, 0.55, 5.5, 33],
  ["openai.gpt-5.4", "us-gov-west-1", 3.375, 0.3375, 3.375, 20.25],
  ["openai.gpt-5.6-cyber", "us-gov-east-1", 16.875, 1.6875, 21.09375, 101.25],
  ["openai.gpt-5.6-terra", "us-gov-west-1", 2.7, 0.27, 3.375, 16.2],
  ["us-gov.openai.gpt-5.6-luna", "us-gov-east-1", 0.27, 0.027, 0.3375, 1.62],
  ["openai.gpt-6.1-sol", "us-east-1", 2.2, 0.11, 2.75, 11],
  ["us.openai.gpt-6.1-sol", "us-east-1", 2.2, 0.11, 2.75, 11],
  ["global.openai.gpt-6.1-sol", "us-east-1", 2, 0.1, 2.5, 10],
] as const)(
  "uses the Standard rates for %s in %s",
  (model, region, input, cacheRead, cacheWrite, output) => {
    const cost = estimateScanCost(
      model,
      {
        input_tokens: 3,
        cached_input_tokens: 1,
        cache_write_input_tokens: 1,
        output_tokens: 1,
      },
      region,
    );
    expect(cost?.pricing?.usdPerMillionTokens).toEqual({
      input,
      cacheRead,
      cacheWrite,
      output,
    });
    expect(cost?.estimatedUsd).toBeCloseTo(
      (input + cacheRead + cacheWrite + output) / 1_000_000,
      15,
    );
  },
);

test("keeps unverified Bedrock IDs, regions, and long-context rates unpriced", () => {
  const usage = { input_tokens: 1_000_000, output_tokens: 0 };
  for (const [model, region] of [
    ["global.openai.gpt-5.5", "us-east-1"],
    ["openai.gpt-6-cyber", "us-east-2"],
    ["gpt-5.6-cyber", "us-gov-east-1"],
    ["openai.gpt-5.5-2026-04-23", "us-east-1"],
    ["openai.gpt-5.6-cyber", "us-gov-west-1"],
    ["openai.gpt-daybreak-blue-5.6-sol", "us-gov-east-1"],
    ["global.openai.gpt-5.6-terra", "us-gov-west-1"],
  ] as const) {
    expect(estimateScanCost(model, usage, region)).toBeNull();
  }
  expect(
    estimateScanCost("openai.gpt-5.4", usage, "us-gov-west-1")
      ?.estimatedUsdRange,
  ).toEqual({ min: 3.375, max: null, context: "unknown" });
  expect(
    estimateScanCost(
      "openai.gpt-5.6-luna",
      { ...usage, cache_write_input_tokens: 0 },
      "us-gov-west-1",
    )?.estimatedUsdRange,
  ).toEqual({ min: 0.27, max: 0.54, context: "unknown" });
});

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
  const cost = estimateScanCost("gpt-5.6-cyber", {
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
