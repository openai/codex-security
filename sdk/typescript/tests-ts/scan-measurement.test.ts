import { expect, test } from "bun:test";
import {
  combineMeasurements,
  measuredScanCost,
  measurementFromUsage,
} from "../src/scan-measurement.js";

const usage = {
  input_tokens: 10,
  cached_input_tokens: 0,
  cache_write_input_tokens: 0,
  output_tokens: 2,
  reasoning_output_tokens: 0,
  total_tokens: 12,
};

test("workbench usage retains coverage identities for a large scan", () => {
  const coverageScope = Array.from(
    { length: 400 },
    (_, index) => `thread:synthetic-worker-${index}`,
  );
  const measurement = {
    ...measurementFromUsage(usage, "synthetic-unpriced-model"),
    coverage: "partial" as const,
    threadCount: 399,
    missingThreadCount: 1,
    coverageScope,
  };
  const envelope = measuredScanCost(measurement);
  expect(envelope?.usage.coverageScope).toEqual(coverageScope);
  expect(envelope?.usage.coverage).toBe("partial");
  expect(envelope?.usage.totalTokens).toBe(12);
  expect(envelope).not.toHaveProperty("cost");
  expect(JSON.stringify(envelope).length).toBeGreaterThan(8192);
});

test("disjoint stage measurements retain the union of known coverage scopes", () => {
  const first = {
    ...measurementFromUsage(usage, "synthetic-unpriced-model"),
    coverageScope: ["thread:first", "worker-attempt:first"],
  };
  const second = {
    ...measurementFromUsage(usage, "synthetic-unpriced-model"),
    coverage: "partial" as const,
    missingThreadCount: 1,
    coverageScope: ["thread:second", "thread:missing", "worker-attempt:second"],
  };
  const combined = combineMeasurements(
    [first, second],
    "synthetic-unpriced-model",
  );
  expect(combined.coverageScope).toEqual([
    "thread:first",
    "thread:missing",
    "thread:second",
    "worker-attempt:first",
    "worker-attempt:second",
  ]);
  expect(combined.coverage).toBe("partial");
  expect(combined.usage?.total_tokens).toBe(24);
  expect(
    combineMeasurements(
      [first, measurementFromUsage(usage, "synthetic-unpriced-model")],
      "synthetic-unpriced-model",
    ),
  ).not.toHaveProperty("coverageScope");
});
