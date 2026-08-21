import { describe, expect, test } from "bun:test";
import fc from "fast-check";
import { estimateScanCost, formatUsd, tokenUsage } from "../src/cost-model.js";
import { propertyOptions } from "./support/property.js";

const rates = [
  ["gpt-5.6", 5000n, 500n, 6250n, 30000n],
  ["gpt-5.6-sol", 5000n, 500n, 6250n, 30000n],
  ["gpt-5.6-terra", 2000n, 200n, 2500n, 12000n],
  ["gpt-5.6-luna", 200n, 20n, 250n, 1200n],
  ["gpt-daybreak-blue-latest", 5000n, 500n, 6250n, 30000n],
  ["gpt-daybreak-red-latest", 12500n, 1250n, 15625n, 75000n],
] as const;
const count = fc.integer({ min: 0, max: 1_000_000_000 });
const usageParts = fc.record({
  uncached: count,
  cached: count,
  written: count,
  output: count,
});

function usage(parts: {
  uncached: number;
  cached: number;
  written: number;
  output: number;
}) {
  return {
    input_tokens: parts.uncached + parts.cached + parts.written,
    cached_input_tokens: parts.cached,
    cache_write_input_tokens: parts.written,
    output_tokens: parts.output,
    reasoning_output_tokens: parts.output,
  };
}

describe("cost-model invariants", () => {
  test("rejects non-object usage and formats small costs without rounding them away", () => {
    for (const value of [undefined, null, [], "usage", 1, true]) {
      expect(tokenUsage(value)).toBeNull();
      expect(estimateScanCost("gpt-5.6-sol", value)).toBeNull();
    }
    expect(formatUsd(0)).toBe("$0.00");
    expect(formatUsd(0.000000001)).toBe("$0.000000001");
    expect(formatUsd(1234.5)).toBe("$1,234.50");
  });

  test("matches an integer nanodollar oracle for every priced model", () => {
    fc.assert(
      fc.property(usageParts, (parts) => {
        const tokens = usage(parts);
        expect(tokenUsage(tokens)).toEqual({
          ...tokens,
          total_tokens: tokens.input_tokens + tokens.output_tokens,
        });
        for (const [
          model,
          inputRate,
          cachedRate,
          writeRate,
          outputRate,
        ] of rates) {
          const nanos =
            BigInt(parts.uncached) * inputRate +
            BigInt(parts.cached) * cachedRate +
            BigInt(parts.written) * writeRate +
            BigInt(parts.output) * outputRate;
          for (const selected of [model, `openai.${model}`]) {
            expect(estimateScanCost(selected, tokens)).toEqual({
              model: selected,
              inputTokens: tokens.input_tokens,
              cachedInputTokens: parts.cached,
              cacheWriteInputTokens: parts.written,
              outputTokens: parts.output,
              estimatedUsd: Number(nanos) / 1_000_000_000,
            });
          }
        }
      }),
      propertyOptions,
    );
  });

  test("normalizes legacy cache writes without double charging", () => {
    fc.assert(
      fc.property(usageParts, (parts) => {
        const canonical = usage(parts);
        const { cache_write_input_tokens: written, ...rest } = canonical;
        const expected = estimateScanCost("gpt-5.6-sol", canonical);
        expect(
          estimateScanCost("gpt-5.6-sol", {
            ...rest,
            cache_write_tokens: written,
          }),
        ).toEqual(expected);
        expect(
          estimateScanCost("gpt-5.6-sol", {
            ...canonical,
            cache_write_tokens: canonical.input_tokens + 1,
          }),
        ).toEqual(expected);
        if (parts.written > 0) {
          expect(
            estimateScanCost("gpt-5.6-sol", {
              ...canonical,
              cache_write_tokens: parts.written - 1,
            }),
          ).toEqual(expected);
        }
        expect(
          estimateScanCost("gpt-5.6-sol", {
            ...rest,
            cache_write_input_tokens: 0,
            cache_write_tokens: written,
          }),
        ).toEqual(expected);
      }),
      propertyOptions,
    );
  });

  test("rejects inconsistent or non-integer token accounting", () => {
    fc.assert(
      fc.property(
        usageParts,
        fc.constantFrom(
          "input_tokens",
          "cached_input_tokens",
          "cache_write_input_tokens",
          "output_tokens",
          "reasoning_output_tokens",
        ),
        fc.constantFrom(
          -1,
          0.5,
          Number.MAX_SAFE_INTEGER + 1,
          NaN,
          Infinity,
          "1",
        ),
        (parts, field, invalid) => {
          const valid = usage(parts);
          expect(
            estimateScanCost("gpt-5.6-sol", { ...valid, [field]: invalid }),
          ).toBeNull();
          expect(
            estimateScanCost("gpt-5.6-sol", {
              ...valid,
              cached_input_tokens: valid.input_tokens + 1,
            }),
          ).toBeNull();
          expect(
            estimateScanCost("gpt-5.6-sol", {
              ...valid,
              reasoning_output_tokens: valid.output_tokens + 1,
            }),
          ).toBeNull();
          expect(
            estimateScanCost("unpriced-synthetic-model", valid),
          ).toBeNull();
          expect(estimateScanCost(undefined, valid)).toBeNull();
        },
      ),
      propertyOptions,
    );
  });

  test("returns no estimate when nanodollar arithmetic would lose precision", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: Number.MAX_SAFE_INTEGER }),
        (input) => {
          const nanos = BigInt(input) * 5000n;
          const result = estimateScanCost("gpt-5.6-sol", {
            input_tokens: input,
            output_tokens: 0,
          });
          if (nanos > BigInt(Number.MAX_SAFE_INTEGER))
            expect(result).toBeNull();
          else expect(result?.estimatedUsd).toBe(Number(nanos) / 1_000_000_000);
        },
      ),
      propertyOptions,
    );
  });
});
