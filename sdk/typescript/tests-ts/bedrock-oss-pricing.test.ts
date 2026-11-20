import { expect, test } from "bun:test";
import { estimateScanCost } from "../src/cost-model.js";

test.each([
  ["openai.gpt-oss-20b-1:0", "ap-southeast-2", 0.0721, 0.309],
  ["openai.gpt-oss-20b", "us-east-1", 0.07, 0.3],
  ["openai.gpt-oss-20b-1:0", "eu-west-2", 0.11, 0.47],
  ["openai.gpt-oss-safeguard-20b", "ap-southeast-2", 0.0721, 0.206],
  ["openai.gpt-oss-safeguard-120b", "ap-southeast-2", 0.1545, 0.618],
  ["openai.gpt-oss-120b", "us-gov-west-1", 0.18, 0.72],
  ["us-gov.openai.gpt-oss-120b-1:0", "us-gov-east-1", 0.18, 0.72],
  ["us-gov.openai.gpt-oss-20b-1:0", null, 0.084, 0.36],
] as const)(
  "prices Standard tokens for %s in %s",
  (model, region, input, output) => {
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
      cacheRead: input,
      cacheWrite: input,
      output,
    });
    expect(cost?.estimatedUsd).toBeCloseTo(
      (3 * input + output) / 1_000_000,
      16,
    );
    expect(cost?.estimatedUsdRange?.max).toBe(cost?.estimatedUsd);
  },
);

test.each([
  ["openai.gpt-oss-20b", undefined],
  ["openai.gpt-oss-20b", null],
  ["openai.gpt-oss-20b-1:0", "ap-southeast-4"],
  ["openai.gpt-oss-safeguard-20b", "us-gov-east-1"],
  ["us-gov.openai.gpt-oss-20b-1:0", "us-west-2"],
  ["us-gov.openai.gpt-oss-20b", "us-gov-east-1"],
  ["global.openai.gpt-oss-120b-1:0", "us-east-1"],
  ["openai.gpt-oss-safeguard-120b-1:0", "us-east-1"],
] as const)("keeps %s in %s unpriced", (model, region) => {
  expect(
    estimateScanCost(model, { input_tokens: 1, output_tokens: 1 }, region),
  ).toBeNull();
});
