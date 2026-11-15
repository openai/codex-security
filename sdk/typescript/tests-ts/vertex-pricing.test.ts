import { expect, test } from "bun:test";
import { estimateScanCost } from "../src/cost-model.js";

const usage = {
  input_tokens: 16_000,
  cached_input_tokens: 8_000,
  cache_write_input_tokens: 2_000,
  output_tokens: 1_000,
};

test.each([
  ["gpt-oss-20b-maas", 0.07, 0.007, 0.25, 0.000866],
  ["gpt-oss-120b-maas", 0.09, 0.09, 0.36, 0.0018],
] as const)(
  "estimates Vertex Standard usage for %s",
  (id, input, cacheRead, output, cost) => {
    for (const model of [id, `openai/${id}`]) {
      const estimate = estimateScanCost(model, usage, { provider: "gcp" });
      expect(estimate).toMatchObject({
        model,
        estimatedUsd: cost,
        estimatedUsdRange: { min: cost, max: cost },
        pricing: {
          source:
            "https://cloud.google.com/model-garden/partner-models/pricing",
          serviceTier: "standard",
          usdPerMillionTokens: { input, cacheRead, cacheWrite: input, output },
        },
      });
    }
  },
);

test.each([
  "gpt-oss-20b",
  "openai/gpt-oss-120b",
  "gpt-oss-20b-maas:latest",
  "meta/gpt-oss-20b-maas",
  "gpt-6-sol",
  "openai.gpt-5.6-cyber",
])("leaves GCP usage for %s unpriced", (model) => {
  expect(estimateScanCost(model, usage, { provider: "gcp" })).toBeNull();
});

test("requires a managed Vertex billing context for MaaS prices", () => {
  expect(estimateScanCost("openai/gpt-oss-120b-maas", usage)).toBeNull();
  expect(
    estimateScanCost("openai/gpt-oss-120b-maas", usage, {
      provider: "gcp",
      managedEndpoint: false,
    }),
  ).toBeNull();
  expect(
    estimateScanCost("openai/gpt-oss-20b-maas", usage, "us-east-1"),
  ).toBeNull();
});
