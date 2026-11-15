// Standard MaaS prices in nanodollars per token. Google lists one price
// across each model's 131,072-token context window. Only 20B discounts
// implicit cache hits. Keep its rates for scans made before its retirement.
const rates = new Map<
  string,
  readonly [
    input: number,
    cacheRead: number,
    cacheWrite: number,
    output: number,
  ]
>([
  ["gpt-oss-20b-maas", [70, 7, 70, 250]],
  ["gpt-oss-120b-maas", [90, 90, 90, 360]],
]);

export function vertexModelPricing(model: string) {
  const price = rates.get(model.replace(/^openai\//, ""));
  if (!price) return undefined;
  return {
    short: price,
    long: price,
    unitsPerUsd: 1_000_000_000,
    source: "https://cloud.google.com/model-garden/partner-models/pricing",
    asOf: "2026-11-05",
  };
}
