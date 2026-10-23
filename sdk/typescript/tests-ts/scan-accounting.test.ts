import { expect, test } from "bun:test";
import { ScanAccounting } from "../src/scan-accounting.js";
import { estimateScanCost, scanCostUsage } from "../src/cost.js";

const receipt = (tokens: number) =>
  estimateScanCost("gpt-5.6-sol", {
    input_tokens: tokens,
    output_tokens: tokens,
  })!;

test("cumulative receipts replace earlier callbacks and unknown children prevent a verified total", () => {
  const ledger = new ScanAccounting();
  expect(ledger.hasUnknown).toBe(false);
  ledger.record("child", null);
  ledger.record("merge", receipt(10));
  expect(ledger.known?.inputTokens).toBe(10);
  expect(ledger.complete).toBeNull();
  ledger.record("child", receipt(20));
  ledger.record("child", receipt(30));
  expect(ledger.complete?.inputTokens).toBe(40);
  ledger.record("merge", receipt(15));
  expect(ledger.complete?.inputTokens).toBe(45);
});

test("known currency does not invent missing cache-write reporting", () => {
  const ledger = new ScanAccounting();
  ledger.record("child", {
    ...receipt(20),
    cacheWriteInputTokensReported: false,
  });
  ledger.record("merge", receipt(10));
  expect(ledger.complete).not.toBeNull();
  expect(scanCostUsage(ledger.complete!)).toMatchObject({
    cache_write_input_tokens_reported: false,
  });
});
