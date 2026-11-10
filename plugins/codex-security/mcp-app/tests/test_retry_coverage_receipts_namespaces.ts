import test from "node:test";
import { publishReceiptFixture } from "./deep_scan_coverage_fixture.ts";

for (const resume of [false, true]) {
  for (const outcome of ["completion", "recovery", "no parent"] as const) {
    for (const retryPending of [false, true]) {
      test(`archived receipt and pending records survive ${resume ? "reconstruction" : "live retry"} and ${outcome} with ${retryPending ? "an updated gap" : "a clean retry"}`, () =>
        publishReceiptFixture({
          receiptRetry: true,
          retryPending,
          outcome,
          resume,
        }));
    }

    for (const [receiptSpelling, activeReceiptSpelling] of [
      ["scan", "scan"],
      ["active scan", "equivalent scan"],
    ] as const) {
      test(`archived ${receiptSpelling} and current ${activeReceiptSpelling} receipts survive ${resume ? "reconstruction" : "live retry"} and ${outcome}`, () =>
        publishReceiptFixture({
          receiptRetry: true,
          receiptSpelling,
          activeReceiptSpelling,
          outcome,
          resume,
        }));
    }
  }
}
