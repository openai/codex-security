import test from "node:test";
import { publishReceiptFixture } from "./deep_scan_coverage_fixture.ts";

for (const resume of [false, true]) {
  for (const outcome of ["completion", "recovery", "no parent"]) {
    for (const retryPending of [false, true]) {
      test(`archived receipt and pending records survive ${resume ? "reconstruction" : "live retry"} and ${outcome} with ${retryPending ? "an updated gap" : "a clean retry"}`, () =>
        publishReceiptFixture({
          receiptRetry: true,
          retryPending,
          stopAfterDraft: outcome === "recovery",
          stopBeforeDraft: outcome === "no parent",
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
          stopAfterDraft: outcome === "recovery",
          stopBeforeDraft: outcome === "no parent",
          resume,
        }));
    }
  }
}
