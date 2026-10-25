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
  }
}

for (const resume of [false, true]) {
  for (const outcome of ["completion", "recovery", "no parent"]) {
    for (const receiptSpelling of ["scan", "equivalent scan"] as const) {
      test(`receipt namespace survives ${resume ? "reconstruction" : "live retry"} and ${outcome} with ${receiptSpelling} spelling`, () =>
        publishReceiptFixture({
          receiptRetry: true,
          receiptSpelling,
          stopAfterDraft: outcome === "recovery",
          stopBeforeDraft: outcome === "no parent",
          resume,
        }));
    }
  }
}

for (const resume of [false, true]) {
  for (const outcome of ["completion", "recovery", "no parent"]) {
    for (const activeReceiptSpelling of ["scan", "equivalent scan"] as const) {
      test(`active receipt namespace survives ${resume ? "reconstruction" : "live retry"} and ${outcome} with ${activeReceiptSpelling} spelling`, () =>
        publishReceiptFixture({
          receiptRetry: true,
          activeReceiptSpelling,
          stopAfterDraft: outcome === "recovery",
          stopBeforeDraft: outcome === "no parent",
          resume,
        }));
    }
  }
}

for (const resume of [false, true]) {
  for (const outcome of ["completion", "recovery", "no parent"]) {
    for (const receiptSpelling of [
      "active scan",
      "equivalent active scan",
    ] as const) {
      test(`linked archived receipts survive ${resume ? "reconstruction" : "live retry"} and ${outcome} with ${receiptSpelling} spelling`, () =>
        publishReceiptFixture({
          receiptRetry: true,
          receiptSpelling,
          stopAfterDraft: outcome === "recovery",
          stopBeforeDraft: outcome === "no parent",
          resume,
        }));
    }
  }
}
