import test from "node:test";
import { publishReceiptFixture } from "./deep_scan_coverage_fixture.ts";

for (const resume of [false, true]) {
  for (const outcome of ["completion", "recovery", "no parent"]) {
    test(`shared scan receipts survive ${resume ? "reconstruction" : "live retry"} and ${outcome}`, () =>
      publishReceiptFixture({
        receiptRetry: true,
        sharedReceipt: true,
        stopAfterDraft: outcome === "recovery",
        stopBeforeDraft: outcome === "no parent",
        resume,
      }));
  }
}

for (const resume of [false, true]) {
  for (const outcome of ["completion", "recovery", "no parent"]) {
    for (const receiptSpelling of [
      "shared scan",
      "equivalent shared scan",
    ] as const) {
      test(`archived shared receipts survive ${resume ? "reconstruction" : "live retry"} and ${outcome} with ${receiptSpelling} spelling`, () =>
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
    for (const sharedReceipt of [false, true]) {
      test(`empty receipt survives ${resume ? "reconstruction" : "live retry"} and ${outcome} with ${sharedReceipt ? "shared" : "worker"} current evidence`, () =>
        publishReceiptFixture({
          receiptRetry: true,
          sharedReceipt,
          emptyReceipt: true,
          stopAfterDraft: outcome === "recovery",
          stopBeforeDraft: outcome === "no parent",
          resume,
        }));
    }
    for (const receiptSpelling of [
      "shared scan",
      "equivalent shared scan",
    ] as const) {
      test(`empty receipt survives ${resume ? "reconstruction" : "live retry"} and ${outcome} with archived ${receiptSpelling} evidence`, () =>
        publishReceiptFixture({
          receiptRetry: true,
          receiptSpelling,
          emptyReceipt: true,
          stopAfterDraft: outcome === "recovery",
          stopBeforeDraft: outcome === "no parent",
          resume,
        }));
    }
  }
}

for (const resume of [false, true]) {
  for (const outcome of ["completion", "recovery", "no parent"]) {
    test(`worker-local receipts win parent collisions during ${resume ? "reconstruction" : "live retry"} and ${outcome}`, () =>
      publishReceiptFixture({
        receiptRetry: true,
        receiptCollision: true,
        stopAfterDraft: outcome === "recovery",
        stopBeforeDraft: outcome === "no parent",
        resume,
      }));
  }
}

for (const resume of [false, true]) {
  for (const outcome of ["completion", "recovery", "no parent"]) {
    test(`inherited shared receipts retain their owner across retry collisions during ${resume ? "reconstruction" : "live retry"} and ${outcome}`, () =>
      publishReceiptFixture({
        receiptRetry: true,
        receiptSpelling: "shared scan",
        receiptCollision: true,
        stopAfterDraft: outcome === "recovery",
        stopBeforeDraft: outcome === "no parent",
        resume,
      }));
  }
}
