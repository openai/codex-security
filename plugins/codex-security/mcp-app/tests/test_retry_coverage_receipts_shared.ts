import test from "node:test";
import { publishReceiptFixture } from "./deep_scan_coverage_fixture.ts";

for (const resume of [false, true]) {
  for (const outcome of ["completion", "recovery", "no parent"] as const) {
    test(`shared scan receipts survive ${resume ? "reconstruction" : "live retry"} and ${outcome}`, () =>
      publishReceiptFixture({
        receiptRetry: true,
        sharedReceipt: true,
        outcome,
        resume,
      }));

    test(`archived shared receipts survive ${resume ? "reconstruction" : "live retry"} and ${outcome} with both spellings`, () =>
      publishReceiptFixture({
        receiptRetry: true,
        receiptSpelling: "shared scan",
        outcome,
        resume,
      }));

    for (const sharedReceipt of [false, true]) {
      test(`empty receipt survives ${resume ? "reconstruction" : "live retry"} and ${outcome} with ${sharedReceipt ? "shared" : "worker"} current evidence`, () =>
        publishReceiptFixture({
          receiptRetry: true,
          sharedReceipt,
          emptyReceipt: true,
          outcome,
          resume,
        }));
    }
    test(`empty receipt survives ${resume ? "reconstruction" : "live retry"} and ${outcome} with both archived shared spellings`, () =>
      publishReceiptFixture({
        receiptRetry: true,
        receiptSpelling: "shared scan",
        emptyReceipt: true,
        outcome,
        resume,
      }));

    test(`worker-local receipts win parent collisions during ${resume ? "reconstruction" : "live retry"} and ${outcome}`, () =>
      publishReceiptFixture({
        receiptRetry: true,
        receiptCollision: true,
        outcome,
        resume,
      }));

    test(`inherited shared receipts retain their owner across retry collisions during ${resume ? "reconstruction" : "live retry"} and ${outcome}`, () =>
      publishReceiptFixture({
        receiptRetry: true,
        receiptSpelling: "shared scan",
        receiptCollision: true,
        outcome,
        resume,
      }));
  }
}
