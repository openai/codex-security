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

    test(`archived shared receipts survive ${resume ? "reconstruction" : "live retry"} and ${outcome} with both spellings`, () =>
      publishReceiptFixture({
        receiptRetry: true,
        receiptSpelling: "shared scan",
        stopAfterDraft: outcome === "recovery",
        stopBeforeDraft: outcome === "no parent",
        resume,
      }));

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
    test(`empty receipt survives ${resume ? "reconstruction" : "live retry"} and ${outcome} with both archived shared spellings`, () =>
      publishReceiptFixture({
        receiptRetry: true,
        receiptSpelling: "shared scan",
        emptyReceipt: true,
        stopAfterDraft: outcome === "recovery",
        stopBeforeDraft: outcome === "no parent",
        resume,
      }));

    test(`worker-local receipts win parent collisions during ${resume ? "reconstruction" : "live retry"} and ${outcome}`, () =>
      publishReceiptFixture({
        receiptRetry: true,
        receiptCollision: true,
        stopAfterDraft: outcome === "recovery",
        stopBeforeDraft: outcome === "no parent",
        resume,
      }));

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
