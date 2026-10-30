import test from "node:test";
import { publishReceiptFixture } from "./deep_scan_coverage_fixture.ts";

const receiptOwnershipCases = [
  [
    "third attempt shared collision",
    {
      extraReceiptRetry: true,
      receiptSpelling: "shared scan",
      receiptCollision: true,
    },
  ],
  [
    "returned shared coverage rewrite collision",
    {
      rewriteReturnedCoverage: true,
      receiptSpelling: "shared scan",
      receiptCollision: true,
    },
  ],
  [
    "shared and new local same spelling",
    {
      sameNamedNewSurface: true,
      receiptSpelling: "shared scan",
      receiptCollision: true,
    },
  ],
  [
    "third attempt shared no collision control",
    {
      extraReceiptRetry: true,
      receiptSpelling: "shared scan",
      receiptCollision: false,
    },
  ],
  [
    "returned worker-local coverage control",
    {
      rewriteReturnedCoverage: true,
      receiptSpelling: "worker",
      receiptCollision: true,
    },
  ],
  [
    "worker-local same spelling control",
    {
      sameNamedNewSurface: true,
      receiptSpelling: "worker",
      receiptCollision: true,
    },
  ],
] as const;
for (const [name, options] of receiptOwnershipCases)
  test(name, () =>
    publishReceiptFixture({
      receiptRetry: true,
      ...options,
    }),
  );

for (const resume of [false, true]) {
  for (const [name, receiptSpelling, receiptCollision] of [
    ["shared same-name collision", "shared scan", true],
    ["shared distinct-name control", "shared scan", false],
    ["worker-local same-name control", "worker", true],
  ] as const) {
    test(`same surface generic closeout retains both receipt owners: ${name}, ${resume ? "reconstructed" : "live"}`, () =>
      publishReceiptFixture({
        receiptRetry: true,
        closeRetriedSurface: true,
        receiptSpelling,
        receiptCollision,
        resume,
      }));
  }
}

for (const resume of [false, true]) {
  for (const receiptOwnershipRetry of [
    "ordinary",
    "candidate",
    "unrelated",
  ] as const) {
    for (const [name, receiptSpelling, receiptCollision] of [
      ["shared same-name collision", "shared scan", true],
      ["shared distinct-name control", "shared scan", false],
      ["worker-local control", "worker", true],
    ] as const) {
      test(`receipt ownership follows the authored observation: ${receiptOwnershipRetry}, ${name}, ${resume ? "reconstructed" : "live"}`, () =>
        publishReceiptFixture({
          receiptRetry: true,
          receiptOwnershipRetry,
          receiptSpelling,
          receiptCollision,
          resume,
        }));
    }
  }
}

for (const resume of [false, true]) {
  for (const outcome of ["completion", "recovery", "no parent"]) {
    for (const [name, firstCheckpointReceipt, receiptCollision] of [
      ["shared same-name collision", "shared", true],
      ["shared distinct-name control", "shared", false],
      ["worker-local priority control", "worker", false],
    ] as const) {
      test(`first checkpoint receipt ownership survives ${resume ? "reconstruction" : "live execution"} and ${outcome}: ${name}`, () =>
        publishReceiptFixture({
          firstCheckpointReceipt,
          receiptCollision,
          resume,
          stopAfterDraft: outcome === "recovery",
          stopBeforeDraft: outcome === "no parent",
        }));
    }
  }
}

for (const resume of [false, true]) {
  for (const [name, firstCheckpointReceipt, receiptCollision] of [
    ["shared same-name collision", "shared", true],
    ["shared distinct-name control", "shared", false],
    ["worker-local priority control", "worker", false],
  ] as const) {
    test(`same attempt closeout retains both receipt owners: ${name}, ${resume ? "reconstructed" : "live"}`, () =>
      publishReceiptFixture({
        firstCheckpointReceipt,
        sameAttemptCloseout: true,
        receiptCollision,
        resume,
      }));
  }
}

test("nested local receipt copies remain distinct from new work after a third attempt and recovery", () =>
  publishReceiptFixture({
    receiptRetry: true,
    extraReceiptRetry: true,
    stopAfterDraft: true,
  }));
