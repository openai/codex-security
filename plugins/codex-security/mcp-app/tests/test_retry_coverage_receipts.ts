import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { publishCoverageFixture } from "./deep_scan_coverage_fixture.ts";

for (const resume of [false, true]) {
  for (const outcome of ["completion", "recovery", "no parent"]) {
    for (const retryPending of [false, true]) {
      test(`archived receipt and pending records survive ${resume ? "reconstruction" : "live retry"} and ${outcome} with ${retryPending ? "an updated gap" : "a clean retry"}`, async () => {
        const root = await mkdtemp(path.join(tmpdir(), "retry-coverage-"));
        try {
          await publishCoverageFixture(root, "complete", {
            receiptRetry: true,
            retryPending,
            stopAfterDraft: outcome === "recovery",
            stopBeforeDraft: outcome === "no parent",
            resume,
          });
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      });
    }
  }
}

for (const resume of [false, true]) {
  for (const outcome of ["completion", "recovery", "no parent"]) {
    for (const receiptSpelling of ["scan", "equivalent scan"] as const) {
      test(`receipt namespace survives ${resume ? "reconstruction" : "live retry"} and ${outcome} with ${receiptSpelling} spelling`, async () => {
        const root = await mkdtemp(path.join(tmpdir(), "receipt-namespace-"));
        try {
          await publishCoverageFixture(root, "complete", {
            receiptRetry: true,
            receiptSpelling,
            stopAfterDraft: outcome === "recovery",
            stopBeforeDraft: outcome === "no parent",
            resume,
          });
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      });
    }
  }
}

for (const resume of [false, true]) {
  for (const outcome of ["completion", "recovery", "no parent"]) {
    for (const activeReceiptSpelling of [
      "worker",
      "scan",
      "equivalent scan",
    ] as const) {
      test(`active receipt namespace survives ${resume ? "reconstruction" : "live retry"} and ${outcome} with ${activeReceiptSpelling} spelling`, async () => {
        const root = await mkdtemp(
          path.join(tmpdir(), "active-receipt-namespace-"),
        );
        try {
          await publishCoverageFixture(root, "complete", {
            receiptRetry: true,
            activeReceiptSpelling,
            stopAfterDraft: outcome === "recovery",
            stopBeforeDraft: outcome === "no parent",
            resume,
          });
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      });
    }
  }
}

for (const resume of [false, true]) {
  for (const outcome of ["completion", "recovery", "no parent"]) {
    for (const receiptSpelling of [
      "active scan",
      "equivalent active scan",
    ] as const) {
      test(`linked archived receipts survive ${resume ? "reconstruction" : "live retry"} and ${outcome} with ${receiptSpelling} spelling`, async () => {
        const root = await mkdtemp(path.join(tmpdir(), "receipt-namespace-"));
        try {
          await publishCoverageFixture(root, "complete", {
            receiptRetry: true,
            receiptSpelling,
            stopAfterDraft: outcome === "recovery",
            stopBeforeDraft: outcome === "no parent",
            resume,
          });
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      });
    }
  }
}

for (const resume of [false, true]) {
  for (const outcome of ["completion", "recovery", "no parent"]) {
    test(`shared scan receipts survive ${resume ? "reconstruction" : "live retry"} and ${outcome}`, async () => {
      const root = await mkdtemp(path.join(tmpdir(), "shared-scan-receipts-"));
      try {
        await publishCoverageFixture(root, "complete", {
          receiptRetry: true,
          sharedReceipt: true,
          stopAfterDraft: outcome === "recovery",
          stopBeforeDraft: outcome === "no parent",
          resume,
        });
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
  }
}

for (const resume of [false, true]) {
  for (const outcome of ["completion", "recovery", "no parent"]) {
    for (const receiptSpelling of [
      "shared scan",
      "equivalent shared scan",
    ] as const) {
      test(`archived shared receipts survive ${resume ? "reconstruction" : "live retry"} and ${outcome} with ${receiptSpelling} spelling`, async () => {
        const root = await mkdtemp(
          path.join(tmpdir(), "archived-shared-receipts-"),
        );
        try {
          await publishCoverageFixture(root, "complete", {
            receiptRetry: true,
            receiptSpelling,
            stopAfterDraft: outcome === "recovery",
            stopBeforeDraft: outcome === "no parent",
            resume,
          });
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      });
    }
  }
}

for (const resume of [false, true]) {
  for (const outcome of ["completion", "recovery", "no parent"]) {
    for (const sharedReceipt of [false, true]) {
      test(`empty receipt survives ${resume ? "reconstruction" : "live retry"} and ${outcome} with ${sharedReceipt ? "shared" : "worker"} current evidence`, async () => {
        const root = await mkdtemp(
          path.join(tmpdir(), "empty-current-receipts-"),
        );
        try {
          await publishCoverageFixture(root, "complete", {
            receiptRetry: true,
            sharedReceipt,
            emptyReceipt: true,
            stopAfterDraft: outcome === "recovery",
            stopBeforeDraft: outcome === "no parent",
            resume,
          });
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      });
    }
    for (const receiptSpelling of [
      "shared scan",
      "equivalent shared scan",
    ] as const) {
      test(`empty receipt survives ${resume ? "reconstruction" : "live retry"} and ${outcome} with archived ${receiptSpelling} evidence`, async () => {
        const root = await mkdtemp(
          path.join(tmpdir(), "empty-archived-receipts-"),
        );
        try {
          await publishCoverageFixture(root, "complete", {
            receiptRetry: true,
            receiptSpelling,
            emptyReceipt: true,
            stopAfterDraft: outcome === "recovery",
            stopBeforeDraft: outcome === "no parent",
            resume,
          });
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      });
    }
  }
}

for (const resume of [false, true]) {
  for (const outcome of ["completion", "recovery", "no parent"]) {
    test(`worker-local receipts win parent collisions during ${resume ? "reconstruction" : "live retry"} and ${outcome}`, async () => {
      const root = await mkdtemp(
        path.join(tmpdir(), "worker-receipt-collision-"),
      );
      try {
        await publishCoverageFixture(root, "complete", {
          receiptRetry: true,
          receiptCollision: true,
          stopAfterDraft: outcome === "recovery",
          stopBeforeDraft: outcome === "no parent",
          resume,
        });
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
  }
}

for (const resume of [false, true]) {
  for (const outcome of ["completion", "recovery", "no parent"]) {
    test(`inherited shared receipts retain their owner across retry collisions during ${resume ? "reconstruction" : "live retry"} and ${outcome}`, async () => {
      const root = await mkdtemp(
        path.join(tmpdir(), "shared-receipt-collision-"),
      );
      try {
        await publishCoverageFixture(root, "complete", {
          receiptRetry: true,
          receiptSpelling: "shared scan",
          receiptCollision: true,
          stopAfterDraft: outcome === "recovery",
          stopBeforeDraft: outcome === "no parent",
          resume,
        });
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
  }
}

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
  test(name, async () => {
    const root = await mkdtemp(path.join(tmpdir(), "supported-receipt-owner-"));
    try {
      await publishCoverageFixture(root, "complete", {
        receiptRetry: true,
        ...options,
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

for (const resume of [false, true]) {
  for (const [name, receiptSpelling, receiptCollision] of [
    ["shared same-name collision", "shared scan", true],
    ["shared distinct-name control", "shared scan", false],
    ["worker-local same-name control", "worker", true],
  ] as const) {
    test(`same surface generic closeout retains both receipt owners: ${name}, ${resume ? "reconstructed" : "live"}`, async () => {
      const root = await mkdtemp(path.join(tmpdir(), "same-surface-closeout-"));
      try {
        await publishCoverageFixture(root, "complete", {
          receiptRetry: true,
          closeRetriedSurface: true,
          receiptSpelling,
          receiptCollision,
          resume,
        });
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
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
      test(`receipt ownership follows the authored observation: ${receiptOwnershipRetry}, ${name}, ${resume ? "reconstructed" : "live"}`, async () => {
        const root = await mkdtemp(
          path.join(tmpdir(), "receipt-owner-observation-"),
        );
        try {
          await publishCoverageFixture(root, "complete", {
            receiptRetry: true,
            receiptOwnershipRetry,
            receiptSpelling,
            receiptCollision,
            resume,
          });
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      });
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
      test(`first checkpoint receipt ownership survives ${resume ? "reconstruction" : "live execution"} and ${outcome}: ${name}`, async () => {
        const root = await mkdtemp(
          path.join(tmpdir(), "first-checkpoint-owner-"),
        );
        try {
          await publishCoverageFixture(root, "complete", {
            firstCheckpointReceipt,
            receiptCollision,
            resume,
            stopAfterDraft: outcome === "recovery",
            stopBeforeDraft: outcome === "no parent",
          });
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      });
    }
  }
}

for (const resume of [false, true]) {
  for (const [name, firstCheckpointReceipt, receiptCollision] of [
    ["shared same-name collision", "shared", true],
    ["shared distinct-name control", "shared", false],
    ["worker-local priority control", "worker", false],
  ] as const) {
    test(`same attempt closeout retains both receipt owners: ${name}, ${resume ? "reconstructed" : "live"}`, async () => {
      const root = await mkdtemp(path.join(tmpdir(), "same-attempt-closeout-"));
      try {
        await publishCoverageFixture(root, "complete", {
          firstCheckpointReceipt,
          sameAttemptCloseout: true,
          receiptCollision,
          resume,
        });
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
  }
}
