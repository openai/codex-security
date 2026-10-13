import { expect, test } from "bun:test";
import { writeSemanticScanDraft } from "../src/scan-draft-publication.js";

test.each([false, true])(
  "workbench owns staged publication outcome (failure: %p)",
  async (fail) => {
    const failure = new Error("publication failed");
    const staged = new Map<string, unknown>();
    let invocation: readonly string[] = [];
    const publication = writeSemanticScanDraft(
      {
        scanDir: "/synthetic/scan",
        contract: {
          mode: "standard",
          targetContract: {
            target: {
              allowedKinds: ["git_worktree"],
              targetId: "synthetic",
              displayName: "fixture",
            },
            scope: { requiredIncludePaths: ["."], requiredExcludePaths: [] },
          },
        },
        expectedDigest: "accepted-draft-digest",
        reconciledCheckpointIds: ["pending.json"],
        claimToken: "synthetic-claim",
        writer: {
          async restore(path, contents) {
            staged.set(path, JSON.parse(Buffer.from(contents).toString()));
          },
        },
        async workbench(args) {
          invocation = args;
          if (fail) throw failure;
        },
      },
      {
        scanId: "synthetic-scan",
        handoffClaimToken: "synthetic-claim",
        findings: [],
        coverage: {
          completeness: "complete",
          surfaces: [],
          explicitExclusions: [],
          deferred: [],
        },
      },
    );
    if (fail) await expect(publication).rejects.toBe(failure);
    else await publication;
    expect(staged.size).toBe(2);
    expect(invocation.slice(-4)).toEqual([
      "--expected-draft-digest",
      "accepted-draft-digest",
      "--claim-token",
      "synthetic-claim",
    ]);
    const checkpoint = [...staged].find(([name]) =>
      name.endsWith(".checkpoint.json"),
    )![1];
    expect(checkpoint).not.toHaveProperty("handoffClaimToken");
  },
);
