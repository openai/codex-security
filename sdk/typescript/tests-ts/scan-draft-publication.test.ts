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

test.each([Infinity, -Infinity, NaN])(
  "authored non-finite values fail before staging or workbench publication: %p",
  async (measurement) => {
    const writes: string[] = [];
    const input = {
      scanId: "synthetic-scan",
      findings: [],
      threatModel: {
        summary: "Synthetic boundary review.",
        audit: { measurement },
      },
      coverage: { surfaces: [], explicitExclusions: [], deferred: [] },
    };
    const original = structuredClone(input);
    await expect(
      writeSemanticScanDraft(
        {
          scanDir: "/synthetic/scan",
          contract: { mode: "standard" },
          writer: {
            async restore(path) {
              writes.push(path);
            },
          },
          async workbench() {
            writes.push("workbench");
          },
        },
        input,
      ),
    ).rejects.toThrow("Stored finding JSON cannot contain non-finite numbers.");
    expect(writes).toEqual([]);
    expect(input).toEqual(original);
  },
);
