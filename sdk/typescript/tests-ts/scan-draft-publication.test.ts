import { cp, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { admitCanonicalArtifacts } from "../src/scan-publication.js";
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
        reviewState: {
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
    expect(checkpoint).toHaveProperty("reviewState.surfaces", []);
    expect(checkpoint).not.toHaveProperty("handoffClaimToken");
    const documents = [...staged].find(
      ([name]) => !name.endsWith(".checkpoint.json"),
    )![1];
    expect(documents).toHaveProperty("reviewState.mode", "repository");
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
      reviewState: { surfaces: [], explicitExclusions: [], deferred: [] },
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

test.each(["completed-scan", "legacy-completed-scan"])(
  "admits the canonical artifacts for the %s contract",
  async (fixture) => {
    await using temp = await scopedTemporaryDirectory("scan-publication-");
    const scanDir = join(temp.path, "scan");
    await cp(join(PLUGIN_ROOT, "examples", fixture), scanDir, {
      recursive: true,
    });
    await admitCanonicalArtifacts({
      scanDir,
      signal: new AbortController().signal,
    });
  },
);

test("a blocked discovery checkpoint is admitted only after the review finishes", async () => {
  await using temp = await scopedTemporaryDirectory("scan-publication-");
  const scanDir = join(temp.path, "scan");
  await cp(join(PLUGIN_ROOT, "examples", "completed-scan"), scanDir, {
    recursive: true,
  });
  const manifestPath = join(scanDir, "scan-manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  const findingsPath = join(scanDir, "findings.json");
  const findings = JSON.parse(await readFile(findingsPath, "utf8"));
  findings.findings = [];
  await writeFile(findingsPath, JSON.stringify(findings));
  const reviewState = {
    surfaces: [],
    explicitExclusions: [],
    deferred: [
      {
        id: "source-access",
        reason: "Source access was denied before review.",
      },
    ],
  };
  const context = { scanDir, signal: new AbortController().signal };
  manifest.scan.complete = false;
  manifest.scan.reviewState = reviewState;
  const checkpoint = JSON.stringify(manifest);
  await writeFile(manifestPath, checkpoint);
  await expect(admitCanonicalArtifacts(context)).rejects.toThrow(
    "unfinished audit checkpoint",
  );
  expect(await readFile(manifestPath, "utf8")).toBe(checkpoint);
  manifest.scan.complete = true;
  manifest.scan.reviewState = { ...reviewState, deferred: [] };
  await writeFile(manifestPath, JSON.stringify(manifest));
  await admitCanonicalArtifacts(context);
});
