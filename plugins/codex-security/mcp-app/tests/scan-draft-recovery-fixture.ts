import { temporaryDirectory } from "./support/temporary-directories.ts";
import { readJson } from "./support/json.ts";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { mkdir, rm } from "node:fs/promises";
import path from "node:path";
import type { TestContext } from "node:test";
import type { ScanDraftInput } from "../src/artifact-scan-draft.js";
import type { ArtifactContext } from "../src/artifact-io.js";
import { importSource } from "./import-module.ts";
export const draftApi = await importSource("../src/artifact-scan-draft.ts", {
  absWorkingDir: import.meta.dirname,
});
export const scanId = "7b95abf2-dc04-47a9-9950-53b5c2057f49";
export const claimToken = "19bfba38-0913-4bd7-86ef-134e9a4d9a42";

type Layout = "standard" | "diff" | "deep" | "worker";

export function draftFixture(root: string, layout: Layout) {
  const context: ArtifactContext = {
    root,
    repoRoot: root,
    scanId,
    layout: layout === "worker" ? "worker" : "scan",
    mode: layout,
    scope: ".",
    status: "running",
    ...(layout === "worker" ? {} : { handoffClaimToken: claimToken }),
    targetRevision: "1234567890abcdef",
    targetContract: {
      target: {
        allowedKinds: [layout === "diff" ? "git_diff" : "git_worktree"],
        targetId: "target_example",
        displayName: "example",
        requiredSnapshotDigest:
          "codex-security-snapshot/v1:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      },
      scope: { requiredIncludePaths: ["."], requiredExcludePaths: [] },
      diffTarget:
        layout === "diff"
          ? {
              kind: "range",
              baseRevision: "a".repeat(40),
              headRevision: "b".repeat(40),
            }
          : null,
    },
  };
  const draft = (
    coverage: { deferred?: unknown[]; [key: string]: unknown } = {},
    complete = false,
  ): ScanDraftInput => ({
    scanId,
    ...(layout === "worker" ? {} : { handoffClaimToken: claimToken }),
    complete,
    findings: [],
    coverage: {
      completeness:
        complete && !coverage.deferred?.length ? "complete" : "partial",
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
      ...coverage,
    },
  });
  return {
    root,
    context,
    draft,
    write: (input: ScanDraftInput) =>
      layout === "worker"
        ? draftApi.recordCodexSecurityWorkerScanDraft(context, input)
        : draftApi.recordCodexSecurityScanDraft(context, input),
    read: async () =>
      layout === "worker"
        ? (await readJson(root, "result.json")).coverage
        : await readJson(root, "coverage.json"),
  };
}

export async function fixture(t: TestContext, layout: Layout) {
  const directory = await temporaryDirectory("draft-recovery-", true);
  t.after(() => rm(directory, { recursive: true, force: true }));
  const root = path.join(directory, "output");
  await mkdir(root);
  return draftFixture(root, layout);
}

export async function interruptDraftWrite(
  destination: string,
  action: () => Promise<unknown>,
) {
  const rename = fs.rename;
  fs.rename = async (source, target) => {
    if (target === destination) throw new Error("interrupted draft write");
    return rename(source, target);
  };
  try {
    await assert.rejects(action(), /interrupted draft write/);
  } finally {
    fs.rename = rename;
  }
}

export const surfaceDisposition = ({
  id,
  disposition,
}: {
  id: string;
  disposition: string;
}) => ({ id, disposition });
