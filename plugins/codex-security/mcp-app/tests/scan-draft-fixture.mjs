import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { mkdir, mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const bundled = await build({
  absWorkingDir: path.dirname(fileURLToPath(import.meta.url)),
  bundle: true,
  entryPoints: ["../src/artifact-scan-draft.ts"],
  format: "esm",
  platform: "node",
  write: false,
});
export const draftApi = await import(
  `data:text/javascript;base64,${Buffer.from(bundled.outputFiles[0].text).toString("base64")}`
);
export const scanId = "7b95abf2-dc04-47a9-9950-53b5c2057f49";
export const claimToken = "19bfba38-0913-4bd7-86ef-134e9a4d9a42";

export function draftFixture(root, layout) {
  const context = {
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
  const draft = (coverage = {}, complete = false) => ({
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
    write: (input) =>
      layout === "worker"
        ? draftApi.recordCodexSecurityWorkerScanDraft(context, input)
        : draftApi.recordCodexSecurityScanDraft(context, input),
    read: async () => {
      const value = JSON.parse(
        await readFile(
          path.join(
            root,
            layout === "worker" ? "result.json" : "coverage.json",
          ),
          "utf8",
        ),
      );
      return layout === "worker" ? value.coverage : value;
    },
  };
}

export async function fixture(t, layout) {
  const directory = await realpath(
    await mkdtemp(path.join(tmpdir(), "draft-recovery-")),
  );
  t.after(() => rm(directory, { recursive: true, force: true }));
  const root = path.join(directory, "output");
  await mkdir(root);
  return draftFixture(root, layout);
}

export async function interruptDraftWrite(destination, action) {
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
