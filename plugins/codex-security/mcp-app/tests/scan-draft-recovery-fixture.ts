import { createHash } from "node:crypto";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import { readJson } from "./support/json.ts";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { mkdir, rm } from "node:fs/promises";
import path from "node:path";
import type { TestContext } from "node:test";
import type { ScanDraftInput } from "../src/artifact-scan-draft.js";
import type { ArtifactContext } from "../src/artifact-io.js";
import { importModule, importSource } from "./import-module.ts";
export const draftApi = await importSource("../src/artifact-scan-draft.ts", {
  absWorkingDir: import.meta.dirname,
});

const {
  artifactDestination,
  replaceArtifactJson,
  replaceArtifactText,
  saveThreatModelDocument,
  semanticScanDraft,
} = await importModule({
  stdin: {
    contents:
      'export * from "./artifact-io.ts"; export * from "./threat-model-document.ts"; export { semanticScanDraft } from "../../../../sdk/typescript/src/scan-semantics.ts";',
    resolveDir: path.join(import.meta.dirname, "../src"),
  },
});

// Unit publication boundary; real lock/binding behavior is covered by the workbench integration suite.
export async function recordCodexSecurityScanDraft(
  context: ArtifactContext,
  input: unknown,
) {
  return draftApi.recordCodexSecurityScanDraft(
    context,
    input,
    async (draft, _digest, checkpoint, reconciled) => {
      const raw = await saveScanDraftCheckpoint(context, checkpoint);
      const accepted = await saveScanDraftCheckpoint(
        context,
        semanticScanDraft(
          context.scanId,
          draft.manifest.scan,
          draft.findings.findings,
          draft.coverage,
        ),
        false,
        false,
      );
      await replaceArtifactJson(
        await artifactDestination(
          context,
          ["checkpoint-head.json"],
          "checkpoint head",
        ),
        { checkpoint: path.basename(accepted) },
      );
      for (const [key, name] of [
        ["findings", "findings.json"],
        ["coverage", "coverage.json"],
        ["manifest", "scan-manifest.json"],
      ]) {
        await replaceArtifactJson(
          await artifactDestination(context, [name], "scan draft"),
          draft[key],
        );
      }
      for (const name of [...reconciled, path.basename(raw)])
        await rm(path.join(context.root, "checkpoints", "pending", name), {
          force: true,
        });
      const warning = await saveThreatModelDocument(
        context,
        draft.manifest.scan.threatModel,
      );
      return warning === undefined ? undefined : [warning];
    },
  );
}

export async function saveScanDraftCheckpoint(
  context: ArtifactContext,
  input: ScanDraftInput,
  _validate = true,
  pending = true,
) {
  const { handoffClaimToken: _claim, ...snapshot } = input;
  const contents = JSON.stringify(snapshot);
  const name = createHash("sha256").update(contents).digest("hex") + ".json";
  await replaceArtifactText(
    await artifactDestination(context, ["checkpoints", name], "checkpoint"),
    contents,
  );
  if (pending)
    await replaceArtifactText(
      await artifactDestination(
        context,
        ["checkpoints", "pending", name],
        "pending checkpoint",
      ),
      "",
    );
  return path.join(context.root, "checkpoints", name);
}

export const scanId = "7b95abf2-dc04-47a9-9950-53b5c2057f49";
export const claimToken = "19bfba38-0913-4bd7-86ef-134e9a4d9a42";

type Layout = "standard" | "diff" | "deep";

export function draftFixture(root: string, layout: Layout) {
  const context: ArtifactContext = {
    root,
    repoRoot: root,
    scanId,
    mode: layout,
    scope: ".",
    status: "running",
    ...{ handoffClaimToken: claimToken },
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
    ...{ handoffClaimToken: claimToken },
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
      recordCodexSecurityScanDraft(context, input),
    read: async () => await readJson(root, "coverage.json"),
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
  let interrupted = false;
  fs.rename = async (source, target) => {
    if (target === destination) {
      interrupted = true;
      throw new Error("interrupted draft write");
    }
    return rename(source, target);
  };
  try {
    await assert.rejects(action(), /interrupted draft write/);
    assert.equal(interrupted, true);
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
