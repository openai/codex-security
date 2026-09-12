import {
  deepReductionToScanDraft,
  parseDeepReduction,
} from "./artifact-validation.js";
import {
  createScanArtifactContext,
  type RunArtifactWorkbench,
} from "../artifact-context.js";
import {
  recordCodexSecurityScanDraftViaWorkbench,
  type DeepScanPublication,
} from "../artifact-scan-draft.js";
import { WorkbenchDeepScanStore } from "./store.js";
import { createDeepScanArtifacts } from "./artifacts.js";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { type ScanDraftInput } from "../artifact-scan-draft.js";
import { requireRegularFile, type DeepScanArtifacts } from "./artifacts.js";
import type {
  DeepScanFinalizationInput,
  DeepScanRunState,
  DeepScanStore,
} from "./types.js";

export type { DeepScanFinalizationInput } from "./types.js";

/** Publish exactly the saved aggregate; the enclosing scan owns public completion. */
export async function publishSelectedDeepScan(input: {
  run: DeepScanRunState;
  artifacts: DeepScanArtifacts;
  signal: AbortSignal;
  publish: (
    draft: ScanDraftInput,
    signal: AbortSignal,
    publication: DeepScanPublication,
  ) => Promise<void>;
  finish: DeepScanStore["finish"];
}): Promise<DeepScanRunState> {
  const { run, artifacts, signal } = input;
  const selection = selectedInput(run);
  if (run.status === "succeeded") return run;
  if (run.status !== "running")
    throw new Error("Stopped Deep Scan finalization cannot become successful.");
  signal.throwIfAborted();
  const draft = await readSelectedDeepScanDraft(
    artifacts,
    run.scanId,
    selection,
  );
  await input.publish(draft, signal, {
    coordinatorGeneration: run.coordinatorGeneration,
    resultPath:
      selection.resultPath === null
        ? null
        : join(run.scanDir, selection.resultPath),
  });
  signal.throwIfAborted();
  return input.finish({
    scanId: run.scanId,
    reason: selection.terminalReason,
    manifestPath: join(run.scanDir, "scan-manifest.json"),
    omittedWorkerIds: selection.omittedWorkerIds,
  });
}

/** Recreate the chosen draft without scheduling discovery or reducer work. */
export async function readSelectedDeepScanDraft(
  artifacts: DeepScanArtifacts,
  scanId: string,
  selection: DeepScanFinalizationInput,
): Promise<ScanDraftInput> {
  if (selection.version !== 1)
    throw new Error("Unsupported Deep Scan finalization input version.");
  if (selection.resultPath === null) {
    if (
      selection.terminalReason !== "capped" ||
      selection.resultSha256 !== null
    ) {
      throw new Error(
        "An empty Deep Scan finalization requires the recorded discovery deadline.",
      );
    }
    return {
      scanId,
      findings: [],
      coverage: {
        completeness: "partial",
        surfaces: [],
        explicitExclusions: [],
        deferred: [
          {
            reason:
              "The configured discovery time limit elapsed before any source review completed.",
          },
        ],
      },
    };
  }
  const resultPath = join(artifacts.scanDir, selection.resultPath);
  await requireRegularFile(resultPath, artifacts.scanDir);
  const contents = await readFile(resultPath);
  if (
    createHash("sha256").update(contents).digest("hex") !==
    selection.resultSha256
  ) {
    throw new Error(
      "The selected Deep Scan finalization input changed after acceptance.",
    );
  }
  const stored = JSON.parse(contents.toString("utf8"));
  const draft = deepReductionToScanDraft(parseDeepReduction(stored, true));
  if (draft.scanId !== scanId || draft.complete === false) {
    throw new Error(
      "Deep Scan finalization requires the selected complete result for this scan.",
    );
  }
  return draft;
}

/** SDK recovery uses the installed plugin's publisher and the original parent scan. */
export async function resumeSelectedDeepScan(input: {
  scanId: string;
  threadId: string;
  pluginRoot: string;
  runWorkbench: RunArtifactWorkbench;
  signal: AbortSignal;
  handoffClaimToken?: string;
}): Promise<void> {
  const store = new WorkbenchDeepScanStore(input.runWorkbench);
  const run = await store.get(input.scanId, input.threadId);
  selectedInput(run);
  try {
    await publishSelectedDeepScan({
      run,
      artifacts: createDeepScanArtifacts(run.scanDir),
      signal: input.signal,
      publish: async (draft, signal, publication) => {
        const context = await createScanArtifactContext(
          input.scanId,
          input.runWorkbench,
          {
            requireRunning: true,
            requireClaim: true,
            handoffClaimToken: input.handoffClaimToken,
            pluginRoot: input.pluginRoot,
          },
        );
        await recordCodexSecurityScanDraftViaWorkbench(
          context,
          draft,
          input.runWorkbench,
          signal,
          publication,
        );
      },
      finish: (selection) =>
        store.finish({
          ...selection,
          coordinatorGeneration: run.coordinatorGeneration,
        }),
    });
  } catch (error) {
    // The original coordinator may publish while the SDK recovers its parent turn.
    const committed = await store
      .get(input.scanId, input.threadId)
      .catch(() => null);
    if (committed?.status !== "succeeded") throw error;
  }
}

function selectedInput(run: DeepScanRunState): DeepScanFinalizationInput {
  const selection = run.finalizationInput;
  if (!selection)
    throw new Error("Deep Scan has no selected finalization input.");
  if (
    run.workflowVersion !== "deep-security-scan/v2" ||
    selection.version !== 1
  ) {
    throw new Error("Unsupported Deep Scan finalization input version.");
  }
  return selection;
}
