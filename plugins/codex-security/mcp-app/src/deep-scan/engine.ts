import { readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { createScanArtifactContext } from "../artifact-context.js";
import { recordCodexSecurityScanDraftViaWorkbench } from "../artifact-scan-draft.js";
import { workbenchArgs } from "../workbench-arguments.js";
import { CodexSdkWorkerExecutor } from "./executor.js";
import type { DeepWorkerParentSandbox } from "./parent-sandbox.js";
import type { DeepScanParentTurn } from "./permission-profile-preflight.js";
import {
  DeepScanCoordinatorRegistry,
  startOrJoinDeepScanCoordinator,
} from "./registry.js";
import type { WorkbenchDeepScanStore } from "./store.js";
import type { DeepScanLogger, DeepScanRunState } from "./types.js";
import type { CoordinatorOptions } from "./coordinator.js";

/** Shared execution behind the SDK engine and the plugin's MCP adapter. */
export function startDeepScanEngine(options: {
  run: DeepScanRunState;
  store: WorkbenchDeepScanStore;
  registry: DeepScanCoordinatorRegistry;
  runWorkbench: Parameters<typeof createScanArtifactContext>[1];
  pluginRoot: string;
  pythonCommand: string;
  parentSandbox: DeepWorkerParentSandbox;
  parentTurn?: DeepScanParentTurn;
  threadId: string;
  handoffClaimToken?: string;
  model?: string;
  reasoningEffort?: string;
  log?: DeepScanLogger;
  onStart?: CoordinatorOptions["onStart"];
}) {
  const { run, runWorkbench, pluginRoot, threadId, handoffClaimToken } =
    options;
  const freshStart = options.store.isFreshStart(run);
  return startOrJoinDeepScanCoordinator({
    run,
    registry: options.registry,
    options: {
      store: options.store,
      executor: new CodexSdkWorkerExecutor({
        model: options.model,
        reasoningEffort: options.reasoningEffort,
        deepScanConfig: run.config,
        parentSandbox: options.parentSandbox,
        parentTurn: options.parentTurn,
        artifactContext: {
          pluginRoot,
          repoRoot: run.targetPath,
          scanId: run.scanId,
          scope: run.scope,
          includePaths: run.includePaths,
          filePaths: run.filePaths,
          pythonCommand: options.pythonCommand,
        },
      }),
      pluginRoot,
      log: options.log,
      onStart: options.onStart,
      handoffClaimToken,
      threadId,
      checkFreshTarget: freshStart ? checkFreshTarget : undefined,
      onComplete: async (draft, signal, publication) => {
        const context = await createScanArtifactContext(
          run.scanId,
          runWorkbench,
          {
            requireRunning: true,
            requireClaim: true,
            handoffClaimToken,
            pluginRoot,
          },
        );
        await recordCodexSecurityScanDraftViaWorkbench(
          context,
          {
            ...draft,
            ...(handoffClaimToken === undefined ? {} : { handoffClaimToken }),
          },
          runWorkbench,
          signal,
          publication,
        );
      },
      onStopped: async (stopped) => {
        await runWorkbench(
          workbenchArgs("preserve-scan-results", {
            scanId: stopped.scanId,
            threadId,
            claimToken: handoffClaimToken,
            coordinatorGeneration: stopped.coordinatorGeneration,
          }),
        );
      },
    },
  });
}

async function checkFreshTarget(
  run: DeepScanRunState,
  signal: AbortSignal,
): Promise<void> {
  const exactFiles = new Set(run.filePaths ?? []);
  let readError: unknown;

  for (const selectedPath of run.includePaths ?? [run.scope]) {
    signal.throwIfAborted();
    if (exactFiles.has(selectedPath)) return;

    const target = join(run.targetPath, selectedPath);
    try {
      if (!(await stat(target)).isDirectory()) return;
      if ((await readdir(target)).length > 0) return;
    } catch (error) {
      readError ??= error;
    }
    signal.throwIfAborted();
  }

  if (readError) throw readError;
  throw new Error(
    "Deep Scan target is empty; no security audit was performed.",
  );
}
