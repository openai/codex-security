import {
  captureDeepScanExecutionSettings,
  retainDeepScanExecutionSettings,
  loadDeepScanExecutionSettings,
  restoredDeepScanWorkerSettings,
  type DeepScanLegacySettingsContext,
} from "./recovery-settings.js";
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
}) {
  const { run, runWorkbench, pluginRoot, threadId, handoffClaimToken } =
    options;
  const executionSettings = retainDeepScanExecutionSettings(async (active) =>
    run.startDisposition === "created"
      ? await captureDeepScanExecutionSettings(
          active,
          options.parentSandbox,
          process.env,
          {
            threadId,
            turnId: options.parentTurn?.turnId,
            startedAt: active.createdAt,
            created: true,
          },
        )
      : await loadDeepScanExecutionSettings(
          active.scanDir,
          active,
          async () => {
            const context = await runWorkbench([
              "get-scan",
              "--scan-id",
              active.scanId,
            ]);
            const recipe = context.recipe as
              Pick<DeepScanLegacySettingsContext, "config"> | undefined;
            const scan = context.scan as {
              executionAttribution?: { owner: DeepScanRunState["usageOwner"] };
            };
            return {
              config: recipe?.config,
              usageOwner: scan.executionAttribution?.owner,
            };
          },
        ),
  );
  return startOrJoinDeepScanCoordinator({
    run,
    registry: options.registry,
    options: {
      store: options.store,
      prepareExecutor: async (active) =>
        new CodexSdkWorkerExecutor({
          ...restoredDeepScanWorkerSettings(
            await executionSettings(active),
            options.parentSandbox,
          ),
          artifactContext: {
            pluginRoot,
            scanRoot: active.scanDir,
            repoRoot: active.targetPath,
            scanId: active.scanId,
            scope: active.scope,
            includePaths: active.includePaths,
            filePaths: active.filePaths,
            pythonCommand: options.pythonCommand,
          },
        }),
      executor: new CodexSdkWorkerExecutor({
        model: options.model,
        reasoningEffort: options.reasoningEffort,
        parentSandbox: options.parentSandbox,
        parentTurn: options.parentTurn,
        artifactContext: {
          pluginRoot,
          scanRoot: run.scanDir,
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
      handoffClaimToken,
      threadId,
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
