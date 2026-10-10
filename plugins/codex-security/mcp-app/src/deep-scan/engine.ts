import {
  captureDeepScanExecutionSettings,
  retainDeepScanExecutionSettings,
  loadDeepScanExecutionSettings,
  restoredDeepScanWorkerSettings,
  type DeepScanLegacySettingsContext,
} from "./recovery-settings.js";
import { createScanArtifactContext } from "../artifact-context.js";
import { recordCodexSecurityScanDraftViaWorkbench } from "../artifact-scan-draft.js";
import { CodexSdkWorkerExecutor } from "./executor.js";
import type { DeepWorkerParentSandbox } from "./parent-sandbox.js";
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
            pythonCommand: options.pythonCommand,
          },
        }),
      executor: new CodexSdkWorkerExecutor({
        model: options.model,
        reasoningEffort: options.reasoningEffort,
        parentSandbox: options.parentSandbox,
        artifactContext: {
          pluginRoot,
          scanRoot: run.scanDir,
          repoRoot: run.targetPath,
          scanId: run.scanId,
          scope: run.scope,
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
        await runWorkbench([
          "preserve-scan-results",
          "--scan-id",
          stopped.scanId,
          "--thread-id",
          threadId,
          ...(handoffClaimToken === undefined
            ? []
            : ["--claim-token", handoffClaimToken]),
          ...(stopped.coordinatorGeneration === undefined
            ? []
            : [
                "--coordinator-generation",
                String(stopped.coordinatorGeneration),
              ]),
        ]);
      },
    },
  });
}
