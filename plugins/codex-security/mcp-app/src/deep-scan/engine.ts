import { promises as fs } from "node:fs";
import type { Dir } from "node:fs";
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
      checkFreshTarget,
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

export async function checkFreshTarget(
  run: DeepScanRunState,
  signal: AbortSignal,
): Promise<void> {
  const exactFiles = new Set(run.filePaths ?? []);
  let readError: unknown;

  for (const selectedPath of run.includePaths ?? [run.scope]) {
    if (signal.aborted) return;

    const target = join(run.targetPath, selectedPath);
    try {
      const metadata = await abortableFilesystemOperation(
        fs.stat(target),
        signal,
      );
      if (metadata === filesystemOperationAborted) return;
      if (signal.aborted) return;
      if (exactFiles.has(selectedPath)) return;
      if (!metadata.isDirectory()) return;
      const hasEntry = await directoryHasEntry(target, signal);
      if (signal.aborted) return;
      if (hasEntry) return;
    } catch (error) {
      if (signal.aborted) return;
      readError ??= error;
    }
  }

  if (readError) throw readError;
  throw new Error(
    "Deep Scan target is empty; no security audit was performed.",
  );
}

const filesystemOperationAborted = Symbol("filesystemOperationAborted");

async function directoryHasEntry(
  target: string,
  signal: AbortSignal,
): Promise<boolean> {
  const open = fs.opendir(target);
  const directory = await abortableFilesystemOperation(open, signal);
  if (directory === filesystemOperationAborted) {
    void open.then(closeDirectoryEventually, () => {});
    return false;
  }
  let closeStarted = false;
  const close = async (wait: boolean): Promise<void> => {
    if (closeStarted) return;
    closeStarted = true;
    let closing: Promise<void>;
    try {
      closing = directory.close();
    } catch (error) {
      if (wait && !signal.aborted) throw error;
      return;
    }
    if (!wait) {
      void closing.catch(() => {});
      return;
    }
    await abortableFilesystemOperation(closing, signal);
  };
  let operationError: unknown;
  try {
    if (signal.aborted) return false;
    const read = directory.read();
    const entry = await abortableFilesystemOperation(read, signal);
    if (entry === filesystemOperationAborted) {
      void close(false);
      return false;
    }
    return entry !== null;
  } catch (error) {
    operationError = error;
    throw error;
  } finally {
    if (!closeStarted) {
      try {
        await close(true);
      } catch (error) {
        if (operationError === undefined && !signal.aborted) throw error;
      }
    }
  }
}

async function abortableFilesystemOperation<T>(
  operation: Promise<T>,
  signal: AbortSignal,
): Promise<T | typeof filesystemOperationAborted> {
  return await new Promise((resolve, reject) => {
    let settled = false;
    const cleanup = () => signal.removeEventListener("abort", onAbort);
    const onAbort = () => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(filesystemOperationAborted);
    };
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) onAbort();
    void operation.then(
      (value) => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(value);
      },
      (error: unknown) => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(error);
      },
    );
  });
}

async function closeDirectoryEventually(directory: Dir): Promise<void> {
  try {
    await directory.close();
  } catch {
    // Cancellation won before the open completed. The handle is no longer part
    // of admission, and a late close failure must not become unhandled.
  }
}
