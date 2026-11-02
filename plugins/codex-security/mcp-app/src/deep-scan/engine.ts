import childProcess from "node:child_process";
import { promises as fs } from "node:fs";
import { join } from "node:path";
import type { Readable } from "node:stream";
import { createScanArtifactContext } from "../artifact-context.js";
import { recordCodexSecurityScanDraftViaWorkbench } from "../artifact-scan-draft.js";
import { encodeGitPath } from "../helpers/inventory-git.js";
import { encodePosixPath } from "../helpers/posix-path.js";
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
    const nativeTarget =
      process.platform === "win32"
        ? encodeGitPath(target)
        : encodePosixPath(target);
    try {
      const metadata = await abortableFilesystemOperation(
        fs.stat(nativeTarget),
        signal,
      );
      if (metadata === filesystemOperationAborted) return;
      if (signal.aborted) return;
      if (exactFiles.has(selectedPath)) return;
      if (!metadata.isDirectory()) return;
      const hasEntry = await directoryHasEntry(nativeTarget, signal);
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
  target: Buffer,
  signal: AbortSignal,
): Promise<boolean> {
  if (signal.aborted) return false;
  const probe = childProcess.spawn(
    process.execPath,
    [
      "--input-type=commonjs",
      "-e",
      directoryProbeScript,
      target.toString("base64"),
    ],
    {
      stdio: ["ignore", "pipe", "pipe", "pipe"],
      windowsHide: true,
    },
  );
  const protocolStream = probe.stdio[3] as Readable | null;
  if (protocolStream === null) {
    probe.kill("SIGKILL");
    throw new Error("Directory probe protocol pipe was not created.");
  }
  return await new Promise<boolean>((resolve, reject) => {
    let settled = false;
    let protocol = "";
    const cleanup = () => signal.removeEventListener("abort", onAbort);
    const finish = (callback: () => void) => {
      if (settled) return;
      settled = true;
      cleanup();
      callback();
    };
    const terminate = () => {
      if (probe.exitCode === null && probe.signalCode === null) {
        try {
          probe.kill("SIGKILL");
        } catch {
          // The child may have exited between the state check and the signal.
        }
      }
      probe.stdout?.destroy();
      probe.stderr?.destroy();
      protocolStream.destroy();
      probe.unref();
    };
    const onAbort = () =>
      finish(() => {
        terminate();
        resolve(false);
      });
    signal.addEventListener("abort", onAbort, { once: true });
    probe.stdout?.resume();
    probe.stderr?.resume();
    protocolStream.on("data", (chunk: Buffer) => {
      protocol = (protocol + chunk.toString()).slice(-64 * 1024);
    });
    const rejectProbe = (error: Error) =>
      finish(() => {
        terminate();
        reject(error);
      });
    protocolStream.on("error", rejectProbe);
    probe.on("error", rejectProbe);
    probe.on("close", (code, childSignal) => {
      finish(() => {
        const message = directoryProbeMessage(protocol, code, childSignal);
        if (message.ok) resolve(message.nonempty);
        else reject(directoryProbeError(message.error));
      });
    });
    if (signal.aborted) onAbort();
  });
}

const directoryProbeScript = String.raw`
const { opendir } = require("node:fs/promises");
const { writeSync } = require("node:fs");
const target = Buffer.from(process.argv[1], "base64");
const errorPayload = (error) => ({
  code: typeof error?.code === "string" ? error.code : undefined,
  errno: typeof error?.errno === "number" ? error.errno : undefined,
  message: error instanceof Error ? error.message : String(error),
  syscall: typeof error?.syscall === "string" ? error.syscall : undefined,
});
(async () => {
  let directory;
  let failure;
  let nonempty = false;
  try {
    directory = await opendir(target, { encoding: "buffer", bufferSize: 1 });
    const entry = await directory.read();
    nonempty = entry !== null;
  } catch (error) {
    failure = error;
  } finally {
    if (directory !== undefined) {
      try {
        await directory.close();
      } catch (error) {
        if (failure === undefined) failure = error;
      }
    }
  }
  const message = failure === undefined
    ? { ok: true, nonempty }
    : { ok: false, error: errorPayload(failure) };
  writeSync(3, JSON.stringify(message));
  if (failure !== undefined) process.exitCode = 1;
})().catch((error) => {
  process.exitCode = 1;
  try {
    writeSync(3, JSON.stringify({ ok: false, error: errorPayload(error) }));
  } catch {}
});
`;

type DirectoryProbeMessage =
  | { ok: true; nonempty: boolean }
  | {
      ok: false;
      error: {
        code?: string;
        errno?: number;
        message: string;
        syscall?: string;
      };
    };

function directoryProbeMessage(
  protocol: string,
  code: number | null,
  signal: NodeJS.Signals | null,
): DirectoryProbeMessage {
  try {
    const parsed = JSON.parse(protocol) as Partial<DirectoryProbeMessage>;
    if (
      code === 0 &&
      parsed.ok === true &&
      typeof parsed.nonempty === "boolean"
    )
      return { ok: true, nonempty: parsed.nonempty };
    if (
      code !== 0 &&
      parsed.ok === false &&
      parsed.error !== undefined &&
      typeof parsed.error.message === "string"
    )
      return { ok: false, error: parsed.error };
  } catch {
    // Fall through to a bounded parent-owned protocol diagnostic.
  }
  return {
    ok: false,
    error: {
      message: `Directory probe failed${signal ? ` with ${signal}` : ` with exit code ${code ?? "unknown"}`}.`,
    },
  };
}

function directoryProbeError(
  payload: Extract<DirectoryProbeMessage, { ok: false }>["error"],
): Error {
  const error = new Error(payload.message);
  const filesystemError = error as NodeJS.ErrnoException;
  filesystemError.code = payload.code;
  filesystemError.errno = payload.errno;
  filesystemError.syscall = payload.syscall;
  return error;
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
