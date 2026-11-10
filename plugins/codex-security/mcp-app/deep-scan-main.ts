import { join } from "node:path";
import { createInterface } from "node:readline";
import {
  PLUGIN_ROOT,
  runWorkbench as runWorkbenchCommand,
} from "./src/workbench-client.js";
import { resolvePythonCommand } from "./src/python_command.js";
import { startDeepScanEngine } from "./src/deep-scan/engine.js";
import { HostedDeepScanExecutor } from "./src/deep-scan/hosted-executor.js";
import { resolveDeepWorkerParentSandbox } from "./src/deep-scan/parent-sandbox.js";
import { DeepScanCoordinatorRegistry } from "./src/deep-scan/registry.js";
import { WorkbenchDeepScanStore } from "./src/deep-scan/store.js";

/** Private SDK entry point. The child process isolates each scan's environment. */
export async function runCliDeepScan(): Promise<void> {
  const runWorkbench = (args: string[], input?: string | Buffer) =>
    runWorkbenchCommand(args, input, { isolatedPython: true });
  const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
  const registry = new DeepScanCoordinatorRegistry();
  const controller = new AbortController();
  let scanId: string | undefined;
  let hostedExecutor: HostedDeepScanExecutor | undefined;
  let coordinatorStatusSent = false;
  const notifyStatus = (status: "succeeded" | "failed" | "canceled") => {
    if (!hostedExecutor || coordinatorStatusSent) return;
    coordinatorStatusSent = true;
    process.send?.(
      { method: "coordinator.status", params: { status } },
      () => {},
    );
  };
  const stop = () => {
    controller.abort();
    registry.shutdown("cli_interrupted");
  };
  lines.once("close", stop);
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
  try {
    const first = await lines[Symbol.asyncIterator]().next();
    if (first.done)
      throw new Error("Deep Scan engine input closed before startup.");
    const input = JSON.parse(first.value) as {
      scanId: string;
      threadId: string;
      model: string;
      reasoningEffort?: string;
      permissionProfile?: unknown;
      hosted?: boolean;
      diagnosticsVersion?: number;
    };
    scanId = input.scanId;
    const pluginRoot = PLUGIN_ROOT;
    process.chdir(pluginRoot);
    const store = new WorkbenchDeepScanStore(runWorkbench);
    if (input.hosted) {
      if (!process.send)
        throw new Error("Hosted Deep Scan requires an IPC host connection.");
      hostedExecutor = new HostedDeepScanExecutor({
        send: (message, callback) => {
          process.send!(message as object, callback);
        },
        on: process.on.bind(process),
        off: process.off.bind(process),
      });
    }
    const parentSandbox = input.hosted
      ? undefined
      : resolveDeepWorkerParentSandbox({
          _meta: {
            "codex/sandbox-state-meta": {
              permissionProfile: input.permissionProfile,
            },
          },
        });
    if (controller.signal.aborted)
      throw new Error("Deep Scan canceled before coordinator startup.");
    const run = await store.begin({
      scanId: input.scanId,
      threadId: input.threadId,
      model: input.model,
      reasoningEffort: input.reasoningEffort,
      scanRoot: join(process.env.CODEX_SECURITY_STATE_DIR!, "scans"),
    });
    if (controller.signal.aborted)
      throw new Error("Deep Scan canceled before coordinator startup.");
    let terminal = run;
    if (run.status === "running") {
      const started = await startDeepScanEngine({
        run,
        store,
        registry,
        runWorkbench,
        pluginRoot,
        pythonCommand: await resolvePythonCommand(),
        ...(input.diagnosticsVersion === 1 &&
          process.send && {
            log: (event) => {
              // A closing diagnostics channel must not interrupt durable cleanup.
              process.send?.(event, () => {});
            },
          }),
        parentSandbox,
        executor: hostedExecutor,
        threadId: input.threadId,
        model: input.model,
        reasoningEffort: input.reasoningEffort,
      });
      if (controller.signal.aborted) stop();
      terminal = await started.coordinator.wait(controller.signal);
    }
    notifyStatus(
      terminal.status === "succeeded"
        ? "succeeded"
        : terminal.status === "canceled"
          ? "canceled"
          : "failed",
    );
    if (terminal.status !== "succeeded") {
      throw new Error(terminal.error ?? `Deep Scan ${terminal.status}.`);
    }
    process.stdout.write(
      JSON.stringify({
        scanId: terminal.scanId,
        manifestPath: terminal.manifestPath,
      }) + "\n",
    );
  } catch (error) {
    notifyStatus(controller.signal.aborted ? "canceled" : "failed");
    throw error;
  } finally {
    const coordinator = scanId === undefined ? undefined : registry.get(scanId);
    registry.shutdown("cli_engine_closed");
    process.removeListener("SIGINT", stop);
    process.removeListener("SIGTERM", stop);
    lines.removeListener("close", stop);
    lines.close();
    process.stdin.destroy();
    await coordinator?.settled();
    hostedExecutor?.close();
    if (hostedExecutor && process.connected) process.disconnect?.();
  }
}
