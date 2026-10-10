import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { runWorkbench as runWorkbenchCommand } from "./server.js";
import { resolvePythonCommand } from "./src/python_command.js";
import { startDeepScanEngine } from "./src/deep-scan/engine.js";
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
      permissionProfile: unknown;
    };
    scanId = input.scanId;
    const pluginRoot =
      process.env.CODEX_SECURITY_PLUGIN_ROOT || resolve(__dirname, "..");
    process.chdir(pluginRoot);
    const store = new WorkbenchDeepScanStore(runWorkbench);
    const parentSandbox = resolveDeepWorkerParentSandbox({
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
        parentSandbox,
        threadId: input.threadId,
        model: input.model,
        reasoningEffort: input.reasoningEffort,
      });
      if (controller.signal.aborted) stop();
      terminal = await started.coordinator.wait(controller.signal);
    }
    if (terminal.status !== "succeeded") {
      throw new Error(terminal.error ?? `Deep Scan ${terminal.status}.`);
    }
    process.stdout.write(
      JSON.stringify({
        scanId: terminal.scanId,
        manifestPath: terminal.manifestPath,
      }) + "\n",
    );
  } finally {
    const coordinator = scanId === undefined ? undefined : registry.get(scanId);
    registry.shutdown("cli_engine_closed");
    process.removeListener("SIGINT", stop);
    process.removeListener("SIGTERM", stop);
    lines.removeListener("close", stop);
    lines.close();
    process.stdin.destroy();
    await coordinator?.settled();
  }
}
