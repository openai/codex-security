import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { ThreadEvent } from "@openai/codex-sdk";
import { afterEach, expect, test } from "bun:test";
import { ScanInterruptedError } from "../src/errors.js";
import { runWorkbench } from "../src/runtime.js";
import { TestClient } from "./support/api-client.js";
import { preparedRuntime } from "./support/api-events.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

for (const fault of [
  "once-before-commit",
  "always-before-commit",
  "lost-response",
  "unavailable-readback",
] as const) {
  test(`Deep cancellation reconciles durable worker state: ${fault}`, async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const scanDir = join(root, "scan");
    const codexHome = join(root, "codex-home");
    const output = join(scanDir, "artifacts", "worker");
    const prompt = join(output, "prompt.md");
    await Promise.all([
      mkdir(repository),
      mkdir(codexHome),
      mkdir(scanDir, { mode: 0o700 }),
    ]);
    await writeFile(join(repository, "source.py"), "# Synthetic source\n");
    const environment = {
      ...process.env,
      CODEX_HOME: codexHome,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
    };
    const controller = new AbortController();
    const reason = new Error("Synthetic caller cancellation");
    const firstFailure = new Error(
      "Synthetic cancellation helper failed before its response",
    );
    const secondFailure = new Error(
      "Synthetic cancellation retry failed before its response",
    );
    const threadId = "1af317a1-c9ed-4c73-b428-cb0d160cf8e8";
    const workerId = "6084fc51-5798-4e0b-b412-de8fc5c1dd9b";
    let scanId = "";
    let workbenchOptions: Parameters<typeof runWorkbench>[0];
    let cancellationCalls = 0;
    const commands: string[] = [];
    const client = TestClient.withDependencies({
      environment,
      prepareRuntime: async () => ({
        ...preparedRuntime(codexHome),
        environment,
      }),
      resolvePluginPython: async () => "python3",
      prepareOutputDir: async () => scanDir,
      runWorkbench: async (options, args, input) => {
        workbenchOptions = options;
        commands.push(args[0]!);
        if (args[0] === "cancel-scan") {
          cancellationCalls++;
          expect(options.signal).toBeUndefined();
          if (
            fault !== "lost-response" &&
            (fault !== "once-before-commit" || cancellationCalls === 1)
          ) {
            throw cancellationCalls === 1 ? firstFailure : secondFailure;
          }
        }
        if (
          args[0] === "get-scan" &&
          cancellationCalls >= 2 &&
          fault === "unavailable-readback"
        ) {
          throw new Error("Synthetic cancellation readback unavailable");
        }
        const result = await runWorkbench(options, args, input);
        if (args[0] === "register-cli-scan")
          scanId = result["scanId"] as string;
        if (args[0] === "cancel-scan" && fault === "lost-response") {
          throw cancellationCalls === 1 ? firstFailure : secondFailure;
        }
        return result;
      },
      createCodex: () => ({
        startThread: () => ({
          id: threadId,
          runStreamed: async () => ({
            events: (async function* (): AsyncGenerator<ThreadEvent> {
              yield { type: "thread.started", thread_id: threadId };
              await runWorkbench(workbenchOptions!, [
                "begin-deep-scan",
                "--scan-id",
                scanId,
                "--thread-id",
                threadId,
              ]);
              await mkdir(output, { recursive: true });
              await writeFile(prompt, "Review the synthetic source.\n");
              await runWorkbench(workbenchOptions!, [
                "upsert-deep-scan-worker",
                "--scan-id",
                scanId,
                "--worker-id",
                workerId,
                "--kind",
                "discovery",
                "--status",
                "running",
                "--prompt-path",
                prompt,
                "--artifact-dir",
                output,
              ]);
              controller.abort(reason);
              throw reason;
            })(),
          }),
        }),
      }),
    });
    try {
      const error = await client
        .run(repository, { mode: "deep", signal: controller.signal })
        .catch((error: unknown) => error);
      expect(scanId, String(error)).not.toBe("");
      const options = { ...workbenchOptions!, signal: undefined };
      const saved = await runWorkbench(options, [
        "get-scan",
        "--scan-id",
        scanId,
      ]);
      const deep = await runWorkbench(options, [
        "get-deep-scan",
        "--scan-id",
        scanId,
        "--thread-id",
        threadId,
      ]);
      const canceled =
        fault === "once-before-commit" || fault === "lost-response";
      expect(saved["scan"]).toMatchObject({
        progress: { status: canceled ? "canceled" : "running" },
      });
      expect(deep["deepScan"]).toMatchObject({
        status: canceled ? "canceled" : "running",
        cancelRequested: canceled,
        workers: [{ id: workerId, status: canceled ? "canceled" : "running" }],
        attempts: [
          {
            workerId,
            status: canceled ? "canceled" : "running",
            endReason: canceled ? "scan_stopped" : null,
          },
        ],
      });
      if (canceled) {
        expect(error).toBeInstanceOf(ScanInterruptedError);
        expect((error as ScanInterruptedError).cause).toBe(reason);
      } else expect(error).toBe(firstFailure);
      expect(cancellationCalls).toBe(2);
      expect(commands).not.toContain("fail-scan");
    } finally {
      if (scanId)
        await runWorkbench({ ...workbenchOptions!, signal: undefined }, [
          "cancel-scan",
          "--scan-id",
          scanId,
        ]);
      await client.close();
    }
  }, 30_000);
}
