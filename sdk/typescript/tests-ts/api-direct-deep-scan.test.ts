import { mkdir, readFile, writeFile } from "node:fs/promises";
import { hash } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { delimiter, join } from "node:path";
import { afterEach, expect, mock, test } from "bun:test";
import { copyCompletedScan } from "./plugin-root.js";
import { TestClient, mockWorkbench } from "./support/api-client.js";
import {
  completedEvents,
  preparedRuntime,
  scanRuntimeDependencies,
} from "./support/api-events.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";
import { writeSession } from "./support/usage-rollout.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

test.each([undefined, "Summarize the completed scan."])(
  "Deep Scan preserves worker usage and the finalized report with post-scan prompt %p",
  async (postScanPrompt) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "codex-home");
    const scanDir = join(root, "scan");
    await mkdir(repository);
    await mkdir(codexHome);
    await mkdir(scanDir, { mode: 0o700 });
    const finalReport =
      "# Final scan report\n\nFinalized synthetic findings.\n";
    const commands: string[] = [];
    let completionReceipt: string | undefined;
    const { promise: runningCost, resolve: recordCost } =
      Promise.withResolvers<number>();
    const parentTurn = mock(async () => {
      throw new Error("A parent model turn must not execute the Deep Scan.");
    });
    const postScanTurn = mock(async () => ({
      events: completedEvents("engine-session"),
    }));
    const resumeThread = mock((threadId: string) => ({
      id: threadId,
      runStreamed: postScanTurn,
    }));
    const started = mock();
    const client = new TestClient(
      { codexOverrides: { model: "gpt-5.6-sol" } },
      {
        ...scanRuntimeDependencies(codexHome, scanDir),
        canRunDirectDeepScan: () => true,
        environment: {
          CODEX_SECURITY_STATE_DIR: join(root, "state"),
          CODEX_API_KEY: "synthetic-direct-scan-key",
        },
        createCodex: () => ({
          startThread: () => ({ id: null, runStreamed: parentTurn }),
          resumeThread,
        }),
        runDeepScan: async function* (options) {
          expect(options.scanId).toBe("scan_example_001");
          expect(options.codexOptions.env).toMatchObject({
            CODEX_SECURITY_SCAN_ID: options.scanId,
            CODEX_SECURITY_SCAN_DIR: scanDir,
            CODEX_SECURITY_REPOSITORY: repository,
          });
          await copyCompletedScan(root);
          const coveragePath = join(scanDir, "coverage.json");
          const coverage = JSON.parse(await readFile(coveragePath, "utf8"));
          coverage.mode = "deep_repository";
          const coverageBytes = JSON.stringify(coverage);
          await writeFile(coveragePath, coverageBytes);
          const manifestPath = join(scanDir, "scan-manifest.json");
          const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
          const artifact = manifest.scan.artifacts.find(
            (entry: { path: string }) => entry.path === "coverage.json",
          );
          artifact.sha256 = hash("sha256", coverageBytes);
          await writeFile(manifestPath, JSON.stringify(manifest));
          await writeSession(
            codexHome,
            "engine-session",
            {},
            {
              cwd: scanDir,
              timestamp: "2026-07-26T12:00:00Z",
            },
          );
          await writeSession(
            codexHome,
            "discovery-session",
            { input_tokens: 100, output_tokens: 10 },
            {
              cwd: join(
                scanDir,
                "artifacts",
                "deep_discovery",
                "workers",
                "one",
                "output",
              ),
              timestamp: "2026-07-26T12:00:01Z",
            },
          );
          yield { type: "thread.started", thread_id: "engine-session" };
          // The host must count workers while the no-inference coordinator runs.
          expect(await runningCost).toBe(100);
          yield {
            type: "turn.completed",
            usage: {
              input_tokens: 0,
              cached_input_tokens: 0,
              cache_write_input_tokens: 0,
              output_tokens: 0,
            },
          };
        },
        runWorkbench: async (_options, args, input) => {
          commands.push(args[0]!);
          if (args[0] === "prepare-scan-completion") {
            await writeFile(
              join(scanDir, "report.md"),
              "# Prepared scan report\n",
            );
          } else if (args[0] === "complete-scan") {
            const receiptIndex = args.indexOf("--cost-json");
            completionReceipt =
              receiptIndex < 0 ? undefined : args[receiptIndex + 1];
            await writeFile(join(scanDir, "report.md"), finalReport);
          }
          return mockWorkbench(args, input);
        },
      },
    );
    try {
      const result = await client.run(repository, {
        mode: "deep",
        postScanPrompt,
        onScanStarted: started,
        onCost: (cost) => recordCost(cost.inputTokens),
      });
      expect(result.threadId).toBe("engine-session");
      expect(result.reportPath).toBe(join(scanDir, "report.md"));
      expect(result.turnResult.finalResponse).toBe(finalReport);
      expect(result.cost?.inputTokens).toBe(100);
      expect(JSON.parse(completionReceipt!)).toMatchObject({
        inputTokens: 100,
      });
      expect(result.toJSON()["turn"]).toMatchObject({
        finalResponse: finalReport,
      });
      expect(parentTurn).not.toHaveBeenCalled();
      expect(resumeThread).toHaveBeenCalledTimes(postScanPrompt ? 1 : 0);
      expect(postScanTurn).toHaveBeenCalledTimes(postScanPrompt ? 1 : 0);
      if (postScanPrompt) {
        expect(resumeThread).toHaveBeenCalledWith(
          "engine-session",
          expect.objectContaining({ workingDirectory: scanDir }),
        );
        expect(postScanTurn).toHaveBeenCalledWith(
          postScanPrompt,
          expect.objectContaining({ signal: expect.any(AbortSignal) }),
        );
      }
      expect(started).toHaveBeenCalledTimes(1);
      expect(
        commands.filter((command) =>
          [
            "register-cli-scan",
            "set-scan-thread",
            "prepare-scan-completion",
            "complete-scan",
          ].includes(command),
        ),
      ).toEqual([
        "register-cli-scan",
        "set-scan-thread",
        "prepare-scan-completion",
        "complete-scan",
      ]);
    } finally {
      await client.close();
    }
  },
);

test.each(["configured", "managed"] as const)(
  "Bun Deep Scans retain the parent route and %s Node configuration",
  async (selection) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "codex-home");
    const scanDir = join(root, "scan");
    await mkdir(repository);
    await mkdir(codexHome);
    await mkdir(scanDir, { mode: 0o700 });
    const inheritedTools = join(root, "operator-tools");
    await mkdir(inheritedTools);
    const runtimeEnvironment: Record<string, string> =
      selection === "configured"
        ? { CODEX_MCP_NODE_PATH: join(root, "managed-node") }
        : { XDG_CACHE_HOME: join(root, "managed-cache") };
    const environment = {
      PATH: inheritedTools,
      ...runtimeEnvironment,
      CODEX_API_KEY: "synthetic-bun-scan-key",
    };
    const postScanPrompt = "Read the completed scan in a code-mode cell.";
    const followUp = mock(async (prompt: string) => {
      expect(prompt).toBe(postScanPrompt);
      return { events: completedEvents("owner") };
    });
    const codeMode = { direct_only_tool_namespaces: ["caller_tools"] };
    const parentTurn = mock(async (prompt: string) => {
      expect(prompt).toContain("start_codex_security_deep_scan");
      async function* events() {
        yield { type: "thread.started", thread_id: "owner" };
        throw new Error("parent route reached");
      }
      return { events: events() };
    });
    const client = new TestClient(
      {
        codexOverrides: {
          model: "gpt-6.1-sol",
          model_reasoning_effort: "high",
          features: { code_mode: codeMode },
        },
      },
      {
        ...scanRuntimeDependencies(codexHome, scanDir),
        environment: {
          ...environment,
          CODEX_SECURITY_STATE_DIR: join(root, "state"),
        },
        prepareRuntime: async () => ({
          ...preparedRuntime(codexHome),
          environment,
        }),
        createCodex: (options) => {
          expect(options.env).toMatchObject(runtimeEnvironment);
          expect(options.env?.["PATH"]?.split(delimiter)).toContain(
            inheritedTools,
          );
          expect(options.config).toMatchObject({
            model: "gpt-6.1-sol",
            model_reasoning_effort: "high",
          });
          return {
            startThread: (threadOptions) => {
              expect(threadOptions.workingDirectory).toBe(scanDir);
              return { id: null, runStreamed: parentTurn };
            },
            resumeThread: (id, threadOptions) => {
              expect(id).toBe("owner");
              expect(threadOptions.workingDirectory).toBe(scanDir);
              expect(options.config?.["features"]).toMatchObject({
                code_mode: codeMode,
              });
              expect(options.configOverrides?.join("\n")).not.toContain(
                "direct_only_tool_namespaces",
              );
              return { id, runStreamed: followUp };
            },
          };
        },
        runDeepScan: async function* () {
          throw new Error("unexpected direct engine");
        },
      },
    );
    try {
      await expect(
        client.run(repository, {
          mode: "deep",
          postScanPrompt,
        }),
      ).rejects.toThrow("parent route reached");
      expect(parentTurn).toHaveBeenCalledTimes(1);
      expect(followUp).toHaveBeenCalledTimes(1);
    } finally {
      await client.close();
    }
  },
);

test("Node runs the direct Deep Scan contracts", async () => {
  if (
    runTestInSubprocess(
      import.meta.path,
      "Node runs the direct Deep Scan contracts",
    )
  )
    return;
  const root = await temporaryDirectory();
  const source = new URL("./direct-deep-scan.test.ts", import.meta.url);
  const built = await Bun.build({
    entrypoints: [fileURLToPath(source)],
    target: "node",
    format: "esm",
    define: { "import.meta.url": JSON.stringify(source.href) },
  });
  expect(built.success).toBe(true);
  const module = join(root, "deep-scan.mjs");
  await writeFile(module, await built.outputs[0]!.text());
  await promisify(execFile)("node", ["--test", module], {
    timeout: Number(process.env["CODEX_SECURITY_TEST_TIMEOUT_MS"] ?? "30000"),
    windowsHide: true,
  });
});
