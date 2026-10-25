import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { afterEach, expect, spyOn, test } from "bun:test";
import { runWorkbench } from "../src/runtime.js";
import * as runtime from "../src/runtime.js";
import * as ownerArtifacts from "../src/scan-owner-suggestions.js";
import { copyCompletedScan } from "./plugin-root.js";
import {
  mockScanRegistration,
  mockWorkbench,
  TestClient,
} from "./support/api-client.js";
import {
  codexFactory,
  completedEvents,
  scanRuntimeDependencies,
} from "./support/api-events.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { FindingWorkflow } from "../src/finding-workflow.js";
import { readKnowledgeBaseSnapshot } from "../src/knowledge-base.js";
import { DEFAULT_DEEP_SCAN_SETTINGS } from "../src/deep-scan-defaults.js";

const { cleanup, temporaryDirectory } = createApiTestFixtures();
afterEach(cleanup);

test.each([
  "completed",
  "receipt-lost",
  "scan-interrupted",
  "prompt-files",
  "knowledge-snapshot",
  "legacy-knowledge",
  "owner-success",
  "owner-failure",
  "owner-success-receipt-lost",
  "owner-failure-receipt-lost",
])(
  "durable scan workflow resumes after %s without rerunning completed work",
  async (scenario) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const scanDir = join(root, "scan");
    await mkdir(repository);
    await mkdir(scanDir, { mode: 0o700 });
    const environment = {
      PATH: process.env["PATH"],
      SystemRoot: process.env["SystemRoot"],
      TEMP: process.env["TEMP"],
      TMP: process.env["TMP"],
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
    };
    const workflowId = "durable-scan";
    const scanPrompt = "Review synthetic authentication boundaries.";
    const promptFile = join(root, "instructions.md");
    const knowledge =
      scenario === "knowledge-snapshot" || scenario === "legacy-knowledge";
    if (scenario === "prompt-files" || knowledge)
      await writeFile(promptFile, scanPrompt);
    const knowledgeOptions = knowledge
      ? {
          knowledgeBasePaths: [promptFile],
          ...(scenario === "knowledge-snapshot"
            ? {
                knowledgeBaseSnapshot: await readKnowledgeBaseSnapshot([
                  promptFile,
                ]),
              }
            : {}),
        }
      : {};
    const ownerScenario = scenario.startsWith("owner-");
    const ownerFailure = scenario.startsWith("owner-failure");
    const receiptLost = scenario.endsWith("receipt-lost");
    const ownerPath = join(scanDir, "owner-suggestions.json");
    const ownerSpy = ownerScenario
      ? spyOn(ownerArtifacts, "writeScanOwnerSuggestions").mockImplementation(
          async () => {
            if (ownerFailure) throw new Error("Synthetic owner failure");
            await writeFile(ownerPath, "{}\n");
            return ownerPath;
          },
        )
      : undefined;
    let modelCalls = 0;
    let completed = false;
    let loseReceipt = receiptLost;
    const makeClient = async (attempt: number) => {
      const codexHome = join(root, `codex-home-${attempt}`);
      await mkdir(codexHome);
      return TestClient.withDependencies({
        environment,
        ...scanRuntimeDependencies(codexHome, scanDir),
        runWorkbench: async (options, args, input) => {
          if (args[0] === "finding-workflow") {
            const payload = JSON.parse(input!);
            if (
              loseReceipt &&
              payload.action === "complete" &&
              payload.stage === "scan"
            ) {
              loseReceipt = false;
              throw new Error("Synthetic receipt write failure");
            }
            const state = await runWorkbench(options, args, input);
            if (scenario === "prompt-files" && payload.action === "begin")
              await rm(promptFile);
            return state;
          }
          if (args[0] === "get-scan")
            return {
              scan: {
                progress: { status: completed ? "complete" : "failed" },
                continuationThreadId: "thread-1",
              },
            };
          if (args[0] === "register-cli-scan") {
            expect(JSON.parse(input!).workflowId).toBe(workflowId);
            expect(JSON.parse(input!).recipe.ownerSuggestions).toBe(
              ownerScenario || undefined,
            );
            const registration = mockScanRegistration(args, input);
            await new FindingWorkflow(workflowId, environment).bind({
              scanId: registration["scanId"] as string,
              scanDir,
            });
            return registration;
          }
          if (args[0] === "complete-scan") completed = true;
          return mockWorkbench(args, input);
        },
        createCodex: codexFactory(async (input: string) => {
          modelCalls++;
          if (scenario === "prompt-files") expect(input).toContain(scanPrompt);
          if (scenario === "scan-interrupted" && modelCalls === 1)
            throw new Error("Synthetic interrupted scan");
          await copyCompletedScan(root);
          return { events: completedEvents() };
        }, "thread-1"),
      });
    };
    const first = await makeClient(1);
    let original: Record<string, unknown> | undefined;
    try {
      const options = {
        workflowId,
        ...knowledgeOptions,
        ownerSuggestions: ownerScenario || undefined,
        ...(scenario === "prompt-files" ? { scanPromptFile: promptFile } : {}),
      };
      if (receiptLost || scenario === "scan-interrupted")
        await expect(first.run(repository, options)).rejects.toThrow(
          "Synthetic",
        );
      else original = (await first.run(repository, options)).toJSON();
    } finally {
      await first.close();
    }
    const resumed = await makeClient(2);
    const python = spyOn(runtime, "resolvePluginPython");
    try {
      const replacement = join(root, "replacement-instructions.md");
      if (scenario === "prompt-files") await writeFile(replacement, scanPrompt);
      const result = await resumed.run(repository, {
        workflowId,
        ...knowledgeOptions,
        ...(scenario === "knowledge-snapshot"
          ? {
              knowledgeBaseSnapshot: await readKnowledgeBaseSnapshot([
                promptFile,
              ]),
            }
          : {}),
        ownerSuggestions: ownerScenario || undefined,
        ...(scenario === "prompt-files" ? { scanPromptFile: replacement } : {}),
      });
      expect(result.manifest.scan.id).toBe("scan_example_001");
      expect(python).toHaveBeenCalledWith(
        expect.objectContaining({ protectedRoot: repository }),
      );
      if (original) expect(result.toJSON()).toEqual(original);
      if (ownerScenario) {
        expect(ownerSpy).toHaveBeenCalledTimes(1);
        expect(result.ownerSuggestionsPath).toBe(
          ownerFailure ? undefined : ownerPath,
        );
        expect(result.ownerSuggestionsError).toBe(
          ownerFailure ? "Synthetic owner failure" : undefined,
        );
        if (!ownerFailure)
          expect(await readFile(ownerPath, "utf8")).toBe("{}\n");
      }
      expect(modelCalls).toBe(scenario === "scan-interrupted" ? 2 : 1);
      expect(
        (await new FindingWorkflow(workflowId, environment).get())?.stages.scan
          .status,
      ).toBe("completed");
      await expect(
        resumed.run(repository, { workflowId, mode: "deep" }),
      ).rejects.toThrow("already bound to a different");
      if (knowledge) {
        if (scenario === "knowledge-snapshot")
          await writeFile(promptFile, "Changed synthetic project guidance.");
        await expect(
          resumed.run(repository, {
            workflowId,
            knowledgeBasePaths: [promptFile],
            knowledgeBaseSnapshot: await readKnowledgeBaseSnapshot([
              promptFile,
            ]),
          }),
        ).rejects.toThrow("Use another --workflow-id.");
        expect(modelCalls).toBe(1);
      }
    } finally {
      python.mockRestore();
      await resumed.close();
      ownerSpy?.mockRestore();
    }
  },
);

test.each(["ambient settings", "shipped defaults"])(
  "a deep workflow can resume after changing %s but rejects a different request",
  async (change) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "codex-home");
    const source = join(codexHome, "codex-security", "config.toml");
    await mkdir(repository);
    await mkdir(dirname(source), { recursive: true });
    await writeFile(source, "[deep_scan]\nsubagents = 1\n");
    const environment = {
      PATH: process.env["PATH"],
      SystemRoot: process.env["SystemRoot"],
      CODEX_HOME: codexHome,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
    };
    const client = TestClient.withDependencies({
      environment,
      runWorkbench: async (options, args, input) => {
        if (
          args[0] === "finding-workflow" &&
          JSON.parse(input!).action === "begin"
        ) {
          throw new Error("Synthetic stop before scan");
        }
        return runWorkbench(options, args, input);
      },
    });
    const defaults = DEFAULT_DEEP_SCAN_SETTINGS as { workers: number };
    const originalWorkers = defaults.workers;
    const request = { workflowId: "deep-resume", mode: "deep" } as const;
    try {
      await expect(client.run(repository, request)).rejects.toThrow(
        "Synthetic stop before scan",
      );
      if (change === "ambient settings")
        await writeFile(source, "[deep_scan]\nworkers = 9\nsubagents = 2\n");
      else defaults.workers = originalWorkers + 1;
      await expect(client.run(repository, request)).rejects.toThrow(
        "Synthetic stop before scan",
      );
      await expect(
        client.run(repository, { ...request, workers: 2 }),
      ).rejects.toThrow("already bound to a different");
    } finally {
      defaults.workers = originalWorkers;
      await client.close();
    }
  },
);
