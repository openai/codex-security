import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import type { ThreadEvent, TurnOptions } from "@openai/codex-sdk";
import { afterEach, expect, mock, test } from "bun:test";
import type { JsonObject } from "../src/config.js";
import { CodexSecurityError, ScanPolicyRefusalError } from "../src/index.js";
import { TestClient, mockWorkbench } from "./support/api-client.js";
import { codexFactory, preparedRuntime } from "./support/api-events.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const fixtures = createApiTestFixtures();
afterEach(fixtures.cleanup);

// The exact refusal string from openai/codex-security#56.
const POLICY_REFUSAL =
  "This content was flagged for possible cybersecurity risk. If this seems wrong, try rephrasing your request. To get authorized for security work, join the Trusted Access for Cyber program: https://chatgpt.com/cyber";

async function* scanEvents(
  failureMessage: string,
): AsyncGenerator<ThreadEvent> {
  yield { type: "thread.started", thread_id: "thread-1" };
  yield { type: "turn.started" };
  yield {
    type: "item.completed",
    item: {
      id: "worker-1",
      type: "agent_message",
      text: 'CODEX_SECURITY_WORKER_STATUS {"phase":"validation","planned":1,"started":1}',
    },
  };
  yield { type: "turn.failed", error: { message: failureMessage } };
}

async function runRefusedScan(failureMessage: string) {
  const root = await fixtures.temporaryDirectory();
  const repository = join(root, "repository");
  const codexHome = join(root, "codex-home");
  const scanDir = join(root, "scan");
  await mkdir(repository);
  await mkdir(codexHome);
  await mkdir(scanDir, { mode: 0o700 });
  const runtime = {
    ...preparedRuntime(codexHome),
    configPath: join(root, "runtime.toml"),
    environment: { OPENAI_API_KEY: "synthetic-api-key" },
  };
  const workbenchCalls: Array<readonly string[]> = [];
  const runStreamed = mock(async (_input: string, _options: TurnOptions) => {
    return { events: scanEvents(failureMessage) };
  });
  const client = new TestClient(
    { codexOverrides: {} },
    {
      environment: { OPENAI_API_KEY: "synthetic-api-key" },
      prepareRuntime: async () => runtime,
      resolvePluginPython: async () =>
        Bun.which("python3") ?? Bun.which("python")!,
      prepareOutputDir: async () => scanDir,
      repositoryRevision: async () => "deadbeef",
      runWorkbench: async (_options, args, input) => {
        workbenchCalls.push(args);
        if (args[0] === "get-scan") {
          return {
            scan: {
              reportAvailable: true,
              progress: { status: "failed" },
            },
          } as unknown as JsonObject;
        }
        return mockWorkbench(args, input);
      },
      createCodex: () => codexFactory(runStreamed)(),
    },
  );
  let thrown: unknown;
  try {
    await client.run(repository, { auth: "api-key" });
  } catch (error) {
    thrown = error;
  } finally {
    await client.close();
  }
  return { thrown, workbenchCalls, scanDir };
}

function workbenchCall(
  calls: Array<readonly string[]>,
  command: string,
): readonly string[] | undefined {
  return calls.find((args) => args[0] === command);
}

test("preserves a refused Standard scan as an incomplete bundle", async () => {
  const { thrown, workbenchCalls, scanDir } =
    await runRefusedScan(POLICY_REFUSAL);

  expect(thrown).toBeInstanceOf(ScanPolicyRefusalError);
  const refusal = thrown as ScanPolicyRefusalError;
  expect(refusal.message).toContain(POLICY_REFUSAL);
  expect(refusal.message).toContain("validation");
  expect(refusal.message).toContain("incomplete bundle");
  expect(refusal.message).toContain(scanDir);
  expect(refusal.scanDir).toBe(scanDir);
  expect(refusal.phase).toBe("validation");
  expect(refusal.bundlePreserved).toBe(true);

  const updateProgress = workbenchCall(workbenchCalls, "update-progress");
  const failScan = workbenchCall(workbenchCalls, "fail-scan");
  expect(updateProgress).toBeDefined();
  expect(updateProgress).toContain("--phase");
  expect(updateProgress).toContain("validation");
  expect(failScan).toBeDefined();
  expect(failScan?.join(" ")).toContain(POLICY_REFUSAL);
  expect(workbenchCalls.indexOf(updateProgress!)).toBeLessThan(
    workbenchCalls.indexOf(failScan!),
  );
});

test("reports no preserved bundle when the workbench has none", async () => {
  const root = await fixtures.temporaryDirectory();
  const repository = join(root, "repository");
  const codexHome = join(root, "codex-home");
  const scanDir = join(root, "scan");
  await mkdir(repository);
  await mkdir(codexHome);
  await mkdir(scanDir, { mode: 0o700 });
  const runtime = {
    ...preparedRuntime(codexHome),
    configPath: join(root, "runtime.toml"),
    environment: { OPENAI_API_KEY: "synthetic-api-key" },
  };
  const runStreamed = mock(async (_input: string, _options: TurnOptions) => {
    return { events: scanEvents(POLICY_REFUSAL) };
  });
  const client = new TestClient(
    { codexOverrides: {} },
    {
      environment: { OPENAI_API_KEY: "synthetic-api-key" },
      prepareRuntime: async () => runtime,
      resolvePluginPython: async () =>
        Bun.which("python3") ?? Bun.which("python")!,
      prepareOutputDir: async () => scanDir,
      repositoryRevision: async () => "deadbeef",
      runWorkbench: async (_options, args, input) => mockWorkbench(args, input),
      createCodex: () => codexFactory(runStreamed)(),
    },
  );
  let thrown: unknown;
  try {
    await client.run(repository, { auth: "api-key" });
  } catch (error) {
    thrown = error;
  } finally {
    await client.close();
  }
  expect(thrown).toBeInstanceOf(ScanPolicyRefusalError);
  const refusal = thrown as ScanPolicyRefusalError;
  expect(refusal.bundlePreserved).toBe(false);
  expect(refusal.message).toContain(
    "No completed scan work could be preserved",
  );
});

test("keeps non-refusal turn failures on the generic failure path", async () => {
  const { thrown, workbenchCalls } = await runRefusedScan(
    "retry budget exhausted",
  );

  expect(thrown).toBeInstanceOf(CodexSecurityError);
  expect(thrown).not.toBeInstanceOf(ScanPolicyRefusalError);
  expect(workbenchCall(workbenchCalls, "update-progress")).toBeUndefined();
  expect(workbenchCall(workbenchCalls, "fail-scan")).toBeDefined();
});
