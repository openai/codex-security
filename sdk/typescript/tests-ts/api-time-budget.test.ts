import { mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { ThreadEvent, TurnOptions } from "@openai/codex-sdk";
import { afterEach, expect, mock, test } from "bun:test";
import { ScanInterruptedError } from "../src/errors.js";
import { copyCompletedScan } from "./plugin-root.js";
import { mockWorkbench, TestClient } from "./support/api-client.js";
import {
  codexFactory,
  completedEvents,
  scanRuntimeDependencies,
} from "./support/api-events.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { cleanup, temporaryDirectory } = createApiTestFixtures();
afterEach(cleanup);

test("rejects an unrepresentable deadline before scan setup", async () => {
  const maxTimeMinutes = 1e12;
  const repository = await temporaryDirectory();
  const prepareRuntime = mock(async () => {
    throw new Error("Unexpected runtime preparation");
  });
  const createCodex = mock(() => {
    throw new Error("Unexpected model preparation");
  });
  const runWorkbench = mock(async () => ({}));
  const now = mock(() => Date.UTC(2026, 0, 1));
  await using client = TestClient.withDependencies({
    prepareRuntime,
    createCodex,
    runWorkbench,
    now,
  });
  await expect(
    client.preflight(repository, { maxTimeMinutes }),
  ).rejects.toThrow("deadline within the supported date range");
  await expect(client.run(repository, { maxTimeMinutes })).rejects.toThrow(
    "deadline within the supported date range",
  );
  expect(prepareRuntime).not.toHaveBeenCalled();
  expect(createCodex).not.toHaveBeenCalled();
  expect(runWorkbench).not.toHaveBeenCalled();
  expect(now).not.toHaveBeenCalled();
});

async function fixture(start = Date.UTC(2026, 0, 1)) {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const codexHome = join(root, "home");
  const scanDir = join(root, "scan");
  await Promise.all([
    mkdir(repository),
    mkdir(codexHome),
    mkdir(scanDir, { mode: 0o700 }),
  ]);
  let clock = start;
  let clockReads = 0;
  const prompts: string[] = [];
  const commands: string[] = [];
  const recipes: Record<string, unknown>[] = [];
  let finish: (options: TurnOptions) => Promise<void> = async () => {};
  const client = TestClient.withDependencies({
    ...scanRuntimeDependencies(codexHome, scanDir),
    now: () => {
      clockReads += 1;
      return clock;
    },
    runWorkbench: async (_options, args, input) => {
      commands.push(args[0]!);
      if (args[0] === "register-cli-scan") {
        recipes.push(JSON.parse(input!).recipe);
      }
      if (args[0] === "get-scan-feedback") clock += 60_000;
      if (args[0] === "list-scans") return { scans: [] };
      if (args[0] === "get-scan")
        return { scan: { progress: { status: "running" } } };
      return mockWorkbench(args, input);
    },
    createCodex: codexFactory(async (prompt: string, options: TurnOptions) => {
      prompts.push(prompt);
      await finish(options);
      await copyCompletedScan(root);
      async function* events(): AsyncGenerator<ThreadEvent> {
        yield { type: "error", message: "Reconnecting... 1/5" };
        yield* completedEvents();
      }
      return { events: events() };
    }),
  });
  return {
    client,
    repository,
    prompts,
    commands,
    recipes,
    get clockReads() {
      return clockReads;
    },
    setFinish(callback: typeof finish) {
      finish = callback;
    },
    advance(milliseconds: number) {
      clock += milliseconds;
    },
  };
}

test.each([1_000, 400_000])(
  "Standard starts its advisory clock after setup and finalizes after %d ms without a timer or extra turn",
  async (duration) => {
    const state = await fixture();
    await using client = state.client;
    state.setFinish(async (options) => {
      state.advance(duration);
      expect(options.signal?.aborted).toBe(false);
    });
    const reconnects: number[] = [];
    const result = await client.run(state.repository, {
      maxTimeMinutes: 5,
      onReconnect: (attempt) => reconnects.push(attempt),
    });
    expect(state.prompts).toHaveLength(1);
    expect(state.prompts[0]).toContain("2026-01-01T00:01:00.000Z");
    expect(state.prompts[0]).toContain("2026-01-01T00:06:00.000Z");
    expect(state.clockReads).toBe(1);
    expect(reconnects).toEqual([1]);
    expect(state.commands).toContain("prepare-scan-completion");
    expect(state.commands).toContain("complete-scan");
    expect(state.commands).not.toContain("fail-scan");
    expect(await readFile(result.reportPath, "utf8")).toContain("Scan report");
    expect(result.turnResult.usage).toMatchObject({ input_tokens: 10 });
    expect(state.recipes[0]).toHaveProperty("maxTimeMinutes", 5);
    expect(JSON.stringify(state.recipes[0])).not.toContain("deadlineAt");
  },
);

test("omitted budget preserves the base prompt and post-scan instructions", async () => {
  const state = await fixture();
  await using client = state.client;
  await client.run(state.repository);
  const baseline = state.prompts[0];
  expect(state.clockReads).toBe(0);
  expect(state.recipes[0]).not.toHaveProperty("maxTimeMinutes");
  await client.run(state.repository, {
    maxTimeMinutes: 5,
    postScanPrompt: "Summarize the completed scan.",
  });
  expect(state.prompts[1]).toStartWith(`${baseline}\n\n`);
  expect(state.prompts[1]).toContain("2026-01-01T00:07:00.000Z");
  expect(state.prompts[2]).toEndWith("\n\nSummarize the completed scan.");
  expect(state.prompts[2]).not.toContain("2026-01-01T00:07:00.000Z");
});

test("concurrent clients keep independent deadlines and reruns get a fresh deadline", async () => {
  const first = await fixture(Date.UTC(2026, 0, 1));
  const second = await fixture(Date.UTC(2026, 0, 2));
  await using firstClient = first.client;
  await using secondClient = second.client;
  await Promise.all([
    firstClient.run(first.repository, { maxTimeMinutes: 5 }),
    secondClient.run(second.repository, { maxTimeMinutes: 10 }),
  ]);
  expect(first.prompts[0]).toContain("2026-01-01T00:06:00.000Z");
  expect(second.prompts[0]).toContain("2026-01-02T00:11:00.000Z");
  first.advance(3_600_000);
  await firstClient.run(first.repository, {
    maxTimeMinutes: first.recipes[0]!["maxTimeMinutes"] as number,
  });
  expect(first.prompts[1]).toContain("2026-01-01T01:07:00.000Z");
  expect(first.prompts[1]).not.toContain("2026-01-01T00:06:00.000Z");
});

test("explicit cancellation remains authoritative with an advisory allowance", async () => {
  const state = await fixture();
  await using client = state.client;
  const controller = new AbortController();
  state.setFinish(async (options) => {
    controller.abort();
    options.signal!.throwIfAborted();
  });
  await expect(
    client.run(state.repository, {
      maxTimeMinutes: 5,
      signal: controller.signal,
    }),
  ).rejects.toBeInstanceOf(ScanInterruptedError);
  expect(state.commands).toContain("cancel-scan");
  expect(state.commands).not.toContain("fail-scan");
  expect(state.commands).not.toContain("complete-scan");
});

test("preflight exposes the effective Deep limit in minutes and leaves Standard unset", async () => {
  const state = await fixture();
  await using client = state.client;
  expect(await client.preflight(state.repository)).not.toHaveProperty(
    "maxTimeMinutes",
  );
  expect(
    await client.preflight(state.repository, {
      mode: "deep",
      maxTimeHours: 1.5,
    }),
  ).toMatchObject({
    maxTimeMinutes: 90,
    maxTimeHours: 1.5,
  });
});

test("Deep stores its converted hard limit without adding the Standard advisory policy", async () => {
  const state = await fixture();
  await using client = state.client;
  state.setFinish(async () => {
    throw new Error("Captured Deep launch");
  });
  await expect(
    client.run(state.repository, {
      mode: "deep",
      maxTimeMinutes: 90,
      workers: 1,
      subagents: 0,
      maxDiscoveryRuns: 1,
      stopAfterConsecutiveErrors: 1,
    }),
  ).rejects.toThrow("Deep Scan reached its consecutive error limit.");
  expect(state.clockReads).toBe(0);
  expect(state.prompts).toHaveLength(1);
  expect(state.prompts[0]).not.toContain("2026-01-01T00:01:00.000Z");
  expect(state.recipes[0]).toMatchObject({
    maxTimeMinutes: 90,
    deepScan: { maxTimeHours: 1.5 },
  });
});
