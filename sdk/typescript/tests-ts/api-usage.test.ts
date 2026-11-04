import { afterEach, expect, mock, test } from "bun:test";
import { once } from "node:events";
import { appendFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { setImmediate } from "node:timers/promises";
import type { ThreadEvent } from "@openai/codex-sdk";
import { readScanBudgetUsage, ScanCostTracker } from "../src/cost.js";
import { ScanCostLimitExceededError } from "../src/errors.js";
import { copyCompletedScan } from "./plugin-root.js";
import {
  completedCodex,
  completedEvents,
  runEvents,
  scanRuntimeDependencies,
} from "./support/api-events.js";
import {
  measuredScanUsage,
  mockWorkbench,
  TestClient,
} from "./support/api-client.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import {
  ownedPythonUsage,
  ownedSdkUsage,
  writeSession,
} from "./support/usage-rollout.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

test.each([
  [false, null],
  [true, null],
  [false, undefined],
  [true, undefined],
] as const)(
  "preserves finalizer results (workbenchValidated=%p, result=%p)",
  async (workbenchValidated, finalizedUsage) => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const codexHome = await temporaryDirectory();
    await writeSession(
      codexHome,
      "worker-thread",
      {},
      {
        parent: "thread-1",
      },
    );
    const tracker = new ScanCostTracker({
      codexHome,
      model: "gpt-5.6-sol",
    });
    const result = await runEvents(scanDir, completedEvents(), {
      workbenchValidated,
      onThreadStarted: (threadId) => tracker.start(threadId),
      onFinalize: async (usage) => {
        const snapshot = await tracker.stop(usage);
        return finalizedUsage === null ? snapshot.usage : undefined;
      },
    });

    expect(result.toJSON()).toMatchObject({
      cost:
        finalizedUsage === null ? null : { inputTokens: 10, outputTokens: 3 },
      turn: {
        usage:
          finalizedUsage === null
            ? null
            : { input_tokens: 10, output_tokens: 3 },
        status: "completed",
      },
    });
  },
);

test.each([false, true])(
  "enforces measured spending with a missing worker after raising the limit: %p",
  async (raiseLimit) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "codex-home");
    const scanDir = join(root, "scan");
    await mkdir(repository);
    await mkdir(scanDir, { mode: 0o700 });
    await writeSession(
      codexHome,
      "pending-worker",
      {},
      {
        parent: "scan-thread",
      },
    );
    let measured = raiseLimit ? 900 : 3_000;
    const parent = await writeSession(codexHome, "scan-thread", {
      input_tokens: measured,
      output_tokens: 0,
    });
    const limitSaved = Promise.withResolvers<void>();
    const costs = mock();
    const usages = mock();
    const approaching = mock(() => 0.008);
    const client = TestClient.withDependencies({
      ...scanRuntimeDependencies(codexHome, scanDir),
      runWorkbench: async (_options, args, input) => {
        if (args[0] === "read-scan-usage") {
          return { ...measuredScanUsage(measured, 0, 0), coverage: "partial" };
        }
        if (args[0] === "set-scan-cost-limit") limitSaved.resolve();
        return mockWorkbench(args, input);
      },
      createCodex: () => ({
        startThread: () => ({
          id: null,
          runStreamed: async (_input, { signal }) => ({
            events: (async function* (): AsyncGenerator<ThreadEvent> {
              yield { type: "thread.started", thread_id: "scan-thread" };
              if (raiseLimit) {
                await limitSaved.promise;
                // Resume after the caller adopts the saved limit.
                await setImmediate();
                measured = 3_000;
                await appendFile(
                  parent,
                  JSON.stringify({
                    type: "event_msg",
                    payload: {
                      type: "token_count",
                      info: {
                        total_token_usage: {
                          input_tokens: 3_000,
                          output_tokens: 0,
                        },
                      },
                    },
                  }) + "\n",
                );
              }
              if (!signal?.aborted) await once(signal!, "abort");
              throw new DOMException("aborted", "AbortError");
            })(),
          }),
        }),
      }),
    });
    const keepAlive = setTimeout(() => {}, 10_000);
    try {
      await expect(
        client.run(repository, {
          maxCostUsd: 0.004,
          signal: AbortSignal.timeout(5_000),
          onCost: costs,
          onUsage: usages,
          ...(raiseLimit ? { onBudgetApproaching: approaching } : {}),
        }),
      ).rejects.toMatchObject({
        name: ScanCostLimitExceededError.name,
        maxCostUsd: raiseLimit ? 0.008 : 0.004,
        cost: { inputTokens: 3_000, estimatedUsd: 0.012 },
      });
      expect(costs).not.toHaveBeenCalled();
      expect(usages).not.toHaveBeenCalled();
      expect(approaching).toHaveBeenCalledTimes(raiseLimit ? 1 : 0);
    } finally {
      clearTimeout(keepAlive);
      await client.close();
    }
  },
);

test.each([false, true])(
  "completes with an unmeasured worker only when no budget was requested (budgeted=%p)",
  async (budgeted) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "codex-home");
    const scanDir = join(root, "scan");
    await mkdir(repository);
    await writeSession(codexHome, "worker", {}, { parent: "thread-1" });
    const commands: string[] = [];
    const client = TestClient.withDependencies({
      ...scanRuntimeDependencies(codexHome, scanDir),
      createCodex: completedCodex(root),
      runWorkbench: async (_options, args, input) => {
        commands.push(args[0]!);
        if (args[0] === "read-scan-usage") {
          expect(args).toEqual([
            "read-scan-usage",
            "--scan-id",
            "scan_example_001",
            "--thread-id",
            "thread-1",
          ]);
          return { coverage: "partial", missingThreadCount: 1 };
        }
        return mockWorkbench(args, input);
      },
    });
    try {
      // The completed parent supplies a receipt; its worker supplies none.
      const run = client.run(repository, budgeted ? { maxCostUsd: 1 } : {});
      if (budgeted) {
        await expect(run).rejects.toThrow(/cost limit|usage/i);
        expect(commands).not.toContain("prepare-scan-completion");
        expect(commands).toContain("fail-scan");
      } else {
        expect((await run).cost).toBeNull();
      }
      expect(commands.includes("complete-scan")).toBe(!budgeted);
    } finally {
      await client.close();
    }
  },
);

test("a direct scan needs measured workers in addition to its control thread", async () => {
  let workerCount = 0;
  const workbench = async () => ({
    ...ownedPythonUsage,
    coverage: "complete",
    byRole: { workers: { threadCount: workerCount } },
  });
  const read = () =>
    readScanBudgetUsage(workbench, "scan", "controller", undefined, true);
  expect((await read()).complete).toBe(false);
  workerCount = 1;
  expect(await read()).toEqual({
    complete: true,
    usage: { ...ownedSdkUsage, cache_write_input_tokens_reported: false },
  });
});

test("a worker-shaped directory alone cannot exhaust a scan budget", async () => {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const scanDir = join(root, "scan");
  const codexHome = join(root, "codex-home");
  await mkdir(repository);
  await writeSession(
    codexHome,
    "thread-1",
    { input_tokens: 10, output_tokens: 3 },
    {
      cwd: scanDir,
      timestamp: "2026-07-26T10:00:00Z",
    },
  );
  await writeSession(
    codexHome,
    "unrelated",
    { input_tokens: 1_000_000, output_tokens: 0 },
    {
      cwd: join(
        scanDir,
        "artifacts",
        "deep_discovery",
        "workers",
        "other",
        "output",
      ),
      timestamp: "2026-07-26T10:00:01Z",
    },
  );
  const client = TestClient.withDependencies({
    ...scanRuntimeDependencies(codexHome, scanDir),
    createCodex: completedCodex(root),
  });
  try {
    const result = await client.run(repository, { maxCostUsd: 1 });
    expect(result.cost).toMatchObject({ inputTokens: 10, outputTokens: 3 });
  } finally {
    await client.close();
  }
});
