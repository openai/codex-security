import { afterEach, expect, mock, test } from "bun:test";
import { once } from "node:events";
import { appendFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { setImmediate } from "node:timers/promises";
import type { ThreadEvent } from "@openai/codex-sdk";
import { ScanCostTracker } from "../src/cost.js";
import { ScanCostLimitExceededError } from "../src/errors.js";
import { copyCompletedScan } from "./plugin-root.js";
import {
  completedEvents,
  runEvents,
  scanRuntimeDependencies,
} from "./support/api-events.js";
import { mockWorkbench, TestClient } from "./support/api-client.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { writeSession } from "./support/usage-rollout.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

test.each([null, undefined])(
  "preserves finalizer usage result %p",
  async (finalizedUsage) => {
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
      onThreadStarted: (threadId) => tracker.start(threadId),
      onFinalize: async (usage) => {
        const snapshot = await tracker.stop(usage);
        return finalizedUsage === null ? snapshot.usage : undefined;
      },
    });

    expect(result).toMatchObject({
      turnResult: {
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
    const parent = await writeSession(codexHome, "scan-thread", {
      input_tokens: raiseLimit ? 900 : 3_000,
      output_tokens: 0,
    });
    const limitSaved = Promise.withResolvers<void>();
    const costs = mock();
    const usages = mock();
    const approaching = mock(() => 0.008);
    const client = TestClient.withDependencies({
      ...scanRuntimeDependencies(codexHome, scanDir),
      runWorkbench: async (_options, args, input) => {
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
