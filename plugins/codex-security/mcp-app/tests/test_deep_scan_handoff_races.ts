import assert from "node:assert/strict";
import { mock, test } from "node:test";
import { Thread } from "@openai/codex-sdk";
import type {
  CodexWorkerRequest,
  DeepScanRunState,
  DeepScanWorkerMutation,
} from "../src/deep-scan/types.js";
import type { DeepScanCoordinator } from "../src/deep-scan/coordinator.js";
import {
  DeepScanCoordinatorRegistry,
  WorkbenchDeepScanStore,
  fixtureRun,
  temporaryDirectories,
} from "./deep_scan_coordinator_fixture.ts";

try {
  for (const scenario of [
    "deadline",
    "concurrent",
    "user cancellation",
    "terminal state",
    "ordinary failure",
  ] as const) {
    await test(`preserves coordinator authority through ${scenario}`, async () => {
      const concurrent = scenario === "concurrent";
      const fixture = await fixtureRun({
        workers: concurrent ? 2 : 1,
        maxDiscoveryRuns: concurrent ? 2 : 1,
      });
      const run = { ...fixture.run, coordinatorGeneration: 2 };
      const replacement: DeepScanRunState =
        scenario === "terminal state"
          ? { ...run, status: "succeeded", terminalReason: "capped" }
          : { ...run, coordinatorGeneration: 3 };
      const diagnostic =
        scenario === "ordinary failure"
          ? "Permission denied: /fixture/Deep Scan coordinator lease belongs to a newer generation./lock\nSynthetic diagnostic detail."
          : "Deep Scan coordinator lease belongs to a newer generation.";
      let reads = 0;
      let failureWrites = 0;
      let metadataMutations = 0;
      let queuedFailureSeen = false;
      const workers = new Map<string, Record<string, unknown>>();
      const store = new WorkbenchDeepScanStore(async (args: string[]) => {
        const value = (flag: string) => args[args.indexOf(flag) + 1];
        switch (args[0]) {
          case "claim-deep-scan-coordinator":
            return { deepScan: run, coordinatorDisposition: "claimed" };
          case "update-progress":
            return { deepScan: run };
          case "upsert-deep-scan-worker": {
            if (
              args.includes("--sdk-thread-id") ||
              (concurrent && metadataMutations > 0)
            ) {
              if (
                args.includes("--sdk-thread-id") &&
                value("--status") === "running"
              )
                metadataMutations += 1;
              else if (concurrent && !args.includes("--sdk-thread-id"))
                queuedFailureSeen = true;
              throw new Error(diagnostic);
            }
            workers.set(value("--worker-id"), {
              id: value("--worker-id"),
              kind: "discovery",
              status: value("--status"),
              mergeState: "none",
              promptPath: value("--prompt-path"),
              artifactDir: value("--artifact-dir"),
              attempt: 1,
            });
            return { deepScan: { ...run, workers: [...workers.values()] } };
          }
          case "get-deep-scan":
            reads += 1;
            if (reads === (scenario === "ordinary failure" ? 1 : 2))
              throw new Error("sqlite3.OperationalError: database is locked");
            return {
              deepScan:
                scenario === "ordinary failure"
                  ? run
                  : reads === 1
                    ? replacement
                    : {
                        ...replacement,
                        status: "succeeded",
                        terminalReason: "capped",
                      },
            };
          case "fail-deep-scan":
            failureWrites += 1;
            if (scenario !== "ordinary failure")
              throw new Error(
                "Deep Scan mutation requires the current coordinator lease.",
              );
            return {
              deepScan: {
                ...run,
                status: "failed",
                error: args
                  .find((arg) => arg.startsWith("--message="))!
                  .slice("--message=".length),
              },
            };
          default:
            throw new Error(`Unexpected fixture operation: ${args[0]}`);
        }
      });
      await store.claimCoordinator({
        scanId: run.scanId,
        threadId: "fixture-owner",
      });
      const secondQueued = Promise.withResolvers<void>();
      const firstMetadata = Promise.withResolvers<void>();
      const updateWorker = store.updateWorker.bind(store);
      let queued = 0;
      store.updateWorker = async (update: DeepScanWorkerMutation) => {
        if (concurrent && update.status === "queued" && ++queued === 2) {
          secondQueued.resolve();
          await firstMetadata.promise;
        }
        return updateWorker(update);
      };
      const executorErrors: Error[] = [];
      let executions = 0;
      let coordinator: DeepScanCoordinator;
      const executor = {
        async run(request: CodexWorkerRequest): Promise<never> {
          const sequence = ++executions;
          if (concurrent) await secondQueued.promise;
          // Only the process event source is synthetic; SDK iterator cleanup is real.
          const thread: Thread = Reflect.construct(Thread, [
            {
              async *run() {
                yield JSON.stringify({
                  type: "thread.started",
                  thread_id: `fixture-worker-${sequence}`,
                });
              },
            },
            {},
            {},
          ]);
          try {
            const { events } = await thread.runStreamed("Synthetic worker");
            for await (const event of events) {
              assert.equal(event.type, "thread.started");
              if (event.type !== "thread.started") continue;
              const mutation = request.onThreadStarted!(event.thread_id);
              if (sequence === 1) firstMetadata.resolve();
              await mutation;
            }
          } catch (error) {
            assert.ok(error instanceof Error);
            executorErrors.push(error);
            if (scenario === "deadline") {
              mock.timers.tick(1);
              assert.equal(request.signal.aborted, true);
              mock.timers.reset();
            } else if (scenario === "user cancellation") {
              coordinator.cancel("Synthetic user cancellation.");
            }
            throw error;
          }
          throw new Error("The synthetic metadata mutation must reject.");
        },
      };
      if (scenario === "deadline") mock.timers.enable({ apis: ["setTimeout"] });
      try {
        coordinator = new DeepScanCoordinatorRegistry().start({
          run,
          store,
          executor,
          pluginRoot: fixture.pluginRoot,
          threadId: "fixture-owner",
          heartbeatIntervalMs: 60_000,
          discoveryTimeoutMs: scenario === "deadline" ? 1 : 60_000,
          retryDelaysMs: [],
        });
        const terminal = await coordinator.wait(undefined, 5_000);
        assert.equal(
          terminal?.status,
          scenario === "user cancellation"
            ? "canceled"
            : scenario === "ordinary failure"
              ? "failed"
              : "succeeded",
        );
        assert.equal(
          terminal?.coordinatorGeneration,
          ["terminal state", "user cancellation", "ordinary failure"].includes(
            scenario,
          )
            ? 2
            : 3,
        );
        assert.equal(failureWrites, scenario === "ordinary failure" ? 1 : 0);
        if (scenario === "ordinary failure") {
          assert.ok(terminal?.error?.includes(diagnostic));
          assert.equal(
            reads,
            2,
            "diagnostic text must not establish ownership loss",
          );
        } else {
          assert.equal(
            reads,
            ["terminal state", "user cancellation"].includes(scenario) ? 1 : 3,
          );
          if (concurrent) {
            assert.equal(queuedFailureSeen, true);
            assert.equal(executions, 1);
            assert.equal(metadataMutations, 1);
            assert.equal(executorErrors.length, 1);
            assert.equal(
              executorErrors[0].name,
              "DeepScanOwnershipChangedError",
            );
          }
        }
      } finally {
        mock.timers.reset();
      }
    });
  }
} finally {
  await temporaryDirectories.cleanup();
}
