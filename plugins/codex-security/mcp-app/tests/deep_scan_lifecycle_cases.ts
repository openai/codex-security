import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import type { DeepScanRunState } from "../src/deep-scan/types.js";

type LifecycleFixtures = Pick<
  typeof import("./deep_scan_coordinator_fixture.ts"),
  | "fixtureRun"
  | "FakeStore"
  | "FakeExecutor"
  | "createCoordinator"
  | "DeepScanCoordinatorRegistry"
  | "immediateClock"
>;

export async function testDeepScanLifecycle({
  fixtureRun,
  FakeStore,
  FakeExecutor,
  createCoordinator,
  DeepScanCoordinatorRegistry,
  immediateClock,
}: LifecycleFixtures) {
  const config = {
    workers: 1,
    subagents: 0,
    stopAfterNoNew: 1,
    maxDiscoveryRuns: 1,
  };
  const errors = [];
  for (const test of [
    canceledPublicationWaitsForHeartbeat,
    delayedReducerDoesNotReplaceStoppedState,
    replacementWaitsForTerminalResult,
    concurrentOwnershipReadsKeepReplacementResult,
    lateFailurePersistenceKeepsStoppedState,
    shutdownStopsReplacementObservation,
    failedCancellationStillPreservesResults,
    lateCancellationKeepsPersistedFailure,
    terminalDiscoveryWaitsForCleanup,
    orphanWorkerDirectoriesAreNotReused,
    ancestorNamesDoNotChooseWorkerSequence,
  ]) {
    try {
      await test();
    } catch (error) {
      errors.push(new Error(test.name, { cause: error }));
    }
  }
  if (errors.length)
    throw new AggregateError(errors, "Deep Scan lifecycle regressions");

  async function canceledPublicationWaitsForHeartbeat() {
    const fixture = await fixtureRun(config);
    fixture.run.coordinatorGeneration = 1;
    const store = new FakeStore(fixture.run);
    const executor = new FakeExecutor({ blockDiscoveryAfterCalls: 0 });
    const publishing = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    const coordinator = createCoordinator(fixture, store, executor, {
      threadId: "fixture-owner",
      heartbeatIntervalMs: 60_000,
      onStopped: async () => {
        publishing.resolve();
        await release.promise;
      },
    });
    coordinator.start();
    await executor.discoveryStarted.promise;
    store.run.status = "canceled";
    coordinator.cancel("fixture cancellation");
    await publishing.promise;
    try {
      await coordinator.renewHeartbeat();
      assert.equal(
        await coordinator.wait(undefined, 0),
        undefined,
        "heartbeat must not release waiters while saved results are being published",
      );
    } finally {
      release.resolve();
      await coordinator.settled();
    }
  }

  async function delayedReducerDoesNotReplaceStoppedState() {
    for (const status of ["canceled", "failed"] as const) {
      const fixture = await fixtureRun(config);
      fixture.run.coordinatorGeneration = 1;
      const store = new FakeStore(fixture.run);
      const committed = Promise.withResolvers<void>();
      const release = Promise.withResolvers<void>();
      const commit = store.commitDedup.bind(store);
      store.commitDedup = async (input) => {
        const response = await commit(input);
        committed.resolve();
        await release.promise;
        return response;
      };
      const coordinator = createCoordinator(
        fixture,
        store,
        new FakeExecutor(),
        {
          threadId: "fixture-owner",
          heartbeatIntervalMs: 60_000,
        },
      );
      coordinator.start();
      await committed.promise;
      store.run.status = status;
      await coordinator.renewHeartbeat();
      release.resolve();
      assert.equal((await coordinator.settled()).status, status);
    }
  }

  async function replacementWaitsForTerminalResult() {
    const fixture = await fixtureRun(config);
    fixture.run.coordinatorGeneration = 1;
    const store = new FakeStore(fixture.run);
    const executor = new FakeExecutor({ blockDiscoveryAfterCalls: 0 });
    const observing = Promise.withResolvers<void>();
    const replacement = Promise.withResolvers<DeepScanRunState>();
    const coordinator = createCoordinator(fixture, store, executor, {
      threadId: "fixture-owner",
      heartbeatIntervalMs: 60_000,
      observeReplacement: async () => {
        observing.resolve();
        return await replacement.promise;
      },
    });
    coordinator.start();
    await executor.discoveryStarted.promise;
    store.run.coordinatorGeneration = 2;
    const heartbeat = coordinator.renewHeartbeat();
    await observing.promise;
    try {
      assert.equal(
        await coordinator.wait(undefined, 0),
        undefined,
        "the original caller must keep waiting for the replacement coordinator",
      );
    } finally {
      replacement.resolve({
        ...store.run,
        status: "succeeded",
        terminalReason: "capped",
      });
      await heartbeat;
    }
    assert.equal((await coordinator.settled()).status, "succeeded");
  }

  async function concurrentOwnershipReadsKeepReplacementResult() {
    for (const [readFails, leaseLossConfirmed] of [
      [false, false],
      [true, false],
      [true, true],
    ]) {
      const fixture = await fixtureRun(config);
      fixture.run.coordinatorGeneration = 2;
      const store = new FakeStore(fixture.run);
      const preparing = Promise.withResolvers<void>();
      const failProgress = Promise.withResolvers<void>();
      const heartbeatReadStarted = Promise.withResolvers<void>();
      const failureReadStarted = Promise.withResolvers<void>();
      const heartbeatRead = Promise.withResolvers<DeepScanRunState>();
      const failureRead = Promise.withResolvers<DeepScanRunState>();
      const observing = Promise.withResolvers<void>();
      const replacement = Promise.withResolvers<DeepScanRunState>();
      const releaseStaleFailure = Promise.withResolvers<void>();
      let reads = 0;
      let failureCalls = 0;
      let observations = 0;
      store.updateProgress = async () => {
        preparing.resolve();
        await failProgress.promise;
        throw new Error(
          leaseLossConfirmed
            ? "Deep Scan coordinator lease belongs to a newer generation."
            : "fixture progress persistence failure",
        );
      };
      store.get = async () => {
        reads += 1;
        if (reads === 1) {
          heartbeatReadStarted.resolve();
          return await heartbeatRead.promise;
        }
        failureReadStarted.resolve();
        return await failureRead.promise;
      };
      store.fail = async () => {
        failureCalls += 1;
        await releaseStaleFailure.promise;
        throw new Error(
          "Deep Scan coordinator lease belongs to a newer generation.",
        );
      };
      const coordinator = createCoordinator(
        fixture,
        store,
        new FakeExecutor(),
        {
          threadId: "fixture-owner",
          heartbeatIntervalMs: 60_000,
          observeReplacement: async () => {
            observations += 1;
            observing.resolve();
            return await replacement.promise;
          },
        },
      );
      coordinator.start();
      await preparing.promise;
      const heartbeat = coordinator.renewHeartbeat();
      await heartbeatReadStarted.promise;
      failProgress.resolve();
      await failureReadStarted.promise;
      const newer = { ...store.run, coordinatorGeneration: 3 };
      store.run = newer;
      heartbeatRead.resolve(structuredClone(newer));
      await observing.promise;
      if (readFails) failureRead.reject(new Error("database is locked"));
      else failureRead.resolve(structuredClone(newer));
      replacement.resolve({
        ...newer,
        status: "succeeded",
        terminalReason: "capped",
      });
      await heartbeat;
      // A stale failure response must arrive only after replacement observation.
      releaseStaleFailure.resolve();
      const terminal = await coordinator.settled();
      assert.equal(terminal.status, "succeeded");
      assert.equal(terminal.coordinatorGeneration, 3);
      assert.equal(
        failureCalls,
        0,
        "a replaced coordinator must not fail the scan",
      );
      assert.equal(observations, 1, "concurrent reads must share one observer");
    }
  }

  async function lateFailurePersistenceKeepsStoppedState() {
    for (const status of ["succeeded", "canceled", "failed"] as const) {
      for (const rejectFailure of [false, true]) {
        const fixture = await fixtureRun(config);
        fixture.run.coordinatorGeneration = 2;
        const store = new FakeStore(fixture.run);
        store.failProgressAt = 1;
        const failing = Promise.withResolvers<void>();
        const release = Promise.withResolvers<void>();
        store.fail = async (_scanId, message) => {
          const stale = {
            ...store.run,
            status: "failed" as const,
            error: message,
          };
          failing.resolve();
          await release.promise;
          if (rejectFailure) throw new Error("fixture stale failure rejected");
          return stale;
        };
        const coordinator = createCoordinator(
          fixture,
          store,
          new FakeExecutor(),
          {
            threadId: "fixture-owner",
            heartbeatIntervalMs: 60_000,
            observeReplacement: async (run) => ({
              ...run,
              status: "succeeded",
              terminalReason: "capped",
            }),
          },
        );
        coordinator.start();
        await failing.promise;
        try {
          if (status === "succeeded") {
            store.run.coordinatorGeneration = 3;
            await coordinator.renewHeartbeat();
          } else if (status === "canceled") {
            store.run.status = "canceled";
            coordinator.cancel("fixture cancellation");
          } else {
            store.run.status = "failed";
            coordinator.failExternallyPersisted("fixture external failure");
          }
        } finally {
          release.resolve();
        }
        const terminal = await coordinator.settled();
        assert.equal(terminal.status, status);
        assert.equal(
          terminal.coordinatorGeneration,
          status === "succeeded" ? 3 : 2,
        );
        assert.equal(
          terminal.error,
          status === "failed" ? "fixture external failure" : undefined,
          "stale failure persistence must not replace the stopped result",
        );
      }
    }
  }

  async function shutdownStopsReplacementObservation() {
    const fixture = await fixtureRun(config);
    fixture.run.coordinatorGeneration = 1;
    const store = new FakeStore(fixture.run);
    const executor = new FakeExecutor({ blockDiscoveryAfterCalls: 0 });
    const registry = new DeepScanCoordinatorRegistry();
    const coordinator = registry.start({
      run: fixture.run,
      store,
      executor,
      pluginRoot: fixture.pluginRoot,
      clock: immediateClock,
      threadId: "fixture-owner",
      heartbeatIntervalMs: 60_000,
    });
    await executor.discoveryStarted.promise;
    store.run.coordinatorGeneration = 2;
    const heartbeat = coordinator.renewHeartbeat();
    await new Promise(setImmediate);
    registry.shutdown("fixture transport closed");
    const terminal = await coordinator.wait(undefined, 100);
    // Release the old implementation's detached observer even on failure.
    store.run.status = "succeeded";
    await heartbeat;
    assert.equal(terminal?.status, "canceled");
  }

  async function failedCancellationStillPreservesResults() {
    const fixture = await fixtureRun(config);
    const store = new FakeStore(fixture.run);
    const executor = new FakeExecutor({ blockDiscoveryAfterCalls: 0 });
    const publishing = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    let publications = 0;
    let cancellationSettled = false;
    const coordinator = createCoordinator(fixture, store, executor, {
      threadId: "fixture-owner",
      onStopped: async () => {
        publishing.resolve();
        await release.promise;
        publications += 1;
      },
    });
    coordinator.start();
    const terminal = coordinator.settled().catch((error: Error) => error);
    await executor.discoveryStarted.promise;
    const cancellation = coordinator
      .cancelAfterPersistence("fixture cancellation", async () => {
        store.run.status = "canceled";
        throw new Error("fixture cancellation response lost");
      })
      .catch((error: Error) => {
        cancellationSettled = true;
        return error;
      });
    await publishing.promise;
    await new Promise<void>((resolve) => setImmediate(resolve));
    try {
      assert.equal(
        cancellationSettled,
        false,
        "lost response must wait for saved result publication",
      );
    } finally {
      release.resolve();
      await terminal;
    }
    assert.match((await cancellation).message, /response lost/);
    const result = await terminal;
    assert.equal(
      publications,
      1,
      "cancellation response failure must not skip saved results",
    );
    assert.match(result.message, /response lost/);
  }

  async function lateCancellationKeepsPersistedFailure() {
    const fixture = await fixtureRun(config);
    const store = new FakeStore(fixture.run);
    const executor = new FakeExecutor({ blockDiscoveryAfterCalls: 0 });
    const publishing = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    let cancellations = 0;
    const coordinator = createCoordinator(fixture, store, executor, {
      threadId: "fixture-owner",
      onStopped: async () => {
        publishing.resolve();
        await release.promise;
      },
    });
    coordinator.start();
    await executor.discoveryStarted.promise;
    store.run.status = "failed";
    coordinator.failExternallyPersisted("fixture worker failure");
    await publishing.promise;
    const cancellation = coordinator.cancelAfterPersistence(
      "late cancellation",
      async () => {
        cancellations += 1;
      },
    );
    release.resolve();
    const result = await cancellation;
    assert.equal(
      cancellations,
      0,
      "a failed scan cannot be canceled while publication settles",
    );
    assert.equal(result.status, "failed");
  }

  async function terminalDiscoveryWaitsForCleanup() {
    for (const status of ["succeeded", "failed"] as const) {
      const fixture = await fixtureRun(config);
      const store = new FakeStore(fixture.run);
      store.failFinish = status === "failed";
      store.rejectFailurePersistence = status === "failed";
      let coordinator: ReturnType<typeof createCoordinator>;
      const finalRead = Promise.withResolvers<void>();
      const release = Promise.withResolvers<void>();
      const originalGet = store.get.bind(store);
      store.get = async (...args) => {
        if (coordinator?.snapshot().status === status) {
          finalRead.resolve();
          await release.promise;
        }
        return await originalGet(...args);
      };
      const registry = new DeepScanCoordinatorRegistry();
      coordinator = registry.start({
        run: fixture.run,
        store,
        executor: new FakeExecutor(),
        pluginRoot: fixture.pluginRoot,
        clock: immediateClock,
        threadId: "fixture-owner",
        onStopped: async () => {},
      });
      await finalRead.promise;
      let persisted = false;
      let resolved = false;
      const cancellation = registry
        .cancelAndWait(fixture.run.scanId, "cancel parent", async () => {
          persisted = true;
        })
        .then((handled: boolean) => {
          resolved = true;
          return handled;
        });
      await Promise.resolve();
      assert.equal(
        resolved,
        false,
        "wait for all coordinator cleanup before durable parent cancellation",
      );
      release.resolve();
      assert.equal(
        await cancellation,
        true,
        "local cleanup completed; the server checks durable parent state",
      );
      assert.equal(
        persisted,
        false,
        "the server performs durable cancellation after coordinator cleanup",
      );
      assert.equal(
        store.run.status,
        status === "failed" ? "running" : "succeeded",
      );
    }
  }

  async function orphanWorkerDirectoriesAreNotReused() {
    for (const suffix of ["0001", "9007199254740992"]) {
      const fixture = await fixtureRun(config);
      const savedPrompts: string[] = [];
      for (const [directory, kind] of [
        ["workers", "discovery"],
        ["dedup", "dedup"],
      ]) {
        const root = path.join(
          fixture.run.scanDir,
          "artifacts",
          "deep_discovery",
          directory,
          `${kind}-${suffix}`,
        );
        await mkdir(root, { recursive: true });
        const prompt = path.join(root, "prompt.md");
        savedPrompts.push(prompt);
        await writeFile(prompt, "interrupted before worker registration\n");
      }
      const store = new FakeStore(fixture.run);
      const executor = new FakeExecutor();
      const coordinator = createCoordinator(fixture, store, executor);
      coordinator.start();
      const terminal = await coordinator.wait(undefined, 5_000);
      assert.equal(terminal?.status, "succeeded", terminal?.error);
      const next = String(BigInt(suffix) + 1n).padStart(4, "0");
      for (const kind of ["discovery", "dedup"]) {
        assert.ok(
          [...store.workers.values()].some((worker) =>
            worker.promptPath.includes(`${kind}-${next}`),
          ),
        );
      }
      for (const prompt of savedPrompts) {
        assert.equal(
          await readFile(prompt, "utf8"),
          "interrupted before worker registration\n",
        );
      }
    }
  }

  async function ancestorNamesDoNotChooseWorkerSequence() {
    const fixture = await fixtureRun({ ...config, maxDiscoveryRuns: 3 });
    const scanDir = path.join(
      path.dirname(fixture.run.scanDir),
      "service-discovery-2",
    );
    await mkdir(fixture.run.scanDir, { recursive: true });
    await rename(fixture.run.scanDir, scanDir);
    fixture.run.scanDir = scanDir;
    const root = path.join(
      scanDir,
      "artifacts",
      "deep_discovery",
      "workers",
      "discovery-0003",
    );
    await mkdir(root, { recursive: true });
    await writeFile(path.join(root, "prompt.md"), "previous worker\n");
    fixture.run.dispatchedCount = 2;
    fixture.run.persistedWorkers = [
      {
        id: randomUUID(),
        kind: "discovery",
        status: "canceled",
        attempt: 0,
        promptPath: path.join(root, "prompt.md"),
        artifactDir: path.join(root, "output"),
        mergeState: "none",
      },
    ];
    const store = new FakeStore(fixture.run);
    const coordinator = createCoordinator(fixture, store, new FakeExecutor());
    coordinator.start();
    const terminal = await coordinator.wait(undefined, 5_000);
    assert.equal(terminal?.status, "succeeded", terminal?.error);
    assert.ok(
      [...store.workers.values()].some((worker) =>
        worker.promptPath.includes("discovery-0004"),
      ),
    );
  }
}
