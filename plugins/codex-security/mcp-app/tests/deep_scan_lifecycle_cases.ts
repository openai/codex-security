import type { TestContext } from "node:test";
import { readJson, writeJson } from "./support/json.ts";
import type { ScanDraftInput } from "../src/artifact-scan-draft.js";
import {
  coordinatorFixture,
  startCoordinator,
  DeepScanCoordinatorRegistry,
  FakeExecutor,
  FakeStore,
  pausePoint,
  fixtureRun,
  immediateClock,
  runCoordinator,
} from "./deep_scan_coordinator_fixture.ts";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { importCoordinatorServer } from "./import-module.ts";
import type { DeepScanRunState } from "../src/deep-scan/types.js";

export async function testDeepScanLifecycle(context: TestContext) {
  const config = {
    workers: 1,
    subagents: 0,
    stopAfterNoNew: 1,
    maxDiscoveryRuns: 1,
  };
  for (const check of [
    lateCancellationWaitsForPersistence,
    failedParentCancellationStopsActiveWorker,
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
    await context.test(check.name, check);
  }

  async function failedParentCancellationStopsActiveWorker() {
    for (const terminalReadFails of [false, true]) {
      const fixture = await fixtureRun(config);
      fixture.run.coordinatorGeneration = 1;
      const store = new FakeStore(fixture.run);
      const executor = new FakeExecutor({ blockDiscoveryAfterCalls: 0 });
      const registry = new DeepScanCoordinatorRegistry();
      const savedError = "synthetic externally persisted failure";
      let publications = 0;
      let cancellationWrites = 0;
      const coordinator = registry.start({
        ...fixture,
        store,
        executor,
        threadId: "fixture-owner",
        heartbeatIntervalMs: 60_000,
        onStopped: async (stopped: DeepScanRunState) => {
          publications += 1;
          assert.equal(stopped.status, "failed");
          assert.equal(stopped.error, savedError);
        },
      });
      const terminal = coordinator.settled();
      void terminal.catch(() => {});
      let cancellation: Promise<boolean> | undefined;
      try {
        await executor.discoveryStarted.promise;
        assert.equal(executor.runningDiscovery, 1);
        store.run.status = "failed";
        store.run.error = savedError;
        store.failNextTerminalGet = terminalReadFails;
        cancellation = registry.cancelAndWait(
          fixture.run.scanId,
          "user_canceled_scan",
          async () => {
            cancellationWrites += 1;
            throw new Error(
              "saved failure must not be replaced by cancellation",
            );
          },
          async () => ({ status: "failed", failureMessage: savedError }),
        );
        void cancellation!.catch(() => {});
        await new Promise(setImmediate);
        assert.equal(
          executor.runningDiscovery,
          0,
          "saved parent failure stops the worker before the next heartbeat",
        );
        assert.equal(await cancellation, true);
        const stopped = await terminal;
        assert.equal(stopped.status, "failed");
        assert.equal(stopped.error, savedError);
        assert.equal(store.run.status, "failed");
        assert.equal(store.run.error, savedError);
        assert.equal(cancellationWrites, 0);
        assert.equal(publications, terminalReadFails ? 0 : 1);
      } finally {
        registry.shutdown("fixture cleanup");
        await Promise.allSettled([terminal, cancellation]);
      }
    }
  }

  async function lateCancellationWaitsForPersistence(context: TestContext) {
    const completedParentStatus: string = JSON.parse(
      execFileSync(
        process.env.PYTHON || "python3",
        [
          "-I",
          "-B",
          "-c",
          `import json, sys, tempfile
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from workbench_test_support import empty_target_scan, run_workbench, write_completed_contract
with tempfile.TemporaryDirectory(prefix="deep-scan-completion-contract-") as root:
    state, target, scan_id, output = empty_target_scan(Path(root))
    write_completed_contract(output, scan_id, target)
    run_workbench(state, "complete-scan", "--scan-id", scan_id)
    saved = run_workbench(state, "get-scan", "--scan-id", scan_id)
    print(json.dumps(saved["workspace"]["results"]["progress"]["status"]))
`,
          path.join(import.meta.dirname, "../../tests"),
        ],
        { encoding: "utf8" },
      ),
    );
    let current: {
      registry: InstanceType<typeof DeepScanCoordinatorRegistry>;
      store: FakeStore;
      persistence: ReturnType<typeof pausePoint>;
      rejectPersistence: boolean;
      calls: string[];
      readParent?: () => Promise<{ workspace: typeof current.workspace }>;
      workspace: {
        setup: { submitted: boolean };
        results: { progress: { status: string }; failureMessage?: string };
      };
    };
    Object.assign(globalThis, {
      deepScanCancellationFixture: {
        registry: {
          get: (...args: unknown[]) => current.registry.get(...args),
          cancelAndWait: (...args: unknown[]) =>
            current.registry.cancelAndWait(...args),
          shutdown: (...args: unknown[]) => current.registry.shutdown(...args),
        },
        async workbench([command]: string[]) {
          current.calls.push(command);
          if (command === "get-scan")
            return current.readParent
              ? await current.readParent()
              : { workspace: structuredClone(current.workspace) };
          if (command === "fail-scan") {
            current.store.run.status = "failed";
            current.store.run.error = "synthetic external failure";
            current.workspace.results.progress.status = "failed";
            return {
              scan: current.workspace.results,
              workspace: current.workspace,
            };
          }
          assert.equal(command, "cancel-scan");
          if (current.workspace.results.progress.status !== "running")
            throw new Error("Only a running scan can be canceled.");
          if (
            current.calls.filter((command) => command === "cancel-scan")
              .length > 1
          )
            throw new Error("synthetic duplicate cancellation persistence");
          await current.persistence.pause();
          if (current.rejectPersistence)
            throw new Error("synthetic cancellation persistence failure");
          current.store.run.status = "canceled";
          current.workspace.results.progress.status = "canceled";
          return current.workspace;
        },
      },
    });
    const { createCodexSecurityServer } = await importCoordinatorServer(
      "deepScanCancellationFixture",
    );
    const server = createCodexSecurityServer();
    const tools = server._registeredTools;
    const cancel = (scanId: string) =>
      tools.cancel_codex_security_scan_from_app.handler({ scanId });
    const failExternally = (scanId: string) =>
      tools.fail_codex_security_scan.handler(
        { scanId, message: "synthetic external failure" },
        {},
      );
    const parentStatus = (result: Awaited<ReturnType<typeof cancel>>) =>
      result.structuredContent.workspace.results.progress.status;
    try {
      for (const stage of [
        "final read",
        "final read heartbeat",
        "final read heartbeat microtask",
        "final read repeated cancellation",
        "onComplete",
        "unpersisted failure",
        "unpersisted unowned failure",
        "persisted failure",
        "observed failure",
        "lost-response failure",
        "lost-response pending-read failure",
        "unpersisted pending-read failure",
        "unavailable pending-read failure",
        "stale heartbeat failure",
        "observed interrupted",
        "unpersisted pending-read external failure",
        "final read completed parent",
        "final read parent completes during admission",
        "onComplete external failure during cleanup",
      ]) {
        for (const rejectPersistence of [false, true]) {
          await context.test(
            `${stage}; persistence rejects=${rejectPersistence}`,
            () => runStage(stage, rejectPersistence),
          );
        }
      }
      for (const joined of [false, true]) {
        await context.test(`Admission read failure; joined=${joined}`, () =>
          runAdmissionFailure(joined),
        );
      }
    } finally {
      await server.close();
      Reflect.deleteProperty(globalThis, "deepScanCancellationFixture");
    }

    async function runStage(stage: string, rejectPersistence: boolean) {
      const fixture = await fixtureRun(config);
      fixture.run.coordinatorGeneration = 1;
      const store = new FakeStore(fixture.run);
      const registry = new DeepScanCoordinatorRegistry();
      const entered = Promise.withResolvers<void>();
      const release = Promise.withResolvers<void>();
      const persistence = pausePoint();
      const failureWrite = pausePoint();
      const failureSaved = Promise.withResolvers<void>();
      const admission = pausePoint();
      const heartbeatOwnershipRead = pausePoint();
      let publications = 0;
      let cancellation: ReturnType<typeof cancel> | undefined;
      let repeatedCancellation: ReturnType<typeof cancel> | undefined;
      let coordinator:
        | ReturnType<InstanceType<typeof DeepScanCoordinatorRegistry>["start"]>
        | undefined;
      let gateHeartbeat = false;
      const concurrentFailure = stage.endsWith("external failure");
      const failureDuringCleanup =
        stage === "onComplete external failure during cleanup";
      const completedParent = stage.includes("completed parent");
      const completesDuringAdmission = stage.includes(
        "completes during admission",
      );
      const pendingFailureRead = stage.includes("pending-read");
      const unavailableRead = stage.startsWith("unavailable");
      const lostResponse = stage.startsWith("lost-response") || unavailableRead;
      const interrupted = stage === "observed interrupted";
      const stoppedStatus = interrupted ? "interrupted" : "failed";
      const observeFailure = stage === "observed failure" || interrupted;
      const publicationGate =
        stage === "lost-response failure" ||
        stage === "stale heartbeat failure";
      const durableFailure =
        stage === "persisted failure" ||
        observeFailure ||
        publicationGate ||
        lostResponse ||
        unavailableRead ||
        concurrentFailure ||
        failureDuringCleanup;
      current = {
        store,
        registry,
        persistence,
        rejectPersistence,
        calls: [],
        workspace: {
          setup: { submitted: true },
          results: {
            progress: {
              status: completedParent ? completedParentStatus : "running",
            },
          },
        },
      };
      let admissionPaused = false;
      current.readParent = async () => {
        const workspace = structuredClone(current.workspace);
        if (workspace.results.progress.status === "failed")
          workspace.results.failureMessage = current.store.run.error;
        if (pendingFailureRead && !admissionPaused) {
          admissionPaused = true;
          await admission.pause();
          if (unavailableRead)
            throw new Error("synthetic terminal state unavailable");
        }
        if (completesDuringAdmission)
          queueMicrotask(() => {
            current.workspace.results.progress.status = completedParentStatus;
          });
        return { workspace };
      };
      if (
        stage.startsWith("final read") ||
        observeFailure ||
        publicationGate ||
        pendingFailureRead
      ) {
        const get = store.get.bind(store);
        let paused = false;
        store.get = async () => {
          const snapshot = await get();
          if (concurrentFailure && paused && !admissionPaused) {
            admissionPaused = true;
            await admission.pause();
          }
          if (gateHeartbeat) {
            gateHeartbeat = false;
            await heartbeatOwnershipRead.pause();
          }
          if (
            !paused &&
            (observeFailure || pendingFailureRead
              ? coordinator?.snapshot().status === stoppedStatus
              : snapshot.status === "succeeded")
          ) {
            paused = true;
            entered.resolve();
            await release.promise;
          }
          return snapshot;
        };
      }
      if (stage.startsWith("unpersisted"))
        store.fail = async () => {
          throw new Error("synthetic failure persistence unavailable");
        };
      if (publicationGate || lostResponse) {
        const fail = store.fail.bind(store);
        store.fail = async (...args) => {
          if (stage === "stale heartbeat failure") {
            await failureWrite.pause();
          }
          const result = await fail(...args);
          current.workspace.results.progress.status = "failed";
          if (lostResponse)
            throw new Error("synthetic committed failure response lost");
          return result;
        };
      }
      const executor = new FakeExecutor(
        observeFailure
          ? { blockDiscoveryAfterCalls: 0 }
          : stage.endsWith("failure")
            ? {
                nonRetryableDiscoveryMessage: "synthetic worker failure",
              }
            : {},
      );
      coordinator = registry.start({
        run: fixture.run,
        store,
        executor,
        pluginRoot: fixture.pluginRoot,
        clock: immediateClock,
        threadId:
          stage === "unpersisted unowned failure" ? undefined : "fixture-owner",
        heartbeatIntervalMs: 60_000,
        onComplete: async () => {
          if (stage.startsWith("onComplete")) {
            entered.resolve();
            await release.promise;
          }
        },
        onStopped: async () => {
          publications++;
          if (publicationGate) {
            entered.resolve();
            await release.promise;
          }
        },
        log: (event: { event: string }) => {
          if (
            failureDuringCleanup &&
            event.event === "coordinator_cancel_requested"
          )
            void failExternally(fixture.run.scanId).then(() =>
              failureSaved.resolve(),
            );
          if (
            stage.endsWith("microtask") &&
            event.event === "coordinator_cleanup_settled"
          )
            queueMicrotask(() => {
              cancellation = cancel(fixture.run.scanId);
              void cancellation.catch(() => {});
            });
          if (
            !stage.endsWith("failure") ||
            event.event !== "coordinator_failed"
          )
            return;
          if (publicationGate || pendingFailureRead) {
            failureSaved.resolve();
            return;
          }
          if (stage === "persisted failure")
            current.workspace.results.progress.status = "failed";
          entered.resolve();
          cancellation = cancel(fixture.run.scanId);
          void cancellation.catch(() => {});
        },
      });
      const terminal = coordinator.settled();
      void terminal.catch(() => {});
      try {
        if (stage === "stale heartbeat failure") {
          await failureWrite.entered;
          gateHeartbeat = true;
          const heartbeat = coordinator.renewHeartbeat();
          await heartbeatOwnershipRead.entered;
          failureWrite.release();
          await failureSaved.promise;
          heartbeatOwnershipRead.release();
          await heartbeat;
        }
        if (observeFailure) {
          await executor.discoveryStarted.promise;
          store.run.status = stoppedStatus;
          current.workspace.results.progress.status = "failed";
          await coordinator.renewHeartbeat();
        }
        await entered.promise;
        if (stage.startsWith("final read heartbeat"))
          await coordinator.renewHeartbeat();
        if (!stage.endsWith("microtask")) {
          cancellation ??= cancel(fixture.run.scanId);
          void cancellation.catch(() => {});
        }
        if (stage === "final read repeated cancellation") {
          await coordinator.renewHeartbeat();
          repeatedCancellation = cancel(fixture.run.scanId);
          void repeatedCancellation.catch(() => {});
        }
        if (pendingFailureRead) {
          const admitted = await Promise.race([
            admission.entered.then(() => true),
            persistence.entered.then(() => false),
            cancellation.then(
              () => false,
              () => false,
            ),
            coordinator.wait(undefined, 25).then(() => false),
          ]);
          if (admitted) {
            if (concurrentFailure) await failExternally(fixture.run.scanId);
            repeatedCancellation = cancel(fixture.run.scanId);
            void repeatedCancellation.catch(() => {});
            assert.equal(await coordinator.wait(undefined, 25), undefined);
            admission.release();
          }
        }
        if (failureDuringCleanup) await failureSaved.promise;
        release.resolve();
        if (completedParent || completesDuringAdmission) {
          persistence.release();
          assert.equal((await terminal).status, "succeeded");
          if (completesDuringAdmission)
            await assert.rejects(
              cancellation,
              /Only a running scan can be canceled/,
            );
          else
            assert.equal(
              parentStatus(await cancellation),
              completedParentStatus,
            );
          assert.equal(store.run.status, "succeeded");
          assert.equal(
            current.workspace.results.progress.status,
            completedParentStatus,
          );
          assert.equal(
            current.calls.filter((command) => command === "cancel-scan").length,
            completesDuringAdmission ? 1 : 0,
          );
          return;
        }
        if (durableFailure) {
          assert.equal((await terminal).status, stoppedStatus);
          if (unavailableRead)
            await assert.rejects(
              cancellation,
              /synthetic terminal state unavailable/,
            );
          else assert.equal(parentStatus(await cancellation), "failed");
          assert.equal(current.calls.includes("cancel-scan"), false);
          if (concurrentFailure || failureDuringCleanup)
            assert.match((await terminal).error, /synthetic external failure/);
          assert.equal(publications, interrupted ? 0 : 1);
          if (unavailableRead)
            assert.match((await terminal).error, /synthetic worker failure/);
          if (repeatedCancellation) {
            if (unavailableRead)
              await assert.rejects(
                repeatedCancellation,
                /synthetic terminal state unavailable/,
              );
            else
              assert.equal(parentStatus(await repeatedCancellation), "failed");
          }
          return;
        }
        await persistence.entered;
        const waiting = await coordinator.wait(undefined, 25);
        persistence.release();
        if (stage.endsWith("microtask")) {
          assert.equal(
            waiting?.status,
            "succeeded",
            "settlement must finish before admitting another cancellation",
          );
          if (rejectPersistence)
            await assert.rejects(
              cancellation,
              /synthetic cancellation persistence failure/,
            );
          else assert.equal(parentStatus(await cancellation), "canceled");
          assert.equal((await terminal).status, "succeeded");
          assert.equal(publications, 0);
          assert.deepEqual(current.calls, ["get-scan", "cancel-scan"]);
          return;
        }
        assert.equal(
          waiting,
          undefined,
          "start waiter must await durable cancellation",
        );
        if (rejectPersistence) {
          await assert.rejects(
            cancellation,
            /synthetic cancellation persistence failure/,
          );
          await assert.rejects(
            terminal,
            /synthetic cancellation persistence failure/,
          );
          if (repeatedCancellation)
            await assert.rejects(
              repeatedCancellation,
              /synthetic cancellation persistence failure/,
            );
          assert.equal(publications, 0);
        } else {
          assert.equal(parentStatus(await cancellation), "canceled");
          assert.equal((await terminal).status, "canceled");
          assert.equal(store.run.status, "canceled");
          assert.equal(
            publications,
            stage === "unpersisted unowned failure" ? 0 : 1,
          );
          if (repeatedCancellation)
            assert.equal(parentStatus(await repeatedCancellation), "canceled");
        }
        assert.equal(current.calls[0], "get-scan");
        assert.equal(
          current.calls.filter((command) => command === "cancel-scan").length,
          1,
        );
      } finally {
        release.resolve();
        persistence.release();
        failureWrite.release();
        heartbeatOwnershipRead.release();
        admission.release();
        registry.shutdown("fixture cleanup");
        await Promise.allSettled([
          terminal,
          cancellation,
          repeatedCancellation,
        ]);
      }
    }

    async function runAdmissionFailure(joined: boolean) {
      const fixture = await fixtureRun(config);
      const store = new FakeStore(fixture.run);
      const registry = new DeepScanCoordinatorRegistry();
      const executor = new FakeExecutor({ blockDiscoveryAfterCalls: 0 });
      const admissionRead = pausePoint();
      const persistence = pausePoint();
      let reads = 0;
      current = {
        store,
        registry,
        persistence,
        rejectPersistence: false,
        calls: [],
        workspace: {
          setup: { submitted: true },
          results: { progress: { status: "running" } },
        },
        readParent: async () => {
          if (reads++ === 0) {
            await admissionRead.pause();
            throw new Error("synthetic temporary parent read failure");
          }
          return { workspace: structuredClone(current.workspace) };
        },
      };
      const coordinator = registry.start({
        run: fixture.run,
        store,
        executor,
        pluginRoot: fixture.pluginRoot,
        clock: immediateClock,
        threadId: "fixture-owner",
        heartbeatIntervalMs: 60_000,
      });
      const outcome = (operation: ReturnType<typeof cancel>) =>
        operation.then(
          () => undefined,
          (error: Error) => error,
        );
      let first: Promise<Error | undefined> | undefined;
      let second: Promise<Error | undefined> | undefined;
      let retry: ReturnType<typeof cancel> | undefined;
      try {
        await executor.discoveryStarted.promise;
        first = outcome(cancel(fixture.run.scanId));
        await admissionRead.entered;
        if (joined) second = outcome(cancel(fixture.run.scanId));
        admissionRead.release();
        assert.match(
          (await first)?.message ?? "",
          /temporary parent read failure/,
        );
        if (second) {
          const result = await Promise.race([
            second,
            coordinator.wait(undefined, 25).then(() => undefined),
          ]);
          assert.match(result?.message ?? "", /temporary parent read failure/);
        }
        assert.equal(coordinator.snapshot().status, "running");
        assert.equal(await coordinator.wait(undefined, 25), undefined);
        retry = cancel(fixture.run.scanId);
        void retry.catch(() => {});
        await persistence.entered;
        assert.equal(await coordinator.wait(undefined, 25), undefined);
        persistence.release();
        assert.equal(parentStatus(await retry), "canceled");
        assert.equal((await coordinator.settled()).status, "canceled");
        assert.equal(
          current.calls.filter((command) => command === "cancel-scan").length,
          1,
        );
      } finally {
        admissionRead.release();
        persistence.release();
        registry.shutdown("fixture cleanup");
        await Promise.allSettled([first, second, retry, coordinator.settled()]);
      }
    }
  }

  async function canceledPublicationWaitsForHeartbeat() {
    const fixture = await fixtureRun(config);
    fixture.run.coordinatorGeneration = 1;
    const store = new FakeStore(fixture.run);
    const executor = new FakeExecutor({ blockDiscoveryAfterCalls: 0 });
    const publication = pausePoint();
    const coordinator = startCoordinator(fixture, store, executor, {
      threadId: "fixture-owner",
      heartbeatIntervalMs: 60_000,
      onStopped: async () => await publication.pause(),
    });
    await executor.discoveryStarted.promise;
    store.run.status = "canceled";
    coordinator.cancel("fixture cancellation");
    await publication.entered;
    try {
      await coordinator.renewHeartbeat();
      assert.equal(
        await coordinator.wait(undefined, 0),
        undefined,
        "heartbeat must not release waiters while saved results are being published",
      );
    } finally {
      publication.release();
      await coordinator.settled();
    }
  }

  async function delayedReducerDoesNotReplaceStoppedState() {
    for (const status of ["canceled", "failed"] as const) {
      const fixture = await fixtureRun(config);
      fixture.run.coordinatorGeneration = 1;
      const store = new FakeStore(fixture.run);
      const commitResponse = pausePoint();
      const commit = store.commitDedup.bind(store);
      store.commitDedup = async (input) => {
        const response = await commit(input);
        await commitResponse.pause();
        return response;
      };
      const coordinator = startCoordinator(fixture, store, new FakeExecutor(), {
        threadId: "fixture-owner",
        heartbeatIntervalMs: 60_000,
      });
      await commitResponse.entered;
      store.run.status = status;
      await coordinator.renewHeartbeat();
      commitResponse.release();
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
    const coordinator = startCoordinator(fixture, store, executor, {
      threadId: "fixture-owner",
      heartbeatIntervalMs: 60_000,
      observeReplacement: async () => {
        observing.resolve();
        return await replacement.promise;
      },
    });
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
      const progressWrite = pausePoint();
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
        await progressWrite.pause();
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
      const coordinator = startCoordinator(fixture, store, new FakeExecutor(), {
        threadId: "fixture-owner",
        heartbeatIntervalMs: 60_000,
        observeReplacement: async () => {
          observations += 1;
          observing.resolve();
          return await replacement.promise;
        },
      });
      await progressWrite.entered;
      const heartbeat = coordinator.renewHeartbeat();
      await heartbeatReadStarted.promise;
      progressWrite.release();
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
        const failureWrite = pausePoint();
        store.fail = async (_scanId, message) => {
          const stale = {
            ...store.run,
            status: "failed" as const,
            error: message,
          };
          await failureWrite.pause();
          if (rejectFailure) throw new Error("fixture stale failure rejected");
          return stale;
        };
        const coordinator = startCoordinator(
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
        await failureWrite.entered;
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
          failureWrite.release();
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
    const publication = pausePoint();
    let publications = 0;
    let cancellationSettled = false;
    const coordinator = startCoordinator(fixture, store, executor, {
      threadId: "fixture-owner",
      onStopped: async () => {
        await publication.pause();
        publications += 1;
      },
    });
    const terminal = coordinator.settled().catch((error: Error) => error);
    await executor.discoveryStarted.promise;
    const cancellation = coordinator
      .cancelAfterPersistence(
        "fixture cancellation",
        async () => {
          store.run.status = "canceled";
          throw new Error("fixture cancellation response lost");
        },
        async () => ({ status: "running" }),
      )
      .catch((error: Error) => {
        cancellationSettled = true;
        return error;
      });
    await publication.entered;
    await new Promise<void>((resolve) => setImmediate(resolve));
    try {
      assert.equal(
        cancellationSettled,
        false,
        "lost response must wait for saved result publication",
      );
    } finally {
      publication.release();
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
    const publication = pausePoint();
    let cancellations = 0;
    const coordinator = startCoordinator(fixture, store, executor, {
      threadId: "fixture-owner",
      onStopped: async () => await publication.pause(),
    });
    await executor.discoveryStarted.promise;
    store.run.status = "failed";
    coordinator.failExternallyPersisted("fixture worker failure");
    await publication.entered;
    const cancellation = coordinator.cancelAfterPersistence(
      "late cancellation",
      async () => {
        cancellations += 1;
      },
      async () => ({ status: "running" }),
    );
    publication.release();
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
      let coordinator: ReturnType<typeof startCoordinator>;
      const finalRead = pausePoint();
      const originalGet = store.get.bind(store);
      store.get = async (...args) => {
        if (coordinator?.snapshot().status === status) {
          await finalRead.pause();
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
      await finalRead.entered;
      let persisted = false;
      let resolved = false;
      const cancellation = registry
        .cancelAndWait(
          fixture.run.scanId,
          "cancel parent",
          async () => {
            persisted = true;
            store.run.status = "canceled";
          },
          async () => ({ status: "running" }),
        )
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
      finalRead.release();
      assert.equal(
        await cancellation,
        true,
        "local cleanup and durable cancellation completed",
      );
      assert.equal(
        persisted,
        true,
        "persist cancellation before releasing coordinator waiters",
      );
      assert.equal(store.run.status, "canceled");
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
      const coordinator = startCoordinator(fixture, store, executor);
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
    const coordinator = startCoordinator(fixture, store, new FakeExecutor());
    const terminal = await coordinator.wait(undefined, 5_000);
    assert.equal(terminal?.status, "succeeded", terminal?.error);
    assert.ok(
      [...store.workers.values()].some((worker) =>
        worker.promptPath.includes("discovery-0004"),
      ),
    );
  }
}

export async function testSuccessfulDeepCoverageRetainsIndependentWorkerReviewStatus() {
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 2,
  });
  const executor = new FakeExecutor();
  const run = executor.run.bind(executor);
  const workerReviewed = {
    label: "Reviewed query",
    disposition: "no_issue_found",
    id: "shared-surface",
    receiptRefs: ["artifacts/worker-receipt.md"],
  };
  const followUp = {
    label: "Worker follow-up",
    disposition: "needs_follow_up",
  };
  executor.run = async (request) => {
    const outcome = await run(request);
    if (request.kind !== "discovery") return outcome;
    const resultPath = path.join(request.artifactContext!.root, "result.json");
    const draft = await readJson(resultPath);
    draft.reviewState = {
      surfaces: [workerReviewed, followUp],
      explicitExclusions: [
        { pattern: "vendor/**", reason: "Third-party code." },
      ],
      deferred: [
        {
          id: "shared-task",
          surfaceIds: ["shared-surface"],
          reason: "An independent review left this question unresolved.",
        },
      ],
      openQuestions: ["Does the deployment enable this path?"],
    };
    await mkdir(path.join(request.artifactContext!.root, "artifacts"), {
      recursive: true,
    });
    await writeFile(
      path.join(request.artifactContext!.root, "artifacts/worker-receipt.md"),
      "Reviewed query evidence.\n",
    );
    await writeJson(resultPath, draft);
    return outcome;
  };
  const completed: ScanDraftInput[] = [];
  const terminal = await runCoordinator(fixture, store, executor, {
    onComplete: async (draft) => void completed.push(structuredClone(draft)),
  });
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(completed.length, 1);
  const coverage = completed[0].reviewState as unknown as {
    reviews: { workerId: string }[];
    surfaces: { id: string; workerId: string; receiptRefs?: string[] }[];
    explicitExclusions: { workerId: string; pattern: string }[];
    deferred: {
      id: string;
      surfaceIds: string[];
      provenance: { workerId: string; sourceId: string; attempt: number };
    }[];
    openQuestions: { question: string; workerId: string }[];
  };

  const workers = [...store.workers.values()].filter(
    (worker) => worker.kind === "discovery",
  );
  assert.equal("completeness" in coverage, false);
  assert.deepEqual(
    coverage.reviews.map((review) => review.workerId).sort(),
    workers.map((worker) => worker.id).sort(),
  );
  assert.equal(coverage.deferred.length, 2);
  assert.equal(coverage.surfaces.length, 4);
  assert.equal(new Set(coverage.surfaces.map((row) => row.id)).size, 4);
  assert.equal(new Set(coverage.deferred.map((row) => row.id)).size, 2);
  assert.equal(coverage.explicitExclusions.length, 2);
  assert.equal(coverage.openQuestions.length, 2);
  for (const row of coverage.deferred) {
    assert.equal(row.provenance.sourceId, "shared-task");
    assert.ok(store.workers.has(row.provenance.workerId));
    assert.equal(row.provenance.attempt, 1);
    assert.deepEqual(row.surfaceIds, [
      `${row.provenance.workerId}-attempt-1-surface-1`,
    ]);
  }
  for (const row of coverage.surfaces) {
    for (const ref of row.receiptRefs ?? []) {
      assert.equal(
        await readFile(path.join(fixture.run.scanDir, ref), "utf8"),
        "Reviewed query evidence.\n",
      );
    }
  }
  for (const worker of workers) {
    const draft = await readJson(worker.resultManifestPath!);
    assert.deepEqual(draft.reviewState.surfaces, [workerReviewed, followUp]);
    assert.equal(draft.reviewState.deferred.length, 1);
  }
}
