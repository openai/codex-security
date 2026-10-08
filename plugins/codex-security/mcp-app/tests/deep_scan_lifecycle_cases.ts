import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { importModule } from "./import-module.ts";
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
    try {
      await test();
    } catch (error) {
      errors.push(new Error(test.name, { cause: error }));
    }
  }
  if (errors.length)
    throw new AggregateError(errors, "Deep Scan lifecycle regressions");

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

  async function lateCancellationWaitsForPersistence() {
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
          fileURLToPath(new URL("../../tests/", import.meta.url)),
        ],
        { encoding: "utf8" },
      ),
    );
    const applicationRoot = fileURLToPath(new URL("../", import.meta.url));
    const source = await readFile(
      new URL("../server.ts", import.meta.url),
      "utf8",
    );
    let current: {
      registry: InstanceType<LifecycleFixtures["DeepScanCoordinatorRegistry"]>;
      store: InstanceType<LifecycleFixtures["FakeStore"]>;
      persistEntered: PromiseWithResolvers<void>;
      persistRelease: PromiseWithResolvers<void>;
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
          current.persistEntered.resolve();
          await current.persistRelease.promise;
          if (current.rejectPersistence)
            throw new Error("synthetic cancellation persistence failure");
          current.store.run.status = "canceled";
          current.workspace.results.progress.status = "canceled";
          return current.workspace;
        },
      },
    });
    const { createCodexSecurityServer } = await importModule({
      stdin: {
        contents: source
          .replace(
            "const deepScanCoordinators = new DeepScanCoordinatorRegistry();",
            "const deepScanCoordinators = globalThis.deepScanCancellationFixture.registry;",
          )
          .replace(
            "async function runWorkbench(",
            "const runWorkbench = (...args) => globalThis.deepScanCancellationFixture.workbench(...args);\nasync function unusedRunWorkbench(",
          ),
        loader: "ts",
        resolveDir: applicationRoot,
      },
      define: {
        __dirname: JSON.stringify(applicationRoot),
        "import.meta.url": JSON.stringify(
          new URL("../server.ts", import.meta.url).href,
        ),
      },
      loader: { ".md": "text" },
    });
    const server = createCodexSecurityServer();
    const cancel =
      server._registeredTools.cancel_codex_security_scan_from_app.handler;
    const fail = server._registeredTools.fail_codex_security_scan.handler;
    const failures = [];
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
          const fixture = await fixtureRun(config);
          fixture.run.coordinatorGeneration = 1;
          const store = new FakeStore(fixture.run);
          const registry = new DeepScanCoordinatorRegistry();
          const entered = Promise.withResolvers<void>();
          const release = Promise.withResolvers<void>();
          const persistEntered = Promise.withResolvers<void>();
          const persistRelease = Promise.withResolvers<void>();
          const failureEntered = Promise.withResolvers<void>();
          const failureRelease = Promise.withResolvers<void>();
          const failureSaved = Promise.withResolvers<void>();
          const admissionEntered = Promise.withResolvers<void>();
          const admissionRelease = Promise.withResolvers<void>();
          const heartbeatRead = Promise.withResolvers<void>();
          const heartbeatRelease = Promise.withResolvers<void>();
          let publications = 0;
          let cancellation: ReturnType<typeof cancel> | undefined;
          let repeatedCancellation: ReturnType<typeof cancel> | undefined;
          let coordinator:
            | ReturnType<
                InstanceType<
                  LifecycleFixtures["DeepScanCoordinatorRegistry"]
                >["start"]
              >
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
          const lostResponse =
            stage.startsWith("lost-response") || unavailableRead;
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
            persistEntered,
            persistRelease,
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
              admissionEntered.resolve();
              await admissionRelease.promise;
              if (unavailableRead)
                throw new Error("synthetic terminal state unavailable");
            }
            if (completesDuringAdmission)
              queueMicrotask(() => {
                current.workspace.results.progress.status =
                  completedParentStatus;
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
                admissionEntered.resolve();
                await admissionRelease.promise;
              }
              if (gateHeartbeat) {
                gateHeartbeat = false;
                heartbeatRead.resolve();
                await heartbeatRelease.promise;
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
                failureEntered.resolve();
                await failureRelease.promise;
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
              stage === "unpersisted unowned failure"
                ? undefined
                : "fixture-owner",
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
                void fail(
                  {
                    scanId: fixture.run.scanId,
                    message: "synthetic external failure",
                  },
                  {},
                ).then(() => failureSaved.resolve());
              if (
                stage.endsWith("microtask") &&
                event.event === "coordinator_cleanup_settled"
              )
                queueMicrotask(() => {
                  cancellation = cancel({ scanId: fixture.run.scanId });
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
              cancellation = cancel({ scanId: fixture.run.scanId });
              void cancellation.catch(() => {});
            },
          });
          const terminal = coordinator.settled();
          void terminal.catch(() => {});
          try {
            if (stage === "stale heartbeat failure") {
              await failureEntered.promise;
              gateHeartbeat = true;
              const heartbeat = coordinator.renewHeartbeat();
              await heartbeatRead.promise;
              failureRelease.resolve();
              await failureSaved.promise;
              heartbeatRelease.resolve();
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
              cancellation ??= cancel({ scanId: fixture.run.scanId });
              void cancellation.catch(() => {});
            }
            if (stage === "final read repeated cancellation") {
              await coordinator.renewHeartbeat();
              repeatedCancellation = cancel({ scanId: fixture.run.scanId });
              void repeatedCancellation.catch(() => {});
            }
            if (pendingFailureRead) {
              const admitted = await Promise.race([
                admissionEntered.promise.then(() => true),
                persistEntered.promise.then(() => false),
                cancellation.then(
                  () => false,
                  () => false,
                ),
                coordinator.wait(undefined, 25).then(() => false),
              ]);
              if (admitted) {
                if (concurrentFailure)
                  await fail(
                    {
                      scanId: fixture.run.scanId,
                      message: "synthetic external failure",
                    },
                    {},
                  );
                repeatedCancellation = cancel({ scanId: fixture.run.scanId });
                void repeatedCancellation.catch(() => {});
                assert.equal(await coordinator.wait(undefined, 25), undefined);
                admissionRelease.resolve();
              }
            }
            if (failureDuringCleanup) await failureSaved.promise;
            release.resolve();
            if (completedParent || completesDuringAdmission) {
              persistRelease.resolve();
              assert.equal((await terminal).status, "succeeded");
              if (completesDuringAdmission)
                await assert.rejects(
                  cancellation,
                  /Only a running scan can be canceled/,
                );
              else
                assert.equal(
                  (await cancellation).structuredContent.workspace.results
                    .progress.status,
                  completedParentStatus,
                );
              assert.equal(store.run.status, "succeeded");
              assert.equal(
                current.workspace.results.progress.status,
                completedParentStatus,
              );
              assert.equal(
                current.calls.filter((command) => command === "cancel-scan")
                  .length,
                completesDuringAdmission ? 1 : 0,
              );
              continue;
            }
            if (durableFailure) {
              assert.equal((await terminal).status, stoppedStatus);
              if (unavailableRead)
                await assert.rejects(
                  cancellation,
                  /synthetic terminal state unavailable/,
                );
              else
                assert.equal(
                  (await cancellation).structuredContent.workspace.results
                    .progress.status,
                  "failed",
                );
              assert.equal(current.calls.includes("cancel-scan"), false);
              if (concurrentFailure || failureDuringCleanup)
                assert.match(
                  (await terminal).error,
                  /synthetic external failure/,
                );
              assert.equal(publications, interrupted ? 0 : 1);
              if (unavailableRead)
                assert.match(
                  (await terminal).error,
                  /synthetic worker failure/,
                );
              if (repeatedCancellation) {
                if (unavailableRead)
                  await assert.rejects(
                    repeatedCancellation,
                    /synthetic terminal state unavailable/,
                  );
                else
                  assert.equal(
                    (await repeatedCancellation).structuredContent.workspace
                      .results.progress.status,
                    "failed",
                  );
              }
              continue;
            }
            await persistEntered.promise;
            const waiting = await coordinator.wait(undefined, 25);
            persistRelease.resolve();
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
              else
                assert.equal(
                  (await cancellation).structuredContent.workspace.results
                    .progress.status,
                  "canceled",
                );
              assert.equal((await terminal).status, "succeeded");
              assert.equal(publications, 0);
              assert.deepEqual(current.calls, ["get-scan", "cancel-scan"]);
              continue;
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
              assert.equal(
                (await cancellation).structuredContent.workspace.results
                  .progress.status,
                "canceled",
              );
              assert.equal((await terminal).status, "canceled");
              assert.equal(store.run.status, "canceled");
              assert.equal(
                publications,
                stage === "unpersisted unowned failure" ? 0 : 1,
              );
              if (repeatedCancellation)
                assert.equal(
                  (await repeatedCancellation).structuredContent.workspace
                    .results.progress.status,
                  "canceled",
                );
            }
            assert.equal(current.calls[0], "get-scan");
            assert.equal(
              current.calls.filter((command) => command === "cancel-scan")
                .length,
              1,
            );
          } catch (error) {
            failures.push(
              new Error(
                `${stage}; persistence rejects=${rejectPersistence}: ${error instanceof Error ? error.message : String(error)}`,
                { cause: error },
              ),
            );
          } finally {
            release.resolve();
            persistRelease.resolve();
            failureRelease.resolve();
            heartbeatRelease.resolve();
            admissionRelease.resolve();
            registry.shutdown("fixture cleanup");
            await Promise.allSettled([
              terminal,
              cancellation,
              repeatedCancellation,
            ]);
          }
        }
      }
      for (const joined of [false, true]) {
        const fixture = await fixtureRun(config);
        const store = new FakeStore(fixture.run);
        const registry = new DeepScanCoordinatorRegistry();
        const executor = new FakeExecutor({ blockDiscoveryAfterCalls: 0 });
        const readEntered = Promise.withResolvers<void>();
        const readRelease = Promise.withResolvers<void>();
        const persistEntered = Promise.withResolvers<void>();
        const persistRelease = Promise.withResolvers<void>();
        let reads = 0;
        current = {
          store,
          registry,
          persistEntered,
          persistRelease,
          rejectPersistence: false,
          calls: [],
          workspace: {
            setup: { submitted: true },
            results: { progress: { status: "running" } },
          },
          readParent: async () => {
            if (reads++ === 0) {
              readEntered.resolve();
              await readRelease.promise;
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
          first = outcome(cancel({ scanId: fixture.run.scanId }));
          await readEntered.promise;
          if (joined) second = outcome(cancel({ scanId: fixture.run.scanId }));
          readRelease.resolve();
          assert.match(
            (await first)?.message ?? "",
            /temporary parent read failure/,
          );
          if (second) {
            const result = await Promise.race([
              second,
              coordinator.wait(undefined, 25).then(() => undefined),
            ]);
            assert.match(
              result?.message ?? "",
              /temporary parent read failure/,
            );
          }
          assert.equal(coordinator.snapshot().status, "running");
          assert.equal(await coordinator.wait(undefined, 25), undefined);
          retry = cancel({ scanId: fixture.run.scanId });
          void retry.catch(() => {});
          await persistEntered.promise;
          assert.equal(await coordinator.wait(undefined, 25), undefined);
          persistRelease.resolve();
          assert.equal(
            (await retry).structuredContent.workspace.results.progress.status,
            "canceled",
          );
          assert.equal((await coordinator.settled()).status, "canceled");
          assert.equal(
            current.calls.filter((command) => command === "cancel-scan").length,
            1,
          );
        } catch (error) {
          failures.push(
            new Error(`Admission read failure; joined=${joined}`, {
              cause: error,
            }),
          );
        } finally {
          readRelease.resolve();
          persistRelease.resolve();
          registry.shutdown("fixture cleanup");
          await Promise.allSettled([
            first,
            second,
            retry,
            coordinator.settled(),
          ]);
        }
      }
      if (failures.length)
        throw new AggregateError(failures, "Late cancellation responses");
    } finally {
      await server.close();
      Reflect.deleteProperty(globalThis, "deepScanCancellationFixture");
    }
  }

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
      async () => ({ status: "running" }),
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
      release.resolve();
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
