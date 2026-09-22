import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

export function createDeepScanWorkerFailureCases({
  fixtureRun,
  FakeStore,
  FakeExecutor,
  DeepScanCoordinator,
  DeepScanFatalError,
  DeepScanNonRetryableError,
  classifyCodexWorkerError,
  deferred,
  immediateClock,
  workerIdFromPrompt,
  promptContext,
}) {
  async function testDiscoveryParsePayloadCannotFailScan() {
    for (const output of ["config unknown", "authentication required"]) {
      const fixture = await fixtureRun({
        workers: 2,
        subagents: 0,
        stopAfterNoNew: 4,
        stopAfterConsecutiveErrors: 2,
        maxDiscoveryRuns: 4,
      });
      const store = new FakeStore(fixture.run);
      const normalExecutor = new FakeExecutor();
      const attempts = [];
      const events = [];
      const parseError = new Error(
        `Failed to parse item: ${JSON.stringify({
          type: "item.completed",
          item: {
            id: "fixture-command",
            type: "command_execution",
            command: "synthetic-command",
            aggregated_output: output,
          },
        })}`,
      );
      const coordinator = new DeepScanCoordinator({
        run: fixture.run,
        store,
        executor: {
          async run(request) {
            if (
              request.kind === "discovery" &&
              (await workerIdFromPrompt(request.promptPath)) ===
                "discovery-0001"
            ) {
              attempts.push(request.resumeThreadId);
              await request.onThreadStarted?.(
                request.resumeThreadId ?? "fixture-parse-thread",
              );
              throw classifyCodexWorkerError(parseError);
            }
            return normalExecutor.run(request);
          },
        },
        pluginRoot: fixture.pluginRoot,
        retryDelaysMs: [1, 3, 9],
        clock: immediateClock,
        log: (event) => events.push(event),
      });
      coordinator.start();

      const terminal = await coordinator.wait(undefined, 5_000);

      assert.equal(terminal?.status, "succeeded", terminal?.error);
      assert.deepEqual(attempts, [
        undefined,
        "fixture-parse-thread",
        "fixture-parse-thread",
        "fixture-parse-thread",
      ]);
      const discoveries = [...store.workers.values()].filter(
        (worker) => worker.kind === "discovery",
      );
      assert.equal(
        discoveries.filter((worker) => worker.status === "succeeded").length,
        3,
        "the sibling and subsequent discoveries must finish",
      );
      assert.equal(
        discoveries.filter((worker) => worker.status === "failed").length,
        0,
      );
      assert.equal(
        discoveries.find((worker) => worker.status === "canceled")
          ?.replaceableFailureKind,
        "transient_error",
      );
      assert.equal(
        events.filter((event) => event.event === "discovery_worker_replaced")
          .length,
        1,
      );
      assert.equal(store.failCalls, 0);
    }
  }

  async function testNonRetryableDiscoveryReplacesOnlyFailedWorker() {
    const fixture = await fixtureRun({
      workers: 2,
      subagents: 0,
      stopAfterNoNew: 10,
      stopAfterConsecutiveErrors: 2,
      maxDiscoveryRuns: 6,
    });
    const store = new FakeStore(fixture.run);
    const normalExecutor = new FakeExecutor();
    const siblingStarted = deferred();
    const failureStarted = deferred();
    const attempts = [];
    const coordinator = new DeepScanCoordinator({
      run: fixture.run,
      store,
      executor: {
        async run(request) {
          if (request.kind === "discovery") {
            const label = await workerIdFromPrompt(request.promptPath);
            if (label === "discovery-0003") {
              attempts.push(request.resumeThreadId);
              await request.onThreadStarted?.("fixture-retired-thread");
              await siblingStarted.promise;
              failureStarted.resolve();
              throw new DeepScanNonRetryableError(
                "fixture local worker failure",
              );
            }
            if (label === "discovery-0004") {
              siblingStarted.resolve();
              await failureStarted.promise;
            }
          }
          return normalExecutor.run(request);
        },
      },
      pluginRoot: fixture.pluginRoot,
      retryDelaysMs: [1, 3, 9],
      clock: immediateClock,
    });
    coordinator.start();

    const terminal = await coordinator.wait(undefined, 5_000);

    assert.equal(terminal?.status, "succeeded", terminal?.error);
    assert.deepEqual(attempts, [undefined]);
    const discoveries = [...store.workers.values()].filter(
      (worker) => worker.kind === "discovery",
    );
    assert.equal(
      discoveries.filter((worker) => worker.status === "succeeded").length,
      5,
    );
    assert.equal(
      discoveries.filter((worker) => worker.status === "failed").length,
      0,
    );
    assert.equal(
      discoveries.find((worker) => worker.status === "canceled")
        ?.replaceableFailureKind,
      "transient_error",
    );
    assert.equal(store.failCalls, 0);
  }

  async function testNonRetryableReducerPreservesInputsAndCommittedAggregate() {
    for (const failure of [
      new DeepScanNonRetryableError("fixture local reducer failure"),
      classifyCodexWorkerError(new Error("Request blocked by cyberPolicy.")),
    ]) {
      const fixture = await fixtureRun({
        workers: 2,
        subagents: 0,
        stopAfterNoNew: 10,
        stopAfterConsecutiveErrors: 2,
        maxDiscoveryRuns: 4,
      });
      const store = new FakeStore(fixture.run);
      const nextDiscovery = deferred();
      const siblingDiscovery = deferred();
      const normalExecutor = new FakeExecutor({
        discoveryCandidateId: "candidate-1",
        canonicalCandidateId: "candidate-1",
        discoveryGates: {
          "discovery-0003": nextDiscovery.promise,
          "discovery-0004": siblingDiscovery.promise,
        },
      });
      let committedResultPath;
      let committedContent;
      const failedAttempts = [];
      const coordinator = new DeepScanCoordinator({
        run: fixture.run,
        store,
        executor: {
          async run(request) {
            if (request.kind === "dedup") {
              const label = (await promptContext(request.promptPath))
                .reducerLabel;
              if (label === "dedup-0002") {
                failedAttempts.push(request.resumeThreadId);
                await request.onThreadStarted?.("fixture-retired-reducer");
                throw failure;
              }
              if (label === "dedup-0003") {
                assert.equal(request.resumeThreadId, undefined);
                assert.equal(
                  request.artifactContext.deepReducer.previousReducerResultPath,
                  committedResultPath,
                );
                assert.deepEqual(
                  store.dedupClaims[2].workerIds,
                  store.dedupClaims[1].workerIds,
                  "the replacement must receive every uncommitted input",
                );
                assert.deepEqual(
                  await readFile(committedResultPath),
                  committedContent,
                );
                siblingDiscovery.resolve();
              }
            }
            return normalExecutor.run(request);
          },
        },
        pluginRoot: fixture.pluginRoot,
        retryDelaysMs: [1, 3, 9],
        clock: immediateClock,
      });
      coordinator.start();
      await store.dedupCommitted.promise;
      committedResultPath = store.dedupCommits[0].resultManifestPath;
      committedContent = await readFile(committedResultPath);
      nextDiscovery.resolve();

      const terminal = await coordinator.wait(undefined, 5_000);

      assert.equal(terminal?.status, "succeeded", terminal?.error);
      assert.deepEqual(failedAttempts, [undefined]);
      const discoveries = [...store.workers.values()].filter(
        (worker) => worker.kind === "discovery",
      );
      assert.equal(discoveries.length, 4);
      assert.equal(
        discoveries.every((worker) => worker.status === "succeeded"),
        true,
      );
      const retiredReducer = [...store.workers.values()].find(
        (worker) => worker.kind === "dedup" && worker.status === "failed",
      );
      assert.equal(retiredReducer?.attempt, 1);
      assert.deepEqual(await readFile(committedResultPath), committedContent);
      const manifest = JSON.parse(
        await readFile(terminal.manifestPath, "utf8"),
      );
      assert.deepEqual(
        manifest.findings.map((finding) => finding.provenance.candidateId),
        ["candidate-1"],
      );
      assert.equal(store.failCalls, 0);
    }
  }

  async function testFatalReducerAbortsScanWithoutRetry(
    failureMessage = "fixture fatal reducer failure",
  ) {
    const fixture = await fixtureRun({
      workers: 2,
      subagents: 0,
      stopAfterNoNew: 10,
      stopAfterConsecutiveErrors: 2,
      maxDiscoveryRuns: 4,
    });
    const store = new FakeStore(fixture.run);
    const normalExecutor = new FakeExecutor({ blockDiscoveryAfterCalls: 2 });
    const attempts = [];
    const sleeps = [];
    const coordinator = new DeepScanCoordinator({
      run: fixture.run,
      store,
      executor: {
        async run(request) {
          if (request.kind === "dedup") {
            attempts.push(request.resumeThreadId);
            throw new DeepScanFatalError(failureMessage);
          }
          return normalExecutor.run(request);
        },
      },
      pluginRoot: fixture.pluginRoot,
      clock: {
        now: immediateClock.now,
        sleep: async (delayMs) => sleeps.push(delayMs),
      },
    });
    coordinator.start();

    const terminal = await coordinator.wait(undefined, 5_000);

    assert.equal(terminal?.status, "failed");
    assert.equal(terminal?.error, failureMessage);
    assert.deepEqual(attempts, [undefined]);
    assert.deepEqual(sleeps, []);
    assert.equal(normalExecutor.runningDiscovery, 0);
    assert.equal(store.failCalls, 1);
    assert.equal(store.dedupCommits.length, 0);
  }

  return {
    testDiscoveryParsePayloadCannotFailScan,
    testNonRetryableDiscoveryReplacesOnlyFailedWorker,
    testNonRetryableReducerPreservesInputsAndCommittedAggregate,
    testFatalReducerAbortsScanWithoutRetry,
  };
}
