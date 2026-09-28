import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

export async function testDeepScanDeadlines({
  fixtureRun,
  FakeStore,
  FakeExecutor,
  DeepScanCoordinator,
  deferred,
  immediateClock,
  eventually,
}) {
  async function testDiscoveryDeadlineDrainsActiveReducerAndPreservesFindings() {
    const fixture = await fixtureRun({
      workers: 2,
      subagents: 0,
      stopAfterNoNew: 99,
      maxDiscoveryRuns: 12,
    });
    const store = new FakeStore(fixture.run);
    const executor = new FakeExecutor({
      blockDedup: true,
      blockDiscoveryAfterCalls: 2,
      discoveryCandidateId: "candidate-1",
      canonicalCandidateId: "candidate-1",
      dedupNewFindings: [1],
    });
    const coordinator = new DeepScanCoordinator({
      run: fixture.run,
      store,
      executor,
      pluginRoot: fixture.pluginRoot,
      clock: immediateClock,
      discoveryTimeoutMs: 500,
    });
    coordinator.start();

    await executor.dedupStarted;
    await eventually(() => executor.runningDiscovery > 0);
    await eventually(() => executor.runningDiscovery === 0);

    const discoveryCallsAtDeadline = executor.discoveryCalls;
    assert.equal(
      executor.runningDedup,
      1,
      "the deadline must let an active reducer finish",
    );
    assert.equal(executor.dedupSignal?.aborted, false);
    assert.equal(store.finishCalls.length, 0);
    executor.releaseDedup();

    const terminal = await coordinator.wait(undefined, 5_000);
    assert.equal(terminal?.status, "succeeded");
    assert.equal(terminal?.terminalReason, "capped");
    assert.equal(store.failCalls, 0);
    assert.equal(executor.discoveryCalls, discoveryCallsAtDeadline);
    assert.equal(
      terminal.dispatchedCount < fixture.run.config.maxDiscoveryRuns,
      true,
    );

    const manifest = JSON.parse(await readFile(terminal.manifestPath, "utf8"));
    assert.equal(manifest.scan.scanId, fixture.run.scanId);
    assert.deepEqual(store.finishCalls[0].omittedWorkerIds, []);
    assert.equal(
      [...store.workers.values()].some(
        (worker) => worker.status === "canceled",
      ),
      true,
    );
    assert.equal(store.dedupCommits.length, 1);
    assert.deepEqual(
      manifest.findings.map((finding) => finding.provenance.candidateId),
      ["candidate-1"],
    );
    assert.equal(
      [...store.workers.values()].some((worker) =>
        ["queued", "running"].includes(worker.status),
      ),
      false,
      "deadline completion must wait for every canceled discovery and reducer to settle",
    );
  }

  async function testDiscoveryDeadlineReducesSingleBufferedFinding() {
    const fixture = await fixtureRun({
      workers: 1,
      subagents: 0,
      stopAfterNoNew: 99,
      maxDiscoveryRuns: 8,
    });
    const store = new FakeStore(fixture.run);
    const executor = new FakeExecutor({
      blockDiscoveryAfterCalls: 1,
      discoveryCandidateId: "candidate-1",
      canonicalCandidateId: "candidate-1",
      dedupNewFindings: [1],
    });
    const coordinator = new DeepScanCoordinator({
      run: fixture.run,
      store,
      executor,
      pluginRoot: fixture.pluginRoot,
      clock: immediateClock,
      discoveryTimeoutMs: 500,
    });
    coordinator.start();

    await eventually(
      () =>
        executor.discoveryCalls === 2 &&
        executor.runningDiscovery === 1 &&
        [...store.workers.values()].some(
          (worker) =>
            worker.kind === "discovery" && worker.status === "succeeded",
        ),
    );
    assert.equal(
      executor.dedupCalls,
      0,
      "the first singleton remains buffered before the deadline",
    );

    const terminal = await coordinator.wait(undefined, 5_000);
    assert.equal(terminal?.status, "succeeded");
    assert.equal(terminal?.terminalReason, "capped");
    assert.equal(terminal.dispatchedCount, 2);
    assert.equal(
      terminal.dispatchedCount < fixture.run.config.maxDiscoveryRuns,
      true,
    );
    assert.equal(store.failCalls, 0);
    assert.equal(executor.dedupCalls, 1);
    assert.equal(executor.runningDiscovery, 0);

    const manifest = JSON.parse(await readFile(terminal.manifestPath, "utf8"));
    assert.equal(store.dedupClaims[0].workerIds.length, 1);
    assert.deepEqual(store.finishCalls[0].omittedWorkerIds, []);
    assert.equal(
      [...store.workers.values()].filter(
        (worker) => worker.status === "canceled",
      ).length,
      1,
    );
    assert.equal(store.dedupCommits.length, 1);
    assert.deepEqual(
      manifest.findings.map((finding) => finding.provenance.candidateId),
      ["candidate-1"],
    );
  }

  async function testDiscoveryAcceptedAtDeadlineIsReduced() {
    const fixture = await fixtureRun({
      workers: 1,
      subagents: 0,
      stopAfterNoNew: 99,
      maxDiscoveryRuns: 8,
    });
    const store = new FakeStore(fixture.run);
    const acceptancePersisted = deferred();
    const releaseAcceptance = deferred();
    const discoveryDeadlineReached = deferred();
    const updateWorker = store.updateWorker.bind(store);
    store.updateWorker = async (update) => {
      const persisted = await updateWorker(update);
      if (update.kind === "discovery" && update.status === "succeeded") {
        acceptancePersisted.resolve();
        await releaseAcceptance.promise;
      }
      return persisted;
    };
    const executor = new FakeExecutor({
      discoveryCandidateId: "candidate-1",
      canonicalCandidateId: "candidate-1",
      dedupNewFindings: [1],
    });
    const coordinator = new DeepScanCoordinator({
      run: fixture.run,
      store,
      executor,
      pluginRoot: fixture.pluginRoot,
      clock: immediateClock,
      discoveryTimeoutMs: 500,
      log: (event) => {
        if (event.event === "discovery_deadline_reached")
          discoveryDeadlineReached.resolve();
      },
    });
    coordinator.start();
    const terminalWait = coordinator.wait(undefined, 5_000);

    await acceptancePersisted.promise;
    await discoveryDeadlineReached.promise;
    releaseAcceptance.resolve();

    const terminal = await terminalWait;
    assert.equal(terminal?.status, "succeeded");
    assert.equal(terminal?.terminalReason, "capped");
    assert.equal(store.failCalls, 0);
    assert.equal(executor.discoveryCalls, 1);
    assert.equal(executor.dedupCalls, 1);

    const manifest = JSON.parse(await readFile(terminal.manifestPath, "utf8"));
    assert.equal(store.dedupClaims[0].workerIds.length, 1);
    assert.deepEqual(store.finishCalls[0].omittedWorkerIds, []);
    assert.equal(
      [...store.workers.values()].some(
        (worker) => worker.status === "canceled",
      ),
      false,
    );
    assert.deepEqual(
      manifest.findings.map((finding) => finding.provenance.candidateId),
      ["candidate-1"],
    );
  }

  async function testDiscoveryDeadlineWithoutAcceptedWorkersReturnsPartialEvidence() {
    const fixture = await fixtureRun({
      workers: 1,
      subagents: 0,
      stopAfterNoNew: 99,
      maxDiscoveryRuns: 8,
    });
    const store = new FakeStore(fixture.run);
    const executor = new FakeExecutor({ blockDiscovery: true });
    const completedDrafts = [];
    const coordinator = new DeepScanCoordinator({
      run: fixture.run,
      store,
      executor,
      pluginRoot: fixture.pluginRoot,
      clock: immediateClock,
      discoveryTimeoutMs: 500,
      onComplete: async (draft) => completedDrafts.push(structuredClone(draft)),
    });
    coordinator.start();
    await executor.discoveryStarted;

    const terminal = await coordinator.wait(undefined, 5_000);
    assert.equal(terminal?.status, "succeeded");
    assert.equal(terminal?.terminalReason, "capped");
    assert.equal(store.failCalls, 0);
    assert.equal(store.finishCalls.length, 1);
    assert.equal(executor.runningDiscovery, 0);
    assert.equal(executor.dedupCalls, 0);

    const manifest = JSON.parse(await readFile(terminal.manifestPath, "utf8"));
    assert.deepEqual(manifest.findings, []);
    assert.equal(manifest.coverage.completeness, "partial");
    assert.deepEqual(completedDrafts[0].coverage.deferred, [
      {
        reason:
          "The configured discovery time limit elapsed before any source review completed.",
      },
    ]);
    assert.deepEqual(store.finishCalls[0].omittedWorkerIds, []);
    assert.equal(
      [...store.workers.values()].filter(
        (worker) => worker.status === "canceled",
      ).length,
      1,
    );
    assert.equal(store.dedupCommits.length, 0);
  }

  async function testDiscoveryDeadlineBeforeWorkerDispatchReturnsPartialEvidence() {
    const fixture = await fixtureRun({
      workers: 1,
      subagents: 0,
      stopAfterNoNew: 99,
      maxDiscoveryRuns: 8,
      maxTimeHours: 1e-12,
    });
    fixture.run.createdAt = new Date(immediateClock.now()).toISOString();
    const store = new FakeStore(fixture.run);
    const executor = new FakeExecutor();
    const coordinator = new DeepScanCoordinator({
      run: fixture.run,
      store,
      executor,
      pluginRoot: fixture.pluginRoot,
      clock: immediateClock,
    });
    coordinator.start();

    const terminal = await coordinator.wait(undefined, 5_000);
    assert.equal(terminal?.status, "succeeded");
    assert.equal(terminal?.terminalReason, "capped");
    assert.equal(store.failCalls, 0);
    assert.equal(store.finishCalls.length, 1);
    assert.equal(executor.discoveryCalls, 0);
    assert.equal(executor.dedupCalls, 0);

    const manifest = JSON.parse(await readFile(terminal.manifestPath, "utf8"));
    assert.deepEqual(manifest.findings, []);
    assert.equal(manifest.coverage.completeness, "partial");
    assert.deepEqual(store.finishCalls[0].omittedWorkerIds, []);
    assert.equal(store.workers.size, 0);
  }

  async function testDiscoveryDeadlineWithoutAcceptedWorkersPublishesEmptyResults() {
    const fixture = await fixtureRun({
      workers: 1,
      subagents: 0,
      stopAfterNoNew: 99,
      maxDiscoveryRuns: 8,
      maxTimeHours: 1e-12,
    });
    fixture.run.createdAt = new Date(immediateClock.now()).toISOString();
    const store = new FakeStore(fixture.run);
    const executor = new FakeExecutor();
    const coordinator = new DeepScanCoordinator({
      run: fixture.run,
      store,
      executor,
      pluginRoot: fixture.pluginRoot,
      clock: immediateClock,
    });
    coordinator.start();

    const terminal = await coordinator.wait(undefined, 5_000);
    assert.equal(terminal?.status, "succeeded");
    assert.equal(store.failCalls, 0);
    assert.equal(store.finishCalls.length, 1);
    assert.equal(executor.discoveryCalls, 0);
    assert.equal(executor.dedupCalls, 0);
    assert.deepEqual(
      JSON.parse(await readFile(terminal.manifestPath, "utf8")).findings,
      [],
    );
  }

  await testDiscoveryDeadlineDrainsActiveReducerAndPreservesFindings();
  await testDiscoveryDeadlineReducesSingleBufferedFinding();
  await testDiscoveryAcceptedAtDeadlineIsReduced();
  await testDiscoveryDeadlineWithoutAcceptedWorkersReturnsPartialEvidence();
  await testDiscoveryDeadlineBeforeWorkerDispatchReturnsPartialEvidence();
  await testDiscoveryDeadlineWithoutAcceptedWorkersPublishesEmptyResults();
}
