import assert from "node:assert/strict";
import { readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";

export async function testDeepScanPublication({
  fixtureRun, FakeStore, FakeExecutor, DeepScanCoordinator, deferred,
  immediateClock, eventually, standardScanDraft,
}) {
  async function testSaturationPublishesFindingAcceptedDuringCancellation() {
    const fixture = await fixtureRun({ workers: 3, subagents: 0, stopAfterNoNew: 2, maxDiscoveryRuns: 3 });
    const store = new FakeStore(fixture.run);
    const releaseLateWorker = deferred();
    const lateAcceptance = deferred();
    const releaseAcceptance = deferred();
    const updateWorker = store.updateWorker.bind(store);
    let acceptedLateWorker;
    store.updateWorker = async (update) => {
      const persisted = await updateWorker(update);
      if (update.kind === "discovery" && update.status === "succeeded"
        && path.basename(path.dirname(update.promptPath)) === "discovery-0003") {
        acceptedLateWorker = persisted;
        // Publication must use the result already validated before acceptance.
        await rm(update.resultManifestPath);
        lateAcceptance.resolve();
        await releaseAcceptance.promise;
      }
      return persisted;
    };
    const executor = new FakeExecutor({
      blockDedup: true,
      discoveryGates: { "discovery-0003": releaseLateWorker.promise },
      discoveryCandidates: { "discovery-0003": "late-accepted-finding" },
    });
    const completed = [];
    const coordinator = new DeepScanCoordinator({
      run: fixture.run, store, executor, pluginRoot: fixture.pluginRoot,
      clock: immediateClock,
      onComplete: async (draft) => completed.push(structuredClone(draft)),
    });
    coordinator.start();
    await executor.dedupStarted;
    releaseLateWorker.resolve();
    await lateAcceptance.promise;
    executor.releaseDedup();
    await eventually(() => executor.dedupSignal?.aborted === true);
    releaseAcceptance.resolve();
    const terminal = await coordinator.wait(undefined, 5_000);
    assert.equal(terminal?.status, "succeeded", terminal?.error);
    assert.equal(terminal.terminalReason, "saturated");
    assert.equal(executor.discoveryCalls, 3);
    assert.equal(executor.dedupCalls, 1, "late accepted results do not restart convergence");
    assert.deepEqual(store.finishCalls[0].omittedWorkerIds, [acceptedLateWorker.id]);
    assert.equal(completed.length, 1);
    assert.equal(completed[0].coverage.completeness, "complete");
    const [finding] = completed[0].findings;
    assert.equal(completed[0].findings.length, 1);
    assert.equal(finding.provenance.candidateId, "late-accepted-finding");
    assert.deepEqual(finding.provenance.sourceFindingIds, [`${acceptedLateWorker.id}:0`]);
    assert.deepEqual(finding.provenance.sourceFindings, [{
      id: `${acceptedLateWorker.id}:0`,
      finding: standardScanDraft(fixture.run.scanId, "late-accepted-finding", "discovery-0003").findings[0],
    }]);
  }

  async function testSuccessfulDeepCoverageIgnoresWorkerAndReducerReviewStatus() {
    const fixture = await fixtureRun({ workers: 2, subagents: 0, stopAfterNoNew: 2, maxDiscoveryRuns: 2 });
    const store = new FakeStore(fixture.run);
    const executor = new FakeExecutor();
    const run = executor.run.bind(executor);
    const reviewed = { label: "Reviewed query", disposition: "no_issue_found" };
    const workerReviewed = { ...reviewed, receiptRefs: ["artifacts/missing-worker-receipt.md"] };
    const followUp = { label: "Worker follow-up", disposition: "needs_follow_up" };
    executor.run = async (request) => {
      const outcome = await run(request);
      const resultPath = path.join(request.artifactContext.root, "result.json");
      const draft = JSON.parse(await readFile(resultPath, "utf8"));
      draft.coverage = {
        completeness: request.kind === "discovery" && request.promptPath.includes("discovery-0002")
          ? "unknown" : "partial",
        surfaces: [workerReviewed, followUp],
        explicitExclusions: [],
        deferred: [{ reason: "An independent review left this question unresolved." }],
      };
      await writeFile(resultPath, JSON.stringify(draft));
      return outcome;
    };
    const completed = [];
    const coordinator = new DeepScanCoordinator({
      run: fixture.run, store, executor, pluginRoot: fixture.pluginRoot,
      clock: immediateClock,
      onComplete: async (draft) => completed.push(structuredClone(draft)),
    });
    coordinator.start();
    const terminal = await coordinator.wait(undefined, 5_000);
    assert.equal(terminal?.status, "succeeded", terminal?.error);
    assert.equal(completed.length, 1);
    assert.deepEqual(completed[0].coverage, {
      completeness: "complete", surfaces: [reviewed], explicitExclusions: [], deferred: [],
    });
    for (const worker of store.workers.values()) {
      if (worker.kind !== "discovery") continue;
      const draft = JSON.parse(await readFile(worker.resultManifestPath, "utf8"));
      assert.notEqual(draft.coverage.completeness, "complete");
      assert.deepEqual(draft.coverage.surfaces, [workerReviewed, followUp]);
      assert.equal(draft.coverage.deferred.length, 1);
    }
  }

  async function testPublicationUsesAcceptedReducerSnapshot() {
    const fixture = await fixtureRun({ workers: 1, subagents: 0, stopAfterNoNew: 1, maxDiscoveryRuns: 1 });
    const store = new FakeStore(fixture.run);
    const commitDedup = store.commitDedup.bind(store);
    store.commitDedup = async (commit) => {
      const accepted = await commitDedup(commit);
      await rm(commit.resultManifestPath);
      return accepted;
    };
    store.finish = async (input) => {
      store.finishCalls.push(input);
      Object.assign(store.run, { status: "succeeded", terminalReason: input.reason, manifestPath: input.manifestPath });
      return structuredClone(store.run);
    };
    const completed = [];
    const coordinator = new DeepScanCoordinator({
      run: fixture.run, store,
      executor: new FakeExecutor({ discoveryCandidateId: "accepted-finding" }),
      pluginRoot: fixture.pluginRoot, clock: immediateClock,
      onComplete: async (draft) => completed.push(structuredClone(draft)),
    });
    coordinator.start();
    const terminal = await coordinator.wait(undefined, 5_000);
    assert.equal(terminal?.status, "succeeded", terminal?.error);
    assert.equal(completed[0].findings[0].provenance.candidateId, "accepted-finding");
    assert.equal(completed[0].coverage.completeness, "complete");
  }

  await testSaturationPublishesFindingAcceptedDuringCancellation();
  await testSuccessfulDeepCoverageIgnoresWorkerAndReducerReviewStatus();
  await testPublicationUsesAcceptedReducerSnapshot();
}
