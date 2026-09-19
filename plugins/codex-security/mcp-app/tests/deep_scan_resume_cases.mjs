import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";

export async function testDeepScanResumeCases({
  fixtureRun, FakeStore, FakeExecutor, DeepScanCoordinator, DeepScanCoordinatorRegistry,
  startOrJoinDeepScanCoordinator, immediateClock, eventually, promptContext, workerIdFromPrompt
}) {
  async function testPausedDiscoverySurvivesCoordinatorRestart(removeHistoricalPrompts = true) {
    const fixture = await fixtureRun({
      workers: 1,
      subagents: 0,
      stopAfterNoNew: 2,
      maxDiscoveryRuns: 2
    });
    fixture.run.userContext = "Original discovery context.";
    fixture.run.createdAt = new Date(immediateClock.now() - 30_000).toISOString();
    const originalInput = structuredClone(fixture.run);
    const handoffClaimToken = randomUUID();
    const store = new FakeStore({
      ...fixture.run,
      phase: "setup",
      coordinatorGeneration: 2,
      updatedAt: "2026-08-03T13:33:08Z"
    });
    const originalExecutor = new FakeExecutor({
      blockDiscoveryAfterCalls: 1,
      discoveryCandidateId: "candidate-original"
    });
    const original = new DeepScanCoordinator({
      run: store.run,
      store,
      executor: originalExecutor,
      pluginRoot: fixture.pluginRoot,
      clock: immediateClock,
      handoffClaimToken
    });
    original.start();
    await eventually(() => (
      [...store.workers.values()].some((worker) => (
        worker.kind === "discovery" && worker.status === "succeeded"
      ))
      && originalExecutor.discoveryCalls >= 2
    ));
    const accepted = [...store.workers.values()].find((worker) => (
      worker.kind === "discovery" && worker.status === "succeeded"
    ));
    assert.ok(accepted);

    // The waiter detached earlier; an app update now removes its MCP process
    // without canceling or finalizing the persisted scan.
    original.cancel("mcp server process restarted");
    await eventually(() => originalExecutor.runningDiscovery === 0);
    const persistedWorkers = [...store.workers.values()].map((worker) => structuredClone(worker));
    const independentReviews = {
      completed: persistedWorkers.filter((worker) => (
        worker.kind === "discovery" && worker.status === "succeeded"
      )).length,
      active: persistedWorkers.filter((worker) => (
        worker.kind === "discovery" && worker.status === "running"
      )).length,
      consolidating: persistedWorkers.some((worker) => (
        worker.kind === "dedup" && worker.status === "running"
      ))
    };
    assert.deepEqual(independentReviews, { completed: 1, active: 0, consolidating: false });
    assert.equal(store.run.status, "running");
    assert.equal(store.run.phase, "discovery");
    assert.equal(store.finishCalls.length, 0);
    assert.equal(store.failCalls, 0);
    assert.equal(store.run.manifestPath, undefined);
    await assert.rejects(
      readFile(path.join(
        fixture.run.scanDir,
        "artifacts",
        "deep_discovery",
        "coordinator-manifest.json"
      )),
      { code: "ENOENT" }
    );

    store.run = {
      ...store.run,
      dispatchedCount: 1,
      persistedWorkers
    };
    const continuationClaims = [];
    store.claimCoordinator = async (input) => {
      continuationClaims.push(structuredClone(input));
      assert.equal(input.handoffClaimToken, handoffClaimToken);
      store.run = {
        ...store.run,
        coordinatorGeneration: 3,
        updatedAt: new Date().toISOString()
      };
      return { acquired: true, run: structuredClone(store.run) };
    };
    store.heartbeatCoordinator = async () => structuredClone(store.run);
    const replacementExecutor = new FakeExecutor({ discoveryCandidateId: "candidate-next" });
    const acceptedResult = await readFile(accepted.resultManifestPath, "utf8");
    const acceptedWorkerId = await workerIdFromPrompt(accepted.promptPath);
    if (removeHistoricalPrompts) {
      await Promise.all(persistedWorkers.map((worker) => rm(worker.promptPath, { force: true })));
    }
    const resumed = await startOrJoinDeepScanCoordinator({
      begin: { run: structuredClone(store.run), shouldStart: false },
      registry: new DeepScanCoordinatorRegistry(),
      options: {
        store,
        executor: replacementExecutor,
        pluginRoot: fixture.pluginRoot,
        clock: immediateClock,
        threadId: "track-c-owning-thread",
        handoffClaimToken
      }
    });
    const terminal = await resumed.coordinator.wait(undefined, 5_000);

    assert.equal(continuationClaims.length, 1);
    assert.equal(continuationClaims[0].handoffClaimToken, handoffClaimToken);
    assert.equal(terminal?.status, "succeeded", terminal?.error);
    assert.equal(store.failCalls, 0);
    assert.equal(replacementExecutor.logicalDiscoveryWorkers.size, 1);
    assert.equal(
      replacementExecutor.logicalDiscoveryWorkers.has(acceptedWorkerId),
      false
    );
    assert.equal(store.dedupClaims.length, 1);
    assert.equal(store.dedupClaims[0].workerIds.includes(accepted.id), true);
    const manifest = JSON.parse(await readFile(terminal.manifestPath, "utf8"));
    assert.equal(manifest.scan.scanId, fixture.run.scanId);
    assert.equal(store.dedupClaims[0].workerIds.length, 2);
    assert.equal(await readFile(accepted.resultManifestPath, "utf8"), acceptedResult);
    assert.deepEqual(store.dedupClaims[0].workerIds, [
      accepted.id,
      ...[...store.workers.values()]
        .filter((worker) => worker.kind === "discovery" && worker.status === "succeeded" && worker.id !== accepted.id)
        .map((worker) => worker.id)
    ]);
    assert.deepEqual(manifest.findings.map((finding) => finding.provenance.candidateId), [
      "candidate-original", "candidate-next"
    ]);
    const newPrompt = [...replacementExecutor.discoveryPromptPaths.values()][0].values().next().value;
    assert.equal((await promptContext(newPrompt)).userContext, originalInput.userContext);
    assert.deepEqual(store.run.config, originalInput.config);
    assert.equal(store.run.createdAt, originalInput.createdAt);
    assert.equal(store.run.targetPath, originalInput.targetPath);
    assert.equal(store.run.scope, originalInput.scope);
  }

  async function testResumedDiscoveryDeadlineUsesPersistedCreationTime(
    alreadyExpired = false,
    maxTimeHours
  ) {
    const fixture = await fixtureRun({
      workers: 1,
      subagents: 0,
      stopAfterNoNew: 99,
      maxDiscoveryRuns: 8,
      ...(maxTimeHours === undefined ? {} : { maxTimeHours })
    });
    const discoveryTimeoutMs = (maxTimeHours ?? 96) * 60 * 60 * 1_000;
    let currentTime = immediateClock.now();
    const clock = {
      now: () => currentTime,
      sleep: immediateClock.sleep
    };
    const createdAt = new Date(currentTime - discoveryTimeoutMs + 30_000).toISOString();
    const store = new FakeStore({
      ...fixture.run,
      createdAt,
      phase: "setup",
      coordinatorGeneration: 2
    });
    const originalExecutor = new FakeExecutor({
      blockDiscoveryAfterCalls: 1,
      discoveryCandidateId: "candidate-1"
    });
    const original = new DeepScanCoordinator({
      run: store.run,
      store,
      executor: originalExecutor,
      pluginRoot: fixture.pluginRoot,
      clock
    });
    original.start();
    await eventually(() => (
      originalExecutor.discoveryCalls === 2
      && originalExecutor.runningDiscovery === 1
      && [...store.workers.values()].some((worker) => (
        worker.kind === "discovery" && worker.status === "succeeded"
      ))
    ));

    original.cancel("mcp server process restarted");
    await eventually(() => originalExecutor.runningDiscovery === 0);
    assert.equal(store.run.status, "running");
    assert.equal(store.run.createdAt, createdAt);
    currentTime = Date.parse(createdAt) + discoveryTimeoutMs + (alreadyExpired ? 1_000 : -1_000);
    store.run = {
      ...store.run,
      persistedWorkers: [...store.workers.values()].map((worker) => structuredClone(worker))
    };
    await Promise.all(store.run.persistedWorkers.map((worker) => rm(worker.promptPath, { force: true })));

    const resumedExecutor = new FakeExecutor({
      blockDiscovery: true,
      canonicalCandidateId: "candidate-1",
      dedupNewFindings: [1]
    });
    const resumed = new DeepScanCoordinator({
      run: store.run,
      store,
      executor: resumedExecutor,
      pluginRoot: fixture.pluginRoot,
      clock
    });
    resumed.start();
    if (!alreadyExpired) await resumedExecutor.discoveryStarted;

    const terminal = await resumed.wait(undefined, 5_000);
    assert.equal(terminal?.status, "succeeded");
    assert.equal(terminal?.terminalReason, "capped");
    assert.equal(store.failCalls, 0);
    assert.equal(resumedExecutor.discoveryCalls, alreadyExpired ? 0 : 1);
    assert.equal(resumedExecutor.dedupCalls, 1);
    assert.equal(resumedExecutor.runningDiscovery, 0);

    const manifest = JSON.parse(await readFile(terminal.manifestPath, "utf8"));
    assert.equal(store.run.config.maxTimeHours, maxTimeHours);
    assert.equal(store.dedupClaims[0].workerIds.length, 1);
    assert.equal([...store.workers.values()].some((worker) => worker.status === "canceled"), true);
    assert.deepEqual(manifest.findings.map((finding) => finding.provenance.candidateId), ["candidate-1"]);
  }

  async function testResumedManifestPreservesCompletedReducer(
    includeUnstartedReducer = false,
    removeHistoricalPrompts = true
  ) {
    const fixture = await fixtureRun({
      workers: 2,
      subagents: 0,
      stopAfterNoNew: 2,
      maxDiscoveryRuns: 3
    });
    const store = new FakeStore({ ...fixture.run, phase: "setup" });
    store.blockDedupCommitResponse = true;
    const original = new DeepScanCoordinator({
      run: store.run,
      store,
      executor: new FakeExecutor({
        discoveryCandidateId: "candidate-accepted",
        blockDiscoveryAfterCalls: 2
      }),
      pluginRoot: fixture.pluginRoot,
      clock: immediateClock
    });
    original.start();
    await store.dedupCommitPersisted.promise;
    original.cancel("mcp server process restarted");
    store.releaseDedupCommitResponse();
    await original.settled();
    await eventually(() => [...store.workers.values()].every((worker) => (
      worker.status !== "queued" && worker.status !== "running"
    )));

    let unstartedReducer;
    if (includeUnstartedReducer) {
      const artifactDir = path.join(
        fixture.run.scanDir,
        "artifacts",
        "deep_discovery",
        "dedup",
        "dedup-unstarted",
        "output"
      );
      await mkdir(artifactDir, { recursive: true });
      const promptPath = path.join(path.dirname(artifactDir), "prompt.md");
      await writeFile(promptPath, "Reducer claimed before coordinator restart.\n");
      unstartedReducer = {
        id: randomUUID(),
        kind: "dedup",
        status: "canceled",
        promptPath,
        artifactDir,
        attempt: 0,
        mergeState: "none"
      };
      store.workers.set(unstartedReducer.id, unstartedReducer);
    }

    store.run = {
      ...store.run,
      status: "running",
      phase: "discovery",
      persistedWorkers: [...store.workers.values()].map((worker) => structuredClone(worker)),
      persistedDedupInputs: store.dedupClaims.flatMap((claim) => (
        claim.workerIds.map((discoveryWorkerId, inputOrder) => ({
          dedupWorkerId: claim.id,
          discoveryWorkerId,
          inputOrder
        }))
      ))
    };
    const acceptedWorkers = store.run.persistedWorkers.filter((worker) => worker.status === "succeeded");
    const acceptedResults = await Promise.all(acceptedWorkers.map((worker) => readFile(worker.resultManifestPath, "utf8")));
    const persistedInputs = structuredClone(store.run.persistedDedupInputs);
    const persistedWorkers = structuredClone(store.run.persistedWorkers);
    const committedReducer = store.workers.get(store.dedupClaims[0].id);
    const committedResult = JSON.parse(await readFile(committedReducer.resultManifestPath, "utf8"));
    if (removeHistoricalPrompts) await rm(committedReducer.promptPath);
    const replacementExecutor = new FakeExecutor();
    const replacement = new DeepScanCoordinator({
      run: store.run,
      store,
      executor: replacementExecutor,
      pluginRoot: fixture.pluginRoot,
      clock: immediateClock
    });
    replacement.start();

    const terminal = await replacement.wait(undefined, 5_000);
    assert.equal(terminal?.status, "succeeded", terminal?.error);
    const manifest = JSON.parse(await readFile(terminal.manifestPath, "utf8"));
    assert.equal(manifest.scan.scanId, fixture.run.scanId);
    assert.equal(store.dedupCommits.length, 1);
    assert.equal(store.dedupClaims.length, 1);
    assert.equal(replacementExecutor.calls, 0, "accepted work needs no new worker launch");
    assert.deepEqual(manifest.findings, committedResult.findings);
    assert.deepEqual(store.run.persistedDedupInputs, persistedInputs);
    assert.deepEqual(store.run.persistedWorkers, persistedWorkers);
    assert.deepEqual(
      await Promise.all(acceptedWorkers.map((worker) => readFile(worker.resultManifestPath, "utf8"))),
      acceptedResults
    );
    assert.equal(store.run.persistedWorkers.some((worker) => worker.id === unstartedReducer?.id),
      includeUnstartedReducer);
  }

  async function testResumeUsesHistoricalCandidateSnapshotForEachReducer() {
    const fixture = await fixtureRun({
      workers: 3,
      subagents: 0,
      stopAfterNoNew: 10,
      maxDiscoveryRuns: 5
    });
    const store = new FakeStore(fixture.run);
    const original = new DeepScanCoordinator({
      run: fixture.run,
      store,
      executor: new FakeExecutor({
        dedupNewFindings: [1, 0],
        dedupEvidenceByCall: ["first reducer evidence", "final reducer evidence"]
      }),
      pluginRoot: fixture.pluginRoot,
      clock: immediateClock
    });
    original.start();
    assert.equal((await original.wait(undefined, 5_000))?.status, "succeeded");
    assert.equal(store.dedupClaims.length >= 2, true);

    store.run = {
      ...store.run,
      status: "running",
      phase: "discovery",
      terminalReason: undefined,
      manifestPath: undefined,
      persistedWorkers: [...store.workers.values()].map((worker) => structuredClone(worker)),
      persistedDedupInputs: store.dedupClaims.flatMap((claim) => (
        claim.workerIds.map((discoveryWorkerId, inputOrder) => ({
          dedupWorkerId: claim.id,
          discoveryWorkerId,
          inputOrder
        }))
      ))
    };
    const persistedInputs = structuredClone(store.run.persistedDedupInputs);
    await Promise.all(store.run.persistedWorkers.map((worker) => rm(worker.promptPath, { force: true })));
    const replacementExecutor = new FakeExecutor();
    const replacement = new DeepScanCoordinator({
      run: store.run,
      store,
      executor: replacementExecutor,
      pluginRoot: fixture.pluginRoot,
      clock: immediateClock
    });
    replacement.start();

    const resumed = await replacement.wait(undefined, 5_000);
    assert.equal(resumed?.status, "succeeded", resumed?.error);
    const firstReducer = store.run.persistedWorkers.find((worker) => (
      worker.kind === "dedup" && worker.promptPath.includes("dedup-0001")
    ));
    assert.ok(firstReducer);
    const firstResult = JSON.parse(await readFile(firstReducer.resultManifestPath, "utf8"));
    assert.equal(firstResult.findings[0]?.rootCause.summary, "first reducer evidence");
    const lastReducer = store.run.persistedWorkers.filter((worker) => (
      worker.kind === "dedup" && worker.status === "succeeded"
    )).at(-1);
    const latestResult = JSON.parse(await readFile(lastReducer.resultManifestPath, "utf8"));
    assert.equal(latestResult.findings[0]?.rootCause.summary, "final reducer evidence");
    const manifest = JSON.parse(await readFile(resumed.manifestPath, "utf8"));
    assert.deepEqual(manifest.findings, latestResult.findings);
    assert.deepEqual(store.run.persistedDedupInputs, persistedInputs);
    assert.equal(replacementExecutor.calls, 0);
  }

  await testPausedDiscoverySurvivesCoordinatorRestart(false);
  await testPausedDiscoverySurvivesCoordinatorRestart();
  await testResumedDiscoveryDeadlineUsesPersistedCreationTime();
  await testResumedDiscoveryDeadlineUsesPersistedCreationTime(true);
  await testResumedDiscoveryDeadlineUsesPersistedCreationTime(false, 2.5);
  await testResumedDiscoveryDeadlineUsesPersistedCreationTime(true, 96);
  await testResumedManifestPreservesCompletedReducer(false, false);
  await testResumedManifestPreservesCompletedReducer();
  await testResumedManifestPreservesCompletedReducer(true);
  await testResumeUsesHistoricalCandidateSnapshotForEachReducer();
}
