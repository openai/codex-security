import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { mkdir, mkdtemp, readFile, readdir, realpath, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { build } from "esbuild";
import { testDeepScanPublication } from "./deep_scan_publication_cases.mjs";

const bundle = await build({
  bundle: true,
  entryPoints: [new URL("../src/deep-scan/registry.ts", import.meta.url).pathname],
  format: "esm",
  loader: { ".md": "text" },
  platform: "node",
  write: false
});
const {
  DeepScanCoordinator,
  DeepScanCoordinatorRegistry,
  DeepScanNonRetryableError,
  DeepScanRemoteCoordinator,
  DeepScanStartLock,
  startOrJoinDeepScanCoordinator
} = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
);
const temporaryRoots = [];
async function testCappedQueueAndSerialDedup() {
  const fixture = await fixtureRun({ workers: 3, subagents: 2, stopAfterNoNew: 10, maxDiscoveryRuns: 5 });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({ dedupNewFindings: [1, 0] });
  const completedDrafts = [];
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    random: () => 0,
    retryDelaysMs: [1, 3, 9],
    clock: immediateClock,
    handoffClaimToken: "claim-fixture",
    onComplete: async (draft) => completedDrafts.push(structuredClone(draft))
  });
  coordinator.start();
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "succeeded");
  assert.equal(terminal?.terminalReason, "capped");
  assert.equal(executor.logicalDiscoveryWorkers.size, 5);
  assert.equal(executor.maximumDiscoveryConcurrency <= 3, true);
  assert.equal(executor.maximumDedupConcurrency, 1);
  assert.equal(executor.discoveryWorkingDirectories.size, 5);
  assert.equal(
    [...executor.discoveryWorkingDirectories].every((directory) => directory.endsWith(path.join("output"))),
    true
  );
  assert.equal(store.dedupClaims.length >= 2, true);
  assert.equal(new Set(store.dedupClaims.flatMap((claim) => claim.workerIds)).size, 5);

  assert.deepEqual(store.progress, [{ scanId: fixture.run.scanId, phase: "discovery", handoffClaimToken: "claim-fixture" }]);

  const manifest = JSON.parse(await readFile(terminal.manifestPath, "utf8"));
  assert.equal(manifest.scan.scanId, fixture.run.scanId);
  assert.equal(manifest.scan.mode, "deep");
  assert.deepEqual(manifest.findings.map((finding) => finding.provenance.candidateId), ["candidate-1"]);
  assert.equal(completedDrafts.length, 1);
  assert.equal(completedDrafts[0].scanId, fixture.run.scanId);
  assert.deepEqual(completedDrafts[0].findings, manifest.findings);
  const reducerWorkers = [...store.workers.values()].filter((worker) => (
    worker.kind === "dedup" && worker.status === "succeeded"
  ));
  const finalReducerResult = JSON.parse(await readFile(
    reducerWorkers.at(-1).resultManifestPath,
    "utf8"
  ));
  assert.equal(finalReducerResult.scanId, fixture.run.scanId);
  assert.deepEqual(finalReducerResult.findings, manifest.findings);
  const finalReducerContext = await promptContext(executor.dedupPromptPaths.at(-1));
  const finalReducerArtifacts = executor.dedupArtifactContexts.at(-1);
  assert.deepEqual(
    finalReducerContext.claimedWorkerIds,
    finalReducerArtifacts.deepReducer.claimedWorkers.map((worker) => worker.id)
  );
  assert.equal(Object.hasOwn(finalReducerContext, "previousReducerResultPath"), false);
  assert.equal(
    finalReducerArtifacts.deepReducer.previousReducerResultPath,
    reducerWorkers.at(-2).resultManifestPath
  );
  for (const worker of [...store.workers.values()].filter((worker) => (
    worker.kind === "discovery" && worker.status === "succeeded"
  ))) {
    const result = JSON.parse(await readFile(worker.resultManifestPath, "utf8"));
    const context = await promptContext(worker.promptPath);
    assert.equal(result.scanId, fixture.run.scanId);
    assert.match(result.threatModel.summary, new RegExp(context.workerLabel));
    assert.equal(context.pluginRoot, fixture.pluginRoot);
  }
  await assert.rejects(
    readFile(path.join(fixture.run.scanDir, "artifacts", "01_context", "threat_model.md")),
    { code: "ENOENT" },
    "the shared parent skill, not the discovery coordinator, owns final threat-model synthesis"
  );
  assert.equal(terminal.manifestPath, path.join(fixture.run.scanDir, "scan-manifest.json"));
}

async function testStandardWorkersReceiveExistingFalsePositiveFeedback() {
  const fixture = await fixtureRun({
    workers: 1,
    subagents: 0,
    stopAfterNoNew: 1,
    maxDiscoveryRuns: 1
  });
  const feedbackPath = path.join(
    fixture.run.scanDir,
    "artifacts",
    "01_context",
    "false_positive_feedback.json"
  );
  await mkdir(path.dirname(feedbackPath), { recursive: true });
  await writeFile(feedbackPath, JSON.stringify([{ reason: "existing control still applies" }]));
  const store = new FakeStore(fixture.run);
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor: new FakeExecutor(),
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock
  });
  coordinator.start();

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  const worker = [...store.workers.values()].find((candidate) => (
    candidate.kind === "discovery"
  ));
  assert.ok(worker);
  const prompt = await readFile(worker.promptPath, "utf8");
  assert.equal(prompt.includes(JSON.stringify(feedbackPath)), true);
  assert.equal(Object.hasOwn(await promptContext(worker.promptPath), "falsePositiveFeedbackPath"), false);
  await assert.rejects(readFile(path.join(
    worker.artifactDir,
    "artifacts",
    "01_context",
    "false_positive_feedback.json"
  )), { code: "ENOENT" });
}

async function testDiscoveryWorkersKeepOneContextAfterPersistedUpdate() {
  const fixture = await fixtureRun({
    workers: 1,
    subagents: 0,
    stopAfterNoNew: 10,
    maxDiscoveryRuns: 2
  });
  fixture.run.userContext = "Initial context.";
  const firstWorkerGate = deferred();
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({
    dedupNewFindings: [1],
    discoveryGates: { "discovery-0001": firstWorkerGate.promise }
  });
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock
  });
  coordinator.start();
  await executor.discoveryStarted;
  store.run.userContext = "Updated context.";
  firstWorkerGate.resolve();
  await coordinator.wait(undefined, 5_000);

  const contexts = await Promise.all(
    [...store.workers.values()]
      .filter((worker) => worker.kind === "discovery")
      .sort((left, right) => left.promptPath.localeCompare(right.promptPath))
      .map(async (worker) => (await promptContext(worker.promptPath)).userContext)
  );
  assert.deepEqual(contexts, ["Initial context.", "Initial context."]);
  assert.equal((await store.get()).userContext, "Updated context.");
}

async function testPersistedContextDoesNotChangeAnotherProcessDiscoverySnapshot() {
  const fixture = await fixtureRun({
    workers: 1,
    subagents: 0,
    stopAfterNoNew: 10,
    maxDiscoveryRuns: 2
  });
  fixture.run.userContext = "Initial cross-process context.";
  const firstWorkerGate = deferred();
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({
    dedupNewFindings: [1],
    discoveryGates: { "discovery-0001": firstWorkerGate.promise }
  });
  const owningRegistry = new DeepScanCoordinatorRegistry();
  const coordinator = owningRegistry.start({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock
  });

  await executor.discoveryStarted;
  store.run.userContext = "Updated cross-process context.";
  firstWorkerGate.resolve();
  const terminal = await coordinator.wait(undefined, 5_000);

  assert.equal(terminal?.status, "succeeded");
  const contexts = await Promise.all(
    [...store.workers.values()]
      .filter((worker) => worker.kind === "discovery")
      .sort((left, right) => left.promptPath.localeCompare(right.promptPath))
      .map(async (worker) => (await promptContext(worker.promptPath)).userContext)
  );
  assert.deepEqual(contexts, [
    "Initial cross-process context.",
    "Initial cross-process context."
  ]);
  assert.equal((await store.get()).userContext, "Updated cross-process context.");
}

async function testWorkerScopedCandidateSourceAggregation() {
  const fixture = await fixtureRun({
    workers: 2,
    subagents: 0,
    stopAfterNoNew: 10,
    maxDiscoveryRuns: 2
  });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({
    discoveryCandidateId: "candidate-1",
    canonicalCandidateId: "candidate-1",
    dedupNewFindings: [1]
  });
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock
  });
  coordinator.start();

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.terminalReason, "capped");
  const manifest = JSON.parse(await readFile(terminal.manifestPath, "utf8"));
  const expectedWorkerIds = [...store.workers.values()]
    .filter((worker) => worker.kind === "discovery" && worker.status === "succeeded")
    .sort((left, right) => left.completionSequence - right.completionSequence)
    .map((worker) => worker.id);
  assert.deepEqual(manifest.findings.map((finding) => finding.provenance.candidateId), ["candidate-1"]);
  assert.deepEqual(store.dedupClaims[0].workerIds, expectedWorkerIds);
  const reducer = [...store.workers.values()].find((worker) => worker.kind === "dedup");
  const reducerResult = JSON.parse(await readFile(reducer.resultManifestPath, "utf8"));
  assert.equal(reducerResult.scanId, fixture.run.scanId);
  assert.deepEqual(reducerResult.findings, manifest.findings);
  assert.equal(executor.dedupCalls, 1, "valid worker provenance must not retry the reducer");
}

async function testConsumedSourceIsNotRereadAfterReducerWritesResult() {
  const fixture = await fixtureRun({
    workers: 2,
    subagents: 0,
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 2
  });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({
    discoveryCandidateId: "candidate-1",
    canonicalCandidateId: "candidate-1",
    corruptAcceptedSource: true
  });
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock
  });
  coordinator.start();

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(terminal?.terminalReason, "capped");
  assert.equal(executor.dedupCalls, 1);
  assert.deepEqual(
    JSON.parse(await readFile(terminal.manifestPath, "utf8"))
      .findings.map((finding) => finding.provenance.candidateId),
    ["candidate-1"]
  );
}

async function testConsumedSourceWithToolDiagnosticIsNotRereadAfterReducerWritesResult() {
  const fixture = await fixtureRun({
    workers: 2,
    subagents: 0,
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 2
  });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({
    dedupNewFindings: [0],
    corruptAcceptedSource: true,
    dedupDiagnostics: [{
      code: "artifact_tool_failed",
      message: "Codex worker artifact tool record_codex_security_deep_reduction failed."
    }]
  });
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock
  });
  coordinator.start();

  const terminal = await coordinator.wait(undefined, 5_000);

  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(terminal?.terminalReason, "saturated");
  assert.equal(executor.dedupCalls, 1);
  assert.deepEqual(JSON.parse(await readFile(terminal.manifestPath, "utf8")).findings, []);
}

async function testRetryKeepsLogicalWorker() {
  const fixture = await fixtureRun({ workers: 2, subagents: 1, stopAfterNoNew: 2, maxDiscoveryRuns: 2 });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({ failFirstDiscoveryAttempt: true, dedupNewFindings: [0] });
  const sleeps = [];
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    random: () => 0.5,
    clock: {
      now: () => 1_700_000_000_000,
      sleep: async (delayMs, signal) => {
        assert.equal(signal.aborted, false);
        sleeps.push(delayMs);
      }
    }
  });
  coordinator.start();
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.terminalReason, "saturated", terminal?.error);
  assert.deepEqual(sleeps, [69_000]);
  assert.equal(executor.logicalDiscoveryWorkers.size, 2);
  assert.equal(executor.discoveryCalls, 3);
  const attemptsByWorker = new Map();
  for (const update of store.workerUpdates) {
    if (update.kind !== "discovery" || update.status !== "running") continue;
    const attempts = attemptsByWorker.get(update.id) ?? new Set();
    attempts.add(update.attempt);
    attemptsByWorker.set(update.id, attempts);
  }
  const retriedId = [...attemptsByWorker.entries()].find(([, attempts]) => attempts.size === 2)?.[0];
  assert.ok(retriedId);
  assert.deepEqual([...attemptsByWorker.get(retriedId)], [1, 2]);
  assert.equal(store.run.dispatchedCount, 2, "retry attempts must not count as logical discovery runs");
  const retriedPromptPaths = executor.discoveryPromptPaths.get(
    [...executor.discoveryAttempts.entries()].find(([, attempts]) => attempts === 2)?.[0]
  );
  assert.equal(retriedPromptPaths?.size, 1, "retries must reuse the identical rendered prompt path");
  assert.doesNotMatch(
    await readFile([...retriedPromptPaths][0], "utf8"),
    /Deterministic validation retry/,
    "execution failures must not be presented to the model as artifact validation feedback"
  );
}

async function testSandboxDiagnosticSurvivesArtifactRetries() {
  const fixture = await fixtureRun({ workers: 1, subagents: 1, stopAfterNoNew: 2, maxDiscoveryRuns: 1 });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({
    alwaysOmitDiscoveryArtifact: "result.json",
    discoveryDiagnostics: [{
      code: "sandbox_namespace_exhausted",
      message: "Codex worker sandbox namespace creation failed (bwrap ENOSPC)."
    }]
  });
  const sleeps = [];
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    retryDelaysMs: [1, 3, 9],
    random: () => 0,
    clock: {
      now: () => 1_700_000_000_000,
      sleep: async (delayMs) => sleeps.push(delayMs)
    }
  });
  coordinator.start();
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "failed");
  assert.deepEqual(sleeps, [1, 3, 9]);
  assert.equal(executor.discoveryCalls, 4);
  assert.deepEqual(executor.discoveryResumeThreadIds, [undefined, undefined, undefined, undefined]);
  assert.match(terminal?.error ?? "", /sandbox_namespace_exhausted|sandbox namespace creation failed/i);
  assert.match(terminal?.error ?? "", /result\.json/i);
  assert.doesNotMatch(terminal?.error ?? "", /super-secret-command|private source text/);
  await assertFailureManifest(terminal, "discovery");
}

async function testCompletionOrdering() {
  const fixture = await fixtureRun({ workers: 2, subagents: 1, stopAfterNoNew: 10, maxDiscoveryRuns: 3 });
  const store = new FakeStore(fixture.run);
  const firstWorkerGate = deferred();
  const executor = new FakeExecutor({
    dedupNewFindings: [1, 0],
    discoveryGates: { "discovery-0001": firstWorkerGate.promise }
  });
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock
  });
  coordinator.start();
  await eventually(() => store.dedupClaims.length === 1);
  firstWorkerGate.resolve();
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.terminalReason, "capped");
  const workerLabel = (workerId) => path.basename(path.dirname(store.workers.get(workerId).promptPath));
  assert.deepEqual(store.dedupClaims[0].workerIds.map(workerLabel), ["discovery-0002", "discovery-0003"]);
  assert.equal(store.workers.get(store.dedupClaims[0].workerIds[0]).completionSequence, 1);
  assert.equal(store.workers.get(store.dedupClaims[0].workerIds[1]).completionSequence, 2);
}

async function testSaturationDrainsBufferedAndCancelsInflight() {
  const fixture = await fixtureRun({ workers: 4, subagents: 1, stopAfterNoNew: 2, maxDiscoveryRuns: 6 });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({
    blockDedup: true,
    blockDiscoveryAfterCalls: 4,
    dedupNewFindings: [0]
  });
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock
  });
  coordinator.start();
  await executor.dedupStarted;
  await eventually(() => executor.discoveryCalls === 6 && executor.runningDiscovery === 2);
  executor.releaseDedup();

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.terminalReason, "saturated");
  await eventually(() => executor.runningDiscovery === 0 && executor.runningDedup === 0);
  const manifest = JSON.parse(await readFile(terminal.manifestPath, "utf8"));
  assert.equal(store.dedupClaims.length, 2, "convergence must drain already accepted output");
  assert.equal(store.dedupClaims[0].workerIds.length, 2);
  assert.equal(store.finishCalls[0].omittedWorkerIds.length, 0);
  assert.equal([...store.workers.values()].filter((worker) => worker.status === "canceled").length, 2);
  assert.deepEqual(manifest.findings, []);
  assert.equal(store.run.noNewStreak, 4);
  assert.equal(
    [...store.workers.values()].some((worker) => ["queued", "running"].includes(worker.status)),
    false,
    "saturation cleanup must persist every worker as settled before finish"
  );
}

async function testSaturationPreservesFindingAlreadyBuffered() {
  const fixture = await fixtureRun({ workers: 4, subagents: 0, stopAfterNoNew: 2, maxDiscoveryRuns: 4 });
  const store = new FakeStore(fixture.run);
  const laterDiscoveries = deferred();
  const executor = new FakeExecutor({
    blockDedup: true,
    discoveryGates: { "discovery-0003": laterDiscoveries.promise, "discovery-0004": laterDiscoveries.promise },
    discoveryCandidates: { "discovery-0003": "buffered-finding", "discovery-0004": "buffered-finding" }
  });
  const completed = [];
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock,
    onComplete: async (draft) => completed.push(draft)
  });
  coordinator.start();
  await executor.dedupStarted;
  laterDiscoveries.resolve();
  await eventually(() => [...store.workers.values()].filter((worker) => (
    worker.kind === "discovery" && worker.status === "succeeded"
  )).length === 4);
  executor.releaseDedup();
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.deepEqual(completed[0].findings.map((finding) => finding.provenance.candidateId), ["buffered-finding"]);
  assert.equal(store.finishCalls[0].omittedWorkerIds.length, 0);
}

async function testDirectReducerCannotDropAcceptedFinding() {
  const fixture = await fixtureRun({ workers: 2, subagents: 0, stopAfterNoNew: 1, maxDiscoveryRuns: 2 });
  const store = new FakeStore(fixture.run);
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor: new FakeExecutor({
      discoveryCandidates: { "discovery-0001": "first-finding", "discovery-0002": "second-finding" },
      dropLastDedupFinding: true
    }),
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock,
    retryDelaysMs: []
  });
  coordinator.start();
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "failed", "direct file output must account for all accepted inputs");
  assert.equal(store.dedupCommits.length, 0);
  assert.equal([...store.workers.values()].filter((worker) => worker.kind === "discovery" && worker.status === "succeeded").length, 2);
}

async function testDiscoveryDeadlineDrainsActiveReducerAndPreservesFindings() {
  const fixture = await fixtureRun({
    workers: 2,
    subagents: 0,
    stopAfterNoNew: 99,
    maxDiscoveryRuns: 12
  });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({
    blockDedup: true,
    blockDiscoveryAfterCalls: 2,
    discoveryCandidateId: "candidate-1",
    canonicalCandidateId: "candidate-1",
    dedupNewFindings: [1]
  });
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock,
    discoveryTimeoutMs: 500
  });
  coordinator.start();

  await executor.dedupStarted;
  await eventually(() => executor.runningDiscovery > 0);
  await eventually(() => executor.runningDiscovery === 0);

  const discoveryCallsAtDeadline = executor.discoveryCalls;
  assert.equal(executor.runningDedup, 1, "the deadline must let an active reducer finish");
  assert.equal(executor.dedupSignal?.aborted, false);
  assert.equal(store.finishCalls.length, 0);
  executor.releaseDedup();

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "succeeded");
  assert.equal(terminal?.terminalReason, "capped");
  assert.equal(store.failCalls, 0);
  assert.equal(executor.discoveryCalls, discoveryCallsAtDeadline);
  assert.equal(terminal.dispatchedCount < fixture.run.config.maxDiscoveryRuns, true);

  const manifest = JSON.parse(await readFile(terminal.manifestPath, "utf8"));
  assert.equal(manifest.scan.scanId, fixture.run.scanId);
  assert.deepEqual(store.finishCalls[0].omittedWorkerIds, []);
  assert.equal([...store.workers.values()].some((worker) => worker.status === "canceled"), true);
  assert.equal(store.dedupCommits.length, 1);
  assert.deepEqual(manifest.findings.map((finding) => finding.provenance.candidateId), ["candidate-1"]);
  assert.equal(
    [...store.workers.values()].some((worker) => ["queued", "running"].includes(worker.status)),
    false,
    "deadline completion must wait for every canceled discovery and reducer to settle"
  );
}

async function testDiscoveryDeadlineReducesSingleBufferedFinding() {
  const fixture = await fixtureRun({
    workers: 1,
    subagents: 0,
    stopAfterNoNew: 99,
    maxDiscoveryRuns: 8
  });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({
    blockDiscoveryAfterCalls: 1,
    discoveryCandidateId: "candidate-1",
    canonicalCandidateId: "candidate-1",
    dedupNewFindings: [1]
  });
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock,
    discoveryTimeoutMs: 500
  });
  coordinator.start();

  await eventually(() => (
    executor.discoveryCalls === 2
    && executor.runningDiscovery === 1
    && [...store.workers.values()].some((worker) => (
      worker.kind === "discovery" && worker.status === "succeeded"
    ))
  ));
  assert.equal(executor.dedupCalls, 0, "the first singleton remains buffered before the deadline");

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "succeeded");
  assert.equal(terminal?.terminalReason, "capped");
  assert.equal(terminal.dispatchedCount, 2);
  assert.equal(terminal.dispatchedCount < fixture.run.config.maxDiscoveryRuns, true);
  assert.equal(store.failCalls, 0);
  assert.equal(executor.dedupCalls, 1);
  assert.equal(executor.runningDiscovery, 0);

  const manifest = JSON.parse(await readFile(terminal.manifestPath, "utf8"));
  assert.equal(store.dedupClaims[0].workerIds.length, 1);
  assert.deepEqual(store.finishCalls[0].omittedWorkerIds, []);
  assert.equal([...store.workers.values()].filter((worker) => worker.status === "canceled").length, 1);
  assert.equal(store.dedupCommits.length, 1);
  assert.deepEqual(manifest.findings.map((finding) => finding.provenance.candidateId), ["candidate-1"]);
}

async function testDiscoveryAcceptedAtDeadlineIsReduced() {
  const fixture = await fixtureRun({
    workers: 1,
    subagents: 0,
    stopAfterNoNew: 99,
    maxDiscoveryRuns: 8
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
    dedupNewFindings: [1]
  });
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock,
    discoveryTimeoutMs: 500,
    log: (event) => {
      if (event.event === "discovery_deadline_reached") discoveryDeadlineReached.resolve();
    }
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
  assert.equal([...store.workers.values()].some((worker) => worker.status === "canceled"), false);
  assert.deepEqual(manifest.findings.map((finding) => finding.provenance.candidateId), ["candidate-1"]);
}

async function testDiscoveryDeadlineWithoutAcceptedWorkersReturnsPartialEvidence() {
  const fixture = await fixtureRun({
    workers: 1,
    subagents: 0,
    stopAfterNoNew: 99,
    maxDiscoveryRuns: 8
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
    onComplete: async (draft) => completedDrafts.push(structuredClone(draft))
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
  assert.deepEqual(completedDrafts[0].coverage.deferred, [{
    reason: "The configured discovery time limit elapsed before any source review completed."
  }]);
  assert.deepEqual(store.finishCalls[0].omittedWorkerIds, []);
  assert.equal([...store.workers.values()].filter((worker) => worker.status === "canceled").length, 1);
  assert.equal(store.dedupCommits.length, 0);
}

async function testDiscoveryDeadlineBeforeWorkerDispatchReturnsPartialEvidence() {
  const fixture = await fixtureRun({
    workers: 1,
    subagents: 0,
    stopAfterNoNew: 99,
    maxDiscoveryRuns: 8,
    maxTimeHours: 1e-12
  });
  fixture.run.createdAt = new Date(immediateClock.now()).toISOString();
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor();
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock
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
    maxTimeHours: 1e-12
  });
  fixture.run.createdAt = new Date(immediateClock.now()).toISOString();
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor();
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock
  });
  coordinator.start();

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "succeeded");
  assert.equal(store.failCalls, 0);
  assert.equal(store.finishCalls.length, 1);
  assert.equal(executor.discoveryCalls, 0);
  assert.equal(executor.dedupCalls, 0);
  assert.deepEqual(JSON.parse(await readFile(terminal.manifestPath, "utf8")).findings, []);
}

async function testSaturationIgnoresWorkerFailureSettledAfterStop() {
  const fixture = await fixtureRun({ workers: 3, subagents: 0, stopAfterNoNew: 2, maxDiscoveryRuns: 3 });
  const store = new FakeStore(fixture.run);
  store.blockDiscoveryFailure = true;
  const executor = new FakeExecutor({
    blockDedup: true,
    dedupNewFindings: [0],
    nonRetryableDiscoveryWorkers: ["discovery-0003"]
  });
  const completedDrafts = [];
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    retryDelaysMs: [],
    clock: immediateClock,
    threadId: "fixture-owning-thread",
    onComplete: async (draft) => completedDrafts.push(structuredClone(draft))
  });
  coordinator.start();

  await Promise.all([executor.dedupStarted, store.discoveryFailureBlocked.promise]);
  executor.releaseDedup();
  await eventually(() => executor.dedupSignal?.aborted === true);
  store.releaseDiscoveryFailure();

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(terminal?.terminalReason, "saturated");
  assert.equal(completedDrafts.length, 1);
  assert.equal(completedDrafts[0].coverage.completeness, "complete");
  assert.deepEqual(completedDrafts[0].findings, []);
  const failedWorker = [...store.workers.values()].find((worker) => (
    worker.status === "failed" && path.basename(path.dirname(worker.promptPath)) === "discovery-0003"
  ));
  assert.ok(failedWorker);
  assert.equal(failedWorker.status, "failed");
  assert.equal(store.failCalls, 0);
  assert.equal(store.finishCalls.length, 1);
  assert.equal(executor.discoveryCalls, 3);
  assert.equal(executor.dedupCalls, 1);
}

async function testSettledReducerIsNotStarvedByDiscoveryBacklog() {
  const fixture = await fixtureRun({ workers: 4, subagents: 1, stopAfterNoNew: 2, maxDiscoveryRuns: 20 });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({
    blockDedup: true,
    blockDiscoveryAfterCalls: 4,
    dedupNewFindings: [0]
  });
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock
  });
  coordinator.start();

  await executor.dedupStarted;
  await eventually(() => executor.discoveryCalls >= 8 && executor.runningDiscovery === 4);
  const dispatchedBeforeConvergence = executor.discoveryCalls;
  executor.releaseDedup();

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.terminalReason, "saturated");
  assert.equal(
    terminal?.dispatchedCount,
    dispatchedBeforeConvergence,
    "a settled reducer must stop dispatch before canceled workers can refill the pool"
  );
  assert.equal(executor.logicalDiscoveryWorkers.size, dispatchedBeforeConvergence);
}

async function testSingletonHardCapReduction() {
  const fixture = await fixtureRun({ workers: 4, subagents: 0, stopAfterNoNew: 6, maxDiscoveryRuns: 1 });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({ dedupNewFindings: [1] });
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock
  });
  coordinator.start();
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.terminalReason, "capped");
  assert.equal(executor.logicalDiscoveryWorkers.size, 1);
  assert.deepEqual(store.dedupClaims.map((claim) => claim.workerIds.length), [1]);
  const manifest = JSON.parse(await readFile(terminal.manifestPath, "utf8"));
  assert.equal(manifest.scan.scanId, fixture.run.scanId);
  assert.equal(store.dedupCommits.length, 1);
}

async function testExhaustedRetryFailsScan() {
  const fixture = await fixtureRun({ workers: 2, subagents: 1, stopAfterNoNew: 2, maxDiscoveryRuns: 2 });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({ alwaysFailDiscovery: true });
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    random: () => 0,
    retryDelaysMs: [1, 3, 9],
    clock: immediateClock
  });
  coordinator.start();
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "failed");
  assert.match(terminal?.error ?? "", /transient worker failure/);
  assert.equal(executor.discoveryCalls >= 4, true);
  assert.equal(executor.discoveryCalls <= 8, true);
  assert.equal(executor.runningDiscovery, 0);
  await assertFailureManifest(terminal, "discovery");
}

async function testCybersecurityRefusalReplacesOnlyRefusedDiscovery() {
  const fixture = await fixtureRun({
    workers: 1,
    subagents: 0,
    stopAfterNoNew: 4,
    stopAfterConsecutiveErrors: 3,
    maxDiscoveryRuns: 3
  });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({
    policyRefusalWorkers: ["discovery-0001"],
    dedupNewFindings: [1]
  });
  const sleeps = [];
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    retryDelaysMs: [1, 3, 9],
    clock: {
      now: immediateClock.now,
      sleep: async (delayMs) => sleeps.push(delayMs)
    }
  });
  coordinator.start();

  const terminal = await coordinator.wait(undefined, 5_000);

  assert.equal(terminal?.status, "succeeded");
  assert.equal(terminal?.terminalReason, "capped");
  assert.equal(executor.logicalDiscoveryWorkers.size, 3);
  assert.equal(executor.discoveryAttempts.get("discovery-0001"), 1);
  assert.deepEqual(sleeps, [], "a refused conversation must never be resumed");
  assert.equal(store.run.consecutiveErrors, 0);
  const refusal = [...store.workers.values()].find((worker) => (
    path.basename(path.dirname(worker.promptPath)) === "discovery-0001"
  ));
  assert.equal(refusal?.replaceableFailureKind, "policy_refusal");
  assert.equal(refusal?.status, "canceled");
}

async function testProviderCybersecurityRiskMessagesReplaceRefusedDiscoveryImmediately() {
  for (const message of [
    "Request blocked by cyberPolicy.",
    "Request blocked by a safety policy violation.",
    "This content was flagged for possible cybersecurity risk.",
    "This content was flagged for potentially high-risk cyber activity.",
  ]) {
    const fixture = await fixtureRun({
      workers: 1,
      subagents: 0,
      stopAfterNoNew: 4,
      stopAfterConsecutiveErrors: 3,
      maxDiscoveryRuns: 3,
    });
    const store = new FakeStore(fixture.run);
    const executor = new FakeExecutor({
      policyRefusalWorkers: ["discovery-0001"],
      policyRefusalMessages: { "discovery-0001": message },
      nonRetryablePolicyRefusalWorkers: ["discovery-0001"],
      dedupNewFindings: [1],
    });
    const sleeps = [];
    const coordinator = new DeepScanCoordinator({
      run: fixture.run,
      store,
      executor,
      pluginRoot: fixture.pluginRoot,
      random: () => 0,
      retryDelaysMs: [1, 3, 9],
      clock: {
        now: immediateClock.now,
        sleep: async (delayMs) => sleeps.push(delayMs),
      },
    });
    coordinator.start();

    const terminal = await coordinator.wait(undefined, 5_000);

    assert.equal(terminal?.status, "succeeded", message);
    assert.equal(executor.discoveryAttempts.get("discovery-0001"), 1, message);
    assert.deepEqual(
      sleeps,
      [],
      `a refused conversation must not be resumed: ${message}`,
    );
    assert.equal(store.run.consecutiveErrors, 0, message);
    assert.equal(
      [...store.workers.values()].find((worker) => (
        path.basename(path.dirname(worker.promptPath)) === "discovery-0001"
      ))?.replaceableFailureKind,
      "policy_refusal",
      message,
    );
  }
}

async function testRateLimitAndUnrelatedRefusalsRetainTransientRecovery() {
  for (const message of [
    "RateLimitExhaustedError: request rate limit reached; "
      + "This content was flagged for possible cybersecurity risk.",
    "429 Too Many Requests: flagged for potentially high-risk cyber activity.",
    "429 Too Many Requests: Request blocked by cyberPolicy.",
    "ordinary model refusal [HTTP 400]",
    "generic safety/security error [HTTP 403]",
  ]) {
    const fixture = await fixtureRun({
      workers: 1,
      subagents: 0,
      stopAfterNoNew: 4,
      stopAfterConsecutiveErrors: 2,
      maxDiscoveryRuns: 3,
    });
    const store = new FakeStore(fixture.run);
    const executor = new FakeExecutor({
      policyRefusalWorkers: ["discovery-0001"],
      policyRefusalMessages: { "discovery-0001": message },
      dedupNewFindings: [1],
    });
    const sleeps = [];
    const coordinator = new DeepScanCoordinator({
      run: fixture.run,
      store,
      executor,
      pluginRoot: fixture.pluginRoot,
      random: () => 0,
      retryDelaysMs: [1, 3, 9],
      clock: {
        now: immediateClock.now,
        sleep: async (delayMs) => sleeps.push(delayMs),
      },
    });
    coordinator.start();

    const terminal = await coordinator.wait(undefined, 5_000);

    assert.equal(terminal?.status, "succeeded", message);
    assert.equal(executor.discoveryAttempts.get("discovery-0001"), 4, message);
    assert.deepEqual(sleeps, [1, 3, 9], message);
    assert.equal(store.run.consecutiveErrors, 0, message);
    assert.equal(
      [...store.workers.values()].find((worker) => (
        path.basename(path.dirname(worker.promptPath)) === "discovery-0001"
      ))?.replaceableFailureKind,
      "transient_error",
      message,
    );
  }
}

async function testConsecutiveCybersecurityRefusalsFailAtConfiguredThreshold() {
  const fixture = await fixtureRun({
    workers: 1,
    subagents: 0,
    stopAfterNoNew: 6,
    stopAfterConsecutiveErrors: 2,
    maxDiscoveryRuns: 10
  });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({
    policyRefusalWorkers: ["discovery-0001", "discovery-0002"],
    policyRefusalMessages: {
      "discovery-0001": "Request blocked by cyberPolicy.",
      "discovery-0002": "Request blocked by cyberPolicy."
    },
    nonRetryablePolicyRefusalWorkers: ["discovery-0001", "discovery-0002"]
  });
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    retryDelaysMs: [1, 3, 9],
    clock: immediateClock
  });
  coordinator.start();

  const terminal = await coordinator.wait(undefined, 5_000);

  assert.equal(terminal?.status, "failed");
  assert.match(terminal?.error ?? "", /2 consecutive unsuccessful discovery workers/);
  assert.match(terminal?.error ?? "", /policy_refusal/);
  assert.equal(executor.logicalDiscoveryWorkers.size, 2);
  assert.equal(executor.discoveryCalls, 2);
  assert.equal(store.run.consecutiveErrors, 2);
  assert.equal(store.finishCalls.length, 0);
  await assertFailureManifest(terminal, "discovery");
  assert.deepEqual(
    [...store.workers.values()].map((worker) => worker.replaceableFailureKind),
    ["policy_refusal", "policy_refusal"]
  );
}

async function testExhaustedTransientDiscoveryIsReplaced() {
  const fixture = await fixtureRun({
    workers: 1,
    subagents: 0,
    stopAfterNoNew: 4,
    stopAfterConsecutiveErrors: 2,
    maxDiscoveryRuns: 3
  });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({
    transientFailureWorkers: ["discovery-0001"],
    dedupNewFindings: [1]
  });
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    retryDelaysMs: [1, 3, 9],
    clock: immediateClock
  });
  coordinator.start();

  const terminal = await coordinator.wait(undefined, 5_000);

  assert.equal(terminal?.status, "succeeded");
  assert.equal(executor.discoveryAttempts.get("discovery-0001"), 4);
  assert.equal(executor.logicalDiscoveryWorkers.size, 3);
  assert.equal(store.run.consecutiveErrors, 0);
  assert.equal(
    [...store.workers.values()].find((worker) => (
      path.basename(path.dirname(worker.promptPath)) === "discovery-0001"
    ))?.replaceableFailureKind,
    "transient_error"
  );
}

async function testSuccessfulDiscoveryResetsConsecutiveFailureThreshold() {
  const fixture = await fixtureRun({
    workers: 1,
    subagents: 0,
    stopAfterNoNew: 8,
    stopAfterConsecutiveErrors: 2,
    maxDiscoveryRuns: 5
  });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({
    policyRefusalWorkers: ["discovery-0001", "discovery-0003"],
    dedupNewFindings: [1]
  });
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    retryDelaysMs: [1, 3, 9],
    clock: immediateClock
  });
  coordinator.start();

  const terminal = await coordinator.wait(undefined, 5_000);

  assert.equal(terminal?.status, "succeeded");
  assert.equal(executor.logicalDiscoveryWorkers.size, 5);
  assert.equal(store.run.consecutiveErrors, 0);
  assert.equal(
    [...store.workers.values()].filter((worker) => worker.replaceableFailureKind === "policy_refusal")
      .length,
    2
  );
}

async function testExhaustedInvalidDiscoveryArtifactsAreReplaced() {
  const fixture = await fixtureRun({
    workers: 1,
    subagents: 0,
    stopAfterNoNew: 4,
    stopAfterConsecutiveErrors: 2,
    maxDiscoveryRuns: 3
  });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({
    invalidDiscoveryAttempts: 4,
    dedupNewFindings: [1]
  });
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    retryDelaysMs: [1, 3, 9],
    clock: immediateClock
  });
  coordinator.start();

  const terminal = await coordinator.wait(undefined, 5_000);

  assert.equal(terminal?.status, "succeeded");
  assert.equal(executor.discoveryAttempts.get("discovery-0001"), 4);
  assert.equal(executor.logicalDiscoveryWorkers.size, 3);
  assert.equal(
    [...store.workers.values()].find((worker) => (
      path.basename(path.dirname(worker.promptPath)) === "discovery-0001"
    ))?.replaceableFailureKind,
    "invalid_discovery_artifacts"
  );
}

async function testExhaustedMalformedDiscoveryDoesNotRemainPublishable() {
  const fixture = await fixtureRun({
    workers: 1,
    subagents: 0,
    stopAfterNoNew: 4,
    stopAfterConsecutiveErrors: 2,
    maxDiscoveryRuns: 3
  });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({
    malformedDiscoveryAttempts: 4,
    dedupNewFindings: [1]
  });
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    retryDelaysMs: [1, 3, 9],
    clock: immediateClock
  });
  coordinator.start();

  const terminal = await coordinator.wait(undefined, 5_000);

  assert.equal(terminal?.status, "succeeded");
  assert.equal(executor.discoveryAttempts.get("discovery-0001"), 4);
  await assert.rejects(
    readFile(path.join(
      fixture.run.scanDir,
      "artifacts",
      "deep_discovery",
      "workers",
      "discovery-0001",
      "output",
      "result.json"
    )),
    { code: "ENOENT" },
    "an exhausted invalid result must not remain available to stopped-result recovery"
  );
}

async function testTransientExecutionFailureResumesWorkerThread() {
  const fixture = await fixtureRun({
    workers: 1,
    subagents: 1,
    stopAfterNoNew: 1,
    maxDiscoveryRuns: 1
  });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({
    failFirstDiscoveryAttempt: true,
    writePartialBeforeFailure: true,
    dedupNewFindings: [0]
  });
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    retryDelaysMs: [1],
    clock: immediateClock
  });
  coordinator.start();
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "succeeded");
  assert.equal(executor.discoveryCalls, 2);
  assert.equal(executor.discoveryResumeThreadIds[0], undefined);
  assert.equal(executor.discoveryResumeThreadIds[1], executor.discoveryThreadIds[0]);
  assert.equal(new Set(executor.discoveryThreadIds).size, 1);
  assert.match(
    executor.discoveryContinuationPrompts[1] ?? "",
    /transient Codex execution failure/
  );
  assert.match(executor.discoveryContinuationPrompts[1] ?? "", /Standard security scan/);
  assert.match(executor.discoveryContinuationPrompts[1] ?? "", /record_codex_security_scan_draft/);
  assert.doesNotMatch(executor.discoveryContinuationPrompts[1] ?? "", /\b(?:Deep|artifacts?|rebuild)\b/i);
  const [workingDirectory] = executor.discoveryWorkingDirectories;
  assert.equal(
    await readFile(path.join(workingDirectory, "partial-progress.txt"), "utf8"),
    "preserve me\n"
  );
}

async function testConfigurationFailureDoesNotRetry() {
  const fixture = await fixtureRun({ workers: 1, subagents: 0, stopAfterNoNew: 1, maxDiscoveryRuns: 1 });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({ nonRetryableDiscovery: true });
  const sleeps = [];
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: {
      now: immediateClock.now,
      sleep: async (delayMs) => sleeps.push(delayMs)
    }
  });
  coordinator.start();
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "failed");
  assert.equal(executor.discoveryCalls, 1);
  assert.deepEqual(sleeps, []);
}

async function testFailureManifestWriteDoesNotMaskOriginalError() {
  const fixture = await fixtureRun({ workers: 1, subagents: 0, stopAfterNoNew: 1, maxDiscoveryRuns: 1 });
  const store = new FakeStore(fixture.run);
  const manifestPath = path.join(
    fixture.run.scanDir,
    "artifacts",
    "deep_discovery",
    "coordinator-manifest.json"
  );
  await mkdir(manifestPath, { recursive: true });
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor: new FakeExecutor({ nonRetryableDiscovery: true }),
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock
  });
  coordinator.start();
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "failed");
  assert.match(terminal?.error ?? "", /fixture configuration failure/);
  assert.equal(terminal?.manifestPath, undefined);
  assert.equal(store.failCalls, 1);
}

async function testFinishPersistenceFailureRewritesManifestAsFailure() {
  const fixture = await fixtureRun({ workers: 1, subagents: 0, stopAfterNoNew: 1, maxDiscoveryRuns: 1 });
  const store = new FakeStore(fixture.run);
  store.failFinish = true;
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor: new FakeExecutor({ dedupNewFindings: [0] }),
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock
  });
  coordinator.start();
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "failed");
  assert.match(terminal?.error ?? "", /fixture finish persistence failure/);
  await assertFailureManifest(terminal, "terminal");
}

async function testLostFinishResponseReplaysWithoutOverwritingSuccessManifest() {
  const fixture = await fixtureRun({ workers: 1, subagents: 0, stopAfterNoNew: 1, maxDiscoveryRuns: 1 });
  const store = new FakeStore(fixture.run);
  store.loseFirstFinishResponseAfterCommit = true;
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor: new FakeExecutor({ dedupNewFindings: [0] }),
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock
  });
  coordinator.start();

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "succeeded");
  assert.equal(store.finishCalls.length, 2);
  assert.deepEqual(store.finishCalls[1], store.finishCalls[0]);
  assert.equal(store.failCalls, 0);
  const manifest = JSON.parse(await readFile(terminal.manifestPath, "utf8"));
  assert.equal(manifest.scan.scanId, fixture.run.scanId);
}

async function testLostWorkerCommitResponsesReplayIdempotently() {
  const fixture = await fixtureRun({ workers: 1, subagents: 0, stopAfterNoNew: 1, maxDiscoveryRuns: 1 });
  const store = new FakeStore(fixture.run);
  store.loseFirstDiscoveryAcceptanceResponseAfterCommit = true;
  store.loseFirstDedupCommitResponseAfterCommit = true;
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor: new FakeExecutor({ dedupNewFindings: [0] }),
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock
  });
  coordinator.start();

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "succeeded");
  assert.equal(store.discoveryAcceptanceResponseLosses, 1);
  assert.equal(store.dedupCommitResponseLosses, 1);
  assert.equal(store.dedupCommitCalls.length, 2);
  assert.equal(store.dedupCommits.length, 1);
  assert.equal(store.failCalls, 0);
}

async function testCommittedReducerIsReconciledBeforeDiscoveryFailureManifest() {
  const fixture = await fixtureRun({ workers: 3, subagents: 0, stopAfterNoNew: 10, maxDiscoveryRuns: 3 });
  const thirdWorkerGate = deferred();
  const store = new FakeStore(fixture.run);
  store.blockDedupCommitResponse = true;
  const executor = new FakeExecutor({
    dedupNewFindings: [0],
    discoveryGates: { "discovery-0003": thirdWorkerGate.promise },
    failDiscoveryWorkersAfterGate: ["discovery-0003"]
  });
  const completedDrafts = [];
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    retryDelaysMs: [],
    clock: immediateClock,
    threadId: "fixture-owning-thread",
    onComplete: async (draft) => completedDrafts.push(structuredClone(draft))
  });
  coordinator.start();

  await store.dedupCommitPersisted.promise;
  thirdWorkerGate.resolve();
  await eventually(() => executor.dedupSignal?.aborted === true);
  store.releaseDedupCommitResponse();

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "failed");
  assert.equal(terminal?.terminalReason, undefined);
  assert.equal(completedDrafts.length, 0);
  assert.match(terminal.error, /fixture late discovery failure/);
  assert.equal(store.dedupCommits.length, 1);
  assert.equal(store.dedupClaims[0].workerIds.length, 2);
  assert.equal(store.run.noNewStreak, 2);
}

async function testLongWorkerErrorIsBoundedOnlyAtPersistenceBoundary() {
  const fixture = await fixtureRun({ workers: 1, subagents: 0, stopAfterNoNew: 1, maxDiscoveryRuns: 1 });
  const store = new FakeStore(fixture.run);
  const fullError = `fixture long validator error: ${"x".repeat(5_000)}`;
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor: new FakeExecutor({ longDiscoveryFailure: fullError }),
    pluginRoot: fixture.pluginRoot,
    retryDelaysMs: [1, 3, 9],
    random: () => 0,
    clock: immediateClock
  });
  coordinator.start();

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "failed");
  assert.equal(store.failureInputs[0].message.length <= 2_400, true);
  assert.match(store.failureInputs[0].message, /truncated; sha256:/);
  assert.equal(terminal.manifestPath, undefined);
  const [worker] = [...store.workers.values()];
  assert.equal(worker.status, "canceled");
  assert.equal(worker.attempt, 4);
  assert.match(worker.error, /truncated; sha256:/);
}

async function testDiscoveryPhasePersistenceFailureStopsDispatch() {
  const fixture = await fixtureRun({ workers: 2, subagents: 1, stopAfterNoNew: 2, maxDiscoveryRuns: 2 });
  const store = new FakeStore(fixture.run);
  store.failProgressAt = 1;
  const executor = new FakeExecutor();
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock
  });
  coordinator.start();
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "failed");
  assert.match(terminal?.error ?? "", /fixture progress persistence failure/);
  assert.equal(executor.logicalDiscoveryWorkers.size, 0);
  await assertFailureManifest(terminal, "discovery");
}

async function testCancellationClearsRetryWait() {
  const fixture = await fixtureRun({ workers: 1, subagents: 1, stopAfterNoNew: 2, maxDiscoveryRuns: 1 });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({ failFirstDiscoveryAttempt: true, blockDiscoveryAfterCalls: 1 });
  const sleepStarted = deferred();
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: {
      now: immediateClock.now,
      sleep: async (_delayMs, signal) => {
        sleepStarted.resolve();
        await waitForAbort(signal);
      }
    }
  });
  coordinator.start();
  await sleepStarted.promise;
  const callsAtCancellation = executor.discoveryCalls;
  coordinator.cancel("cancel retry wait");
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "canceled");
  await eventually(() => executor.runningDiscovery === 0);
  assert.equal(
    executor.discoveryCalls,
    callsAtCancellation,
    "canceling a retry delay must not launch another attempt"
  );
}

async function testMissingDiscoveryResultResumesExistingThread(withToolFailure = false) {
  const fixture = await fixtureRun({ workers: 1, subagents: 0, stopAfterNoNew: 1, maxDiscoveryRuns: 1 });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({
    dedupNewFindings: [0],
    omitFirstDiscoveryArtifact: true,
    ...(withToolFailure ? {
      discoveryDiagnostics: [{
        code: "artifact_tool_failed",
        message: "Codex worker artifact tool record_codex_security_scan_draft failed."
      }]
    } : {})
  });
  const sleeps = [];
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    random: () => 0,
    retryDelaysMs: [1, 3, 9],
    clock: {
      now: immediateClock.now,
      sleep: async (delayMs) => sleeps.push(delayMs)
    }
  });
  coordinator.start();

  const terminal = await coordinator.wait(undefined, 5_000);

  assert.equal(terminal?.status, "succeeded");
  assert.equal(executor.discoveryCalls, 2);
  assert.deepEqual(sleeps, [1]);
  assert.deepEqual(executor.discoveryResumeThreadIds, [undefined, executor.discoveryThreadIds[0]]);
  assert.equal(new Set(executor.discoveryThreadIds).size, 1);
  const continuation = executor.discoveryContinuationPrompts[1] ?? "";
  assert.match(continuation, /completed source analysis/);
  assert.match(
    continuation,
    /record_codex_security_scan_draft\(\{ scanId, scope\?, threatModel\?, findings, coverage \}\)/
  );
  assert.doesNotMatch(continuation, /\b(?:Deep|artifacts?|rebuild)\b/i);
  assert.equal([...executor.discoveryPromptPaths.values()][0].size, 1);
  await assert.rejects(
    realpath(path.join(
      fixture.run.scanDir,
      "artifacts",
      "deep_discovery",
      "workers",
      "discovery-0001",
      "attempts",
      "attempt-01"
    )),
    { code: "ENOENT" },
    "same-thread completion must preserve the Standard scan workspace instead of archiving it"
  );
}

async function testInvalidArtifactsRetry() {
  const fixture = await fixtureRun({ workers: 2, subagents: 1, stopAfterNoNew: 2, maxDiscoveryRuns: 2 });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({
    dedupNewFindings: [0],
    malformedDiscoveryAttempts: 1
  });
  const sleeps = [];
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    random: () => 0,
    retryDelaysMs: [1, 3, 9],
    clock: {
      now: immediateClock.now,
      sleep: async (delayMs, signal) => {
        assert.equal(signal.aborted, false);
        sleeps.push(delayMs);
      }
    }
  });
  coordinator.start();
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.terminalReason, "saturated");
  assert.deepEqual(sleeps, [1]);
  assert.equal(executor.discoveryCalls, 3);
  const retriedPromptPaths = executor.discoveryPromptPaths.get(
    [...executor.discoveryAttempts.entries()].find(([, attempts]) => attempts === 2)?.[0]
  );
  const retriedWorkerId = [...executor.discoveryAttempts.entries()]
    .find(([, attempts]) => attempts === 2)?.[0];
  assert.deepEqual(
    executor.discoveryResumeThreadIdsByWorker.get(retriedWorkerId),
    [undefined, undefined],
    "deterministic validation retries must start a clean thread"
  );
  assert.equal(retriedPromptPaths?.size, 2);
  const [basePromptPath, retryPromptPath] = [...retriedPromptPaths];
  const retriedContext = await promptContext(basePromptPath);
  assert.equal(Object.hasOwn(retriedContext, "inScopeFilesPath"), false);
  const workerRoot = path.join(
    fixture.run.scanDir,
    "artifacts",
    "deep_discovery",
    "workers",
    retriedContext.workerLabel
  );
  const retriedResult = JSON.parse(await readFile(path.join(workerRoot, "output", "result.json"), "utf8"));
  assert.equal(retriedResult.scanId, fixture.run.scanId);
  assert.equal(
    await readFile(path.join(workerRoot, "attempts", "attempt-01", "result.json"), "utf8"),
    "{malformed"
  );
  const basePrompt = await readFile(basePromptPath, "utf8");
  const retriedPrompt = await readFile(retryPromptPath, "utf8");
  assert.doesNotMatch(basePrompt, /Deterministic validation retry/);
  assert.match(retriedPrompt, /Deterministic validation retry after attempt 1/);
  const retryInstructions = retriedPrompt
    .split("## Deterministic validation retry after attempt 1")[1]
    ?.split('{"validation_error":')[0] ?? "";
  assert.match(retryInstructions, /Standard security review/);
  assert.match(retryInstructions, /record_codex_security_scan_draft/);
  assert.doesNotMatch(retryInstructions, /\b(?:Deep|artifacts?|rebuild)\b/i);
  assert.match(retriedPrompt, /result\.json/);
  assert.equal(
    new Set(store.workerUpdates
      .filter((update) => [basePromptPath, retryPromptPath].includes(update.promptPath))
      .map((update) => update.promptPath)).size,
    1,
    "persistence must retain the immutable base prompt path"
  );
}

async function testInvalidReducerResultRetriesFromSnapshot(missingCandidateLedger = false) {
  const fixture = await fixtureRun({ workers: 2, subagents: 1, stopAfterNoNew: 2, maxDiscoveryRuns: 2 });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({
    dedupNewFindings: [0],
    ...(missingCandidateLedger
      ? {
        omitFirstDedupCandidateLedger: true,
        dedupDiagnostics: [{
          code: "artifact_tool_failed",
          message: "Codex worker artifact tool record_codex_security_deep_reduction failed."
        }]
      }
      : { invalidFirstDedupResult: true })
  });
  const sleeps = [];
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    random: () => 0,
    retryDelaysMs: [1, 3, 9],
    clock: {
      now: immediateClock.now,
      sleep: async (delayMs) => sleeps.push(delayMs)
    }
  });
  coordinator.start();
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.terminalReason, "saturated", terminal?.error);
  assert.deepEqual(sleeps, [1]);
  assert.equal(executor.dedupCalls, 2);
  const reducerPrompts = store.workerUpdates
    .filter((update) => update.kind === "dedup" && update.status === "running")
    .map((update) => update.promptPath);
  assert.equal(new Set(reducerPrompts).size, 1);
  assert.equal(new Set(executor.dedupPromptPaths).size, missingCandidateLedger ? 1 : 2);
  const [basePromptPath, retryPromptPath] = [...new Set(executor.dedupPromptPaths)];
  assert.doesNotMatch(await readFile(basePromptPath, "utf8"), /Deterministic validation retry/);
  if (missingCandidateLedger) {
    assert.deepEqual(executor.dedupResumeThreadIds, [undefined, executor.dedupThreadIds[0]],
      "an incomplete tool submission must resume its existing reducer conversation");
  } else {
    assert.match(await readFile(retryPromptPath, "utf8"), /Deterministic validation retry after attempt 1/);
    assert.deepEqual(executor.dedupResumeThreadIds, [undefined, undefined],
      "an invalid reducer result must still retry in a clean conversation");
  }
}

async function testMissingReducerResultResumesExistingThread() {
  const fixture = await fixtureRun({
    workers: 1,
    subagents: 0,
    stopAfterNoNew: 1,
    stopAfterConsecutiveErrors: 2,
    maxDiscoveryRuns: 1
  });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({
    missingDedupResultsByLabel: { "dedup-0001": 1 },
    dedupDiagnostics: [{
      code: "artifact_tool_failed",
      message: "Codex worker artifact tool record_codex_security_deep_reduction failed."
    }]
  });
  const sleeps = [];
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    random: () => 0,
    retryDelaysMs: [1, 3, 9],
    clock: {
      now: immediateClock.now,
      sleep: async (delayMs) => sleeps.push(delayMs)
    }
  });
  coordinator.start();

  const terminal = await coordinator.wait(undefined, 5_000);

  assert.equal(terminal?.status, "succeeded");
  assert.equal(store.dedupClaims.length, 1);
  assert.equal(executor.dedupCalls, 2);
  assert.deepEqual(sleeps, [1]);
  assert.deepEqual(executor.dedupResumeThreadIds, [undefined, executor.dedupThreadIds[0]]);
  assert.equal(new Set(executor.dedupThreadIds).size, 1);
  assert.match(
    executor.dedupContinuationPrompts[1] ?? "",
    /record_codex_security_deep_reduction\(\{ scanId, findings, threatModel\?, scope\? \}\)/
  );
  assert.doesNotMatch(executor.dedupContinuationPrompts[1] ?? "", /\{ candidates, merges \}/);
  assert.match(executor.dedupContinuationPrompts[1] ?? "", /retry the call until it succeeds/);
  assert.equal(new Set(executor.dedupPromptPaths).size, 1);
  await assert.rejects(
    realpath(path.join(
      fixture.run.scanDir,
      "artifacts",
      "deep_discovery",
      "dedup",
      "dedup-0001",
      "attempts",
      "attempt-01"
    )),
    { code: "ENOENT" },
    "same-thread completion must preserve reducer artifacts instead of archiving them"
  );
}

async function testExhaustedReducerIsReplacedAtDiscoveryLimit() {
  const fixture = await fixtureRun({
    workers: 2,
    subagents: 0,
    stopAfterNoNew: 4,
    stopAfterConsecutiveErrors: 2,
    maxDiscoveryRuns: 2
  });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({
    discoveryCandidateId: "candidate-1",
    canonicalCandidateId: "candidate-1",
    missingDedupResultsByLabel: { "dedup-0001": 4 },
    dedupDiagnostics: [{
      code: "artifact_tool_failed",
      message: "Codex worker artifact tool record_codex_security_deep_reduction failed."
    }]
  });
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    retryDelaysMs: [1, 3, 9],
    clock: immediateClock
  });
  coordinator.start();

  const terminal = await coordinator.wait(undefined, 5_000);

  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(terminal?.terminalReason, "capped");
  assert.equal(terminal?.dispatchedCount, 2);
  assert.equal(store.dedupClaims.length, 2);
  assert.deepEqual(store.dedupClaims[1].workerIds, store.dedupClaims[0].workerIds);
  assert.equal(executor.dedupAttemptsByLabel.get("dedup-0001"), 4);
  assert.equal(executor.dedupAttemptsByLabel.get("dedup-0002"), 1);
  assert.deepEqual(
    executor.dedupResumeThreadIds.slice(0, 4),
    [undefined, executor.dedupThreadIds[0], executor.dedupThreadIds[0], executor.dedupThreadIds[0]]
  );
  assert.equal(executor.dedupResumeThreadIds[4], undefined);
  const manifest = JSON.parse(await readFile(terminal.manifestPath, "utf8"));
  assert.deepEqual(manifest.findings.map((finding) => finding.provenance.candidateId), ["candidate-1"]);
  assert.equal(store.dedupCommits.length, 1);
  const failedReducer = [...store.workers.values()].find((worker) => (
    worker.kind === "dedup" && worker.status === "failed"
  ));
  assert.equal(path.basename(path.dirname(failedReducer.promptPath)), "dedup-0001");
  assert.equal(failedReducer?.attempt, 4);
  assert.match(failedReducer?.error ?? "", /result\.json/);
}

async function testExhaustedReducerPreservesCommittedArtifacts() {
  const fixture = await fixtureRun({
    workers: 2,
    subagents: 0,
    stopAfterNoNew: 99,
    stopAfterConsecutiveErrors: 2,
    maxDiscoveryRuns: 3
  });
  const nextDiscovery = deferred();
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({
    discoveryCandidateId: "candidate-1",
    canonicalCandidateId: "candidate-1",
    discoveryGates: { "discovery-0003": nextDiscovery.promise },
    invalidDedupFromCall: 2
  });
  const completedDrafts = [];
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    retryDelaysMs: [1],
    clock: immediateClock,
    threadId: "fixture-owning-thread",
    onComplete: async (draft) => completedDrafts.push(structuredClone(draft))
  });
  coordinator.start();

  await store.dedupCommitted.promise;
  const committedResultPath = store.dedupCommits[0].resultManifestPath;
  const committedContent = await readFile(committedResultPath);
  nextDiscovery.resolve();

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "failed");
  assert.equal(terminal?.terminalReason, undefined);
  assert.equal(store.dedupCommits.length, 1);
  assert.equal(executor.dedupCalls, 5);
  assert.equal(completedDrafts.length, 0);
  assert.equal(store.finishCalls.length, 0);
  assert.match(terminal.error, /2 consecutive unsuccessful reducer workers/);
  assert.deepEqual(await readFile(committedResultPath), committedContent,
    "an exhausted reducer must preserve the committed semantic Standard result");
}

async function testCommittedAggregateIsNotSalvagedWhenUntrusted(failure) {
  const fixture = await fixtureRun({
    workers: 2,
    subagents: 0,
    stopAfterNoNew: 99,
    stopAfterConsecutiveErrors: 1,
    maxDiscoveryRuns: 3
  });
  const nextDiscovery = deferred();
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({
    discoveryCandidateId: "candidate-1",
    canonicalCandidateId: "candidate-1",
    discoveryGates: { "discovery-0003": nextDiscovery.promise },
    invalidDedupFromCall: 2
  });
  const completedDrafts = [];
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    retryDelaysMs: [],
    clock: immediateClock,
    ...(failure === "missing-owner" ? {} : { threadId: "fixture-owning-thread" }),
    onComplete: async (draft) => completedDrafts.push(structuredClone(draft))
  });
  coordinator.start();

  await store.dedupCommitted.promise;
  const committedResultPath = store.dedupCommits[0].resultManifestPath;
  if (failure === "wrong-scan") {
    const draft = JSON.parse(await readFile(committedResultPath, "utf8"));
    await writeFile(committedResultPath, JSON.stringify({ ...draft, scanId: randomUUID() }));
  }
  if (failure === "stale-owner") {
    const get = store.get.bind(store);
    store.get = async () => ({
      ...await get(),
      coordinatorGeneration: (fixture.run.coordinatorGeneration ?? 0) + 1
    });
  }
  nextDiscovery.resolve();

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "failed");
  assert.equal(store.finishCalls.length, 0);
  assert.equal(completedDrafts.length, 0);
  assert.equal(store.dedupCommits.length, 1);
}

async function testCancellationAfterCommittedAggregateRemainsCanceled() {
  const fixture = await fixtureRun({ workers: 2, subagents: 0, stopAfterNoNew: 99, maxDiscoveryRuns: 3 });
  const nextDiscovery = deferred();
  const store = new FakeStore(fixture.run);
  const completedDrafts = [];
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor: new FakeExecutor({
      discoveryCandidateId: "candidate-1",
      discoveryGates: { "discovery-0003": nextDiscovery.promise }
    }),
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock,
    threadId: "fixture-owning-thread",
    onComplete: async (draft) => completedDrafts.push(structuredClone(draft))
  });
  coordinator.start();

  await store.dedupCommitted.promise;
  coordinator.cancel("user canceled after a valid committed aggregate");
  nextDiscovery.resolve();

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "canceled");
  assert.equal(store.finishCalls.length, 0);
  assert.equal(completedDrafts.length, 0);
  assert.equal(store.dedupCommits.length, 1);
}

async function testFailedFirstReducerDoesNotPublishTentativeCandidates() {
  const fixture = await fixtureRun({
    workers: 1,
    subagents: 0,
    stopAfterNoNew: 1,
    maxDiscoveryRuns: 1
  });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({ alwaysInvalidDedupResult: true });
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    retryDelaysMs: [1],
    clock: immediateClock
  });
  coordinator.start();

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "failed");
  assert.equal(executor.dedupCalls, 2);
  assert.equal(store.dedupCommits.length, 0);
  await assertNoPublishedCandidates(fixture.run.scanDir);
}

async function testCanceledReducerDoesNotPublishTentativeCandidates() {
  const fixture = await fixtureRun({
    workers: 1,
    subagents: 0,
    stopAfterNoNew: 1,
    maxDiscoveryRuns: 1
  });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({ blockDedupAfterWrite: true });
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock
  });
  coordinator.start();

  await executor.dedupArtifactsWritten.promise;
  await assertNoPublishedCandidates(fixture.run.scanDir);
  coordinator.cancel("cancel reducer after tentative output");
  assert.equal(executor.dedupSignal?.aborted, true);

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "canceled");
  assert.equal(store.dedupCommits.length, 0);
  await assertNoPublishedCandidates(fixture.run.scanDir);
}

async function testRejectedStaleReducerCommitPreservesReplacementCandidates() {
  const fixture = await fixtureRun({
    workers: 2,
    subagents: 0,
    stopAfterNoNew: 99,
    maxDiscoveryRuns: 3
  });
  const nextDiscovery = deferred();
  const store = new FakeStore(fixture.run);
  store.failDedupCommitFromCall = 2;
  store.replacementCandidatesBeforeDedupRejection = JSON.stringify(
    standardScanDraft(fixture.run.scanId, "replacement-candidate", "replacement coordinator")
  );
  const executor = new FakeExecutor({
    discoveryCandidateId: "candidate-1",
    canonicalCandidateId: "candidate-1",
    dedupEvidenceByCall: ["first committed evidence", "new uncommitted evidence"],
    discoveryGates: { "discovery-0003": nextDiscovery.promise }
  });
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock
  });
  coordinator.start();
  await store.dedupCommitted.promise;
  const canonicalPath = store.dedupCommits[0].resultManifestPath;
  const committed = await readFile(canonicalPath, "utf8");
  nextDiscovery.resolve();

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "failed");
  assert.equal(store.dedupCommits.length, 1);
  assert.notEqual(committed, store.replacementCandidatesBeforeDedupRejection);
  assert.equal(
    await readFile(canonicalPath, "utf8"),
    store.replacementCandidatesBeforeDedupRejection,
    "a rejected stale reducer must not restore over the replacement coordinator's semantic result"
  );
}

async function testRejectedFinishDoesNotOverwriteReplacementManifest() {
  const fixture = await fixtureRun({
    workers: 1,
    subagents: 0,
    stopAfterNoNew: 1,
    maxDiscoveryRuns: 1
  });
  const store = new FakeStore(fixture.run);
  store.failFinish = true;
  store.rejectFailurePersistence = true;
  store.replacementManifestBeforeFinishRejection = '{"owner":"replacement"}\n';
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor: new FakeExecutor({ dedupNewFindings: [0] }),
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock
  });
  coordinator.start();

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "failed");
  assert.equal(
    await readFile(path.join(fixture.run.scanDir, "scan-manifest.json"), "utf8"),
    store.replacementManifestBeforeFinishRejection,
    "a stale coordinator failure path must not overwrite the replacement manifest"
  );
}

async function testAmbiguousReducerCommitPreservesPublishedCandidates() {
  const fixture = await fixtureRun({
    workers: 2,
    subagents: 0,
    stopAfterNoNew: 99,
    maxDiscoveryRuns: 3
  });
  const nextDiscovery = deferred();
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({
    discoveryCandidateId: "candidate-1",
    canonicalCandidateId: "candidate-1",
    dedupEvidenceByCall: ["first committed evidence", "possibly committed evidence"],
    discoveryGates: { "discovery-0003": nextDiscovery.promise }
  });
  const completedDrafts = [];
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock,
    threadId: "fixture-owning-thread",
    onComplete: async (draft) => completedDrafts.push(structuredClone(draft))
  });
  coordinator.start();
  await store.dedupCommitted.promise;
  const previousResultPath = store.dedupCommits[0].resultManifestPath;
  const previous = await readFile(previousResultPath, "utf8");
  store.loseEveryDedupCommitResponseAfterCommit = true;
  nextDiscovery.resolve();

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "failed");
  assert.equal(terminal?.terminalReason, undefined);
  assert.equal(store.dedupCommits.length, 2);
  const currentResultPath = store.dedupCommits[1].resultManifestPath;
  assert.notEqual(await readFile(currentResultPath, "utf8"), previous);
  assert.equal(
    JSON.parse(await readFile(currentResultPath, "utf8")).findings[0].rootCause.summary,
    "possibly committed evidence"
  );
  assert.equal(completedDrafts.length, 0, "preserving a committed result must not mark a failed run successful");
}

async function testReducerTraceabilityRetryNamesExactMissingSource() {
  const fixture = await fixtureRun({
    workers: 2,
    subagents: 0,
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 2
  });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({
    discoveryCandidateId: "candidate-1",
    canonicalCandidateId: "candidate-1",
    invalidFirstDedupTraceability: true
  });
  const sleeps = [];
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    retryDelaysMs: [1, 3, 9],
    random: () => 0,
    clock: {
      now: immediateClock.now,
      sleep: async (delayMs) => sleeps.push(delayMs)
    }
  });
  coordinator.start();
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "succeeded");
  assert.equal(terminal?.terminalReason, "capped");
  assert.deepEqual(sleeps, [1]);
  assert.equal(executor.dedupCalls, 2);

  const [basePromptPath, retryPromptPath] = [...new Set(executor.dedupPromptPaths)];
  const context = await promptContext(basePromptPath);
  const missingWorkerId = context.claimedWorkerIds.at(-1);
  const [basePrompt, retryPrompt] = await Promise.all([
    readFile(basePromptPath, "utf8"),
    readFile(retryPromptPath, "utf8")
  ]);
  assert.doesNotMatch(basePrompt, /artifact_validation_failed/);
  assert.match(retryPrompt, /artifact_validation_failed/);
  assert.match(retryPrompt, /findings/s);
  assert.equal(context.claimedWorkerIds.includes(missingWorkerId), true);
}

async function testThreeValidationAttemptsKeepPriorPromptsImmutable() {
  const fixture = await fixtureRun({ workers: 1, subagents: 0, stopAfterNoNew: 1, maxDiscoveryRuns: 1 });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({
    dedupNewFindings: [0],
    malformedDiscoveryAttempts: 2
  });
  const sleeps = [];
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    retryDelaysMs: [1, 3, 9],
    random: () => 0,
    clock: {
      now: immediateClock.now,
      sleep: async (delayMs) => sleeps.push(delayMs)
    }
  });
  coordinator.start();
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "succeeded");
  assert.deepEqual(sleeps, [1, 3]);
  const promptPaths = [...executor.discoveryPromptPaths.values()][0];
  assert.equal(promptPaths.size, 3);
  const [basePath, secondPath, thirdPath] = [...promptPaths];
  const [base, second, third] = await Promise.all(
    [basePath, secondPath, thirdPath].map((promptPath) => readFile(promptPath, "utf8"))
  );
  assert.doesNotMatch(base, /Deterministic validation retry/);
  assert.match(second, /after attempt 1/);
  assert.doesNotMatch(second, /after attempt 2/);
  assert.match(third, /after attempt 2/);
  assert.doesNotMatch(third, /after attempt 1/);
}

async function testWaiterDetachAndCancellation() {
  const fixture = await fixtureRun({ workers: 2, subagents: 1, stopAfterNoNew: 2, maxDiscoveryRuns: 4 });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({ blockDiscovery: true });
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock
  });
  coordinator.start();
  await executor.discoveryStarted;
  assert.equal(coordinator.snapshot().dispatchedCount, 2);

  const waiterAbort = new AbortController();
  const detached = coordinator.wait(waiterAbort.signal);
  waiterAbort.abort("chat turn stopped");
  await assert.rejects(detached, { name: "AbortError" });
  assert.equal(executor.runningDiscovery > 0, true, "detaching a waiter must not stop workers");

  const timedOut = await coordinator.wait(undefined, 1);
  assert.equal(timedOut, undefined);
  assert.equal(executor.runningDiscovery > 0, true);

  coordinator.cancel("user canceled in UI");
  const canceled = await coordinator.wait(undefined, 5_000);
  assert.equal(canceled?.status, "canceled");
  await eventually(() => executor.runningDiscovery === 0);
  await eventually(() => [...store.workers.values()].every((worker) => worker.status === "canceled"));
}

async function testCancellationDropsUnvalidatedDiscoveryResult() {
  const fixture = await fixtureRun({
    workers: 1,
    subagents: 0,
    stopAfterNoNew: 1,
    maxDiscoveryRuns: 1,
  });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({ blockDiscoveryAfterWrite: true });
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock,
    threadId: "checkpoint-owner",
  });
  coordinator.start();
  await executor.discoveryArtifactsWritten.promise;
  const worker = [...store.workers.values()].find(
    (candidate) => candidate.kind === "discovery",
  );
  const checkpointDir = path.join(worker.artifactDir, "checkpoints");
  await mkdir(checkpointDir, { recursive: true });
  await writeFile(
    path.join(checkpointDir, "saved.json"),
    JSON.stringify(standardScanDraft(fixture.run.scanId, "checkpoint-candidate", "saved")),
  );
  coordinator.cancel("fixture canceled before host validation");
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "canceled");
  await assert.rejects(
    readFile(path.join(worker.artifactDir, "result.json")),
    { code: "ENOENT" },
  );
  assert.equal(
    (await readdir(path.join(worker.artifactDir, "checkpoints"))).length > 0,
    true,
    "host-written checkpoints must survive cancellation",
  );
}

async function testCancellationDuringDiscoveryAcceptanceRejectsLateSuccess() {
  const fixture = await fixtureRun({ workers: 1, subagents: 0, stopAfterNoNew: 1, maxDiscoveryRuns: 1 });
  const store = new FakeStore(fixture.run);
  store.blockDiscoverySuccess = true;
  const executor = new FakeExecutor({ dedupNewFindings: [0] });
  const events = [];
  const preserved = deferred();
  const releasePreservation = deferred();
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock,
    log: (event) => events.push(event),
    threadId: "checkpoint-owner",
    onStopped: async () => {
      const worker = [...store.workers.values()].find((worker) => worker.kind === "discovery");
      const result = JSON.parse(await readFile(path.join(worker.artifactDir, "result.json"), "utf8"));
      assert.equal(worker.status, "canceled");
      preserved.resolve(result);
      await releasePreservation.promise;
    }
  });
  coordinator.start();
  await store.discoverySuccessBlocked.promise;

  // The real cancel command persists this state before signaling the coordinator.
  store.run.status = "canceled";
  for (const worker of store.workers.values()) worker.status = "canceled";
  coordinator.cancel("fixture persisted cancellation");
  store.releaseDiscoverySuccess();

  let terminalSettled = false;
  const terminalPromise = coordinator.wait(undefined, 5_000).then((state) => {
    terminalSettled = true;
    return state;
  });
  assert.equal((await preserved.promise).scanId, fixture.run.scanId);
  await Promise.resolve();
  assert.equal(terminalSettled, false, "terminal waiters must not outrun stopped-result preservation");
  releasePreservation.resolve();
  const terminal = await terminalPromise;
  assert.equal(terminal?.status, "canceled");
  await eventually(() => events.some((event) => event.event === "coordinator_cleanup_settled"));
  assert.equal(events.some((event) => event.event === "discovery_accepted"), false);
  const worker = [...store.workers.values()].find((worker) => worker.kind === "discovery");
  const result = JSON.parse(await readFile(path.join(worker.artifactDir, "result.json"), "utf8"));
  assert.equal(result.scanId, fixture.run.scanId, "cancellation must retain saved worker output");
  await assert.rejects(
    readFile(path.join(fixture.run.scanDir, "artifacts", "deep_discovery", "coordinator-manifest.json")),
    { code: "ENOENT" }
  );
}

async function testRegistryEvictionAndExternalFailure() {
  const completedFixture = await fixtureRun({ workers: 1, subagents: 0, stopAfterNoNew: 2, maxDiscoveryRuns: 1 });
  const completedStore = new FakeStore(completedFixture.run);
  const registry = new DeepScanCoordinatorRegistry();
  const completed = registry.start({
    run: completedFixture.run,
    store: completedStore,
    executor: new FakeExecutor({ dedupNewFindings: [1] }),
    pluginRoot: completedFixture.pluginRoot,
    clock: immediateClock
  });
  assert.equal((await completed.wait(undefined, 5_000))?.status, "succeeded");
  await eventually(() => registry.get(completedFixture.run.scanId) === undefined);

  const failedFixture = await fixtureRun({ workers: 1, subagents: 0, stopAfterNoNew: 1, maxDiscoveryRuns: 1 });
  const failedStore = new FakeStore(failedFixture.run);
  const failedExecutor = new FakeExecutor({ blockDiscovery: true });
  const failed = registry.start({
    run: failedFixture.run,
    store: failedStore,
    executor: failedExecutor,
    pluginRoot: failedFixture.pluginRoot,
    clock: immediateClock
  });
  await failedExecutor.discoveryStarted;
  failedStore.run.status = "failed";
  failedStore.run.error = "failure already persisted by fail-scan";
  assert.equal(
    registry.failExternallyPersisted(failedFixture.run.scanId, failedStore.run.error),
    true
  );
  const terminal = await failed.wait(undefined, 5_000);
  assert.equal(terminal?.status, "failed");
  assert.equal(terminal?.error, "failure already persisted by fail-scan");
  await eventually(() => failedExecutor.runningDiscovery === 0);
  await eventually(() => registry.get(failedFixture.run.scanId) === undefined);
  assert.equal(failedStore.failCalls, 0, "an externally persisted failure must not be persisted again");
}

async function testStoppedPublicationFailurePreservesOriginalDiagnostic() {
  const fixture = await fixtureRun({
    workers: 1,
    subagents: 0,
    stopAfterNoNew: 1,
    maxDiscoveryRuns: 1,
  });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({ blockDiscovery: true });
  const events = [];
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock,
    threadId: "checkpoint-owner",
    log: (event) => events.push(event),
    onStopped: async () => {
      throw new Error(
        `fixture retained result publication failure ${"y".repeat(2_350)}`,
      );
    },
  });
  coordinator.start();
  await executor.discoveryStarted;
  store.run.status = "failed";
  store.run.error = `authoritative worker failure diagnostic ${"x".repeat(2_350)}`;
  coordinator.failExternallyPersisted("stale coordinator-local failure diagnostic");

  const terminal = await coordinator.wait(undefined, 5_000);

  assert.equal(terminal?.status, "failed");
  assert.match(terminal?.error ?? "", /authoritative worker failure diagnostic/);
  assert.doesNotMatch(terminal?.error ?? "", /stale coordinator-local failure diagnostic/);
  assert.match(
    terminal?.error ?? "",
    /Saved result publication failed: fixture retained result publication failure/,
  );
  assert.match(terminal?.error ?? "", /Original Deep Scan failure:/);
  assert.equal((terminal?.error?.length ?? 0) <= 2_400, true);
  assert.equal(
    (await store.get(fixture.run.scanId, "checkpoint-owner")).error,
    terminal?.error,
    "publication failures must remain visible after the live coordinator is evicted",
  );
  assert.equal(
    events.some((event) => event.event === "coordinator_result_preservation_failed"),
    true,
  );
}

async function testStoppedPublicationFailureBoundsPrefixedDiagnostic() {
  const fixture = await fixtureRun({
    workers: 1,
    subagents: 0,
    stopAfterNoNew: 1,
    maxDiscoveryRuns: 1,
  });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({ blockDiscovery: true });
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock,
    threadId: "checkpoint-owner",
    onStopped: async () => {
      throw new Error(`fixture publication failure ${"z".repeat(2_400)}`);
    },
  });
  coordinator.start();
  await executor.discoveryStarted;
  store.run.status = "canceled";
  coordinator.cancel("fixture persisted cancellation");

  const terminal = await coordinator.wait(undefined, 5_000);

  assert.equal(terminal?.status, "canceled");
  assert.equal((terminal?.error?.length ?? 0) <= 2_400, true);
  assert.equal(store.publicationFailureMessages.length, 1);
  assert.equal(store.publicationFailureMessages[0].length <= 2_400, true);
  assert.match(
    store.publicationFailureMessages[0],
    /^Saved result publication failed: fixture publication failure/,
  );
}

async function testTerminalReadFailureIsNotRecordedAsPublicationFailure() {
  const fixture = await fixtureRun({
    workers: 1,
    subagents: 0,
    stopAfterNoNew: 1,
    maxDiscoveryRuns: 1,
  });
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({ blockDiscovery: true });
  let publicationAttempts = 0;
  const coordinator = new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock,
    threadId: "checkpoint-owner",
    onStopped: async () => { publicationAttempts += 1; },
  });
  coordinator.start();
  await executor.discoveryStarted;
  store.run.status = "failed";
  store.run.error = "original worker failure diagnostic";
  store.failNextTerminalGet = true;
  coordinator.failExternallyPersisted(store.run.error);

  const terminal = await coordinator.wait(undefined, 5_000);

  assert.equal(terminal?.error, "original worker failure diagnostic");
  assert.equal(publicationAttempts, 0);
  assert.deepEqual(store.publicationFailureMessages, []);
}

async function testCoordinatorHeartbeatsStopAfterOwnershipChanges() {
  const fixture = await fixtureRun({
    workers: 1,
    subagents: 0,
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 2
  });
  const run = {
    ...fixture.run,
    coordinatorGeneration: 2,
    updatedAt: new Date().toISOString()
  };
  const store = new FakeStore(run);
  let heartbeats = 0;
  store.heartbeatCoordinator = async () => {
    heartbeats += 1;
    return structuredClone(store.run);
  };
  let reads = 0;
  store.get = async () => {
    reads += 1;
    if (reads === 1) throw new Error("sqlite3.OperationalError: database is locked");
    if (reads === 3) store.run = { ...store.run, coordinatorGeneration: 3 };
    if (reads >= 4) store.run = { ...store.run, status: "succeeded", terminalReason: "capped" };
    return structuredClone(store.run);
  };
  const executor = new FakeExecutor({ blockDiscovery: true });
  const registry = new DeepScanCoordinatorRegistry();
  const coordinator = registry.start({
    run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock,
    threadId: "thread-fixture",
    heartbeatIntervalMs: 5
  });
  coordinator.start();
  const current = await coordinator.wait(undefined, 2_000);
  await eventually(() => executor.runningDiscovery === 0);
  await new Promise((resolve) => setTimeout(resolve, 25));

  assert.equal(heartbeats, 3, "heartbeat writes continue until a newer generation is confirmed");
  assert.equal(reads, 4, "a failed ownership read must not be treated as lease loss");
  assert.equal(current?.status, "succeeded");
  assert.equal(current?.coordinatorGeneration, 3);
  assert.equal(store.failCalls, 0, "a stale coordinator must never fail the new owner");
}

async function testCoordinatorHeartbeatsContinueDuringBlockedOwnershipRead() {
  const fixture = await fixtureRun({ workers: 1, subagents: 0, stopAfterNoNew: 2, maxDiscoveryRuns: 2 });
  const run = { ...fixture.run, coordinatorGeneration: 2 };
  const store = new FakeStore(run);
  const ownershipRead = deferred();
  let heartbeats = 0;
  let reads = 0;
  store.heartbeatCoordinator = async () => {
    heartbeats += 1;
    return structuredClone(store.run);
  };
  store.get = async () => {
    reads += 1;
    await ownershipRead.promise;
    return structuredClone(store.run);
  };
  const coordinator = new DeepScanCoordinatorRegistry().start({
    run,
    store,
    executor: new FakeExecutor({ blockDiscovery: true }),
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock,
    threadId: "thread-fixture",
    heartbeatIntervalMs: 5
  });

  try {
    await eventually(() => heartbeats >= 3);
    assert.equal(reads, 1, "only one ownership read may remain blocked");
  } finally {
    ownershipRead.resolve();
    coordinator.cancel("blocked ownership test completed");
    await coordinator.settled();
  }
}

async function testRemoteObserverRetriesTransientPersistenceFailures() {
  const fixture = await fixtureRun({ workers: 1, subagents: 0, stopAfterNoNew: 1, maxDiscoveryRuns: 1 });
  const store = new FakeStore({ ...fixture.run, coordinatorGeneration: 2 });
  let reads = 0;
  store.get = async () => {
    reads += 1;
    if (reads === 1) throw new Error("sqlite3.OperationalError: database is locked");
    return { ...store.run, status: "succeeded", terminalReason: "capped" };
  };
  const options = {
    store,
    executor: new FakeExecutor(),
    pluginRoot: fixture.pluginRoot,
    threadId: "thread-fixture"
  };
  const observer = new DeepScanRemoteCoordinator({
    run: store.run,
    registry: new DeepScanCoordinatorRegistry(),
    options
  });

  assert.equal((await observer.wait(undefined, 2_000))?.status, "succeeded");
  assert.equal(reads, 2);
  store.get = async () => {
    throw new Error("Deep Scan orchestration is owned by another continuation.");
  };
  await assert.rejects(observer.wait(undefined, 2_000), /owned by another continuation/);

  for (const outcome of ["locked", "succeeded", "canceled", "terminal-read-locked", "unauthorized"]) {
    store.run = {
      ...fixture.run,
      coordinatorGeneration: 2,
      updatedAt: "2000-01-01T00:00:00Z"
    };
    let outcomeReads = 0;
    store.get = async () => {
      outcomeReads += 1;
      if (outcome === "terminal-read-locked" && outcomeReads === 2) {
        throw new Error("sqlite3.OperationalError: database is locked");
      }
      return structuredClone(store.run);
    };
    let claims = 0;
    store.claimCoordinator = async () => {
      claims += 1;
      if (outcome === "locked") {
        if (claims === 1) throw new Error("sqlite3.OperationalError: database is locked");
        store.run = { ...store.run, status: "succeeded", terminalReason: "capped" };
        return { run: store.run, acquired: false };
      }
      if (outcome === "unauthorized") {
        throw new Error("Deep Scan orchestration is owned by another continuation.");
      }
      store.run = { ...store.run, status: outcome === "terminal-read-locked" ? "succeeded" : outcome };
      throw new Error("Only a running Deep Scan can update orchestration state.");
    };
    const remote = new DeepScanRemoteCoordinator({
      run: store.run,
      registry: new DeepScanCoordinatorRegistry(),
      options
    });
    remote.nextClaimAt = 0;
    if (outcome === "unauthorized") {
      await assert.rejects(remote.wait(undefined, 2_500), /owned by another continuation/);
    } else {
      assert.equal(
        (await remote.wait(undefined, 2_500))?.status,
        ["locked", "terminal-read-locked"].includes(outcome) ? "succeeded" : outcome
      );
      assert.equal(claims, outcome === "locked" ? 2 : 1);
      if (outcome === "terminal-read-locked") assert.equal(outcomeReads, 3);
    }
  }
}

async function testStaleMutationObservesReplacement() {
  const fixture = await fixtureRun({ workers: 1, subagents: 0, stopAfterNoNew: 2, maxDiscoveryRuns: 2 });
  const run = { ...fixture.run, coordinatorGeneration: 2 };
  const store = new FakeStore(run);
  store.updateProgress = async () => {
    throw new Error("Deep Scan coordinator lease belongs to a newer generation.");
  };
  let reads = 0;
  store.get = async () => {
    reads += 1;
    store.run = reads === 1
      ? { ...store.run, coordinatorGeneration: 3 }
      : { ...store.run, coordinatorGeneration: 3, status: "succeeded", terminalReason: "capped" };
    return structuredClone(store.run);
  };
  const coordinator = new DeepScanCoordinatorRegistry().start({
    run,
    store,
    executor: new FakeExecutor(),
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock,
    threadId: "thread-fixture",
    heartbeatIntervalMs: 60_000
  });

  const terminal = await coordinator.wait(undefined, 2_000);

  assert.equal(terminal?.status, "succeeded");
  assert.equal(terminal?.coordinatorGeneration, 3);
  assert.equal(store.failCalls, 0, "a fenced mutation must observe rather than fail the replacement");
}

async function testJoinAndOrphanRules() {
  const fixture = await fixtureRun({ workers: 2, subagents: 1, stopAfterNoNew: 2, maxDiscoveryRuns: 2 });
  const existingCoordinator = { marker: "existing" };
  const defaults = {
    executor: {},
    pluginRoot: fixture.pluginRoot,
    threadId: "thread-fixture"
  };
  let starts = 0;
  let failures = 0;
  const existing = await startOrJoinDeepScanCoordinator({
    begin: { run: { ...fixture.run, persistedWorkerCount: 3 }, shouldStart: false },
    registry: {
      get: () => existingCoordinator,
      start: () => {
        starts += 1;
        return existingCoordinator;
      }
    },
    options: {
      ...defaults,
      store: { fail: async () => { failures += 1; } }
    }
  });
  assert.equal(existing.coordinator, existingCoordinator);
  assert.equal(existing.joined, true);
  assert.equal(starts, 0);
  assert.equal(failures, 0);

  const running = { ...fixture.run, coordinatorGeneration: 2, updatedAt: new Date().toISOString() };
  const observed = await startOrJoinDeepScanCoordinator({
    begin: { run: running, shouldStart: false },
    registry: {
      get: () => undefined,
      start: () => { starts += 1; return existingCoordinator; }
    },
    options: {
      ...defaults,
      store: {
        claimCoordinator: async () => ({ run: running, acquired: false }),
        get: async () => ({ ...running, status: "succeeded" }),
        fail: async () => { failures += 1; }
      }
    }
  });
  assert.equal(observed.joined, true);
  assert.equal((await observed.coordinator.wait(undefined, 1_000))?.status, "succeeded");
  assert.equal(starts, 0, "another process must not create a duplicate coordinator");
  assert.equal(failures, 0, "another process must not interrupt the live scan");

  let staleClaims = 0;
  const staleRunning = { ...running, updatedAt: "2026-01-01T00:00:00Z" };
  const staleObserver = await startOrJoinDeepScanCoordinator({
    begin: { run: staleRunning, shouldStart: false },
    registry: { get: () => undefined, start: () => existingCoordinator },
    options: {
      ...defaults,
      store: {
        claimCoordinator: async () => {
          staleClaims += 1;
          return { run: staleRunning, acquired: false };
        },
        get: async () => staleRunning
      }
    }
  });
  assert.equal(await staleObserver.coordinator.wait(undefined, 1_100), undefined);
  assert.equal(staleClaims, 1, "a confirmed live lease must not be reclaimed on every poll");

  const recovered = await startOrJoinDeepScanCoordinator({
    begin: { run: fixture.run, shouldStart: false },
    registry: {
      get: () => undefined,
      start: (options) => {
        starts += 1;
        assert.equal(options.run.coordinatorGeneration, 2);
        return existingCoordinator;
      }
    },
    options: {
      ...defaults,
      store: {
        claimCoordinator: async () => ({
          acquired: true,
          run: { ...fixture.run, coordinatorGeneration: 2 }
        }),
        fail: async () => {
          failures += 1;
        }
      }
    }
  });
  assert.equal(recovered.coordinator, existingCoordinator);
  assert.equal(recovered.joined, false);
  assert.equal(starts, 1, "only an expired coordinator may be adopted");
  assert.equal(failures, 0, "recovering an orphan must not fail the logical scan");

  const lock = new DeepScanStartLock();
  const firstGate = deferred();
  let liveCoordinator;
  starts = 0;
  const registry = {
    get: () => liveCoordinator,
    start: () => {
      starts += 1;
      liveCoordinator = { marker: "concurrent" };
      return liveCoordinator;
    }
  };
  const options = {
    ...defaults,
    store: {
      claimCoordinator: async () => ({ acquired: true, run: fixture.run }),
      fail: async () => { failures += 1; }
    }
  };
  const first = lock.run(async () => {
    await firstGate.promise;
    return await startOrJoinDeepScanCoordinator({
      begin: { run: fixture.run, shouldStart: true },
      registry,
      options
    });
  });
  const second = lock.run(async () => await startOrJoinDeepScanCoordinator({
    begin: { run: fixture.run, shouldStart: false },
    registry,
    options
  }));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(starts, 0, "the second caller must wait through begin plus registry start");
  firstGate.resolve();
  const [created, joined] = await Promise.all([first, second]);
  assert.equal(created.joined, false);
  assert.equal(joined.joined, true);
  assert.equal(created.coordinator, joined.coordinator);
  assert.equal(starts, 1);
  assert.equal(failures, 0);
}

async function testPausedDiscoverySurvivesCoordinatorRestart() {
  const fixture = await fixtureRun({
    workers: 1,
    subagents: 0,
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 2
  });
  const handoffClaimToken = randomUUID();
  const store = new FakeStore({
    ...fixture.run,
    phase: "setup",
    coordinatorGeneration: 2,
    updatedAt: "2026-08-03T13:33:08Z"
  });
  const originalExecutor = new FakeExecutor({ blockDiscoveryAfterCalls: 1 });
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
  const replacementExecutor = new FakeExecutor({ dedupNewFindings: [0] });
  const acceptedResult = await readFile(accepted.resultManifestPath, "utf8");
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
  assert.equal(terminal?.status, "succeeded");
  assert.equal(store.failCalls, 0);
  assert.equal(replacementExecutor.logicalDiscoveryWorkers.size, 1);
  assert.equal(
    replacementExecutor.logicalDiscoveryWorkers.has(await workerIdFromPrompt(accepted.promptPath)),
    false
  );
  assert.equal(store.dedupClaims.length, 1);
  assert.equal(store.dedupClaims[0].workerIds.includes(accepted.id), true);
  const manifest = JSON.parse(await readFile(terminal.manifestPath, "utf8"));
  assert.equal(manifest.scan.scanId, fixture.run.scanId);
  assert.equal(store.dedupClaims[0].workerIds.length, 2);
  assert.equal(await readFile(accepted.resultManifestPath, "utf8"), acceptedResult);
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

async function testResumedManifestPreservesCompletedReducer(includeUnstartedReducer = false) {
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
      dedupNewFindings: [0],
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
  const replacement = new DeepScanCoordinator({
    run: store.run,
    store,
    executor: new FakeExecutor(),
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock
  });
  replacement.start();

  const terminal = await replacement.wait(undefined, 5_000);
  assert.equal(terminal?.status, "succeeded");
  const manifest = JSON.parse(await readFile(terminal.manifestPath, "utf8"));
  assert.equal(manifest.scan.scanId, fixture.run.scanId);
  assert.equal(store.dedupCommits.length, 1);
  assert.equal(store.dedupClaims.length, 1);
  assert.equal(store.run.persistedWorkers.some((worker) => worker.id === unstartedReducer?.id),
    includeUnstartedReducer);
}

async function testResumeUsesHistoricalCandidateSnapshotForEachReducer(legacyLayout = false) {
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
  const replacement = new DeepScanCoordinator({
    run: store.run,
    store,
    executor: new FakeExecutor(),
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
}

async function testPersistedErrorLimitStopsBeforeRescheduling() {
  const fixture = await fixtureRun({
    workers: 1,
    subagents: 0,
    stopAfterNoNew: 2,
    stopAfterConsecutiveErrors: 2,
    maxDiscoveryRuns: 2
  });
  const failedWorker = {
    id: randomUUID(),
    kind: "discovery",
    status: "canceled",
    promptPath: path.join(fixture.run.scanDir, "failed", "prompt.md"),
    artifactDir: path.join(fixture.run.scanDir, "failed", "output"),
    attempt: 1,
    mergeState: "none",
    error: "transient_error: persisted worker failure"
  };
  await mkdir(path.dirname(failedWorker.promptPath), { recursive: true });
  await writeFile(failedWorker.promptPath, "persisted failed prompt\n");
  const run = {
    ...fixture.run,
    phase: "discovery",
    consecutiveErrors: 2,
    dispatchedCount: 1,
    persistedWorkers: [failedWorker]
  };
  const store = new FakeStore(run);
  const executor = new FakeExecutor();
  const coordinator = new DeepScanCoordinator({
    run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock
  });
  coordinator.start();

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "failed");
  assert.equal(executor.discoveryCalls, 0);
  assert.match(terminal?.error ?? "", /2 consecutive unsuccessful discovery workers/);
  assert.match(terminal?.error ?? "", /persisted worker failure/);
  assert.equal(terminal.manifestPath, undefined);
  assert.equal(store.run.persistedWorkers[0].id, failedWorker.id);
}

async function testPersistedReducerErrorLimitStopsBeforeRescheduling() {
  const fixture = await fixtureRun({
    workers: 1,
    subagents: 0,
    stopAfterNoNew: 3,
    stopAfterConsecutiveErrors: 2,
    maxDiscoveryRuns: 2
  });
  const reducers = await Promise.all([1, 2].map(async (index) => {
    const directory = path.join(fixture.run.scanDir, `dedup-${String(index).padStart(4, "0")}`);
    await mkdir(directory, { recursive: true });
    const promptPath = path.join(directory, "prompt.md");
    await writeFile(promptPath, `persisted reducer ${index}\n`);
    return {
      id: randomUUID(),
      kind: "dedup",
      status: "failed",
      promptPath,
      artifactDir: directory,
      attempt: 1,
      mergeState: "none",
      error: `persisted reducer failure ${index}`
    };
  }));
  const run = {
    ...fixture.run,
    phase: "discovery",
    consecutiveErrors: 0,
    persistedWorkers: reducers
  };
  const store = new FakeStore(run);
  const executor = new FakeExecutor();
  const coordinator = new DeepScanCoordinator({
    run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock
  });
  coordinator.start();

  const terminal = await coordinator.wait(undefined, 5_000);

  assert.equal(terminal?.status, "failed");
  assert.equal(executor.discoveryCalls, 0);
  assert.equal(store.run.consecutiveErrors, 0);
  assert.match(terminal?.error ?? "", /2 consecutive unsuccessful reducer workers/);
  assert.match(terminal?.error ?? "", /persisted reducer failure 2/);
}

async function fixtureRun(config) {
  const root = await realpath(
    await mkdtemp(path.join(tmpdir(), "codex-security-deep-coordinator-"))
  );
  temporaryRoots.push(root);
  const targetPath = path.join(root, "target");
  const scanDir = path.join(root, "scan");
  const pluginRoot = path.join(root, "plugin");
  await Promise.all([mkdir(targetPath), mkdir(scanDir), mkdir(pluginRoot)]);
  return {
    pluginRoot,
    run: {
      scanId: randomUUID(),
      status: "running",
      targetPath,
      scope: ".",
      scanDir,
      config: {
        ...config,
        stopAfterConsecutiveErrors: config.stopAfterConsecutiveErrors
          ?? config.stopAfterNoNew
      },
      dispatchedCount: 0,
      noNewStreak: 0,
      consecutiveErrors: 0,
      persistedWorkerCount: 0
    }
  };
}

class FakeStore {
  constructor(run) {
    this.run = structuredClone(run);
  }

  workerUpdates = [];
  workers = new Map();
  completionSequence = 0;
  progress = [];
  dedupClaims = [];
  dedupCommits = [];
  dedupCommitCalls = [];
  committedDedupIds = new Set();
  failDedupCommitFromCall = undefined;
  loseEveryDedupCommitResponseAfterCommit = false;
  progressCalls = 0;
  failCalls = 0;
  failureInputs = [];
  finishCalls = [];
  failFinish = false;
  rejectFailurePersistence = false;
  replacementManifestBeforeFinishRejection = undefined;
  replacementCandidatesBeforeDedupRejection = undefined;
  loseFirstFinishResponseAfterCommit = false;
  loseFirstDiscoveryAcceptanceResponseAfterCommit = false;
  discoveryAcceptanceResponseLosses = 0;
  loseFirstDedupCommitResponseAfterCommit = false;
  dedupCommitResponseLosses = 0;
  blockDedupCommitResponse = false;
  dedupCommitPersisted = deferred();
  dedupCommitResponseGate = deferred();
  blockDiscoverySuccess = false;
  discoverySuccessBlocked = deferred();
  discoverySuccessGate = deferred();
  blockDiscoveryFailure = false;
  discoveryFailureBlocked = deferred();
  discoveryFailureGate = deferred();
  dedupCommitted = deferred();
  failNextTerminalGet = false;
  publicationFailureMessages = [];

  async begin() {
    return { run: structuredClone(this.run), shouldStart: true };
  }

  async get() {
    if (this.failNextTerminalGet && this.run.status !== "running") {
      this.failNextTerminalGet = false;
      throw new Error("database is locked");
    }
    return structuredClone({
      ...this.run,
      ...(this.workers.size > 0 ? { persistedWorkers: [...this.workers.values()] } : {})
    });
  }

  async claimCoordinator() {
    return { run: structuredClone(this.run), acquired: true };
  }

  async heartbeatCoordinator() {
    this.run.updatedAt = new Date().toISOString();
    return structuredClone(this.run);
  }

  async updateWorker(update) {
    if (update.error) {
      assert.equal(update.error.length <= 2_400, true, "persisted worker errors must be bounded");
    }
    if (this.blockDiscoveryFailure && update.kind === "discovery" && update.status === "failed") {
      this.discoveryFailureBlocked.resolve();
      await this.discoveryFailureGate.promise;
    }
    if (this.blockDiscoverySuccess && update.kind === "discovery" && update.status === "succeeded") {
      this.discoverySuccessBlocked.resolve();
      await this.discoverySuccessGate.promise;
      if (this.run.status !== "running") {
        throw new Error("Only a running Deep Scan can update orchestration state.");
      }
    }
    this.workerUpdates.push(structuredClone(update));
    const previous = this.workers.get(update.id);
    const persisted = { mergeState: "none", ...previous, ...structuredClone(update) };
    if (update.kind === "discovery" && update.status === "queued" && !previous) {
      this.run.dispatchedCount += 1;
    }
    if (
      update.kind === "discovery"
      && update.status === "canceled"
      && update.replaceableFailureKind
      && previous?.status === "running"
    ) {
      this.run.consecutiveErrors += 1;
    }
    if (update.kind === "discovery" && update.status === "succeeded" && !persisted.completionSequence) {
      persisted.completionSequence = ++this.completionSequence;
      persisted.mergeState = "buffered";
      this.run.consecutiveErrors = 0;
    }
    if (update.kind === "dedup" && update.status === "failed" && previous?.status === "running") {
      const claim = this.dedupClaims.find((candidate) => candidate.id === update.id);
      for (const workerId of claim?.workerIds ?? []) {
        const discovery = this.workers.get(workerId);
        if (discovery?.status === "succeeded" && discovery.mergeState === "merging") {
          this.workers.set(workerId, { ...discovery, mergeState: "buffered" });
        }
      }
      this.run.phase = "discovery";
    }
    persisted.consecutiveErrors = this.run.consecutiveErrors;
    this.workers.set(update.id, persisted);
    this.run.persistedWorkerCount = this.workers.size;
    if (
      this.loseFirstDiscoveryAcceptanceResponseAfterCommit
      && update.kind === "discovery"
      && update.status === "succeeded"
      && this.discoveryAcceptanceResponseLosses === 0
    ) {
      this.discoveryAcceptanceResponseLosses += 1;
      throw new Error("fixture lost discovery acceptance response after commit");
    }
    return structuredClone(persisted);
  }

  async claimDedup(input) {
    this.dedupClaims.push(structuredClone(input));
    for (const workerId of input.workerIds) {
      const discovery = this.workers.get(workerId);
      assert.equal(discovery?.mergeState, "buffered");
      this.workers.set(workerId, { ...discovery, mergeState: "merging" });
    }
    await this.updateWorker({
      id: input.id,
      scanId: input.scanId,
      kind: "dedup",
      status: "running",
      promptPath: input.promptPath,
      artifactDir: input.artifactDir,
      attempt: 1
    });
  }

  async commitDedup(commit) {
    this.dedupCommitCalls.push(structuredClone(commit));
    if (
      this.failDedupCommitFromCall !== undefined
      && this.dedupCommitCalls.length >= this.failDedupCommitFromCall
    ) {
      if (this.replacementCandidatesBeforeDedupRejection) {
        await writeFile(this.dedupCommits.at(-1).resultManifestPath,
          this.replacementCandidatesBeforeDedupRejection);
      }
      throw new DeepScanNonRetryableError("fixture rejected the reducer commit");
    }
    if (this.committedDedupIds.has(commit.id)) {
      if (this.loseEveryDedupCommitResponseAfterCommit) {
        throw new Error("fixture lost the committed reducer response");
      }
      return structuredClone(this.run);
    }
    this.dedupCommits.push(structuredClone(commit));
    const consumedCount = this.dedupClaims.find((claim) => claim.id === commit.id)?.workerIds.length;
    assert.equal(typeof consumedCount, "number");
    if (commit.newFindings > 0) this.run.noNewStreak = 0;
    else this.run.noNewStreak += consumedCount;
    const consumed = this.dedupClaims.find((claim) => claim.id === commit.id)?.workerIds ?? [];
    for (const workerId of consumed) {
      const discovery = this.workers.get(workerId);
      assert.equal(discovery?.mergeState, "merging");
      this.workers.set(workerId, { ...discovery, mergeState: "merged" });
    }
    await this.updateWorker({
      ...this.workers.get(commit.id),
      id: commit.id,
      scanId: commit.scanId,
      kind: "dedup",
      status: "succeeded",
      attempt: this.workers.get(commit.id)?.attempt ?? 1,
      resultManifestPath: commit.resultManifestPath
    });
    this.committedDedupIds.add(commit.id);
    this.dedupCommitted.resolve();
    this.dedupCommitPersisted.resolve();
    if (this.loseEveryDedupCommitResponseAfterCommit) {
      throw new Error("fixture lost the committed reducer response");
    }
    if (this.blockDedupCommitResponse) await this.dedupCommitResponseGate.promise;
    if (this.loseFirstDedupCommitResponseAfterCommit && this.dedupCommitResponseLosses === 0) {
      this.dedupCommitResponseLosses += 1;
      throw new Error("fixture lost dedup commit response after commit");
    }
    return structuredClone(this.run);
  }

  async finish(input) {
    this.finishCalls.push(structuredClone(input));
    if (this.run.status === "succeeded") return structuredClone(this.run);
    if (this.failFinish) {
      if (this.replacementManifestBeforeFinishRejection) {
        await writeFile(input.manifestPath, this.replacementManifestBeforeFinishRejection);
      }
      throw new DeepScanNonRetryableError("fixture finish persistence failure");
    }
    if (input.stagedManifestPath) await rename(input.stagedManifestPath, input.manifestPath);
    const latestReducer = [...this.workers.values()]
      .filter((worker) => worker.kind === "dedup" && worker.status === "succeeded")
      .at(-1);
    const draft = latestReducer?.resultManifestPath
      ? JSON.parse(await readFile(latestReducer.resultManifestPath, "utf8"))
      : {
        scanId: this.run.scanId,
        findings: [],
        coverage: {
          completeness: "partial",
          surfaces: [],
          explicitExclusions: [],
          deferred: []
        }
      };
    await writeFile(input.manifestPath, JSON.stringify({
      scan: {
        scanId: draft.scanId,
        mode: "deep",
        ...(draft.threatModel ? { threatModel: draft.threatModel } : {})
      },
      findings: draft.findings,
      coverage: draft.coverage
    }));
    this.run.status = "succeeded";
    this.run.terminalReason = input.reason;
    this.run.manifestPath = input.manifestPath;
    if (this.loseFirstFinishResponseAfterCommit && this.finishCalls.length === 1) {
      throw new Error("fixture lost finish response after commit");
    }
    return structuredClone(this.run);
  }

  async fail(_scanId, message, status = "failed", manifestPath, stagedManifestPath) {
    this.failCalls += 1;
    this.failureInputs.push({ message, status, manifestPath });
    if (this.rejectFailurePersistence) {
      throw new DeepScanNonRetryableError("fixture rejected stale failure persistence");
    }
    if (stagedManifestPath && manifestPath) await rename(stagedManifestPath, manifestPath);
    this.run.status = status;
    this.run.error = message;
    this.run.manifestPath = manifestPath;
    return structuredClone(this.run);
  }

  async recordStoppedPublicationFailure(_scanId, message) {
    this.publicationFailureMessages.push(message);
    const original = this.run.error?.trim();
    this.run.error = original
      ? boundedFixtureErrorPair(message, "\nOriginal Deep Scan failure:\n", original)
      : message;
    return structuredClone(this.run);
  }

  async updateProgress(input) {
    this.progressCalls += 1;
    if (this.progressCalls === this.failProgressAt) {
      throw new Error("fixture progress persistence failure");
    }
    this.progress.push(structuredClone(input));
    if (input.phase) this.run.phase = input.phase;
  }

  releaseDiscoverySuccess() {
    this.discoverySuccessGate.resolve();
  }

  releaseDiscoveryFailure() {
    this.discoveryFailureGate.resolve();
  }

  releaseDedupCommitResponse() {
    this.dedupCommitResponseGate.resolve();
  }
}

class FakeExecutor {
  constructor(options = {}) {
    this.options = options;
    this.discoveryStarted = new Promise((resolve) => {
      this.resolveDiscoveryStarted = resolve;
    });
    this.dedupStarted = new Promise((resolve) => {
      this.resolveDedupStarted = resolve;
    });
    this.dedupGate = deferred();
    this.dedupArtifactsWritten = deferred();
    this.discoveryArtifactsWritten = deferred();
  }

  calls = 0;
  discoveryCalls = 0;
  discoveryAttempts = new Map();
  discoveryPromptPaths = new Map();
  discoveryWorkingDirectories = new Set();
  discoveryResumeThreadIds = [];
  discoveryResumeThreadIdsByWorker = new Map();
  discoveryContinuationPrompts = [];
  discoveryThreadIds = [];
  logicalDiscoveryWorkers = new Set();
  runningDiscovery = 0;
  maximumDiscoveryConcurrency = 0;
  runningDedup = 0;
  maximumDedupConcurrency = 0;
  dedupIndex = 0;
  failedOnce = false;
  invalidDiscoveryCount = 0;
  invalidDedupOnce = false;
  invalidDedupTraceabilityOnce = false;
  dedupCalls = 0;
  dedupAttemptsByLabel = new Map();
  dedupResumeThreadIds = [];
  dedupThreadIds = [];
  dedupContinuationPrompts = [];
  dedupPromptPaths = [];
  dedupArtifactContexts = [];
  dedupSignal = undefined;

  async run(request) {
    this.calls += 1;
    const threadId = request.resumeThreadId ?? randomUUID();
    await request.onThreadStarted?.(threadId);
    if (request.kind === "discovery") {
      const workerId = await workerIdFromPrompt(request.promptPath);
      this.logicalDiscoveryWorkers.add(workerId);
      this.discoveryWorkingDirectories.add(request.workingDirectory);
      this.discoveryResumeThreadIds.push(request.resumeThreadId);
      const resumeThreadIds = this.discoveryResumeThreadIdsByWorker.get(workerId) ?? [];
      resumeThreadIds.push(request.resumeThreadId);
      this.discoveryResumeThreadIdsByWorker.set(workerId, resumeThreadIds);
      this.discoveryContinuationPrompts.push(request.continuationPrompt);
      this.discoveryThreadIds.push(threadId);
      this.discoveryCalls += 1;
      this.discoveryAttempts.set(workerId, (this.discoveryAttempts.get(workerId) ?? 0) + 1);
      const promptPaths = this.discoveryPromptPaths.get(workerId) ?? new Set();
      promptPaths.add(request.promptPath);
      this.discoveryPromptPaths.set(workerId, promptPaths);
      this.runningDiscovery += 1;
      this.maximumDiscoveryConcurrency = Math.max(this.maximumDiscoveryConcurrency, this.runningDiscovery);
      this.resolveDiscoveryStarted();
      try {
        if (this.options.policyRefusalWorkers?.includes(workerId)) {
          const message = this.options.policyRefusalMessages?.[workerId]
            ?? "Request refused due to cybersecurity policy violation";
          throw this.options.nonRetryablePolicyRefusalWorkers?.includes(workerId)
            ? new DeepScanNonRetryableError(message)
            : new Error(message);
        }
        if (this.options.transientFailureWorkers?.includes(workerId)) {
          throw new Error("transient worker failure");
        }
        if (this.options.longDiscoveryFailure) {
          throw new Error(this.options.longDiscoveryFailure);
        }
        if (this.options.alwaysFailDiscovery || (this.options.failFirstDiscoveryAttempt && !this.failedOnce)) {
          this.failedOnce = true;
          if (this.options.writePartialBeforeFailure) {
            await writeFile(
              path.join(request.workingDirectory, "partial-progress.txt"),
              "preserve me\n"
            );
          }
          throw new Error("transient worker failure");
        }
        if (this.options.nonRetryableDiscovery) {
          throw new DeepScanNonRetryableError("fixture configuration failure");
        }
        if (this.options.nonRetryableDiscoveryWorkers?.includes(workerId)) {
          throw new DeepScanNonRetryableError("fixture configuration failure");
        }
        await this.options.discoveryGates?.[workerId];
        if (this.options.failDiscoveryWorkersAfterGate?.includes(workerId)) {
          throw new DeepScanNonRetryableError("fixture late discovery failure");
        }
        const delayMs = this.options.discoveryDelayMs?.[workerId] ?? 0;
        if (delayMs > 0) await new Promise((resolve) => setTimeout(resolve, delayMs));
        if (this.options.blockDiscoveryAfterCalls && this.discoveryCalls > this.options.blockDiscoveryAfterCalls) {
          await waitForAbort(request.signal);
        }
        if (this.options.blockDiscovery) await waitForAbort(request.signal);
        const omitArtifact = this.options.alwaysOmitDiscoveryArtifact
          || (this.invalidDiscoveryCount
            < (this.options.invalidDiscoveryAttempts
              ?? (this.options.omitFirstDiscoveryArtifact ? 1 : 0)));
        const malformedResult = this.invalidDiscoveryCount
          < (this.options.malformedDiscoveryAttempts ?? 0);
        if (omitArtifact || malformedResult) this.invalidDiscoveryCount += 1;
        await writeDiscoveryArtifacts(
          request.promptPath,
          omitArtifact ? "result.json" : undefined,
          this.options.discoveryCandidates?.[workerId] ?? this.options.discoveryCandidateId
            ?? (this.options.dedupNewFindings?.some((count) => count > 0)
              ? "candidate-1"
              : undefined),
          request.workingDirectory,
          request.artifactContext
        );
        if (malformedResult) {
          await writeFile(path.join(request.artifactContext.root, "result.json"), "{malformed");
        }
        this.discoveryArtifactsWritten.resolve();
        if (this.options.blockDiscoveryAfterWrite) await waitForAbort(request.signal);
        return {
          finalResponse: "discovery complete",
          threadId,
          ...(this.options.discoveryDiagnostics ? { diagnostics: this.options.discoveryDiagnostics } : {})
        };
      } finally {
        this.runningDiscovery -= 1;
      }
    }

    this.runningDedup += 1;
    this.dedupSignal = request.signal;
    this.dedupResumeThreadIds.push(request.resumeThreadId);
    this.dedupThreadIds.push(threadId);
    this.dedupContinuationPrompts.push(request.continuationPrompt);
    this.dedupPromptPaths.push(request.promptPath);
    this.dedupArtifactContexts.push(request.artifactContext);
    this.maximumDedupConcurrency = Math.max(this.maximumDedupConcurrency, this.runningDedup);
    this.resolveDedupStarted();
    try {
      if (this.options.blockDedup) await this.dedupGate.promise;
      if (request.signal.aborted) throw abortError();
      this.dedupIndex += 1;
      this.dedupCalls += 1;
      const reducerLabel = (await promptContext(request.promptPath)).reducerLabel;
      const reducerAttempt = (this.dedupAttemptsByLabel.get(reducerLabel) ?? 0) + 1;
      this.dedupAttemptsByLabel.set(reducerLabel, reducerAttempt);
      if (reducerAttempt <= (this.options.missingDedupResultsByLabel?.[reducerLabel] ?? 0)) {
        return {
          finalResponse: "dedup completed without recording its result",
          threadId,
          ...(this.options.dedupDiagnostics ? { diagnostics: this.options.dedupDiagnostics } : {})
        };
      }
      const invalidResult = this.options.alwaysInvalidDedupResult
        || (this.options.invalidDedupFromCall !== undefined
          && this.dedupCalls >= this.options.invalidDedupFromCall)
        || (this.options.invalidFirstDedupResult && !this.invalidDedupOnce);
      this.invalidDedupOnce ||= invalidResult;
      const invalidTraceability = this.options.invalidFirstDedupTraceability
        && !this.invalidDedupTraceabilityOnce;
      this.invalidDedupTraceabilityOnce ||= invalidTraceability;
      await writeDedupArtifacts(
        request,
        invalidResult ? [] : undefined,
        {
          canonicalCandidateId: this.options.canonicalCandidateId,
          evidence: this.options.dedupEvidenceByCall?.[this.dedupCalls - 1],
          omitLastWorkerSource: invalidTraceability,
          dropLastFinding: this.options.dropLastDedupFinding,
          corruptAcceptedSource: this.options.corruptAcceptedSource
        }
      );
      if (this.options.omitFirstDedupCandidateLedger && this.dedupCalls === 1) {
        await rm(path.join(request.artifactContext.root, "result.json"));
      }
      this.dedupArtifactsWritten.resolve();
      if (this.options.blockDedupAfterWrite) await waitForAbort(request.signal);
      return {
        finalResponse: "dedup complete",
        threadId,
        ...(this.options.dedupDiagnostics ? { diagnostics: this.options.dedupDiagnostics } : {})
      };
    } finally {
      this.runningDedup -= 1;
    }
  }

  releaseDedup() {
    this.dedupGate.resolve();
  }
}

async function workerIdFromPrompt(promptPath) {
  return (await promptContext(promptPath)).workerLabel ?? promptPath;
}

async function promptContext(promptPath) {
  const prompt = await readFile(promptPath, "utf8");
  const encoded = prompt.match(/```json\n([\s\S]*?)\n```/)?.[1];
  if (!encoded) throw new Error(`Missing JSON context in ${promptPath}`);
  return JSON.parse(encoded);
}

async function writeDiscoveryArtifacts(
  promptPath,
  omittedName,
  candidateId,
  output,
  artifactContext
) {
  const context = await promptContext(promptPath);
  assert.equal(artifactContext?.layout, "worker");
  assert.equal(artifactContext.root, output);
  if (omittedName === "result.json") return;
  const draft = standardScanDraft(context.scanId, candidateId, context.workerLabel);
  await writeFile(path.join(artifactContext.root, "result.json"), JSON.stringify(draft));
}

async function writeDedupArtifacts(request, consumedOverride, options = {}) {
  const context = await promptContext(request.promptPath);
  const artifactContext = request.artifactContext;
  assert.equal(artifactContext?.layout, "reducer");
  const reducer = artifactContext.deepReducer;
  assert.ok(reducer);
  const workerIds = reducer.claimedWorkers.map((worker) => worker.id);
  assert.deepEqual(context.claimedWorkerIds, workerIds);
  const workerDrafts = await Promise.all(reducer.claimedWorkers.map(async (worker) => {
    const result = JSON.parse(await readFile(worker.resultPath, "utf8"));
    result.findings = result.findings.map((finding, index) => ({
      ...finding, provenance: { ...finding.provenance, sourceFindingIds: [`${worker.id}:${index}`] }
    }));
    return result;
  }));
  const previousDraft = reducer.previousReducerResultPath
    ? JSON.parse(await readFile(reducer.previousReducerResultPath, "utf8"))
    : undefined;
  const mergedFindings = new Map();
  for (const finding of [
    ...previousDraft?.findings ?? [],
    ...workerDrafts.flatMap((draft) => draft.findings)
  ]) {
    const findingIdentity = finding.identity?.anchor ?? finding.provenance?.candidateId ?? finding.ruleId;
    mergedFindings.set(findingIdentity, {
      ...mergedFindings.get(findingIdentity),
      ...finding,
      provenance: {
        ...finding.provenance,
        sourceFindingIds: [...new Set([
          ...mergedFindings.get(findingIdentity)?.provenance.sourceFindingIds ?? [],
          ...finding.provenance.sourceFindingIds ?? []
        ])]
      }
    });
  }
  const draft = standardScanDraft(
    previousDraft?.scanId ?? workerDrafts[0]?.scanId,
    undefined,
    context.reducerLabel
  );
  draft.findings = [...mergedFindings.values()].map((finding) => ({
    ...finding,
    ...(options.evidence === undefined ? {} : { rootCause: { summary: options.evidence } })
  }));
  if (options.canonicalCandidateId && draft.findings.length > 0) {
    draft.findings[0].provenance.candidateId = options.canonicalCandidateId;
  }
  delete draft.coverage;
  if (consumedOverride || options.omitLastWorkerSource) draft.findings = "invalid";
  if (options.dropLastFinding) draft.findings.pop();
  const resultPath = path.join(artifactContext.root, "result.json");
  await mkdir(path.dirname(resultPath), { recursive: true });
  await writeFile(resultPath, JSON.stringify(draft));
  if (options.corruptAcceptedSource) {
    const source = reducer.claimedWorkers.at(-1);
    await writeFile(source.resultPath, "{invalid standard scan\n");
  }
}

function standardScanDraft(scanId, candidateId, workerLabel) {
  return {
    scanId,
    threatModel: { summary: `Independent threat model for ${workerLabel}.` },
    findings: candidateId ? [{
      ruleId: "sql-injection.fixture",
      title: "Unsafe fixture query",
      summary: "A request-controlled value reaches a security-sensitive sink.",
      severity: { level: "high" },
      confidence: { level: "high", rationale: "Source evidence establishes reachability." },
      taxonomy: { category: "sql-injection", cwe: ["CWE-89"] },
      locations: [{ path: "fixture.py", startLine: 1, endLine: 1 }],
      remediation: "Use a parameterized query.",
      provenance: { source: "local_plugin", candidateId, workerId: workerLabel }
    }] : [],
    coverage: {
      completeness: "complete",
      surfaces: [{ label: "Fixture query", disposition: candidateId ? "reported" : "no_issue_found" }],
      explicitExclusions: [],
      deferred: []
    }
  };
}

async function waitForAbort(signal) {
  if (signal.aborted) throw abortError();
  await new Promise((_, reject) => {
    signal.addEventListener("abort", () => reject(abortError()), { once: true });
  });
}

function abortError() {
  const error = new Error("aborted");
  error.name = "AbortError";
  return error;
}

function deferred() {
  let resolve;
  const promise = new Promise((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

async function eventually(predicate) {
  const deadline = Date.now() + 2_000;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  assert.fail("condition did not become true");
}

async function assertFailureManifest(terminal, _phase) {
  assert.equal(terminal?.status, "failed");
  assert.equal(terminal.manifestPath, undefined);
}

async function assertNoPublishedCandidates(scanDir) {
  await assert.rejects(
    readFile(path.join(scanDir, "scan-manifest.json"), "utf8"),
    (error) => error.code === "ENOENT"
  );
}

const immediateClock = {
  now: () => 1_700_000_000_000,
  sleep: async (_delayMs, signal) => {
    if (signal.aborted) throw abortError();
  }
};

function boundedFixtureErrorPair(primary, separator, secondary) {
  const available = 2_400 - separator.length;
  let primaryBudget = Math.min(primary.length, Math.floor(available / 2));
  const secondaryBudget = Math.min(secondary.length, available - primaryBudget);
  primaryBudget = Math.min(primary.length, available - secondaryBudget);
  return boundedFixtureErrorText(primary, primaryBudget)
    + separator
    + boundedFixtureErrorText(secondary, secondaryBudget);
}

function boundedFixtureErrorText(message, maximum) {
  if (message.length <= maximum) return message;
  const digest = createHash("sha256").update(message).digest("hex");
  const suffix = `\n...[truncated; sha256:${digest}]`;
  if (suffix.length >= maximum) return message.slice(0, maximum);
  return message.slice(0, maximum - suffix.length) + suffix;
}

try {
  await testCappedQueueAndSerialDedup();
  await testStandardWorkersReceiveExistingFalsePositiveFeedback();
  await testDiscoveryWorkersKeepOneContextAfterPersistedUpdate();
  await testPersistedContextDoesNotChangeAnotherProcessDiscoverySnapshot();
  await testWorkerScopedCandidateSourceAggregation();
  await testConsumedSourceIsNotRereadAfterReducerWritesResult();
  await testConsumedSourceWithToolDiagnosticIsNotRereadAfterReducerWritesResult();
  await testRetryKeepsLogicalWorker();
  await testSandboxDiagnosticSurvivesArtifactRetries();
  await testCompletionOrdering();
  await testSaturationPreservesFindingAlreadyBuffered();
  await testDeepScanPublication({
    fixtureRun, FakeStore, FakeExecutor, DeepScanCoordinator, deferred,
    immediateClock, eventually,
  });
  await testDirectReducerCannotDropAcceptedFinding();
  await testSaturationDrainsBufferedAndCancelsInflight();
  await testDiscoveryDeadlineDrainsActiveReducerAndPreservesFindings();
  await testDiscoveryDeadlineReducesSingleBufferedFinding();
  await testDiscoveryAcceptedAtDeadlineIsReduced();
  await testDiscoveryDeadlineWithoutAcceptedWorkersReturnsPartialEvidence();
  await testDiscoveryDeadlineBeforeWorkerDispatchReturnsPartialEvidence();
  await testDiscoveryDeadlineWithoutAcceptedWorkersPublishesEmptyResults();
  await testSaturationIgnoresWorkerFailureSettledAfterStop();
  await testSettledReducerIsNotStarvedByDiscoveryBacklog();
  await testSingletonHardCapReduction();
  await testExhaustedRetryFailsScan();
  await testCybersecurityRefusalReplacesOnlyRefusedDiscovery();
  await testProviderCybersecurityRiskMessagesReplaceRefusedDiscoveryImmediately();
  await testRateLimitAndUnrelatedRefusalsRetainTransientRecovery();
  await testConsecutiveCybersecurityRefusalsFailAtConfiguredThreshold();
  await testExhaustedTransientDiscoveryIsReplaced();
  await testSuccessfulDiscoveryResetsConsecutiveFailureThreshold();
  await testExhaustedInvalidDiscoveryArtifactsAreReplaced();
  await testExhaustedMalformedDiscoveryDoesNotRemainPublishable();
  await testTransientExecutionFailureResumesWorkerThread();
  await testConfigurationFailureDoesNotRetry();
  await testFailureManifestWriteDoesNotMaskOriginalError();
  await testFinishPersistenceFailureRewritesManifestAsFailure();
  await testLostFinishResponseReplaysWithoutOverwritingSuccessManifest();
  await testLostWorkerCommitResponsesReplayIdempotently();
  await testCommittedReducerIsReconciledBeforeDiscoveryFailureManifest();
  await testLongWorkerErrorIsBoundedOnlyAtPersistenceBoundary();
  await testDiscoveryPhasePersistenceFailureStopsDispatch();
  await testCancellationClearsRetryWait();
  await testMissingDiscoveryResultResumesExistingThread();
  await testMissingDiscoveryResultResumesExistingThread(true);
  await testInvalidArtifactsRetry();
  await testInvalidReducerResultRetriesFromSnapshot();
  await testInvalidReducerResultRetriesFromSnapshot(true);
  await testMissingReducerResultResumesExistingThread();
  await testExhaustedReducerIsReplacedAtDiscoveryLimit();
  await testExhaustedReducerPreservesCommittedArtifacts();
  await testCommittedAggregateIsNotSalvagedWhenUntrusted("missing-owner");
  await testCommittedAggregateIsNotSalvagedWhenUntrusted("wrong-scan");
  await testCommittedAggregateIsNotSalvagedWhenUntrusted("stale-owner");
  await testCancellationAfterCommittedAggregateRemainsCanceled();
  await testFailedFirstReducerDoesNotPublishTentativeCandidates();
  await testCanceledReducerDoesNotPublishTentativeCandidates();
  await testRejectedStaleReducerCommitPreservesReplacementCandidates();
  await testRejectedFinishDoesNotOverwriteReplacementManifest();
  await testAmbiguousReducerCommitPreservesPublishedCandidates();
  await testReducerTraceabilityRetryNamesExactMissingSource();
  await testThreeValidationAttemptsKeepPriorPromptsImmutable();
  await testWaiterDetachAndCancellation();
  await testCancellationDropsUnvalidatedDiscoveryResult();
  await testCancellationDuringDiscoveryAcceptanceRejectsLateSuccess();
  await testRegistryEvictionAndExternalFailure();
  await testStoppedPublicationFailurePreservesOriginalDiagnostic();
  await testStoppedPublicationFailureBoundsPrefixedDiagnostic();
  await testTerminalReadFailureIsNotRecordedAsPublicationFailure();
  await testStaleMutationObservesReplacement();
  await testCoordinatorHeartbeatsStopAfterOwnershipChanges();
  await testCoordinatorHeartbeatsContinueDuringBlockedOwnershipRead();
  await testRemoteObserverRetriesTransientPersistenceFailures();
  await testJoinAndOrphanRules();
  await testPausedDiscoverySurvivesCoordinatorRestart();
  await testResumedDiscoveryDeadlineUsesPersistedCreationTime();
  await testResumedDiscoveryDeadlineUsesPersistedCreationTime(true);
  await testResumedDiscoveryDeadlineUsesPersistedCreationTime(false, 2.5);
  await testResumedDiscoveryDeadlineUsesPersistedCreationTime(true, 96);
  await testResumedManifestPreservesCompletedReducer();
  await testResumedManifestPreservesCompletedReducer(true);
  await testResumeUsesHistoricalCandidateSnapshotForEachReducer();
  await testResumeUsesHistoricalCandidateSnapshotForEachReducer(true);
  await testPersistedErrorLimitStopsBeforeRescheduling();
  await testPersistedReducerErrorLimitStopsBeforeRescheduling();
} finally {
  await Promise.all(temporaryRoots.map((root) => rm(root, { recursive: true, force: true })));
}
