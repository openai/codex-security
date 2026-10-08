import { readJson, writeJson } from "./support/json.ts";
import type { CoordinatorOptions } from "../src/deep-scan/coordinator.js";
import type { ScanDraftInput } from "../src/artifact-scan-draft.js";
import type {
  DeepScanRunState,
  PersistedDeepScanWorker,
  DeepScanLogEvent,
} from "../src/deep-scan/types.js";
import { mock } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import {
  mkdir,
  readFile,
  readdir,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { testDeepScanLifecycle } from "./deep_scan_lifecycle_cases.ts";
import {
  DeepScanCoordinatorRegistry,
  DeepScanNonRetryableError,
  DeepScanRemoteCoordinator,
  AsyncLock,
  classifyCodexWorkerError,
  startOrJoinDeepScanCoordinator,
  claimDedupInputs,
  recordSleeps,
  temporaryDirectories,
  fixtureRun,
  coordinatorFixture,
  FakeStore,
  FakeExecutor,
  workerIdFromPrompt,
  promptContext,
  standardScanDraft,
  eventually,
  assertNoPublishedCandidates,
  immediateClock,
  createCoordinator,
  runCoordinator,
  recordingClock,
  type TestWorker,
  type StoreInput,
} from "./deep_scan_coordinator_fixture.ts";

async function testCappedQueueAndSerialDedup() {
  const { fixture, store } = await coordinatorFixture({
    workers: 3,
    subagents: 2,
    stopAfterNoNew: 10,
    maxDiscoveryRuns: 5,
  });
  const executor = new FakeExecutor({ discoveryCandidateId: "candidate-1" });
  const completedDrafts: ScanDraftInput[] = [];
  const terminal = await runCoordinator(fixture, store, executor, {
    random: () => 0,
    retryDelaysMs: [1, 3, 9],
    handoffClaimToken: "claim-fixture",
    onComplete: async (draft) =>
      void completedDrafts.push(structuredClone(draft)),
  });
  assert.equal(terminal?.status, "succeeded");
  assert.equal(terminal?.terminalReason, "capped");
  assert.equal(executor.discoveryAttempts.size, 5);
  assert.equal(executor.maximumDiscoveryConcurrency <= 3, true);
  assert.equal(executor.maximumDedupConcurrency, 1);
  assert.equal(executor.discoveryWorkingDirectories.size, 5);
  assert.equal(
    [...executor.discoveryWorkingDirectories].every((directory) =>
      directory.endsWith(path.join("output")),
    ),
    true,
  );
  assert.equal(store.dedupClaims.length >= 2, true);
  assert.equal(
    new Set(store.dedupClaims.flatMap((claim) => claim.workerIds)).size,
    5,
  );

  assert.deepEqual(store.progress, [
    {
      scanId: fixture.run.scanId,
      phase: "discovery" as const,
      handoffClaimToken: "claim-fixture",
    },
  ]);

  const manifest = await readJson(terminal.manifestPath);
  assert.equal(manifest.scan.scanId, fixture.run.scanId);
  assert.equal(manifest.scan.mode, "deep");
  assert.deepEqual(
    manifest.findings.map(
      (finding: Record<string, unknown>) =>
        (finding.provenance as { candidateId: string }).candidateId,
    ),
    ["candidate-1"],
  );
  assert.equal(completedDrafts.length, 1);
  assert.equal(completedDrafts[0].scanId, fixture.run.scanId);
  assert.deepEqual(completedDrafts[0].findings, manifest.findings);
  const reducerWorkers = [...store.workers.values()].filter(
    (worker) => worker.kind === "dedup" && worker.status === "succeeded",
  );
  const finalReducerResult = await readJson(
    reducerWorkers.at(-1)!.resultManifestPath!,
  );
  assert.equal(finalReducerResult.scanId, fixture.run.scanId);
  assert.deepEqual(finalReducerResult.findings, manifest.findings);
  const finalReducerContext = await promptContext(
    executor.dedupPromptPaths.at(-1)!,
  );
  const finalReducerArtifacts = executor.dedupArtifactContexts.at(-1);
  assert.deepEqual(
    finalReducerContext.claimedWorkerIds,
    finalReducerArtifacts!.deepReducer!.claimedWorkers.map(
      (worker) => worker.id,
    ),
  );
  assert.equal(
    Object.hasOwn(finalReducerContext, "previousReducerResultPath"),
    false,
  );
  assert.equal(
    finalReducerArtifacts!.deepReducer!.previousReducerResultPath,
    reducerWorkers.at(-2)!.resultManifestPath,
  );
  for (const worker of [...store.workers.values()].filter(
    (worker) => worker.kind === "discovery" && worker.status === "succeeded",
  )) {
    const result = await readJson(worker.resultManifestPath!);
    const context = await promptContext(worker.promptPath);
    assert.equal(result.scanId, fixture.run.scanId);
    assert.match(result.threatModel.summary, new RegExp(context.workerLabel));
    assert.equal(context.pluginRoot, fixture.pluginRoot);
  }
  await assert.rejects(
    readFile(
      path.join(
        fixture.run.scanDir,
        "artifacts",
        "01_context",
        "threat_model.md",
      ),
    ),
    { code: "ENOENT" },
    "the shared parent skill, not the discovery coordinator, owns final threat-model synthesis",
  );
  assert.equal(
    terminal.manifestPath,
    path.join(fixture.run.scanDir, "scan-manifest.json"),
  );
}

async function testStandardWorkersReceiveExistingFalsePositiveFeedback() {
  const { fixture, store } = await coordinatorFixture();
  const feedbackPath = path.join(
    fixture.run.scanDir,
    "artifacts",
    "01_context",
    "false_positive_feedback.json",
  );
  await mkdir(path.dirname(feedbackPath), { recursive: true });
  await writeJson(feedbackPath, [{ reason: "existing control still applies" }]);
  const terminal = await runCoordinator(fixture, store, new FakeExecutor());
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  const worker = [...store.workers.values()].find(
    (candidate) => candidate.kind === "discovery",
  );
  assert.ok(worker);
  const prompt = await readFile(worker.promptPath, "utf8");
  assert.equal(prompt.includes(JSON.stringify(feedbackPath)), true);
  assert.equal(
    Object.hasOwn(
      await promptContext(worker.promptPath),
      "falsePositiveFeedbackPath",
    ),
    false,
  );
  await assert.rejects(
    readFile(
      path.join(
        worker.artifactDir,
        "artifacts",
        "01_context",
        "false_positive_feedback.json",
      ),
    ),
    { code: "ENOENT" },
  );
}

async function testDiscoveryWorkersKeepOneContextAfterPersistedUpdate() {
  const fixture = await fixtureRun({
    stopAfterNoNew: 10,
    maxDiscoveryRuns: 2,
  });
  fixture.run.userContext = "Initial context.";
  const firstWorkerGate = Promise.withResolvers<void>();
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({
    discoveryCandidateId: "candidate-1",
    discoveryGates: { "discovery-0001": firstWorkerGate.promise },
  });
  const coordinator = createCoordinator(fixture, store, executor);
  coordinator.start();
  await executor.discoveryStarted.promise;
  store.run.userContext = "Updated context.";
  firstWorkerGate.resolve();
  await coordinator.wait(undefined, 5_000);

  const contexts = await Promise.all(
    [...store.workers.values()]
      .filter((worker) => worker.kind === "discovery")
      .sort((left, right) => left.promptPath.localeCompare(right.promptPath))
      .map(
        async (worker) => (await promptContext(worker.promptPath)).userContext,
      ),
  );
  assert.deepEqual(contexts, ["Initial context.", "Initial context."]);
  assert.equal((await store.get()).userContext, "Updated context.");
}

async function testPersistedContextDoesNotChangeAnotherProcessDiscoverySnapshot() {
  const fixture = await fixtureRun({
    stopAfterNoNew: 10,
    maxDiscoveryRuns: 2,
  });
  fixture.run.userContext = "Initial cross-process context.";
  const firstWorkerGate = Promise.withResolvers<void>();
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor({
    discoveryCandidateId: "candidate-1",
    discoveryGates: { "discovery-0001": firstWorkerGate.promise },
  });
  const owningRegistry = new DeepScanCoordinatorRegistry();
  const coordinator = owningRegistry.start({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock,
  });

  await executor.discoveryStarted.promise;
  store.run.userContext = "Updated cross-process context.";
  firstWorkerGate.resolve();
  const terminal = await coordinator.wait(undefined, 5_000);

  assert.equal(terminal?.status, "succeeded");
  const contexts = await Promise.all(
    [...store.workers.values()]
      .filter((worker) => worker.kind === "discovery")
      .sort((left, right) => left.promptPath.localeCompare(right.promptPath))
      .map(
        async (worker) => (await promptContext(worker.promptPath)).userContext,
      ),
  );
  assert.deepEqual(contexts, [
    "Initial cross-process context.",
    "Initial cross-process context.",
  ]);
  assert.equal(
    (await store.get()).userContext,
    "Updated cross-process context.",
  );
}

async function testWorkerScopedCandidateSourceAggregation() {
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    stopAfterNoNew: 10,
    maxDiscoveryRuns: 2,
  });
  const executor = new FakeExecutor({
    discoveryCandidateId: "candidate-1",
    canonicalCandidateId: "candidate-1",
  });
  const terminal = await runCoordinator(fixture, store, executor);
  assert.equal(terminal?.terminalReason, "capped");
  const manifest = await readJson(terminal.manifestPath);
  const expectedWorkerIds = [...store.workers.values()]
    .filter(
      (worker) => worker.kind === "discovery" && worker.status === "succeeded",
    )
    .sort((left, right) => left.completionSequence! - right.completionSequence!)
    .map((worker) => worker.id);
  assert.deepEqual(
    manifest.findings.map(
      (finding: Record<string, unknown>) =>
        (finding.provenance as { candidateId: string }).candidateId,
    ),
    ["candidate-1"],
  );
  assert.deepEqual(store.dedupClaims[0].workerIds, expectedWorkerIds);
  const reducer = [...store.workers.values()].find(
    (worker) => worker.kind === "dedup",
  );
  const reducerResult = await readJson(reducer!.resultManifestPath!);
  assert.equal(reducerResult.scanId, fixture.run.scanId);
  assert.deepEqual(reducerResult.findings, manifest.findings);
  assert.equal(
    executor.dedupCalls,
    1,
    "valid worker provenance must not retry the reducer",
  );
}

async function testConsumedSourceIsNotRereadAfterReducerWritesResult() {
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 2,
  });
  const executor = new FakeExecutor({
    discoveryCandidateId: "candidate-1",
    canonicalCandidateId: "candidate-1",
    corruptAcceptedSource: true,
  });
  const terminal = await runCoordinator(fixture, store, executor);
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(terminal?.terminalReason, "capped");
  assert.equal(executor.dedupCalls, 1);
  assert.deepEqual(
    (await readJson(terminal.manifestPath)).findings.map(
      (finding: Record<string, unknown>) =>
        (finding.provenance as { candidateId: string }).candidateId,
    ),
    ["candidate-1"],
  );
}

async function testConsumedSourceWithToolDiagnosticIsNotRereadAfterReducerWritesResult() {
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 2,
  });
  const executor = new FakeExecutor({
    corruptAcceptedSource: true,
    dedupDiagnostics: [
      {
        code: "artifact_tool_failed" as const,
        message:
          "Codex worker artifact tool record_codex_security_deep_reduction failed.",
      },
    ],
  });
  const terminal = await runCoordinator(fixture, store, executor);

  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(terminal?.terminalReason, "saturated");
  assert.equal(executor.dedupCalls, 1);
  assert.deepEqual((await readJson(terminal.manifestPath)).findings, []);
}

async function testRetryKeepsLogicalWorker() {
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    subagents: 1,
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 2,
  });
  const executor = new FakeExecutor({
    failFirstDiscoveryAttempt: true,
  });
  const sleeps: number[] = [];
  const terminal = await runCoordinator(fixture, store, executor, {
    random: () => 0.5,
    clock: {
      now: () => 1_700_000_000_000,
      sleep: recordSleeps(sleeps),
    },
  });
  assert.equal(terminal?.terminalReason, "saturated", terminal?.error);
  assert.deepEqual(sleeps, [69_000]);
  assert.equal(executor.discoveryAttempts.size, 2);
  assert.equal(executor.discoveryCalls, 3);
  const attemptsByWorker = new Map();
  for (const update of store.workerUpdates) {
    if (update.kind !== "discovery" || update.status !== "running") continue;
    const attempts = attemptsByWorker.get(update.id) ?? new Set();
    attempts.add(update.attempt);
    attemptsByWorker.set(update.id, attempts);
  }
  const retriedId = [...attemptsByWorker.entries()].find(
    ([, attempts]) => attempts.size === 2,
  )?.[0];
  assert.ok(retriedId);
  assert.deepEqual([...attemptsByWorker.get(retriedId)], [1, 2]);
  assert.equal(
    store.run.dispatchedCount,
    2,
    "retry attempts must not count as logical discovery runs",
  );
  const retriedPromptPaths = executor.discoveryPromptPaths.get(
    [...executor.discoveryAttempts.entries()].find(
      ([, attempts]) => attempts === 2,
    )?.[0]!,
  );
  assert.equal(
    retriedPromptPaths?.size,
    1,
    "retries must reuse the identical rendered prompt path",
  );
  assert.doesNotMatch(
    await readFile([...retriedPromptPaths][0], "utf8"),
    /Deterministic validation retry/,
    "execution failures must not be presented to the model as artifact validation feedback",
  );
}

async function testSandboxDiagnosticSurvivesArtifactRetries() {
  const { fixture, store } = await coordinatorFixture({
    subagents: 1,
    stopAfterNoNew: 2,
  });
  const executor = new FakeExecutor({
    invalidDiscoveryAttempts: Infinity,
    discoveryDiagnostics: [
      {
        code: "sandbox_namespace_exhausted",
        message:
          "Codex worker sandbox namespace creation failed (bwrap ENOSPC).",
      },
    ],
  });
  const sleeps: number[] = [];
  const terminal = await runCoordinator(fixture, store, executor, {
    retryDelaysMs: [1, 3, 9],
    random: () => 0,
    clock: {
      now: () => 1_700_000_000_000,
      sleep: async (delayMs) => void sleeps.push(delayMs),
    },
  });
  assert.equal(terminal?.status, "failed");
  assert.deepEqual(sleeps, [1, 3, 9]);
  assert.deepEqual(executor.discoveryResumeThreadIds, [
    undefined,
    undefined,
    undefined,
    undefined,
  ]);
  assert.match(
    terminal?.error ?? "",
    /sandbox_namespace_exhausted|sandbox namespace creation failed/i,
  );
  assert.match(terminal?.error ?? "", /result\.json/i);
  assert.doesNotMatch(
    terminal?.error ?? "",
    /super-secret-command|private source text/,
  );
  assert.equal(terminal.manifestPath, undefined);
}

async function testCompletionOrdering() {
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    subagents: 1,
    stopAfterNoNew: 10,
    maxDiscoveryRuns: 3,
  });
  const firstWorkerGate = Promise.withResolvers<void>();
  const executor = new FakeExecutor({
    discoveryCandidateId: "candidate-1",
    discoveryGates: { "discovery-0001": firstWorkerGate.promise },
  });
  const coordinator = createCoordinator(fixture, store, executor);
  coordinator.start();
  await eventually(() => store.dedupClaims.length === 1);
  firstWorkerGate.resolve();
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.terminalReason, "capped");
  const workerLabel = (workerId: string) =>
    path.basename(path.dirname(store.workers.get(workerId)!.promptPath));
  assert.deepEqual(store.dedupClaims[0].workerIds.map(workerLabel), [
    "discovery-0002",
    "discovery-0003",
  ]);
  assert.equal(
    store.workers.get(store.dedupClaims[0].workerIds[0])!.completionSequence,
    1,
  );
  assert.equal(
    store.workers.get(store.dedupClaims[0].workerIds[1])!.completionSequence,
    2,
  );
}

async function testSaturationDrainsBufferedAndCancelsInflight() {
  const { fixture, store } = await coordinatorFixture({
    workers: 4,
    subagents: 1,
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 6,
  });
  const executor = new FakeExecutor({
    blockDiscoveryAfterCalls: 4,
  });
  executor.dedupGate = Promise.withResolvers<void>();
  const coordinator = createCoordinator(fixture, store, executor);
  coordinator.start();
  await executor.dedupStarted.promise;
  await eventually(
    () => executor.discoveryCalls === 6 && executor.runningDiscovery === 2,
  );
  executor.dedupGate.resolve();

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.terminalReason, "saturated");
  assert.ok(executor.runningDiscovery === 0 && executor.runningDedup === 0);
  const manifest = await readJson(terminal.manifestPath);
  assert.equal(
    store.dedupClaims.length,
    2,
    "convergence must drain already accepted output",
  );
  assert.equal(store.dedupClaims[0].workerIds.length, 2);
  assert.equal(store.finishCalls[0].omittedWorkerIds.length, 0);
  assert.equal(
    [...store.workers.values()].filter((worker) => worker.status === "canceled")
      .length,
    2,
  );
  assert.deepEqual(manifest.findings, []);
  assert.equal(store.run.noNewStreak, 4);
  assert.equal(
    [...store.workers.values()].some((worker) =>
      ["queued", "running"].includes(worker.status),
    ),
    false,
    "saturation cleanup must persist every worker as settled before finish",
  );
}

async function testSaturationPreservesFindingAlreadyBuffered() {
  const { fixture, store } = await coordinatorFixture({
    workers: 4,
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 4,
  });
  const laterDiscoveries = Promise.withResolvers<void>();
  const executor = new FakeExecutor({
    discoveryGates: {
      "discovery-0003": laterDiscoveries.promise,
      "discovery-0004": laterDiscoveries.promise,
    },
    discoveryCandidates: {
      "discovery-0003": "buffered-finding",
      "discovery-0004": "buffered-finding",
    },
  });
  executor.dedupGate = Promise.withResolvers<void>();
  const completed: ScanDraftInput[] = [];
  const coordinator = createCoordinator(fixture, store, executor, {
    onComplete: async (draft) => void completed.push(draft),
  });
  coordinator.start();
  await executor.dedupStarted.promise;
  laterDiscoveries.resolve();
  await eventually(
    () =>
      [...store.workers.values()].filter(
        (worker) =>
          worker.kind === "discovery" && worker.status === "succeeded",
      ).length === 4,
  );
  executor.dedupGate.resolve();
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.deepEqual(
    completed[0].findings.map(
      (finding: Record<string, unknown>) =>
        (finding.provenance as { candidateId: string }).candidateId,
    ),
    ["buffered-finding"],
  );
  assert.equal(store.finishCalls[0].omittedWorkerIds.length, 0);
}

async function testDirectReducerCannotDropAcceptedFinding() {
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    maxDiscoveryRuns: 2,
  });
  const terminal = await runCoordinator(
    fixture,
    store,
    new FakeExecutor({
      discoveryCandidates: {
        "discovery-0001": "first-finding",
        "discovery-0002": "second-finding",
      },
      dropLastDedupFinding: true,
    }),
    { retryDelaysMs: [] },
  );
  assert.equal(
    terminal?.status,
    "failed",
    "direct file output must account for all accepted inputs",
  );
  assert.equal(store.dedupCommits.length, 0);
  assert.equal(
    [...store.workers.values()].filter(
      (worker) => worker.kind === "discovery" && worker.status === "succeeded",
    ).length,
    2,
  );
}

async function testSaturationIgnoresWorkerFailureSettledAfterStop() {
  const { fixture, store } = await coordinatorFixture({
    workers: 3,
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 3,
  });
  store.blockDiscoveryUpdate = "failed";
  const executor = new FakeExecutor({
    nonRetryableDiscoveryWorkers: ["discovery-0003"],
  });
  executor.dedupGate = Promise.withResolvers<void>();
  const completedDrafts: ScanDraftInput[] = [];
  const coordinator = createCoordinator(fixture, store, executor, {
    retryDelaysMs: [],
    threadId: "fixture-owning-thread",
    onComplete: async (draft) =>
      void completedDrafts.push(structuredClone(draft)),
  });
  coordinator.start();

  await executor.dedupStarted.promise;
  await store.discoveryBlocked.promise;
  executor.dedupGate.resolve();
  await eventually(() => executor.dedupSignal?.aborted === true);
  store.discoveryGate.resolve();

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(terminal?.terminalReason, "saturated");
  assert.equal(completedDrafts.length, 1);
  assert.equal(completedDrafts[0].coverage.completeness, "complete");
  assert.deepEqual(completedDrafts[0].findings, []);
  const failedWorker = [...store.workers.values()].find(
    (worker) =>
      worker.status === "failed" &&
      path.basename(path.dirname(worker.promptPath)) === "discovery-0003",
  );
  assert.ok(failedWorker);
  assert.equal(store.failureMessages.length, 0);
  assert.equal(store.finishCalls.length, 1);
  assert.equal(executor.discoveryCalls, 3);
  assert.equal(executor.dedupCalls, 1);
}

async function testSettledReducerIsNotStarvedByDiscoveryBacklog() {
  const { fixture, store } = await coordinatorFixture({
    workers: 4,
    subagents: 1,
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 20,
  });
  const executor = new FakeExecutor({
    blockDiscoveryAfterCalls: 4,
  });
  executor.dedupGate = Promise.withResolvers<void>();
  const coordinator = createCoordinator(fixture, store, executor);
  coordinator.start();

  await executor.dedupStarted.promise;
  await eventually(
    () => executor.discoveryCalls >= 8 && executor.runningDiscovery === 4,
  );
  const dispatchedBeforeConvergence = executor.discoveryCalls;
  executor.dedupGate.resolve();

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.terminalReason, "saturated");
  assert.equal(
    terminal?.dispatchedCount,
    dispatchedBeforeConvergence,
    "a settled reducer must stop dispatch before canceled workers can refill the pool",
  );
  assert.equal(executor.discoveryAttempts.size, dispatchedBeforeConvergence);
}

async function testSingletonHardCapReduction() {
  const { fixture, store } = await coordinatorFixture({
    workers: 4,
    stopAfterNoNew: 6,
  });
  const executor = new FakeExecutor({ discoveryCandidateId: "candidate-1" });
  const terminal = await runCoordinator(fixture, store, executor);
  assert.equal(terminal?.terminalReason, "capped");
  assert.equal(executor.discoveryAttempts.size, 1);
  assert.deepEqual(
    store.dedupClaims.map((claim) => claim.workerIds.length),
    [1],
  );
  const manifest = await readJson(terminal.manifestPath);
  assert.equal(manifest.scan.scanId, fixture.run.scanId);
  assert.equal(store.dedupCommits.length, 1);
}

async function testExhaustedRetryFailsScan() {
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    subagents: 1,
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 2,
  });
  const executor = new FakeExecutor({
    discoveryFailureMessage: "transient worker failure",
  });
  const terminal = await runCoordinator(fixture, store, executor, {
    random: () => 0,
    retryDelaysMs: [1, 3, 9],
  });
  assert.equal(terminal?.status, "failed");
  assert.match(terminal?.error ?? "", /transient worker failure/);
  assert.equal(executor.discoveryCalls >= 4, true);
  assert.equal(executor.discoveryCalls <= 8, true);
  assert.equal(executor.runningDiscovery, 0);
  assert.equal(terminal.manifestPath, undefined);
}

async function testProviderCybersecurityRiskMessagesReplaceRefusedDiscoveryImmediately() {
  for (const message of [
    "Request blocked by cyberPolicy.",
    "Request blocked by a safety policy violation.",
    "This content was flagged for possible cybersecurity risk.",
    "This content was flagged for potentially high-risk cyber activity.",
  ]) {
    const { fixture, store } = await coordinatorFixture({
      stopAfterNoNew: 4,
      stopAfterConsecutiveErrors: 3,
      maxDiscoveryRuns: 3,
    });
    const executor = new FakeExecutor({
      discoveryFailureMessages: { "discovery-0001": message },
      discoveryCandidateId: "candidate-1",
    });
    const sleeps: number[] = [];
    const terminal = await runCoordinator(fixture, store, executor, {
      random: () => 0,
      retryDelaysMs: [1, 3, 9],
      clock: recordingClock(sleeps),
    });

    assert.equal(terminal?.status, "succeeded", message);
    assert.equal(terminal?.terminalReason, "capped");
    assert.equal(executor.discoveryAttempts.size, 3);
    assert.equal(executor.discoveryAttempts.get("discovery-0001"), 1, message);
    assert.deepEqual(
      sleeps,
      [],
      `a refused conversation must not be resumed: ${message}`,
    );
    assert.equal(store.run.consecutiveErrors, 0, message);
    const refusal = [...store.workers.values()].find(
      (worker) =>
        path.basename(path.dirname(worker.promptPath)) === "discovery-0001",
    );
    assert.equal(refusal?.replaceableFailureKind, "policy_refusal", message);
    assert.equal(refusal?.status, "canceled");
  }
}

async function testTransientDiscoveryErrorsRetainRecovery() {
  for (const message of [
    "RateLimitExhaustedError: request rate limit reached; " +
      "This content was flagged for possible cybersecurity risk.",
    "429 Too Many Requests: flagged for potentially high-risk cyber activity.",
    "429 Too Many Requests: Request blocked by cyberPolicy.",
    "ordinary model refusal [HTTP 400]",
    "generic safety/security error [HTTP 403]",
    "transient worker failure",
  ]) {
    const { fixture, store } = await coordinatorFixture({
      stopAfterNoNew: 4,
      stopAfterConsecutiveErrors: 2,
      maxDiscoveryRuns: 3,
    });
    const executor = new FakeExecutor({
      discoveryFailureMessages: { "discovery-0001": message },
      discoveryCandidateId: "candidate-1",
    });
    const sleeps: number[] = [];
    const terminal = await runCoordinator(fixture, store, executor, {
      random: () => 0,
      retryDelaysMs: [1, 3, 9],
      clock: recordingClock(sleeps),
    });

    assert.equal(terminal?.status, "succeeded", message);
    assert.equal(executor.discoveryAttempts.get("discovery-0001"), 4, message);
    assert.equal(executor.discoveryAttempts.size, 3);
    assert.deepEqual(sleeps, [1, 3, 9], message);
    assert.equal(store.run.consecutiveErrors, 0, message);
    assert.equal(
      [...store.workers.values()].find(
        (worker) =>
          path.basename(path.dirname(worker.promptPath)) === "discovery-0001",
      )?.replaceableFailureKind,
      "transient_error",
      message,
    );
  }
}

async function testConsecutiveCybersecurityRefusalsFailAtConfiguredThreshold() {
  const { fixture, store } = await coordinatorFixture({
    stopAfterNoNew: 6,
    stopAfterConsecutiveErrors: 2,
    maxDiscoveryRuns: 10,
  });
  const executor = new FakeExecutor({
    discoveryFailureMessages: {
      "discovery-0001": "Request blocked by cyberPolicy.",
      "discovery-0002": "Request blocked by cyberPolicy.",
    },
  });
  const terminal = await runCoordinator(fixture, store, executor, {
    retryDelaysMs: [1, 3, 9],
  });

  assert.equal(terminal?.status, "failed");
  assert.match(
    terminal?.error ?? "",
    /2 consecutive unsuccessful discovery workers/,
  );
  assert.match(terminal?.error ?? "", /policy_refusal/);
  assert.equal(executor.discoveryAttempts.size, 2);
  assert.equal(executor.discoveryCalls, 2);
  assert.equal(store.run.consecutiveErrors, 2);
  assert.equal(store.finishCalls.length, 0);
  assert.equal(terminal.manifestPath, undefined);
  assert.deepEqual(
    [...store.workers.values()].map((worker) => worker.replaceableFailureKind),
    ["policy_refusal", "policy_refusal"],
  );
}

async function testSuccessfulDiscoveryResetsConsecutiveFailureThreshold() {
  const { fixture, store } = await coordinatorFixture({
    stopAfterNoNew: 8,
    stopAfterConsecutiveErrors: 2,
    maxDiscoveryRuns: 5,
  });
  const executor = new FakeExecutor({
    discoveryFailureMessages: {
      "discovery-0001": "Request blocked by cyberPolicy.",
      "discovery-0003": "Request blocked by cyberPolicy.",
    },
    discoveryCandidateId: "candidate-1",
  });
  const terminal = await runCoordinator(fixture, store, executor, {
    retryDelaysMs: [1, 3, 9],
  });

  assert.equal(terminal?.status, "succeeded");
  assert.equal(executor.discoveryAttempts.size, 5);
  assert.equal(store.run.consecutiveErrors, 0);
  assert.equal(
    [...store.workers.values()].filter(
      (worker) => worker.replaceableFailureKind === "policy_refusal",
    ).length,
    2,
  );
}

async function testExhaustedInvalidDiscoveryArtifactsAreReplaced() {
  const { fixture, store } = await coordinatorFixture({
    stopAfterNoNew: 4,
    stopAfterConsecutiveErrors: 2,
    maxDiscoveryRuns: 3,
  });
  const executor = new FakeExecutor({
    invalidDiscoveryAttempts: 4,
    discoveryCandidateId: "candidate-1",
  });
  const terminal = await runCoordinator(fixture, store, executor, {
    retryDelaysMs: [1, 3, 9],
  });

  assert.equal(terminal?.status, "succeeded");
  assert.equal(executor.discoveryAttempts.get("discovery-0001"), 4);
  assert.equal(executor.discoveryAttempts.size, 3);
  assert.equal(
    [...store.workers.values()].find(
      (worker) =>
        path.basename(path.dirname(worker.promptPath)) === "discovery-0001",
    )?.replaceableFailureKind,
    "invalid_discovery_artifacts",
  );
}

async function testExhaustedMalformedDiscoveryDoesNotRemainPublishable() {
  const { fixture, store } = await coordinatorFixture({
    stopAfterNoNew: 4,
    stopAfterConsecutiveErrors: 2,
    maxDiscoveryRuns: 3,
  });
  const executor = new FakeExecutor({
    malformedDiscoveryAttempts: 4,
    discoveryCandidateId: "candidate-1",
  });
  const terminal = await runCoordinator(fixture, store, executor, {
    retryDelaysMs: [1, 3, 9],
  });

  assert.equal(terminal?.status, "succeeded");
  assert.equal(executor.discoveryAttempts.get("discovery-0001"), 4);
  await assert.rejects(
    readFile(
      path.join(
        fixture.run.scanDir,
        "artifacts",
        "deep_discovery",
        "workers",
        "discovery-0001",
        "output",
        "result.json",
      ),
    ),
    { code: "ENOENT" },
    "an exhausted invalid result must not remain available to stopped-result recovery",
  );
}

async function testTransientExecutionFailureResumesWorkerThread() {
  const { fixture, store } = await coordinatorFixture({
    subagents: 1,
  });
  const executor = new FakeExecutor({
    failFirstDiscoveryAttempt: true,
    writePartialBeforeFailure: true,
  });
  const terminal = await runCoordinator(fixture, store, executor, {
    retryDelaysMs: [1],
  });
  assert.equal(terminal?.status, "succeeded");
  assert.deepEqual(executor.discoveryResumeThreadIds, [
    undefined,
    executor.discoveryThreadIds[0],
  ]);
  assert.equal(new Set(executor.discoveryThreadIds).size, 1);
  assert.match(
    executor.discoveryContinuationPrompts[1] ?? "",
    /transient Codex execution failure/,
  );
  assert.match(
    executor.discoveryContinuationPrompts[1] ?? "",
    /Standard security scan/,
  );
  assert.match(
    executor.discoveryContinuationPrompts[1] ?? "",
    /record_codex_security_scan_draft/,
  );
  assert.doesNotMatch(
    executor.discoveryContinuationPrompts[1] ?? "",
    /\b(?:Deep|artifacts?|rebuild)\b/i,
  );
  const [workingDirectory] = executor.discoveryWorkingDirectories;
  assert.equal(
    await readFile(path.join(workingDirectory, "partial-progress.txt"), "utf8"),
    "preserve me\n",
  );
}

async function testConfigurationFailureDoesNotRetry(
  failureMessage = "fixture configuration failure",
) {
  const { fixture, store } = await coordinatorFixture();
  const executor = new FakeExecutor({
    nonRetryableDiscoveryMessage: failureMessage,
  });
  const sleeps: number[] = [];
  const terminal = await runCoordinator(fixture, store, executor, {
    clock: recordingClock(sleeps),
  });
  assert.equal(terminal?.status, "failed");
  assert.equal(terminal?.error, failureMessage);
  assert.equal(executor.discoveryCalls, 1);
  assert.deepEqual(sleeps, []);
  assert.equal([...store.workers.values()][0]?.status, "failed");
}

async function testFailureManifestWriteDoesNotMaskOriginalError() {
  const { fixture, store } = await coordinatorFixture();
  const manifestPath = path.join(
    fixture.run.scanDir,
    "artifacts",
    "deep_discovery",
    "coordinator-manifest.json",
  );
  await mkdir(manifestPath, { recursive: true });
  const terminal = await runCoordinator(
    fixture,
    store,
    new FakeExecutor({
      nonRetryableDiscoveryMessage: "fixture configuration failure",
    }),
  );
  assert.equal(terminal?.status, "failed");
  assert.match(terminal?.error ?? "", /fixture configuration failure/);
  assert.equal(terminal?.manifestPath, undefined);
  assert.equal(store.failureMessages.length, 1);
}

async function testFinishPersistenceFailureRewritesManifestAsFailure() {
  const { fixture, store } = await coordinatorFixture();
  store.failFinish = true;
  const terminal = await runCoordinator(fixture, store, new FakeExecutor());
  assert.equal(terminal?.status, "failed");
  assert.match(terminal?.error ?? "", /fixture finish persistence failure/);
  assert.equal(terminal.manifestPath, undefined);
}

async function testLostFinishResponseReplaysWithoutOverwritingSuccessManifest() {
  const { fixture, store } = await coordinatorFixture();
  store.loseFirstFinishResponseAfterCommit = true;
  const terminal = await runCoordinator(fixture, store, new FakeExecutor());
  assert.equal(terminal?.status, "succeeded");
  assert.equal(store.finishCalls.length, 2);
  assert.deepEqual(store.finishCalls[1], store.finishCalls[0]);
  assert.equal(store.failureMessages.length, 0);
  const manifest = await readJson(terminal.manifestPath);
  assert.equal(manifest.scan.scanId, fixture.run.scanId);
}

async function testLostWorkerCommitResponsesReplayIdempotently() {
  const { fixture, store } = await coordinatorFixture();
  store.loseFirstDiscoveryAcceptanceResponseAfterCommit = true;
  store.loseFirstDedupCommitResponseAfterCommit = true;
  const terminal = await runCoordinator(fixture, store, new FakeExecutor());
  assert.equal(terminal?.status, "succeeded");
  assert.equal(store.loseFirstDiscoveryAcceptanceResponseAfterCommit, false);
  assert.equal(store.loseFirstDedupCommitResponseAfterCommit, false);
  assert.equal(store.dedupCommitCalls.length, 2);
  assert.equal(store.dedupCommits.length, 1);
  assert.equal(store.failureMessages.length, 0);
}

async function testCommittedReducerIsReconciledBeforeDiscoveryFailureManifest() {
  const { fixture, store } = await coordinatorFixture({
    workers: 3,
    stopAfterNoNew: 10,
    maxDiscoveryRuns: 3,
  });
  const thirdWorkerGate = Promise.withResolvers<void>();
  store.dedupCommitResponseGate = Promise.withResolvers<void>();
  const executor = new FakeExecutor({
    discoveryGates: { "discovery-0003": thirdWorkerGate.promise },
    failDiscoveryWorkersAfterGate: ["discovery-0003"],
  });
  const completedDrafts: ScanDraftInput[] = [];
  const coordinator = createCoordinator(fixture, store, executor, {
    retryDelaysMs: [],
    threadId: "fixture-owning-thread",
    onComplete: async (draft) =>
      void completedDrafts.push(structuredClone(draft)),
  });
  coordinator.start();

  await store.dedupCommitted.promise;
  thirdWorkerGate.resolve();
  await eventually(() => executor.dedupSignal?.aborted === true);
  store.dedupCommitResponseGate.resolve();

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
  const { fixture, store } = await coordinatorFixture();
  const fullError = `fixture long validator error: ${"x".repeat(5_000)}`;
  const terminal = await runCoordinator(
    fixture,
    store,
    new FakeExecutor({ discoveryFailureMessage: fullError }),
    { retryDelaysMs: [1, 3, 9], random: () => 0 },
  );
  assert.equal(terminal?.status, "failed");
  assert.equal(store.failureMessages[0].length <= 2_400, true);
  assert.match(store.failureMessages[0], /truncated; sha256:/);
  assert.equal(terminal.manifestPath, undefined);
  const [worker] = [...store.workers.values()];
  assert.equal(worker.status, "canceled");
  assert.equal(worker.attempt, 4);
  assert.match(worker.error!, /truncated; sha256:/);
}

async function testDiscoveryPhasePersistenceFailureStopsDispatch() {
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    subagents: 1,
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 2,
  });
  store.failProgressAt = 1;
  const executor = new FakeExecutor();
  const terminal = await runCoordinator(fixture, store, executor);
  assert.equal(terminal?.status, "failed");
  assert.match(terminal?.error ?? "", /fixture progress persistence failure/);
  assert.equal(executor.discoveryAttempts.size, 0);
  assert.equal(terminal.manifestPath, undefined);
}

async function testCancellationClearsRetryWait() {
  const { fixture, store } = await coordinatorFixture({
    subagents: 1,
    stopAfterNoNew: 2,
  });
  const executor = new FakeExecutor({
    failFirstDiscoveryAttempt: true,
    blockDiscoveryAfterCalls: 1,
  });
  const sleepStarted = Promise.withResolvers<void>();
  const coordinator = createCoordinator(fixture, store, executor, {
    clock: undefined,
    log: (event) => {
      if (event.event === "worker_retry_scheduled") sleepStarted.resolve();
    },
  });
  coordinator.start();
  await sleepStarted.promise;
  const callsAtCancellation = executor.discoveryCalls;
  coordinator.cancel("cancel retry wait");
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "canceled");
  assert.equal(executor.runningDiscovery, 0);
  assert.equal(
    executor.discoveryCalls,
    callsAtCancellation,
    "canceling a retry delay must not launch another attempt",
  );
}

async function testMissingDiscoveryResultResumesExistingThread(
  withToolFailure = false,
) {
  const { fixture, store } = await coordinatorFixture();
  const executor = new FakeExecutor({
    invalidDiscoveryAttempts: 1,
    ...(withToolFailure
      ? {
          discoveryDiagnostics: [
            {
              code: "artifact_tool_failed" as const,
              message:
                "Codex worker artifact tool record_codex_security_scan_draft failed.",
            },
          ],
        }
      : {}),
  });
  const sleeps: number[] = [];
  const terminal = await runCoordinator(fixture, store, executor, {
    random: () => 0,
    retryDelaysMs: [1, 3, 9],
    clock: recordingClock(sleeps),
  });

  assert.equal(terminal?.status, "succeeded");
  assert.deepEqual(sleeps, [1]);
  assert.deepEqual(executor.discoveryResumeThreadIds, [
    undefined,
    executor.discoveryThreadIds[0],
  ]);
  assert.equal(new Set(executor.discoveryThreadIds).size, 1);
  const continuation = executor.discoveryContinuationPrompts[1] ?? "";
  assert.match(continuation, /completed source analysis/);
  assert.match(
    continuation,
    /record_codex_security_scan_draft\(\{ scanId, scope\?, threatModel\?, findings, coverage \}\)/,
  );
  assert.doesNotMatch(continuation, /\b(?:Deep|artifacts?|rebuild)\b/i);
  assert.equal([...executor.discoveryPromptPaths.values()][0].size, 1);
  await assert.rejects(
    realpath(
      path.join(
        fixture.run.scanDir,
        "artifacts",
        "deep_discovery",
        "workers",
        "discovery-0001",
        "attempts",
        "attempt-01",
      ),
    ),
    { code: "ENOENT" },
    "same-thread completion must preserve the Standard scan workspace instead of archiving it",
  );
}

async function testInvalidArtifactsRetry() {
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    subagents: 1,
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 2,
  });
  const executor = new FakeExecutor({
    malformedDiscoveryAttempts: 1,
  });
  const sleeps: number[] = [];
  const terminal = await runCoordinator(fixture, store, executor, {
    random: () => 0,
    retryDelaysMs: [1, 3, 9],
    clock: {
      now: immediateClock.now,
      sleep: recordSleeps(sleeps),
    },
  });
  assert.equal(terminal?.terminalReason, "saturated");
  assert.deepEqual(sleeps, [1]);
  const retriedWorkerId = [...executor.discoveryAttempts.entries()].find(
    ([, attempts]) => attempts === 2,
  )?.[0];
  const retriedPromptPaths = executor.discoveryPromptPaths.get(
    retriedWorkerId!,
  );
  assert.deepEqual(
    executor.discoveryResumeThreadIds,
    [undefined, undefined, undefined],
    "deterministic validation retries must start a clean thread",
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
    retriedContext.workerLabel,
  );
  const retriedResult = await readJson(workerRoot, "output", "result.json");
  assert.equal(retriedResult.scanId, fixture.run.scanId);
  assert.equal(
    await readFile(
      path.join(workerRoot, "attempts", "attempt-01", "result.json"),
      "utf8",
    ),
    "{malformed",
  );
  const basePrompt = await readFile(basePromptPath, "utf8");
  const retriedPrompt = await readFile(retryPromptPath, "utf8");
  assert.doesNotMatch(basePrompt, /Deterministic validation retry/);
  assert.match(retriedPrompt, /Deterministic validation retry after attempt 1/);
  const retryInstructions =
    retriedPrompt
      .split("## Deterministic validation retry after attempt 1")[1]
      ?.split('{"validation_error":')[0] ?? "";
  assert.match(retryInstructions, /Standard security review/);
  assert.match(retryInstructions, /record_codex_security_scan_draft/);
  assert.doesNotMatch(retryInstructions, /\b(?:Deep|artifacts?|rebuild)\b/i);
  assert.match(retriedPrompt, /result\.json/);
  assert.equal(
    new Set(
      store.workerUpdates
        .filter((update) =>
          [basePromptPath, retryPromptPath].includes(update.promptPath),
        )
        .map((update) => update.promptPath),
    ).size,
    1,
    "persistence must retain the immutable base prompt path",
  );
}

async function testInvalidReducerResultRetriesFromSnapshot(
  missingCandidateLedger = false,
) {
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    subagents: 1,
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 2,
  });
  const executor = new FakeExecutor({
    ...(missingCandidateLedger
      ? {
          omitFirstDedupCandidateLedger: true,
          dedupDiagnostics: [
            {
              code: "artifact_tool_failed" as const,
              message:
                "Codex worker artifact tool record_codex_security_deep_reduction failed.",
            },
          ],
        }
      : { invalidFirstDedupResult: true }),
  });
  const sleeps: number[] = [];
  const terminal = await runCoordinator(fixture, store, executor, {
    random: () => 0,
    retryDelaysMs: [1, 3, 9],
    clock: recordingClock(sleeps),
  });
  assert.equal(terminal?.terminalReason, "saturated", terminal?.error);
  assert.deepEqual(sleeps, [1]);
  assert.equal(executor.dedupCalls, 2);
  const reducerPrompts = store.workerUpdates
    .filter((update) => update.kind === "dedup" && update.status === "running")
    .map((update) => update.promptPath);
  assert.equal(new Set(reducerPrompts).size, 1);
  assert.equal(
    new Set(executor.dedupPromptPaths).size,
    missingCandidateLedger ? 1 : 2,
  );
  const [basePromptPath, retryPromptPath] = executor.dedupPromptPaths;
  assert.doesNotMatch(
    await readFile(basePromptPath, "utf8"),
    /Deterministic validation retry/,
  );
  if (missingCandidateLedger) {
    assert.deepEqual(
      executor.dedupResumeThreadIds,
      [undefined, executor.dedupThreadIds[0]],
      "an incomplete tool submission must resume its existing reducer conversation",
    );
  } else {
    assert.match(
      await readFile(retryPromptPath, "utf8"),
      /Deterministic validation retry after attempt 1/,
    );
    assert.deepEqual(
      executor.dedupResumeThreadIds,
      [undefined, undefined],
      "an invalid reducer result must still retry in a clean conversation",
    );
  }
}

async function testMissingReducerResultResumesExistingThread(
  diagnosticMessage = "Codex worker artifact tool record_codex_security_deep_reduction failed.",
) {
  const { fixture, store } = await coordinatorFixture({
    stopAfterConsecutiveErrors: 2,
  });
  const executor = new FakeExecutor({
    missingDedupResultsByLabel: { "dedup-0001": 1 },
    dedupDiagnostics: [
      {
        code: "artifact_tool_failed" as const,
        message: diagnosticMessage,
      },
    ],
  });
  const sleeps: number[] = [];
  const terminal = await runCoordinator(fixture, store, executor, {
    random: () => 0,
    retryDelaysMs: [1, 3, 9],
    clock: recordingClock(sleeps),
  });

  assert.equal(terminal?.status, "succeeded");
  assert.equal(store.dedupClaims.length, 1);
  assert.equal(executor.dedupCalls, 2);
  assert.deepEqual(sleeps, [1]);
  assert.ok(
    store.workerUpdates.some(
      (update) =>
        update.kind === "dedup" &&
        update.error?.startsWith(diagnosticMessage) &&
        update.error.includes("result.json"),
    ),
    "the persisted missing-result error must retain the tool failure reason",
  );
  assert.deepEqual(executor.dedupResumeThreadIds, [
    undefined,
    executor.dedupThreadIds[0],
  ]);
  assert.equal(new Set(executor.dedupThreadIds).size, 1);
  assert.match(
    executor.dedupContinuationPrompts[1] ?? "",
    /record_codex_security_deep_reduction\(\{ scanId, findings, threatModel\?, scope\? \}\)/,
  );
  assert.doesNotMatch(
    executor.dedupContinuationPrompts[1] ?? "",
    /\{ candidates, merges \}/,
  );
  assert.match(
    executor.dedupContinuationPrompts[1] ?? "",
    /retry the call until it succeeds/,
  );
  assert.match(
    executor.dedupContinuationPrompts[1] ?? "",
    /smaller maxBytes budget.*halve the failed request's budget/,
  );
  assert.match(
    executor.dedupContinuationPrompts[1] ?? "",
    /preserving its cursor and findingRef to retry the same page/,
  );
  assert.match(
    executor.dedupContinuationPrompts[1] ?? "",
    /paginate all assigned findings and the previous aggregate/,
  );
  assert.equal(new Set(executor.dedupPromptPaths).size, 1);
  await assert.rejects(
    realpath(
      path.join(
        fixture.run.scanDir,
        "artifacts",
        "deep_discovery",
        "dedup",
        "dedup-0001",
        "attempts",
        "attempt-01",
      ),
    ),
    { code: "ENOENT" },
    "same-thread completion must preserve reducer artifacts instead of archiving them",
  );
}

async function testMissingReducerResultRetainsSizeDiagnosticAfterOtherFailures() {
  const sizeMessage =
    "code-mode delegate response exceeds the IPC frame limit: code-mode IPC frame length 76008279 exceeds 67108864 bytes";
  for (const earlierDiagnostic of [
    { code: "file_change_failed", message: "Codex worker file change failed." },
    {
      code: "sandbox_namespace_exhausted",
      message: "Codex worker sandbox namespace creation failed (bwrap ENOSPC).",
    },
  ] as const) {
    const { fixture, store } = await coordinatorFixture();
    const executor = new FakeExecutor({
      missingDedupResultsByLabel: { "dedup-0001": 1 },
      dedupDiagnostics: [
        earlierDiagnostic,
        { code: "artifact_tool_failed" as const, message: sizeMessage },
      ],
    });
    const terminal = await runCoordinator(fixture, store, executor, {
      retryDelaysMs: [1],
    });
    assert.equal(terminal?.status, "succeeded", terminal?.error);
    const failure = store.workerUpdates.find(
      (update) => update.kind === "dedup" && update.error,
    );
    assert.ok(failure!.error!.includes(earlierDiagnostic.message));
    assert.ok(failure!.error!.includes(sizeMessage));
    assert.ok(failure!.error!.includes("result.json"));
    const retryPrompt = await readFile(executor.dedupPromptPaths[1], "utf8");
    assert.ok(retryPrompt.includes(earlierDiagnostic.message));
    assert.ok(retryPrompt.includes(sizeMessage));
  }
}

async function testExhaustedReducerIsReplacedAtDiscoveryLimit() {
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    stopAfterNoNew: 4,
    stopAfterConsecutiveErrors: 2,
    maxDiscoveryRuns: 2,
  });
  const executor = new FakeExecutor({
    discoveryCandidateId: "candidate-1",
    canonicalCandidateId: "candidate-1",
    missingDedupResultsByLabel: { "dedup-0001": 4 },
    dedupDiagnostics: [
      {
        code: "artifact_tool_failed" as const,
        message:
          "Codex worker artifact tool record_codex_security_deep_reduction failed.",
      },
    ],
  });
  const terminal = await runCoordinator(fixture, store, executor, {
    retryDelaysMs: [1, 3, 9],
  });

  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(terminal?.terminalReason, "capped");
  assert.equal(terminal?.dispatchedCount, 2);
  assert.equal(store.dedupClaims.length, 2);
  assert.deepEqual(
    store.dedupClaims[1].workerIds,
    store.dedupClaims[0].workerIds,
  );
  assert.equal(executor.dedupAttemptsByLabel.get("dedup-0001"), 4);
  assert.equal(executor.dedupAttemptsByLabel.get("dedup-0002"), 1);
  assert.deepEqual(executor.dedupResumeThreadIds.slice(0, 4), [
    undefined,
    executor.dedupThreadIds[0],
    executor.dedupThreadIds[0],
    executor.dedupThreadIds[0],
  ]);
  assert.equal(executor.dedupResumeThreadIds[4], undefined);
  const manifest = await readJson(terminal.manifestPath);
  assert.deepEqual(
    manifest.findings.map(
      (finding: Record<string, unknown>) =>
        (finding.provenance as { candidateId: string }).candidateId,
    ),
    ["candidate-1"],
  );
  assert.equal(store.dedupCommits.length, 1);
  const failedReducer = [...store.workers.values()].find(
    (worker) => worker.kind === "dedup" && worker.status === "failed",
  );
  assert.equal(
    path.basename(path.dirname(failedReducer!.promptPath)),
    "dedup-0001",
  );
  assert.equal(failedReducer?.attempt, 4);
  assert.match(failedReducer?.error ?? "", /result\.json/);
}

async function testExhaustedReducerPreservesCommittedArtifacts() {
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    stopAfterNoNew: 99,
    stopAfterConsecutiveErrors: 2,
    maxDiscoveryRuns: 3,
  });
  const nextDiscovery = Promise.withResolvers<void>();
  const executor = new FakeExecutor({
    discoveryCandidateId: "candidate-1",
    canonicalCandidateId: "candidate-1",
    discoveryGates: { "discovery-0003": nextDiscovery.promise },
    invalidDedupFromCall: 2,
  });
  const completedDrafts: ScanDraftInput[] = [];
  const coordinator = createCoordinator(fixture, store, executor, {
    retryDelaysMs: [1],
    threadId: "fixture-owning-thread",
    onComplete: async (draft) =>
      void completedDrafts.push(structuredClone(draft)),
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
  assert.deepEqual(
    await readFile(committedResultPath),
    committedContent,
    "an exhausted reducer must preserve the committed semantic Standard result",
  );
}

async function testCommittedAggregateIsNotSalvagedWhenUntrusted(
  failure: string,
) {
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    stopAfterNoNew: 99,
    stopAfterConsecutiveErrors: 1,
    maxDiscoveryRuns: 3,
  });
  const nextDiscovery = Promise.withResolvers<void>();
  const executor = new FakeExecutor({
    discoveryCandidateId: "candidate-1",
    canonicalCandidateId: "candidate-1",
    discoveryGates: { "discovery-0003": nextDiscovery.promise },
    invalidDedupFromCall: 2,
  });
  const completedDrafts: ScanDraftInput[] = [];
  const coordinator = createCoordinator(fixture, store, executor, {
    retryDelaysMs: [],
    ...(failure === "missing-owner"
      ? {}
      : { threadId: "fixture-owning-thread" }),
    onComplete: async (draft) =>
      void completedDrafts.push(structuredClone(draft)),
  });
  coordinator.start();

  await store.dedupCommitted.promise;
  const committedResultPath = store.dedupCommits[0].resultManifestPath;
  if (failure === "wrong-scan") {
    const draft = await readJson(committedResultPath);
    await writeJson(committedResultPath, { ...draft, scanId: randomUUID() });
  }
  if (failure === "stale-owner") {
    const get = store.get.bind(store);
    store.get = async () => ({
      ...(await get()),
      coordinatorGeneration: (fixture.run.coordinatorGeneration ?? 0) + 1,
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
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    stopAfterNoNew: 99,
    maxDiscoveryRuns: 3,
  });
  const nextDiscovery = Promise.withResolvers<void>();
  const completedDrafts: ScanDraftInput[] = [];
  const coordinator = createCoordinator(
    fixture,
    store,
    new FakeExecutor({
      discoveryCandidateId: "candidate-1",
      discoveryGates: { "discovery-0003": nextDiscovery.promise },
    }),
    {
      threadId: "fixture-owning-thread",
      onComplete: async (draft) =>
        void completedDrafts.push(structuredClone(draft)),
    },
  );
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
  const { fixture, store } = await coordinatorFixture();
  const executor = new FakeExecutor({ invalidDedupFromCall: 1 });
  const terminal = await runCoordinator(fixture, store, executor, {
    retryDelaysMs: [1],
  });
  assert.equal(terminal?.status, "failed");
  assert.equal(executor.dedupCalls, 2);
  assert.equal(store.dedupCommits.length, 0);
  await assertNoPublishedCandidates(fixture.run.scanDir);
}

async function testCanceledReducerDoesNotPublishTentativeCandidates() {
  const { fixture, store } = await coordinatorFixture();
  const executor = new FakeExecutor({ blockDedupAfterWrite: true });
  const coordinator = createCoordinator(fixture, store, executor);
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
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    stopAfterNoNew: 99,
    maxDiscoveryRuns: 3,
  });
  const nextDiscovery = Promise.withResolvers<void>();
  store.failDedupCommitFromCall = 2;
  store.replacementCandidatesBeforeDedupRejection = JSON.stringify(
    standardScanDraft(
      fixture.run.scanId,
      "replacement-candidate",
      "replacement coordinator",
    ),
  );
  const executor = new FakeExecutor({
    discoveryCandidateId: "candidate-1",
    canonicalCandidateId: "candidate-1",
    dedupEvidenceByCall: [
      "first committed evidence",
      "new uncommitted evidence",
    ],
    discoveryGates: { "discovery-0003": nextDiscovery.promise },
  });
  const coordinator = createCoordinator(fixture, store, executor);
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
    "a rejected stale reducer must not restore over the replacement coordinator's semantic result",
  );
}

async function testRejectedFinishDoesNotOverwriteReplacementManifest() {
  const { fixture, store } = await coordinatorFixture();
  store.failFinish = true;
  store.rejectFailurePersistence = true;
  store.replacementManifestBeforeFinishRejection = '{"owner":"replacement"}\n';
  const terminal = await runCoordinator(fixture, store, new FakeExecutor());
  assert.equal(terminal?.status, "failed");
  assert.equal(
    await readFile(
      path.join(fixture.run.scanDir, "scan-manifest.json"),
      "utf8",
    ),
    store.replacementManifestBeforeFinishRejection,
    "a stale coordinator failure path must not overwrite the replacement manifest",
  );
}

async function testAmbiguousReducerCommitPreservesPublishedCandidates() {
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    stopAfterNoNew: 99,
    maxDiscoveryRuns: 3,
  });
  const nextDiscovery = Promise.withResolvers<void>();
  const executor = new FakeExecutor({
    discoveryCandidateId: "candidate-1",
    canonicalCandidateId: "candidate-1",
    dedupEvidenceByCall: [
      "first committed evidence",
      "possibly committed evidence",
    ],
    discoveryGates: { "discovery-0003": nextDiscovery.promise },
  });
  const completedDrafts: ScanDraftInput[] = [];
  const coordinator = createCoordinator(fixture, store, executor, {
    threadId: "fixture-owning-thread",
    onComplete: async (draft) =>
      void completedDrafts.push(structuredClone(draft)),
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
    (await readJson(currentResultPath)).findings[0].rootCause.summary,
    "possibly committed evidence",
  );
  assert.equal(
    completedDrafts.length,
    0,
    "preserving a committed result must not mark a failed run successful",
  );
}

async function testReducerTraceabilityRetryNamesExactMissingSource() {
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 2,
  });
  const executor = new FakeExecutor({
    discoveryCandidateId: "candidate-1",
    canonicalCandidateId: "candidate-1",
    invalidFirstDedupResult: true,
  });
  const sleeps: number[] = [];
  const terminal = await runCoordinator(fixture, store, executor, {
    retryDelaysMs: [1, 3, 9],
    random: () => 0,
    clock: recordingClock(sleeps),
  });
  assert.equal(terminal?.status, "succeeded");
  assert.equal(terminal?.terminalReason, "capped");
  assert.deepEqual(sleeps, [1]);
  assert.equal(executor.dedupCalls, 2);

  const [basePromptPath, retryPromptPath] = executor.dedupPromptPaths;
  const context = await promptContext(basePromptPath);
  const basePrompt = await readFile(basePromptPath, "utf8");
  const retryPrompt = await readFile(retryPromptPath, "utf8");
  assert.doesNotMatch(basePrompt, /artifact_validation_failed/);
  assert.match(retryPrompt, /artifact_validation_failed/);
  assert.match(retryPrompt, /findings/s);
  assert.equal(context.claimedWorkerIds.length > 0, true);
}

async function testThreeValidationAttemptsKeepPriorPromptsImmutable() {
  const { fixture, store } = await coordinatorFixture();
  const executor = new FakeExecutor({
    malformedDiscoveryAttempts: 2,
  });
  const sleeps: number[] = [];
  const terminal = await runCoordinator(fixture, store, executor, {
    retryDelaysMs: [1, 3, 9],
    random: () => 0,
    clock: recordingClock(sleeps),
  });
  assert.equal(terminal?.status, "succeeded");
  assert.deepEqual(sleeps, [1, 3]);
  const promptPaths = [...executor.discoveryPromptPaths.values()][0];
  assert.equal(promptPaths.size, 3);
  const [base, second, third] = await Promise.all(
    [...promptPaths].map((promptPath) => readFile(promptPath, "utf8")),
  );
  assert.doesNotMatch(base, /Deterministic validation retry/);
  assert.match(second, /after attempt 1/);
  assert.doesNotMatch(second, /after attempt 2/);
  assert.match(third, /after attempt 2/);
  assert.doesNotMatch(third, /after attempt 1/);
}

async function testWaiterDetachAndCancellation() {
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    subagents: 1,
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 4,
  });
  const executor = new FakeExecutor({ blockDiscoveryAfterCalls: 0 });
  const coordinator = createCoordinator(fixture, store, executor);
  coordinator.start();
  await executor.discoveryStarted.promise;
  assert.equal(coordinator.snapshot().dispatchedCount, 2);

  const waiterAbort = new AbortController();
  const detached = coordinator.wait(waiterAbort.signal);
  waiterAbort.abort("chat turn stopped");
  await assert.rejects(detached, { name: "AbortError" });
  assert.equal(
    executor.runningDiscovery > 0,
    true,
    "detaching a waiter must not stop workers",
  );

  const timedOut = await coordinator.wait(undefined, 1);
  assert.equal(timedOut, undefined);
  assert.equal(executor.runningDiscovery > 0, true);

  coordinator.cancel("user canceled in UI");
  const canceled = await coordinator.wait(undefined, 5_000);
  assert.equal(canceled?.status, "canceled");
  assert.equal(executor.runningDiscovery, 0);
  assert.ok(
    [...store.workers.values()].every((worker) => worker.status === "canceled"),
  );
}

async function testCancellationDropsUnvalidatedDiscoveryResult() {
  const { fixture, store } = await coordinatorFixture();
  const executor = new FakeExecutor({ blockDiscoveryAfterWrite: true });
  const coordinator = createCoordinator(fixture, store, executor, {
    threadId: "checkpoint-owner",
  });
  coordinator.start();
  await executor.discoveryArtifactsWritten.promise;
  const worker = [...store.workers.values()].find(
    (candidate) => candidate.kind === "discovery",
  );
  const checkpointDir = path.join(worker!.artifactDir, "checkpoints");
  await mkdir(checkpointDir, { recursive: true });
  await writeJson(
    path.join(checkpointDir, "saved.json"),
    standardScanDraft(fixture.run.scanId, "checkpoint-candidate", "saved"),
  );
  coordinator.cancel("fixture canceled before host validation");
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "canceled");
  await assert.rejects(
    readFile(path.join(worker!.artifactDir, "result.json")),
    {
      code: "ENOENT",
    },
  );
  assert.equal(
    (await readdir(path.join(worker!.artifactDir, "checkpoints"))).length > 0,
    true,
    "host-written checkpoints must survive cancellation",
  );
}

async function testCancellationDuringDiscoveryAcceptanceRejectsLateSuccess() {
  const { fixture, store } = await coordinatorFixture();
  store.blockDiscoveryUpdate = "succeeded";
  const executor = new FakeExecutor();
  const events: DeepScanLogEvent[] = [];
  const preserved = Promise.withResolvers<DeepScanRunState>();
  const releasePreservation = Promise.withResolvers<void>();
  const coordinator = createCoordinator(fixture, store, executor, {
    log: (event) => events.push(event),
    threadId: "checkpoint-owner",
    onStopped: async () => {
      const worker = [...store.workers.values()].find(
        (worker) => worker.kind === "discovery",
      );
      const result = await readJson(worker!.artifactDir, "result.json");
      assert.equal(worker!.status, "canceled");
      preserved.resolve(result);
      await releasePreservation.promise;
    },
  });
  coordinator.start();
  await store.discoveryBlocked.promise;

  // The real cancel command persists this state before signaling the coordinator.
  store.run.status = "canceled";
  for (const worker of store.workers.values()) worker.status = "canceled";
  coordinator.cancel("fixture persisted cancellation");
  store.discoveryGate.resolve();

  let terminalSettled = false;
  const terminalPromise = coordinator
    .wait(undefined, 5_000)
    .then((state: DeepScanRunState) => {
      terminalSettled = true;
      return state;
    });
  assert.equal((await preserved.promise).scanId, fixture.run.scanId);
  await Promise.resolve();
  assert.equal(
    terminalSettled,
    false,
    "terminal waiters must not outrun stopped-result preservation",
  );
  releasePreservation.resolve();
  const terminal = await terminalPromise;
  assert.equal(terminal?.status, "canceled");
  assert.ok(
    events.some((event) => event.event === "coordinator_cleanup_settled"),
  );
  assert.equal(
    events.some((event) => event.event === "discovery_accepted"),
    false,
  );
  const worker = [...store.workers.values()].find(
    (worker) => worker.kind === "discovery",
  );
  const result = await readJson(worker!.artifactDir, "result.json");
  assert.equal(
    result.scanId,
    fixture.run.scanId,
    "cancellation must retain saved worker output",
  );
  await assert.rejects(
    readFile(
      path.join(
        fixture.run.scanDir,
        "artifacts",
        "deep_discovery",
        "coordinator-manifest.json",
      ),
    ),
    { code: "ENOENT" },
  );
}

async function testRegistryEvictionAndExternalFailure() {
  const completedFixture = await fixtureRun({
    stopAfterNoNew: 2,
  });
  const completedStore = new FakeStore(completedFixture.run);
  const registry = new DeepScanCoordinatorRegistry();
  const completed = registry.start({
    run: completedFixture.run,
    store: completedStore,
    executor: new FakeExecutor({ discoveryCandidateId: "candidate-1" }),
    pluginRoot: completedFixture.pluginRoot,
    clock: immediateClock,
  });
  assert.equal((await completed.wait(undefined, 5_000))?.status, "succeeded");
  assert.equal(registry.get(completedFixture.run.scanId), undefined);

  const failedFixture = await fixtureRun();
  const failedStore = new FakeStore(failedFixture.run);
  const failedExecutor = new FakeExecutor({ blockDiscoveryAfterCalls: 0 });
  const failed = registry.start({
    run: failedFixture.run,
    store: failedStore,
    executor: failedExecutor,
    pluginRoot: failedFixture.pluginRoot,
    clock: immediateClock,
  });
  await failedExecutor.discoveryStarted.promise;
  failedStore.run.status = "failed";
  failedStore.run.error = "failure already persisted by fail-scan";
  registry
    .get(failedFixture.run.scanId)
    ?.failExternallyPersisted(failedStore.run.error);
  const terminal = await failed.wait(undefined, 5_000);
  assert.equal(terminal?.status, "failed");
  assert.equal(terminal?.error, "failure already persisted by fail-scan");
  assert.equal(failedExecutor.runningDiscovery, 0);
  assert.equal(registry.get(failedFixture.run.scanId), undefined);
  assert.equal(
    failedStore.failureMessages.length,
    0,
    "an externally persisted failure must not be persisted again",
  );
}

async function testStoppedPublicationFailurePreservesOriginalDiagnostic() {
  const { fixture, store } = await coordinatorFixture();
  const executor = new FakeExecutor({ blockDiscoveryAfterCalls: 0 });
  const events: DeepScanLogEvent[] = [];
  const coordinator = createCoordinator(fixture, store, executor, {
    threadId: "checkpoint-owner",
    log: (event) => events.push(event),
    onStopped: async () => {
      throw new Error(
        `fixture retained result publication failure ${"y".repeat(2_350)}`,
      );
    },
  });
  coordinator.start();
  await executor.discoveryStarted.promise;
  store.run.status = "failed";
  store.run.error = `authoritative worker failure diagnostic ${"x".repeat(2_350)}`;
  coordinator.failExternallyPersisted(
    "stale coordinator-local failure diagnostic",
  );

  const terminal = await coordinator.wait(undefined, 5_000);

  assert.equal(terminal?.status, "failed");
  assert.match(
    terminal?.error ?? "",
    /authoritative worker failure diagnostic/,
  );
  assert.doesNotMatch(
    terminal?.error ?? "",
    /stale coordinator-local failure diagnostic/,
  );
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
    events.some(
      (event) => event.event === "coordinator_result_preservation_failed",
    ),
    true,
  );
}

async function testStoppedPublicationFailureBoundsPrefixedDiagnostic() {
  const { fixture, store } = await coordinatorFixture();
  const executor = new FakeExecutor({ blockDiscoveryAfterCalls: 0 });
  const coordinator = createCoordinator(fixture, store, executor, {
    threadId: "checkpoint-owner",
    onStopped: async () => {
      throw new Error(`fixture publication failure ${"z".repeat(2_400)}`);
    },
  });
  coordinator.start();
  await executor.discoveryStarted.promise;
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
  const { fixture, store } = await coordinatorFixture();
  const executor = new FakeExecutor({ blockDiscoveryAfterCalls: 0 });
  const publicationAttempts = mock.fn(async () => {});
  const coordinator = createCoordinator(fixture, store, executor, {
    threadId: "checkpoint-owner",
    onStopped: publicationAttempts,
  });
  coordinator.start();
  await executor.discoveryStarted.promise;
  store.run.status = "failed";
  store.run.error = "original worker failure diagnostic";
  store.failNextTerminalGet = true;
  coordinator.failExternallyPersisted(store.run.error);

  const terminal = await coordinator.wait(undefined, 5_000);

  assert.equal(terminal?.error, "original worker failure diagnostic");
  assert.equal(publicationAttempts.mock.callCount(), 0);
  assert.deepEqual(store.publicationFailureMessages, []);
}

async function testCoordinatorHeartbeatsStopAfterOwnershipChanges() {
  const fixture = await fixtureRun({
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 2,
  });
  const run = {
    ...fixture.run,
    coordinatorGeneration: 2,
    updatedAt: new Date().toISOString(),
  };
  const store = new FakeStore(run);
  const heartbeatCoordinator = mock.fn(async () => {
    return structuredClone(store.run);
  });
  store.heartbeatCoordinator = heartbeatCoordinator;
  let reads = 0;
  store.get = async () => {
    reads += 1;
    if (reads === 1)
      throw new Error("sqlite3.OperationalError: database is locked");
    if (reads === 3) store.run = { ...store.run, coordinatorGeneration: 3 };
    if (reads >= 4)
      store.run = {
        ...store.run,
        status: "succeeded",
        terminalReason: "capped",
      };
    return structuredClone(store.run);
  };
  const executor = new FakeExecutor({ blockDiscoveryAfterCalls: 0 });
  const registry = new DeepScanCoordinatorRegistry();
  const coordinator = registry.start({
    run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock,
    threadId: "thread-fixture",
    heartbeatIntervalMs: 5,
  });
  coordinator.start();
  const current = await coordinator.wait(undefined, 2_000);
  await eventually(() => executor.runningDiscovery === 0);
  await new Promise((resolve) => setTimeout(resolve, 25));

  assert.equal(
    heartbeatCoordinator.mock.callCount(),
    3,
    "heartbeat writes continue until a newer generation is confirmed",
  );
  assert.equal(
    reads,
    4,
    "a failed ownership read must not be treated as lease loss",
  );
  assert.equal(current?.status, "succeeded");
  assert.equal(current?.coordinatorGeneration, 3);
  assert.equal(
    store.failureMessages.length,
    0,
    "a stale coordinator must never fail the new owner",
  );
}

async function testCoordinatorHeartbeatsContinueDuringBlockedOwnershipRead() {
  const fixture = await fixtureRun({
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 2,
  });
  const run = { ...fixture.run, coordinatorGeneration: 2 };
  const store = new FakeStore(run);
  const ownershipRead = Promise.withResolvers<void>();
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
    executor: new FakeExecutor({ blockDiscoveryAfterCalls: 0 }),
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock,
    threadId: "thread-fixture",
    heartbeatIntervalMs: 5,
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
  const fixture = await fixtureRun();
  const store = new FakeStore({ ...fixture.run, coordinatorGeneration: 2 });
  let reads = 0;
  store.get = async () => {
    reads += 1;
    if (reads === 1)
      throw new Error("sqlite3.OperationalError: database is locked");
    return { ...store.run, status: "succeeded", terminalReason: "capped" };
  };
  const options = {
    store,
    executor: new FakeExecutor(),
    pluginRoot: fixture.pluginRoot,
    threadId: "thread-fixture",
  };
  const observer = new DeepScanRemoteCoordinator({
    run: store.run,
    registry: new DeepScanCoordinatorRegistry(),
    options,
  });

  assert.equal((await observer.wait(undefined, 2_000))?.status, "succeeded");
  assert.equal(reads, 2);
  store.get = async () => {
    throw new Error(
      "Deep Scan orchestration is owned by another continuation.",
    );
  };
  await assert.rejects(
    observer.wait(undefined, 2_000),
    /owned by another continuation/,
  );

  for (const outcome of [
    "locked",
    "succeeded",
    "canceled",
    "terminal-read-locked",
    "unauthorized",
  ] as const) {
    store.run = {
      ...fixture.run,
      coordinatorGeneration: 2,
      updatedAt: "2000-01-01T00:00:00Z",
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
        if (claims === 1)
          throw new Error("sqlite3.OperationalError: database is locked");
        store.run = {
          ...store.run,
          status: "succeeded",
          terminalReason: "capped",
        };
        return { run: store.run, acquired: false };
      }
      if (outcome === "unauthorized") {
        throw new Error(
          "Deep Scan orchestration is owned by another continuation.",
        );
      }
      store.run = {
        ...store.run,
        status: outcome === "terminal-read-locked" ? "succeeded" : outcome,
      };
      throw new Error(
        "Only a running Deep Scan can update orchestration state.",
      );
    };
    const remote = new DeepScanRemoteCoordinator({
      run: store.run,
      registry: new DeepScanCoordinatorRegistry(),
      options,
    });
    remote.nextClaimAt = 0;
    if (outcome === "unauthorized") {
      await assert.rejects(
        remote.wait(undefined, 2_500),
        /owned by another continuation/,
      );
    } else {
      assert.equal(
        (await remote.wait(undefined, 2_500))?.status,
        ["locked", "terminal-read-locked"].includes(outcome)
          ? "succeeded"
          : outcome,
      );
      assert.equal(claims, outcome === "locked" ? 2 : 1);
      if (outcome === "terminal-read-locked") assert.equal(outcomeReads, 3);
    }
  }
}

async function testStaleMutationObservesReplacement() {
  const fixture = await fixtureRun({
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 2,
  });
  const run = { ...fixture.run, coordinatorGeneration: 2 };
  const store = new FakeStore(run);
  store.updateProgress = async () => {
    throw new Error(
      "Deep Scan coordinator lease belongs to a newer generation.",
    );
  };
  let reads = 0;
  store.get = async () => {
    reads += 1;
    store.run =
      reads === 1
        ? { ...store.run, coordinatorGeneration: 3 }
        : {
            ...store.run,
            coordinatorGeneration: 3,
            status: "succeeded",
            terminalReason: "capped",
          };
    return structuredClone(store.run);
  };
  const coordinator = new DeepScanCoordinatorRegistry().start({
    run,
    store,
    executor: new FakeExecutor(),
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock,
    threadId: "thread-fixture",
    heartbeatIntervalMs: 60_000,
  });

  const terminal = await coordinator.wait(undefined, 2_000);

  assert.equal(terminal?.status, "succeeded");
  assert.equal(terminal?.coordinatorGeneration, 3);
  assert.equal(
    store.failureMessages.length,
    0,
    "a fenced mutation must observe rather than fail the replacement",
  );
}

async function testJoinAndOrphanRules() {
  const fixture = await fixtureRun({
    workers: 2,
    subagents: 1,
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 2,
  });
  const existingCoordinator = { marker: "existing" };
  const defaults = {
    executor: {},
    pluginRoot: fixture.pluginRoot,
    threadId: "thread-fixture",
  };
  const starts = mock.fn(() => existingCoordinator);
  const failures = mock.fn(async () => {});
  const existing = await startOrJoinDeepScanCoordinator({
    run: fixture.run,
    registry: {
      get: () => existingCoordinator,
      start: starts,
    },
    options: {
      ...defaults,
      store: {
        fail: failures,
      },
    },
  });
  assert.equal(existing.coordinator, existingCoordinator);
  assert.equal(existing.joined, true);
  assert.equal(starts.mock.callCount(), 0);
  assert.equal(failures.mock.callCount(), 0);

  const running = {
    ...fixture.run,
    coordinatorGeneration: 2,
    updatedAt: new Date().toISOString(),
  };
  const observed = await startOrJoinDeepScanCoordinator({
    run: running,
    registry: {
      get: () => undefined,
      start: starts,
    },
    options: {
      ...defaults,
      store: {
        claimCoordinator: async () => ({ run: running, acquired: false }),
        get: async () => ({ ...running, status: "succeeded" }),
        fail: failures,
      },
    },
  });
  assert.equal(observed.joined, true);
  assert.equal(
    (await observed.coordinator.wait(undefined, 1_000))?.status,
    "succeeded",
  );
  assert.equal(
    starts.mock.callCount(),
    0,
    "another process must not create a duplicate coordinator",
  );
  assert.equal(
    failures.mock.callCount(),
    0,
    "another process must not interrupt the live scan",
  );

  const staleClaims = mock.fn(async () => {
    return { run: staleRunning, acquired: false };
  });
  const staleRunning = { ...running, updatedAt: "2026-01-01T00:00:00Z" };
  const staleObserver = await startOrJoinDeepScanCoordinator({
    run: staleRunning,
    registry: { get: () => undefined, start: () => existingCoordinator },
    options: {
      ...defaults,
      store: {
        claimCoordinator: staleClaims,
        get: async () => staleRunning,
      },
    },
  });
  assert.equal(
    await staleObserver.coordinator.wait(undefined, 1_100),
    undefined,
  );
  assert.equal(
    staleClaims.mock.callCount(),
    1,
    "a confirmed live lease must not be reclaimed on every poll",
  );

  const recovered = await startOrJoinDeepScanCoordinator({
    run: fixture.run,
    registry: {
      get: () => undefined,
      start: (options: CoordinatorOptions) => {
        starts();
        assert.equal(options.run.coordinatorGeneration, 2);
        return existingCoordinator;
      },
    },
    options: {
      ...defaults,
      store: {
        claimCoordinator: async () => ({
          acquired: true,
          run: { ...fixture.run, coordinatorGeneration: 2 },
        }),
        fail: failures,
      },
    },
  });
  assert.equal(recovered.coordinator, existingCoordinator);
  assert.equal(recovered.joined, false);
  assert.equal(
    starts.mock.callCount(),
    1,
    "only an expired coordinator may be adopted",
  );
  assert.equal(
    failures.mock.callCount(),
    0,
    "recovering an orphan must not fail the logical scan",
  );

  const lock = new AsyncLock();
  const firstGate = Promise.withResolvers<void>();
  let liveCoordinator: { marker: string } | undefined;
  starts.mock.resetCalls();
  const registry = {
    get: () => liveCoordinator,
    start: () => {
      starts();
      liveCoordinator = { marker: "concurrent" };
      return liveCoordinator;
    },
  };
  const options = {
    ...defaults,
    store: {
      claimCoordinator: async () => ({ acquired: true, run: fixture.run }),
      fail: failures,
    },
  };
  const first = lock.run(async () => {
    await firstGate.promise;
    return await startOrJoinDeepScanCoordinator({
      run: fixture.run,
      registry,
      options,
    });
  });
  const second = lock.run(
    async () =>
      await startOrJoinDeepScanCoordinator({
        run: fixture.run,
        registry,
        options,
      }),
  );
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(
    starts.mock.callCount(),
    0,
    "the second caller must wait through begin plus registry start",
  );
  firstGate.resolve();
  const [created, joined] = await Promise.all([first, second]);
  assert.equal(created.joined, false);
  assert.equal(joined.joined, true);
  assert.equal(created.coordinator, joined.coordinator);
  assert.equal(starts.mock.callCount(), 1);
  assert.equal(failures.mock.callCount(), 0);
}

async function testPausedDiscoverySurvivesCoordinatorRestart() {
  const fixture = await fixtureRun({
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 2,
  });
  const handoffClaimToken = randomUUID();
  const store = new FakeStore({
    ...fixture.run,
    coordinatorGeneration: 2,
    updatedAt: "2026-08-03T13:33:08Z",
  });
  const originalExecutor = new FakeExecutor({ blockDiscoveryAfterCalls: 1 });
  const original = createCoordinator(fixture, store, originalExecutor, {
    run: store.run,
    handoffClaimToken,
  });
  original.start();
  await eventually(
    () =>
      [...store.workers.values()].some(
        (worker) =>
          worker.kind === "discovery" && worker.status === "succeeded",
      ) && originalExecutor.discoveryCalls >= 2,
  );
  const accepted = [...store.workers.values()].find(
    (worker) => worker.kind === "discovery" && worker.status === "succeeded",
  );
  assert.ok(accepted);

  // The waiter detached earlier; an app update now removes its MCP process
  // without canceling or finalizing the persisted scan.
  original.cancel("mcp server process restarted");
  await eventually(() => originalExecutor.runningDiscovery === 0);
  const persistedWorkers = structuredClone([...store.workers.values()]);
  const independentReviews = {
    completed: persistedWorkers.filter(
      (worker) => worker.kind === "discovery" && worker.status === "succeeded",
    ).length,
    active: persistedWorkers.filter(
      (worker) => worker.kind === "discovery" && worker.status === "running",
    ).length,
    consolidating: persistedWorkers.some(
      (worker) => worker.kind === "dedup" && worker.status === "running",
    ),
  };
  assert.deepEqual(independentReviews, {
    completed: 1,
    active: 0,
    consolidating: false,
  });
  assert.equal(store.run.status, "running");
  assert.equal(store.progress.at(-1)?.phase, "discovery");
  assert.equal(store.finishCalls.length, 0);
  assert.equal(store.failureMessages.length, 0);
  assert.equal(store.run.manifestPath, undefined);
  await assert.rejects(
    readFile(
      path.join(
        fixture.run.scanDir,
        "artifacts",
        "deep_discovery",
        "coordinator-manifest.json",
      ),
    ),
    { code: "ENOENT" },
  );

  store.run = {
    ...store.run,
    dispatchedCount: 1,
    persistedWorkers,
  };
  const continuationClaims: StoreInput<"claimCoordinator">[] = [];
  store.claimCoordinator = async (input) => {
    continuationClaims.push(structuredClone(input!));
    assert.equal(input!.handoffClaimToken, handoffClaimToken);
    store.run = {
      ...store.run,
      coordinatorGeneration: 3,
      updatedAt: new Date().toISOString(),
    };
    return { acquired: true, run: structuredClone(store.run) };
  };
  store.heartbeatCoordinator = async () => structuredClone(store.run);
  const replacementExecutor = new FakeExecutor();
  const acceptedResult = await readFile(accepted.resultManifestPath!, "utf8");
  const resumed = await startOrJoinDeepScanCoordinator({
    run: structuredClone(store.run),
    registry: new DeepScanCoordinatorRegistry(),
    options: {
      store,
      executor: replacementExecutor,
      pluginRoot: fixture.pluginRoot,
      clock: immediateClock,
      threadId: "track-c-owning-thread",
      handoffClaimToken,
    },
  });
  const terminal = await resumed.coordinator.wait(undefined, 5_000);

  assert.equal(continuationClaims.length, 1);
  assert.equal(continuationClaims[0].handoffClaimToken, handoffClaimToken);
  assert.equal(terminal?.status, "succeeded");
  assert.equal(store.failureMessages.length, 0);
  assert.equal(replacementExecutor.discoveryAttempts.size, 1);
  assert.equal(
    replacementExecutor.discoveryAttempts.has(
      await workerIdFromPrompt(accepted.promptPath),
    ),
    false,
  );
  assert.equal(store.dedupClaims.length, 1);
  assert.equal(store.dedupClaims[0].workerIds.includes(accepted.id), true);
  const manifest = await readJson(terminal.manifestPath);
  assert.equal(manifest.scan.scanId, fixture.run.scanId);
  assert.equal(store.dedupClaims[0].workerIds.length, 2);
  assert.equal(
    await readFile(accepted.resultManifestPath!, "utf8"),
    acceptedResult,
  );
}

async function testResumedDiscoveryDeadlineUsesPersistedCreationTime(
  alreadyExpired = false,
  maxTimeHours?: number,
) {
  const fixture = await fixtureRun({
    stopAfterNoNew: 99,
    maxDiscoveryRuns: 8,
    ...(maxTimeHours === undefined ? {} : { maxTimeHours }),
  });
  const discoveryTimeoutMs = (maxTimeHours ?? 96) * 60 * 60 * 1_000;
  let currentTime = immediateClock.now();
  const clock = {
    now: () => currentTime,
    sleep: immediateClock.sleep,
  };
  const createdAt = new Date(
    currentTime - discoveryTimeoutMs + 30_000,
  ).toISOString();
  const store = new FakeStore({
    ...fixture.run,
    createdAt,
    coordinatorGeneration: 2,
  });
  const originalExecutor = new FakeExecutor({
    blockDiscoveryAfterCalls: 1,
    discoveryCandidateId: "candidate-1",
  });
  const original = createCoordinator(fixture, store, originalExecutor, {
    run: store.run,
    clock,
  });
  original.start();
  await eventually(
    () =>
      originalExecutor.discoveryCalls === 2 &&
      originalExecutor.runningDiscovery === 1 &&
      [...store.workers.values()].some(
        (worker) =>
          worker.kind === "discovery" && worker.status === "succeeded",
      ),
  );

  original.cancel("mcp server process restarted");
  await eventually(() => originalExecutor.runningDiscovery === 0);
  assert.equal(store.run.status, "running");
  assert.equal(store.run.createdAt, createdAt);
  currentTime =
    Date.parse(createdAt) +
    discoveryTimeoutMs +
    (alreadyExpired ? 1_000 : -1_000);
  store.run = {
    ...store.run,
    persistedWorkers: structuredClone([...store.workers.values()]),
  };

  const resumedExecutor = new FakeExecutor({
    blockDiscoveryAfterCalls: 0,
    canonicalCandidateId: "candidate-1",
    discoveryCandidateId: "candidate-1",
  });
  const resumed = createCoordinator(fixture, store, resumedExecutor, {
    run: store.run,
    clock,
  });
  resumed.start();
  if (!alreadyExpired) await resumedExecutor.discoveryStarted.promise;

  const terminal = await resumed.wait(undefined, 5_000);
  assert.equal(terminal?.status, "succeeded");
  assert.equal(terminal?.terminalReason, "capped");
  assert.equal(store.failureMessages.length, 0);
  assert.equal(resumedExecutor.discoveryCalls, alreadyExpired ? 0 : 1);
  assert.equal(resumedExecutor.dedupCalls, 1);
  assert.equal(resumedExecutor.runningDiscovery, 0);

  const manifest = await readJson(terminal.manifestPath);
  assert.equal(store.run.config.maxTimeHours, maxTimeHours);
  assert.equal(store.dedupClaims[0].workerIds.length, 1);
  assert.equal(
    [...store.workers.values()].some((worker) => worker.status === "canceled"),
    true,
  );
  assert.deepEqual(
    manifest.findings.map(
      (finding: Record<string, unknown>) =>
        (finding.provenance as { candidateId: string }).candidateId,
    ),
    ["candidate-1"],
  );
}

async function testResumedManifestPreservesCompletedReducer(
  includeUnstartedReducer = false,
) {
  const fixture = await fixtureRun({
    workers: 2,
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 3,
  });
  const store = new FakeStore(fixture.run);
  store.dedupCommitResponseGate = Promise.withResolvers<void>();
  const original = createCoordinator(
    fixture,
    store,
    new FakeExecutor({
      blockDiscoveryAfterCalls: 2,
    }),
    { run: store.run },
  );
  original.start();
  await store.dedupCommitted.promise;
  original.cancel("mcp server process restarted");
  store.dedupCommitResponseGate.resolve();
  await original.settled();
  assert.ok(
    [...store.workers.values()].every(
      (worker) => worker.status !== "queued" && worker.status !== "running",
    ),
  );

  let unstartedReducer: TestWorker | undefined;
  if (includeUnstartedReducer) {
    const artifactDir = path.join(
      fixture.run.scanDir,
      "artifacts",
      "deep_discovery",
      "dedup",
      "dedup-unstarted",
      "output",
    );
    await mkdir(artifactDir, { recursive: true });
    const promptPath = path.join(path.dirname(artifactDir), "prompt.md");
    await writeFile(
      promptPath,
      "Reducer claimed before coordinator restart.\n",
    );
    unstartedReducer = {
      id: randomUUID(),
      kind: "dedup" as const,
      status: "canceled" as const,
      promptPath,
      artifactDir,
      attempt: 0,
      mergeState: "none" as const,
    };
    store.workers.set(unstartedReducer.id, unstartedReducer);
  }

  store.run = {
    ...store.run,
    status: "running" as const,
    persistedWorkers: structuredClone([...store.workers.values()]),
    persistedDedupInputs: store.dedupClaims.flatMap(claimDedupInputs),
  };
  const terminal = await runCoordinator(fixture, store, new FakeExecutor(), {
    run: store.run,
  });
  assert.equal(terminal?.status, "succeeded");
  const manifest = await readJson(terminal.manifestPath);
  assert.equal(manifest.scan.scanId, fixture.run.scanId);
  assert.equal(store.dedupCommits.length, 1);
  assert.equal(store.dedupClaims.length, 1);
  assert.equal(
    store.run.persistedWorkers!.some(
      (worker) => worker.id === unstartedReducer?.id,
    ),
    includeUnstartedReducer,
  );
}

async function testResumeUsesHistoricalCandidateSnapshotForEachReducer() {
  const { fixture, store } = await coordinatorFixture({
    workers: 3,
    stopAfterNoNew: 10,
    maxDiscoveryRuns: 5,
  });
  const original = createCoordinator(
    fixture,
    store,
    new FakeExecutor({
      discoveryCandidateId: "candidate-1",
      dedupEvidenceByCall: ["first reducer evidence", "final reducer evidence"],
    }),
  );
  original.start();
  assert.equal((await original.wait(undefined, 5_000))?.status, "succeeded");
  assert.equal(store.dedupClaims.length >= 2, true);

  store.run = {
    ...store.run,
    status: "running" as const,
    terminalReason: undefined,
    manifestPath: undefined,
    persistedWorkers: structuredClone([...store.workers.values()]),
    persistedDedupInputs: store.dedupClaims.flatMap(claimDedupInputs),
  };
  const completedDrafts: ScanDraftInput[] = [];
  const resumed = await runCoordinator(fixture, store, new FakeExecutor(), {
    run: store.run,
    onComplete: async (draft) =>
      void completedDrafts.push(structuredClone(draft)),
  });
  assert.equal(resumed?.status, "succeeded", resumed?.error);
  const firstReducer = store.run.persistedWorkers!.find(
    (worker) =>
      worker.kind === "dedup" && worker.promptPath.includes("dedup-0001"),
  );
  assert.ok(firstReducer);
  const firstResult = await readJson(firstReducer.resultManifestPath!);
  assert.equal(
    firstResult.findings[0]?.rootCause.summary,
    "first reducer evidence",
  );
  const lastReducer = store.run.persistedWorkers!.findLast(
    (worker) => worker.kind === "dedup" && worker.status === "succeeded",
  );
  const latestResult = await readJson(lastReducer!.resultManifestPath!);
  assert.equal(
    latestResult.findings[0]?.rootCause.summary,
    "final reducer evidence",
  );
  assert.deepEqual(
    completedDrafts.map((draft) => draft.findings),
    [latestResult.findings],
  );
}

async function testPersistedErrorLimitStopsBeforeRescheduling() {
  const fixture = await fixtureRun({
    stopAfterNoNew: 2,
    stopAfterConsecutiveErrors: 2,
    maxDiscoveryRuns: 2,
  });
  const failedWorker = {
    id: randomUUID(),
    kind: "discovery" as const,
    status: "canceled" as const,
    promptPath: path.join(fixture.run.scanDir, "failed", "prompt.md"),
    artifactDir: path.join(fixture.run.scanDir, "failed", "output"),
    attempt: 1,
    mergeState: "none" as const,
    error: "transient_error: persisted worker failure",
  };
  for (const promptExists of [false, true]) {
    if (promptExists) {
      await mkdir(path.dirname(failedWorker.promptPath), { recursive: true });
      await writeFile(failedWorker.promptPath, "persisted failed prompt\n");
    }
    const run = {
      ...fixture.run,
      consecutiveErrors: 2,
      dispatchedCount: 1,
      persistedWorkers: [failedWorker],
    };
    const store = new FakeStore(run);
    const executor = new FakeExecutor();
    const terminal = await runCoordinator(fixture, store, executor, {
      run,
    });
    assert.equal(terminal?.status, "failed");
    assert.equal(executor.discoveryCalls, 0);
    assert.match(
      terminal?.error ?? "",
      promptExists ? /2 consecutive unsuccessful discovery workers/ : /ENOENT/,
    );
    if (promptExists)
      assert.match(terminal?.error ?? "", /persisted worker failure/);
    assert.equal(terminal.manifestPath, undefined);
    assert.equal(store.run.persistedWorkers![0].id, failedWorker.id);
  }
}

async function testPersistedReducerErrorLimitStopsBeforeRescheduling() {
  const fixture = await fixtureRun({
    stopAfterNoNew: 3,
    stopAfterConsecutiveErrors: 2,
    maxDiscoveryRuns: 2,
  });
  const reducers = await Promise.all(
    [1, 2].map(async (index) => {
      const directory = path.join(
        fixture.run.scanDir,
        `dedup-${String(index).padStart(4, "0")}`,
      );
      await mkdir(directory, { recursive: true });
      const promptPath = path.join(directory, "prompt.md");
      await writeFile(promptPath, `persisted reducer ${index}\n`);
      return {
        id: randomUUID(),
        kind: "dedup" as const,
        status: "failed" as const,
        promptPath,
        artifactDir: directory,
        attempt: 1,
        mergeState: "none" as const,
        error: `persisted reducer failure ${index}`,
      };
    }),
  );
  const run = {
    ...fixture.run,
    consecutiveErrors: 0,
    persistedWorkers: reducers,
  };
  const store = new FakeStore(run);
  const executor = new FakeExecutor();
  const terminal = await runCoordinator(fixture, store, executor, { run });

  assert.equal(terminal?.status, "failed");
  assert.equal(executor.discoveryCalls, 0);
  assert.equal(store.run.consecutiveErrors, 0);
  assert.match(
    terminal?.error ?? "",
    /2 consecutive unsuccessful reducer workers/,
  );
  assert.match(terminal?.error ?? "", /persisted reducer failure 2/);
}

async function testDiscoveryDeadlineDrainsActiveReducerAndPreservesFindings() {
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    stopAfterNoNew: 99,
    maxDiscoveryRuns: 12,
  });
  const executor = new FakeExecutor({
    blockDiscoveryAfterCalls: 2,
    discoveryCandidateId: "candidate-1",
    canonicalCandidateId: "candidate-1",
  });
  executor.dedupGate = Promise.withResolvers<void>();
  const coordinator = createCoordinator(fixture, store, executor, {
    discoveryTimeoutMs: 500,
  });
  coordinator.start();

  await executor.dedupStarted.promise;
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
  executor.dedupGate.resolve();

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "succeeded");
  assert.equal(terminal?.terminalReason, "capped");
  assert.equal(store.failureMessages.length, 0);
  assert.equal(executor.discoveryCalls, discoveryCallsAtDeadline);
  assert.equal(
    terminal.dispatchedCount < fixture.run.config.maxDiscoveryRuns,
    true,
  );

  const manifest = await readJson(terminal.manifestPath);
  assert.equal(manifest.scan.scanId, fixture.run.scanId);
  assert.deepEqual(store.finishCalls[0].omittedWorkerIds, []);
  assert.equal(
    [...store.workers.values()].some((worker) => worker.status === "canceled"),
    true,
  );
  assert.equal(store.dedupCommits.length, 1);
  assert.deepEqual(
    manifest.findings.map(
      (finding: { provenance: { candidateId: string } }) =>
        finding.provenance.candidateId,
    ),
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
  const { fixture, store } = await coordinatorFixture({
    stopAfterNoNew: 99,
    maxDiscoveryRuns: 8,
  });
  const executor = new FakeExecutor({
    blockDiscoveryAfterCalls: 1,
    discoveryCandidateId: "candidate-1",
    canonicalCandidateId: "candidate-1",
  });
  const coordinator = createCoordinator(fixture, store, executor, {
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
  assert.equal(store.failureMessages.length, 0);
  assert.equal(executor.dedupCalls, 1);
  assert.equal(executor.runningDiscovery, 0);

  const manifest = await readJson(terminal.manifestPath);
  assert.equal(store.dedupClaims[0].workerIds.length, 1);
  assert.deepEqual(store.finishCalls[0].omittedWorkerIds, []);
  assert.equal(
    [...store.workers.values()].filter((worker) => worker.status === "canceled")
      .length,
    1,
  );
  assert.equal(store.dedupCommits.length, 1);
  assert.deepEqual(
    manifest.findings.map(
      (finding: { provenance: { candidateId: string } }) =>
        finding.provenance.candidateId,
    ),
    ["candidate-1"],
  );
}

async function testDiscoveryAcceptedAtDeadlineIsReduced() {
  const { fixture, store } = await coordinatorFixture({
    stopAfterNoNew: 99,
    maxDiscoveryRuns: 8,
  });
  const acceptancePersisted = Promise.withResolvers<void>();
  const releaseAcceptance = Promise.withResolvers<void>();
  const discoveryDeadlineReached = Promise.withResolvers<void>();
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
  });
  const terminalWait = runCoordinator(fixture, store, executor, {
    discoveryTimeoutMs: 500,
    log: (event) => {
      if (event.event === "discovery_deadline_reached")
        discoveryDeadlineReached.resolve();
    },
  });

  await acceptancePersisted.promise;
  await discoveryDeadlineReached.promise;
  releaseAcceptance.resolve();

  const terminal = await terminalWait;
  assert.equal(terminal?.status, "succeeded");
  assert.equal(terminal?.terminalReason, "capped");
  assert.equal(store.failureMessages.length, 0);
  assert.equal(executor.discoveryCalls, 1);
  assert.equal(executor.dedupCalls, 1);

  const manifest = await readJson(terminal.manifestPath);
  assert.equal(store.dedupClaims[0].workerIds.length, 1);
  assert.deepEqual(store.finishCalls[0].omittedWorkerIds, []);
  assert.equal(
    [...store.workers.values()].some((worker) => worker.status === "canceled"),
    false,
  );
  assert.deepEqual(
    manifest.findings.map(
      (finding: { provenance: { candidateId: string } }) =>
        finding.provenance.candidateId,
    ),
    ["candidate-1"],
  );
}

async function testDiscoveryDeadlineWithoutAcceptedWorkersReturnsPartialEvidence() {
  const { fixture, store } = await coordinatorFixture({
    stopAfterNoNew: 99,
    maxDiscoveryRuns: 8,
  });
  const executor = new FakeExecutor({ blockDiscoveryAfterCalls: 0 });
  const completedDrafts: ScanDraftInput[] = [];
  const coordinator = createCoordinator(fixture, store, executor, {
    discoveryTimeoutMs: 500,
    onComplete: async (draft) =>
      void completedDrafts.push(structuredClone(draft)),
  });
  coordinator.start();
  await executor.discoveryStarted.promise;

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "succeeded");
  assert.equal(terminal?.terminalReason, "capped");
  assert.equal(store.failureMessages.length, 0);
  assert.equal(store.finishCalls.length, 1);
  assert.equal(executor.runningDiscovery, 0);
  assert.equal(executor.dedupCalls, 0);

  const manifest = await readJson(terminal.manifestPath);
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
    [...store.workers.values()].filter((worker) => worker.status === "canceled")
      .length,
    1,
  );
  assert.equal(store.dedupCommits.length, 0);
}

async function testDiscoveryDeadlineBeforeWorkerDispatchReturnsPartialEvidence() {
  const fixture = await fixtureRun({
    stopAfterNoNew: 99,
    maxDiscoveryRuns: 8,
    maxTimeHours: 1e-12,
  });
  fixture.run.createdAt = new Date(immediateClock.now()).toISOString();
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor();
  const terminal = await runCoordinator(fixture, store, executor);
  assert.equal(terminal?.status, "succeeded");
  assert.equal(terminal?.terminalReason, "capped");
  assert.equal(store.failureMessages.length, 0);
  assert.equal(store.finishCalls.length, 1);
  assert.equal(executor.discoveryCalls, 0);
  assert.equal(executor.dedupCalls, 0);

  const manifest = await readJson(terminal.manifestPath);
  assert.deepEqual(manifest.findings, []);
  assert.equal(manifest.coverage.completeness, "partial");
  assert.deepEqual(store.finishCalls[0].omittedWorkerIds, []);
  assert.equal(store.workers.size, 0);
}

async function testSaturationOmitsWorkerAcceptedDuringCancellation() {
  const { fixture, store } = await coordinatorFixture({
    workers: 3,
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 3,
  });
  const releaseLateWorker = Promise.withResolvers<void>();
  const lateAcceptance = Promise.withResolvers<void>();
  const releaseAcceptance = Promise.withResolvers<void>();
  const updateWorker = store.updateWorker.bind(store);
  let acceptedLateWorker;
  store.updateWorker = async (update) => {
    const persisted = await updateWorker(update);
    if (
      update.kind === "discovery" &&
      update.status === "succeeded" &&
      path.basename(path.dirname(update.promptPath)) === "discovery-0003"
    ) {
      acceptedLateWorker = persisted;
      // This worker finishes too late to be included in the final result.
      await rm(update.resultManifestPath!);
      lateAcceptance.resolve();
      await releaseAcceptance.promise;
    }
    return persisted;
  };
  const executor = new FakeExecutor({
    discoveryGates: { "discovery-0003": releaseLateWorker.promise },
    discoveryCandidates: { "discovery-0003": "late-accepted-finding" },
  });
  executor.dedupGate = Promise.withResolvers<void>();
  const completed: ScanDraftInput[] = [];
  const coordinator = createCoordinator(fixture, store, executor, {
    onComplete: async (draft) => void completed.push(structuredClone(draft)),
  });
  coordinator.start();
  await executor.dedupStarted.promise;
  releaseLateWorker.resolve();
  await lateAcceptance.promise;
  executor.dedupGate.resolve();
  await eventually(() => executor.dedupSignal?.aborted === true);
  releaseAcceptance.resolve();
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(terminal.terminalReason, "saturated");
  assert.equal(executor.discoveryCalls, 3);
  assert.equal(
    executor.dedupCalls,
    1,
    "late accepted results do not restart convergence",
  );
  assert.deepEqual(store.finishCalls[0].omittedWorkerIds, [
    acceptedLateWorker!.id,
  ]);
  assert.equal(completed.length, 1);
  assert.equal(completed[0].coverage.completeness, "complete");
  assert.deepEqual(
    completed[0].findings,
    [],
    "late worker findings are not appended to the saturated aggregate",
  );
}

async function testSuccessfulDeepCoverageIgnoresWorkerAndReducerReviewStatus() {
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 2,
  });
  const executor = new FakeExecutor();
  const run = executor.run.bind(executor);
  const reviewed = { label: "Reviewed query", disposition: "no_issue_found" };
  const workerReviewed = {
    ...reviewed,
    receiptRefs: ["artifacts/missing-worker-receipt.md"],
  };
  const followUp = {
    label: "Worker follow-up",
    disposition: "needs_follow_up",
  };
  executor.run = async (request) => {
    const outcome = await run(request);
    const resultPath = path.join(request.artifactContext!.root, "result.json");
    const draft = await readJson(resultPath);
    draft.coverage = {
      completeness:
        request.kind === "discovery" &&
        request.promptPath.includes("discovery-0002")
          ? "unknown"
          : "partial",
      surfaces: [workerReviewed, followUp],
      explicitExclusions: [],
      deferred: [
        { reason: "An independent review left this question unresolved." },
      ],
    };
    await writeJson(resultPath, draft);
    return outcome;
  };
  const completed: ScanDraftInput[] = [];
  const terminal = await runCoordinator(fixture, store, executor, {
    onComplete: async (draft) => void completed.push(structuredClone(draft)),
  });
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(completed.length, 1);
  assert.deepEqual(completed[0].coverage, {
    completeness: "complete",
    surfaces: [],
    explicitExclusions: [],
    deferred: [],
  });
  for (const worker of store.workers.values()) {
    if (worker.kind !== "discovery") continue;
    const draft = await readJson(worker.resultManifestPath!);
    assert.notEqual(draft.coverage.completeness, "complete");
    assert.deepEqual(draft.coverage.surfaces, [workerReviewed, followUp]);
    assert.equal(draft.coverage.deferred.length, 1);
  }
}

async function testSaturationIgnoresDiscoveryCancellationWriteFailure() {
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 6,
  });
  const executor = new FakeExecutor({
    blockDiscoveryAfterCalls: 2,
  });
  executor.dedupGate = Promise.withResolvers<void>();
  const updateWorker = store.updateWorker.bind(store);
  const rejectedCancellations = new Set();
  store.updateWorker = async (update) => {
    if (update.kind === "discovery" && update.status === "canceled") {
      assert.equal(executor.dedupSignal?.aborted, true);
      assert.equal(store.run.noNewStreak, 2);
      rejectedCancellations.add(update.id);
      throw new Error("fixture cancellation persistence failure");
    }
    return updateWorker(update);
  };
  const completed: ScanDraftInput[] = [];
  const coordinator = createCoordinator(fixture, store, executor, {
    onComplete: async (draft) => void completed.push(structuredClone(draft)),
  });
  coordinator.start();
  await executor.dedupStarted.promise;
  await eventually(
    () => executor.discoveryCalls === 4 && executor.runningDiscovery === 2,
  );
  executor.dedupGate.resolve();

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(
    rejectedCancellations.size,
    2,
    "the redundant discoveries reached the failing cancellation write",
  );
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(terminal.terminalReason, "saturated");
  assert.equal(store.failureMessages.length, 0);
  assert.equal(store.finishCalls.length, 1);
  assert.equal(store.finishCalls[0].reason, "saturated");
  assert.equal(
    executor.discoveryCalls,
    4,
    "cancellation persistence failures must not dispatch replacement reviews after saturation",
  );
  assert.equal(
    executor.dedupCalls,
    1,
    "cancellation persistence failures must not restart reduction after saturation",
  );
  assert.equal(executor.runningDiscovery, 0);
  assert.equal(completed.length, 1);
  assert.equal(completed[0].coverage.completeness, "complete");
  const acceptedReducer = [...store.workers.values()].find(
    (worker) => worker.kind === "dedup" && worker.status === "succeeded",
  );
  const { coverage, ...publishedReduction } = completed[0];
  assert.deepEqual(
    publishedReduction,
    await readJson(acceptedReducer!.resultManifestPath!),
    "the accepted aggregate still reaches publication when redundant cancellation writes fail",
  );
}

async function testPublicationUsesAcceptedReducerSnapshot() {
  const { fixture, store } = await coordinatorFixture();
  const commitDedup = store.commitDedup.bind(store);
  store.commitDedup = async (commit) => {
    const accepted = await commitDedup(commit);
    await rm(commit.resultManifestPath);
    return accepted;
  };
  store.finish = async (input) => {
    store.finishCalls.push(input);
    Object.assign(store.run, {
      status: "succeeded",
      terminalReason: input.reason,
      manifestPath: input.manifestPath,
    });
    return structuredClone(store.run);
  };
  const completed: ScanDraftInput[] = [];
  const terminal = await runCoordinator(
    fixture,
    store,
    new FakeExecutor({ discoveryCandidateId: "accepted-finding" }),
    {
      onComplete: async (draft) => void completed.push(structuredClone(draft)),
    },
  );
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(
    (completed[0].findings[0].provenance as { candidateId: string })
      .candidateId,
    "accepted-finding",
  );
  assert.equal(completed[0].coverage.completeness, "complete");
}

async function testResumeRequiresHistoricalWorkerPrompt(
  status: "failed" | "canceled",
) {
  const fixture = await fixtureRun({
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 2,
  });
  const promptPath = path.join(fixture.run.scanDir, "missing-prompt.md");
  const store = new FakeStore({
    ...fixture.run,
    persistedWorkers: [
      {
        id: "historical-worker",
        kind: "discovery",
        status,
        attempt: 1,
        promptPath,
        artifactDir: fixture.run.scanDir,
      } as PersistedDeepScanWorker,
    ],
  });
  const executor = new FakeExecutor();
  const terminal = await runCoordinator(fixture, store, executor, {
    run: store.run,
  });
  assert.equal(terminal?.status, "failed");
  assert.match(terminal.error, /ENOENT/);
  assert.ok(terminal.error.includes(promptPath));
  assert.equal(executor.discoveryCalls, 0);
}

async function testRecoverableWorkerErrorsCannotFailScan() {
  const failures = ["config unknown", "authentication required"].map(
    (output) =>
      new Error(
        `Failed to parse item: ${JSON.stringify({
          type: "item.completed",
          item: {
            id: "fixture-command",
            type: "command_execution",
            command: "synthetic-command",
            aggregated_output: output,
          },
        })}`,
      ),
  );
  failures.push(
    ...["ENOENT", "EACCES", "ENOEXEC", "EPERM"].map((code) =>
      Object.assign(new Error("fixture worker I/O failure"), { code }),
    ),
  );
  for (const failure of failures) {
    const { fixture, store } = await coordinatorFixture({
      workers: 2,
      stopAfterNoNew: 4,
      stopAfterConsecutiveErrors: 2,
      maxDiscoveryRuns: 4,
    });
    const normalExecutor = new FakeExecutor();
    const attempts: (string | undefined)[] = [];
    const events: DeepScanLogEvent[] = [];
    const terminal = await runCoordinator(
      fixture,
      store,
      {
        async run(request) {
          if (
            request.kind === "discovery" &&
            (await workerIdFromPrompt(request.promptPath)) === "discovery-0001"
          ) {
            attempts.push(request.resumeThreadId);
            await request.onThreadStarted?.(
              request.resumeThreadId ?? "fixture-parse-thread",
            );
            throw classifyCodexWorkerError(failure);
          }
          return normalExecutor.run(request);
        },
      },
      { retryDelaysMs: [1, 3, 9], log: (event) => events.push(event) },
    );

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
    assert.equal(store.failureMessages.length, 0);
  }
}

async function testPolicyRefusedReducerPreservesInputsAndCommittedAggregate() {
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    stopAfterNoNew: 10,
    stopAfterConsecutiveErrors: 2,
    maxDiscoveryRuns: 4,
  });
  const nextDiscovery = Promise.withResolvers<void>();
  const siblingDiscovery = Promise.withResolvers<void>();
  const normalExecutor = new FakeExecutor({
    discoveryCandidateId: "candidate-1",
    canonicalCandidateId: "candidate-1",
    discoveryGates: {
      "discovery-0003": nextDiscovery.promise,
      "discovery-0004": siblingDiscovery.promise,
    },
  });
  let committedResultPath!: string;
  let committedContent!: Buffer;
  const failedAttempts: (string | undefined)[] = [];
  const coordinator = createCoordinator(
    fixture,
    store,
    {
      async run(request) {
        if (request.kind === "dedup") {
          const label = (await promptContext(request.promptPath)).reducerLabel;
          if (label === "dedup-0002") {
            failedAttempts.push(request.resumeThreadId);
            await request.onThreadStarted?.("fixture-retired-reducer");
            throw classifyCodexWorkerError(
              new Error("Request blocked by cyberPolicy."),
            );
          }
          if (label === "dedup-0003") {
            assert.equal(request.resumeThreadId, undefined);
            assert.equal(
              request.artifactContext!.deepReducer!.previousReducerResultPath,
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
    { retryDelaysMs: [1, 3, 9] },
  );
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
  const manifest = await readJson(terminal.manifestPath);
  assert.deepEqual(
    manifest.findings.map(
      (finding: { provenance: { candidateId: string } }) =>
        finding.provenance.candidateId,
    ),
    ["candidate-1"],
  );
  assert.equal(store.failureMessages.length, 0);
}

async function testNonRetryableReducerAbortsScanWithoutRetry(
  failureMessage = "fixture fatal reducer failure",
) {
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    stopAfterNoNew: 10,
    stopAfterConsecutiveErrors: 2,
    maxDiscoveryRuns: 4,
  });
  const normalExecutor = new FakeExecutor({ blockDiscoveryAfterCalls: 2 });
  const attempts: (string | undefined)[] = [];
  const sleeps: number[] = [];
  const terminal = await runCoordinator(
    fixture,
    store,
    {
      async run(request) {
        if (request.kind === "dedup") {
          attempts.push(request.resumeThreadId);
          throw new DeepScanNonRetryableError(failureMessage);
        }
        return normalExecutor.run(request);
      },
    },
    {
      clock: recordingClock(sleeps),
    },
  );

  assert.equal(terminal?.status, "failed");
  assert.equal(terminal?.error, failureMessage);
  assert.deepEqual(attempts, [undefined]);
  assert.deepEqual(sleeps, []);
  assert.equal(normalExecutor.runningDiscovery, 0);
  assert.equal(store.failureMessages.length, 1);
  assert.equal(store.dedupCommits.length, 0);
}

try {
  await testDeepScanLifecycle({
    fixtureRun,
    FakeStore,
    FakeExecutor,
    createCoordinator,
    DeepScanCoordinatorRegistry,
    immediateClock,
  });
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
  await testSaturationOmitsWorkerAcceptedDuringCancellation();
  await testSuccessfulDeepCoverageIgnoresWorkerAndReducerReviewStatus();
  await testSaturationIgnoresDiscoveryCancellationWriteFailure();
  await testPublicationUsesAcceptedReducerSnapshot();
  await testDirectReducerCannotDropAcceptedFinding();
  await testSaturationDrainsBufferedAndCancelsInflight();
  await testDiscoveryDeadlineDrainsActiveReducerAndPreservesFindings();
  await testDiscoveryDeadlineReducesSingleBufferedFinding();
  await testDiscoveryAcceptedAtDeadlineIsReduced();
  await testDiscoveryDeadlineWithoutAcceptedWorkersReturnsPartialEvidence();
  await testDiscoveryDeadlineBeforeWorkerDispatchReturnsPartialEvidence();
  await testSaturationIgnoresWorkerFailureSettledAfterStop();
  await testSettledReducerIsNotStarvedByDiscoveryBacklog();
  await testSingletonHardCapReduction();
  await testExhaustedRetryFailsScan();
  await testProviderCybersecurityRiskMessagesReplaceRefusedDiscoveryImmediately();
  await testTransientDiscoveryErrorsRetainRecovery();
  await testConsecutiveCybersecurityRefusalsFailAtConfiguredThreshold();
  await testRecoverableWorkerErrorsCannotFailScan();
  await testSuccessfulDiscoveryResetsConsecutiveFailureThreshold();
  await testExhaustedInvalidDiscoveryArtifactsAreReplaced();
  await testExhaustedMalformedDiscoveryDoesNotRemainPublishable();
  await testTransientExecutionFailureResumesWorkerThread();
  await testConfigurationFailureDoesNotRetry();
  await testConfigurationFailureDoesNotRetry("Request blocked by cyberPolicy.");
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
  await testMissingReducerResultResumesExistingThread(
    "code-mode delegate response exceeds the IPC frame limit: code-mode IPC frame length 76008279 exceeds 67108864 bytes",
  );
  await testMissingReducerResultRetainsSizeDiagnosticAfterOtherFailures();
  await testExhaustedReducerIsReplacedAtDiscoveryLimit();
  await testPolicyRefusedReducerPreservesInputsAndCommittedAggregate();
  await testNonRetryableReducerAbortsScanWithoutRetry();
  await testNonRetryableReducerAbortsScanWithoutRetry(
    "Request blocked by cyberPolicy.",
  );
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
  await testResumeRequiresHistoricalWorkerPrompt("failed");
  await testResumeRequiresHistoricalWorkerPrompt("canceled");
  await testPausedDiscoverySurvivesCoordinatorRestart();
  await testResumedDiscoveryDeadlineUsesPersistedCreationTime();
  await testResumedDiscoveryDeadlineUsesPersistedCreationTime(true);
  await testResumedDiscoveryDeadlineUsesPersistedCreationTime(false, 2.5);
  await testResumedDiscoveryDeadlineUsesPersistedCreationTime(true, 96);
  await testResumedManifestPreservesCompletedReducer();
  await testResumedManifestPreservesCompletedReducer(true);
  await testResumeUsesHistoricalCandidateSnapshotForEachReducer();
  await testPersistedErrorLimitStopsBeforeRescheduling();
  await testPersistedReducerErrorLimitStopsBeforeRescheduling();
} finally {
  await temporaryDirectories.cleanup();
}
