import { testSharedReceiptSurvivesWorkerRetry } from "./deep_scan_receipt_cases.ts";
import { readJson, writeJson } from "./support/json.ts";
import {
  assertNoArtifactUsage,
  assertWorkerRetryReceipts,
  assertCanceledWorkerReceipts,
  testWorkerUsageWithoutHostDirectory,
  withCumulativeUsage,
  workerUsage,
} from "./deep_scan_worker_usage_assertions.ts";
import type { CoordinatorOptions } from "../src/deep-scan/coordinator.js";
import type { ScanDraftInput } from "../src/artifact-scan-draft.js";
import type { JsonObject } from "../src/types.js";
import type {
  DeepScanConfig,
  DeepScanRunState,
  CodexWorkerDiagnostic,
  PersistedDeepScanWorker,
  DeepScanLogEvent,
  CodexWorkerRequest,
  CodexWorkerResult,
} from "../src/deep-scan/types.js";
import { after, mock, test, type TestContext } from "node:test";
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
import {
  testDeepScanLifecycle,
  testSuccessfulDeepCoverageRetainsIndependentWorkerReviewStatus,
} from "./deep_scan_lifecycle_cases.ts";
import {
  DeepScanCoordinatorRegistry,
  WorkbenchDeepScanStore,
  DeepScanRemoteCoordinator,
  AsyncLock,
  classifyCodexWorkerError,
  codexWorkerTurnError,
  startOrJoinDeepScanCoordinator,
  iterationInputs,
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
  recordCodexSecurityWorkerScanDraft,
  type TestWorker,
  type StoreInput,
} from "./deep_scan_coordinator_fixture.ts";

function twoRunConfig(config: Partial<DeepScanConfig> = {}) {
  return { ...config, stopAfterNoNew: 2, maxDiscoveryRuns: 2 };
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

async function testDiscoveryAllocatesUniqueLabelsAfterRecovery() {
  const { fixture, store } = await coordinatorFixture({
    maxDiscoveryRuns: 12,
    stopAfterNoNew: 1,
  });
  const root = path.join(
    fixture.run.scanDir,
    "artifacts",
    "deep_discovery",
    "workers",
  );
  Object.assign(store.run, {
    dispatchedCount: 1,
    persistedWorkers: [
      {
        id: randomUUID(),
        kind: "discovery",
        status: "canceled",
        attempt: 1,
        mergeState: "none",
        artifactDir: path.join(root, "discovery-0010", "output"),
        promptPath: path.join(root, "discovery-0010", "prompt.md"),
      },
    ],
  });
  // A stale coordinator writes its final prompt after the new coordinator's listing.
  const occupied = path.join(root, "discovery-0011", "prompt.md");
  const updateProgress = store.updateProgress.bind(store);
  store.updateProgress = async (input) => {
    await mkdir(path.dirname(occupied), { recursive: true });
    await writeFile(occupied, "old coordinator");
    await updateProgress(input);
  };
  const executor = new FakeExecutor();
  const terminal = await runCoordinator(fixture, store, executor, {
    run: store.run,
  });
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.deepEqual([...executor.discoveryAttempts.keys()], ["discovery-0012"]);
  assert.equal(await readFile(occupied, "utf8"), "old coordinator");
}

async function testConcurrentCheckpointKeepsExistingIteration() {
  const { fixture, store } = await coordinatorFixture({ maxDiscoveryRuns: 1 });
  const gate = Promise.withResolvers<void>();
  const executor = new FakeExecutor({
    discoveryGates: { "discovery-0001": gate.promise },
  });
  const coordinator = createCoordinator(fixture, store, executor);
  coordinator.start();
  await executor.discoveryStarted.promise;
  const root = path.join(
    fixture.run.scanDir,
    "artifacts",
    "deep_discovery",
    "dedup",
  );
  const existing = path.join(root, "dedup-0001", "output", "result.json");
  try {
    // Another coordinator commits its checkpoint while this one is scanning.
    await mkdir(path.dirname(existing), { recursive: true });
    await writeFile(existing, "checkpoint owned by another coordinator");
  } finally {
    gate.resolve();
  }
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(
    await readFile(existing, "utf8"),
    "checkpoint owned by another coordinator",
  );
  assert.equal(
    store.iterations[0].resultPath,
    path.join(root, "dedup-0002", "output", "result.json"),
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

  assert.equal(terminal?.status, "succeeded", terminal?.error);
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
  });
  const terminal = await runCoordinator(fixture, store, executor);
  assert.equal(terminal?.terminalReason, "capped");
  const manifest = await readJson(terminal.manifestPath);
  const expectedWorkerIds = [...store.workers.values()]
    .filter(
      (worker) => worker.kind === "discovery" && worker.status === "succeeded",
    )
    .sort((left, right) => left.promptPath.localeCompare(right.promptPath))
    .map((worker) => worker.id);
  assert.deepEqual(
    manifest.findings.map(
      (finding: Record<string, unknown>) =>
        (finding.provenance as { candidateId: string }).candidateId,
    ),
    ["candidate-1"],
  );
  assert.deepEqual(store.iterations[0].workerIds, expectedWorkerIds);
  const reducer = [...store.workers.values()].find(
    (worker) => worker.kind === "dedup",
  );
  const reducerResult = await readJson(reducer!.resultManifestPath!);
  assert.equal(reducerResult.scanId, fixture.run.scanId);
  assert.deepEqual(reducerResult.findings, manifest.findings);
  assert.equal(
    executor.discoveryCalls,
    expectedWorkerIds.length,
    "only Standard scans invoke the model",
  );
}

async function testRetryKeepsLogicalWorker() {
  const { fixture, store } = await coordinatorFixture(
    twoRunConfig({ workers: 2, subagents: 1 }),
  );
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
    store.iterations.map((claim) => claim.workerIds.length),
    [1],
  );
  const manifest = await readJson(terminal.manifestPath);
  assert.equal(manifest.scan.scanId, fixture.run.scanId);
  assert.equal(store.iterations.length, 1);
}

async function testExhaustedRetryFailsScan() {
  const { fixture, store } = await coordinatorFixture(
    twoRunConfig({ workers: 2, subagents: 1 }),
  );
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

async function testTransientDiscoveryErrorsRetainRecovery() {
  // Unclassified executor failures are distinct from a native turn.failed event.
  for (const message of [
    "Request blocked by cyberPolicy.",
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

async function testConsecutiveTransientErrorsFailAtConfiguredThreshold() {
  const { fixture, store } = await coordinatorFixture({
    stopAfterNoNew: 6,
    stopAfterConsecutiveErrors: 2,
    maxDiscoveryRuns: 10,
  });
  const executor = new FakeExecutor({
    discoveryFailureMessages: {
      "discovery-0001": "transient worker failure",
      "discovery-0002": "transient worker failure",
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
  assert.match(terminal?.error ?? "", /transient_error/);
  assert.equal(executor.discoveryAttempts.size, 2);
  assert.equal(executor.discoveryCalls, 8);
  assert.equal(store.run.consecutiveErrors, 2);
  assert.equal(store.finishCalls.length, 0);
  assert.equal(terminal.manifestPath, undefined);
  assert.deepEqual(
    [...store.workers.values()].map((worker) => worker.replaceableFailureKind),
    ["transient_error", "transient_error"],
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
      "discovery-0001": "transient worker failure",
      "discovery-0003": "transient worker failure",
    },
    discoveryCandidateId: "candidate-1",
  });
  const terminal = await runCoordinator(fixture, store, executor, {
    retryDelaysMs: [1, 3, 9],
  });

  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(executor.discoveryAttempts.size, 5);
  assert.equal(store.run.consecutiveErrors, 0);
  assert.equal(
    [...store.workers.values()].filter(
      (worker) => worker.replaceableFailureKind === "transient_error",
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

  assert.equal(terminal?.status, "succeeded", terminal?.error);
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

  assert.equal(terminal?.status, "succeeded", terminal?.error);
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
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.deepEqual(executor.discoveryResumeThreadIds, [
    undefined,
    executor.discoveryThreadIds[0],
  ]);
  assert.equal(new Set(executor.discoveryThreadIds).size, 1);
  assert.match(
    executor.discoveryContinuationPrompts[1] ?? "",
    /execution failure/,
  );
  assert.match(
    executor.discoveryContinuationPrompts[1] ?? "",
    /Standard security scan/,
  );
  assert.match(
    executor.discoveryContinuationPrompts[1] ?? "",
    /record_codex_security_scan_draft/,
  );
  assert.match(
    executor.discoveryContinuationPrompts[1] ?? "",
    /complete:false/,
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

async function testLongWorkerErrorIsPreservedAtPersistenceBoundary() {
  const { fixture, store } = await coordinatorFixture();
  const fullError = `fixture long validator error: ${"x".repeat(5_000)}`;
  const terminal = await runCoordinator(
    fixture,
    store,
    new FakeExecutor({ discoveryFailureMessage: fullError }),
    { retryDelaysMs: [1, 3, 9], random: () => 0 },
  );
  assert.equal(terminal?.status, "failed");
  assert.ok(store.failureMessages[0].includes(fullError));
  assert.equal(terminal.error, store.failureMessages[0]);
  assert.equal(terminal.manifestPath, undefined);
  const [worker] = [...store.workers.values()];
  assert.equal(worker.status, "canceled");
  assert.equal(worker.attempt, 4);
  assert.equal(worker.error, `transient_error: ${fullError}`);
}

async function testDiscoveryPhasePersistenceFailureStopsDispatch() {
  const { fixture, store } = await coordinatorFixture(
    twoRunConfig({ workers: 2, subagents: 1 }),
  );
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
  const sleepStarted = Promise.withResolvers<DeepScanLogEvent>();
  const coordinator = createCoordinator(fixture, store, executor, {
    clock: undefined,
    log: (event) => {
      if (event.event === "worker_retry_scheduled") sleepStarted.resolve(event);
    },
  });
  coordinator.start();
  assert.equal((await sleepStarted.promise).reason, "transient worker failure");
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

async function testGenericDiagnosticsPreserveMissingResultRetries() {
  for (const code of [
    undefined,
    "file_change_failed",
    "artifact_tool_failed",
  ] as const) {
    for (const genericFirst of [false, true]) {
      const diagnostics: CodexWorkerDiagnostic[] = [
        {
          code: "worker_error",
          message: "Synthetic stream reconnect notification.",
        },
      ];
      if (code)
        diagnostics.push({
          code,
          message: "Synthetic recognized worker failure.",
        });
      if (!genericFirst) diagnostics.reverse();
      const { fixture, store } = await coordinatorFixture();
      const executor = new FakeExecutor({
        invalidDiscoveryAttempts: 1,
        discoveryDiagnostics: diagnostics,
      });
      const terminal = await runCoordinator(fixture, store, executor, {
        retryDelaysMs: [1],
      });
      assert.equal(terminal?.status, "succeeded", terminal?.error);
      assert.deepEqual(executor.discoveryResumeThreadIds, [
        undefined,
        code === "file_change_failed"
          ? undefined
          : executor.discoveryThreadIds[0],
      ]);
      for (const diagnostic of diagnostics) {
        assert.ok(
          store.workerUpdates.some((update) =>
            update.error?.includes(diagnostic.message),
          ),
        );
      }
    }
  }
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
                "--provider-error EACCES: permission denied, open /synthetic/result.json\nArtifact transport closed.",
            },
          ],
        }
      : {}),
  });
  withCumulativeUsage(executor, fixture.run.workerUsageDirectory);
  const events: DeepScanLogEvent[] = [];
  const sleeps: number[] = [];
  const terminal = await runCoordinator(fixture, store, executor, {
    random: () => 0,
    retryDelaysMs: [1, 3, 9],
    clock: recordingClock(sleeps),
    log: (event) => {
      events.push(event);
      if (withToolFailure) throw new Error("Synthetic log sink failure");
    },
  });

  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.deepEqual(sleeps, [1]);
  assert.deepEqual(executor.discoveryResumeThreadIds, [
    undefined,
    executor.discoveryThreadIds[0],
  ]);
  assert.equal(new Set(executor.discoveryThreadIds).size, 1);
  await assertWorkerRetryReceipts(fixture.run.workerUsageDirectory!, events);
  await assertNoArtifactUsage(fixture.run.scanDir);
  if (withToolFailure) {
    const message = executor.options.discoveryDiagnostics![0].message;
    assert.ok(
      store.workerUpdates.some((update) => update.error?.includes(message)),
    );
  }
  const continuation = executor.discoveryContinuationPrompts[1] ?? "";
  assert.match(continuation, /completed source analysis/);
  assert.match(
    continuation,
    /record_codex_security_scan_draft\(\{ scanId, complete, scope\?, threatModel\?, findings, reviewState \}\)/,
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
  const { fixture, store } = await coordinatorFixture(
    twoRunConfig({ workers: 2, subagents: 1 }),
  );
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
  assert.match(retryInstructions, /ended without a valid completed result/);
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

  await store.iterationCommitted.promise;
  coordinator.cancel("user canceled after a valid committed aggregate");
  nextDiscovery.resolve();

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "canceled");
  assert.equal(store.finishCalls.length, 0);
  assert.equal(completedDrafts.length, 0);
  assert.equal(store.iterations.length, 1);
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

async function testCancellationDropsUnvalidatedDiscoveryResult(
  usageReported = false,
) {
  const { fixture, store } = await coordinatorFixture();
  const executor = new FakeExecutor({ blockDiscoveryAfterWrite: true });
  let reportUsage: CodexWorkerRequest["onUsage"];
  const originalRun = executor.run.bind(executor);
  executor.run = (request) => {
    reportUsage = request.onUsage;
    return originalRun(request);
  };
  const events: DeepScanLogEvent[] = [];
  const coordinator = createCoordinator(fixture, store, executor, {
    threadId: "checkpoint-owner",
    log: (event) => events.push(event),
  });
  coordinator.start();
  await executor.discoveryArtifactsWritten.promise;
  if (usageReported) await reportUsage?.(workerUsage(1), "synthetic-turn");
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
  await assertCanceledWorkerReceipts(
    fixture.run.workerUsageDirectory!,
    events,
    usageReported,
  );
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

async function testDiscoveryAcceptanceFailureFinishesWorkerAsFailed() {
  const { fixture, store } = await coordinatorFixture();
  const updateWorker = store.updateWorker.bind(store);
  store.updateWorker = async (update) => {
    if (update.kind === "discovery" && update.status === "succeeded") {
      throw new Error("Synthetic acceptance write failed");
    }
    return updateWorker(update);
  };
  const events: DeepScanLogEvent[] = [];
  const terminal = await runCoordinator(fixture, store, new FakeExecutor(), {
    log: (event) => events.push(event),
  });
  assert.equal(terminal?.status, "failed");
  const finished = events.filter((event) => event.event === "worker_finished");
  assert.equal(finished.length, 1);
  assert.equal(finished[0].outcome, "failed");
  const directory = fixture.run.workerUsageDirectory!;
  const names = await readdir(directory);
  assert.equal(names.length, 1);
  assert.equal((await readJson(directory, names[0])).outcome, "failed");
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
  await store.discoveryUpdate.entered;

  // The real cancel command persists this state before signaling the coordinator.
  store.run.status = "canceled";
  for (const worker of store.workers.values()) worker.status = "canceled";
  coordinator.cancel("fixture persisted cancellation");
  store.discoveryUpdate.release();

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
    events.some(
      (event) =>
        event.event === "discovery_accepted" ||
        event.event === "worker_succeeded",
    ),
    false,
  );
  await assertCanceledWorkerReceipts(
    fixture.run.workerUsageDirectory!,
    events,
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
  assert.ok(terminal?.error?.includes("y".repeat(2_350)));
  assert.ok(terminal?.error?.includes("x".repeat(2_350)));
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

async function testStoppedPublicationFailurePreservesPrefixedDiagnostic() {
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
  assert.equal(
    terminal?.error,
    `Saved result publication failed: fixture publication failure ${"z".repeat(2_400)}`,
  );
  assert.deepEqual(store.publicationFailureMessages, [terminal.error]);
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
  const fixture = await fixtureRun(twoRunConfig());
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
  const fixture = await fixtureRun(twoRunConfig());
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
  const fixture = await fixtureRun(twoRunConfig());
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

  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(terminal?.coordinatorGeneration, 3);
  assert.equal(
    store.failureMessages.length,
    0,
    "a fenced mutation must observe rather than fail the replacement",
  );
}

async function testStoreConfirmedReplacementSurvivesReadFailure() {
  for (const confirmation of ["mutation", "failure-write"])
    for (const replaced of [false, true]) {
      const fixture = await fixtureRun();
      const run = { ...fixture.run, coordinatorGeneration: 2 };
      let current: DeepScanRunState = run;
      const stale =
        "Deep Scan coordinator lease belongs to a newer generation.";
      const diagnostic = replaced
        ? stale
        : `Permission denied: /fixture/${stale}/lock`;
      let reads = 0;
      const failures: string[][] = [];
      const store = new WorkbenchDeepScanStore(async (args: string[]) => {
        switch (args[0]) {
          case "claim-deep-scan-coordinator":
            return { deepScan: current, coordinatorDisposition: "claimed" };
          case "update-progress":
            if (replaced) current = { ...current, coordinatorGeneration: 3 };
            throw new Error(diagnostic);
          case "get-deep-scan": {
            reads += 1;
            if (
              reads === 2 ||
              (reads === 1 && (!replaced || confirmation === "failure-write"))
            )
              throw new Error("sqlite3.OperationalError: database is locked");
            const snapshot = current;
            if (replaced)
              current = {
                ...current,
                status: "succeeded",
                terminalReason: "capped",
              };
            return { deepScan: snapshot };
          }
          case "fail-deep-scan":
            failures.push(args);
            if (replaced)
              throw new Error(
                args.includes("--coordinator-generation")
                  ? stale
                  : "Deep Scan mutation requires the current coordinator lease.",
              );
            current = {
              ...current,
              status: "failed",
              error: args
                .find((arg) => arg.startsWith("--message="))!
                .slice("--message=".length),
            };
            return { deepScan: current };
          default:
            throw new Error(`Unexpected fixture operation: ${args[0]}`);
        }
      });
      await store.claimCoordinator({
        scanId: run.scanId,
        threadId: "fixture-thread",
      });
      const coordinator = new DeepScanCoordinatorRegistry().start({
        run,
        store,
        executor: new FakeExecutor(),
        pluginRoot: fixture.pluginRoot,
        clock: immediateClock,
        threadId: "fixture-thread",
        heartbeatIntervalMs: 60_000,
      });
      const terminal = await coordinator.wait(undefined, 2_500);
      assert.equal(
        terminal?.status,
        replaced ? "succeeded" : "failed",
        confirmation,
      );
      assert.equal(terminal?.coordinatorGeneration, replaced ? 3 : 2);
      assert.equal(current.status, terminal?.status);
      assert.equal(
        failures.length,
        replaced && confirmation === "mutation" ? 0 : 1,
      );
      if (replaced) {
        assert.equal(reads, confirmation === "mutation" ? 3 : 4);
        assert.equal(store.coordinatorGeneration(run.scanId), undefined);
      } else {
        assert.equal(
          reads,
          2,
          "unconfirmed diagnostics must not add ownership reads",
        );
        assert.equal(terminal?.error, diagnostic);
        const generationFlag = failures[0].indexOf("--coordinator-generation");
        assert.equal(failures[0][generationFlag + 1], "2");
      }
    }
}

async function testStoreConfirmationSurvivesReplayAndThreadMetadata() {
  for (const operation of [
    "finish",
    "worker-acceptance",
    "thread-started",
  ] as const)
    for (const replaced of [false, true]) {
      const fixture = await fixtureRun();
      const run = { ...fixture.run, coordinatorGeneration: 2 };
      let current: DeepScanRunState = run;
      const store = new FakeStore(run);
      const stale =
        "Deep Scan coordinator lease belongs to a newer generation.";
      const diagnostic = replaced
        ? stale
        : `Permission denied: /fixture/${stale}/lock`;
      let mutations = 0;
      let reads = 0;
      let failures = 0;
      const persisted = new WorkbenchDeepScanStore(async (args: string[]) => {
        switch (args[0]) {
          case "claim-deep-scan-coordinator":
            return { deepScan: current, coordinatorDisposition: "claimed" };
          case "finish-deep-scan":
          case "upsert-deep-scan-worker":
            mutations += 1;
            if (operation !== "thread-started" && mutations === 1)
              throw new Error("sqlite3.OperationalError: database is locked");
            if (replaced) current = { ...current, coordinatorGeneration: 3 };
            throw new Error(diagnostic);
          case "get-deep-scan": {
            reads += 1;
            if (reads === 2)
              throw new Error("sqlite3.OperationalError: database is locked");
            const snapshot = current;
            if (replaced)
              current = {
                ...current,
                status: "succeeded",
                terminalReason: "capped",
              };
            return { deepScan: snapshot };
          }
          case "fail-deep-scan":
            failures += 1;
            if (replaced)
              throw new Error(
                "Deep Scan mutation requires the current coordinator lease.",
              );
            current = {
              ...current,
              status: "failed",
              error: args
                .find((arg) => arg.startsWith("--message="))!
                .slice("--message=".length),
            };
            return { deepScan: current };
          default:
            throw new Error(`Unexpected fixture operation: ${args[0]}`);
        }
      });
      await persisted.claimCoordinator({
        scanId: run.scanId,
        threadId: "fixture-thread",
      });
      store.get = persisted.get.bind(persisted);
      store.fail = persisted.fail.bind(persisted);
      if (operation === "finish")
        store.finish = persisted.finish.bind(persisted);
      else {
        const updateWorker = store.updateWorker.bind(store);
        store.updateWorker = async (update) =>
          (operation === "worker-acceptance" &&
            update.status === "succeeded") ||
          (operation === "thread-started" && update.threadId !== undefined)
            ? persisted.updateWorker(update)
            : updateWorker(update);
      }
      const coordinator = new DeepScanCoordinatorRegistry().start({
        run,
        store,
        executor: new FakeExecutor(),
        pluginRoot: fixture.pluginRoot,
        clock: immediateClock,
        threadId: "fixture-thread",
        heartbeatIntervalMs: 60_000,
        retryDelaysMs: [],
      });
      const terminal = await coordinator.wait(undefined, 2_500);
      assert.equal(
        terminal?.status,
        replaced ? "succeeded" : "failed",
        operation,
      );
      assert.equal(terminal?.coordinatorGeneration, replaced ? 3 : 2);
      assert.equal(current.status, terminal?.status);
      assert.equal(failures, replaced ? 0 : 1);
      if (replaced) {
        assert.equal(mutations, operation === "thread-started" ? 1 : 2);
        assert.equal(reads, 3);
      } else {
        assert.ok(terminal?.error?.includes(diagnostic));
      }
    }
}

async function testJoinAndOrphanRules() {
  const fixture = await fixtureRun(twoRunConfig({ workers: 2, subagents: 1 }));
  const existingCoordinator = {
    marker: "existing",
    snapshot: () => fixture.run,
  };
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
  let liveCoordinator:
    { marker: string; snapshot: () => DeepScanRunState } | undefined;
  starts.mock.resetCalls();
  const registry = {
    get: () => liveCoordinator,
    start: () => {
      starts();
      liveCoordinator = { marker: "concurrent", snapshot: () => fixture.run };
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

async function testPausedDiscoverySurvivesCoordinatorRestart(
  removeHistoricalPrompts = true,
) {
  const fixture = await fixtureRun(twoRunConfig());
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
  const acceptedWorkerId = await workerIdFromPrompt(accepted.promptPath);
  if (removeHistoricalPrompts)
    await Promise.all(
      persistedWorkers
        .filter((worker) => worker.kind === "discovery")
        .map((worker) => rm(worker.promptPath, { force: true })),
    );
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
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(store.failureMessages.length, 0);
  assert.equal(replacementExecutor.discoveryAttempts.size, 1);
  assert.equal(
    replacementExecutor.discoveryAttempts.has(acceptedWorkerId),
    false,
  );
  assert.deepEqual(
    store.iterations.map((claim) => claim.workerIds.length),
    [1, 1],
  );
  assert.deepEqual(store.iterations[0].workerIds, [accepted.id]);
  const manifest = await readJson(terminal.manifestPath);
  assert.equal(manifest.scan.scanId, fixture.run.scanId);
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

  await Promise.all(
    store.run
      .persistedWorkers!.filter((worker) => worker.kind === "discovery")
      .map((worker) => rm(worker.promptPath, { force: true })),
  );
  const resumedExecutor = new FakeExecutor({
    blockDiscoveryAfterCalls: 0,

    discoveryCandidateId: "candidate-1",
  });
  const resumed = createCoordinator(fixture, store, resumedExecutor, {
    run: store.run,
    clock,
  });
  resumed.start();
  if (!alreadyExpired) await resumedExecutor.discoveryStarted.promise;

  const terminal = await resumed.wait(undefined, 5_000);
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(terminal?.terminalReason, "capped");
  assert.equal(store.failureMessages.length, 0);
  assert.equal(resumedExecutor.discoveryCalls, alreadyExpired ? 0 : 1);
  assert.equal(resumedExecutor.runningDiscovery, 0);

  const manifest = await readJson(terminal.manifestPath);
  assert.equal(store.run.config.maxTimeHours, maxTimeHours);
  assert.equal(store.iterations[0].workerIds.length, 1);
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
  removeHistoricalPrompts = true,
  includePaths?: string[],
) {
  const fixture = await fixtureRun({
    workers: 2,
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 2,
  });
  fixture.run.includePaths = includePaths;
  const store = new FakeStore(fixture.run);
  store.iterationResponseGate = Promise.withResolvers<void>();
  const original = createCoordinator(
    fixture,
    store,
    new FakeExecutor({
      blockDiscoveryAfterCalls: 2,
      discoveryCandidateId: includePaths ? "scope-candidate" : undefined,
    }),
    { run: store.run },
  );
  original.start();
  await store.iterationCommitted.promise;
  original.cancel("mcp server process restarted");
  store.iterationResponseGate.resolve();
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
    persistedDedupInputs: store.iterations.flatMap(iterationInputs),
  };
  const acceptedWorkers = store.run.persistedWorkers!.filter(
    (worker) => worker.status === "succeeded",
  );
  const acceptedResults = await Promise.all(
    acceptedWorkers.map((worker) =>
      readFile(worker.resultManifestPath!, "utf8"),
    ),
  );
  const persistedInputs = structuredClone(store.run.persistedDedupInputs);
  const persistedWorkers = structuredClone(store.run.persistedWorkers);
  const committedReducer = store.workers.get(store.iterations[0].id)!;
  const committedResult = await readJson(committedReducer.resultManifestPath!);
  if (includePaths) assert.ok(committedResult.findings.length > 0);
  if (removeHistoricalPrompts) {
    for (const worker of acceptedWorkers.filter(
      (worker) => worker.kind === "discovery",
    ))
      await rm(worker.promptPath);
  }
  const replacementExecutor = new FakeExecutor();
  const published: ScanDraftInput[] = [];
  const terminal = await runCoordinator(fixture, store, replacementExecutor, {
    run: store.run,
    onComplete: async (draft) => void published.push(structuredClone(draft)),
  });
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  const manifest = await readJson(terminal.manifestPath);
  assert.equal(manifest.scan.scanId, fixture.run.scanId);
  assert.equal(store.iterations.length, 1);
  assert.equal(
    replacementExecutor.discoveryCalls,
    0,
    "accepted work needs no new worker launch",
  );
  assert.deepEqual(manifest.findings, committedResult.findings);
  assert.equal(published.length, 1);
  assert.deepEqual(
    published[0].findings,
    includePaths ? [] : committedResult.findings,
  );
  assert.deepEqual(store.run.persistedDedupInputs, persistedInputs);
  assert.deepEqual(store.run.persistedWorkers, persistedWorkers);
  assert.deepEqual(
    await Promise.all(
      acceptedWorkers.map((worker) =>
        readFile(worker.resultManifestPath!, "utf8"),
      ),
    ),
    acceptedResults,
  );
  assert.equal(
    store.run.persistedWorkers!.some(
      (worker) => worker.id === unstartedReducer?.id,
    ),
    includeUnstartedReducer,
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
      /2 consecutive unsuccessful discovery workers/,
    );
    assert.match(terminal?.error ?? "", /persisted worker failure/);
    assert.equal(terminal.manifestPath, undefined);
    assert.equal(store.run.persistedWorkers![0].id, failedWorker.id);
  }
}

async function testRestartRestoresDispatchOrderAfterMixedResults(
  limit: number,
) {
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    maxDiscoveryRuns: 2,
    stopAfterConsecutiveErrors: limit,
  });
  const workers = path.join(
    fixture.run.scanDir,
    "artifacts",
    "deep_discovery",
    "workers",
  );
  const persisted: TestWorker[] = ["discovery-0001", "discovery-0002"].map(
    (label) => ({
      id: randomUUID(),
      kind: "discovery",
      status: "canceled",
      promptPath: path.join(workers, label, "prompt.md"),
      artifactDir: path.join(workers, label, "output"),
      attempt: 1,
      mergeState: "none",
    }),
  );
  const [first, second] = persisted;
  first.error = "transient_error: first scan finished last";
  second.status = "succeeded";
  second.mergeState = "buffered";
  second.completionSequence = 1;
  second.resultManifestPath = path.join(second.artifactDir, "result.json");
  await mkdir(second.artifactDir, { recursive: true });
  await writeJson(
    second.resultManifestPath,
    standardScanDraft(fixture.run.scanId, "issue", "discovery-0002"),
  );
  for (const worker of persisted) store.workers.set(worker.id, worker);
  Object.assign(store.run, {
    persistedWorkers: persisted,
    consecutiveErrors: 1,
    dispatchedCount: 2,
  });
  const executor = new FakeExecutor();
  const terminal = await runCoordinator(fixture, store, executor, {
    run: store.run,
  });
  assert.equal(
    terminal?.status,
    limit === 1 ? "failed" : "succeeded",
    terminal?.error,
  );
  assert.equal(store.iterations[0].consecutiveErrors, limit === 1 ? 1 : 0);
  assert.deepEqual(store.iterations[0].workerIds, [second.id]);
  assert.equal(executor.discoveryCalls, 0);
}

async function testComparisonStopCondition(mode: "quota" | "deadline") {
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    stopAfterNoNew: 3,
    maxDiscoveryRuns: 6,
  });
  const worker = new FakeExecutor({ discoveryCandidateId: "candidate-1" });
  const deadline = Promise.withResolvers<void>();
  let comparisons = 0;
  const terminal = await runCoordinator(
    fixture,
    store,
    {
      async run(request) {
        const result = await worker.run(request);
        const resultPath = path.join(
          request.artifactContext!.root,
          "result.json",
        );
        const draft = await readJson(resultPath);
        draft.findings[0].title = (
          await promptContext(request.promptPath)
        ).workerLabel;
        await writeJson(resultPath, draft);
        return result;
      },
      async compareFindings(_prompt, _cwd, signal) {
        comparisons++;
        if (mode === "quota")
          throw codexWorkerTurnError(
            "Quota exceeded. Check your plan and billing details.",
          );
        await deadline.promise;
        signal.throwIfAborted();
        return JSON.stringify({
          uncertain: [],
          defects: [
            {
              path: "fixture.py",
              operation: "query",
              failure: "check",
              reports: [0, 1].map((id) => ({ id, evidence: 0 })),
            },
          ],
        });
      },
    },
    {
      ...(mode === "deadline" && { discoveryTimeoutMs: 500 }),
      log: (event) => {
        if (event.event === "discovery_deadline_reached") deadline.resolve();
      },
    },
  );
  assert.equal(comparisons, 1);
  assert.equal(worker.discoveryCalls, 2);
  assert.equal(store.iterations.length, 1);
  assert.equal(store.iterations[0].workerIds.length, 2);
  assert.equal(
    terminal?.status,
    mode === "quota" ? "interrupted" : "succeeded",
    terminal?.error,
  );
  const checkpoint = await readJson(store.iterations[0].resultPath);
  assert.equal(checkpoint.findings.length, mode === "quota" ? 2 : 1);
  if (mode === "quota") {
    assert.match(terminal.error ?? "", /Quota exceeded/);
    assert.equal(store.finishCalls.length, 0);
    await assertNoPublishedCandidates(fixture.run.scanDir);
    const saved = await readFile(store.iterations[0].resultPath, "utf8");
    // The workbench reactivates the same run and fences the old coordinator.
    Object.assign(store.run, {
      status: "running",
      error: null,
      cancelRequested: false,
      coordinatorGeneration: 3,
      resumeAvailable: undefined,
    });
    const replacement = new FakeExecutor();
    const continued = await runCoordinator(fixture, store, replacement, {
      run: await store.get(),
    });
    assert.equal(continued?.status, "succeeded", continued?.error);
    assert.equal(continued.scanId, terminal.scanId);
    assert.ok(replacement.discoveryCalls > 0);
    assert.equal(replacement.discoveryAttempts.has("discovery-0001"), false);
    assert.equal(replacement.discoveryAttempts.has("discovery-0002"), false);
    assert.equal(await readFile(store.iterations[0].resultPath, "utf8"), saved);
    const manifest = await readJson(continued.manifestPath);
    assert.equal(manifest.findings.length, 2);
  }
}

async function testDiscoveryDeadlineReducesSingleBufferedFinding(
  t: TestContext,
) {
  const { fixture, store } = await coordinatorFixture({
    stopAfterNoNew: 99,
    maxDiscoveryRuns: 8,
  });
  const first = new FakeExecutor({ discoveryCandidateId: "candidate-1" });
  const blocked = new FakeExecutor({ blockDiscoveryAfterCalls: 0 });
  let dispatched = 0;
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const coordinator = createCoordinator(
    fixture,
    store,
    {
      run(request) {
        return (++dispatched === 1 ? first : blocked).run(request);
      },
    },
    { discoveryTimeoutMs: 500 },
  );
  t.after(() => coordinator.cancel("fixture cleanup"));
  coordinator.start();
  await blocked.discoveryStarted.promise;
  assert.equal(dispatched, 2);
  assert.equal(blocked.runningDiscovery, 1);
  assert.ok(
    [...store.workers.values()].some(
      (worker) => worker.kind === "discovery" && worker.status === "succeeded",
    ),
  );
  assert.equal(
    store.iterations.length,
    1,
    "the completed scan is checkpointed before the next scan starts",
  );

  t.mock.timers.tick(500);
  t.mock.timers.reset();
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(terminal?.terminalReason, "capped");
  assert.equal(terminal.dispatchedCount, 2);
  assert.equal(
    terminal.dispatchedCount < fixture.run.config.maxDiscoveryRuns,
    true,
  );
  assert.equal(store.failureMessages.length, 0);
  assert.equal(blocked.runningDiscovery, 0);

  const manifest = await readJson(terminal.manifestPath);
  assert.equal(store.iterations[0].workerIds.length, 1);
  assert.deepEqual(store.finishCalls[0].omittedWorkerIds, []);
  assert.equal(
    [...store.workers.values()].filter((worker) => worker.status === "canceled")
      .length,
    1,
  );
  assert.equal(store.iterations.length, 1);
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
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(terminal?.terminalReason, "capped");
  assert.equal(store.failureMessages.length, 0);
  assert.equal(executor.discoveryCalls, 1);

  const manifest = await readJson(terminal.manifestPath);
  assert.equal(store.iterations[0].workerIds.length, 1);
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
  let lateRefusal = false;
  const coordinator = createCoordinator(
    fixture,
    store,
    {
      run(request) {
        request.signal.addEventListener(
          "abort",
          () => {
            lateRefusal = true;
            request.onNonRetryableError?.(
              codexWorkerTurnError("Request blocked by cyberPolicy."),
            );
          },
          { once: true },
        );
        return executor.run(request);
      },
    },
    {
      discoveryTimeoutMs: 500,
      onComplete: async (draft) =>
        void completedDrafts.push(structuredClone(draft)),
    },
  );
  coordinator.start();
  await executor.discoveryStarted.promise;

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(terminal?.terminalReason, "capped");
  assert.equal(lateRefusal, true);
  assert.equal(
    store.workerUpdates.some((update) => update.terminalFailure),
    false,
  );
  assert.equal(store.failureMessages.length, 0);
  assert.equal(store.finishCalls.length, 1);
  assert.equal(executor.runningDiscovery, 0);

  const manifest = await readJson(terminal.manifestPath);
  assert.deepEqual(manifest.findings, []);

  assert.deepEqual(completedDrafts[0].reviewState.deferred, [
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
  assert.equal(store.iterations.length, 0);
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
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(terminal?.terminalReason, "capped");
  assert.equal(store.failureMessages.length, 0);
  assert.equal(store.finishCalls.length, 1);
  assert.equal(executor.discoveryCalls, 0);

  const manifest = await readJson(terminal.manifestPath);
  assert.deepEqual(manifest.findings, []);

  assert.deepEqual(store.finishCalls[0].omittedWorkerIds, []);
  assert.equal(store.workers.size, 0);
}

async function testResumeDoesNotRequireHistoricalWorkerPrompt(
  status: "failed" | "canceled",
) {
  const fixture = await fixtureRun(twoRunConfig());
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
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(store.failureMessages.length, 0);
  assert.equal(executor.discoveryCalls, 2);
  assert.equal(store.run.persistedWorkers?.[0].promptPath, promptPath);
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

async function testTerminalFailureStopsDispatchBeforeWorkerShutdown(
  resumed: boolean,
) {
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    stopAfterNoNew: 10,
    stopAfterConsecutiveErrors: 4,
    maxDiscoveryRuns: 10,
  });
  const normal = new FakeExecutor({
    blockDiscoveryAfterCalls: 2,
    discoveryCandidateId: "accepted-before-refusal",
  });
  const notified = Promise.withResolvers<void>();
  const shutdown = Promise.withResolvers<void>();
  const signals: AbortSignal[] = [];
  const sleeps: number[] = [];
  const message = resumed
    ? "Request blocked by cyberPolicy."
    : "Quota exceeded. Check your plan and billing details.";
  const attempts: (string | undefined)[] = [];
  let lateQuotaReported = false;
  const terminal = runCoordinator(
    fixture,
    store,
    {
      async run(request) {
        signals.push(request.signal);
        // The first batch commits results. In the second batch the sibling waits for abort.
        if (signals.length >= 4) {
          attempts.push(request.resumeThreadId);
          await request.onThreadStarted?.("fixture-terminal-thread");
          if (resumed && attempts.length === 1)
            throw new Error("transient worker failure");
          const error = codexWorkerTurnError(message);
          request.onNonRetryableError?.(error);
          notified.resolve();
          await shutdown.promise;
          throw new Error("later cleanup failure");
        }
        try {
          return await normal.run(request);
        } catch (error) {
          if (!resumed && request.signal.aborted) {
            // A late sibling quota signal must not replace the first cause.
            lateQuotaReported = true;
            request.onNonRetryableError?.(
              codexWorkerTurnError(
                "You’ve hit your usage limit. Try again later.",
              ),
            );
          }
          throw error;
        }
      },
    },
    { clock: recordingClock(sleeps), retryDelaysMs: [1], random: () => 0 },
  );
  try {
    await Promise.race([
      notified.promise,
      terminal.then(() => assert.fail("terminal failure was not reported")),
    ]);
    assert.ok(signals.slice(2).every((signal) => signal.aborted));
    const callsAtFailure = signals.length;
    assert.equal(store.iterations.length, 1);
    const checkpoint = store.iterations[0].resultPath;
    const committed = await readFile(checkpoint, "utf8");
    assert.match(committed, /accepted-before-refusal/);
    const [source] = store.workerUpdates.filter(
      (update) => update.terminalFailure,
    );
    assert.equal(source?.error, message);
    assert.equal(source.threadId, "fixture-terminal-thread");
    assert.equal(source.attempt, resumed ? 2 : 1);
    assert.deepEqual(
      attempts,
      resumed ? [undefined, "fixture-terminal-thread"] : [undefined],
    );

    if (resumed) {
      const snapshot = await store.get();
      assert.equal(snapshot.error, message);
      const replacement = new FakeExecutor();
      const adopted = await runCoordinator(fixture, store, replacement, {
        run: snapshot,
      });
      assert.equal(adopted?.status, "failed");
      assert.equal(adopted.error, message);
      assert.equal(replacement.discoveryCalls, 0);
    }
    shutdown.resolve();
    const result = await terminal;
    assert.equal(result?.status, resumed ? "failed" : "interrupted");
    assert.equal(result?.error, message);
    assert.equal(signals.length, callsAtFailure);
    assert.equal(
      store.workers.get(source.id)?.status,
      resumed ? "failed" : "canceled",
    );
    assert.deepEqual(
      store.workerUpdates.filter((update) => update.terminalFailure),
      [source],
    );
    assert.ok(
      [...store.workers.values()].some(
        (worker) => worker.status === "canceled",
      ),
    );
    assert.equal(store.finishCalls.length, 0);
    assert.equal(await readFile(checkpoint, "utf8"), committed);
    assert.deepEqual(sleeps, resumed ? [1] : []);
    assert.equal(lateQuotaReported, !resumed);
  } finally {
    shutdown.resolve();
    await terminal;
  }
}

async function testPersistedQuotaInterruptsBeforeDispatch() {
  const { fixture, store } = await coordinatorFixture(twoRunConfig());
  const message = "You’ve hit your usage limit. Try again later.";
  store.run.error = message;
  const executor = new FakeExecutor();
  let publications = 0;
  const terminal = await runCoordinator(fixture, store, executor, {
    run: await store.get(),
    onStopped: async () => {
      publications++;
    },
  });
  assert.equal(terminal?.status, "interrupted");
  assert.equal(terminal.error, message);
  assert.equal(executor.discoveryCalls, 0);
  assert.equal(publications, 0);
  assert.equal(store.finishCalls.length, 0);
  await assertNoPublishedCandidates(fixture.run.scanDir);
}

function registerCases<T extends unknown[]>(
  check: (...args: T) => Promise<void>,
  cases: T[],
) {
  for (const args of cases)
    test(`${check.name} ${JSON.stringify(args)}`, () => check(...args));
}

after(() => temporaryDirectories.cleanup());
test("Deep Scan lifecycle", testDeepScanLifecycle);
test(testPersistedQuotaInterruptsBeforeDispatch);
registerCases(testTerminalFailureStopsDispatchBeforeWorkerShutdown, [
  [false],
  [true],
]);
test(testStandardWorkersReceiveExistingFalsePositiveFeedback);
test(testConcurrentCheckpointKeepsExistingIteration);
test(testDiscoveryAllocatesUniqueLabelsAfterRecovery);
test(testDiscoveryWorkersKeepOneContextAfterPersistedUpdate);
test(testPersistedContextDoesNotChangeAnotherProcessDiscoverySnapshot);
test(testWorkerScopedCandidateSourceAggregation);
test(testRetryKeepsLogicalWorker);
test(testSandboxDiagnosticSurvivesArtifactRetries);
test(testSuccessfulDeepCoverageRetainsIndependentWorkerReviewStatus);
registerCases(testComparisonStopCondition, [["quota"], ["deadline"]]);
test({ timeout: 30_000 }, testDiscoveryDeadlineReducesSingleBufferedFinding);
test(testDiscoveryAcceptedAtDeadlineIsReduced);
test(testDiscoveryDeadlineWithoutAcceptedWorkersReturnsPartialEvidence);
test(testDiscoveryDeadlineBeforeWorkerDispatchReturnsPartialEvidence);
test(testSingletonHardCapReduction);
test(testExhaustedRetryFailsScan);
test(testTransientDiscoveryErrorsRetainRecovery);
test(testConsecutiveTransientErrorsFailAtConfiguredThreshold);
test(testRecoverableWorkerErrorsCannotFailScan);
test(testSuccessfulDiscoveryResetsConsecutiveFailureThreshold);
test(testExhaustedInvalidDiscoveryArtifactsAreReplaced);
test(testExhaustedMalformedDiscoveryDoesNotRemainPublishable);
test(testTransientExecutionFailureResumesWorkerThread);
registerCases(testConfigurationFailureDoesNotRetry, [
  [],
  ["Request blocked by cyberPolicy."],
]);
test(testFailureManifestWriteDoesNotMaskOriginalError);
test(testFinishPersistenceFailureRewritesManifestAsFailure);
test(testLongWorkerErrorIsPreservedAtPersistenceBoundary);
test(testDiscoveryPhasePersistenceFailureStopsDispatch);
test(testCancellationClearsRetryWait);
test(testGenericDiagnosticsPreserveMissingResultRetries);
registerCases(testMissingDiscoveryResultResumesExistingThread, [[], [true]]);
test(testWorkerUsageWithoutHostDirectory);
test(testInvalidArtifactsRetry);
test(testSharedReceiptSurvivesWorkerRetry);
test(testCancellationAfterCommittedAggregateRemainsCanceled);
test(testRejectedFinishDoesNotOverwriteReplacementManifest);
test(testWaiterDetachAndCancellation);
registerCases(testCancellationDropsUnvalidatedDiscoveryResult, [[], [true]]);
test(testDiscoveryAcceptanceFailureFinishesWorkerAsFailed);
test(testCancellationDuringDiscoveryAcceptanceRejectsLateSuccess);
test(testRegistryEvictionAndExternalFailure);
test(testStoppedPublicationFailurePreservesOriginalDiagnostic);
test(testStoppedPublicationFailurePreservesPrefixedDiagnostic);
test(testTerminalReadFailureIsNotRecordedAsPublicationFailure);
test(testStaleMutationObservesReplacement);
test(testStoreConfirmedReplacementSurvivesReadFailure);
test(testStoreConfirmationSurvivesReplayAndThreadMetadata);
test(testCoordinatorHeartbeatsStopAfterOwnershipChanges);
test(testCoordinatorHeartbeatsContinueDuringBlockedOwnershipRead);
test(testRemoteObserverRetriesTransientPersistenceFailures);
test(testJoinAndOrphanRules);
registerCases(testResumeDoesNotRequireHistoricalWorkerPrompt, [
  ["failed"],
  ["canceled"],
]);
registerCases(testPausedDiscoverySurvivesCoordinatorRestart, [[false], []]);
registerCases(testResumedDiscoveryDeadlineUsesPersistedCreationTime, [
  [],
  [true],
  [false, 2.5],
  [true, 96],
]);
registerCases(testResumedManifestPreservesCompletedReducer, [
  [false, false],
  [],
  [true],
  [false, true, ["api", "background jobs"]],
]);
test(testPersistedErrorLimitStopsBeforeRescheduling);
registerCases(testRestartRestoresDispatchOrderAfterMixedResults, [[1], [2]]);
