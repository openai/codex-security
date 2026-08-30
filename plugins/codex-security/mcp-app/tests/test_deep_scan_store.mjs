import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { availableParallelism, tmpdir } from "node:os";
import { join } from "node:path";
import { build } from "esbuild";

const bundle = await build({
  bundle: true,
  entryPoints: [new URL("../src/deep-scan/store.ts", import.meta.url).pathname],
  format: "esm",
  platform: "node",
  write: false
});
const { WorkbenchDeepScanStore, parseDeepScan } = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
);

await testBeginProtocolAndParsing();
await testCanonicalCommitProtocol();
await testTerminalProtocol();
testCanonicalNullAndPartialParsing();
testRunErrorParsing();
testConfiguredMaximumDurationParsing();
await testWriteSerializationAndRecovery();
await testBeginUsesTheWriteQueue();
await testHeartbeatBypassesBlockedWriteQueue();
await testOwnershipReadClearsStaleLease();
await testWorkerResponseParsing();
await testReplaceableDiscoveryFailureProtocol();
await testTransientIdempotentPersistenceRetries();
await testTransientTimeoutAndNestedCauseRetries();
await testPersistenceRetriesRemainInsideTheWriteQueue();
await testPersistenceRetryExhaustionPreservesDiagnostics();
await testDeterministicPersistenceFailuresAreNotRetried();
await testNonIdempotentMutationsAreNotRetried();
testInvalidPersistedConfig();

async function testBeginProtocolAndParsing() {
  const scanId = randomUUID();
  const calls = [];
  const runner = async (args, input) => {
    calls.push({ args, input });
    return stateResult(scanId, { startDisposition: "created" });
  };
  const store = new WorkbenchDeepScanStore(runner);
  const result = await store.begin({
    model: "gpt-5.6-sol",
    reasoningEffort: "high",
    targetPath: "/fixture/repository",
    scope: ".",
    userContext: "focus on archive parsing",
    threadId: "thread-fixture",
    scanRoot: "/fixture/scans"
  });
  assert.equal(result.shouldStart, true);
  assert.equal(result.run.scanId, scanId);
  assert.deepEqual(result.run.config, {
    workers: 6,
    subagents: 3,
    stopAfterNoNew: 6,
    stopAfterConsecutiveErrors: 6,
    maxDiscoveryRuns: 60
  });
  assert.deepEqual(calls[0].args.slice(0, 3), ["begin-deep-scan", "--thread-id", "thread-fixture"]);
  assert.equal(flagValue(calls[0].args, "--target-path"), "/fixture/repository");
  assert.equal(flagValue(calls[0].args, "--model"), "gpt-5.6-sol");
  assert.equal(flagValue(calls[0].args, "--reasoning-effort"), "high");
  assert.equal(flagValue(calls[0].args, "--scope"), ".");
  assert.equal(calls[0].args.includes("--user-context-stdin"), true);
  assert.equal(calls[0].input, "focus on archive parsing");
  assert.equal(flagValue(calls[0].args, "--scan-root"), "/fixture/scans");
  assert.equal(flagValue(calls[0].args, "--available-parallelism"), String(availableParallelism()));
  assert.equal(flagValue(calls[0].args, "--workflow-version"), "deep-scan-mcp/v1");

  const claimToken = randomUUID();
  let joinedArgs;
  const joinedRunner = async (args) => {
    joinedArgs = args;
    return stateResult(scanId, { startDisposition: "joined" });
  };
  const joined = await new WorkbenchDeepScanStore(joinedRunner).begin({
    scanId,
    handoffClaimToken: claimToken,
    threadId: "thread-fixture",
    scanRoot: "/fixture/scans"
  });
  assert.equal(joined.shouldStart, false);
  assert.equal(flagValue(joinedArgs, "--claim-token"), claimToken);
}

async function testWriteSerializationAndRecovery() {
  const calls = [];
  const firstGate = deferred();
  let first = true;
  const runner = async (args) => {
    calls.push(args);
    if (first) {
      first = false;
      await firstGate.promise;
      throw new Error("first write failed");
    }
    return {};
  };
  const store = new WorkbenchDeepScanStore(runner);
  const claimToken = randomUUID();
  const firstWrite = store.updateProgress({ scanId: randomUUID(), phase: "discovery", handoffClaimToken: claimToken });
  const secondWrite = store.updateProgress({ scanId: randomUUID(), reviewItemsCompleted: 1 });
  const cancellation = store.cancel(randomUUID(), "thread-fixture");
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(calls.length, 1, "workbench mutations must execute through one ordered queue");
  firstGate.resolve();
  await assert.rejects(firstWrite, /first write failed/);
  await Promise.all([secondWrite, cancellation]);
  assert.equal(calls.length, 3, "a failed mutation must not wedge later persistence");
  assert.equal(calls[0][0], "update-progress");
  assert.equal(flagValue(calls[0], "--claim-token"), claimToken);
  assert.equal(calls[1][0], "update-progress");
  assert.equal(calls[2][0], "cancel-scan", "cancellation must use the same ordered persistence queue");
}

async function testBeginUsesTheWriteQueue() {
  const scanId = randomUUID();
  const calls = [];
  const firstGate = deferred();
  const runner = async (args) => {
    calls.push(args);
    if (args[0] === "update-progress") {
      await firstGate.promise;
      return {};
    }
    return stateResult(scanId, { startDisposition: "created" });
  };
  const store = new WorkbenchDeepScanStore(runner);
  const progress = store.updateProgress({ scanId, phase: "discovery" });
  const begin = store.begin({
    targetPath: "/fixture/repository",
    scope: ".",
    threadId: "thread-fixture",
    scanRoot: "/fixture/scans"
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(calls.length, 1, "begin must wait behind an earlier mutation");
  firstGate.resolve();
  await Promise.all([progress, begin]);
  assert.deepEqual(calls.map((args) => args[0]), ["update-progress", "begin-deep-scan"]);
}

async function testHeartbeatBypassesBlockedWriteQueue() {
  const scanId = randomUUID();
  const handoffClaimToken = randomUUID();
  const scanDir = await mkdtemp(join(tmpdir(), "deep-scan-heartbeat-"));
  const blockedWriteGate = deferred();
  const calls = [];
  const runner = async (args) => {
    calls.push(args);
    if (args[0] === "update-progress") {
      await blockedWriteGate.promise;
      return {};
    }
    return {
      ...stateResult(scanId, { deepScan: { coordinatorGeneration: 2, scanDir } }),
      coordinatorDisposition: "claimed"
    };
  };
  const store = new WorkbenchDeepScanStore(runner);
  const lease = { scanId, threadId: "thread-fixture", handoffClaimToken };
  await store.claimCoordinator(lease);
  const blockedWrite = store.updateProgress({ scanId, phase: "discovery" });
  await new Promise((resolve) => setImmediate(resolve));
  const heartbeat = store.heartbeatCoordinator(lease);

  try {
    const renewed = await heartbeat;
    assert.equal(calls.length, 2, "heartbeat must not invoke the SQLite workbench");
    assert.equal(renewed.coordinatorGeneration, 2);
    assert.deepEqual(JSON.parse(await readFile(join(
      scanDir,
      "artifacts",
      "deep_discovery",
      "coordinator-heartbeat-2.json"
    ), "utf8")), { coordinatorGeneration: 2, updatedAt: renewed.updatedAt });
    await assert.rejects(
      store.heartbeatCoordinator({ ...lease, handoffClaimToken: randomUUID() }),
      /another continuation/
    );
  } finally {
    blockedWriteGate.resolve();
    await Promise.allSettled([blockedWrite, heartbeat]);
    await rm(scanDir, { recursive: true, force: true });
  }
}

async function testOwnershipReadClearsStaleLease() {
  const scanId = randomUUID();
  const calls = [];
  let generation = 2;
  let rejectProgress = false;
  const store = new WorkbenchDeepScanStore(async (args) => {
    calls.push(args);
    if (args[0] === "update-progress" && rejectProgress) {
      throw new Error("Deep Scan coordinator lease belongs to a newer generation.");
    }
    if (args[0] === "get-deep-scan") generation = 3;
    return {
      ...stateResult(scanId, { deepScan: { coordinatorGeneration: generation } }),
      coordinatorDisposition: "claimed"
    };
  });
  const lease = { scanId, threadId: "thread-fixture" };

  await store.claimCoordinator(lease);
  await store.get(scanId, lease.threadId);
  await store.claimCoordinator(lease);

  assert.equal(calls[0].includes("--coordinator-generation"), false);
  assert.equal(calls[2].includes("--coordinator-generation"), false,
    "a confirmed newer generation must clear the cached lease before a later claim");

  rejectProgress = true;
  await assert.rejects(store.updateProgress({ scanId, phase: "discovery" }), /newer generation/);
  generation = 4;
  await store.claimCoordinator(lease);
  assert.equal(calls[4].includes("--coordinator-generation"), false,
    "a fenced mutation must also clear the cached lease");
}

async function testWorkerResponseParsing() {
  const scanId = randomUUID();
  const workerId = randomUUID();
  const mutation = {
    id: workerId,
    scanId,
    kind: "discovery",
    status: "succeeded",
    promptPath: "/fixture/prompt.md",
    artifactDir: "/fixture/output",
    attempt: 1,
    resultManifestPath: "/fixture/output/result.json"
  };
  const worker = await new WorkbenchDeepScanStore(async () => stateResult(scanId, {
    deepScan: {
      workers: [{
        id: workerId,
        kind: "discovery",
        status: "succeeded",
        mergeState: "buffered",
        promptPath: mutation.promptPath,
        artifactDir: mutation.artifactDir,
        resultManifestPath: mutation.resultManifestPath,
        attempt: 1,
        sdkThreadId: "thread-worker",
        completionSequence: 3,
        error: "worker was rate limited"
      }]
    }
  })).updateWorker(mutation);

  assert.equal(worker.completionSequence, 3);
  assert.equal(worker.mergeState, "buffered");
  assert.equal(worker.threadId, "thread-worker");
  assert.equal(worker.error, "worker was rate limited");
}

async function testReplaceableDiscoveryFailureProtocol() {
  const scanId = randomUUID();
  const workerId = randomUUID();
  let invocation;
  const store = new WorkbenchDeepScanStore(async (args) => {
    invocation = args;
    return stateResult(scanId, {
      deepScan: {
        consecutiveErrors: 2,
        workers: [{
          id: workerId,
          kind: "discovery",
          status: "canceled",
          mergeState: "none",
          promptPath: "/fixture/prompt.md",
          artifactDir: "/fixture/output",
          attempt: 1,
          error: "policy_refusal: request refused by cybersecurity policy"
        }]
      }
    });
  });

  const worker = await store.updateWorker({
    id: workerId,
    scanId,
    kind: "discovery",
    status: "canceled",
    promptPath: "/fixture/prompt.md",
    artifactDir: "/fixture/output",
    attempt: 1,
    replaceableFailureKind: "policy_refusal",
    error: "policy_refusal: request refused by cybersecurity policy"
  });

  assert.equal(flagValue(invocation, "--replaceable-failure-kind"), "policy_refusal");
  assert.equal(worker.status, "canceled");
  assert.equal(worker.consecutiveErrors, 2);
}

async function testCanonicalCommitProtocol() {
  const scanId = randomUUID();
  const canonical = {
    inScopeFilesPath: "/fixture/scans/run/artifacts/02_discovery/in_scope_files.txt",
    candidateLedgerPath: "/fixture/scans/run/artifacts/02_discovery/candidate_ledger.jsonl"
  };
  const reducerId = randomUUID();
  const resultManifestPath = "/fixture/scans/run/artifacts/deep_discovery/dedup/result.json";
  let command;
  const store = new WorkbenchDeepScanStore(async (args) => {
    command = args;
    return stateResult(scanId, { deepScan: { canonicalArtifacts: canonical } });
  });
  const state = await store.commitDedup({
    id: reducerId,
    scanId,
    newFindings: 1,
    resultManifestPath
  });
  assert.deepEqual(state.canonicalArtifacts, canonical);
  assert.deepEqual(command, [
    "commit-deep-scan-dedup",
    "--scan-id", scanId,
    "--worker-id", reducerId,
    "--result-manifest-path", resultManifestPath,
    "--new-findings-count", "1"
  ]);
}

async function testTerminalProtocol() {
  const scanId = randomUUID();
  const omittedWorkerIds = [randomUUID(), randomUUID()];
  const calls = [];
  const store = new WorkbenchDeepScanStore(async (args) => {
    calls.push(args);
    return stateResult(scanId, {
      deepScan: {
        status: args[0] === "finish-deep-scan" ? "succeeded" : "failed",
        manifestPath: flagValue(args, "--manifest-path"),
        terminalReason: args[0] === "finish-deep-scan" ? "saturated" : undefined,
        error: args[0] === "fail-deep-scan" ? "fixture failure" : undefined
      }
    });
  });
  await store.finish({
    scanId,
    reason: "saturated",
    manifestPath: "/fixture/scans/run/coordinator-manifest.json",
    omittedWorkerIds
  });
  await store.fail(
    scanId,
    "fixture failure",
    "failed",
    "/fixture/scans/run/coordinator-failure-manifest.json"
  );
  assert.deepEqual(
    repeatedFlagValues(calls[0], "--omitted-worker-id"),
    omittedWorkerIds
  );
  assert.equal(
    flagValue(calls[1], "--manifest-path"),
    "/fixture/scans/run/coordinator-failure-manifest.json"
  );
}

async function testTransientIdempotentPersistenceRetries() {
  for (const scenario of idempotentPersistenceScenarios()) {
    const calls = [];
    const store = new WorkbenchDeepScanStore(async (args) => {
      calls.push([...args]);
      if (calls.length < 3) {
        throw Object.assign(new Error("sqlite3.OperationalError: database is locked"), {
          code: "SQLITE_BUSY"
        });
      }
      return scenario.result;
    });

    await scenario.invoke(store);

    assert.equal(calls.length, 3, `${scenario.operation} should retry bounded transient contention`);
    assert.equal(calls[0][0], scenario.operation);
    assert.deepEqual(calls[1], calls[0], `${scenario.operation} must replay the identical mutation`);
    assert.deepEqual(calls[2], calls[0], `${scenario.operation} must preserve its original identities and inputs`);
  }
}

async function testTransientTimeoutAndNestedCauseRetries() {
  for (const failure of [
    Object.assign(new Error("workbench command timed out"), { code: "ETIMEDOUT" }),
    new Error("workbench command failed", {
      cause: Object.assign(new Error("sqlite3.OperationalError: database is locked"), {
        code: "SQLITE_LOCKED"
      })
    }),
    Object.assign(new Error("workbench command ended before returning its commit"), {
      killed: true,
      signal: "SIGTERM"
    })
  ]) {
    const scenario = idempotentPersistenceScenarios()[1];
    let attempts = 0;
    const store = new WorkbenchDeepScanStore(async () => {
      attempts += 1;
      if (attempts === 1) throw failure;
      return scenario.result;
    });

    await scenario.invoke(store);
    assert.equal(attempts, 2, `expected one exact replay for ${failure.message}`);
  }
}

async function testPersistenceRetriesRemainInsideTheWriteQueue() {
  const scanId = randomUUID();
  const calls = [];
  const store = new WorkbenchDeepScanStore(async (args) => {
    calls.push(args[0]);
    if (args[0] === "claim-deep-scan-dedup" && calls.length === 1) {
      throw new Error("sqlite3.OperationalError: database is locked");
    }
    return {};
  });

  const claim = store.claimDedup({
    id: randomUUID(),
    scanId,
    workerIds: [randomUUID()],
    promptPath: "/fixture/reducer/prompt.md",
    artifactDir: "/fixture/reducer/output"
  });
  const cancellation = store.cancel(scanId, "thread-fixture");
  await Promise.all([claim, cancellation]);

  assert.deepEqual(calls, [
    "claim-deep-scan-dedup",
    "claim-deep-scan-dedup",
    "cancel-scan"
  ], "later mutations must not interleave with an idempotent persistence replay");
}

async function testPersistenceRetryExhaustionPreservesDiagnostics() {
  const scanId = randomUUID();
  const reducerId = randomUUID();
  const originalFailure = Object.assign(
    new Error("sqlite3.OperationalError: database is locked"),
    { code: "SQLITE_BUSY", exitCode: 1, signal: "SIGTERM", killed: true, timeout: 30_000 }
  );
  const calls = [];
  const events = [];
  const originalConsoleError = console.error;
  const store = new WorkbenchDeepScanStore(async (args) => {
    calls.push([...args]);
    if (args[0] === "claim-deep-scan-dedup") throw originalFailure;
    return {};
  });
  console.error = (event) => events.push(event);

  try {
    await assert.rejects(
      store.claimDedup({
        id: reducerId,
        scanId,
        workerIds: [randomUUID()],
        promptPath: "/fixture/reducer/prompt.md",
        artifactDir: "/fixture/reducer/output"
      }),
      (error) => {
        assert.equal(error.name, "DeepScanPersistenceError");
        assert.equal(error.operation, "claim-deep-scan-dedup");
        assert.equal(error.scanId, scanId);
        assert.equal(error.workerId, reducerId);
        assert.equal(error.attempts, 3);
        assert.equal(error.code, "SQLITE_BUSY");
        assert.equal(error.exitCode, 1);
        assert.equal(error.signal, "SIGTERM");
        assert.equal(error.killed, true);
        assert.equal(error.timeoutMs, 30_000);
        assert.equal(error.cause, originalFailure);
        assert.match(error.message, /database is locked/);
        assert.match(error.message, /failed after 3 attempts/);
        assert.ok(Number.isInteger(error.elapsedMs) && error.elapsedMs >= 0);
        return true;
      }
    );
  } finally {
    console.error = originalConsoleError;
  }

  assert.equal(calls.length, 3, "transient failures must stop at the bounded replay budget");
  assert.equal(events.length, 1, "retry exhaustion must leave one diagnostic event");
  const event = JSON.parse(events[0]);
  assert.equal(event.event, "persistence_retry_exhausted");
  assert.equal(event.operation, "claim-deep-scan-dedup");
  assert.equal(event.scanId, scanId);
  assert.equal(event.workerId, reducerId);
  assert.equal(event.attempts, 3);
  assert.equal(event.code, "SQLITE_BUSY");
  assert.equal(event.exitCode, 1);
  assert.equal(event.signal, "SIGTERM");
  assert.equal(event.killed, true);
  assert.equal(event.timeoutMs, 30_000);
  assert.match(event.error, /database is locked/);

  await store.updateProgress({ scanId, phase: "discovery" });
  assert.equal(calls[3][0], "update-progress", "exhaustion must not wedge subsequent persistence");
}

async function testDeterministicPersistenceFailuresAreNotRetried() {
  for (const diagnostic of [
    "Reducer must claim an ordered prefix of buffered discovery results.",
    "sqlite3.DatabaseError: database disk image is malformed",
    "SQLITE_CORRUPT: invalid database page",
    "sqlite3.OperationalError: no such table: deep_scan_workers",
    "sqlite3.OperationalError: attempt to write a readonly database",
    "Reducer source provenance contains an unknown worker.",
    "Artifact path escapes the assigned scan directory.",
    "Authentication required for Codex Security workbench."
  ]) {
    const scenario = idempotentPersistenceScenarios()[1];
    const expected = new Error(diagnostic);
    let attempts = 0;
    const store = new WorkbenchDeepScanStore(async () => {
      attempts += 1;
      throw expected;
    });

    await assert.rejects(scenario.invoke(store), (error) => error === expected);
    assert.equal(attempts, 1, `${diagnostic} must not be blindly replayed`);
  }

  const canceled = Object.assign(new Error("workbench command timed out"), {
    code: "ABORT_ERR",
    name: "AbortError"
  });
  let attempts = 0;
  const store = new WorkbenchDeepScanStore(async () => {
    attempts += 1;
    throw canceled;
  });
  await assert.rejects(idempotentPersistenceScenarios()[1].invoke(store), (error) => error === canceled);
  assert.equal(attempts, 1, "explicit cancellation must never be treated as a transient timeout");

  for (const status of ["queued", "running", "succeeded", "failed", "canceled"]) {
    for (const failure of [
      Object.assign(new Error("sqlite3.DatabaseError: database disk image is malformed"), {
        code: "SQLITE_CORRUPT"
      }),
      Object.assign(new Error("workbench command timed out"), {
        code: "ABORT_ERR",
        name: "AbortError"
      })
    ]) {
      let workerAttempts = 0;
      const workerStore = new WorkbenchDeepScanStore(async () => {
        workerAttempts += 1;
        throw failure;
      });

      await assert.rejects(workerStore.updateWorker({
        id: randomUUID(),
        scanId: randomUUID(),
        kind: "discovery",
        status,
        promptPath: "/fixture/worker/prompt.md",
        artifactDir: "/fixture/worker/output",
        attempt: 1
      }), (error) => error === failure);
      assert.equal(workerAttempts, 1, `${status} updates must not replay ${failure.code}`);
    }
  }
}

async function testNonIdempotentMutationsAreNotRetried() {
  for (const operation of ["progress", "cancel", "fail", "begin"]) {
    let attempts = 0;
    const expected = new Error("sqlite3.OperationalError: database is locked");
    const store = new WorkbenchDeepScanStore(async () => {
      attempts += 1;
      throw expected;
    });
    const scanId = randomUUID();
    const request = operation === "progress"
      ? store.updateProgress({ scanId, phase: "discovery" })
      : operation === "cancel"
        ? store.cancel(scanId, "thread-fixture")
        : operation === "fail"
          ? store.fail(scanId, "fixture failure")
          : store.begin({
            targetPath: "/fixture/repository",
            threadId: "thread-fixture",
            scanRoot: "/fixture/scans"
          });

    await assert.rejects(request, (error) => error === expected);
    assert.equal(attempts, 1, `${operation} must not gain a new persistence retry policy`);
  }
}

function idempotentPersistenceScenarios() {
  const scanId = randomUUID();
  const workerId = randomUUID();
  const reducerId = randomUUID();
  const canonical = {
    inScopeFilesPath: "/fixture/scans/run/artifacts/02_discovery/in_scope_files.txt",
    candidateLedgerPath: "/fixture/scans/run/artifacts/02_discovery/candidate_ledger.jsonl"
  };
  const worker = {
    id: workerId,
    kind: "discovery",
    status: "succeeded",
    mergeState: "buffered",
    promptPath: "/fixture/discovery/prompt.md",
    artifactDir: "/fixture/discovery/output",
    attempt: 1,
    resultManifestPath: "/fixture/discovery/output/result.json",
    completionSequence: 1
  };

  return [{
    operation: "upsert-deep-scan-worker",
    result: stateResult(scanId, {
      deepScan: {
        workers: [{
          ...worker,
          status: "running",
          mergeState: "none",
          resultManifestPath: undefined,
          completionSequence: undefined
        }]
      }
    }),
    invoke: (store) => store.updateWorker({
      id: workerId,
      scanId,
      kind: "discovery",
      status: "running",
      promptPath: worker.promptPath,
      artifactDir: worker.artifactDir,
      attempt: worker.attempt
    })
  }, {
    operation: "upsert-deep-scan-worker",
    result: stateResult(scanId, {
      deepScan: {
        workers: [{
          ...worker,
          status: "running",
          mergeState: "none",
          resultManifestPath: undefined,
          completionSequence: undefined,
          sdkThreadId: "thread-worker"
        }]
      }
    }),
    invoke: (store) => store.updateWorker({
      id: workerId,
      scanId,
      kind: "discovery",
      status: "running",
      promptPath: worker.promptPath,
      artifactDir: worker.artifactDir,
      attempt: worker.attempt,
      threadId: "thread-worker"
    })
  }, ...["queued", "failed", "canceled"].map((status) => ({
    operation: "upsert-deep-scan-worker",
    result: stateResult(scanId, {
      deepScan: {
        workers: [{
          ...worker,
          status,
          mergeState: "none",
          resultManifestPath: undefined,
          completionSequence: undefined
        }]
      }
    }),
    invoke: (store) => store.updateWorker({
      id: workerId,
      scanId,
      kind: "discovery",
      status,
      promptPath: worker.promptPath,
      artifactDir: worker.artifactDir,
      attempt: worker.attempt
    })
  })), {
    operation: "upsert-deep-scan-worker",
    result: stateResult(scanId, { deepScan: { workers: [worker] } }),
    invoke: (store) => store.updateWorker({
      id: workerId,
      scanId,
      kind: "discovery",
      status: "succeeded",
      promptPath: worker.promptPath,
      artifactDir: worker.artifactDir,
      attempt: worker.attempt,
      resultManifestPath: worker.resultManifestPath
    })
  }, {
    operation: "claim-deep-scan-dedup",
    result: {},
    invoke: (store) => store.claimDedup({
      id: reducerId,
      scanId,
      workerIds: [workerId],
      promptPath: "/fixture/reducer/prompt.md",
      artifactDir: "/fixture/reducer/output"
    })
  }, {
    operation: "commit-deep-scan-dedup",
    result: stateResult(scanId, { deepScan: { canonicalArtifacts: canonical } }),
    invoke: (store) => store.commitDedup({
      id: reducerId,
      scanId,
      newFindings: 1,
      canonicalArtifacts: canonical,
      resultManifestPath: "/fixture/reducer/output/result.json"
    })
  }, {
    operation: "finish-deep-scan",
    result: stateResult(scanId, {
      deepScan: {
        status: "succeeded",
        terminalReason: "saturated",
        manifestPath: "/fixture/scans/run/coordinator-manifest.json"
      }
    }),
    invoke: (store) => store.finish({
      scanId,
      reason: "saturated",
      manifestPath: "/fixture/scans/run/coordinator-manifest.json",
      omittedWorkerIds: []
    })
  }, {
    operation: "record-deep-scan-publication-failure",
    result: stateResult(scanId, {
      deepScan: {
        status: "canceled",
        error: "Saved result publication failed: fixture publication failure"
      }
    }),
    invoke: (store) => store.recordStoppedPublicationFailure(
      scanId,
      "Saved result publication failed: fixture publication failure",
      3
    )
  }];
}

function testInvalidPersistedConfig() {
  assert.throws(
    () => parseDeepScan(stateResult(randomUUID(), {
      deepScan: { config: { maxDiscoveryRuns: 0 } }
    })),
    /invalid deepScan\.config\.maxDiscoveryRuns/
  );
  assert.throws(
    () => parseDeepScan(stateResult(randomUUID(), {
      deepScan: { config: { stopAfterConsecutiveErrors: 0 } }
    })),
    /invalid deepScan\.config\.stopAfterConsecutiveErrors/
  );
  assert.throws(
    () => parseDeepScan(stateResult(randomUUID(), {
      deepScan: { consecutiveErrors: -1 }
    })),
    /invalid deepScan\.consecutiveErrors/
  );
  for (const maxTimeHours of [0, -1, 96.01, Infinity, -Infinity, NaN, true, "2.5"]) {
    assert.throws(
      () => parseDeepScan(stateResult(randomUUID(), {
        deepScan: { config: { maxTimeHours } }
      })),
      /invalid deepScan\.config\.maxTimeHours/,
      `invalid configured duration ${String(maxTimeHours)} must be rejected`
    );
  }
}

function testConfiguredMaximumDurationParsing() {
  for (const maxTimeHours of [0.25, 2.5, 95, 96]) {
    const state = parseDeepScan(stateResult(randomUUID(), {
      deepScan: { config: { maxTimeHours } }
    }));
    assert.equal(state.config.maxTimeHours, maxTimeHours);
  }
  const legacyState = parseDeepScan(stateResult(randomUUID()));
  assert.equal(Object.hasOwn(legacyState.config, "maxTimeHours"), false);
}

function testRunErrorParsing() {
  const createdAt = "2026-08-12T19:00:00Z";
  const state = parseDeepScan(stateResult(randomUUID(), {
    deepScan: { status: "failed", error: "discovery retries exhausted", createdAt }
  }));
  assert.equal(state.createdAt, createdAt);
  assert.equal(state.error, "discovery retries exhausted");
}

function testCanonicalNullAndPartialParsing() {
  assert.equal(parseDeepScan(stateResult(randomUUID(), {
    deepScan: { canonicalArtifacts: null }
  })).canonicalArtifacts, undefined);
  assert.throws(
    () => parseDeepScan(stateResult(randomUUID(), {
      deepScan: {
        canonicalArtifacts: {
          inScopeFilesPath: "/fixture/scans/run/artifacts/02_discovery/in_scope_files.txt"
        }
      }
    })),
    /invalid deepScan\.canonicalArtifacts\.candidateLedgerPath/
  );
  assert.throws(
    () => parseDeepScan(stateResult(randomUUID(), {
      deepScan: {
        canonicalArtifacts: {
          candidateLedgerPath: "/fixture/scans/run/artifacts/02_discovery/candidate_ledger.jsonl"
        }
      }
    })),
    /invalid deepScan\.canonicalArtifacts\.inScopeFilesPath/
  );
}

function stateResult(scanId, overrides = {}) {
  const deepScanOverride = overrides.deepScan ?? {};
  return {
    startDisposition: overrides.startDisposition,
    deepScan: {
      scanId,
      status: "running",
      targetPath: "/fixture/repository",
      scope: ".",
      userContext: null,
      scanDir: "/fixture/scans/run",
      ...deepScanOverride,
      config: {
        workers: 6,
        subagents: 3,
        stopAfterNoNew: 6,
        stopAfterConsecutiveErrors: 6,
        maxDiscoveryRuns: 60,
        ...(deepScanOverride.config ?? {})
      },
      dispatchedCount: deepScanOverride.dispatchedCount ?? 0,
      noNewStreak: deepScanOverride.noNewStreak ?? 0,
      consecutiveErrors: deepScanOverride.consecutiveErrors ?? 0,
      workers: deepScanOverride.workers ?? []
    }
  };
}

function flagValue(args, flag) {
  const index = args.indexOf(flag);
  assert.notEqual(index, -1, `missing ${flag}`);
  return args[index + 1];
}

function repeatedFlagValues(args, flag) {
  return args.flatMap((value, index) => value === flag ? [args[index + 1]] : []);
}

function deferred() {
  let resolve;
  const promise = new Promise((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}
