import { readJson, writeJsonLine } from "./support/json.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import assert from "node:assert/strict";
import { mock } from "node:test";
import { execFile, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { importModule } from "./import-module.ts";

const execFileAsync = promisify(execFile);
const mcpAppRoot = path.resolve(import.meta.dirname, "..");
const pluginRoot = path.resolve(mcpAppRoot, "..");
const workbenchPath = path.join(pluginRoot, "scripts", "workbench_db.py");
const {
  WorkbenchDeepScanStore,
  createScanArtifactContext,
  recordCodexSecurityScanDraftViaWorkbench,
} = await importModule({
  stdin: {
    contents: `export { WorkbenchDeepScanStore } from "./src/deep-scan/store.ts";
export { createScanArtifactContext } from "./src/artifact-context.ts";
export { recordCodexSecurityScanDraftViaWorkbench } from "./src/artifact-scan-draft.ts";`,
    resolveDir: mcpAppRoot,
  },
});

await testFreeformFailureMessagesAgainstRealWorkbench();
await testReducerCommitAndFinishAgainstRealWorkbench();
await testReducerCommitAndFinishAgainstRealWorkbench(true);
await testExpiredDeadlineWithoutCompletedDiscoveryAgainstRealWorkbench();
await testLateParentDraftPreservesCheckpointWithoutOverwritingTerminalSeal();
await testRecoveredPublicationRejectsLateFailure();
await testNoopStoppedRefreshRetainsPublicationFailure();
await testConcurrentParentDraftsPreserveBothCheckpoints();

async function createWorkbenchFixture(prefix: string) {
  const fixtureRoot = await temporaryDirectory(prefix);
  const targetPath = path.join(fixtureRoot, "target");
  const environment = {
    ...process.env,
    CODEX_HOME: path.join(fixtureRoot, "codex-home"),
    CODEX_SECURITY_STATE_DIR: path.join(fixtureRoot, "state"),
  };
  try {
    await mkdir(targetPath, { recursive: true });
    await writeFile(path.join(targetPath, "fixture.py"), "print('fixture')\n");
    return { fixtureRoot, targetPath, environment };
  } catch (error) {
    await rm(fixtureRoot, { recursive: true, force: true });
    throw error;
  }
}

function createWorkbenchRunner(environment: NodeJS.ProcessEnv, bounded = true) {
  const python = process.env.PYTHON?.trim() || "python3";
  return async (args: string[]) => {
    const { stdout } = await execFileAsync(python, [workbenchPath, ...args], {
      cwd: pluginRoot,
      env: environment,
      ...(bounded ? { timeout: 30_000, maxBuffer: 4 * 1024 * 1024 } : {}),
    });
    return JSON.parse(stdout);
  };
}

async function testFreeformFailureMessagesAgainstRealWorkbench() {
  const { fixtureRoot, targetPath, environment } = await createWorkbenchFixture(
    "deep-scan-error-transport-",
  );
  const store = new WorkbenchDeepScanStore(createWorkbenchRunner(environment));
  try {
    const run = await store.begin({
      targetPath,
      threadId: "error-owner",
      scanRoot: path.join(fixtureRoot, "scans"),
    });
    await store.claimCoordinator({
      scanId: run.scanId,
      threadId: "error-owner",
    });
    const worker = await createWorkerFixture(run, "discovery", "discovery");
    await store.updateWorker({ ...worker, status: "running" });
    const message = "--provider-error=café\nretry the request";
    const failed = await store.updateWorker({
      ...worker,
      status: "failed",
      error: message,
    });
    assert.equal(failed.error, message);
    assert.equal((await store.fail(run.scanId, message)).error, message);
    const reloaded = await store.get(run.scanId, "error-owner");
    assert.equal(reloaded.error, message);
    assert.equal(reloaded.persistedWorkers[0].error, message);
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
}

async function testRecoveredPublicationRejectsLateFailure() {
  const { fixtureRoot, targetPath, environment } = await createWorkbenchFixture(
    "deep-scan-publication-failure-",
  );
  const runWorkbench = createWorkbenchRunner(environment);
  try {
    const store = new WorkbenchDeepScanStore(runWorkbench);
    const run = await store.begin({
      targetPath,
      scope: ".",
      threadId: "publication-failure-owner",
      scanRoot: path.join(fixtureRoot, "scans"),
    });
    const claim = await store.claimCoordinator({
      scanId: run.scanId,
      threadId: "publication-failure-owner",
    });
    assert.equal(claim.acquired, true);
    assert.equal(claim.run.coordinatorGeneration > 1, true);
    const context = await createScanArtifactContext(run.scanId, runWorkbench, {
      requireRunning: true,
    });
    await recordCodexSecurityScanDraftViaWorkbench(
      context,
      checkpoint(
        run.scanId,
        "publication-recovery-candidate",
        "Publication recovery remains pending.",
      ),
      runWorkbench,
    );
    await runWorkbench([
      "cancel-scan",
      "--scan-id",
      run.scanId,
      "--thread-id",
      "publication-failure-owner",
    ]);
    assert.equal(
      (await store.get(run.scanId, "publication-failure-owner")).status,
      "canceled",
    );
    const message =
      "Saved result publication failed: stale fixture publication failure";
    await store.recordStoppedPublicationFailure(
      run.scanId,
      message,
      claim.run.coordinatorGeneration,
    );
    const reloaded = await new WorkbenchDeepScanStore(runWorkbench).get(
      run.scanId,
      "publication-failure-owner",
    );
    assert.equal(reloaded.status, "canceled");
    assert.equal(
      reloaded.error,
      undefined,
      "a delayed failure write must not restore an error after publication recovered",
    );
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
}

async function testNoopStoppedRefreshRetainsPublicationFailure() {
  const { fixtureRoot, targetPath, environment } = await createWorkbenchFixture(
    "deep-scan-noop-publication-",
  );
  const runWorkbench = createWorkbenchRunner(environment);
  try {
    const store = new WorkbenchDeepScanStore(runWorkbench);
    const run = await store.begin({
      targetPath,
      scope: ".",
      threadId: "noop-publication-owner",
      scanRoot: path.join(fixtureRoot, "scans"),
    });
    const claim = await store.claimCoordinator({
      scanId: run.scanId,
      threadId: "noop-publication-owner",
    });
    await runWorkbench([
      "cancel-scan",
      "--scan-id",
      run.scanId,
      "--thread-id",
      "noop-publication-owner",
    ]);
    const message =
      "--publication-error=café\nSaved result publication failed.";
    await store.recordStoppedPublicationFailure(
      run.scanId,
      message,
      claim.run.coordinatorGeneration,
    );
    await runWorkbench(["get-scan", "--scan-id", run.scanId]);
    assert.equal(
      (
        await new WorkbenchDeepScanStore(runWorkbench).get(
          run.scanId,
          "noop-publication-owner",
        )
      ).error,
      message,
      "a no-op retained-result refresh must keep its publication failure",
    );
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
}

function checkpoint(scanId: string, candidateId: string, reason: string) {
  return {
    scanId,
    complete: false,
    findings: [],
    coverage: {
      completeness: "partial",
      surfaces: [],
      explicitExclusions: [],
      deferred: [{ candidateId, reason, paths: ["fixture.py"] }],
    },
  };
}

async function testConcurrentParentDraftsPreserveBothCheckpoints() {
  const { fixtureRoot, targetPath, environment } = await createWorkbenchFixture(
    "scan-draft-concurrency-integration-",
  );
  const rawRunWorkbench = createWorkbenchRunner(environment);
  let stagedWrites = 0;
  const initialWritesReady = Promise.withResolvers<void>();
  const runWorkbench = async (args: string[]) => {
    if (args[0] === "write-scan-draft" && ++stagedWrites <= 2) {
      if (stagedWrites === 2) initialWritesReady.resolve();
      await initialWritesReady.promise;
    }
    return rawRunWorkbench(args);
  };
  try {
    const run = await new WorkbenchDeepScanStore(rawRunWorkbench).begin({
      targetPath,
      scope: ".",
      threadId: "concurrent-draft-owner",
      scanRoot: path.join(fixtureRoot, "scans"),
    });
    const context = await createScanArtifactContext(run.scanId, runWorkbench, {
      requireRunning: true,
    });

    await Promise.all([
      recordCodexSecurityScanDraftViaWorkbench(
        context,
        checkpoint(
          run.scanId,
          "concurrent-a",
          "Independent review remains pending.",
        ),
        runWorkbench,
      ),
      recordCodexSecurityScanDraftViaWorkbench(
        context,
        checkpoint(
          run.scanId,
          "concurrent-b",
          "Independent review remains pending.",
        ),
        runWorkbench,
      ),
    ]);
    assert.equal(
      stagedWrites,
      3,
      "the stale writer retries after the host rejects its digest",
    );

    const coverage = await readJson(run.scanDir, "coverage.json");
    assert.deepEqual(
      new Set(
        coverage.deferred.map(
          (item: { candidateId: string }) => item.candidateId,
        ),
      ),
      new Set(["concurrent-a", "concurrent-b"]),
      "overlapping canonical writes must merge every immutable checkpoint",
    );
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
}

async function testLateParentDraftPreservesCheckpointWithoutOverwritingTerminalSeal() {
  const { fixtureRoot, targetPath, environment } = await createWorkbenchFixture(
    "scan-draft-cancel-integration-",
  );
  const runWorkbench = createWorkbenchRunner(environment);
  try {
    const run = await new WorkbenchDeepScanStore(runWorkbench).begin({
      targetPath,
      scope: ".",
      threadId: "checkpoint-owner",
      scanRoot: path.join(fixtureRoot, "scans"),
    });
    const context = await createScanArtifactContext(run.scanId, runWorkbench, {
      requireRunning: true,
    });
    await recordCodexSecurityScanDraftViaWorkbench(
      context,
      checkpoint(
        run.scanId,
        "early-result",
        "Source validation remains pending.",
      ),
      runWorkbench,
    );
    await runWorkbench([
      "cancel-scan",
      "--scan-id",
      run.scanId,
      "--thread-id",
      "checkpoint-owner",
    ]);
    const manifestPath = path.join(run.scanDir, "scan-manifest.json");
    const sealed = await readFile(manifestPath, "utf8");
    assert.equal(JSON.parse(sealed).scan.status, "canceled");

    await assert.rejects(
      recordCodexSecurityScanDraftViaWorkbench(
        context,
        checkpoint(
          run.scanId,
          "late-result",
          "Source validation remains pending.",
        ),
        runWorkbench,
      ),
      /not running|stopped|terminal/i,
    );
    assert.equal(
      await readFile(manifestPath, "utf8"),
      sealed,
      "a stale writer cannot overwrite a terminal seal",
    );
    const stopped = await runWorkbench(["get-scan", "--scan-id", run.scanId]);
    assert.equal(stopped.scan.progress.status, "canceled");
    const coverage = await readJson(run.scanDir, "coverage.json");
    const pending = coverage.deferred.map(
      (item: { candidateId: string }) => item.candidateId,
    );
    assert.ok(pending.includes("early-result"));
    assert.ok(
      !pending.includes("late-result"),
      "a checkpoint written after cancellation must not change retained results",
    );
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
}

async function testReducerCommitAndFinishAgainstRealWorkbench(
  replaceFailedReducer = false,
) {
  const { fixtureRoot, targetPath, environment } = await createWorkbenchFixture(
    "deep-scan-store-integration-",
  );
  const scanRoot = path.join(fixtureRoot, "scans");
  const codexHome = path.join(fixtureRoot, "codex-home");
  const threadId = "deep-scan-store-integration-thread";
  const python = process.env.PYTHON?.trim() || "python3";
  const runWorkbench = mock.fn(createWorkbenchRunner(environment));
  const store = new WorkbenchDeepScanStore(runWorkbench);

  try {
    await mkdir(path.join(codexHome, "codex-security"), { recursive: true });
    await writeFile(
      path.join(codexHome, "codex-security", "config.toml"),
      `[deep_scan]
workers = 2
subagents = 0
stop_after_no_new = 2
max_discovery_runs = 3
max_time_hours = 2.5
`,
    );

    const run = await store.begin({
      targetPath,
      scope: ".",
      threadId,
      scanRoot,
    });
    assert.equal(typeof run.createdAt, "string");
    assert.equal(run.config.maxTimeHours, 2.5);
    const owned = await store.claimCoordinator({
      scanId: run.scanId,
      threadId,
    });
    assert.equal(owned.run.coordinatorGeneration, 2);
    const observer = new WorkbenchDeepScanStore(runWorkbench);
    const joined = await observer.begin({
      scanId: run.scanId,
      threadId,
      scanRoot,
    });
    const observed = await observer.claimCoordinator({
      scanId: joined.scanId,
      threadId,
    });
    assert.equal(observed.acquired, false);
    assert.equal(
      observed.run.coordinatorGeneration,
      owned.run.coordinatorGeneration,
    );
    assert.equal(observed.run.config.maxTimeHours, 2.5);
    await assert.rejects(
      observer.fail(run.scanId, "observer cannot fail its owner"),
      /current coordinator lease/,
    );
    const writer = spawn(python, [
      "-c",
      `import sqlite3, sys
connection = sqlite3.connect(sys.argv[1])
connection.execute("UPDATE deep_scan_runs SET updated_at = ? WHERE scan_id = ?", ("2000-01-01T00:00:00Z", sys.argv[2]))
connection.commit()
connection.execute("BEGIN IMMEDIATE")
print("locked", flush=True)
sys.stdin.read(1)
connection.rollback()`,
      path.join(fixtureRoot, "state", "workbench.sqlite3"),
      run.scanId,
    ]);
    await once(writer.stdout, "data");
    const heartbeat = store.heartbeatCoordinator({
      scanId: run.scanId,
      threadId,
    });
    let timeout;
    try {
      const renewed = await Promise.race([
        heartbeat,
        new Promise((_, reject) => {
          timeout = setTimeout(
            () => reject(new Error("heartbeat blocked by SQLite writer lock")),
            1_000,
          );
        }),
      ]);
      assert.equal(
        renewed.coordinatorGeneration,
        owned.run.coordinatorGeneration,
      );
      const lease = await readJson(
        run.scanDir,
        "artifacts",
        "deep_discovery",
        `coordinator-heartbeat-${owned.run.coordinatorGeneration}.json`,
      );
      assert.deepEqual(lease, {
        coordinatorGeneration: owned.run.coordinatorGeneration,
        updatedAt: renewed.updatedAt,
      });
    } finally {
      clearTimeout(timeout);
      const unlocked = once(writer, "exit");
      writer.stdin.end("x");
      await unlocked;
      await Promise.allSettled([heartbeat]);
    }
    const observedAfterLockedHeartbeat = await observer.claimCoordinator({
      scanId: run.scanId,
      threadId,
    });
    assert.equal(observedAfterLockedHeartbeat.acquired, false);
    assert.equal(
      observedAfterLockedHeartbeat.run.coordinatorGeneration,
      owned.run.coordinatorGeneration,
    );

    const first = await createDiscovery(store, run, "first", "succeeded");
    const second = await createDiscovery(store, run, "second", "succeeded");
    const late = await createDiscovery(store, run, "late", "running");
    if (replaceFailedReducer) {
      const retired = await createWorkerFixture(
        run,
        "retired-reducer",
        "dedup",
      );
      await store.claimDedup({
        ...retired,
        workerIds: [first.id, second.id],
      });
      await store.updateWorker({ ...retired, status: "running" });
      await store.updateWorker({
        ...retired,
        status: "failed",
        error: "Request blocked by cyberPolicy.",
      });
      const afterRetirement = await store.get(run.scanId, threadId);
      assert.equal(afterRetirement.status, "running");
      for (const workerId of [first.id, second.id]) {
        assert.equal(
          afterRetirement.persistedWorkers.find(
            (worker: { id: string }) => worker.id === workerId,
          )?.mergeState,
          "buffered",
          "a retired reducer must release every input for its replacement",
        );
      }
    }
    const reducer = await createWorkerFixture(run, "dedup-0001", "dedup");
    await writeJsonLine(reducer.resultPath, {
      schemaVersion: 1,
      consumedWorkerIds: [first.id, second.id],
      merges: [],
    });
    await store.claimDedup({
      ...reducer,
      workerIds: [first.id, second.id],
    });
    await store.updateWorker({
      ...reducer,
      status: "running",
      threadId: "fixture-reducer-thread",
    });

    const canonical = await createCanonicalFixture(run.scanDir);
    const stagedCandidateLedgerPath = path.join(
      reducer.artifactDir,
      "canonical",
      "candidate_ledger.jsonl",
    );
    await writePrivateFile(
      stagedCandidateLedgerPath,
      '{"candidate_id":"replacement"}\n',
    );
    const afterCommit = await store.commitDedup({
      id: reducer.id,
      scanId: run.scanId,
      newFindings: 0,
      resultManifestPath: reducer.resultPath,
      candidateLedgerPath: stagedCandidateLedgerPath,
    });
    assert.equal(afterCommit.status, "running");
    assert.equal(afterCommit.terminalReason, undefined);
    assert.equal(afterCommit.manifestPath, undefined);
    assert.equal(afterCommit.noNewStreak, 2);
    assert.equal(
      (await runWorkbench.mock.calls.at(-1)!.result).deepScan
        .canonicalArtifacts,
      null,
    );
    assert.equal(
      await readFile(canonical.candidateLedgerPath, "utf8"),
      '{"candidate_id":"replacement"}\n',
    );
    assert.equal(
      await readFile(stagedCandidateLedgerPath, "utf8"),
      '{"candidate_id":"replacement"}\n',
    );

    const acceptedLate = await store.updateWorker({
      ...late,
      status: "succeeded",
      resultManifestPath: late.resultPath,
    });
    assert.equal(acceptedLate.status, "succeeded");
    assert.equal(acceptedLate.mergeState, "buffered");
    assert.equal(acceptedLate.completionSequence, 3);

    const manifestPath = path.join(
      run.scanDir,
      "artifacts",
      "deep_discovery",
      "coordinator-manifest.json",
    );
    const stagedManifestPath = path.join(
      run.scanDir,
      "artifacts",
      "deep_discovery",
      "coordinator-manifest.generation-2.staged.json",
    );
    await writePrivateFile(
      stagedManifestPath,
      `${JSON.stringify({ status: "succeeded" })}\n`,
    );
    const finished = await store.finish({
      scanId: run.scanId,
      reason: "saturated",
      manifestPath,
      stagedManifestPath,
      omittedWorkerIds: [late.id],
    });
    assert.equal(finished.status, "succeeded");
    assert.equal(finished.terminalReason, "saturated");
    assert.equal(finished.manifestPath, manifestPath);

    const continued = await store.begin({
      targetPath,
      scope: ".",
      threadId: "deep-scan-store-continuation-thread",
      scanRoot,
    });
    assert.equal(continued.scanId, run.scanId);
    assert.equal(continued.status, "succeeded");
    assert.equal(continued.manifestPath, manifestPath);
    assert.equal(continued.config.maxTimeHours, 2.5);

    const replay = await store.finish({
      scanId: run.scanId,
      reason: "saturated",
      manifestPath,
      stagedManifestPath,
      omittedWorkerIds: [late.id],
    });
    assert.equal(replay.status, "succeeded");

    const differentManifestPath = path.join(
      run.scanDir,
      "artifacts",
      "deep_discovery",
      "different-manifest.json",
    );
    await writePrivateFile(differentManifestPath, "{}\n");
    await assert.rejects(
      store.finish({
        scanId: run.scanId,
        reason: "saturated",
        manifestPath: differentManifestPath,
        omittedWorkerIds: [late.id],
      }),
      /terminal state is immutable/,
    );
  } finally {
    await rm(fixtureRoot, { force: true, recursive: true });
  }
}

async function testExpiredDeadlineWithoutCompletedDiscoveryAgainstRealWorkbench() {
  const { fixtureRoot, targetPath, environment } = await createWorkbenchFixture(
    "deep-scan-store-zero-discovery-",
  );
  const codexHome = path.join(fixtureRoot, "codex-home");
  const threadId = "deep-scan-store-zero-discovery-thread";
  const runWorkbench = mock.fn(createWorkbenchRunner(environment, false));
  const store = new WorkbenchDeepScanStore(runWorkbench);

  try {
    await mkdir(path.join(codexHome, "codex-security"), { recursive: true });
    await writeFile(
      path.join(codexHome, "codex-security", "config.toml"),
      "[deep_scan]\nworkers = 1\nmax_discovery_runs = 3\nmax_time_hours = 1e-12\n",
    );

    const run = await store.begin({
      targetPath,
      scope: ".",
      threadId,
      scanRoot: path.join(fixtureRoot, "scans"),
    });
    assert.equal(run.config.maxTimeHours, 1e-12);
    const owned = await store.claimCoordinator({
      scanId: run.scanId,
      threadId,
    });
    assert.equal(owned.acquired, true);
    assert.equal(
      (await runWorkbench.mock.calls.at(-1)!.result).deepScan
        .canonicalArtifacts,
      null,
    );
    const canonical = await createCanonicalFixture(run.scanDir);
    const manifestPath = path.join(
      run.scanDir,
      "artifacts",
      "deep_discovery",
      "coordinator-manifest.json",
    );
    await writePrivateFile(
      manifestPath,
      '{"status":"succeeded","discoveryCount":0}\n',
    );

    const finished = await store.finish({
      scanId: run.scanId,
      reason: "capped",
      manifestPath,
      omittedWorkerIds: [],
    });
    assert.equal(finished.status, "succeeded");
    assert.equal(finished.terminalReason, "capped");
    assert.equal(finished.dispatchedCount, 0);
    assert.deepEqual(
      (await runWorkbench.mock.calls.at(-1)!.result).deepScan
        .canonicalArtifacts,
      canonical,
    );
    assert.equal(await readFile(canonical.candidateLedgerPath, "utf8"), "");
    assert.equal(
      await readFile(canonical.inScopeFilesPath, "utf8"),
      "fixture.py\n",
    );

    const observed = await new WorkbenchDeepScanStore(runWorkbench).get(
      run.scanId,
      threadId,
    );
    assert.equal(observed.status, "succeeded");
    assert.equal(observed.terminalReason, "capped");
    assert.deepEqual(
      (await runWorkbench.mock.calls.at(-1)!.result).deepScan
        .canonicalArtifacts,
      canonical,
    );
    assert.deepEqual(observed.persistedWorkers, []);
  } finally {
    await rm(fixtureRoot, { force: true, recursive: true });
  }
}

async function createDiscovery(
  store: import("../src/deep-scan/types.js").DeepScanStore,
  run: import("../src/deep-scan/types.js").DeepScanRunState,
  label: string,
  finalState: "running" | "succeeded",
) {
  const fixture = await createWorkerFixture(
    run,
    `discovery-${label}`,
    "discovery",
  );
  await writeFile(fixture.resultPath, "{}\n");
  if (finalState === "succeeded") {
    await store.updateWorker({ ...fixture, status: "queued" });
  }
  const started = { ...fixture, threadId: `fixture-${label}-thread` };
  await store.updateWorker({ ...started, status: "running" });
  if (finalState === "succeeded") {
    await store.updateWorker({
      ...started,
      status: "succeeded",
      resultManifestPath: fixture.resultPath,
    });
  }
  return started;
}

async function createWorkerFixture(
  run: import("../src/deep-scan/types.js").DeepScanRunState,
  label: string,
  kind: "discovery" | "dedup",
) {
  const root = path.join(run.scanDir, "artifacts", "deep_discovery", label);
  const artifactDir = path.join(root, "output");
  const promptPath = path.join(root, "prompt.md");
  await mkdir(artifactDir, { recursive: true });
  await writeFile(promptPath, "fixture prompt\n");
  return {
    id: randomUUID(),
    scanId: run.scanId,
    kind,
    artifactDir,
    promptPath,
    resultPath: path.join(artifactDir, "result.json"),
    attempt: 1,
  };
}

async function createCanonicalFixture(scanDir: string) {
  const paths = {
    inScopeFilesPath: path.join(
      scanDir,
      "artifacts",
      "02_discovery",
      "in_scope_files.txt",
    ),
    candidateLedgerPath: path.join(
      scanDir,
      "artifacts",
      "02_discovery",
      "candidate_ledger.jsonl",
    ),
  };
  await writePrivateFile(paths.inScopeFilesPath, "fixture.py\n");
  await writePrivateFile(paths.candidateLedgerPath, "");
  return paths;
}

async function writePrivateFile(filePath: string, content: string) {
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, content, { mode: 0o600 });
}

console.log("deep scan store integration tests passed");
