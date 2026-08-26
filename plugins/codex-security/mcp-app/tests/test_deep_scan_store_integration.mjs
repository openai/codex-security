import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const execFileAsync = promisify(execFile);
const mcpAppRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const pluginRoot = path.resolve(mcpAppRoot, "..");
const workbenchPath = path.join(pluginRoot, "scripts", "workbench_db.py");

const bundle = await build({
  bundle: true,
  stdin: {
    contents: [
      'export { WorkbenchDeepScanStore } from "./src/deep-scan/store.ts";',
      'export { createScanArtifactContext } from "./src/artifact-context.ts";',
      'export { recordCodexSecurityScanDraftViaWorkbench } from "./src/artifact-scan-draft.ts";'
    ].join("\n"),
    resolveDir: mcpAppRoot
  },
  format: "esm",
  platform: "node",
  write: false
});
const {
  WorkbenchDeepScanStore,
  createScanArtifactContext,
  recordCodexSecurityScanDraftViaWorkbench,
} = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
);

await testReducerCommitAndFinishAgainstRealWorkbench();
await testExpiredDeadlineWithoutCompletedDiscoveryAgainstRealWorkbench();
await testLateParentDraftPreservesCheckpointWithoutOverwritingTerminalSeal();
await testRecoveredPublicationRejectsLateFailure();
await testNoopStoppedRefreshRetainsPublicationFailure();
await testConcurrentParentDraftsPreserveBothCheckpoints();

async function testRecoveredPublicationRejectsLateFailure() {
  const fixtureRoot = await mkdtemp(path.join(tmpdir(), "deep-scan-publication-failure-"));
  const targetPath = path.join(fixtureRoot, "target");
  const environment = {
    ...process.env,
    CODEX_HOME: path.join(fixtureRoot, "home"),
    CODEX_SECURITY_STATE_DIR: path.join(fixtureRoot, "state"),
  };
  const python = process.env.PYTHON?.trim() || "python3";
  const runWorkbench = async (args) => {
    const { stdout } = await execFileAsync(python, [workbenchPath, ...args], {
      cwd: pluginRoot, env: environment, timeout: 30_000, maxBuffer: 4 * 1024 * 1024,
    });
    return JSON.parse(stdout);
  };
  try {
    await mkdir(targetPath, { recursive: true });
    await writeFile(path.join(targetPath, "fixture.py"), "print('fixture')\n");
    const store = new WorkbenchDeepScanStore(runWorkbench);
    const { run } = await store.begin({
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
    await recordCodexSecurityScanDraftViaWorkbench(context, {
      scanId: run.scanId,
      complete: false,
      findings: [],
      coverage: {
        completeness: "partial",
        surfaces: [],
        explicitExclusions: [],
        deferred: [{
          candidateId: "publication-recovery-candidate",
          reason: "Publication recovery remains pending.",
          paths: ["fixture.py"],
        }],
      },
    }, runWorkbench);
    await runWorkbench([
      "cancel-scan", "--scan-id", run.scanId,
      "--thread-id", "publication-failure-owner",
    ]);
    assert.equal(
      (await store.get(run.scanId, "publication-failure-owner")).status,
      "canceled",
    );
    const message = "Saved result publication failed: stale fixture publication failure";
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
  const fixtureRoot = await mkdtemp(path.join(tmpdir(), "deep-scan-noop-publication-"));
  const targetPath = path.join(fixtureRoot, "target");
  const environment = {
    ...process.env,
    CODEX_HOME: path.join(fixtureRoot, "home"),
    CODEX_SECURITY_STATE_DIR: path.join(fixtureRoot, "state"),
  };
  const python = process.env.PYTHON?.trim() || "python3";
  const runWorkbench = async (args) => {
    const { stdout } = await execFileAsync(python, [workbenchPath, ...args], {
      cwd: pluginRoot, env: environment, timeout: 30_000, maxBuffer: 4 * 1024 * 1024,
    });
    return JSON.parse(stdout);
  };
  try {
    await mkdir(targetPath, { recursive: true });
    await writeFile(path.join(targetPath, "fixture.py"), "print('fixture')\n");
    const store = new WorkbenchDeepScanStore(runWorkbench);
    const { run } = await store.begin({
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
      "cancel-scan", "--scan-id", run.scanId,
      "--thread-id", "noop-publication-owner",
    ]);
    const message = "Saved result publication failed: fixture no-op publication failure";
    await store.recordStoppedPublicationFailure(
      run.scanId,
      message,
      claim.run.coordinatorGeneration,
    );
    await runWorkbench(["get-scan", "--scan-id", run.scanId]);
    assert.equal(
      (await new WorkbenchDeepScanStore(runWorkbench).get(
        run.scanId,
        "noop-publication-owner",
      )).error,
      message,
      "a no-op retained-result refresh must keep its publication failure",
    );
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
}

async function testConcurrentParentDraftsPreserveBothCheckpoints() {
  const fixtureRoot = await mkdtemp(path.join(tmpdir(), "scan-draft-concurrency-integration-"));
  const targetPath = path.join(fixtureRoot, "target");
  const environment = {
    ...process.env,
    CODEX_HOME: path.join(fixtureRoot, "home"),
    CODEX_SECURITY_STATE_DIR: path.join(fixtureRoot, "state")
  };
  const python = process.env.PYTHON?.trim() || "python3";
  const rawRunWorkbench = async (args) => {
    const { stdout } = await execFileAsync(python, [workbenchPath, ...args], {
      cwd: pluginRoot, env: environment, timeout: 30_000, maxBuffer: 4 * 1024 * 1024
    });
    return JSON.parse(stdout);
  };
  let stagedWrites = 0;
  let releaseInitialWrites;
  const initialWritesReady = new Promise((resolve) => { releaseInitialWrites = resolve; });
  const runWorkbench = async (args) => {
    if (args[0] === "write-scan-draft" && ++stagedWrites <= 2) {
      if (stagedWrites === 2) releaseInitialWrites();
      await initialWritesReady;
    }
    return rawRunWorkbench(args);
  };
  try {
    await mkdir(targetPath, { recursive: true });
    await writeFile(path.join(targetPath, "fixture.py"), "print('fixture')\n");
    const { run } = await new WorkbenchDeepScanStore(rawRunWorkbench).begin({
      targetPath, scope: ".", threadId: "concurrent-draft-owner", scanRoot: path.join(fixtureRoot, "scans")
    });
    const context = await createScanArtifactContext(run.scanId, runWorkbench, { requireRunning: true });
    const checkpoint = (candidateId) => ({
      scanId: run.scanId,
      complete: false,
      findings: [],
      coverage: {
        completeness: "partial", surfaces: [], explicitExclusions: [],
        deferred: [{ candidateId, reason: "Independent review remains pending.", paths: ["fixture.py"] }]
      }
    });

    await Promise.all([
      recordCodexSecurityScanDraftViaWorkbench(
        context,
        checkpoint("concurrent-a"),
        runWorkbench,
      ),
      recordCodexSecurityScanDraftViaWorkbench(
        context,
        checkpoint("concurrent-b"),
        runWorkbench,
      )
    ]);
    assert.equal(stagedWrites, 3, "the stale writer retries after the host rejects its digest");

    const coverage = JSON.parse(await readFile(path.join(run.scanDir, "coverage.json"), "utf8"));
    assert.deepEqual(
      new Set(coverage.deferred.map((item) => item.candidateId)),
      new Set(["concurrent-a", "concurrent-b"]),
      "overlapping canonical writes must merge every immutable checkpoint",
    );
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
}

async function testLateParentDraftPreservesCheckpointWithoutOverwritingTerminalSeal() {
  const fixtureRoot = await mkdtemp(path.join(tmpdir(), "scan-draft-cancel-integration-"));
  const targetPath = path.join(fixtureRoot, "target");
  const environment = {
    ...process.env,
    CODEX_HOME: path.join(fixtureRoot, "home"),
    CODEX_SECURITY_STATE_DIR: path.join(fixtureRoot, "state")
  };
  const python = process.env.PYTHON?.trim() || "python3";
  const runWorkbench = async (args) => {
    const { stdout } = await execFileAsync(python, [workbenchPath, ...args], {
      cwd: pluginRoot, env: environment, timeout: 30_000, maxBuffer: 4 * 1024 * 1024
    });
    return JSON.parse(stdout);
  };
  try {
    await mkdir(targetPath, { recursive: true });
    await writeFile(path.join(targetPath, "fixture.py"), "print('fixture')\n");
    const { run } = await new WorkbenchDeepScanStore(runWorkbench).begin({
      targetPath, scope: ".", threadId: "checkpoint-owner", scanRoot: path.join(fixtureRoot, "scans")
    });
    const context = await createScanArtifactContext(run.scanId, runWorkbench, { requireRunning: true });
    const checkpoint = (candidateId) => ({
      scanId: run.scanId,
      complete: false,
      findings: [],
      coverage: {
        completeness: "partial", surfaces: [], explicitExclusions: [],
        deferred: [{ candidateId, reason: "Source validation remains pending.", paths: ["fixture.py"] }]
      }
    });
    await recordCodexSecurityScanDraftViaWorkbench(
      context,
      checkpoint("early-result"),
      runWorkbench,
    );
    await runWorkbench(["cancel-scan", "--scan-id", run.scanId, "--thread-id", "checkpoint-owner"]);
    const manifestPath = path.join(run.scanDir, "scan-manifest.json");
    const sealed = await readFile(manifestPath, "utf8");
    assert.equal(JSON.parse(sealed).scan.status, "canceled");

    await assert.rejects(
      recordCodexSecurityScanDraftViaWorkbench(
        context,
        checkpoint("late-result"),
        runWorkbench,
      ),
      /not running|stopped|terminal/i,
    );
    assert.equal(await readFile(manifestPath, "utf8"), sealed, "a stale writer cannot overwrite a terminal seal");
    const stopped = await runWorkbench(["get-scan", "--scan-id", run.scanId]);
    assert.equal(stopped.scan.progress.status, "canceled");
    const coverage = JSON.parse(await readFile(path.join(run.scanDir, "coverage.json"), "utf8"));
    const pending = coverage.deferred.map((item) => item.candidateId);
    assert.ok(pending.includes("early-result"));
    assert.ok(
      !pending.includes("late-result"),
      "a checkpoint written after cancellation must not change retained results",
    );
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
}

async function testReducerCommitAndFinishAgainstRealWorkbench() {
  const fixtureRoot = await mkdtemp(path.join(tmpdir(), "deep-scan-store-integration-"));
  const targetPath = path.join(fixtureRoot, "target");
  const scanRoot = path.join(fixtureRoot, "scans");
  const stateDir = path.join(fixtureRoot, "state");
  const codexHome = path.join(fixtureRoot, "codex-home");
  const threadId = "deep-scan-store-integration-thread";
  const environment = {
    ...process.env,
    CODEX_HOME: codexHome,
    CODEX_SECURITY_STATE_DIR: stateDir
  };
  const python = process.env.PYTHON?.trim() || "python3";
  const runWorkbench = async (args) => {
    const { stdout } = await execFileAsync(python, [workbenchPath, ...args], {
      cwd: pluginRoot,
      env: environment,
      maxBuffer: 4 * 1024 * 1024,
      timeout: 30_000
    });
    return JSON.parse(stdout);
  };
  const store = new WorkbenchDeepScanStore(runWorkbench);

  try {
    await Promise.all([
      mkdir(targetPath, { recursive: true }),
      mkdir(scanRoot, { recursive: true }),
      mkdir(stateDir, { recursive: true }),
      mkdir(path.join(codexHome, "codex-security"), { recursive: true })
    ]);
    await writeFile(path.join(targetPath, "fixture.py"), "print('fixture')\n");
    await writeFile(
      path.join(codexHome, "codex-security", "config.toml"),
      [
        "[deep_scan]",
        "workers = 2",
        "subagents = 0",
        "stop_after_no_new = 2",
        "max_discovery_runs = 3",
        "max_time_hours = 2.5",
        ""
      ].join("\n")
    );

    const begun = await store.begin({
      targetPath,
      scope: ".",
      threadId,
      scanRoot
    });
    assert.equal(begun.shouldStart, true);
    const { run } = begun;
    assert.equal(typeof run.createdAt, "string");
    assert.equal(run.config.maxTimeHours, 2.5);
    const owned = await store.claimCoordinator({ scanId: run.scanId, threadId });
    assert.equal(owned.run.coordinatorGeneration, 2);
    const observer = new WorkbenchDeepScanStore(runWorkbench);
    const joined = await observer.begin({ scanId: run.scanId, threadId, scanRoot });
    const observed = await observer.claimCoordinator({ scanId: joined.run.scanId, threadId });
    assert.equal(observed.acquired, false);
    assert.equal(observed.run.coordinatorGeneration, owned.run.coordinatorGeneration);
    assert.equal(observed.run.config.maxTimeHours, 2.5);
    await assert.rejects(observer.fail(run.scanId, "observer cannot fail its owner"), /current coordinator lease/);
    const writer = spawn(python, [
      "-c",
      [
        "import sqlite3, sys",
        "connection = sqlite3.connect(sys.argv[1])",
        "connection.execute(\"UPDATE deep_scan_runs SET updated_at = ? WHERE scan_id = ?\", (\"2000-01-01T00:00:00Z\", sys.argv[2]))",
        "connection.commit()",
        "connection.execute(\"BEGIN IMMEDIATE\")",
        "print(\"locked\", flush=True)",
        "sys.stdin.read(1)",
        "connection.rollback()"
      ].join("\n"),
      path.join(stateDir, "workbench.sqlite3"),
      run.scanId
    ]);
    await once(writer.stdout, "data");
    const heartbeat = store.heartbeatCoordinator({ scanId: run.scanId, threadId });
    let timeout;
    try {
      const renewed = await Promise.race([
        heartbeat,
        new Promise((_, reject) => {
          timeout = setTimeout(() => reject(new Error("heartbeat blocked by SQLite writer lock")), 1_000);
        })
      ]);
      assert.equal(renewed.coordinatorGeneration, owned.run.coordinatorGeneration);
      const lease = JSON.parse(await readFile(path.join(
        run.scanDir,
        "artifacts",
        "deep_discovery",
        `coordinator-heartbeat-${owned.run.coordinatorGeneration}.json`
      ), "utf8"));
      assert.deepEqual(lease, {
        coordinatorGeneration: owned.run.coordinatorGeneration,
        updatedAt: renewed.updatedAt
      });
    } finally {
      clearTimeout(timeout);
      const unlocked = once(writer, "exit");
      writer.stdin.end("x");
      await unlocked;
      await Promise.allSettled([heartbeat]);
    }
    const observedAfterLockedHeartbeat = await observer.claimCoordinator({ scanId: run.scanId, threadId });
    assert.equal(observedAfterLockedHeartbeat.acquired, false);
    assert.equal(observedAfterLockedHeartbeat.run.coordinatorGeneration, owned.run.coordinatorGeneration);

    const first = await createSucceededDiscovery(store, run, "first");
    const second = await createSucceededDiscovery(store, run, "second");
    const late = await createRunningDiscovery(store, run, "late");
    const reducer = await createReducerFixture(run.scanDir, [first.id, second.id]);
    await store.claimDedup({
      id: reducer.id,
      scanId: run.scanId,
      workerIds: [first.id, second.id],
      promptPath: reducer.promptPath,
      artifactDir: reducer.artifactDir
    });
    await store.updateWorker({
      id: reducer.id,
      scanId: run.scanId,
      kind: "dedup",
      status: "running",
      promptPath: reducer.promptPath,
      artifactDir: reducer.artifactDir,
      attempt: 1,
      threadId: "fixture-reducer-thread"
    });

    const canonical = await createCanonicalFixture(run.scanDir);
    const stagedCandidateLedgerPath = path.join(
      reducer.artifactDir,
      "canonical",
      "candidate_ledger.jsonl"
    );
    await writePrivateFile(stagedCandidateLedgerPath, '{"candidate_id":"replacement"}\n');
    const afterCommit = await store.commitDedup({
      id: reducer.id,
      scanId: run.scanId,
      newFindings: 0,
      resultManifestPath: reducer.resultPath,
      candidateLedgerPath: stagedCandidateLedgerPath
    });
    assert.equal(afterCommit.status, "running");
    assert.equal(afterCommit.terminalReason, undefined);
    assert.equal(afterCommit.manifestPath, undefined);
    assert.equal(afterCommit.noNewStreak, 2);
    assert.equal(afterCommit.canonicalArtifacts, undefined);
    assert.equal(
      await readFile(canonical.candidateLedgerPath, "utf8"),
      '{"candidate_id":"replacement"}\n'
    );
    assert.equal(
      await readFile(stagedCandidateLedgerPath, "utf8"),
      '{"candidate_id":"replacement"}\n'
    );

    const acceptedLate = await store.updateWorker({
      id: late.id,
      scanId: run.scanId,
      kind: "discovery",
      status: "succeeded",
      promptPath: late.promptPath,
      artifactDir: late.artifactDir,
      attempt: 1,
      threadId: "fixture-late-thread",
      resultManifestPath: late.resultPath
    });
    assert.equal(acceptedLate.status, "succeeded");
    assert.equal(acceptedLate.mergeState, "buffered");
    assert.equal(acceptedLate.completionSequence, 3);

    const manifestPath = path.join(
      run.scanDir,
      "artifacts",
      "deep_discovery",
      "coordinator-manifest.json"
    );
    const stagedManifestPath = path.join(
      run.scanDir,
      "artifacts",
      "deep_discovery",
      "coordinator-manifest.generation-2.staged.json"
    );
    await writePrivateFile(
      stagedManifestPath,
      `${JSON.stringify({ status: "succeeded" })}\n`
    );
    const finished = await store.finish({
      scanId: run.scanId,
      reason: "saturated",
      manifestPath,
      stagedManifestPath,
      omittedWorkerIds: [late.id]
    });
    assert.equal(finished.status, "succeeded");
    assert.equal(finished.terminalReason, "saturated");
    assert.equal(finished.manifestPath, manifestPath);

    const continued = await store.begin({
      targetPath,
      scope: ".",
      threadId: "deep-scan-store-continuation-thread",
      scanRoot
    });
    assert.equal(continued.shouldStart, false);
    assert.equal(continued.run.scanId, run.scanId);
    assert.equal(continued.run.status, "succeeded");
    assert.equal(continued.run.manifestPath, manifestPath);
    assert.equal(continued.run.config.maxTimeHours, 2.5);

    const replay = await store.finish({
      scanId: run.scanId,
      reason: "saturated",
      manifestPath,
      stagedManifestPath,
      omittedWorkerIds: [late.id]
    });
    assert.equal(replay.status, "succeeded");

    const differentManifestPath = path.join(
      run.scanDir,
      "artifacts",
      "deep_discovery",
      "different-manifest.json"
    );
    await writePrivateFile(differentManifestPath, "{}\n");
    await assert.rejects(
      store.finish({
        scanId: run.scanId,
        reason: "saturated",
        manifestPath: differentManifestPath,
        omittedWorkerIds: [late.id]
      }),
      /terminal state is immutable/
    );
  } finally {
    await rm(fixtureRoot, { force: true, recursive: true });
  }
}

async function testExpiredDeadlineWithoutCompletedDiscoveryAgainstRealWorkbench() {
  const fixtureRoot = await mkdtemp(path.join(tmpdir(), "deep-scan-store-zero-discovery-"));
  const targetPath = path.join(fixtureRoot, "target");
  const scanRoot = path.join(fixtureRoot, "scans");
  const stateDir = path.join(fixtureRoot, "state");
  const codexHome = path.join(fixtureRoot, "codex-home");
  const threadId = "deep-scan-store-zero-discovery-thread";
  const environment = {
    ...process.env,
    CODEX_HOME: codexHome,
    CODEX_SECURITY_STATE_DIR: stateDir
  };
  const python = process.env.PYTHON?.trim() || "python3";
  const runWorkbench = async (args) => {
    const { stdout } = await execFileAsync(python, [workbenchPath, ...args], {
      cwd: pluginRoot,
      env: environment
    });
    return JSON.parse(stdout);
  };
  const store = new WorkbenchDeepScanStore(runWorkbench);

  try {
    await Promise.all([
      mkdir(targetPath, { recursive: true }),
      mkdir(scanRoot, { recursive: true }),
      mkdir(stateDir, { recursive: true }),
      mkdir(path.join(codexHome, "codex-security"), { recursive: true })
    ]);
    await writeFile(path.join(targetPath, "fixture.py"), "print('fixture')\n");
    await writeFile(
      path.join(codexHome, "codex-security", "config.toml"),
      "[deep_scan]\nworkers = 1\nmax_discovery_runs = 3\nmax_time_hours = 1e-12\n"
    );

    const { run } = await store.begin({ targetPath, scope: ".", threadId, scanRoot });
    assert.equal(run.config.maxTimeHours, 1e-12);
    const owned = await store.claimCoordinator({ scanId: run.scanId, threadId });
    assert.equal(owned.acquired, true);
    assert.equal(owned.run.canonicalArtifacts, undefined);
    const canonical = await createCanonicalFixture(run.scanDir);
    const manifestPath = path.join(
      run.scanDir,
      "artifacts",
      "deep_discovery",
      "coordinator-manifest.json"
    );
    await writePrivateFile(manifestPath, '{"status":"succeeded","discoveryCount":0}\n');

    const finished = await store.finish({
      scanId: run.scanId,
      reason: "capped",
      manifestPath,
      omittedWorkerIds: []
    });
    assert.equal(finished.status, "succeeded");
    assert.equal(finished.terminalReason, "capped");
    assert.equal(finished.dispatchedCount, 0);
    assert.deepEqual(finished.canonicalArtifacts, canonical);
    assert.equal(await readFile(canonical.candidateLedgerPath, "utf8"), "");
    assert.equal(await readFile(canonical.inScopeFilesPath, "utf8"), "fixture.py\n");

    const observed = await new WorkbenchDeepScanStore(runWorkbench).get(run.scanId, threadId);
    assert.equal(observed.status, "succeeded");
    assert.equal(observed.terminalReason, "capped");
    assert.deepEqual(observed.canonicalArtifacts, canonical);
    assert.deepEqual(observed.persistedWorkers, []);
  } finally {
    await rm(fixtureRoot, { force: true, recursive: true });
  }
}

async function createSucceededDiscovery(store, run, label) {
  const fixture = await createWorkerFixture(run.scanDir, `discovery-${label}`);
  await store.updateWorker({
    id: fixture.id,
    scanId: run.scanId,
    kind: "discovery",
    status: "queued",
    promptPath: fixture.promptPath,
    artifactDir: fixture.artifactDir,
    attempt: 1
  });
  await store.updateWorker({
    id: fixture.id,
    scanId: run.scanId,
    kind: "discovery",
    status: "running",
    promptPath: fixture.promptPath,
    artifactDir: fixture.artifactDir,
    attempt: 1,
    threadId: `fixture-${label}-thread`
  });
  const persisted = await store.updateWorker({
    id: fixture.id,
    scanId: run.scanId,
    kind: "discovery",
    status: "succeeded",
    promptPath: fixture.promptPath,
    artifactDir: fixture.artifactDir,
    attempt: 1,
    threadId: `fixture-${label}-thread`,
    resultManifestPath: fixture.resultPath
  });
  return { ...fixture, ...persisted };
}

async function createRunningDiscovery(store, run, label) {
  const fixture = await createWorkerFixture(run.scanDir, `discovery-${label}`);
  await store.updateWorker({
    id: fixture.id,
    scanId: run.scanId,
    kind: "discovery",
    status: "running",
    promptPath: fixture.promptPath,
    artifactDir: fixture.artifactDir,
    attempt: 1,
    threadId: `fixture-${label}-thread`
  });
  return fixture;
}

async function createReducerFixture(scanDir, workerIds) {
  const fixture = await createWorkerFixture(scanDir, "dedup-0001");
  await writeFile(
    fixture.resultPath,
    `${JSON.stringify({ schemaVersion: 1, consumedWorkerIds: workerIds, merges: [] })}\n`
  );
  return fixture;
}

async function createWorkerFixture(scanDir, label) {
  const root = path.join(scanDir, "artifacts", "deep_discovery", label);
  const artifactDir = path.join(root, "output");
  const promptPath = path.join(root, "prompt.md");
  const resultPath = path.join(artifactDir, "result.json");
  await mkdir(artifactDir, { recursive: true });
  await Promise.all([
    writeFile(promptPath, "fixture prompt\n"),
    writeFile(resultPath, "{}\n")
  ]);
  return { id: randomUUID(), artifactDir, promptPath, resultPath };
}

async function createCanonicalFixture(scanDir) {
  const paths = {
    inScopeFilesPath: path.join(
      scanDir,
      "artifacts",
      "02_discovery",
      "in_scope_files.txt"
    ),
    candidateLedgerPath: path.join(
      scanDir,
      "artifacts",
      "02_discovery",
      "candidate_ledger.jsonl"
    )
  };
  await Promise.all([
    writePrivateFile(paths.inScopeFilesPath, "fixture.py\n"),
    writePrivateFile(paths.candidateLedgerPath, "")
  ]);
  return paths;
}

async function writePrivateFile(filePath, content) {
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, content, { mode: 0o600 });
}

console.log("deep scan store integration tests passed");
