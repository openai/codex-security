import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

export async function testCheckpointResume({
  DeepScanCoordinator, FakeStore, FakeExecutor, fixtureRun,
  standardScanDraft, immediateClock, deferred, eventually
}) {
  const bundle = await build({
    bundle: true,
    entryPoints: [fileURLToPath(new URL("../src/artifact-scan-draft.ts", import.meta.url))],
    format: "esm",
    platform: "node",
    write: false
  });
  const { saveScanDraftCheckpoint, recordCodexSecurityWorkerScanDraft } = await import(
    `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
  );

  for (const { previousAttempt, interruptRetry } of [
    { previousAttempt: 0, interruptRetry: false },
    { previousAttempt: 3, interruptRetry: false },
    { previousAttempt: 3, interruptRetry: true }
  ]) {
    const fixture = await fixtureRun({
      workers: 1, subagents: 0, stopAfterNoNew: 2, maxDiscoveryRuns: 4
    });
    const store = new FakeStore(fixture.run);
    const updateWorker = store.updateWorker.bind(store);
    store.updateWorker = async (update) => {
      const existing = store.workers.get(update.id);
      if (existing) {
        assert.equal(update.promptPath, existing.promptPath, "registered worker prompt paths are immutable");
        assert.equal(update.artifactDir, existing.artifactDir, "registered worker artifact paths are immutable");
      }
      return await updateWorker(update);
    };
    store.blockDedupCommitResponse = true;
    const original = new DeepScanCoordinator({
      run: fixture.run, store,
      executor: new FakeExecutor({ blockDiscoveryAfterCalls: 2, dedupNewFindings: [0] }),
      pluginRoot: fixture.pluginRoot, clock: immediateClock
    });
    original.start();
    await store.dedupCommitPersisted.promise;
    original.cancel("mcp_transport_closed");
    store.releaseDedupCommitResponse();
    await original.settled();
    assert.equal(store.run.noNewStreak, 2);
    assert.equal(store.run.status, "running");
    store.workers = new Map([...store.workers].filter(([, worker]) => worker.status === "succeeded"));

    const continuations = [];
    const oldPrompts = new Map();
    for (const sequence of [3, 4]) {
      const id = randomUUID();
      const label = `discovery-${String(sequence).padStart(4, "0")}`;
      const workerRoot = path.join(fixture.run.scanDir, "artifacts", "deep_discovery", "workers", label);
      const artifactDir = path.join(workerRoot, "output");
      const promptPath = path.join(workerRoot, "prompt.md");
      await mkdir(artifactDir, { recursive: true });
      await writeFile(promptPath, `Original saved prompt for ${label}.\n`);
      oldPrompts.set(promptPath, await readFile(promptPath, "utf8"));
      const candidateId = `${label}-pending`;
      const pending = standardScanDraft(fixture.run.scanId, candidateId, id).findings[0];
      const context = {
        root: artifactDir, repoRoot: fixture.run.targetPath,
        layout: "worker", scanId: fixture.run.scanId, scope: "."
      };
      await saveScanDraftCheckpoint(context, {
        scanId: fixture.run.scanId, complete: false, findings: [],
        coverage: {
          completeness: "partial",
          reviewedFiles: ["reviewed.js"],
          surfaces: [{ label: "Pending validation", disposition: "needs_follow_up", candidateId }],
          explicitExclusions: [],
          deferred: [{ candidateId, reason: "Complete the saved validation.", finding: pending }]
        }
      });
      const worker = {
        id, kind: "discovery", status: "queued", promptPath, artifactDir,
        attempt: previousAttempt, mergeState: "none"
      };
      store.workers.set(id, worker);
      continuations.push({ worker, context, candidateId, started: deferred(), gate: deferred() });
    }
    store.run = {
      ...store.run, coordinatorGeneration: 2, dispatchedCount: 4,
      persistedWorkers: [...store.workers.values()].map((worker) => structuredClone(worker)),
      persistedDedupInputs: store.dedupClaims.flatMap((claim) => (
        claim.workerIds.map((discoveryWorkerId, inputOrder) => ({
          dedupWorkerId: claim.id, discoveryWorkerId, inputOrder
        }))
      ))
    };
    const calls = new Map();
    const delays = [];
    const backoffStarted = deferred();
    const reducerExecutor = new FakeExecutor({ dedupNewFindings: [0, 0] });
    const executor = {
      async run(request) {
        if (request.kind !== "discovery") return await reducerExecutor.run(request);
        const saved = continuations.find(({ worker }) => worker.id === request.artifactContext.workerId);
        assert.ok(saved, "resume must dispatch the queued logical owner before any new worker");
        assert.equal(request.workingDirectory, saved.worker.artifactDir);
        assert.equal(request.artifactContext.root, saved.worker.artifactDir);
        const count = (calls.get(saved.worker.id) ?? 0) + 1;
        calls.set(saved.worker.id, count);
        const repaired = previousAttempt > 0 && saved === continuations[0] && count > 1;
        assert.equal(request.promptPath, path.join(
          path.dirname(saved.worker.artifactDir), "prompts",
          `attempt-${String(previousAttempt + (repaired ? 2 : 1)).padStart(2, "0")}.md`
        ));
        const prompt = await readFile(request.promptPath, "utf8");
        assert.ok(prompt.includes(fixture.run.scanId), "validation repair must retain the child scan binding");
        assert.ok(prompt.includes(JSON.stringify(saved.worker.id)));
        assert.ok(prompt.includes(JSON.stringify(path.join(saved.worker.artifactDir, "checkpoint-head.json"))));
        const checkpointRoot = repaired
          ? path.join(path.dirname(saved.worker.artifactDir), "attempts", `attempt-${String(previousAttempt + 1).padStart(2, "0")}`)
          : saved.worker.artifactDir;
        const head = JSON.parse(await readFile(path.join(checkpointRoot, "checkpoint-head.json"), "utf8"));
        const checkpoint = JSON.parse(await readFile(path.join(checkpointRoot, "checkpoints", head.checkpoint), "utf8"));
        assert.equal(checkpoint.coverage.deferred[0].candidateId, saved.candidateId);
        assert.equal(checkpoint.coverage.deferred[0].finding.provenance.workerId, saved.worker.id);
        assert.deepEqual(checkpoint.coverage.reviewedFiles, ["reviewed.js"]);
        await request.onThreadStarted?.(request.resumeThreadId ?? randomUUID());
        if (previousAttempt > 0 && saved === continuations[0] && count === 1) {
          await recordCodexSecurityWorkerScanDraft(saved.context, checkpoint);
          return { finalResponse: "Only saved the partial checkpoint." };
        }
        saved.started.resolve();
        await saved.gate.promise;
        await recordCodexSecurityWorkerScanDraft(saved.context, {
          scanId: fixture.run.scanId, complete: true, findings: [],
          coverage: {
            completeness: "complete", reviewedFiles: ["remaining.js"],
            surfaces: [{ label: "Validated saved candidate", disposition: "rejected", candidateId: saved.candidateId }],
            explicitExclusions: [], deferred: []
          }
        });
        const result = JSON.parse(await readFile(path.join(saved.worker.artifactDir, "result.json"), "utf8"));
        assert.equal(result.complete, true);
        assert.equal(result.coverage.completeness, "complete");
        assert.deepEqual(result.coverage.deferred, []);
        assert.deepEqual(new Set(result.coverage.reviewedFiles), new Set(["reviewed.js", "remaining.js"]));
        return { finalResponse: "Saved validation completed." };
      }
    };
    const completedDrafts = [];
    const coordinatorOptions = {
      run: store.run, store, executor, pluginRoot: fixture.pluginRoot,
      clock: {
        now: immediateClock.now,
        sleep: async (delay, signal) => {
          delays.push(delay);
          if (interruptRetry && delays.length === 1) {
            backoffStarted.resolve();
            await new Promise((resolve) => signal.addEventListener("abort", resolve, { once: true }));
            throw new DOMException("The coordinator stopped during retry backoff.", "AbortError");
          }
        }
      },
      random: () => 0, retryDelaysMs: [1],
      onComplete: async (draft) => completedDrafts.push(draft)
    };
    let coordinator = new DeepScanCoordinator(coordinatorOptions);
    coordinator.start();
    if (interruptRetry) {
      await Promise.race([
        backoffStarted.promise,
        coordinator.settled().then((terminal) => assert.fail(`Continuation ended before retry: ${terminal.error}`))
      ]);
      const interrupted = store.workers.get(continuations[0].worker.id);
      assert.equal(interrupted.attempt, previousAttempt + 1);
      assert.equal(interrupted.completionSequence, undefined);
      assert.equal(store.run.noNewStreak, 2);
      coordinator.cancel("mcp_transport_closed");
      await coordinator.settled();
      assert.equal(store.run.status, "running");
      await assert.rejects(readFile(path.join(
        path.dirname(interrupted.artifactDir), "prompts",
        `attempt-${String(previousAttempt + 2).padStart(2, "0")}.md`
      )), { code: "ENOENT" }, "backoff must not create the next prompt before reserving its attempt");
      for (const { worker } of continuations) {
        const persisted = store.workers.get(worker.id);
        store.workers.set(worker.id, { ...persisted, status: "queued" });
      }
      store.run = {
        ...store.run, coordinatorGeneration: store.run.coordinatorGeneration + 1,
        persistedWorkers: [...store.workers.values()].map((worker) => structuredClone(worker))
      };
      coordinator = new DeepScanCoordinator({ ...coordinatorOptions, run: store.run });
      coordinator.start();
    }
    await Promise.race([
      continuations[0].started.promise,
      coordinator.settled().then((terminal) => assert.fail(`Continuation ended before starting: ${terminal.error}`))
    ]);
    assert.equal(store.run.dispatchedCount, 4, "queued units already consume the configured cap");
    assert.equal(store.run.noNewStreak, 2, "incomplete checkpoints are not accepted review passes");
    assert.equal(store.workers.get(continuations[0].worker.id).completionSequence, undefined);
    assert.equal(store.workers.get(continuations[1].worker.id).status, "queued");
    continuations[0].gate.resolve();
    await continuations[1].started.promise;
    await eventually(() => store.run.noNewStreak === 3);
    assert.equal(coordinator.snapshot().status, "running", "saturation must wait for the active inherited owner");
    assert.equal(store.workers.get(continuations[1].worker.id).status, "running");
    continuations[1].gate.resolve();
    const terminal = await coordinator.wait(undefined, 5_000);
    assert.equal(terminal?.status, "succeeded", terminal?.error);
    assert.equal(terminal.terminalReason, "saturated");
    assert.equal(terminal.dispatchedCount, 4);
    assert.equal(calls.size, 2, "no new random discovery may exceed the cap");
    assert.equal(store.workers.get(continuations[0].worker.id).attempt, previousAttempt + (previousAttempt > 0 ? 2 : 1));
    assert.equal(store.workers.get(continuations[1].worker.id).attempt, previousAttempt + 1);
    assert.deepEqual(delays, previousAttempt > 0 ? [1] : []);
    assert.deepEqual(completedDrafts[0].coverage.deferred, []);
    assert.equal(store.run.noNewStreak, 4);
    for (const { worker } of continuations) {
      assert.equal(store.workers.get(worker.id).status, "succeeded");
      assert.equal(store.workers.get(worker.id).mergeState, "merged");
      assert.equal(store.workers.get(worker.id).promptPath, worker.promptPath);
      assert.ok(store.dedupClaims.some((claim) => claim.workerIds.includes(worker.id)));
    }
    for (const [promptPath, contents] of oldPrompts) {
      assert.equal(await readFile(promptPath, "utf8"), contents);
    }
  }
}

export async function testResumedDiscoveryDeadlines({
  DeepScanCoordinator, FakeStore, FakeExecutor, fixtureRun, immediateClock, eventually
}) {
  for (const args of [[], [true], [false, 2.5], [true, 96], [true, 2.5, true]]) {
    await testResumedDiscoveryDeadlineUsesPersistedCreationTime(...args);
  }

  async function testResumedDiscoveryDeadlineUsesPersistedCreationTime(
    alreadyExpired = false,
    maxTimeHours,
    restoreQueued = false
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
    const savedCheckpoints = new Map();
    if (restoreQueued) {
      for (const worker of store.workers.values()) {
        if (worker.kind !== "discovery" || worker.status !== "canceled") continue;
        worker.status = "queued";
        const checkpoint = path.join(worker.artifactDir, "checkpoints", "accepted.json");
        const contents = JSON.stringify({ scanId: store.run.scanId, complete: false, findings: [] });
        await mkdir(path.dirname(checkpoint), { recursive: true });
        await writeFile(checkpoint, contents);
        savedCheckpoints.set(checkpoint, contents);
      }
      assert.ok(savedCheckpoints.size > 0);
      const claimDedup = store.claimDedup.bind(store);
      store.claimDedup = async (input) => {
        if (input.workerIds.length === 1) {
          assert.equal(
            [...store.workers.values()].some((worker) => (
              worker.kind === "discovery" && ["queued", "running"].includes(worker.status)
            )),
            false,
            "The workbench permits the final singleton reducer only after discoveries settle."
          );
        }
        return await claimDedup(input);
      };
      const finish = store.finish.bind(store);
      store.finish = async (input) => {
        assert.equal(
          [...store.workers.values()].some((worker) => ["queued", "running"].includes(worker.status)),
          false,
          "The workbench requires restored workers to settle before finishing Deep Scan."
        );
        return await finish(input);
      };
    }
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
    for (const [checkpoint, contents] of savedCheckpoints) {
      assert.equal(await readFile(checkpoint, "utf8"), contents);
    }
  }
}
