import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { WorkerTelemetryOptions } from "../src/deep-scan/types.js";
import { workerUsage } from "./deep_scan_worker_usage_assertions.ts";
import type { ScanDraftInput } from "../src/artifact-scan-draft.js";
import { readJson, writeJson } from "./support/json.ts";
import {
  iterationInputs,
  coordinatorFixture,
  FakeExecutor,
  immediateClock,
  runCoordinator,
  temporaryDirectories,
} from "./deep_scan_coordinator_fixture.ts";

try {
  await testResumeRepairsPreviouslyAcceptedEvidence(false);
  await testResumeRepairsPreviouslyAcceptedEvidence(true);
  await testResumeRepairsPreviouslyAcceptedEvidence(true, true);
} finally {
  await temporaryDirectories.cleanup();
}

async function testResumeRepairsPreviouslyAcceptedEvidence(
  completedIteration: boolean,
  withLaterBatch = false,
) {
  const { fixture, store } = await coordinatorFixture({
    workers: 1,
    stopAfterNoNew: 1,
    maxDiscoveryRuns: 1,
  });
  assert.equal(
    (
      await runCoordinator(
        fixture,
        store,
        new FakeExecutor({
          discoveryCandidateId: "accepted-finding",
        }),
      )
    )?.status,
    "succeeded",
  );
  for (const worker of [...store.workers.values()]) {
    if (!completedIteration && worker.kind === "dedup") {
      store.workers.delete(worker.id);
      continue;
    }
    const saved = await readJson(worker.resultManifestPath!);
    for (const finding of saved.findings) {
      delete finding.validation;
      if (withLaterBatch && worker.kind === "dedup") {
        // A pre-upgrade checkpoint can retain multiple source groups from one repair.
        const source = structuredClone(finding);
        const ids = ["first", "second"];
        finding.provenance.sourceFindingIds = ids;
        finding.provenance.sourceFindings = ids.map((id) => ({
          id,
          finding: source,
        }));
        finding.provenance.deepScanRepairGroups = ids.map((id, order) => ({
          order,
          sources: [id],
        }));
      }
    }
    await writeJson(worker.resultManifestPath!, saved);
    if (!completedIteration && worker.kind === "discovery")
      store.workers.set(worker.id, { ...worker, mergeState: "buffered" });
  }
  if (!completedIteration) {
    store.iterations = [];
  }
  const resetForResume = () => {
    store.run = {
      ...store.run,
      status: "running",
      terminalReason: undefined,
      manifestPath: undefined,
      config: { ...store.run.config, maxDiscoveryRuns: withLaterBatch ? 2 : 1 },
      noNewStreak: completedIteration && !withLaterBatch ? 1 : 0,
      persistedWorkers: structuredClone([...store.workers.values()]),
      persistedDedupInputs: store.iterations.flatMap(iterationInputs),
    };
  };
  resetForResume();
  const acceptedPaths = [...store.workers.values()].map(
    (worker) => worker.resultManifestPath!,
  );
  const acceptedBytes = await Promise.all(
    acceptedPaths.map((file) => readFile(file, "utf8")),
  );
  const evidenceAttempts = new Set<string>();
  let repairCalls = 0;
  const executor = Object.assign(new FakeExecutor(), {
    async repairFindingEvidence(
      prompt: string,
      cwd: string,
      _signal: AbortSignal,
      _schema: Record<string, unknown>,
      telemetry?: WorkerTelemetryOptions,
    ) {
      assert.ok(telemetry?.attemptId);
      assert.equal(
        telemetry.workerUsageDirectory,
        fixture.run.workerUsageDirectory,
      );
      evidenceAttempts.add(telemetry.attemptId);
      await telemetry.onThreadStarted?.(`evidence-${telemetry.attemptId}`);
      await telemetry.onUsage?.(workerUsage(1), "evidence-turn");
      assert.equal(
        cwd,
        join(fixture.run.scanDir, "artifacts", "deep_discovery"),
      );
      assert.match(prompt, /missing evidence/i);
      repairCalls++;
      if (repairCalls === 1) return "{}";
      const { finding, targetPath } = JSON.parse(prompt.split("\n")[1]!);
      assert.equal(targetPath, fixture.run.targetPath);
      return JSON.stringify({
        codeEvidence: finding.codeEvidence,
        rootCause: finding.rootCause.summary,
        attackPath: finding.attackPath,
        validation: {
          method: "Static analysis",
          summary: "The query reaches SQL execution.",
          evidence: "The query argument is unparameterized.",
        },
      });
    },
  });
  const published: ScanDraftInput[] = [];
  const terminal = await runCoordinator(fixture, store, executor, {
    run: store.run,
    retryDelaysMs: [1],
    clock: immediateClock,
    onComplete: async (draft) => void published.push(structuredClone(draft)),
  });
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(
    executor.discoveryCalls,
    withLaterBatch ? 1 : 0,
    "repair must honor the discovery cap",
  );
  assert.equal(repairCalls, withLaterBatch ? 3 : 2);
  assert.equal(evidenceAttempts.size, repairCalls);
  for (const attempt of evidenceAttempts) {
    const receipt = await readJson(
      join(fixture.run.workerUsageDirectory!, `${attempt}.json`),
    );
    assert.equal(receipt.kind, "evidence");
    assert.equal(receipt.outcome, "succeeded");
    assert.equal(receipt.threadId, `evidence-${attempt}`);
    assert.equal(receipt.turnId, "evidence-turn");
    assert.deepEqual(receipt.usage, workerUsage(1));
  }
  assert.equal(store.run.dispatchedCount, withLaterBatch ? 2 : 1);
  assert.equal(store.failureMessages.length, 0);
  assert.equal(published.length, 1);
  assert.ok(published[0].findings[0].validation);
  assert.equal(
    store.iterations.at(-1)!.workerIds.length,
    completedIteration && !withLaterBatch ? 0 : 1,
  );
  assert.deepEqual(
    await Promise.all(acceptedPaths.map((file) => readFile(file, "utf8"))),
    acceptedBytes,
  );

  resetForResume();
  const restarted = new FakeExecutor();
  const next = await runCoordinator(fixture, store, restarted, {
    run: store.run,
  });
  assert.equal(next?.status, "succeeded", next?.error);
  assert.equal(restarted.discoveryCalls, 0);
}
