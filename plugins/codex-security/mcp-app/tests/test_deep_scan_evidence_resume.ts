import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
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
} finally {
  await temporaryDirectories.cleanup();
}

async function testResumeRepairsPreviouslyAcceptedEvidence(
  completedIteration: boolean,
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
    for (const finding of saved.findings) delete finding.validation;
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
      noNewStreak: completedIteration ? 1 : 0,
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
  let repairCalls = 0;
  const executor = Object.assign(new FakeExecutor(), {
    async repairFindingEvidence(prompt: string, cwd: string) {
      assert.equal(cwd, fixture.run.targetPath);
      assert.match(prompt, /missing evidence/i);
      repairCalls++;
      if (repairCalls === 1) return "{}";
      const { finding } = JSON.parse(prompt.split("\n")[1]!);
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
    0,
    "repair must honor the discovery cap",
  );
  assert.equal(repairCalls, 2, "incomplete repair uses the normal retry");
  assert.equal(store.run.dispatchedCount, 1);
  assert.equal(store.failureMessages.length, 0);
  assert.equal(published.length, 1);
  assert.ok(published[0].findings[0].validation);
  assert.equal(
    store.iterations.at(-1)!.workerIds.length,
    completedIteration ? 0 : 1,
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
