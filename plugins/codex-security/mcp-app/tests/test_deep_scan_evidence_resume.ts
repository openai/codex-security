import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import type { ScanDraftInput } from "../src/artifact-scan-draft.js";
import { readJson, writeJson } from "./support/json.ts";
import {
  claimDedupInputs,
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
  completedReducer: boolean,
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
    if (!completedReducer && worker.kind === "dedup") {
      store.workers.delete(worker.id);
      continue;
    }
    const saved = await readJson(worker.resultManifestPath!);
    for (const finding of saved.findings) delete finding.validation;
    await writeJson(worker.resultManifestPath!, saved);
    if (!completedReducer && worker.kind === "discovery")
      store.workers.set(worker.id, { ...worker, mergeState: "buffered" });
  }
  if (!completedReducer) {
    store.dedupClaims = [];
    store.dedupCommits = [];
  }
  const resetForResume = () => {
    store.run = {
      ...store.run,
      status: "running",
      terminalReason: undefined,
      manifestPath: undefined,
      noNewStreak: completedReducer ? 1 : 0,
      persistedWorkers: structuredClone([...store.workers.values()]),
      persistedDedupInputs: store.dedupClaims.flatMap(claimDedupInputs),
    };
  };
  resetForResume();
  const acceptedPaths = [...store.workers.values()].map(
    (worker) => worker.resultManifestPath!,
  );
  const acceptedBytes = await Promise.all(
    acceptedPaths.map((file) => readFile(file, "utf8")),
  );
  const executor = new FakeExecutor();
  const execute = executor.run.bind(executor);
  executor.run = async (request) => {
    assert.equal(request.kind, "dedup");
    assert.match(
      await readFile(request.promptPath, "utf8"),
      /missing evidence/i,
    );
    const result = await execute(request);
    if (executor.dedupCalls > 1) {
      const output = path.join(request.artifactContext!.root, "result.json");
      const draft = await readJson(output);
      for (const finding of draft.findings)
        finding.validation = {
          method: "Static source inspection",
          summary: "The existing source proof supports the reported sink.",
          evidenceRefs: finding.codeEvidence.map(
            (item: { id: string }) => item.id,
          ),
        };
      await writeJson(output, draft);
    }
    return result;
  };
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
  assert.equal(
    executor.dedupCalls,
    2,
    "incomplete repair uses the normal retry",
  );
  assert.equal(store.run.dispatchedCount, 1);
  assert.equal(store.failureMessages.length, 0);
  assert.equal(published.length, 1);
  assert.ok(published[0].findings[0].validation);
  assert.equal(
    store.dedupClaims.at(-1)!.workerIds.length,
    completedReducer ? 0 : 1,
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
  assert.equal(restarted.discoveryCalls + restarted.dedupCalls, 0);
}
