import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { readJson, writeJson } from "./support/json.ts";
import type { ScanDraftInput } from "../src/artifact-scan-draft.js";
import {
  coordinatorFixture,
  FakeExecutor,
  runCoordinator,
} from "./deep_scan_coordinator_fixture.ts";

export async function testSuccessfulDeepCoveragePreservesWorkerReviewStatus() {
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
    id: "shared-surface",
    receiptRefs: ["artifacts/worker-receipt.md"],
  };
  const followUp = {
    label: "Worker follow-up",
    disposition: "needs_follow_up",
  };
  executor.run = async (request) => {
    const outcome = await run(request);
    if (request.kind !== "discovery") return outcome;
    const resultPath = path.join(request.artifactContext!.root, "result.json");
    const draft = await readJson(resultPath);
    draft.coverage = {
      completeness: request.promptPath.includes("discovery-0002")
        ? "unknown"
        : "partial",
      surfaces: [workerReviewed, followUp],
      explicitExclusions: [
        { pattern: "vendor/**", reason: "Third-party code." },
      ],
      deferred: [
        {
          id: "shared-task",
          surfaceIds: ["shared-surface"],
          reason: "An independent review left this question unresolved.",
        },
      ],
      openQuestions: ["Does the deployment enable this path?"],
    };
    await mkdir(path.join(request.artifactContext!.root, "artifacts"), {
      recursive: true,
    });
    await writeFile(
      path.join(request.artifactContext!.root, "artifacts/worker-receipt.md"),
      "Reviewed query evidence.\n",
    );
    await writeJson(resultPath, draft);
    return outcome;
  };
  const completed: ScanDraftInput[] = [];
  const terminal = await runCoordinator(fixture, store, executor, {
    onComplete: async (draft) => void completed.push(structuredClone(draft)),
  });
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(completed.length, 1);
  const coverage = completed[0].coverage as unknown as {
    completeness?: string;
    reviews: { workerId: string }[];
    surfaces: { id: string; workerId: string; receiptRefs?: string[] }[];
    explicitExclusions: { workerId: string; pattern: string }[];
    deferred: {
      id: string;
      surfaceIds: string[];
      provenance: { workerId: string; sourceId: string; attempt: number };
    }[];
    openQuestions: { question: string; workerId: string }[];
  };

  assert.equal(coverage.completeness, undefined);
  assert.equal(coverage.deferred.length, 2);
  assert.equal(coverage.reviews.length, 2);
  assert.deepEqual(
    new Set(coverage.reviews.map((review) => review.workerId)),
    new Set(
      [...store.workers.values()]
        .filter((worker) => worker.kind === "discovery")
        .map((worker) => worker.id),
    ),
  );
  assert.equal(coverage.surfaces.length, 4);
  assert.equal(new Set(coverage.surfaces.map((row) => row.id)).size, 4);
  assert.equal(new Set(coverage.deferred.map((row) => row.id)).size, 2);
  assert.equal(coverage.explicitExclusions.length, 2);
  assert.equal(coverage.openQuestions.length, 2);
  for (const row of coverage.deferred) {
    assert.equal(row.provenance.sourceId, "shared-task");
    assert.ok(store.workers.has(row.provenance.workerId));
    assert.equal(row.provenance.attempt, 1);
    assert.deepEqual(row.surfaceIds, [
      `${row.provenance.workerId}-attempt-1-surface-1`,
    ]);
  }
  for (const row of coverage.surfaces) {
    for (const ref of row.receiptRefs ?? []) {
      assert.equal(
        await readFile(path.join(fixture.run.scanDir, ref), "utf8"),
        "Reviewed query evidence.\n",
      );
    }
  }
  for (const worker of store.workers.values()) {
    if (worker.kind !== "discovery") continue;
    const draft = await readJson(worker.resultManifestPath!);
    assert.notEqual(draft.coverage.completeness, "complete");
    assert.deepEqual(draft.coverage.surfaces, [workerReviewed, followUp]);
    assert.equal(draft.coverage.deferred.length, 1);
  }
}

export async function testWorkerScopedCandidateSourceAggregation() {
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
