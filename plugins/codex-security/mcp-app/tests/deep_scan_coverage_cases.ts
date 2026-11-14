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
    draft.reviewState = {
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
  const coverage = completed[0].reviewState as unknown as {
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
    assert.notEqual(draft.reviewState.completeness, "complete");
    assert.deepEqual(draft.reviewState.surfaces, [workerReviewed, followUp]);
    assert.equal(draft.reviewState.deferred.length, 1);
  }
}

export async function testSuccessfulDeepCoverageRetainsIndependentWorkerReviewStatus() {
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 2,
  });
  const executor = new FakeExecutor();
  const run = executor.run.bind(executor);
  const workerReviewed = {
    label: "Reviewed query",
    disposition: "no_issue_found",
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
    draft.reviewState = {
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
  const coverage = completed[0].reviewState as unknown as {
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

  const workers = [...store.workers.values()].filter(
    (worker) => worker.kind === "discovery",
  );
  assert.equal("completeness" in coverage, false);
  assert.deepEqual(
    coverage.reviews.map((review) => review.workerId).sort(),
    workers.map((worker) => worker.id).sort(),
  );
  assert.equal(coverage.deferred.length, 2);
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
  for (const worker of workers) {
    const draft = await readJson(worker.resultManifestPath!);
    assert.deepEqual(draft.reviewState.surfaces, [workerReviewed, followUp]);
    assert.equal(draft.reviewState.deferred.length, 1);
  }
}
