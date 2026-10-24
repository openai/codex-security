import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { readJson, writeJson } from "./support/json.ts";
import type { ScanDraftInput } from "../src/artifact-scan-draft.js";
import type { JsonObject } from "../src/types.js";
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
    receiptRefs: ["artifacts/review.md"],
  };
  const followUp = {
    label: "Worker follow-up",
    disposition: "needs_follow_up",
  };
  executor.run = async (request) => {
    const outcome = await run(request);
    if (request.kind !== "discovery") return outcome;
    const receiptPath = path.join(
      request.artifactContext!.root,
      workerReviewed.receiptRefs[0],
    );
    await mkdir(path.dirname(receiptPath), { recursive: true });
    await writeFile(receiptPath, "Independent source review receipt.\n");
    const resultPath = path.join(request.artifactContext!.root, "result.json");
    const draft = await readJson(resultPath);
    draft.coverage = {
      completeness:
        request.kind === "discovery" &&
        request.promptPath.includes("discovery-0002")
          ? "unknown"
          : "partial",
      surfaces: [workerReviewed, followUp],
      explicitExclusions: [],
      deferred: [
        { reason: "An independent review left this question unresolved." },
      ],
    };
    await writeJson(resultPath, draft);
    return outcome;
  };
  const completed: ScanDraftInput[] = [];
  const terminal = await runCoordinator(fixture, store, executor, {
    onComplete: async (draft) => void completed.push(structuredClone(draft)),
  });
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(completed.length, 1);
  const coverage = completed[0].coverage;
  assert.equal(coverage.completeness, undefined);
  assert.equal((coverage.deferred as JsonObject[]).length, 2);
  assert.equal((coverage.surfaces as JsonObject[]).length, 4);
  const reviews = coverage.reviews as { workerId: string }[];
  assert.equal(reviews.length, 2);
  assert.deepEqual(
    new Set(reviews.map((review) => review.workerId)),
    new Set(
      [...store.workers.values()]
        .filter((worker) => worker.kind === "discovery")
        .map((worker) => worker.id),
    ),
  );
  for (const item of coverage.deferred as JsonObject[]) {
    const provenance = item.provenance as { workerId: string; attempt: number };
    assert.equal(provenance.attempt, 1);
    assert.ok(store.workers.has(provenance.workerId));
  }
  for (const worker of store.workers.values()) {
    if (worker.kind !== "discovery") continue;
    const draft = await readJson(worker.resultManifestPath!);
    assert.notEqual(draft.coverage.completeness, "complete");
    assert.deepEqual(draft.coverage.surfaces, [workerReviewed, followUp]);
    assert.equal(draft.coverage.deferred.length, 1);
  }
}
