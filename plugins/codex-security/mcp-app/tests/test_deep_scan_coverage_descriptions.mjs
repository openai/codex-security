import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { publishCoverageFixture } from "./deep_scan_coverage_fixture.mjs";

const descriptions = { source: "source-review", worker: "focused-reviewer", task: "Check the filesystem boundary." };
const sourceProvenance = {
  ...descriptions,
  workerId: "worker-local-label", attempt: 99, sourceId: "worker-local-source", candidateId: "worker-local-candidate",
};

for (const options of [
  {},
  { resume: true },
  { resume: true, continueAfterResume: true },
  { resume: true, selectedRecovery: true, discardMutableResults: true },
  { resume: true, selectedRecovery: true, discardMutableResults: true, splitSeededReducers: true },
]) {
  test(`coverage source descriptions survive publication and recovery: ${JSON.stringify(options)}`, async () => {
    const root = await mkdtemp(path.join(tmpdir(), "deep-coverage-descriptions-"));
    try {
      const fixture = path.join(root, "fixture");
      await mkdir(fixture, { mode: 0o700 });
      const { scanDir } = await publishCoverageFixture(fixture, "partial", {
        ...options, immutableInputs: true, materialFindings: true, sourceProvenance,
      });
      const coverage = JSON.parse(await readFile(path.join(scanDir, "coverage.json"), "utf8"));
      assert.equal(coverage.completeness, "partial");
      assert.equal(new Set(coverage.deferred.map((item) => item.candidateId)).size, 2);
      for (const field of ["surfaces", "explicitExclusions", "deferred", "openQuestions"]) {
        assert.ok(coverage[field].length > 0);
        for (const item of coverage[field]) {
          const review = coverage.reviews.find((review) => review.workerId === item.provenance.workerId);
          assert.ok(review, "host identity names an actual independent review");
          assert.deepEqual(item.provenance, {
            ...descriptions, workerId: review.workerId, attempt: review.attempt,
            ...(field === "surfaces" ? { sourceId: "shared-surface" } : {}),
            ...(field === "deferred" ? { sourceId: "same-id", candidateId: "candidate-1" } : {}),
          });
        }
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}
