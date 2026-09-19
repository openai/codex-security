import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { publishCoverageFixture } from "./deep_scan_coverage_fixture.mjs";

for (const continueAfterResume of [false, true]) {
  test(`immutable discovery receipts survive resumed publication (continued: ${continueAfterResume})`, async () => {
    const root = await mkdtemp(path.join(tmpdir(), "deep-checkpoint-coverage-"));
    try {
      const fixture = path.join(root, "fixture");
      await mkdir(fixture, { mode: 0o700 });
      const { scanDir } = await publishCoverageFixture(fixture, "partial", {
        resume: true, continueAfterResume, immutableInputs: true,
      });
      const coverage = JSON.parse(await readFile(path.join(scanDir, "coverage.json"), "utf8"));
      assert.equal(coverage.completeness, "partial");
      assert.deepEqual(coverage.reviews.map((review) => review.completeness), ["partial", "complete", "unknown"]);
      assert.equal(coverage.reviews[0].attempt, 2);
      assert.equal(new Set(coverage.deferred.map((item) => item.candidateId)).size, 2);
      const report = await readFile(path.join(scanDir, "report.md"), "utf8");
      for (const item of coverage.deferred) assert.ok(report.includes(item.reason));
      for (const surface of coverage.surfaces) {
        for (const receipt of surface.receiptRefs) {
          assert.equal(await readFile(path.join(scanDir, receipt), "utf8"), "Synthetic review evidence.\n");
        }
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}
