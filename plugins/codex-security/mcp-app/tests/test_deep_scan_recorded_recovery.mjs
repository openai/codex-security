import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { materialRemediations, materialRemediationTests, publishCoverageFixture } from "./deep_scan_coverage_fixture.mjs";

for (const [continueAfterResume, legacyAttempts, splitSeededReducers] of [[false, false, false], [true, false, false], [true, true, false], [false, false, true], [false, true, true]]) {
  test(`recorded inputs preserve fixes and coverage after mutable outputs disappear (continued: ${continueAfterResume}, legacy attempts: ${legacyAttempts}, reducer chain: ${splitSeededReducers})`, async () => {
    const root = await mkdtemp(path.join(tmpdir(), "recorded-coverage-recovery-"));
    try {
      const fixture = path.join(root, "fixture");
      await mkdir(fixture, { mode: 0o700 });
      const { scanDir } = await publishCoverageFixture(fixture, "partial", {
        resume: true, continueAfterResume, legacyAttempts, splitSeededReducers,
        immutableInputs: true, materialFindings: true, discardMutableResults: true,
      });
      const report = await readFile(path.join(scanDir, "report.md"), "utf8");
      for (const fix of [...materialRemediations, ...materialRemediationTests]) {
        assert.equal(report.split(fix).length - 1, 1);
      }
      const coverage = JSON.parse(await readFile(path.join(scanDir, "coverage.json"), "utf8"));
      assert.equal(coverage.completeness, "partial");
      assert.deepEqual(coverage.reviews.map((review) => review.completeness), ["partial", "complete", "unknown"]);
      assert.equal(new Set(coverage.deferred.map((item) => item.candidateId)).size, 2);
      for (const surface of coverage.surfaces) {
        assert.equal(await readFile(path.join(scanDir, surface.receiptRefs[0]), "utf8"), "Synthetic review evidence.\n");
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}
