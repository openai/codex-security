import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { materialRemediations, materialRemediationTests, publishCoverageFixture } from "./deep_scan_coverage_fixture.mjs";

for (const splitSeededReducers of [false, true]) {
  test(`selected publication retains fixes and coverage after failure and a rejected checkpoint (reducer chain: ${splitSeededReducers})`, async () => {
    const root = await mkdtemp(path.join(tmpdir(), "selected-coverage-publication-"));
    try {
      const fixture = path.join(root, "fixture");
      await mkdir(fixture, { mode: 0o700 });
      const { scanDir, terminal } = await publishCoverageFixture(fixture, "partial", {
        resume: true, immutableInputs: true, materialFindings: true, discardMutableResults: true,
        splitSeededReducers, selectedRecovery: true,
      });
      assert.equal(terminal.workflowVersion, "deep-security-scan/v2");
      assert.match(terminal.finalizationInput.resultPath, /checkpoints/);
      const report = await readFile(path.join(scanDir, "report.md"), "utf8");
      for (const fix of [...materialRemediations, ...materialRemediationTests]) {
        assert.equal(report.split(fix).length - 1, 1);
      }
      const coverage = JSON.parse(await readFile(path.join(scanDir, "coverage.json"), "utf8"));
      assert.equal(coverage.completeness, "partial");
      assert.deepEqual(coverage.reviews.map((review) => review.completeness), ["partial", "complete", "unknown"]);
      assert.equal(new Set(coverage.deferred.map((item) => item.candidateId)).size, 2);
      for (const item of coverage.deferred) assert.ok(report.includes(item.reason));
      for (const surface of coverage.surfaces) {
        assert.equal(await readFile(path.join(scanDir, surface.receiptRefs[0]), "utf8"), "Synthetic review evidence.\n");
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}
