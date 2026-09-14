import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { materialRemediations, materialRemediationTests, publishCoverageFixture } from "./deep_scan_coverage_fixture.mjs";

for (const [resume, continueAfterResume] of [[false, false], [true, false], [true, true]]) {
  test(`material fixes and unresolved coverage survive canonical publication (resume: ${resume}, continued: ${continueAfterResume})`, async () => {
    const root = await mkdtemp(path.join(tmpdir(), "deep-material-coverage-"));
    try {
      const fixture = path.join(root, "fixture");
      await mkdir(fixture, { mode: 0o700 });
      const { scanDir } = await publishCoverageFixture(fixture, "partial", {
        resume, continueAfterResume, immutableInputs: true, materialFindings: true,
      });
      const { findings } = JSON.parse(await readFile(path.join(scanDir, "findings.json"), "utf8"));
      assert.equal(findings.length, 1);
      const sources = findings[0].provenance.sourceFindings;
      assert.deepEqual(sources.map((source) => source.finding.remediation), materialRemediations);
      assert.equal(new Set(sources.map((source) => source.id)).size, 2);
      const report = await readFile(path.join(scanDir, "report.md"), "utf8");
      for (const text of [...materialRemediations, ...materialRemediationTests]) {
        assert.equal(report.split(text).length - 1, 1, `canonical report retains ${text}`);
      }
      const coverage = JSON.parse(await readFile(path.join(scanDir, "coverage.json"), "utf8"));
      assert.equal(coverage.completeness, "partial");
      assert.deepEqual(coverage.reviews.map((review) => review.completeness), ["partial", "complete", "unknown"]);
      assert.equal(coverage.deferred.length, 2, "a finding does not discharge independent unresolved work");
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
