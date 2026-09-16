import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { publishCoverageFixture } from "./deep_scan_coverage_fixture.mjs";

for (const resume of [false, true]) {
  for (const stopAfterDraft of [false, true]) {
    test(`coverage provenance survives ${resume ? "reconstructed" : "live"} reduction and ${stopAfterDraft ? "recovery" : "completion"}`, async () => {
      const root = await mkdtemp(path.join(tmpdir(), "coverage-provenance-"));
      try {
        const { scanDir } = await publishCoverageFixture(root, "partial", { resume, stopAfterDraft });
        const coverage = JSON.parse(await readFile(path.join(scanDir, "coverage.json"), "utf8"));
        for (const field of ["surfaces", "explicitExclusions", "deferred", "openQuestions"]) {
          const records = coverage[field].filter((item) => item.id !== "scan-stopped");
          assert.ok(records.length > 0, field);
          for (const item of records) {
            const review = coverage.reviews.find((review) => review.workerId === item.provenance.workerId);
            assert.ok(review, "ownership comes from the accepted worker");
            assert.deepEqual(item.provenance, {
              description: `Original ${field} context.`, details: { evidence: ["source review"] },
              workerId: review.workerId, attempt: review.attempt,
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
}
