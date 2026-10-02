import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { publishCoverageFixture } from "./deep_scan_coverage_fixture.mjs";

for (const resume of [false, true]) {
  for (const outcome of ["completion", "recovery", "no parent"]) {
    test(`coverage provenance survives ${resume ? "reconstructed" : "live"} reduction and ${outcome}`, async () => {
      const root = await mkdtemp(path.join(tmpdir(), "coverage-provenance-"));
      try {
        const { scanDir } = await publishCoverageFixture(root, "partial", {
          resume,
          stopAfterDraft: outcome === "recovery",
          stopBeforeDraft: outcome === "no parent",
        });
        const coverage = JSON.parse(
          await readFile(path.join(scanDir, "coverage.json"), "utf8"),
        );
        assert.equal(coverage.completeness, "partial");
        assert.equal(coverage.reviews.length, 3);
        assert.deepEqual(
          coverage.surfaces.map((surface) => surface.label),
          Array(3).fill(["Archive route", "Archive settings"]).flat(),
        );
        assert.deepEqual(
          coverage.deferred
            .filter((item) => item.id !== "scan-stopped")
            .map((item) => item.reason),
          ["Verify entry boundaries.", "Verify symbolic links."],
        );
        for (const item of coverage.deferred.filter(
          (item) => item.id !== "scan-stopped",
        )) {
          const linked = coverage.surfaces.find(
            (surface) => surface.id === item.surfaceIds[0],
          );
          assert.equal(linked.label, "Archive route");
          assert.equal(linked.provenance.workerId, item.provenance.workerId);
          assert.equal(linked.provenance.attempt, item.provenance.attempt);
        }
        for (const surface of coverage.surfaces) {
          assert.equal(
            await readFile(path.join(scanDir, surface.receiptRefs[0]), "utf8"),
            "Synthetic review evidence.\n",
          );
        }
        for (const field of [
          "surfaces",
          "explicitExclusions",
          "deferred",
          "openQuestions",
        ]) {
          const records = coverage[field].filter(
            (item) => item.id !== "scan-stopped",
          );
          assert.ok(records.length > 0, field);
          for (const item of records) {
            const review = coverage.reviews.find(
              (review) => review.workerId === item.provenance.workerId,
            );
            assert.ok(review, "ownership comes from the accepted worker");
            assert.deepEqual(item.provenance, {
              description: `Original ${field} context.`,
              details: { evidence: ["source review"] },
              workerId: review.workerId,
              attempt: review.attempt,
              ...(field === "surfaces" ? { sourceId: "shared-surface" } : {}),
              ...(field === "deferred"
                ? { sourceId: "same-id", candidateId: "candidate-1" }
                : {}),
            });
          }
        }
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
  }
}

for (const resume of [false, true]) {
  test(`unknown coverage survives ${resume ? "resumed" : "live"} subsequent clean review`, async () => {
    const root = await mkdtemp(path.join(tmpdir(), "unknown-coverage-"));
    try {
      const { scanDir } = await publishCoverageFixture(root, "unknown", {
        resume,
        continueAfterResume: resume,
      });
      const coverage = JSON.parse(
        await readFile(path.join(scanDir, "coverage.json"), "utf8"),
      );
      assert.equal(coverage.completeness, "unknown");
      assert.deepEqual(
        coverage.reviews.map((review) => review.completeness),
        ["unknown", "complete", "complete"],
      );
      assert.equal(coverage.explicitExclusions.length, 3);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}

for (const outcome of ["completion", "recovery", "frozen recovery"]) {
  test(`open questions are retained once through ${outcome}`, async () => {
    const root = await mkdtemp(path.join(tmpdir(), "question-coverage-"));
    try {
      const { scanDir } = await publishCoverageFixture(root, "complete", {
        stopAfterDraft: outcome !== "completion",
        interruptPublication: outcome === "frozen recovery",
        questionRows: [
          "  Which deployment controls apply?  ",
          {
            question: "  Which runtime settings apply?  ",
            followUpPrompt: " Check the deployment settings. ",
          },
        ],
      });
      const coverage = JSON.parse(
        await readFile(path.join(scanDir, "coverage.json"), "utf8"),
      );
      assert.deepEqual(
        coverage.openQuestions.map((item) => item.question),
        ["Which deployment controls apply?", "Which runtime settings apply?"],
      );
      assert.equal(
        coverage.openQuestions[1].followUpPrompt,
        " Check the deployment settings. ",
      );
      for (const question of coverage.openQuestions) {
        assert.equal(
          question.provenance.workerId,
          coverage.reviews[0].workerId,
        );
        assert.equal(question.provenance.attempt, coverage.reviews[0].attempt);
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}
