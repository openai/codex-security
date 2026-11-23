import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { afterEach, test } from "node:test";
import { readFixtureCoverage } from "./deep_scan_coverage_fixture.ts";
import {
  materialRemediations,
  materialRemediationTests,
  publishCoverageFixture,
} from "./deep_scan_publication_fixture.mjs";
import { readJson } from "./support/json.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";

const directories = createTemporaryDirectories(true);
afterEach(directories.cleanup);

const replayModes = [
  {},
  { resume: true },
  { resume: true, continueAfterResume: true },
];
const selectedModes = [
  { selectedRecovery: true },
  { selectedRecovery: true, splitSeededReducers: true },
];
const recorded = { resume: true, discardMutableResults: true };

async function publish(completeness, options) {
  const root = await directories.create("deep-material-coverage-");
  const { scanDir, terminal } = await publishCoverageFixture(
    root,
    completeness,
    options,
  );
  return { scanDir, terminal, coverage: await readFixtureCoverage(scanDir) };
}

async function publishPartial(options) {
  const { scanDir, terminal, coverage } = await publish("partial", {
    immutableInputs: true,
    ...options,
  });
  const report = await readFile(path.join(scanDir, "report.md"), "utf8");
  assert.equal(coverage.completeness, undefined);
  assert.deepEqual(
    coverage.reviews.map((review) => review.completeness),
    [undefined, undefined, undefined],
  );
  for (const exclusion of coverage.explicitExclusions)
    assert.ok(report.includes(exclusion.pattern));
  for (const surface of coverage.surfaces) {
    assert.ok(surface.receiptRefs.length);
    for (const receipt of surface.receiptRefs)
      assert.equal(
        await readFile(path.join(scanDir, receipt), "utf8"),
        "Synthetic review evidence.\n",
      );
  }
  if (options.materialFindings) {
    for (const text of [...materialRemediations, ...materialRemediationTests])
      assert.equal(
        report.split(text).length - 1,
        1,
        `canonical report retains ${text}`,
      );
  }
  return { scanDir, coverage, terminal };
}

for (const options of [
  ...replayModes.filter(({ resume }) => resume),
  ...replayModes.map((mode) => ({ ...mode, materialFindings: true })),
]) {
  test(`immutable discovery coverage survives publication: ${JSON.stringify(options)}`, async () => {
    const { scanDir, coverage } = await publishPartial(options);
    if (!options.materialFindings) assert.equal(coverage.reviews[0].attempt, 2);

    assert.equal(
      new Set(
        coverage.deferred.map(({ provenance }) =>
          JSON.stringify([provenance.workerId, provenance.candidateId]),
        ),
      ).size,
      2,
    );
    if (options.materialFindings) {
      assert.equal(
        coverage.deferred.length,
        2,
        "a finding does not discharge independent unresolved work",
      );
      const { findings } = await readJson(scanDir, "findings.json");
      assert.equal(findings.length, 1);
      const sources = findings[0].provenance.sourceFindings;
      assert.deepEqual(
        sources.map((source) => source.finding.remediation),
        materialRemediations,
      );
      assert.equal(new Set(sources.map((source) => source.id)).size, 2);
    }
  });
}

for (const mode of [
  {},
  { continueAfterResume: true },
  { continueAfterResume: true, legacyAttempts: true },
  { continueAfterResume: true, legacyAttempts: "before-bindings" },
  { splitSeededReducers: true },
  { splitSeededReducers: true, legacyAttempts: true },
  ...selectedModes,
]) {
  test(`recorded inputs preserve fixes and coverage after mutable outputs disappear: ${JSON.stringify(mode)}`, async () => {
    const { coverage, terminal } = await publishPartial({
      ...recorded,
      materialFindings: true,
      ...mode,
    });
    assert.equal(new Set(coverage.deferred.map((item) => item.id)).size, 2);
    if (mode.selectedRecovery) {
      assert.equal(terminal.workflowVersion, "deep-security-scan/v2");
      assert.match(
        terminal.finalizationInput.resultPath,
        /accepted-[a-f0-9]{64}\.json$/,
      );
    }
  });
}

const descriptions = {
  source: "source-review",
  worker: "focused-reviewer",
  task: "Check the filesystem boundary.",
};
const sourceProvenance = {
  ...descriptions,
  workerId: "worker-local-label",
  attempt: 99,
  sourceId: "worker-local-source",
  candidateId: "worker-local-candidate",
};

for (const options of [
  ...replayModes,
  ...selectedModes.map((mode) => ({ ...recorded, ...mode })),
]) {
  test(`coverage source descriptions survive publication and recovery: ${JSON.stringify(options)}`, async () => {
    const { coverage } = await publish("partial", {
      ...options,
      immutableInputs: true,
      materialFindings: true,
      sourceProvenance,
    });
    assert.equal(coverage.completeness, undefined);
    assert.equal(new Set(coverage.deferred.map((item) => item.id)).size, 2);
    for (const field of [
      "surfaces",
      "explicitExclusions",
      "deferred",
      "openQuestions",
    ]) {
      assert.ok(coverage[field].length > 0);
      for (const item of coverage[field]) {
        const review = coverage.reviews.find(
          (review) => review.workerId === item.provenance.workerId,
        );
        assert.ok(review, "host identity names an actual independent review");
        assert.deepEqual(item.provenance, {
          ...descriptions,
          workerId: review.workerId,
          attempt: review.attempt,
          ...(field === "surfaces" ? { sourceId: "shared-surface" } : {}),
          ...(field === "deferred"
            ? { sourceId: "same-id", candidateId: "candidate-1" }
            : {}),
        });
      }
    }
  });
}

for (const retry of ["missing", "collision"]) {
  test(`archived discovery receipt preserves its origin after retry (${retry})`, async () => {
    const { scanDir, coverage } = await publish("complete", {
      discoveryReceiptRetry: retry,
    });
    const archived = coverage.surfaces.find(
      (surface) => surface.label === "Archived boundary",
    );
    assert.ok(archived, "accepted archived coverage reaches publication");
    assert.equal(archived.receiptRefs.length, 1);
    assert.equal(
      await readFile(path.join(scanDir, archived.receiptRefs[0]), "utf8"),
      "Archived review evidence.\n",
    );
    const current = coverage.surfaces.find(
      (surface) => surface.label === "Archive route",
    );
    assert.equal(
      await readFile(path.join(scanDir, current.receiptRefs[0]), "utf8"),
      "Synthetic review evidence.\n",
    );
  });
}
