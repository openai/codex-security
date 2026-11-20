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

async function publishPartial(options) {
  const root = await directories.create("deep-material-coverage-");
  const { scanDir } = await publishCoverageFixture(root, "partial", {
    immutableInputs: true,
    ...options,
  });
  const coverage = await readFixtureCoverage(scanDir);
  const report = await readFile(path.join(scanDir, "report.md"), "utf8");
  assert.equal(Object.hasOwn(coverage, "completeness"), false);
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
  return { scanDir, coverage };
}

for (const options of [
  { resume: true },
  { resume: true, continueAfterResume: true },
  { materialFindings: true },
  { materialFindings: true, resume: true },
  { materialFindings: true, resume: true, continueAfterResume: true },
]) {
  test(`immutable discovery coverage survives publication: ${JSON.stringify(options)}`, async () => {
    const { scanDir, coverage } = await publishPartial(options);
    assert.deepEqual(
      coverage.reviews.map((review) => review.attempt),
      [2, 1, 1],
    );

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
