import assert from "node:assert/strict";
import { rm } from "node:fs/promises";
import test from "node:test";
import {
  publishCoverageFixture,
  readFixtureCoverage,
} from "./deep_scan_coverage_fixture.ts";
import { finding } from "./scan-draft-fixture.ts";
import { readJson } from "./support/json.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

for (const resume of [false, true]) {
  for (const dispositions of [["rejected", "not_applicable"], ["reported"]]) {
    for (const resolveOnRetry of [false, true]) {
      test(`${resume ? "resumed" : "live"} stopped recovery preserves ${resolveOnRetry ? "the later disposition" : "newer gaps"} after ${dispositions.join(" and ")} retries`, async (t) => {
        const root = await temporaryDirectory("retry-disposition-");
        t.after(() => rm(root, { recursive: true, force: true }));
        const cases = dispositions.flatMap((disposition) =>
          ["surface-only", "deferred"].map((kind) => {
            const candidateId = `${disposition}-${kind}`;
            return {
              candidateId,
              disposition,
              label: `Retry boundary: ${candidateId}`,
              surfaceOnly: kind === "surface-only",
              gapReasons: ["First", "Second"].map(
                (boundary) =>
                  `${boundary} ${candidateId} boundary needs proof.`,
              ),
            };
          }),
        );
        const resolved = {
          completeness: "complete",
          surfaces: cases.map(({ candidateId, disposition }) => ({
            id: `disposition-${candidateId}`,
            label: `Disposition: ${candidateId}`,
            candidateId,
            disposition,
            receiptRefs: [],
          })),
          explicitExclusions: [],
          deferred: [],
          openQuestions: [],
        };
        const pending = {
          completeness: "partial",
          surfaces: cases.flatMap(({ candidateId, label, surfaceOnly }) =>
            (surfaceOnly ? ["first", "second"] : ["first"]).map((suffix) => ({
              id: `follow-up-${candidateId}-${suffix}`,
              label,
              candidateId,
              disposition: "needs_follow_up",
              receiptRefs: [],
            })),
          ),
          explicitExclusions: [],
          deferred: cases
            .filter((row) => !row.surfaceOnly)
            .flatMap(({ candidateId, gapReasons }) =>
              gapReasons.map((reason, index) => ({
                id: `retry-gap-${candidateId}-${index}`,
                candidateId,
                reason,
                surfaceIds: [`follow-up-${candidateId}-first`],
              })),
            ),
          openQuestions: [],
        };
        const findings = cases
          .filter(({ disposition }) => disposition === "reported")
          .map(({ candidateId }) => ({
            ...finding(candidateId, "source.py"),
            provenance: { source: "local_plugin", candidateId },
          }));
        const { scanDir } = await publishCoverageFixture(root, "partial", {
          stopBeforeDraft: true,
          resume,
          otherWorkerCandidateIds: cases.map((row) => row.candidateId),
          retryCoverage: resolveOnRetry
            ? [pending, resolved]
            : [resolved, pending],
          retryFindings: findings.length
            ? resolveOnRetry
              ? [[], findings]
              : [findings, []]
            : undefined,
        });
        const coverage = await readFixtureCoverage(scanDir);
        const retained = await readJson(scanDir, "findings.json");
        assert.deepEqual(
          retained.findings.map((row: { ruleId: string }) => row.ruleId).sort(),
          findings.map((row) => row.ruleId).sort(),
        );
        for (const disposition of dispositions) {
          const expected = cases.filter(
            (row) =>
              row.disposition === disposition &&
              (resolveOnRetry ||
                (row.surfaceOnly && disposition !== "reported")),
          );
          assert.deepEqual(
            coverage.surfaces
              .filter((row) => row.disposition === disposition)
              .map((row) => row.provenance?.candidateId)
              .sort(),
            expected.map((row) => row.candidateId).sort(),
          );
        }
        for (const { candidateId, label, gapReasons, surfaceOnly } of cases) {
          const retryGaps = coverage.deferred.filter((item) =>
            gapReasons.includes(item.reason),
          );
          assert.deepEqual(
            retryGaps.map((item) => item.reason),
            resolveOnRetry || surfaceOnly ? [] : gapReasons,
          );
          assert.equal(
            coverage.surfaces.filter((row) => row.label === label).length,
            resolveOnRetry ? 0 : surfaceOnly ? 2 : 1,
          );
          assert.ok(
            coverage.deferred.some(
              (item) =>
                item.reason === "Verify symbolic links." &&
                item.provenance?.candidateId === candidateId,
            ),
            `another worker's gap for ${candidateId} remains independent`,
          );
          for (const gap of retryGaps) {
            assert.equal(gap.provenance?.candidateId, candidateId);
            assert.equal(
              coverage.surfaces.find(
                (surface) => surface.id === gap.surfaceIds[0],
              )?.label,
              label,
            );
          }
        }
      });
    }
  }
}
