import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  publishCoverageFixture,
  readFixtureCoverage,
} from "./deep_scan_coverage_fixture.ts";

for (const surfaceOnly of [false, true]) {
  for (const resume of [false, true]) {
    for (const dispositions of [["rejected", "not_applicable"], ["reported"]]) {
      for (const resolveOnRetry of [false, true]) {
        test(`${resume ? "resumed" : "live"} ${surfaceOnly ? "surface-only" : "deferred"} stopped recovery preserves ${resolveOnRetry ? "the later disposition" : "newer gaps"} after ${dispositions.join(" and ")} retries`, async () => {
          const root = await mkdtemp(path.join(tmpdir(), "retry-disposition-"));
          try {
            const cases = dispositions.map((disposition) => ({
              disposition,
              candidateId: `candidate-${disposition}`,
              label: `Retry boundary: ${disposition}`,
              gapReasons: ["First", "Second"].map(
                (boundary) =>
                  `${boundary} ${disposition} boundary needs proof.`,
              ),
            }));
            const resolved = {
              completeness: "complete",
              surfaces: cases.map(({ candidateId, disposition }) => ({
                id: `disposition-${disposition}`,
                label: `Disposition: ${disposition}`,
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
              surfaces: cases.flatMap(({ candidateId, disposition, label }) =>
                (surfaceOnly ? ["first", "second"] : ["first"]).map(
                  (suffix) => ({
                    id: `follow-up-${disposition}-${suffix}`,
                    label,
                    candidateId,
                    disposition: "needs_follow_up",
                    receiptRefs: [],
                  }),
                ),
              ),
              explicitExclusions: [],
              deferred: surfaceOnly
                ? []
                : cases.flatMap(({ candidateId, disposition, gapReasons }) =>
                    gapReasons.map((reason, index) => ({
                      id: `retry-gap-${disposition}-${index}`,
                      candidateId,
                      reason,
                      surfaceIds: [`follow-up-${disposition}-first`],
                    })),
                  ),
              openQuestions: [],
            };
            const findings = dispositions.includes("reported")
              ? [
                  {
                    ruleId: "synthetic.retained-boundary",
                    title: "Synthetic boundary finding",
                    summary: "A finding retained from an earlier review.",
                    severity: {
                      level: "high",
                      score: 8.1,
                      scoringSystem: "CVSS:3.1",
                    },
                    confidence: {
                      level: "high",
                      rationale: "Synthetic evidence.",
                    },
                    taxonomy: { category: "path-traversal", cwe: ["CWE-22"] },
                    locations: [
                      { path: "source.py", startLine: 1, endLine: 1 },
                    ],
                    remediation: "Review the synthetic boundary.",
                    provenance: {
                      source: "local_plugin",
                      candidateId: "candidate-reported",
                    },
                  },
                ]
              : undefined;
            const { scanDir } = await publishCoverageFixture(root, "partial", {
              stopBeforeDraft: true,
              resume,
              otherWorkerCandidateIds: cases.map((row) => row.candidateId),
              retryCoverage: resolveOnRetry
                ? [pending, resolved]
                : [resolved, pending],
              retryFindings:
                findings && (resolveOnRetry ? [[], findings] : [findings, []]),
            });
            const coverage = await readFixtureCoverage(scanDir);
            if (findings) {
              const retained = JSON.parse(
                await readFile(path.join(scanDir, "findings.json"), "utf8"),
              );
              assert.equal(retained.findings.length, 1);
              assert.equal(retained.findings[0].ruleId, findings[0].ruleId);
            }
            for (const {
              candidateId,
              disposition,
              label,
              gapReasons,
            } of cases) {
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
              const dispositionRows = coverage.surfaces.filter(
                (item) => item.disposition === disposition,
              );
              assert.equal(
                dispositionRows.length,
                resolveOnRetry || (surfaceOnly && disposition !== "reported")
                  ? 1
                  : 0,
              );
              for (const row of dispositionRows) {
                assert.equal(row.provenance?.candidateId, candidateId);
              }
              assert.ok(
                coverage.deferred.some(
                  (item) =>
                    item.reason === "Verify symbolic links." &&
                    item.provenance?.candidateId === candidateId,
                ),
                `another worker's gap for ${candidateId} remains independent`,
              );
              for (const gap of retryGaps) {
                assert.equal(
                  coverage.surfaces.find(
                    (surface) => surface.id === gap.surfaceIds[0],
                  )?.label,
                  label,
                );
              }
            }
          } finally {
            await rm(root, { recursive: true, force: true });
          }
        });
      }
    }
  }
}
