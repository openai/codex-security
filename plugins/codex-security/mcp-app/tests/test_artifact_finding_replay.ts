import { test } from "node:test";
import assert from "node:assert/strict";
import {
  draftApi,
  fixture as createFixture,
} from "./scan-draft-recovery-fixture.ts";
import { readJson } from "./support/json.ts";
const finding = {
  ruleId: "path-traversal.archive-extraction",
  title: "Unsafe archive extraction",
  summary: "An untrusted archive entry reaches a filesystem write.",
  severity: { level: "high", score: 8.1, scoringSystem: "CVSS:3.1" },
  confidence: {
    level: "high",
    rationale: "Source evidence establishes reachability.",
  },
  taxonomy: { category: "path-traversal", cwe: ["CWE-22"] },
  locations: [{ path: "src/extract.py", startLine: 41, endLine: 44 }],
  remediation: "Validate each output path before writing.",
  provenance: {
    source: "local_plugin",
    candidateId: "candidate-shared",
    workerId: "discovery-worker-1",
  },
  extensions: { candidateId: "candidate-shared" },
};
for (const mode of ["standard", "diff"] as const) {
  for (const priorReport of [undefined, "report-a", "no-history"] as const) {
    test(`${mode} report-backed siblings after ${priorReport ?? "unqualified saved candidate"}`, async (t) => {
      const f = await createFixture(t, mode);
      if (priorReport !== "no-history")
        await f.write(
          draftApi.scanDraftInputSchema.parse({
            ...f.draft(),
            findings: [
              {
                ...finding,
                extensions: {
                  ...finding.extensions,
                  ...(priorReport ? { reportId: priorReport } : {}),
                },
              },
            ],
          }),
        );
      await f.write(
        draftApi.scanDraftInputSchema.parse({
          ...f.draft(),
          findings: ["report-a", "report-b"].map((reportId) => ({
            ...finding,
            extensions: { ...finding.extensions, reportId },
          })),
        }),
      );
      const saved = (await readJson(f.root, "findings.json")).findings as {
        extensions: Record<string, unknown>;
        identity: unknown;
      }[];
      const rows = saved.filter((row) => row.extensions.reportId);
      assert.equal(
        rows.length,
        2,
        "both report-backed rows remain represented",
      );
      assert.equal(
        new Set(rows.map((row) => JSON.stringify(row.identity))).size,
        2,
        "distinct stable report-backed instances stay distinct",
      );
    });
  }
}
