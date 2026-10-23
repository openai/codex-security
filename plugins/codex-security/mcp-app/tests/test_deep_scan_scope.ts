import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { finding } from "./scan-draft-fixture.ts";
import { importSource } from "./import-module.ts";

const {
  recordCodexSecurityScanDraft,
  parseScanDraft,
  parseCanonicalScanDraft,
} = await importSource("../src/artifact-scan-draft.ts", {
  absWorkingDir: import.meta.dirname,
});
const findings = [
  finding("api", "api/source.py"),
  finding("jobs", "background jobs/source.py"),
  finding("unrelated", "unrelated/source.py"),
  finding("prefix", "api-other/source.py"),
];

for (const mode of ["deep", "standard"] as const) {
  for (const [label, paths, expected] of [
    ["multiple paths", ["api", "background jobs"], ["api", "jobs"]],
    ["single path", ["api"], ["api"]],
    ["whole repository", ["."], ["api", "jobs", "unrelated", "prefix"]],
  ] as const) {
    test(`${mode} composed publication preserves ${label}`, async (t) => {
      const root = await mkdtemp(join(tmpdir(), "composed-scope-"));
      t.after(() => rm(root, { recursive: true, force: true }));
      const context = {
        root,
        repoRoot: root,
        scanId: "7fc17317-9594-49e0-b06a-d72fd7e14bba",
        status: "running",
        mode,
        targetRevision: "unversioned",
        targetContract: {
          target: {
            allowedKinds: ["directory_snapshot"],
            targetId: "synthetic-target",
            displayName: "Synthetic repository",
          },
          scope: { requiredIncludePaths: [...paths], requiredExcludePaths: [] },
        },
      };
      const input = {
        scanId: context.scanId,
        complete: true,
        findings: structuredClone(findings),
        coverage: {
          completeness: "partial",
          surfaces: [],
          explicitExclusions: [],
          deferred: [],
        },
      };
      let documents: any, checkpoint: any;
      await recordCodexSecurityScanDraft(
        context,
        input,
        async (draft: any, _digest: unknown, saved: any) => {
          documents = structuredClone(draft);
          checkpoint = structuredClone(saved);
        },
      );
      const anchors = (rows: any[]) => rows.map((row) => row.identity.anchor);
      const selected =
        mode === "deep"
          ? [...expected]
          : ["api", "jobs", "unrelated", "prefix"];
      assert.deepEqual(anchors(documents.findings.findings), selected);
      assert.deepEqual(anchors(checkpoint.findings), selected);
      assert.deepEqual(input.findings, findings);
      assert.deepEqual(documents.manifest.scan.scope.includePaths, [...paths]);
    });
  }
}

test("composed discovery and canonical draft admission require typed surface IDs", () => {
  const coverage = {
    completeness: "partial",
    surfaces: [
      { id: "HTTP API", label: "HTTP API", disposition: "no_issue_found" },
    ],
    explicitExclusions: [],
    deferred: [],
  };
  assert.throws(
    () =>
      parseScanDraft({
        scanId: "7fc17317-9594-49e0-b06a-d72fd7e14bba",
        findings: [],
        coverage,
      }),
    /Invalid string/,
  );
  assert.throws(
    () =>
      parseCanonicalScanDraft({
        scanId: "7fc17317-9594-49e0-b06a-d72fd7e14bba",
        manifest: { scan: { id: "7fc17317-9594-49e0-b06a-d72fd7e14bba" } },
        findings: { findings: [] },
        coverage,
      }),
    /Invalid string/,
  );
});
