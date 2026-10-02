import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const bundled = await build({
  absWorkingDir: path.dirname(fileURLToPath(import.meta.url)),
  bundle: true,
  entryPoints: ["../src/artifact-scan-draft.ts"],
  format: "esm",
  platform: "node",
  write: false,
});
const { recordCodexSecurityScanDraft } = await import(
  `data:text/javascript;base64,${Buffer.from(bundled.outputFiles[0].text).toString("base64")}`
);

const scanId = "00000000-0000-4000-8000-000000000001";
const finding = {
  ruleId: "synthetic-review",
  title: "Synthetic observation",
  summary: "A saved observation in a publication fixture.",
  severity: { level: "low" },
  confidence: { level: "high", rationale: "Synthetic fixture." },
  taxonomy: { category: "synthetic", cwe: [] },
  locations: [{ path: "fixture.py", startLine: 1 }],
  remediation: "Review the fixture.",
  provenance: { source: "local_plugin", candidateId: "synthetic-candidate" },
};
const coverage = {
  completeness: "complete",
  surfaces: [],
  explicitExclusions: [],
  deferred: [],
};

function context(root) {
  return {
    root,
    repoRoot: root,
    layout: "scan",
    scanId,
    mode: "standard",
    status: "running",
    scope: ".",
    targetContract: {
      target: {
        allowedKinds: ["git_worktree"],
        targetId: "synthetic-target",
        displayName: "Synthetic fixture",
      },
      scope: { requiredIncludePaths: ["."], requiredExcludePaths: [] },
    },
  };
}

test("publishing a pre-index scan retains findings saved only in checkpoint history", async (t) => {
  const root = await mkdtemp(
    path.join(tmpdir(), "legacy-checkpoint-publication-"),
  );
  t.after(() => rm(root, { recursive: true, force: true }));
  const saved = { scanId, complete: true, findings: [finding], coverage };
  const contents = JSON.stringify(saved);
  const name = createHash("sha256").update(contents).digest("hex") + ".json";
  await mkdir(path.join(root, "checkpoints"));
  await writeFile(path.join(root, "checkpoints", name), contents);

  const result = await recordCodexSecurityScanDraft(context(root), {
    scanId,
    complete: false,
    findings: [],
    coverage: { ...coverage, completeness: "partial" },
  });

  assert.equal(result.findingCount, 1);
  const published = JSON.parse(
    await readFile(path.join(root, "findings.json"), "utf8"),
  );
  assert.equal(published.findings[0].title, finding.title);
  assert.equal(
    await readFile(path.join(root, "checkpoints", name), "utf8"),
    contents,
  );
});
