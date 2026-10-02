import assert from "node:assert/strict";
import {
  mkdtemp,
  mkdir,
  readFile,
  realpath,
  rename,
  rm,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const bundle = await build({
  absWorkingDir: path.dirname(fileURLToPath(import.meta.url)),
  entryPoints: ["../src/artifact-worker-scan-draft.ts"],
  bundle: true,
  format: "esm",
  platform: "node",
  write: false,
});
const { recordCodexSecurityWorkerScanDraft: record, saveScanDraftCheckpoint } =
  await import(
    `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].text).toString("base64")}`
  );
const root = await realpath(
  await mkdtemp(path.join(tmpdir(), "codex-worker-identity-")),
);
const scanId = "7b95abf2-dc04-47a9-9950-53b5c2057f49";
try {
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
      candidateId: "candidate-b5b7a3d14a148f6a",
      workerId: "discovery-worker-1",
    },
    extensions: {
      preserved: "semantic extension",
      candidateId: "candidate-b5b7a3d14a148f6a",
    },
  };

  const coverage = {
    completeness: "complete",
    surfaces: [
      {
        label: "Archive extraction",
        disposition: "reported",
        notes: "Reviewed.",
      },
    ],
    explicitExclusions: [],
    deferred: [],
    extensions: { preserved: true },
  };

  for (const disposition of ["reported", "no_issue_found", "needs_follow_up"]) {
    const directory = path.join(root, disposition);
    await mkdir(directory);
    const context = {
      root: directory,
      repoRoot: root,
      layout: "worker",
      scanId,
    };
    const surface = { id: "surface-review", label: "Entry point", disposition };
    const deferred = {
      reason: "A separate path still needs review.",
      surfaceIds: [surface.id],
    };
    await record(context, {
      scanId,
      complete: false,
      findings: [],
      coverage: {
        ...coverage,
        completeness: "partial",
        surfaces: [surface],
        deferred: [deferred],
      },
    });
    await record(context, {
      scanId,
      findings: [],
      coverage: {
        ...coverage,
        surfaces: [{ ...surface, disposition: "reported" }],
        deferred: [],
      },
    });
    const result = JSON.parse(
      await readFile(path.join(directory, "result.json"), "utf8"),
    );
    assert.equal(
      result.coverage.deferred.length,
      disposition === "needs_follow_up" ? 0 : 1,
      "only an actual transition resolves independent deferred review work",
    );
  }
  for (const field of ["reportId", "ledgerRowId"]) {
    const directory = path.join(root, field);
    await mkdir(directory);
    const context = {
      root: directory,
      repoRoot: root,
      layout: "worker",
      scanId,
    };
    const candidateId = "synthetic-legacy-candidate";
    const legacyFinding = structuredClone(finding);
    delete legacyFinding.provenance.candidateId;
    legacyFinding.extensions = { [field]: candidateId };
    await record(context, {
      scanId,
      complete: false,
      findings: [],
      coverage: {
        ...coverage,
        completeness: "partial",
        deferred: [{ candidateId, reason: "Awaiting candidate review." }],
      },
    });
    await record(context, { scanId, findings: [legacyFinding], coverage });
    const result = JSON.parse(
      await readFile(path.join(directory, "result.json"), "utf8"),
    );
    assert.equal(
      result.coverage.deferred.length,
      0,
      "legacy identity resolves its saved candidate",
    );
    assert.equal(result.findings.length, 1);
  }
  const completedRoot = path.join(root, "completed-worker");
  await mkdir(completedRoot);
  const completedContext = {
    root: completedRoot,
    repoRoot: root,
    layout: "worker",
    scanId,
  };
  const final = { scanId, findings: [finding], coverage };
  await record(completedContext, final);
  await record(completedContext, {
    ...final,
    complete: false,
    coverage: {
      ...coverage,
      completeness: "partial",
      deferred: [{ reason: "Late incomplete review." }],
    },
  });
  const completed = JSON.parse(
    await readFile(path.join(completedRoot, "result.json"), "utf8"),
  );
  assert.notEqual(completed.complete, false);
  assert.deepEqual(completed.coverage.deferred, []);

  const pendingRoot = path.join(root, "pending-candidate");
  await mkdir(pendingRoot);
  const pendingContext = { ...completedContext, root: pendingRoot };
  const candidate = {
    summary: "Synthetic candidate",
    evidence: "Original source trace.",
  };
  await record(pendingContext, {
    scanId,
    complete: false,
    findings: [],
    coverage: {
      ...coverage,
      completeness: "partial",
      surfaces: [],
      deferred: [
        {
          candidateId: finding.provenance.candidateId,
          reason: "Awaiting review",
          candidate,
        },
      ],
    },
  });
  await record(pendingContext, final);
  const resolved = JSON.parse(
    await readFile(path.join(pendingRoot, "result.json"), "utf8"),
  );
  assert.deepEqual(resolved.coverage.deferred, []);
  assert.deepEqual(resolved.findings[0].provenance.originalCandidates, [
    candidate,
  ]);

  const archivedRoot = path.join(root, "archived-worker");
  const output = path.join(archivedRoot, "output");
  await mkdir(output, { recursive: true });
  const archivedContext = { ...completedContext, root: output };
  const prior = {
    ...final,
    complete: false,
    scope: { summary: "Original source scope." },
  };
  await record(archivedContext, prior);
  const checkpointFinding = structuredClone(finding);
  checkpointFinding.identity = { anchor: "checkpoint-only" };
  checkpointFinding.provenance.candidateId = "checkpoint-only";
  checkpointFinding.extensions.candidateId = "checkpoint-only";
  await saveScanDraftCheckpoint(archivedContext, {
    ...prior,
    findings: [finding, checkpointFinding],
  });
  await mkdir(path.join(archivedRoot, "attempts"));
  await rename(output, path.join(archivedRoot, "attempts", "attempt-01"));
  await mkdir(output);
  await record(archivedContext, { scanId, findings: [], coverage });
  const restored = JSON.parse(
    await readFile(path.join(output, "result.json"), "utf8"),
  );
  assert.deepEqual(
    new Set(restored.findings.map((row) => row.provenance.candidateId)),
    new Set([finding.provenance.candidateId, "checkpoint-only"]),
  );
  assert.deepEqual(restored.scope, prior.scope);
  console.log("split worker identity and reconciliation: 8 cases passed");
} finally {
  await rm(root, { recursive: true, force: true });
}
