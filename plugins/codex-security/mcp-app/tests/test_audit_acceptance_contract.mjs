import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, readdir, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { build } from "esbuild";

const bundle = await build({
  stdin: {
    contents: `export * from "./src/artifact-scan-draft.ts";
      export * from "./src/deep-scan/artifact-validation.ts";
      export * from "./src/deep-scan/artifacts.ts";
      export * from "../../../sdk/typescript/src/accepted-audit.ts";`,
    resolveDir: path.resolve(import.meta.dirname, ".."),
  },
  bundle: true, format: "esm", platform: "node", write: false,
  footer: { js: "//# sourceURL=audit-acceptance-contract.js" },
});
const {
  createDeepScanArtifacts, recordCodexSecurityScanDraft,
  recordCodexSecurityWorkerScanDraft, validateDiscoveryArtifacts,
  readDiscoveryAuditDraft, auditEvidence, runAcceptedAudit,
} = await import(`data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`);

const scanId = "811aef98-3709-4c2d-8b7a-742977521865";
const finding = {
  ruleId: "path-traversal.archive-extraction", title: "Unsafe archive extraction",
  summary: "An archive entry reaches a filesystem write.",
  severity: { level: "high" }, confidence: { level: "high", rationale: "Source review." },
  taxonomy: { category: "path-traversal", cwe: ["CWE-22"] },
  locations: [{ path: "src/extract.py", startLine: 4 }],
  remediation: "Validate the resolved output path before writing.",
  provenance: { source: "local_plugin", candidateId: "archive-entry" },
};

for (const completeness of ["complete", "partial", "unknown"]) {
  test(`Standard and Deep retain accepted semantic evidence with ${completeness} coverage`, async () => {
    const root = await realpath(await mkdtemp(path.join(tmpdir(), "audit-contract-")));
    try {
      const repository = path.join(root, "repository");
      const scanDir = path.join(root, "scan");
      const artifacts = createDeepScanArtifacts(scanDir);
      const workerRoot = path.join(artifacts.workersRoot, "discovery-0001", "output");
      await Promise.all([mkdir(repository), mkdir(workerRoot, { recursive: true })]);
      const semantic = {
        scanId, complete: true,
        threatModel: { summary: "An untrusted caller supplies archive entries." },
        findings: [finding],
        coverage: {
          completeness,
          surfaces: [{ id: "archive", label: "Archive extraction", disposition: "reported", receiptRefs: [] }],
          explicitExclusions: [],
          deferred: completeness === "complete" ? [] : [{ id: "deployment-controls", reason: "Deployment controls remain unverified." }],
        },
      };
      const standard = {
        root: scanDir, repoRoot: repository, layout: "scan", scanId,
        mode: "standard", status: "running", scope: ".",
        targetContract: {
          target: {
            allowedKinds: ["directory_snapshot"], targetId: "target_example", displayName: "example",
            requiredSnapshotDigest: `codex-security-snapshot/v1:sha256:${"a".repeat(64)}`,
          },
          scope: { requiredIncludePaths: ["."], requiredExcludePaths: [] }, diffTarget: null,
        },
      };
      const worker = { root: workerRoot, repoRoot: repository, layout: "worker", scanId };
      const checkpoint = { ...semantic, complete: false };
      await recordCodexSecurityScanDraft(standard, checkpoint);
      await recordCodexSecurityWorkerScanDraft(worker, checkpoint);
      await assert.rejects(validateDiscoveryArtifacts(artifacts, path.join(workerRoot, "result.json"), scanId), /checkpoint/);
      assert.equal(JSON.parse(await readFile(path.join(scanDir, "scan-manifest.json"))).scan.complete, false);
      const controller = new AbortController();
      const execute = async () => ({ threadId: "audit-conversation", usage: null });
      const accept = async () => auditEvidence(await readDiscoveryAuditDraft(
        artifacts, path.join(workerRoot, "result.json"), scanId,
      ));
      const unfinished = await runAcceptedAudit({ signal: controller.signal, execute, accept });
      assert.equal(unfinished.status, "checkpoint");
      assert.equal(unfinished.checkpoint.complete, false);
      assert.equal(unfinished.accepted, undefined);
      assert.equal(unfinished.execution.usage, null);
      const standardWrite = await recordCodexSecurityScanDraft(standard, semantic);
      const deepWrite = await recordCodexSecurityWorkerScanDraft(worker, semantic);
      assert.equal(standardWrite.status, "draft_written");
      assert.equal(deepWrite.status, "draft_written");
      const accepted = await validateDiscoveryArtifacts(artifacts, path.join(workerRoot, "result.json"), scanId);
      const manifest = JSON.parse(await readFile(path.join(scanDir, "scan-manifest.json")));
      const findings = JSON.parse(await readFile(path.join(scanDir, "findings.json")));
      const coverage = JSON.parse(await readFile(path.join(scanDir, "coverage.json")));
      assert.deepEqual(accepted.findings, [finding]);
      for (const [key, value] of Object.entries(finding)) {
        assert.deepEqual(findings.findings[0][key], value);
      }
      assert.ok(findings.findings[0].identity.anchor);
      assert.deepEqual(accepted.threatModel, manifest.scan.threatModel);
      for (const field of ["completeness", "surfaces", "explicitExclusions", "deferred"]) {
        assert.deepEqual(coverage[field], accepted.coverage[field]);
      }
      assert.equal(accepted.scanId, scanId);
      const audit = await runAcceptedAudit({ signal: controller.signal, execute, accept });
      assert.equal(audit.status, "accepted");
      assert.deepEqual(audit.accepted, accepted);
      assert.deepEqual(audit.checkpoint, accepted);
      const failure = new Error("Synthetic execution failure");
      const failed = await runAcceptedAudit({ signal: controller.signal,
        execute: async () => { throw failure; },
        accept: async () => { assert.fail("An execution failure cannot accept old output"); },
      });
      assert.equal(failed.status, "failed");
      assert.equal(failed.stage, "execution");
      assert.equal(failed.error, failure);
      assert.equal(failed.accepted, undefined);
      const canceled = await runAcceptedAudit({ signal: controller.signal, execute,
        accept: async () => { const evidence = await accept(); controller.abort("user canceled"); return evidence; },
      });
      assert.equal(canceled.status, "canceled");
      assert.deepEqual(canceled.checkpoint, accepted);
      assert.equal(manifest.scan.sealedAt, undefined);
      assert.equal(manifest.scan.artifacts, undefined);
      assert.equal((await readdir(workerRoot)).includes("scan-manifest.json"), false);
      assert.equal((await readdir(scanDir)).includes("report.md"), false);
      await assert.rejects(validateDiscoveryArtifacts(artifacts, path.join(workerRoot, "result.json"), "b4c84677-5aaf-410c-88d2-3e97e6f8c4d8"), /scan/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}
