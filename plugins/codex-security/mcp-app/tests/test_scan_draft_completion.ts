import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import { isDeepStrictEqual, promisify } from "node:util";
import { importModule } from "./import-module.ts";
import { readJson } from "./support/json.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

const execFileAsync = promisify(execFile);
const pluginRoot = path.resolve(import.meta.dirname, "../..");
const { createScanArtifactContext, recordCodexSecurityScanDraftViaWorkbench } =
  await importModule({
    stdin: {
      contents: `export { createScanArtifactContext } from "./src/artifact-context.ts";
export { recordCodexSecurityScanDraftViaWorkbench } from "./src/artifact-scan-draft.ts";`,
      resolveDir: path.join(pluginRoot, "mcp-app"),
    },
  });

for (const mode of ["standard", "diff"]) {
  for (const variant of [
    "identical",
    "reversed",
    "end line",
    "stronger inferred",
    "stronger explicit",
    "more evidence",
    "repeated inferred",
    "repeated mixed",
    "mixed siblings",
    "explicit duplicates",
  ]) {
    test(`${mode}: normal completion after candidate identity reuse, ${variant}`, async (t) => {
      const root = await temporaryDirectory("scan-draft-completion-");
      t.after(() => rm(root, { recursive: true, force: true }));
      const target = path.join(root, "target");
      await mkdir(target);
      await writeFile(path.join(target, "app.py"), "value = 1\n");
      if (mode === "diff") {
        for (const args of [
          ["init", "-q"],
          ["add", "app.py"],
          [
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.com",
            "commit",
            "-qm",
            "Fixture",
          ],
        ])
          await execFileAsync("git", args, { cwd: target });
        await writeFile(path.join(target, "app.py"), "value = 2\n");
      }
      const runWorkbench = async (args: string[]) => {
        const { stdout } = await execFileAsync(
          process.env.PYTHON?.trim() || "python3",
          [path.join(pluginRoot, "scripts/workbench_db.py"), ...args],
          {
            env: {
              ...process.env,
              CODEX_HOME: path.join(root, "home"),
              CODEX_SECURITY_STATE_DIR: path.join(root, "state"),
            },
          },
        );
        return JSON.parse(stdout);
      };
      const workspaceId = randomUUID();
      await runWorkbench([
        "create-workspace",
        "--workspace-id",
        workspaceId,
        "--target-path",
        target,
      ]);
      await runWorkbench([
        "save-workspace",
        "--workspace-id",
        workspaceId,
        "--target-path",
        target,
        "--scope",
        ".",
        "--mode",
        mode,
        ...(mode === "diff" ? ["--diff-target-kind", "working_tree"] : []),
      ]);
      const { results: scan } = await runWorkbench([
        "start-scan",
        "--workspace-id",
        workspaceId,
        "--scan-root",
        path.join(root, "scans"),
      ]);
      const claim = randomUUID();
      for (const command of [
        "claim-handoff-delivery",
        "mark-handoff-delivered",
      ])
        await runWorkbench([
          command,
          "--scan-id",
          scan.scanId,
          "--claim-token",
          claim,
        ]);
      const context = await createScanArtifactContext(
        scan.scanId,
        runWorkbench,
        { requireRunning: true },
      );
      const evidence = (id: string) => ({
        id,
        label: "Synthetic evidence " + id,
        path: "app.py",
        startLine: 1,
        code: mode === "diff" ? "value = 2" : "value = 1",
        explanation: "Preserve this observed source detail.",
      });
      const generated = {
        ruleId: "fixture.review",
        title: "Synthetic review finding",
        summary: "The candidate outcome must survive publication.",
        severity: { level: variant === "stronger inferred" ? "high" : "low" },
        confidence: {
          level: "high",
          rationale: "Synthetic persistence fixture.",
        },
        taxonomy: { category: "other", cwe: [] },
        locations: [{ path: "app.py", startLine: 1 }],
        remediation: "Complete the review.",
        provenance: { source: "local_plugin", candidateId: "shared-candidate" },
        ...(variant === "more evidence"
          ? { codeEvidence: [evidence("first-observation")] }
          : {}),
      };
      const explicit = {
        ...structuredClone(generated),
        identity: { anchor: "synthetic-review-finding", instance: "original" },
        severity: { level: variant === "stronger explicit" ? "high" : "low" },
        ...(variant === "end line"
          ? { locations: [{ path: "app.py", startLine: 1, endLine: 1 }] }
          : {}),
        ...(variant === "more evidence"
          ? {
              codeEvidence: [
                evidence("second-observation"),
                evidence("additional-detail"),
              ],
            }
          : {}),
      };
      const observations =
        variant === "mixed siblings"
          ? [
              explicit,
              {
                ...explicit,
                identity: { ...explicit.identity, instance: "second" },
              },
              generated,
              { ...generated, severity: { level: "high" } },
            ]
          : variant === "explicit duplicates"
            ? [explicit, structuredClone(explicit)]
            : variant === "repeated inferred"
              ? [generated, structuredClone(generated)]
              : variant === "reversed"
                ? [explicit, generated]
                : [generated, explicit];
      const writes =
        variant.startsWith("repeated") || variant === "explicit duplicates"
          ? 2
          : 1;
      for (let attempt = 0; attempt < writes; attempt += 1)
        await recordCodexSecurityScanDraftViaWorkbench(
          context,
          {
            scanId: scan.scanId,
            handoffClaimToken: claim,
            complete: true,
            findings: observations,
            reviewState: { surfaces: [], explicitExclusions: [], deferred: [] },
          },
          runWorkbench,
        );
      const complete = () =>
        runWorkbench([
          "complete-scan",
          "--scan-id",
          scan.scanId,
          "--claim-token",
          claim,
        ]);
      if (variant === "explicit duplicates") {
        await assert.rejects(complete, /duplicate occurrence identity/);
        return;
      }
      await complete();
      const { findings } = await readJson(scan.scanDir, "findings.json");
      if (variant === "mixed siblings") {
        assert.deepEqual(
          findings
            .slice(0, 2)
            .map((row: typeof explicit) => row.identity.instance),
          ["original", "second"],
        );
        assert.equal(findings.length, 3);
        assert.equal(findings[2].severity.level, "high");
        return;
      }
      assert.equal(findings.length, 1);
      assert.deepEqual(
        findings[0].identity,
        variant === "repeated inferred"
          ? {
              anchor: "shared-candidate",
              instance: "synthetic-review-finding",
            }
          : explicit.identity,
      );
      assert.equal(
        findings[0].severity.level,
        variant.startsWith("stronger") ? "high" : "low",
      );
      if (variant.startsWith("stronger"))
        assert.ok(
          findings[0].provenance.previousFindings.some(
            (finding: { severity: { level: string } }) =>
              finding.severity.level === "low",
          ),
        );
      if (variant === "more evidence") {
        assert.deepEqual(findings[0].codeEvidence, explicit.codeEvidence);
        assert.ok(
          findings[0].provenance.previousFindings.some(
            (finding: { codeEvidence?: unknown }) =>
              isDeepStrictEqual(finding.codeEvidence, generated.codeEvidence),
          ),
        );
      }
    });
  }
}
