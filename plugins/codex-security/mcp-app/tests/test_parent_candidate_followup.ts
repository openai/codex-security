import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { importSource } from "./import-module.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

const exec = promisify(execFile);
const pluginRoot = path.resolve(import.meta.dirname, "../..");
const { recordCodexSecurityScanDraftViaWorkbench } = await importSource(
  "../src/artifact-scan-draft.ts",
  { absWorkingDir: import.meta.dirname },
);
const { createScanArtifactContext } = await importSource(
  "../src/artifact-context.ts",
  { absWorkingDir: import.meta.dirname },
);

for (const newerTask of [false, true]) {
  for (const stoppedRetry of [false, true]) {
    test(`parent candidate follow-up: newer task=${newerTask}, stopped retry=${stoppedRetry}`, async (t) => {
      const root = await temporaryDirectory("parent-candidate-followup-", true);
      t.after(() => rm(root, { recursive: true, force: true }));
      const target = path.join(root, "target");
      const scanDir = path.join(root, "scan");
      await mkdir(path.join(target, "src"), { recursive: true });
      await mkdir(scanDir, { mode: 0o700 });
      await writeFile(
        path.join(target, "src/example.py"),
        "# Synthetic source\n",
      );
      const environment = {
        ...process.env,
        CODEX_HOME: path.join(root, "home"),
        CODEX_SECURITY_STATE_DIR: path.join(root, "state"),
      };
      const script = path.join(pluginRoot, "scripts/workbench_db.py");
      const runWorkbench = async (args: string[]) => {
        const { stdout } = await exec(
          process.env.PYTHON || "python3",
          [script, ...args],
          { env: environment },
        );
        return JSON.parse(stdout);
      };
      const registered = await runWorkbench([
        "register-cli-scan",
        "--repository",
        target,
        "--scan-dir",
        scanDir,
        "--recipe-json",
        JSON.stringify({
          config: {},
          mode: "standard",
          repository: target,
          target: { kind: "repository", paths: [] },
        }),
      ]);
      const scanId = registered.scanId;
      const context = await createScanArtifactContext(scanId, runWorkbench, {
        requireRunning: true,
      });
      const finding = {
        ruleId: "fixture.review",
        identity: { anchor: "synthetic-review" },
        title: "Synthetic review finding",
        summary: "Retained evidence remains available.",
        severity: { level: "low" },
        confidence: {
          level: "high",
          rationale: "Synthetic persistence fixture.",
        },
        taxonomy: { category: "other", cwe: [] },
        locations: [{ path: "src/example.py", startLine: 1 }],
        remediation: "Complete the review.",
        provenance: { source: "local_plugin", candidateId: "candidate-c" },
      };
      const task = {
        id: "candidate-followup",
        candidateId: "candidate-c",
        reason: "Review the later caller.",
        paths: ["src/example.py"],
      };
      const coverage = {
        completeness: "partial",
        surfaces: [],
        explicitExclusions: [],
        deferred: [],
      };
      await recordCodexSecurityScanDraftViaWorkbench(
        context,
        {
          scanId,
          complete: false,
          findings: newerTask ? [finding] : [],
          coverage: { ...coverage, deferred: newerTask ? [] : [task] },
        },
        runWorkbench,
      );
      const written = await recordCodexSecurityScanDraftViaWorkbench(
        context,
        {
          scanId,
          complete: true,
          findings: newerTask ? [] : [finding],
          coverage: {
            ...coverage,
            completeness: newerTask ? "partial" : "complete",
            deferred: newerTask ? [task] : [],
          },
        },
        runWorkbench,
      );
      assert.equal(written.findingCount, 1);
      assert.deepEqual(written.coverage.deferred, newerTask ? [task] : []);
      if (stoppedRetry) {
        const fault = path.join(root, "fault.py");
        await writeFile(
          fault,
          `import sys\nsys.path.insert(0, ${JSON.stringify(path.join(pluginRoot, "scripts"))})\nimport workbench_db, workbench_saved_results\ndef fail(*args, **kwargs):\n    raise OSError("Synthetic publication interruption.")\nworkbench_saved_results._write_prepared_scan_finalization = fail\nworkbench_db.main()\n`,
        );
        const { stdout } = await exec(
          process.env.PYTHON || "python3",
          [
            fault,
            "fail-scan",
            "--scan-id",
            scanId,
            "--message",
            "Synthetic stop.",
          ],
          { env: environment },
        );
        assert.equal(JSON.parse(stdout).scan.resultsRecoveryNeeded, true);
        await runWorkbench(["recover-scan-results", "--scan-id", scanId]);
      } else {
        await runWorkbench(["complete-scan", "--scan-id", scanId]);
      }
      const saved = (await runWorkbench(["get-scan", "--scan-id", scanId]))
        .scan;
      assert.equal(saved.resultsRecoveryNeeded, false);
      assert.equal(saved.findingCount, 1);
      const published = JSON.parse(
        await readFile(path.join(scanDir, "coverage.json"), "utf8"),
      );
      assert.deepEqual(
        published.deferred.filter(
          (row: { id: string }) => row.id !== "scan-stopped",
        ),
        newerTask ? [task] : [],
      );
      const bytes = await readFile(path.join(scanDir, "coverage.json"), "utf8");
      await runWorkbench([
        stoppedRetry ? "recover-scan-results" : "get-scan",
        "--scan-id",
        scanId,
      ]);
      assert.equal(
        await readFile(path.join(scanDir, "coverage.json"), "utf8"),
        bytes,
      );
    });
  }
}
