import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
import { importSource } from "./import-module.ts";
import { draftApi, fixture } from "./scan-draft-recovery-fixture.ts";
import { finding } from "./scan-draft-fixture.ts";
import { readJson } from "./support/json.ts";

const execFileAsync = promisify(execFile);
const { validateDiscoveryArtifacts } = await importSource(
  "../src/deep-scan/artifact-validation.ts",
  { absWorkingDir: import.meta.dirname },
);

for (const outcome of ["reported", "rejected", "not_applicable"] as const) {
  for (const reopened of [false, true]) {
    for (const stop of ["fail-deep-scan", "cancel-scan"] as const) {
      test(`worker terminal publication survives ${stop}: ${outcome}, reopened=${reopened}`, async (t) => {
        const f = await fixture(t, "deep");
        const directory = path.dirname(f.root);
        const target = path.join(directory, "target");
        const home = path.join(directory, "home");
        const state = path.join(directory, "state");
        await mkdir(target);
        await writeFile(path.join(target, "app.py"), "synthetic source\n");
        await mkdir(path.join(home, "codex-security"), {
          recursive: true,
          mode: 0o700,
        });
        await writeFile(
          path.join(home, "codex-security/config.toml"),
          "[deep_scan]\nworkers = 1\nmax_discovery_runs = 1\n",
        );
        const workbench = async (...args: string[]) => {
          const { stdout } = await execFileAsync(
            process.env.PYTHON?.trim() || "python3",
            [
              path.join(import.meta.dirname, "../../scripts/workbench_db.py"),
              ...args,
            ],
            {
              env: {
                ...process.env,
                CODEX_HOME: home,
                CODEX_SECURITY_STATE_DIR: state,
              },
            },
          );
          return JSON.parse(stdout);
        };
        const { deepScan } = await workbench(
          "begin-deep-scan",
          "--thread-id",
          "synthetic-parent-thread",
          "--target-path",
          target,
          "--scope",
          ".",
          "--scan-root",
          path.join(directory, "scans"),
          "--available-parallelism",
          "16",
        );
        const scanId = deepScan.scanId;
        const workerId = randomUUID();
        const output = path.join(
          deepScan.scanDir,
          "artifacts/deep_discovery/worker",
        );
        await mkdir(output, { recursive: true });
        const prompt = path.join(output, "prompt.md");
        await writeFile(prompt, "Review the synthetic candidate.\n");
        const workerArgs = [
          "upsert-deep-scan-worker",
          "--scan-id",
          scanId,
          "--worker-id",
          workerId,
          "--kind",
          "discovery",
          "--prompt-path",
          prompt,
          "--artifact-dir",
          output,
          "--attempt",
          "1",
        ];
        await workbench(...workerArgs, "--status", "running");
        const context = {
          root: output,
          repoRoot: target,
          scanId,
          layout: "worker",
          scope: ".",
        };
        const current = {
          ...finding("review", "app.py"),
          provenance: { source: "local_plugin", candidateId: "candidate-one" },
        };
        const pending = {
          id: "gap",
          candidateId: "candidate-one",
          reason: "Earlier proof gap.",
        };
        const draft = {
          scanId,
          complete: true,
          findings: outcome === "reported" ? [current] : [],
          coverage: {
            completeness: "partial",
            surfaces:
              outcome === "reported"
                ? []
                : [
                    {
                      id: "review",
                      label: "Candidate review",
                      candidateId: "candidate-one",
                      disposition: outcome,
                      notes: "Current review resolved the candidate.",
                      receiptRefs: [],
                    },
                  ],
            explicitExclusions: [],
            deferred: [pending],
          },
        };
        await draftApi.recordCodexSecurityWorkerScanDraft(context, draft);
        if (reopened)
          await draftApi.recordCodexSecurityWorkerScanDraft(context, {
            ...draft,
            findings: [],
            coverage: {
              ...draft.coverage,
              surfaces: [],
              deferred: [
                {
                  ...pending,
                  reason: "A later publication explicitly reopens the review.",
                },
              ],
            },
          });
        const resultPath = path.join(output, "result.json");
        await validateDiscoveryArtifacts(
          { workersRoot: output },
          resultPath,
          scanId,
        );
        await workbench(
          ...workerArgs,
          "--status",
          "succeeded",
          "--result-manifest-path",
          resultPath,
        );
        const snapshots = await Promise.all(
          [
            "result.json",
            "checkpoint-head.json",
            ...(await readdir(path.join(output, "checkpoints"))).map((name) =>
              path.join("checkpoints", name),
            ),
          ].map(
            async (name) =>
              [name, await readFile(path.join(output, name))] as const,
          ),
        );
        await workbench(
          stop,
          "--scan-id",
          scanId,
          ...(stop === "cancel-scan"
            ? ["--thread-id", "synthetic-parent-thread"]
            : ["--message", "Synthetic interruption."]),
        );
        for (let replay = 0; replay < 2; replay++) {
          const { scan } = await workbench("get-scan", "--scan-id", scanId);
          assert.equal(scan.progress.candidates.unresolved, reopened ? 1 : 0);
          const coverage = await readJson(deepScan.scanDir, "coverage.json");
          const findings = await readJson(deepScan.scanDir, "findings.json");
          const deferred = coverage.deferred.filter(
            (row: { candidateId?: string }) =>
              row.candidateId === pending.candidateId,
          );
          assert.equal(deferred.length, reopened ? 1 : 0);
          if (reopened)
            assert.equal(
              deferred[0].reason,
              "A later publication explicitly reopens the review.",
            );
          if (outcome === "reported") {
            assert.equal(findings.findings.length, 1);
            assert.equal(
              findings.findings[0].provenance.candidateReopened === true,
              reopened,
            );
          } else {
            const decisions = coverage.surfaces.filter(
              (row: { candidateId?: string }) =>
                row.candidateId === pending.candidateId,
            );
            assert.equal(decisions.length, reopened ? 0 : 1);
            if (!reopened) assert.equal(decisions[0].disposition, outcome);
          }
          for (const [name, bytes] of snapshots)
            assert.deepEqual(await readFile(path.join(output, name)), bytes);
          await workbench(
            "preserve-scan-results",
            "--scan-id",
            scanId,
            "--thread-id",
            "synthetic-parent-thread",
          );
        }
      });
    }
  }
}
