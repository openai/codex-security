import { randomUUID } from "node:crypto";
import { createTestWorkbench } from "./support/discovery.ts";
import assert from "node:assert/strict";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { test, type TestContext } from "node:test";
import { importSource } from "./import-module.ts";
import {
  draftApi,
  fixture,
  recordCodexSecurityScanDraft,
} from "./scan-draft-recovery-fixture.ts";
import { finding } from "./scan-draft-fixture.ts";
import { readSavedReviewState, readJson } from "./support/json.ts";

const { createScanArtifactContext } = await importSource(
  "../src/artifact-context.ts",
  { absWorkingDir: import.meta.dirname },
);
import {
  mergeWorkerFiles,
  scanUnionToDraft,
  validateDiscoveryArtifacts,
} from "./scan-union-fixture.ts";

async function reopeningFixture(
  t: TestContext,
  mode: "standard" | "worker" | "deep",
) {
  const f = await fixture(t, mode);
  const directory = path.dirname(f.root);
  const target = path.join(directory, "target");
  const state = path.join(directory, "state");
  await mkdir(target);
  await writeFile(path.join(target, "app.py"), "synthetic source\n");
  const workbench = await createTestWorkbench(directory);
  const current = {
    ...finding("review", "app.py"),
    provenance: { source: "local_plugin", candidateId: "candidate-one" },
  };
  return { f, directory, target, state, current, workbench };
}

for (const mode of ["standard", "worker"] as const) {
  for (const scenario of [
    "same-publication",
    "later-pending",
    "later-resolved",
    "other-candidate",
  ] as const) {
    test(`publishes explicit candidate state through ${mode}: ${scenario}`, async (t) => {
      const { f, directory, target, state, current, workbench } =
        await reopeningFixture(t, mode);
      let context = { ...f.context, repoRoot: target };
      if (mode === "standard") {
        const { scan } = await workbench([
          "start-headless-standard-scan",
          "--thread-id",
          "synthetic-standard-thread",
          "--target-path",
          target,
          "--scope",
          ".",
          "--scan-root",
          path.join(directory, "scans"),
        ]);
        context = await createScanArtifactContext(scan.scanId, workbench, {
          requireRunning: true,
        });
      }
      if (mode === "worker") {
        context.root = path.join(
          f.root,
          "artifacts/deep_discovery/workers/worker-one/output",
        );
        await mkdir(context.root, { recursive: true });
      }
      assert.ok(context.scanId);
      const pending = {
        id: "gap",
        candidateId:
          scenario === "other-candidate" ? "candidate-two" : "candidate-one",
        reason: "Reopened proof gap requires additional evidence.",
      };
      const coverage = {
        completeness: "complete",
        surfaces: [],
        explicitExclusions: [],
        deferred: [],
      };
      const draft = {
        scanId: context.scanId,
        handoffClaimToken: context.handoffClaimToken,
        complete: true,
        findings: [current],
        reviewState: coverage,
      };
      const write =
        mode === "standard"
          ? recordCodexSecurityScanDraft
          : draftApi.recordCodexSecurityWorkerScanDraft;
      if (scenario !== "same-publication") await write(context, draft);
      const update = {
        ...draft,
        findings: scenario === "same-publication" ? [current] : [],
        reviewState: {
          ...coverage,
          completeness: "partial",
          deferred: [pending],
        },
      };
      await write(context, update);
      await write(context, scenario === "later-resolved" ? draft : update);
      const checkpoints = path.join(context.root, "checkpoints");
      const originals = await Promise.all(
        (await readdir(checkpoints)).map(
          async (name) =>
            [name, await readFile(path.join(checkpoints, name))] as const,
        ),
      );
      const expectedPending =
        scenario === "later-pending" || scenario === "other-candidate";
      const reopened = scenario === "later-pending";
      if (mode === "standard") {
        assert.ok(context.handoffClaimToken);
        await workbench([
          "complete-scan",
          "--scan-id",
          context.scanId,
          "--claim-token",
          context.handoffClaimToken,
        ]);
        const savedCoverage = await readSavedReviewState(context.root, state);
        const savedFindings = await readJson(context.root, "findings.json");
        assert.equal(savedCoverage.deferred.length, Number(expectedPending));
        if (expectedPending)
          assert.equal(savedCoverage.deferred[0].reason, pending.reason);
        assert.equal(savedFindings.findings.length, 1);
        assert.equal(
          savedFindings.findings[0].provenance.candidateReopened === true,
          reopened,
        );
        const report = await readFile(
          path.join(context.root, "report.md"),
          "utf8",
        );
        assert.equal(report.includes(pending.reason), expectedPending);
        const { scan } = await workbench([
          "get-scan",
          "--scan-id",
          context.scanId,
        ]);
        assert.equal(
          scan.progress.candidates.unresolved,
          Number(expectedPending),
        );
      } else {
        const resultPath = path.join(context.root, "result.json");
        const originalResult = await readFile(resultPath);
        for (let replay = 0; replay < 2; replay++) {
          const reduced = await mergeWorkerFiles(
            f.root,
            [{ id: "worker-one", resultPath }],
            { scanId: context.scanId, findings: [] },
          );
          assert.equal(
            (reduced.unresolvedCandidates ?? []).length,
            Number(expectedPending),
          );
          if (expectedPending)
            assert.equal(
              reduced.unresolvedCandidates[0].reason,
              pending.reason,
            );
          assert.equal(reduced.findings.length, 1);
          assert.equal(
            reduced.findings[0].provenance.candidateReopened === true,
            reopened,
          );
          assert.equal(
            scanUnionToDraft(reduced).reviewState.deferred.length,
            Number(expectedPending),
          );
        }
        assert.deepEqual(await readFile(resultPath), originalResult);
      }
      for (const [name, bytes] of originals)
        assert.deepEqual(await readFile(path.join(checkpoints, name)), bytes);
    });
  }
}

for (const outcome of ["reported", "rejected", "not_applicable"] as const) {
  for (const reopened of [false, true]) {
    for (const stop of ["fail-deep-scan", "cancel-scan"] as const) {
      test(`worker terminal publication survives ${stop}: ${outcome}, reopened=${reopened}`, async (t) => {
        const { directory, target, state, current, workbench } =
          await reopeningFixture(t, "deep");
        const home = path.join(directory, "home");
        await mkdir(path.join(home, "codex-security"), {
          recursive: true,
          mode: 0o700,
        });
        await writeFile(
          path.join(home, "codex-security/config.toml"),
          "[deep_scan]\nworkers = 1\nmax_discovery_runs = 1\n",
        );
        const { deepScan } = await workbench([
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
        ]);
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
        await workbench([...workerArgs, "--status", "running"]);
        const context = {
          root: output,
          repoRoot: target,
          scanId,
          layout: "worker",
          scope: ".",
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
          reviewState: {
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
            reviewState: {
              ...draft.reviewState,
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
        await workbench([
          ...workerArgs,
          "--status",
          "succeeded",
          "--result-manifest-path",
          resultPath,
        ]);
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
        await workbench([
          stop,
          "--scan-id",
          scanId,
          ...(stop === "cancel-scan"
            ? ["--thread-id", "synthetic-parent-thread"]
            : ["--message", "Synthetic interruption."]),
        ]);
        const isWorkerCandidate = (row: {
          provenance?: Record<string, unknown>;
        }) =>
          row.provenance?.workerId === workerId &&
          row.provenance.attempt === 1 &&
          row.provenance.candidateId === pending.candidateId;
        for (let replay = 0; replay < 2; replay++) {
          const { scan } = await workbench(["get-scan", "--scan-id", scanId]);
          assert.equal(scan.progress.candidates.unresolved, reopened ? 1 : 0);
          const coverage = await readSavedReviewState(deepScan.scanDir, state);
          const findings = await readJson(deepScan.scanDir, "findings.json");
          const deferred = coverage.deferred.filter(isWorkerCandidate);
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
            const decisions = coverage.surfaces.filter(isWorkerCandidate);
            assert.equal(decisions.length, reopened ? 0 : 1);
            if (!reopened) assert.equal(decisions[0].disposition, outcome);
          }
          for (const [name, bytes] of snapshots)
            assert.deepEqual(await readFile(path.join(output, name)), bytes);
          await workbench([
            "preserve-scan-results",
            "--scan-id",
            scanId,
            "--thread-id",
            "synthetic-parent-thread",
          ]);
        }
      });
    }
  }
}
