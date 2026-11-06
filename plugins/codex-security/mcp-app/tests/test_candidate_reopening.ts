import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
import { importSource } from "./import-module.ts";
import {
  draftApi,
  fixture,
  recordCodexSecurityScanDraft,
} from "./scan-draft-recovery-fixture.ts";
import { finding } from "./scan-draft-fixture.ts";
import { readSavedReviewState, readJson } from "./support/json.ts";

const execFileAsync = promisify(execFile);
const { createScanArtifactContext } = await importSource(
  "../src/artifact-context.ts",
  { absWorkingDir: import.meta.dirname },
);
import { mergeWorkerFiles, scanUnionToDraft } from "./scan-union-fixture.ts";

for (const mode of ["standard", "worker"] as const) {
  for (const scenario of [
    "same-publication",
    "later-pending",
    "later-resolved",
    "other-candidate",
  ] as const) {
    test(`publishes explicit candidate state through ${mode}: ${scenario}`, async (t) => {
      const f = await fixture(t, mode);
      const directory = path.dirname(f.root);
      const target = path.join(directory, "target");
      const home = path.join(directory, "home");
      const state = path.join(directory, "state");
      await mkdir(target);
      await writeFile(path.join(target, "app.py"), "synthetic source\n");
      await mkdir(home, { mode: 0o700 });
      const workbench = async (args: string[]) => {
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
      const current = {
        ...finding("review", "app.py"),
        provenance: { source: "local_plugin", candidateId: "candidate-one" },
      };
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
