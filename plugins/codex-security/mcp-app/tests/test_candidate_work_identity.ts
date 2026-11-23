import {
  createTestWorkbench,
  discoverCandidate,
  importDiscoverySource,
  rememberCheckpoints,
  startDiffScan,
} from "./support/discovery.ts";
import { readJson, readSavedReviewState } from "./support/json.ts";
import assert from "node:assert/strict";
import { mkdir, rm, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import test, { type TestContext } from "node:test";
import { importSource } from "./import-module.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

const { createScanArtifactContext } = await importSource(
  "../src/artifact-context.ts",
  { absWorkingDir: import.meta.dirname },
);
const { recordCodexSecurityScanDraftViaWorkbench: record } = await importSource(
  "../src/artifact-scan-draft.ts",
  { absWorkingDir: import.meta.dirname },
);

const discoveryApi = await importDiscoverySource();
const { recordCodexSecurityCandidateValidations } = await importSource(
  "../src/artifact-candidate-ledger.ts",
  { absWorkingDir: import.meta.dirname },
);

async function diffFixture(t: TestContext) {
  const directory = await temporaryDirectory("candidate-work-identity-", true);
  t.after(() => rm(directory, { recursive: true, force: true }));
  const { scan, workbench } = await startDiffScan(directory);
  const context = await createScanArtifactContext(scan.scanId, workbench, {
    requireRunning: true,
    pluginRoot: path.resolve(
      import.meta.dirname,
      "../../../../sdk/typescript/_bundled_plugin",
    ),
  });
  const review = () =>
    readSavedReviewState(context.root, path.join(directory, "state"));
  return { context, scan, workbench, review };
}

type DiffFixture = Awaited<ReturnType<typeof diffFixture>>;

async function* recoveryStages({ context, scan, workbench }: DiffFixture) {
  const assertUnchanged = await rememberCheckpoints(context.root);
  yield "publication";
  for (const command of ["fail-scan", "preserve-scan-results"]) {
    await workbench([
      command,
      "--scan-id",
      scan.scanId,
      ...(command === "fail-scan"
        ? ["--message", "Synthetic interruption."]
        : []),
    ]);
    yield command;
  }
  await assertUnchanged();
}

for (const collision of [false, true]) {
  for (const missingReceipt of [false, true]) {
    for (const disposition of ["rejected", "not_applicable"] as const) {
      test(`candidate receipt recovery retains a general closure (collision=${collision}, missing=${missingReceipt}, disposition=${disposition})`, async (t) => {
        const directory = await temporaryDirectory(
          "candidate-work-identity-",
          true,
        );
        t.after(() => rm(directory, { recursive: true, force: true }));
        const target = path.join(directory, "target");
        await mkdir(target);
        await writeFile(path.join(target, "app.py"), "synthetic source\n");
        const workbench = await createTestWorkbench(directory);
        const { scan } = await workbench([
          "start-headless-standard-scan",
          "--thread-id",
          "synthetic-general-review",
          "--target-path",
          target,
          "--scope",
          ".",
          "--scan-root",
          path.join(directory, "scans"),
        ]);
        const context = await createScanArtifactContext(
          scan.scanId,
          workbench,
          {
            requireRunning: true,
          },
        );
        const first = await record(
          context,
          {
            scanId: scan.scanId,
            handoffClaimToken: context.handoffClaimToken,
            complete: false,
            findings: [],
            reviewState: {
              completeness: "partial",
              surfaces: [],
              explicitExclusions: [],
              deferred: [
                { id: "general-review", reason: "Independent general review." },
              ],
            },
          },
          workbench,
        );
        const generalId = first.reviewState.deferred[0]!.id;
        const closure = {
          id: generalId,
          reason: "Independent general review completed.",
        };
        const receipt = path.join(context.root, "artifacts/receipt.txt");
        await mkdir(path.dirname(receipt), { recursive: true });
        await writeFile(receipt, "Synthetic candidate review evidence.\n");
        await record(
          context,
          {
            scanId: scan.scanId,
            handoffClaimToken: context.handoffClaimToken,
            complete: true,
            findings: [],
            reviewState: {
              completeness: "complete",
              surfaces: [
                {
                  id: "candidate-decision",
                  label: "Candidate review",
                  candidateId: collision ? generalId : "candidate-review",
                  disposition,
                  notes: "Candidate review completed separately.",
                  receiptRefs: ["artifacts/receipt.txt"],
                },
              ],
              explicitExclusions: [],
              deferred: [],
              resolvedDeferred: [closure],
            },
          },
          workbench,
        );
        if (missingReceipt) await unlink(receipt);
        await workbench([
          "prepare-scan-completion",
          "--scan-id",
          scan.scanId,
          "--claim-token",
          context.handoffClaimToken!,
        ]);
        const coverage = await readSavedReviewState(
          context.root,
          path.join(directory, "state"),
        );
        assert.deepEqual(coverage.resolvedDeferred, [closure]);
        const manifest = await readJson(context.root, "scan-manifest.json");
        const pending = manifest.scan.review.unresolvedCandidates ?? [];
        assert.equal(pending.length, missingReceipt ? 1 : 0);
        if (missingReceipt)
          assert.equal(
            pending[0].candidateId,
            collision ? generalId : "candidate-review",
          );
        await workbench([
          "prepare-scan-completion",
          "--scan-id",
          scan.scanId,
          "--claim-token",
          context.handoffClaimToken!,
        ]);
        assert.deepEqual(
          await readSavedReviewState(
            context.root,
            path.join(directory, "state"),
          ),
          coverage,
        );
      });
    }
  }
}

for (const collision of [false, true]) {
  test(`later Diff discovery preserves an already requested generic closure (collision=${collision})`, async (t) => {
    const f = await diffFixture(t);
    const { context, scan, workbench } = f;
    const candidateId = "candidate-3c527b024e10b356";
    const task = {
      id: collision ? candidateId : "general-review",
      reason: "Independent generic review task.",
    };
    const draft = {
      scanId: scan.scanId,
      handoffClaimToken: context.handoffClaimToken,
      complete: false,
      findings: [],
      reviewState: {
        completeness: "partial",
        surfaces: [],
        explicitExclusions: [],
        deferred: [task],
      },
    };
    await record(context, draft, workbench);
    assert.equal(await discoverCandidate(discoveryApi, context), candidateId);
    const closure = {
      id: task.id,
      reason: "Independent generic task completed.",
    };
    await record(
      context,
      {
        ...draft,
        complete: true,
        reviewState: {
          ...draft.reviewState,
          completeness: "complete",
          deferred: [],
          resolvedDeferred: [closure],
        },
      },
      workbench,
    );
    for await (const stage of recoveryStages(f)) {
      const coverage = await f.review();
      assert.deepEqual(
        coverage.resolvedDeferred,
        [closure],
        `closure survives ${stage}`,
      );
      const pending = coverage.deferred.filter(
        (row: { candidateId?: string }) => row.candidateId === candidateId,
      );
      assert.equal(pending.length, 1);
      assert.notEqual(pending[0].id, closure.id);
    }
  });
}

for (const collision of [false, true]) {
  for (const sourceWorkerId of [undefined, "imported-owner"]) {
    test(`candidate dismissal preserves an independent surface: collision=${collision}, owner=${sourceWorkerId}`, async (t) => {
      const f = await diffFixture(t);
      const { context, scan, workbench } = f;
      const candidateId = "candidate-3c527b024e10b356";
      const surface = {
        id: collision ? candidateId : "independent-review",
        label: "Independent directory review",
        disposition: "needs_follow_up",
        notes: "Unrelated independent coverage is unfinished.",
        receiptRefs: [],
        ...(sourceWorkerId === undefined ? {} : { sourceWorkerId }),
      };
      const draft = {
        scanId: scan.scanId,
        handoffClaimToken: context.handoffClaimToken,
        complete: false,
        findings: [],
        reviewState: {
          completeness: "partial",
          surfaces: [surface],
          explicitExclusions: [],
          deferred: [],
        },
      };
      await record(context, draft, workbench);
      assert.equal(await discoverCandidate(discoveryApi, context), candidateId);
      await recordCodexSecurityCandidateValidations(context, {
        validations: [
          {
            candidateId,
            validation: {
              disposition: "suppressed",
              method: "Static inspection",
              confidence: "high",
              confidence_rationale: "Synthetic evidence",
              rubric: "Synthetic criterion",
              evidence: "Candidate dismissed.",
              counterevidence_or_proof_gap: "Synthetic counterevidence.",
              remaining_uncertainty: "",
            },
          },
        ],
      });
      await record(
        context,
        {
          ...draft,
          complete: true,
          reviewState: {
            ...draft.reviewState,
            completeness: "complete",
            surfaces: [],
          },
        },
        workbench,
      );
      for await (const stage of recoveryStages(f)) {
        const coverage = await f.review();
        assert.deepEqual(
          coverage.surfaces.find(
            (row: { id: string }) => row.id === surface.id,
          ),
          surface,
          stage,
        );
        assert.equal(coverage.completeness, undefined, stage);
        const decisions = coverage.surfaces.filter(
          (row: { candidateId?: string }) => row.candidateId === candidateId,
        );
        assert.equal(decisions.length, 1, stage);
        assert.equal(decisions[0].disposition, "rejected", stage);
        assert.equal(
          coverage.deferred.filter(
            (row: { candidateId?: string }) => row.candidateId === candidateId,
          ).length,
          0,
          stage,
        );
      }
    });
  }
}

for (const shared of [false, true]) {
  for (const disposition of ["rejected", "not_applicable"] as const) {
    test(`accepted Diff finding retains shared terminal surface evidence: shared=${shared}, disposition=${disposition}`, async (t) => {
      const f = await diffFixture(t);
      const { context, scan, workbench } = f;
      const discovery = path.join(context.root, "artifacts/02_discovery");
      await mkdir(discovery, { recursive: true });
      await writeFile(path.join(discovery, "in_scope_files.txt"), "app.ts\n");
      await discoveryApi.recordCodexSecurityDiscoveryCandidates(
        {
          candidates: ["a", "b"].map((instance) => ({
            cwe_ids: [],
            locations: [
              { path: "app.ts", start_line: 1, end_line: 1, role: "evidence" },
            ],
            instance,
            summary: `Candidate ${instance}`,
            evidence: `Evidence ${instance}`,
          })),
        },
        context,
      );
      const listed = await discoveryApi.listCodexSecurityCandidates(
        {},
        context,
      );
      assert.equal(listed.rows.length, 2);
      const acceptedId = listed.rows.find(
        (row: { summary: string }) => row.summary === "Candidate a",
      )!.candidate_id;
      const pendingId = listed.rows.find(
        (row: { summary: string }) => row.summary === "Candidate b",
      )!.candidate_id;
      const receipt = "artifacts/proof/shared.txt";
      await mkdir(path.join(context.root, "artifacts/proof"), {
        recursive: true,
      });
      await writeFile(
        path.join(context.root, receipt),
        "Synthetic shared evidence.\n",
      );
      const surface = {
        id: "shared",
        candidateId: acceptedId,
        label: "Shared candidate evidence",
        disposition,
        notes: "This evidence is also needed by candidate b.",
        receiptRefs: [receipt],
      };
      await record(
        context,
        {
          scanId: scan.scanId,
          handoffClaimToken: context.handoffClaimToken,
          complete: true,
          findings: [
            {
              ruleId: "synthetic-review",
              title: "Synthetic finding",
              summary: "Synthetic evidence",
              taxonomy: { category: "synthetic", cwe: [] },
              severity: { level: "low" },
              confidence: { level: "high", rationale: "Synthetic evidence" },
              locations: [{ path: "app.ts", startLine: 1 }],
              remediation: "Apply synthetic fix",
              provenance: { source: "local_plugin", candidateId: acceptedId },
            },
          ],
          reviewState: {
            completeness: "partial",
            surfaces: [surface],
            explicitExclusions: [],
            deferred: [
              {
                id: "b-work",
                candidateId: pendingId,
                reason: "Candidate b review remains.",
                ...(shared ? { surfaceIds: [surface.id] } : {}),
              },
            ],
          },
        },
        workbench,
      );
      for await (const stage of recoveryStages(f)) {
        const coverage = await f.review();
        const findings = await readJson(context.root, "findings.json");
        const retained = coverage.surfaces.find(
          (row: { id: string }) => row.id === surface.id,
        );
        assert.equal(
          Boolean(retained),
          shared,
          `shared evidence survives ${stage}`,
        );
        const pending = coverage.deferred.filter(
          (row: { candidateId?: string }) => row.candidateId === pendingId,
        );
        assert.equal(pending.length, 1, stage);
        assert.equal(
          findings.findings.filter(
            (row: { provenance: { candidateId?: string } }) =>
              row.provenance.candidateId === acceptedId,
          ).length,
          1,
          stage,
        );
        if (shared) {
          assert.equal(retained.disposition, "reported", stage);
          assert.equal(retained.notes, surface.notes, stage);
          assert.deepEqual(retained.receiptRefs, surface.receiptRefs, stage);
          assert.ok(pending[0].surfaceIds.includes(retained.id), stage);
        }
      }
    });
  }
}
