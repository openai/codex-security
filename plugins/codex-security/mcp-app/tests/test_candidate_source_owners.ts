import assert from "node:assert/strict";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import { importSource } from "./import-module.ts";
import { finding, scanId, workerDraft } from "./scan-draft-fixture.ts";
import { readJson } from "./support/json.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

const { recordCodexSecurityWorkerScanDraft } = await importSource(
  "../src/artifact-scan-draft.ts",
  { absWorkingDir: import.meta.dirname },
);
const { getCodexSecurityDeepReducerInputs, recordCodexSecurityDeepReduction } =
  await importSource("../src/artifact-deep-reducer.ts", {
    absWorkingDir: import.meta.dirname,
  });
const { validateReducerArtifacts } = await importSource(
  "../src/deep-scan/artifact-validation.ts",
  { absWorkingDir: import.meta.dirname },
);
const { createDeepScanArtifacts } = await importSource(
  "../src/deep-scan/artifacts.ts",
  { absWorkingDir: import.meta.dirname },
);

const cases = [
  ...["origin:a", "opaque-ref", "previous:0", "saved-worker:0"].flatMap(
    (reference) =>
      [false, true].map((reopened) => ({
        reference,
        reopened,
        owner: "saved-worker" as string | undefined,
        currentWorker: undefined as string | undefined,
      })),
  ),
  ...["origin", "previous"].flatMap((currentWorker) =>
    [
      { owner: "saved-worker", reopened: false },
      { owner: "saved-worker", reopened: true },
      { owner: undefined, reopened: false },
    ].map((state) => ({
      ...state,
      reference: `${currentWorker}:a`,
      currentWorker,
    })),
  ),
];

for (const { reference, reopened, owner, currentWorker } of cases) {
  test(`resumed reducer preserves ${reference}, owner=${owner}, current=${currentWorker}, reopened=${reopened}`, async (t) => {
    const root = await temporaryDirectory("candidate-source-owner-", true);
    t.after(() => rm(root, { recursive: true, force: true }));
    const artifacts = createDeepScanArtifacts(root);
    await mkdir(artifacts.dedupRoot, { recursive: true });
    const original = {
      ...finding("candidate-one", "app.py"),
      provenance: {
        source: "local_plugin",
        candidateId: "candidate-one",
        ...(owner === undefined ? {} : { sourceWorkerId: owner }),
      },
    };
    // Persisted references are opaque; older accepted aggregates retain them.
    let previousPath = path.join(artifacts.dedupRoot, "previous.json");
    await writeFile(
      previousPath,
      JSON.stringify({
        scanId,
        findings: [
          {
            ...original,
            provenance: {
              ...original.provenance,
              sourceFindingIds: [reference],
              sourceFindings: [{ id: reference, finding: original }],
            },
          },
        ],
      }),
    );
    await validateReducerArtifacts(
      {
        artifacts,
        artifactDir: artifacts.dedupRoot,
        resultPath: previousPath,
        reducerId: "previous",
      },
      scanId,
    );
    const retained = new Map<string, Buffer>();
    retained.set(previousPath, await readFile(previousPath));
    for (let round = 0; round < 2; round++) {
      const workers =
        round === 0
          ? [
              currentWorker ?? (reopened ? "saved-worker" : "next-worker"),
              ...(currentWorker && reopened ? ["saved-worker"] : []),
            ]
          : ["last-worker"];
      const claimedWorkers = [];
      for (const workerId of workers) {
        const workerRoot = path.join(artifacts.workersRoot, workerId, "output");
        await mkdir(workerRoot, { recursive: true });
        const pending = reopened && workerId === "saved-worker";
        await recordCodexSecurityWorkerScanDraft(
          { root: workerRoot, repoRoot: root, scanId, layout: "worker" },
          workerDraft(
            workerId === currentWorker
              ? [
                  {
                    ...finding("candidate-two", "other.py"),
                    provenance: {
                      source: "local_plugin",
                      candidateId: "candidate-two",
                      sourceWorkerId: "imported-owner",
                    },
                  },
                ]
              : [],
            {
              complete: true,
              coverage: {
                completeness: pending ? "partial" : "complete",
                surfaces: [],
                explicitExclusions: [],
                deferred: pending
                  ? [
                      {
                        id: "proof-gap",
                        candidateId: "candidate-one",
                        reason: "Synthetic additional review required.",
                      },
                    ]
                  : [],
              },
            },
          ),
        );
        const resultPath = path.join(workerRoot, "result.json");
        retained.set(resultPath, await readFile(resultPath));
        claimedWorkers.push({ id: workerId, resultPath });
      }
      const reducerRoot = path.join(
        artifacts.dedupRoot,
        `round-${round}`,
        "output",
      );
      await mkdir(reducerRoot, { recursive: true });
      const context = {
        root: reducerRoot,
        repoRoot: root,
        scanId,
        layout: "reducer" as const,
        deepReducer: {
          scanRoot: root,
          claimedWorkers,
          previousReducerResultPath: previousPath,
        },
      };
      const inputs = await getCodexSecurityDeepReducerInputs(context);
      await recordCodexSecurityDeepReduction(context, {
        scanId,
        findings: [
          ...inputs.previous.findings,
          ...inputs.discoveries.flatMap(
            (source: { result: { findings: Record<string, unknown>[] } }) =>
              source.result.findings,
          ),
        ].map((row: Record<string, unknown>) => {
          const result = structuredClone(row);
          const provenance = result.provenance as Record<string, unknown>;
          delete provenance.sourceFindings;
          delete provenance.previousFindings;
          return result;
        }),
      });
      const resultPath = path.join(reducerRoot, "result.json");
      await validateReducerArtifacts(
        {
          artifacts,
          artifactDir: reducerRoot,
          resultPath,
          reducerId: `round-${round}`,
          previousReducerResultPath: previousPath,
          sources: inputs,
        },
        scanId,
      );
      const saved = await readJson(resultPath);
      assert.equal(saved.findings.length, currentWorker ? 2 : 1);
      assert.equal(saved.findings[0].provenance.candidateId, "candidate-one");
      assert.equal(saved.findings[0].provenance.sourceWorkerId, owner);
      assert.equal(
        saved.findings[0].provenance.candidateReopened === true,
        reopened,
      );
      assert.deepEqual(saved.findings[0].provenance.sourceFindingIds, [
        reference,
      ]);
      assert.deepEqual(saved.findings[0].provenance.sourceFindings, [
        { id: reference, finding: original },
      ]);
      if (currentWorker) {
        const current = saved.findings[1];
        assert.equal(current.provenance.candidateId, "candidate-two");
        assert.equal(current.provenance.sourceWorkerId, currentWorker);
        assert.equal(current.provenance.candidateReopened === true, false);
        assert.deepEqual(current.provenance.sourceFindingIds, [
          `${currentWorker}:0`,
        ]);
        assert.equal(
          current.provenance.sourceFindings[0].finding.provenance
            .sourceWorkerId,
          currentWorker,
        );
        assert.equal(
          current.provenance.sourceFindings[0].finding.provenance.previousFindings.some(
            (row: { provenance: { sourceWorkerId?: string } }) =>
              row.provenance.sourceWorkerId === "imported-owner",
          ),
          true,
        );
      }
      assert.equal((saved.unresolvedCandidates ?? []).length, Number(reopened));
      if (reopened)
        assert.equal(
          saved.unresolvedCandidates[0].sourceWorkerId,
          "saved-worker",
        );
      for (const [file, bytes] of retained)
        assert.deepEqual(await readFile(file), bytes);
      retained.set(resultPath, await readFile(resultPath));
      previousPath = resultPath;
    }
  });
}
