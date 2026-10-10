import assert from "node:assert/strict";
import { test } from "node:test";
import { promises as fs } from "node:fs";
import {
  mkdir,
  readFile,
  readdir,
  rm,
  utimes,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { importSource } from "./import-module.ts";
import { finding, scanId, workerDraft } from "./scan-draft-fixture.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import { readJson } from "./support/json.ts";

const { recordCodexSecurityWorkerScanDraft } = await importSource(
  new URL("../src/artifact-scan-draft.ts", import.meta.url).pathname,
);
const { recordCodexSecurityDeepReduction, getCodexSecurityDeepReducerInputs } =
  await importSource(
    new URL("../src/artifact-deep-reducer.ts", import.meta.url).pathname,
  );
const { archiveDirectory, createDeepScanArtifacts } = await importSource(
  new URL("../src/deep-scan/artifacts.ts", import.meta.url).pathname,
);
const { deepReductionScanDraft, validateReducerArtifacts } = await importSource(
  new URL("../src/deep-scan/artifact-validation.ts", import.meta.url).pathname,
);
const { unresolvedCandidates } = await importSource(
  new URL("../../../../sdk/typescript/src/candidates.ts", import.meta.url)
    .pathname,
);

async function fixture() {
  const root = await temporaryDirectory("deep-candidate-receipts-", true);
  const workerRoot = path.join(
    root,
    "artifacts",
    "deep_discovery",
    "workers",
    "worker-a",
  );
  const output = path.join(workerRoot, "output");
  const reducerRoot = path.join(
    root,
    "artifacts",
    "deep_discovery",
    "dedup",
    "reducer",
    "output",
  );
  await mkdir(output, { recursive: true });
  await mkdir(reducerRoot, { recursive: true });
  return {
    root,
    workerRoot,
    output,
    reducerRoot,
    worker: { root: output, repoRoot: root, layout: "worker", scanId },
    reducer: {
      root: reducerRoot,
      repoRoot: root,
      layout: "reducer",
      scanId,
      deepReducer: {
        scanRoot: root,
        claimedWorkers: [
          { id: "worker-a", resultPath: path.join(output, "result.json") },
        ],
      },
    },
  };
}

for (const receipt of [
  "original",
  "empty",
  "missing",
  "current-attempt",
  "other-attempt",
  "partial-valid-first",
  "partial-missing-first",
]) {
  test(`retained terminal receipt binds its original attempt: ${receipt}`, async () => {
    const f = await fixture();
    try {
      const ref = "artifacts/review.bin";
      const contents =
        receipt === "empty"
          ? Buffer.alloc(0)
          : Buffer.from([0, 255, 128, 10, 65]);
      const hasOriginal = [
        "original",
        "empty",
        "partial-valid-first",
        "partial-missing-first",
      ].includes(receipt);
      if (hasOriginal) {
        await mkdir(path.join(f.output, "artifacts"));
        await writeFile(path.join(f.output, ref), contents);
      }
      await recordCodexSecurityWorkerScanDraft(
        f.worker,
        workerDraft([], {
          complete: false,
          coverage: {
            completeness: "partial",
            surfaces: [
              {
                id: "decision",
                label: "Reviewed candidate",
                disposition: "rejected",
                candidateId: "candidate",
                receiptRefs:
                  receipt === "partial-valid-first"
                    ? [ref, "artifacts/missing.txt"]
                    : receipt === "partial-missing-first"
                      ? ["artifacts/missing.txt", ref]
                      : [ref],
              },
            ],
            explicitExclusions: [],
            deferred: [],
          },
        }),
      );
      const archive = path.join(f.workerRoot, "attempts", "attempt-01");
      await archiveDirectory(f.output, archive);
      const original = await readFile(path.join(archive, "result.json"));
      if (["current-attempt", "other-attempt"].includes(receipt)) {
        const wrongRoot =
          receipt === "current-attempt"
            ? f.output
            : path.join(f.workerRoot, "attempts", "attempt-02");
        await mkdir(path.join(wrongRoot, "artifacts"), { recursive: true });
        await writeFile(
          path.join(wrongRoot, ref),
          "Unrelated same-name receipt",
        );
      }
      await recordCodexSecurityWorkerScanDraft(f.worker, workerDraft([]));
      const current = await readJson(path.join(f.output, "result.json"));
      await recordCodexSecurityDeepReduction(f.reducer, {
        scanId,
        findings: [],
      });
      const published = deepReductionScanDraft(
        await readJson(path.join(f.reducerRoot, "result.json")),
      );
      const valid = ["original", "empty"].includes(receipt);
      assert.equal(
        unresolvedCandidates(published.coverage, published.findings).length,
        valid ? 0 : 1,
      );
      assert.equal(
        published.coverage.completeness,
        valid ? "complete" : "partial",
      );
      if (hasOriginal) {
        const retainedRef = current.coverage.surfaces.find(
          (row: any) => row.candidateId === "candidate",
        ).receiptRefs[0];
        assert.notEqual(retainedRef, ref);
        assert.deepEqual(
          await readFile(path.join(f.output, retainedRef)),
          contents,
        );
        assert.deepEqual(await readFile(path.join(archive, ref)), contents);
        await recordCodexSecurityWorkerScanDraft(f.worker, workerDraft([]));
        assert.equal(
          (
            await readJson(path.join(f.output, "result.json"))
          ).coverage.surfaces.find(
            (row: any) => row.candidateId === "candidate",
          ).receiptRefs[0],
          retainedRef,
        );
        await archiveDirectory(
          f.output,
          path.join(f.workerRoot, "attempts", "attempt-03"),
        );
        await recordCodexSecurityWorkerScanDraft(f.worker, workerDraft([]));
        const retried = await readJson(path.join(f.output, "result.json"));
        assert.equal(
          retried.coverage.surfaces.find(
            (row: any) => row.candidateId === "candidate",
          ).receiptRefs[0],
          retainedRef,
        );
        assert.deepEqual(
          await readFile(path.join(f.output, retainedRef)),
          contents,
        );
      }
      assert.deepEqual(
        await readFile(path.join(archive, "result.json")),
        original,
      );
    } finally {
      await rm(f.root, { recursive: true, force: true });
    }
  });
}

for (const savedGap of [false, true]) {
  test(`missing receipt retains all candidate evidence archives: saved gap=${savedGap}`, async () => {
    const f = await fixture();
    try {
      const oldCandidate = { evidence: "Earlier candidate proof" };
      const oldFinding = { summary: "Earlier finding proof" };
      await recordCodexSecurityWorkerScanDraft(
        f.worker,
        workerDraft([], {
          complete: false,
          coverage: {
            completeness: "partial",
            surfaces: [],
            explicitExclusions: [],
            deferred: [
              {
                candidateId: "candidate",
                reason: "Original gap",
                candidate: oldCandidate,
                previousFindings: [oldFinding],
              },
            ],
          },
        }),
      );
      await recordCodexSecurityWorkerScanDraft(
        f.worker,
        workerDraft([], {
          coverage: {
            completeness: "complete",
            surfaces: [
              {
                id: "decision",
                label: "Reviewed",
                disposition: "rejected",
                candidateId: "candidate",
                candidate: { evidence: "Latest candidate proof" },
                receiptRefs: ["artifacts/missing.txt"],
              },
            ],
            explicitExclusions: [],
            deferred: [],
          },
        }),
      );
      const resultPath = path.join(f.output, "result.json");
      const worker = await readJson(resultPath);
      assert.deepEqual(worker.coverage.surfaces[0].originalCandidates, [
        oldCandidate,
      ]);
      assert.deepEqual(worker.coverage.surfaces[0].previousFindings, [
        oldFinding,
      ]);
      if (savedGap) {
        worker.coverage.completeness = "partial";
        worker.coverage.deferred = [
          {
            candidateId: "candidate",
            reason: "Saved receipt gap",
            candidate: { evidence: "Independent saved proof" },
          },
        ];
        await writeFile(resultPath, JSON.stringify(worker));
      }
      const original = await readFile(resultPath);
      await recordCodexSecurityDeepReduction(f.reducer, {
        scanId,
        findings: [],
      });
      const saved = await readJson(path.join(f.reducerRoot, "result.json"));
      const pending = saved.unresolvedCandidates[0];
      assert.ok(
        pending.originalCandidates.some(
          (row: any) => row.evidence === oldCandidate.evidence,
        ),
      );
      assert.deepEqual(pending.previousFindings, [oldFinding]);
      if (savedGap) {
        assert.equal(pending.reason, "Saved receipt gap");
        assert.equal(pending.candidate.evidence, "Independent saved proof");
        assert.ok(
          pending.originalCandidates.some(
            (row: any) => row.evidence === "Latest candidate proof",
          ),
        );
      }
      const publication = deepReductionScanDraft(saved);
      assert.equal(
        unresolvedCandidates(publication.coverage, publication.findings).length,
        1,
      );
      assert.deepEqual(await readFile(resultPath), original);
    } finally {
      await rm(f.root, { recursive: true, force: true });
    }
  });
}

for (const mode of ["current", "previous", "merged"]) {
  for (const association of ["supported", "unsupported"]) {
    test(`reducer source candidate associations: ${mode}/${association}`, async () => {
      const f = await fixture();
      try {
        const originalFinding = {
          ...finding("confirmed", "src/confirmed.ts"),
          provenance: { source: "local_plugin", candidateId: "confirmed" },
        };
        await recordCodexSecurityWorkerScanDraft(
          f.worker,
          workerDraft([originalFinding]),
        );
        const originals = new Map([
          [
            f.reducer.deepReducer.claimedWorkers[0]!.resultPath,
            await readFile(path.join(f.output, "result.json")),
          ],
        ]);
        const pendingOwner = mode === "merged" ? "worker-c" : "worker-b";
        const otherOutput = path.join(
          path.dirname(f.workerRoot),
          pendingOwner,
          "output",
        );
        await mkdir(otherOutput, { recursive: true });
        const pendingId = mode === "merged" ? "confirmed" : "pending";
        await recordCodexSecurityWorkerScanDraft(
          { ...f.worker, root: otherOutput },
          workerDraft([], {
            coverage: {
              completeness: "partial",
              surfaces: [],
              explicitExclusions: [],
              deferred: [
                {
                  candidateId: pendingId,
                  reason: "Independent candidate proof gap",
                },
              ],
            },
          }),
        );
        const claimed = [
          ...f.reducer.deepReducer.claimedWorkers,
          {
            id: pendingOwner,
            resultPath: path.join(otherOutput, "result.json"),
          },
        ];
        let refs = ["worker-a:0"];
        if (mode === "merged") {
          const mergedOutput = path.join(
            path.dirname(f.workerRoot),
            "worker-b",
            "output",
          );
          await mkdir(mergedOutput, { recursive: true });
          await recordCodexSecurityWorkerScanDraft(
            { ...f.worker, root: mergedOutput },
            workerDraft([originalFinding]),
          );
          claimed.push({
            id: "worker-b",
            resultPath: path.join(mergedOutput, "result.json"),
          });
          refs.push("worker-b:0");
        }
        let previousReducerResultPath;
        if (mode === "previous") {
          const previousRoot = path.join(
            path.dirname(f.reducerRoot),
            "previous",
          );
          await mkdir(previousRoot);
          await recordCodexSecurityDeepReduction(
            { ...f.reducer, root: previousRoot },
            {
              scanId,
              findings: [
                {
                  ...originalFinding,
                  provenance: {
                    ...originalFinding.provenance,
                    sourceFindingIds: refs,
                  },
                },
              ],
            },
          );
          previousReducerResultPath = path.join(previousRoot, "result.json");
          originals.set(
            previousReducerResultPath,
            await readFile(previousReducerResultPath),
          );
          claimed.shift();
        }
        const submitted = {
          ...originalFinding,
          provenance: {
            ...originalFinding.provenance,
            candidateId:
              association === "unsupported" ? pendingId : "confirmed",
            sourceWorkerId:
              association === "unsupported"
                ? pendingOwner
                : mode === "merged"
                  ? "worker-b"
                  : "worker-a",
            sourceFindingIds: refs,
          },
        };
        await recordCodexSecurityDeepReduction(
          {
            ...f.reducer,
            deepReducer: {
              ...f.reducer.deepReducer,
              claimedWorkers: claimed,
              ...(previousReducerResultPath
                ? { previousReducerResultPath }
                : {}),
            },
          },
          { scanId, findings: [submitted] },
        );
        const saved = await readJson(path.join(f.reducerRoot, "result.json"));
        const projection = deepReductionScanDraft(saved);
        assert.equal(
          unresolvedCandidates(projection.coverage, projection.findings).length,
          1,
        );
        assert.equal(saved.findings[0].provenance.candidateId, "confirmed");
        assert.ok(
          ["worker-a", ...(mode === "merged" ? ["worker-b"] : [])].includes(
            saved.findings[0].provenance.sourceWorkerId,
          ),
        );
        if (association === "supported")
          assert.equal(
            saved.findings[0].provenance.sourceWorkerId,
            submitted.provenance.sourceWorkerId,
          );
        else
          assert.ok(
            saved.findings[0].provenance.previousFindings.some(
              (row: any) => row.provenance.sourceWorkerId === pendingOwner,
            ),
          );
        for (const [file, bytes] of originals)
          assert.deepEqual(await readFile(file), bytes);
      } finally {
        await rm(f.root, { recursive: true, force: true });
      }
    });
  }
}

for (const archived of [false, true]) {
  for (const ref of [
    "artifacts/review.txt",
    "artifacts/./review.txt",
    "artifacts//review.txt",
  ]) {
    test(`candidate receipt path aliases remain resolved: archived=${archived}, ref=${ref}`, async () => {
      const f = await fixture();
      try {
        const contents = Buffer.from([0, 255, 10, 65]);
        await mkdir(path.join(f.output, "artifacts"));
        await writeFile(path.join(f.output, "artifacts/review.txt"), contents);
        await recordCodexSecurityWorkerScanDraft(
          f.worker,
          workerDraft([], {
            coverage: {
              completeness: "complete",
              surfaces: [
                {
                  id: "decision",
                  label: "Reviewed candidate",
                  candidateId: "candidate",
                  disposition: "rejected",
                  receiptRefs: [ref],
                },
              ],
              explicitExclusions: [],
              deferred: [],
            },
          }),
        );
        const source = archived
          ? path.join(f.workerRoot, "attempts", "attempt-01")
          : f.output;
        if (archived) await archiveDirectory(f.output, source);
        const original = await readFile(path.join(source, "result.json"));
        if (archived)
          await recordCodexSecurityWorkerScanDraft(f.worker, workerDraft([]));
        await recordCodexSecurityDeepReduction(f.reducer, {
          scanId,
          findings: [],
        });
        const published = deepReductionScanDraft(
          await readJson(path.join(f.reducerRoot, "result.json")),
        );
        assert.equal(
          unresolvedCandidates(published.coverage, published.findings).length,
          0,
        );
        assert.equal(published.coverage.completeness, "complete");
        assert.deepEqual(
          await readFile(path.join(source, "result.json")),
          original,
        );
        assert.deepEqual(
          await readFile(path.join(source, "artifacts/review.txt")),
          contents,
        );
      } finally {
        await rm(f.root, { recursive: true, force: true });
      }
    });
  }
}

for (const archived of [false, true]) {
  for (const candidateId of [
    "review/auth",
    "review\\auth",
    "candidate-review",
  ]) {
    test(`recovered semantic candidate identity remains readable: archived=${archived}, id=${candidateId}`, async () => {
      const f = await fixture();
      try {
        await recordCodexSecurityWorkerScanDraft(
          f.worker,
          workerDraft([], {
            coverage: {
              completeness: "complete",
              surfaces: [
                {
                  id: "review",
                  label: "Reviewed candidate",
                  candidateId,
                  disposition: "rejected",
                  receiptRefs: ["artifacts/missing.txt"],
                },
              ],
              explicitExclusions: [],
              deferred: [],
            },
          }),
        );
        const source = archived
          ? path.join(f.workerRoot, "attempts", "attempt-01")
          : f.output;
        if (archived) await archiveDirectory(f.output, source);
        const original = await readFile(path.join(source, "result.json"));
        if (archived)
          await recordCodexSecurityWorkerScanDraft(f.worker, workerDraft([]));
        const sources = await getCodexSecurityDeepReducerInputs(f.reducer);
        await recordCodexSecurityDeepReduction(f.reducer, {
          scanId,
          findings: [],
        });
        const accepted = await validateReducerArtifacts(
          {
            artifacts: createDeepScanArtifacts(f.root),
            artifactDir: f.reducerRoot,
            resultPath: path.join(f.reducerRoot, "result.json"),
            reducerId: "reducer",
            sources,
          },
          scanId,
        );
        assert.equal(accepted.result.unresolvedCandidates.length, 1);
        assert.equal(
          accepted.result.unresolvedCandidates[0].candidateId,
          candidateId,
        );
        assert.equal(
          accepted.result.unresolvedCandidates[0].sourceWorkerId,
          "worker-a",
        );
        assert.deepEqual(
          await readFile(path.join(source, "result.json")),
          original,
        );
      } finally {
        await rm(f.root, { recursive: true, force: true });
      }
    });
  }
}

for (const outcome of [
  "pending",
  "finding",
  "decision",
  "valid-receipt",
] as const) {
  test(`archived receipt recovery retains finding evidence: ${outcome}`, async () => {
    const f = await fixture();
    try {
      const original = {
        ...finding("archived-proof", "src/handler.ts"),
        provenance: { source: "local_plugin", candidateId: "candidate" },
      };
      await recordCodexSecurityWorkerScanDraft(
        f.worker,
        workerDraft([original], { complete: true }),
      );
      const resultBytes = await readFile(path.join(f.output, "result.json"));
      for (const name of [
        "result.json",
        "checkpoint-head.json",
        ...(await readdir(path.join(f.output, "checkpoints"))).map((name) =>
          path.join("checkpoints", name),
        ),
      ])
        await utimes(path.join(f.output, name), 10, 10);
      const ref = "artifacts/decision.txt";
      if (outcome === "valid-receipt") {
        await mkdir(path.join(f.output, "artifacts"));
        await writeFile(
          path.join(f.output, ref),
          "Synthetic terminal evidence.\n",
        );
      }
      const terminal = workerDraft([], {
        complete: true,
        coverage: {
          completeness: "complete",
          surfaces: [
            {
              id: "review",
              candidateId: "candidate",
              label: "Synthetic review",
              disposition: "rejected",
              notes: "Review requires its saved receipt.",
              receiptRefs: [ref],
            },
          ],
          explicitExclusions: [],
          deferred: [],
        },
      });
      const rename = fs.rename;
      fs.rename = async (source, target) => {
        await rename(source, target);
        if (
          path.dirname(String(target)) === path.join(f.output, "checkpoints")
        ) {
          await utimes(target, 20, 20);
          throw new Error("interrupted after authored checkpoint");
        }
      };
      try {
        await assert.rejects(
          recordCodexSecurityWorkerScanDraft(f.worker, terminal),
          /interrupted after authored checkpoint/,
        );
      } finally {
        fs.rename = rename;
      }
      assert.deepEqual(
        await readFile(path.join(f.output, "result.json")),
        resultBytes,
      );
      const archive = path.join(f.workerRoot, "attempts", "attempt-01");
      await archiveDirectory(f.output, archive);
      const originals = await Promise.all(
        [
          "result.json",
          "checkpoint-head.json",
          ...(await readdir(path.join(archive, "checkpoints"))).map((name) =>
            path.join("checkpoints", name),
          ),
        ].map(
          async (name) =>
            [name, await readFile(path.join(archive, name))] as const,
        ),
      );
      const current = workerDraft(outcome === "finding" ? [original] : [], {
        complete: true,
      });
      if (outcome === "decision")
        (current.coverage.surfaces as Record<string, unknown>[]).push({
          id: "new-review",
          candidateId: "candidate",
          label: "New review",
          disposition: "not_applicable",
          notes: "A new review resolves this candidate.",
          receiptRefs: [],
        });
      await recordCodexSecurityWorkerScanDraft(f.worker, current);
      for (let retry = 0; retry < 2; retry++) {
        await recordCodexSecurityWorkerScanDraft(
          f.worker,
          workerDraft([], { complete: true }),
        );
        const saved = await readJson(path.join(f.output, "result.json"));
        const inputs = await getCodexSecurityDeepReducerInputs(f.reducer);
        await recordCodexSecurityDeepReduction(f.reducer, {
          scanId,
          findings: inputs.discoveries.flatMap(
            (input: any) => input.result.findings,
          ),
        });
        const reduced = deepReductionScanDraft(
          await readJson(path.join(f.reducerRoot, "result.json")),
        );
        for (const published of [saved, reduced]) {
          assert.equal(
            unresolvedCandidates(published.coverage, published.findings).length,
            outcome === "pending" ? 1 : 0,
          );
          if (outcome === "pending") {
            assert.equal(published.findings.length, 0);
            assert.deepEqual(
              published.coverage.deferred.find(
                (row: any) => row.candidateId === "candidate",
              ).finding,
              original,
            );
          }
          if (outcome === "finding") assert.equal(published.findings.length, 1);
          if (outcome === "decision" && published === saved)
            assert.ok(
              published.coverage.surfaces.some(
                (row: any) => row.disposition === "not_applicable",
              ),
            );
        }
        for (const [name, bytes] of originals)
          assert.deepEqual(await readFile(path.join(archive, name)), bytes);
      }
    } finally {
      await rm(f.root, { recursive: true, force: true });
    }
  });
}
