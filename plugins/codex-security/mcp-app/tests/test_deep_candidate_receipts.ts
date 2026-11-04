import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
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
import {
  mergeWorkerFiles,
  scanUnionToDraft,
  persistedScanUnion,
  parseScanUnion,
} from "./scan-union-fixture.ts";
import { finding, scanId, workerDraft } from "./scan-draft-fixture.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import { readJson } from "./support/json.ts";

const {
  recordCodexSecurityWorkerScanDraft,
  parseScanDraft,
  parsePersistedScanDraft,
} = await importSource(
  new URL("../src/artifact-scan-draft.ts", import.meta.url).pathname,
);
const { archiveDirectory } = await importSource(
  new URL("../src/deep-scan/artifacts.ts", import.meta.url).pathname,
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
  await mkdir(output, { recursive: true });
  const source = {
    id: "worker-a",
    resultPath: path.join(output, "result.json"),
  };
  return {
    root,
    workerRoot,
    output,
    source,
    worker: { root: output, repoRoot: root, layout: "worker", scanId },
    merge: () => mergeWorkerFiles(root, [source]),
  };
}

for (const archived of [false, true]) {
  for (const [label, refs, valid, disposition = "rejected"] of [
    ["object", { receipt: "artifacts/review.bin" }, false],
    ["null", null, false],
    ["number", 1, false],
    ["boolean", false, false],
    ["string", "artifacts/review.bin", false],
    ["null element", [null], false],
    ["object element", [{}], false],
    ["mixed elements", ["artifacts/review.bin", null], false],
    ["valid", ["artifacts/review.bin"], true],
    ["empty", [], true],
    ["absent", undefined, true],
    ["follow-up missing", ["artifacts/missing.bin"], false, "needs_follow_up"],
    ["omitted malformed", null, false, null],
  ] as const) {
    test(`accepted exclusion receipt metadata recovers: ${label}, archived=${archived}`, async () => {
      const f = await fixture();
      try {
        await mkdir(path.join(f.output, "artifacts"));
        await writeFile(
          path.join(f.output, "artifacts/review.bin"),
          "Synthetic receipt.",
        );
        const candidate = {
          evidence: "Retain the authored candidate evidence.",
        };
        const draft = workerDraft([], {
          complete: true,
          reviewState: {
            completeness: "complete",
            surfaces: [],
            explicitExclusions: [
              {
                candidateId: "candidate",
                pattern: "src/example.ts",
                reason: "Synthetic candidate decision.",
                ...(disposition === null ? {} : { disposition }),
                candidate,
                ...(refs === undefined ? {} : { receiptRefs: refs }),
              },
            ],
            deferred: [],
          },
        });
        for (const parse of [parseScanDraft, parsePersistedScanDraft])
          assert.deepEqual(
            parse(draft).reviewState.explicitExclusions[0].receiptRefs,
            refs,
          );
        await recordCodexSecurityWorkerScanDraft(f.worker, draft);
        const source = archived
          ? path.join(f.workerRoot, "attempts", "attempt-01")
          : f.output;
        if (archived) await archiveDirectory(f.output, source);
        const original = await readFile(path.join(source, "result.json"));
        const pending = JSON.parse(
          execFileSync(
            process.env.PYTHON?.trim() || "python3",
            [
              "-c",
              `import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from workbench_budget_candidates import recover_candidate_receipts
from candidate_identity import unresolved_candidates
root=Path(sys.argv[2]); draft=json.loads((root/'result.json').read_text()); warnings=[]
recovered=recover_candidate_receipts(draft,root,warnings)
print(json.dumps(unresolved_candidates(recovered['reviewState'],recovered['findings'])))`,
              path.join(import.meta.dirname, "../../scripts"),
              source,
            ],
            { encoding: "utf8" },
          ),
        );
        assert.equal(pending.length, valid ? 0 : 1);
        for (let replay = 0; replay < 2; replay++) {
          if (archived)
            await recordCodexSecurityWorkerScanDraft(f.worker, workerDraft([]));
          const saved = await f.merge();
          assert.equal(saved.unresolvedCandidates?.length ?? 0, valid ? 0 : 1);
          const published = scanUnionToDraft(saved);
          assert.equal(
            unresolvedCandidates(published.reviewState, published.findings)
              .length,
            valid ? 0 : 1,
          );
          if (!valid) {
            assert.deepEqual(
              saved.unresolvedCandidates[0].candidate,
              candidate,
            );
            assert.equal(published.reviewState.completeness, undefined);
          }
          assert.deepEqual(
            await readFile(path.join(source, "result.json")),
            original,
          );
        }
      } finally {
        await rm(f.root, { recursive: true, force: true });
      }
    });
  }
}

for (const receipt of [
  "original",
  "empty",
  "missing",
  "current-attempt",
  "other-attempt",
  "unrelated-parent",
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
      if (receipt === "unrelated-parent") {
        await writeFile(path.join(f.root, ref), "Unrelated same-name receipt");
      }
      await recordCodexSecurityWorkerScanDraft(
        f.worker,
        workerDraft([], {
          complete: false,
          reviewState: {
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
            explicitExclusions:
              receipt === "original" || receipt === "current-attempt"
                ? [
                    {
                      candidateId: "candidate",
                      pattern: "src/review.ts",
                      reason: "Archived decision.",
                      disposition: "rejected",
                      receiptRefs: [
                        `${path.relative(f.root, f.output).split(path.sep).join("/")}/${ref}`,
                      ],
                    },
                  ]
                : [],
            deferred: [],
          },
        }),
      );
      const archive = path.join(f.workerRoot, "attempts", "attempt-01");
      await archiveDirectory(f.output, archive);
      const original = await readFile(path.join(archive, "result.json"));
      if (["original", "current-attempt", "other-attempt"].includes(receipt)) {
        const wrongRoot =
          receipt !== "other-attempt"
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
      if (receipt === "original" || receipt === "current-attempt") {
        const [exclusion] = current.reviewState.explicitExclusions;
        if (receipt === "original")
          assert.deepEqual(
            await readFile(path.join(f.output, exclusion.receiptRefs[0])),
            contents,
          );
        else {
          assert.equal(exclusion.disposition, "needs_follow_up");
          assert.deepEqual(exclusion.receiptRefs, []);
        }
      }
      const published = scanUnionToDraft(await f.merge());
      const valid = ["original", "empty"].includes(receipt);
      assert.equal(
        unresolvedCandidates(published.reviewState, published.findings).length,
        valid ? 0 : 1,
      );
      assert.equal(published.reviewState.completeness, undefined);
      if (hasOriginal) {
        const retainedRef = current.reviewState.surfaces.find(
          (row: any) => row.candidateId === "candidate",
        ).receiptRefs[0];
        const retainedPath = path.join(f.root, retainedRef);
        assert.equal(
          path.dirname(retainedPath),
          path.join(f.output, "artifacts/retained-receipts"),
        );
        assert.deepEqual(await readFile(retainedPath), contents);
        assert.deepEqual(await readFile(path.join(archive, ref)), contents);
        await recordCodexSecurityWorkerScanDraft(f.worker, workerDraft([]));
        assert.equal(
          (
            await readJson(path.join(f.output, "result.json"))
          ).reviewState.surfaces.find(
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
          retried.reviewState.surfaces.find(
            (row: any) => row.candidateId === "candidate",
          ).receiptRefs[0],
          retainedRef,
        );
        assert.deepEqual(await readFile(retainedPath), contents);
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
          reviewState: {
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
          reviewState: {
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
      assert.deepEqual(worker.reviewState.surfaces[0].originalCandidates, [
        oldCandidate,
      ]);
      assert.deepEqual(worker.reviewState.surfaces[0].previousFindings, [
        oldFinding,
      ]);
      if (savedGap) {
        worker.reviewState.completeness = "partial";
        worker.reviewState.deferred = [
          {
            candidateId: "candidate",
            reason: "Saved receipt gap",
            candidate: { evidence: "Independent saved proof" },
          },
        ];
        await writeFile(resultPath, JSON.stringify(worker));
      }
      const original = await readFile(resultPath);
      const saved = await f.merge();
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
      const publication = scanUnionToDraft(saved);
      assert.equal(
        unresolvedCandidates(publication.reviewState, publication.findings)
          .length,
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
    test(`Deep Scan source candidate associations: ${mode}/${association}`, async () => {
      const f = await fixture();
      try {
        const originalFinding = {
          ...finding("confirmed", "src/confirmed.ts"),
          provenance: {
            source: "local_plugin",
            candidateId: "confirmed",
            ...(association === "unsupported" && {
              sourceWorkerId: mode === "merged" ? "worker-c" : "worker-b",
            }),
          },
        };
        await recordCodexSecurityWorkerScanDraft(
          f.worker,
          workerDraft([originalFinding]),
        );
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
            reviewState: {
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
          f.source,
          {
            id: pendingOwner,
            resultPath: path.join(otherOutput, "result.json"),
          },
        ];

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
        }
        const originals = await Promise.all(
          claimed.map(
            async ({ resultPath }) =>
              [resultPath, await readFile(resultPath)] as const,
          ),
        );
        let previous;
        if (mode === "previous") {
          previous = persistedScanUnion(await f.merge());
          claimed.shift();
        }
        const saved = await mergeWorkerFiles(f.root, claimed, previous);
        const projection = scanUnionToDraft(saved);
        assert.equal(
          unresolvedCandidates(projection.reviewState, projection.findings)
            .length,
          1,
        );
        assert.equal(saved.findings[0].provenance.candidateId, "confirmed");
        assert.equal(saved.findings[0].provenance.sourceWorkerId, "worker-a");
        assert.equal(
          saved.unresolvedCandidates[0].sourceWorkerId,
          pendingOwner,
        );
        assert.equal(saved.unresolvedCandidates[0].candidateId, pendingId);
        assert.deepEqual(
          saved.findings[0].provenance.sourceFindingIds,
          mode === "merged" ? ["worker-a:0", "worker-b:0"] : ["worker-a:0"],
        );
        if (association === "unsupported") {
          const history =
            saved.findings[0].provenance.sourceFindings[0].finding.provenance
              .previousFindings;
          assert.ok(
            history.some(
              (row: any) => row.provenance.sourceWorkerId === pendingOwner,
            ),
          );
        }
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
            reviewState: {
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
        const published = scanUnionToDraft(await f.merge());
        assert.equal(
          unresolvedCandidates(published.reviewState, published.findings)
            .length,
          0,
        );
        assert.equal(published.reviewState.completeness, undefined);
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
            reviewState: {
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
        const accepted = parseScanUnion(persistedScanUnion(await f.merge()));
        assert.equal(accepted.unresolvedCandidates.length, 1);
        assert.equal(accepted.unresolvedCandidates[0].candidateId, candidateId);
        assert.equal(
          accepted.unresolvedCandidates[0].sourceWorkerId,
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
        reviewState: {
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
        (current.reviewState.surfaces as Record<string, unknown>[]).push({
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
        const reduced = scanUnionToDraft(await f.merge());
        for (const published of [saved, reduced]) {
          assert.equal(
            unresolvedCandidates(published.reviewState, published.findings)
              .length,
            outcome === "pending" ? 1 : 0,
          );
          if (outcome === "pending") {
            assert.equal(published.findings.length, 0);
            assert.deepEqual(
              published.reviewState.deferred.find(
                (row: any) =>
                  (row.provenance?.candidateId ?? row.candidateId) ===
                  "candidate",
              ).finding,
              original,
            );
          }
          if (outcome === "finding") assert.equal(published.findings.length, 1);
          if (outcome === "decision" && published === saved)
            assert.ok(
              published.reviewState.surfaces.some(
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

for (const id of [7, { opaque: [1, null] }, "", " ", "metadata-id"]) {
  test(
    "exclusion IDs remain metadata during worker receipt recovery: " +
      JSON.stringify(id),
    async () => {
      const f = await fixture();
      try {
        const draft = workerDraft([], {
          complete: true,
          reviewState: {
            completeness: "partial",
            surfaces: [],
            deferred: [],
            explicitExclusions: [
              {
                id,
                pattern: "app.py",
                reason: "Synthetic decision.",
                candidateId: "candidate",
                disposition: "rejected",
                receiptRefs: ["artifacts/missing.bin"],
              },
            ],
          },
        });
        await recordCodexSecurityWorkerScanDraft(f.worker, draft);
        const original = await readFile(path.join(f.output, "result.json"));
        assert.deepEqual(
          JSON.parse(original.toString()).reviewState.explicitExclusions[0].id,
          id,
        );
        const { unresolvedCandidates: pending } = await f.merge();
        assert.equal(pending.length, 1);
        assert.equal(pending[0].candidateId, "candidate");
        assert.equal(pending[0].surfaceIds, undefined);
        assert.deepEqual(
          await readFile(path.join(f.output, "result.json")),
          original,
        );
      } finally {
        await rm(f.root, { recursive: true, force: true });
      }
    },
  );
}
