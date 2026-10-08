import assert from "node:assert/strict";
import { mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { importSource } from "./import-module.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import { workerDraft, scanId, finding } from "./scan-draft-fixture.ts";

const source = fileURLToPath(new URL("../src", import.meta.url));
const {
  recordCodexSecurityWorkerScanDraft,
  parsePersistedScanDraft,
  saveScanDraftCheckpoint,
  readArchivedWorkerCheckpoints,
} = await importSource(path.join(source, "artifact-scan-draft.ts"));
const { readDeepReductionSources, recordCodexSecurityDeepReduction } =
  await importSource(path.join(source, "artifact-deep-reducer.ts"));
const { validateDiscoveryArtifacts } = await importSource(
  path.join(source, "deep-scan/artifact-validation.ts"),
);
const { archiveDirectory } = await importSource(
  path.join(source, "deep-scan/artifacts.ts"),
);

async function fixture() {
  const root = await temporaryDirectory("deep-reducer-coverage-history-", true);
  const scanRoot = path.join(root, "scan");
  const workerRoot = path.join(
    scanRoot,
    "artifacts/deep_discovery/workers/discovery-0001",
  );
  const output = path.join(workerRoot, "output");
  await mkdir(output, { recursive: true });
  const resultPath = path.join(output, "result.json");
  const reducerRoot = path.join(
    scanRoot,
    "artifacts/deep_discovery/dedup/dedup-0001/output",
  );
  await mkdir(reducerRoot, { recursive: true });
  const workerContext = {
    root: output,
    repoRoot: root,
    scanId,
    layout: "worker",
  };
  const context = {
    root: reducerRoot,
    repoRoot: root,
    scanId,
    layout: "reducer",
    deepReducer: {
      scanRoot,
      persistSourceCoverage: true,
      claimedWorkers: [{ id: "synthetic-worker", attempt: 2, resultPath }],
    },
  };
  return {
    root,
    scanRoot,
    workerRoot,
    output,
    resultPath,
    reducerRoot,
    workerContext,
    context,
  };
}

for (const close of [false, true]) {
  test(`accepted worker ${close ? "closure" : "pending control"} survives actual reducer publication`, async () => {
    const f = await fixture();
    try {
      const pending = {
        id: "review",
        reason: "Synthetic review still needs evidence.",
      };
      await recordCodexSecurityWorkerScanDraft(
        f.workerContext,
        workerDraft([], {
          complete: false,
          coverage: {
            completeness: "partial",
            surfaces: [],
            explicitExclusions: [],
            deferred: [pending],
          },
        }),
      );
      await recordCodexSecurityWorkerScanDraft(
        f.workerContext,
        workerDraft([], {
          complete: true,
          coverage: {
            completeness: close ? "complete" : "partial",
            surfaces: [],
            explicitExclusions: [],
            deferred: close ? [] : [pending],
            ...(close
              ? {
                  resolvedDeferred: [
                    { id: "review", reason: "Synthetic review completed." },
                  ],
                }
              : {}),
          },
        }),
      );
      const original = await readFile(f.resultPath);
      const accepted = parsePersistedScanDraft(JSON.parse(original.toString()));
      if (close) assert.equal(accepted.coverage.resolvedDeferred.length, 1);
      await validateDiscoveryArtifacts(
        { workersRoot: path.dirname(f.workerRoot) },
        f.resultPath,
        scanId,
      );
      await recordCodexSecurityDeepReduction(f.context, {
        scanId,
        complete: true,
        findings: [],
      });
      const persisted = JSON.parse(
        await readFile(path.join(f.reducerRoot, "result.json"), "utf8"),
      );
      parsePersistedScanDraft({
        scanId,
        complete: true,
        findings: [],
        coverage: persisted.sourceCoverage,
      });
      if (close) {
        assert.equal(persisted.sourceCoverage.resolvedDeferred?.length, 1);
        assert.equal(
          persisted.sourceCoverage.resolvedDeferred[0].id,
          "synthetic-worker-attempt-2-resolved-review",
        );
        assert.equal(
          persisted.sourceCoverage.resolvedDeferred[0].reason,
          "Synthetic review completed.",
        );
        assert.equal(persisted.sourceCoverage.deferred.length, 0);
      } else {
        assert.equal(persisted.sourceCoverage.deferred.length, 1);
        assert.equal(persisted.sourceCoverage.resolvedDeferred?.length ?? 0, 0);
      }
      assert.deepEqual(await readFile(f.resultPath), original);
    } finally {
      await rm(f.root, { recursive: true, force: true });
    }
  });
}

for (const direct of [false, true]) {
  for (const changed of [false, true]) {
    test(`retry closure keeps its originating attempt, direct=${direct}, changed=${changed}`, async () => {
      const f = await fixture();
      try {
        await recordCodexSecurityWorkerScanDraft(
          f.workerContext,
          workerDraft([], {
            complete: false,
            coverage: {
              completeness: "partial",
              surfaces: [],
              explicitExclusions: [],
              deferred: [{ id: "review", reason: "Synthetic pending review." }],
            },
          }),
        );
        await recordCodexSecurityWorkerScanDraft(
          f.workerContext,
          workerDraft([], {
            complete: true,
            coverage: {
              completeness: "complete",
              surfaces: [],
              explicitExclusions: [],
              deferred: [],
              resolvedDeferred: [{ id: "review", reason: "Original closure." }],
            },
          }),
        );
        const archive = path.join(f.workerRoot, "attempts/attempt-01");
        await archiveDirectory(f.output, archive);
        const historical = await readFile(path.join(archive, "result.json"));
        await mkdir(f.output, { recursive: true });
        const current = workerDraft([], { complete: true });
        if (changed)
          Object.assign(current.coverage, {
            resolvedDeferred: [{ id: "review", reason: "Updated closure." }],
          });
        if (direct) await writeFile(f.resultPath, JSON.stringify(current));
        else await recordCodexSecurityWorkerScanDraft(f.workerContext, current);
        const original = await readFile(f.resultPath);
        await recordCodexSecurityDeepReduction(f.context, {
          scanId,
          complete: true,
          findings: [],
        });
        const { sourceCoverage } = JSON.parse(
          await readFile(path.join(f.reducerRoot, "result.json"), "utf8"),
        );
        parsePersistedScanDraft({
          scanId,
          complete: true,
          findings: [],
          coverage: sourceCoverage,
        });
        const attempt = changed ? 2 : 1;
        assert.deepEqual(sourceCoverage.resolvedDeferred, [
          {
            id: `synthetic-worker-attempt-${attempt}-resolved-review`,
            reason: changed ? "Updated closure." : "Original closure.",
          },
        ]);
        assert.ok(
          sourceCoverage.reviews.some(
            (review: { attempt: number }) => review.attempt === attempt,
          ),
        );
        assert.equal(sourceCoverage.deferred.length, 0);
        assert.deepEqual(await readFile(f.resultPath), original);
        assert.deepEqual(
          await readFile(path.join(archive, "result.json")),
          historical,
        );
      } finally {
        await rm(f.root, { recursive: true, force: true });
      }
    });
  }
}

for (const direct of [false, true]) {
  test(`${direct ? "accepted direct-file" : "worker recording control"} retry retains archived-only observations`, async () => {
    const f = await fixture();
    try {
      await recordCodexSecurityWorkerScanDraft(
        f.workerContext,
        workerDraft([], {
          complete: false,
          coverage: {
            completeness: "partial",
            surfaces: [
              {
                id: "saved-surface",
                label: "Synthetic archived-only surface",
                disposition: "needs_follow_up",
                receiptRefs: [],
              },
            ],
            explicitExclusions: [
              {
                pattern: "synthetic-excluded/**",
                reason: "Synthetic archived exclusion.",
              },
            ],
            deferred: [
              {
                id: "saved-task",
                reason: "Synthetic archived proof remains.",
                surfaceIds: ["saved-surface"],
              },
            ],
          },
        }),
      );
      const archive = path.join(f.workerRoot, "attempts/attempt-01");
      await archiveDirectory(f.output, archive);
      const historical = await readFile(path.join(archive, "result.json"));
      await mkdir(f.output, { recursive: true });
      const completed = workerDraft([], { complete: true });
      if (direct) await writeFile(f.resultPath, JSON.stringify(completed));
      else await recordCodexSecurityWorkerScanDraft(f.workerContext, completed);
      const current = await readFile(f.resultPath);
      await validateDiscoveryArtifacts(
        { workersRoot: path.dirname(f.workerRoot) },
        f.resultPath,
        scanId,
      );
      const inputs = await readDeepReductionSources(f.context);
      const coverage = inputs.discoveries[0].coverage;
      assert.equal(coverage.surfaces.length, 1);
      assert.equal(coverage.explicitExclusions.length, 1);
      assert.equal(coverage.deferred.length, 1);
      for (const field of ["surfaces", "explicitExclusions", "deferred"])
        assert.equal(coverage[field][0].provenance.attempt, 1);
      assert.deepEqual(
        new Set(coverage.deferred[0].surfaceIds),
        new Set(coverage.surfaces.map((row: { id: string }) => row.id)),
      );
      assert.deepEqual(await readFile(f.resultPath), current);
      assert.deepEqual(
        await readFile(path.join(archive, "result.json")),
        historical,
      );
    } finally {
      await rm(f.root, { recursive: true, force: true });
    }
  });
}

test("one worker closure retains another worker's same-named pending review", async () => {
  const f = await fixture();
  try {
    const pending = {
      id: "shared-review",
      reason: "Synthetic independent review remains.",
    };
    await recordCodexSecurityWorkerScanDraft(
      f.workerContext,
      workerDraft([], {
        complete: false,
        coverage: {
          completeness: "partial",
          surfaces: [],
          explicitExclusions: [],
          deferred: [pending],
        },
      }),
    );
    await recordCodexSecurityWorkerScanDraft(
      f.workerContext,
      workerDraft([], {
        complete: true,
        coverage: {
          completeness: "complete",
          surfaces: [],
          explicitExclusions: [],
          deferred: [],
          resolvedDeferred: [
            {
              id: pending.id,
              reason: "Synthetic first worker review completed.",
            },
          ],
        },
      }),
    );
    const secondOutput = path.join(
      f.scanRoot,
      "artifacts/deep_discovery/workers/discovery-0002/output",
    );
    await mkdir(secondOutput, { recursive: true });
    const secondResult = path.join(secondOutput, "result.json");
    await recordCodexSecurityWorkerScanDraft(
      { ...f.workerContext, root: secondOutput },
      workerDraft([], {
        complete: true,
        coverage: {
          completeness: "partial",
          surfaces: [],
          explicitExclusions: [],
          deferred: [pending],
        },
      }),
    );
    f.context.deepReducer.claimedWorkers.push({
      id: "independent-worker",
      attempt: 1,
      resultPath: secondResult,
    });
    const originals = await Promise.all([
      readFile(f.resultPath),
      readFile(secondResult),
    ]);
    for (const result of [f.resultPath, secondResult])
      await validateDiscoveryArtifacts(
        { workersRoot: path.dirname(f.workerRoot) },
        result,
        scanId,
      );
    await recordCodexSecurityDeepReduction(f.context, {
      scanId,
      complete: true,
      findings: [],
    });
    const persisted = JSON.parse(
      await readFile(path.join(f.reducerRoot, "result.json"), "utf8"),
    );
    parsePersistedScanDraft({
      scanId,
      complete: true,
      findings: [],
      coverage: persisted.sourceCoverage,
    });
    assert.equal(persisted.sourceCoverage.resolvedDeferred?.length, 1);
    assert.equal(persisted.sourceCoverage.deferred.length, 1);
    assert.equal(
      persisted.sourceCoverage.deferred[0].provenance.workerId,
      "independent-worker",
    );
    assert.notEqual(
      persisted.sourceCoverage.resolvedDeferred[0].id,
      persisted.sourceCoverage.deferred[0].id,
    );
    assert.deepEqual(
      await Promise.all([readFile(f.resultPath), readFile(secondResult)]),
      originals,
    );
  } finally {
    await rm(f.root, { recursive: true, force: true });
  }
});

test("accepted direct-file terminal outcome retains generic archive evidence without reopening the candidate", async () => {
  const f = await fixture();
  try {
    const candidateId = "candidate-1";
    await recordCodexSecurityWorkerScanDraft(
      f.workerContext,
      workerDraft([], {
        complete: false,
        coverage: {
          completeness: "partial",
          surfaces: [
            {
              id: "candidate-surface",
              label: "Synthetic candidate proof",
              candidateId,
              disposition: "needs_follow_up",
              receiptRefs: [],
            },
          ],
          explicitExclusions: [],
          deferred: [
            {
              id: "candidate-task",
              candidateId,
              reason: "Synthetic candidate proof remains.",
              surfaceIds: ["candidate-surface"],
            },
            {
              id: "generic-task",
              reason: "Synthetic independent generic review remains.",
            },
          ],
        },
      }),
    );
    const archive = path.join(f.workerRoot, "attempts/attempt-01");
    await archiveDirectory(f.output, archive);
    const historical = await readFile(path.join(archive, "result.json"));
    await mkdir(f.output, { recursive: true });
    await writeFile(
      f.resultPath,
      JSON.stringify(
        workerDraft([], {
          complete: true,
          coverage: {
            completeness: "complete",
            surfaces: [
              {
                id: "candidate-terminal",
                label: "Synthetic candidate rejected",
                candidateId,
                disposition: "rejected",
                receiptRefs: [],
              },
            ],
            explicitExclusions: [],
            deferred: [],
          },
        }),
      ),
    );
    const current = await readFile(f.resultPath);
    await validateDiscoveryArtifacts(
      { workersRoot: path.dirname(f.workerRoot) },
      f.resultPath,
      scanId,
    );
    const inputs = await readDeepReductionSources(f.context);
    const coverage = inputs.discoveries[0].coverage;
    assert.equal(coverage.deferred.length, 1);
    assert.equal(
      coverage.deferred[0].reason,
      "Synthetic independent generic review remains.",
    );
    assert.equal(
      coverage.deferred.some(
        (row: { candidateId?: string }) => row.candidateId === candidateId,
      ),
      false,
    );
    assert.equal(
      coverage.surfaces.some(
        (row: { candidateId?: string; disposition: string }) =>
          row.candidateId === candidateId && row.disposition === "rejected",
      ),
      true,
    );
    assert.equal(
      coverage.surfaces.some(
        (row: { candidateId?: string; disposition: string }) =>
          row.candidateId === candidateId &&
          row.disposition === "needs_follow_up",
      ),
      false,
    );
    assert.deepEqual(await readFile(f.resultPath), current);
    assert.deepEqual(
      await readFile(path.join(archive, "result.json")),
      historical,
    );
  } finally {
    await rm(f.root, { recursive: true, force: true });
  }
});

for (const kind of ["anonymous", "duplicate", "malformed-current"] as const) {
  for (const history of [false, true]) {
    test(`accepted retry ${kind} keeps saved source identities (archive: ${history})`, async () => {
      const f = await fixture();
      try {
        if (history) {
          await recordCodexSecurityWorkerScanDraft(
            f.workerContext,
            workerDraft([], { complete: false }),
          );
          await archiveDirectory(
            f.output,
            path.join(f.workerRoot, "attempts/attempt-01"),
          );
          await rm(f.output, { recursive: true, force: true });
          await mkdir(f.output);
        }
        const surfaces =
          kind === "duplicate"
            ? ["First route", "Second route"].map((label) => ({
                id: "shared",
                label,
                disposition: "needs_follow_up",
                receiptRefs: [],
              }))
            : [
                {
                  label: "Synthetic route",
                  disposition: "needs_follow_up",
                  receiptRefs: [],
                },
              ];
        const deferred = [
          {
            ...(kind === "anonymous" ? {} : { id: "review" }),
            reason: "Synthetic review remains.",
            ...(kind === "duplicate" ? { surfaceIds: ["shared"] } : {}),
          },
        ];
        const input = workerDraft([], {
          complete: true,
          coverage: {
            completeness: "partial",
            surfaces,
            explicitExclusions: [],
            deferred,
          },
        });
        if (kind === "malformed-current") {
          await mkdir(path.join(f.output, "checkpoints"));
          await writeFile(
            path.join(f.output, "checkpoints/obsolete.json"),
            "{invalid checkpoint",
          );
        }
        await writeFile(f.resultPath, JSON.stringify(input));
        const original = await readFile(f.resultPath);
        await validateDiscoveryArtifacts(
          { workersRoot: path.dirname(f.workerRoot) },
          f.resultPath,
          scanId,
        );
        const sources = await readDeepReductionSources(f.context);
        const coverage = sources.discoveries[0].coverage;
        assert.equal(coverage.surfaces.length, surfaces.length);
        assert.equal(coverage.deferred.length, deferred.length);
        assert.equal(coverage.deferred[0].provenance.sourceId, deferred[0].id);
        if (kind === "duplicate") {
          assert.deepEqual(
            new Set(coverage.deferred[0].surfaceIds),
            new Set(coverage.surfaces.map((row: { id: string }) => row.id)),
          );
        } else {
          assert.equal(coverage.surfaces[0].provenance.sourceId, undefined);
        }
        assert.deepEqual(await readFile(f.resultPath), original);
      } finally {
        await rm(f.root, { recursive: true, force: true });
      }
    });
  }
}

for (const reopen of [false, true]) {
  test(`archived selected checkpoint preserves ${reopen ? "reopened review" : "closure control"} after torn publication`, async () => {
    const f = await fixture();
    try {
      const pending = workerDraft([], {
        complete: false,
        coverage: {
          completeness: "partial",
          surfaces: [],
          explicitExclusions: [],
          deferred: [{ id: "review", reason: "Synthetic review remains." }],
        },
      });
      const closed = workerDraft([], {
        complete: true,
        coverage: {
          completeness: "complete",
          surfaces: [],
          explicitExclusions: [],
          deferred: [],
          resolvedDeferred: [
            { id: "review", reason: "Synthetic review completed." },
          ],
        },
      });
      await saveScanDraftCheckpoint(f.workerContext, pending);
      await new Promise((resolve) => setTimeout(resolve, 20));
      await saveScanDraftCheckpoint(f.workerContext, closed);
      await new Promise((resolve) => setTimeout(resolve, 20));
      // A selected immutable checkpoint can outlive a failed replaceable result write.
      await writeFile(f.resultPath, JSON.stringify(reopen ? closed : pending));
      await new Promise((resolve) => setTimeout(resolve, 20));
      await saveScanDraftCheckpoint(f.workerContext, reopen ? pending : closed);
      await archiveDirectory(
        f.output,
        path.join(f.workerRoot, "attempts/attempt-01"),
      );
      await writeFile(
        f.resultPath,
        JSON.stringify(workerDraft([], { complete: true })),
      );
      const saved = await readArchivedWorkerCheckpoints(f.workerContext, true);
      assert.deepEqual(
        saved[0].input.coverage,
        (reopen ? pending : closed).coverage,
      );
      await validateDiscoveryArtifacts(
        { workersRoot: path.dirname(f.workerRoot) },
        f.resultPath,
        scanId,
      );
      const { discoveries } = await readDeepReductionSources(f.context);
      assert.equal(discoveries[0].coverage.deferred.length, reopen ? 1 : 0);
      if (reopen)
        assert.equal(
          discoveries[0].coverage.deferred[0].reason,
          "Synthetic review remains.",
        );
    } finally {
      await rm(f.root, { recursive: true, force: true });
    }
  });
}

for (const scenario of [
  "unusable-checkpoints",
  "no-archive-control",
  "missing-receipt",
  "readable-receipt-control",
  "merged-receipts",
  "copied-anonymous-surface",
  "changed-receipt-control",
] as const) {
  test(`accepted direct-file retry preserves source identity (${scenario})`, async () => {
    const f = await fixture();
    try {
      const anonymous =
        scenario === "copied-anonymous-surface" ||
        scenario === "changed-receipt-control";
      const archived =
        scenario === "unusable-checkpoints" ||
        scenario === "merged-receipts" ||
        anonymous;
      const receipts = path.join(f.output, "artifacts");
      await mkdir(receipts, { recursive: true });
      const surface = {
        ...(anonymous ? {} : { id: "saved-surface" }),
        label: "Synthetic accepted surface",
        disposition: "no_issue_found",
        receiptRefs: ["artifacts/receipt.txt"],
      };
      let historical: Buffer | undefined;
      const archive = path.join(f.workerRoot, "attempts/attempt-01");
      if (archived) {
        const pending = scenario === "unusable-checkpoints";
        const closing = scenario === "merged-receipts";
        await writeFile(
          path.join(receipts, "receipt.txt"),
          "Synthetic receipt.",
        );
        const previous = workerDraft([], {
          complete: !pending && !closing,
          coverage: {
            completeness: pending || closing ? "partial" : "complete",
            surfaces: pending
              ? []
              : [
                  {
                    ...surface,
                    disposition: closing ? "needs_follow_up" : "no_issue_found",
                  },
                ],
            explicitExclusions: [],
            deferred:
              pending || closing
                ? [
                    {
                      id: "review",
                      reason: "Synthetic pending proof.",
                      ...(closing ? { surfaceIds: ["saved-surface"] } : {}),
                    },
                  ]
                : [],
          },
        });
        if (anonymous) {
          await writeFile(f.resultPath, JSON.stringify(previous));
          await validateDiscoveryArtifacts(
            { workersRoot: path.dirname(f.workerRoot) },
            f.resultPath,
            scanId,
          );
        } else {
          await recordCodexSecurityWorkerScanDraft(f.workerContext, previous);
        }
        await archiveDirectory(f.output, archive);
        historical = await readFile(path.join(archive, "result.json"));
        await mkdir(receipts, { recursive: true });
      }
      const checkpointFile =
        scenario === "unusable-checkpoints" ||
        scenario === "no-archive-control";
      if (checkpointFile)
        await writeFile(
          path.join(f.output, "checkpoints"),
          "Synthetic unreadable collection.",
        );
      if (!checkpointFile && scenario !== "missing-receipt")
        await writeFile(
          path.join(receipts, "receipt.txt"),
          scenario === "changed-receipt-control"
            ? "Synthetic changed receipt."
            : "Synthetic receipt.",
        );
      const closing = scenario === "merged-receipts";
      if (closing)
        await writeFile(
          path.join(receipts, "new.txt"),
          "Synthetic new evidence.",
        );
      const current = workerDraft([], {
        complete: true,
        coverage: {
          completeness: "complete",
          surfaces: checkpointFile
            ? []
            : [
                {
                  ...surface,
                  ...(closing ? { receiptRefs: ["artifacts/new.txt"] } : {}),
                },
              ],
          explicitExclusions: [],
          deferred: [],
          ...(closing
            ? {
                resolvedDeferred: [
                  { id: "review", reason: "Synthetic proof completed." },
                ],
              }
            : {}),
        },
      });
      await writeFile(f.resultPath, JSON.stringify(current));
      const acceptedBytes = await readFile(f.resultPath);
      await validateDiscoveryArtifacts(
        { workersRoot: path.dirname(f.workerRoot) },
        f.resultPath,
        scanId,
      );
      const { discoveries } = await readDeepReductionSources(f.context);
      const coverage = discoveries[0].coverage;
      assert.equal(
        coverage.deferred.length,
        scenario === "unusable-checkpoints" ? 1 : 0,
      );
      assert.equal(
        coverage.surfaces.length,
        checkpointFile ? 0 : scenario === "changed-receipt-control" ? 2 : 1,
      );
      if (!checkpointFile && !anonymous)
        assert.equal(coverage.surfaces[0].provenance.sourceId, "saved-surface");
      if (anonymous)
        assert.ok(
          coverage.surfaces.every(
            (row: { provenance: { sourceId?: string } }) =>
              row.provenance.sourceId === undefined,
          ),
        );
      if (closing) {
        assert.equal(coverage.resolvedDeferred.length, 1);
        assert.equal(coverage.surfaces[0].receiptRefs.length, 2);
      }
      assert.deepEqual(await readFile(f.resultPath), acceptedBytes);
      if (historical)
        assert.deepEqual(
          await readFile(path.join(archive, "result.json")),
          historical,
        );
    } finally {
      await rm(f.root, { recursive: true, force: true });
    }
  });
}

test("ordinary worker writes retain strict checkpoint-directory validation", async () => {
  const f = await fixture();
  try {
    await writeFile(
      path.join(f.output, "checkpoints"),
      "Synthetic invalid checkpoint collection.",
    );
    await assert.rejects(
      recordCodexSecurityWorkerScanDraft(
        f.workerContext,
        workerDraft([], { complete: true }),
      ),
      /destination directory is not a regular directory/u,
    );
    assert.equal(
      await readFile(path.join(f.output, "checkpoints"), "utf8"),
      "Synthetic invalid checkpoint collection.",
    );
  } finally {
    await rm(f.root, { recursive: true, force: true });
  }
});

test(
  "accepted retry projection rejects unsafe checkpoint directory links",
  { skip: process.platform === "win32" },
  async () => {
    const f = await fixture();
    try {
      await recordCodexSecurityWorkerScanDraft(
        f.workerContext,
        workerDraft([], { complete: false }),
      );
      await archiveDirectory(
        f.output,
        path.join(f.workerRoot, "attempts/attempt-01"),
      );
      const target = path.join(f.root, "synthetic-other-checkpoints");
      await mkdir(target);
      await symlink(target, path.join(f.output, "checkpoints"), "dir");
      await writeFile(
        f.resultPath,
        JSON.stringify(workerDraft([], { complete: true })),
      );
      await validateDiscoveryArtifacts(
        { workersRoot: path.dirname(f.workerRoot) },
        f.resultPath,
        scanId,
      );
      await assert.rejects(
        readDeepReductionSources(f.context),
        /checkpoint set is not a safe directory/u,
      );
    } finally {
      await rm(f.root, { recursive: true, force: true });
    }
  },
);

for (const direct of [false, true]) {
  for (const outcome of [
    "rejected",
    "not_applicable",
    "independent",
    "generic",
  ] as const) {
    test(`${direct ? "accepted direct-file" : "typed writer"} retry exclusion ${outcome} preserves the accepted candidate decision`, async () => {
      const f = await fixture();
      try {
        const archivedFinding = {
          ...finding("archived-exclusion", "src/synthetic.ts"),
          provenance: { source: "local_plugin", candidateId: "candidate-1" },
        };
        await recordCodexSecurityWorkerScanDraft(
          f.workerContext,
          workerDraft([archivedFinding], {
            complete: true,
            coverage: {
              completeness: "partial",
              surfaces: [],
              explicitExclusions: [],
              deferred: [
                {
                  id: "generic-review",
                  reason: "Synthetic independent proof remains.",
                },
              ],
            },
          }),
        );
        const archive = path.join(f.workerRoot, "attempts/attempt-01");
        await archiveDirectory(f.output, archive);
        const historical = await readFile(path.join(archive, "result.json"));
        await mkdir(f.output, { recursive: true });
        const terminal = outcome === "rejected" || outcome === "not_applicable";
        const exclusion = {
          pattern: "src/synthetic.ts",
          reason: "Synthetic accepted exclusion decision.",
          ...(outcome === "generic"
            ? {}
            : {
                candidateId:
                  outcome === "independent" ? "candidate-2" : "candidate-1",
                disposition: terminal ? outcome : "rejected",
              }),
        };
        const submitted = workerDraft([], {
          complete: true,
          coverage: {
            completeness: "complete",
            surfaces: [],
            explicitExclusions: [exclusion],
            deferred: [],
          },
        });
        if (direct) await writeFile(f.resultPath, JSON.stringify(submitted));
        else
          await recordCodexSecurityWorkerScanDraft(f.workerContext, submitted);
        await validateDiscoveryArtifacts(
          { workersRoot: path.dirname(f.workerRoot) },
          f.resultPath,
          scanId,
        );
        const current = await readFile(f.resultPath);
        const inputs = await readDeepReductionSources(f.context);
        const accepted = inputs.discoveries[0];
        assert.equal(accepted.result.findings.length, terminal ? 0 : 1);
        assert.equal(accepted.coverage.deferred.length, 1);
        assert.equal(
          accepted.coverage.deferred[0].reason,
          "Synthetic independent proof remains.",
        );
        const publishedExclusion = accepted.coverage.explicitExclusions[0];
        assert.equal(publishedExclusion.reason, exclusion.reason);
        if (terminal)
          assert.equal(publishedExclusion.finding.title, archivedFinding.title);
        await recordCodexSecurityDeepReduction(f.context, {
          scanId,
          complete: true,
          findings: accepted.result.findings,
        });
        const reduced = JSON.parse(
          await readFile(path.join(f.reducerRoot, "result.json"), "utf8"),
        );
        assert.equal(reduced.findings.length, terminal ? 0 : 1);
        assert.equal(reduced.sourceCoverage.explicitExclusions.length, 1);
        assert.equal(reduced.sourceCoverage.deferred.length, 1);
        assert.deepEqual(await readFile(f.resultPath), current);
        assert.deepEqual(
          await readFile(path.join(archive, "result.json")),
          historical,
        );
      } finally {
        await rm(f.root, { recursive: true, force: true });
      }
    });
  }
}

for (const mode of ["idless", "explicit", "mixed"] as const) {
  test(`accepted historical ${mode} worker surfaces keep distinct observations through reduction`, async () => {
    const f = await fixture();
    try {
      // The public worker writer at 42a60ff4732a persisted surface IDs as supplied.
      // These fixtures model its accepted results before surface normalization.
      const surface = {
        label: "Synthetic repeated legacy observation",
        disposition: "needs_follow_up",
        receiptRefs: [],
      };
      const historicalSurfaces =
        mode === "explicit"
          ? [
              { ...surface, id: "legacy-first" },
              { ...surface, id: "legacy-second" },
            ]
          : mode === "mixed"
            ? [surface, { ...surface, id: "legacy-explicit" }]
            : [surface, { ...surface }];
      const legacy = (surfaces: Record<string, unknown>[]) =>
        workerDraft([], {
          complete: true,
          coverage: {
            completeness: "partial",
            surfaces,
            explicitExclusions: [],
            deferred: [],
          },
        });
      await writeFile(f.resultPath, JSON.stringify(legacy(historicalSurfaces)));
      await validateDiscoveryArtifacts(
        { workersRoot: path.dirname(f.workerRoot) },
        f.resultPath,
        scanId,
      );
      const archive = path.join(f.workerRoot, "attempts/attempt-01");
      await archiveDirectory(f.output, archive);
      const historical = await readFile(path.join(archive, "result.json"));
      await mkdir(f.output, { recursive: true });
      // The old writer retained both explicit IDs; repeated ID-less rows were equal.
      const currentSurfaces =
        mode === "explicit" ? historicalSurfaces : [surface];
      await writeFile(f.resultPath, JSON.stringify(legacy(currentSurfaces)));
      await validateDiscoveryArtifacts(
        { workersRoot: path.dirname(f.workerRoot) },
        f.resultPath,
        scanId,
      );
      const current = await readFile(f.resultPath);
      const inputs = await readDeepReductionSources(f.context);
      const surfaces = inputs.discoveries[0].coverage.surfaces;
      assert.equal(surfaces.length, 2);
      assert.equal(
        new Set(surfaces.map((row: { id: string }) => row.id)).size,
        2,
      );
      assert(
        surfaces.every((row: { label: string }) => row.label === surface.label),
      );
      assert(
        surfaces.every(
          (row: { disposition: string }) =>
            row.disposition === surface.disposition,
        ),
      );
      assert.equal(inputs.discoveries[0].result.findings.length, 0);
      await recordCodexSecurityDeepReduction(f.context, {
        scanId,
        complete: true,
        findings: [],
      });
      const persisted = JSON.parse(
        await readFile(path.join(f.reducerRoot, "result.json"), "utf8"),
      );
      assert.equal(persisted.sourceCoverage.surfaces.length, 2);
      assert.equal(
        new Set(
          persisted.sourceCoverage.surfaces.map(
            (row: { id: string }) => row.id,
          ),
        ).size,
        2,
      );
      assert.deepEqual(await readFile(f.resultPath), current);
      assert.deepEqual(
        await readFile(path.join(archive, "result.json")),
        historical,
      );
    } finally {
      await rm(f.root, { recursive: true, force: true });
    }
  });
}
