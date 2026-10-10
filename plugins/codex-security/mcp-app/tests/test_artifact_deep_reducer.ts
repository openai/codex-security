import { readJson, writeJson } from "./support/json.ts";
import { sourceReferences } from "./support/source-references.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import { finding, scanId, workerDraft } from "./scan-draft-fixture.ts";
import assert from "node:assert/strict";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { importSource } from "./import-module.ts";

type Finding = ReturnType<typeof finding>;

const {
  deepReducerInputsInputSchema,
  deepReductionInputSchema,
  getCodexSecurityDeepReducerInputs,
  recordCodexSecurityDeepReduction,
} = await importSource(
  path.join(import.meta.dirname, "../src/artifact-deep-reducer.ts"),
);

const validReduction = reduction([]);

assert.equal(
  deepReducerInputsInputSchema.safeParse({ maxBytes: 4096 }).success,
  true,
);
assert.equal(deepReducerInputsInputSchema.safeParse({}).success, false);
assert.equal(
  deepReducerInputsInputSchema.safeParse({ path: "/tmp" }).success,
  false,
);
assert.equal(deepReductionInputSchema.safeParse(validReduction).success, true);
assert.equal(
  deepReductionInputSchema.safeParse(workerDraft([])).success,
  false,
  "Deep reducer submissions no longer accept coverage",
);
assert.equal(
  deepReductionInputSchema.safeParse({ ...validReduction, resultPath: "/tmp" })
    .success,
  false,
);
assert.equal(
  deepReductionInputSchema.safeParse({
    ...validReduction,
    consumedWorkerIds: ["spoofed"],
  }).success,
  false,
);
assert.equal(
  deepReductionInputSchema.safeParse({ candidates: [], merges: [] }).success,
  false,
);

const root = await temporaryDirectory("codex-security-deep-reducer-", true);
try {
  const scanRoot = path.join(root, "scan");
  const workersRoot = path.join(
    scanRoot,
    "artifacts",
    "deep_discovery",
    "workers",
  );
  const dedupRoot = path.join(scanRoot, "artifacts", "deep_discovery", "dedup");

  const shared = finding("shared", "src/shared.ts");
  const independent = finding("independent", "src/independent.ts");
  const rejectedCoverage = {
    completeness: "partial",
    surfaces: [
      {
        label: "SQL route",
        disposition: "rejected",
        notes: "Parameterized queries prevent injection.",
        receiptRefs: ["artifacts/missing-worker-receipt.md"],
      },
      {
        label: "Archive upload",
        disposition: "needs_follow_up",
        notes: "The guard still needs review.",
      },
    ],
    explicitExclusions: [
      { pattern: "vendor", reason: "Outside the requested source scope." },
    ],
    deferred: [
      {
        candidateId: "candidate-upload",
        reason: "Review the guard.",
        paths: ["src/upload.ts"],
      },
    ],
    openQuestions: ["Does the alternate upload handler use the guard?"],
  };
  const first = await createWorker({
    workersRoot,
    label: "discovery-0001",
    id: "worker-001",
    result: workerDraft([shared], {
      threatModel: { summary: "Requests may reach shared code." },
      coverage: rejectedCoverage,
    }),
  });
  const second = await createWorker({
    workersRoot,
    label: "discovery-0002",
    id: "worker-002",
    result: workerDraft([shared, independent], {
      scope: { summary: "Shared and independent request handling." },
      coverage: { ...workerDraft([]).coverage, completeness: "unknown" },
    }),
  });
  const originalWorkerArtifacts = await Promise.all(
    [first, second].map((worker) => readFile(worker.resultPath, "utf8")),
  );
  const outputRoot = path.join(dedupRoot, "dedup-0001", "output");
  await mkdir(outputRoot, { recursive: true });
  const context = {
    root: outputRoot,
    repoRoot: root,
    scanId,
    layout: "reducer",
    deepReducer: {
      scanRoot,
      claimedWorkers: [first, second],
    },
  };

  const inputs = await getCodexSecurityDeepReducerInputs(context);
  await assert.rejects(
    recordCodexSecurityDeepReduction(
      context,
      reduction([], { complete: false }),
    ),
    /only a checkpoint/,
    "a reducer submission must contain a complete result",
  );
  await assert.rejects(
    recordCodexSecurityDeepReduction(context, reduction([shared])),
    /unaccounted|discarded.*finding/,
    "a successful reduction must account for every fresh finding, not just one",
  );
  await assert.rejects(
    recordCodexSecurityDeepReduction(
      context,
      reduction([
        shared,
        independent,
        finding("invented", "src/unreviewed.ts"),
      ]),
    ),
    /no assigned source finding/,
    "a reducer cannot introduce an unvalidated finding outside its assigned sources",
  );
  await assert.rejects(
    recordCodexSecurityDeepReduction(
      context,
      reduction(
        [
          { ...shared, validation: { evidenceRefs: ["missing-evidence"] } },
          independent,
        ],
        { complete: true },
      ),
    ),
    /evidenceRefs must refer/,
    "live reducer submissions reject unknown evidence references instead of silently removing them",
  );
  assert.deepEqual(inputs, {
    discoveries: [
      { workerId: first.id, result: withSourceRefs(first) },
      { workerId: second.id, result: withSourceRefs(second) },
    ],
    previous: null,
  });
  assert.equal(JSON.stringify(inputs).includes(root), false);
  assert.equal(JSON.stringify(inputs).includes("result.json"), false);

  await assert.rejects(readFile(path.join(outputRoot, "result.json"), "utf8"), {
    code: "ENOENT",
  });
  await assert.rejects(
    readdir(path.join(outputRoot, "checkpoints")),
    { code: "ENOENT" },
    "invalid reducer submissions do not save a checkpoint",
  );
  await assert.rejects(
    recordCodexSecurityDeepReduction(context, reduction([])),
    /discarded every accepted Standard scan finding/,
  );

  const merged = reduction([shared, independent], {
    threatModel: { summary: "Requests reach shared and independent code." },
    scope: { summary: "Shared and independent request handling." },
  });
  const outcome = await recordCodexSecurityDeepReduction(context, merged);
  const mergedWithSources = {
    ...merged,
    unresolvedCandidates: [
      { ...rejectedCoverage.deferred[0], sourceWorkerId: first.id },
    ],
    findings: [
      retainedFinding(shared, [
        { id: "worker-001:0", finding: shared },
        { id: "worker-002:0", finding: shared },
      ]),
      retainedFinding(independent, [
        { id: "worker-002:1", finding: independent },
      ]),
    ],
  };
  assert.deepEqual(outcome, {
    findingCount: 2,
    consumedWorkerIds: [first.id, second.id],
  });
  assert.deepEqual(
    await readJson(outputRoot, "result.json"),
    mergedWithSources,
  );
  const checkpointNames = await readdir(path.join(outputRoot, "checkpoints"));
  assert.equal(checkpointNames.length, 1);
  assert.deepEqual(
    await readJson(outputRoot, "checkpoints", checkpointNames[0]),
    mergedWithSources,
    "reducer checkpoints retain the accepted findings and scope without coverage",
  );

  assert.deepEqual(
    await Promise.all(
      [first, second].map((worker) => readFile(worker.resultPath, "utf8")),
    ),
    originalWorkerArtifacts,
    "reduction must not rewrite raw Standard worker coverage evidence",
  );

  const collision = {
    ...independent,
    ruleId: shared.ruleId,
    identity: shared.identity,
  };
  const collisionWorker = await createWorker({
    workersRoot,
    label: "discovery-collision",
    id: "worker-collision",
    result: workerDraft([shared, collision]),
  });
  const collisionRoot = path.join(dedupRoot, "dedup-collision", "output");
  await mkdir(collisionRoot, { recursive: true });
  const collisionContext = {
    ...context,
    root: collisionRoot,
    deepReducer: { scanRoot, claimedWorkers: [collisionWorker] },
  };
  await assert.rejects(
    recordCodexSecurityDeepReduction(collisionContext, reduction([shared])),
    /ambiguous|unaccounted/,
  );
  const collisionInputs =
    await getCodexSecurityDeepReducerInputs(collisionContext);
  const sourceFindingIds =
    collisionInputs.discoveries[0].result.findings.flatMap(
      (finding: { provenance: { sourceFindingIds: string[] } }) =>
        finding.provenance.sourceFindingIds,
    );
  assert.deepEqual(sourceFindingIds, [
    "worker-collision:0",
    "worker-collision:1",
  ]);
  await recordCodexSecurityDeepReduction(
    collisionContext,
    reduction([
      {
        ...shared,
        provenance: { ...shared.provenance, sourceFindingIds },
      },
    ]),
  );
  const collisionOutput = await readJson(collisionRoot, "result.json");
  assert.deepEqual(collisionOutput.findings[0].provenance.sourceFindings, [
    { id: "worker-collision:0", finding: shared },
    { id: "worker-collision:1", finding: collision },
  ]);
  await assert.rejects(
    recordCodexSecurityDeepReduction(
      collisionContext,
      reduction([
        {
          ...shared,
          provenance: {
            ...shared.provenance,
            sourceFindingIds: ["unassigned:0"],
          },
        },
      ]),
    ),
    /unknown source finding/,
  );
  await assert.rejects(
    readFile(
      path.join(
        scanRoot,
        "artifacts",
        "02_discovery",
        "candidate_ledger.jsonl",
      ),
    ),
    { code: "ENOENT" },
  );

  const third = await createWorker({
    workersRoot,
    label: "discovery-0003",
    id: "worker-003",
    result: workerDraft([shared]),
  });
  const nextOutputRoot = path.join(dedupRoot, "dedup-0002", "output");
  await mkdir(nextOutputRoot, { recursive: true });
  const nextContext = {
    root: nextOutputRoot,
    repoRoot: root,
    scanId,
    layout: "reducer",
    deepReducer: {
      scanRoot,
      claimedWorkers: [third],
      previousReducerResultPath: path.join(outputRoot, "result.json"),
    },
  };
  const nextInputs = await getCodexSecurityDeepReducerInputs(nextContext);
  assert.deepEqual(nextInputs, {
    discoveries: [{ workerId: third.id, result: withSourceRefs(third) }],
    previous: mergedWithSources,
  });
  await assert.rejects(
    recordCodexSecurityDeepReduction(nextContext, reduction([shared])),
    (error: NodeJS.ErrnoException) =>
      error.code === "merge_traceability_unstable_candidate_id",
  );
  assert.deepEqual(
    await recordCodexSecurityDeepReduction(nextContext, merged),
    { findingCount: 2, consumedWorkerIds: [third.id] },
  );
  assert.deepEqual(await readJson(nextOutputRoot, "result.json"), {
    ...mergedWithSources,
    findings: [
      retainedFinding(shared, [
        { id: "worker-003:0", finding: shared },
        { id: "worker-001:0", finding: shared },
        { id: "worker-002:0", finding: shared },
      ]),
      mergedWithSources.findings[1],
    ],
  });

  const enrichedPrevious = structuredClone(mergedWithSources);
  enrichedPrevious.findings[0].summary =
    "The earlier reduction established an additional reachable output route.";
  enrichedPrevious.findings[0].validation = {
    summary: "Both output routes bypass the same encoding control.",
  };
  for (const legacyCoverage of [
    rejectedCoverage,
    {
      completeness: "outdated",
      surfaces: [null],
      explicitExclusions: false,
      deferred: 42,
    },
    "legacy coverage is no longer structured",
  ]) {
    const previousArtifact = JSON.stringify({
      ...enrichedPrevious,
      coverage: legacyCoverage,
    });
    await writeFile(path.join(outputRoot, "result.json"), previousArtifact);
    assert.deepEqual(
      (await getCodexSecurityDeepReducerInputs(nextContext)).previous,
      enrichedPrevious,
      "previous reducer coverage is ignored even when malformed; findings and scope remain intact",
    );
    assert.equal(
      await readFile(path.join(outputRoot, "result.json"), "utf8"),
      previousArtifact,
      "reading a previous reduction does not rewrite its legacy coverage",
    );
  }
  const previousArtifact = await readFile(
    path.join(outputRoot, "result.json"),
    "utf8",
  );
  await recordCodexSecurityDeepReduction(nextContext, merged);
  const preservedEnrichment = await readJson(nextOutputRoot, "result.json");
  assert.equal(
    Object.hasOwn(preservedEnrichment, "coverage"),
    false,
    "a subsequent accepted reduction omits the previous reducer's legacy coverage",
  );
  assert.equal(
    await readFile(path.join(outputRoot, "result.json"), "utf8"),
    previousArtifact,
    "the original previous reduction remains available without rewriting its coverage",
  );
  assert.equal(
    preservedEnrichment.findings[0].provenance.previousFindings[0].summary,
    enrichedPrevious.findings[0].summary,
    "previous synthesized evidence must survive even when source references are unchanged",
  );

  await assert.rejects(
    getCodexSecurityDeepReducerInputs({ root, repoRoot: root, layout: "scan" }),
    /No active Deep reducer is bound/,
  );
  await assert.rejects(
    recordCodexSecurityDeepReduction(context, {
      ...merged,
      scanId: "12c17317-9594-49e0-b06a-d72fd7e14bba",
    }),
    /scanId does not match/,
  );
  await assert.rejects(
    recordCodexSecurityDeepReduction(context, {
      ...merged,
      findings: [
        {
          ...shared,
          locations: [{ path: "src/shared.ts", startLine: 3, endLine: 2 }],
        },
      ],
    }),
    /endLine/,
  );
  await assert.rejects(
    getCodexSecurityDeepReducerInputs({
      ...context,
      deepReducer: { ...context.deepReducer, claimedWorkers: [first, first] },
    }),
    /repeats assigned Standard scan worker/,
  );

  await writeJson(first.resultPath, { ...first.result, complete: false });
  await assert.rejects(
    getCodexSecurityDeepReducerInputs(context),
    /only a checkpoint/,
    "unfinished Standard worker results are not reducer inputs",
  );

  for (const invalidCoverage of [
    undefined,
    { ...workerDraft([]).coverage, completeness: "outdated" },
  ]) {
    await writeJson(first.resultPath, {
      ...first.result,
      coverage: invalidCoverage,
    });
    await assert.rejects(
      getCodexSecurityDeepReducerInputs(context),
      /coverage|completeness/,
      "Standard worker coverage remains required and validated before projection",
    );
  }

  await writeFile(first.resultPath, "{invalid Standard scan\n");
  await assert.rejects(
    getCodexSecurityDeepReducerInputs(context),
    (error: Error) =>
      error.name !== "DeepScanNonRetryableError" &&
      /Invalid Deep Scan JSON artifact/.test(error.message) &&
      !error.message.includes(root),
  );

  await writeJson(first.resultPath, {
    ...first.result,
    scanId: "12c17317-9594-49e0-b06a-d72fd7e14bba",
  });
  await assert.rejects(
    getCodexSecurityDeepReducerInputs(context),
    (error: Error) =>
      error.name !== "DeepScanNonRetryableError" &&
      /different scan/.test(error.message) &&
      !error.message.includes(root),
  );
} finally {
  await rm(root, { recursive: true, force: true });
}

console.log("artifact deep reducer tests passed");

async function createWorker({
  workersRoot,
  label,
  id,
  result,
}: {
  workersRoot: string;
  label: string;
  id: string;
  result: ReturnType<typeof workerDraft<Finding>>;
}) {
  const workerRoot = path.join(workersRoot, label, "output");
  await mkdir(workerRoot, { recursive: true });
  const resultPath = path.join(workerRoot, "result.json");
  await writeFile(resultPath, JSON.stringify(result) + "\n");
  return { id, resultPath, result };
}

function reduction(findings: Record<string, unknown>[], extra = {}) {
  return { scanId, findings, ...extra };
}

function withSourceRefs(worker: Awaited<ReturnType<typeof createWorker>>) {
  const { coverage, ...result } = worker.result;
  const unresolvedCandidates = coverage.deferred
    .filter(
      (item: Record<string, unknown>) => typeof item.candidateId === "string",
    )
    .map((item: Record<string, unknown>) => ({
      ...item,
      sourceWorkerId: worker.id,
    }));
  return {
    ...result,
    ...(unresolvedCandidates.length > 0 ? { unresolvedCandidates } : {}),
    findings: worker.result.findings.map(sourceReferences(worker)),
  };
}

function retainedFinding(
  finding: Finding & { validation?: unknown },
  sourceFindings: { id: string; finding: unknown }[],
) {
  return {
    ...finding,
    provenance: {
      ...finding.provenance,
      sourceFindingIds: sourceFindings.map((source) => source.id),
      sourceFindings,
    },
  };
}

for (const kind of ["correct", "imported", "merged", "previous"]) {
  const importedOwner = kind !== "correct";
  const merged = kind === "merged";
  test(`live two-worker reduction binds retained source ownership ${kind}`, async () => {
    const root = await temporaryDirectory("deep-live-source-owner-", true);
    try {
      const { recordCodexSecurityWorkerScanDraft } = await importSource(
        fileURLToPath(
          new URL("../src/artifact-scan-draft.ts", import.meta.url),
        ),
      );
      const { unresolvedCandidates } = await importSource(
        fileURLToPath(
          new URL(
            "../../../../sdk/typescript/src/candidates.ts",
            import.meta.url,
          ),
        ),
      );
      const firstFinding = {
        ...finding("shared-candidate", "src/shared.ts"),
        provenance: { source: "local_plugin", candidateId: "candidate-shared" },
      };
      const pending = {
        id: "pending-review",
        candidateId: "candidate-shared",
        reason: "Independent second worker proof gap.",
        paths: ["src/shared.ts"],
      };
      const workersRoot = path.join(
        root,
        "artifacts",
        "deep_discovery",
        "workers",
      );
      const claimed = [];
      const originals = new Map<string, string>();
      for (const [index, findings] of [
        [0, [firstFinding]],
        [1, merged ? [firstFinding] : []],
      ] as const) {
        const output = path.join(
          workersRoot,
          `discovery-000${index + 1}`,
          "output",
        );
        await mkdir(output, { recursive: true });
        const source = workerDraft([...findings], {
          complete: true,
          ...(index === 1 && !merged
            ? {
                coverage: {
                  completeness: "partial",
                  surfaces: [],
                  explicitExclusions: [],
                  deferred: [pending],
                },
              }
            : {}),
        });
        await recordCodexSecurityWorkerScanDraft(
          { root: output, repoRoot: root, layout: "worker", scanId },
          source,
        );
        const resultPath = path.join(output, "result.json");
        claimed.push({
          id: index === 0 ? "worker-a" : "worker-b",
          attempt: 1,
          resultPath,
        });
        originals.set(resultPath, await readFile(resultPath, "utf8"));
      }
      const output = path.join(
        root,
        "artifacts",
        "deep_discovery",
        "dedup",
        "dedup-0001",
        "output",
      );
      await mkdir(output, { recursive: true });
      const aggregate = {
        ...firstFinding,
        provenance: {
          ...firstFinding.provenance,
          sourceWorkerId: importedOwner ? "worker-b" : "worker-a",
          sourceFindingIds: merged
            ? ["worker-a:0", "worker-b:0"]
            : ["worker-a:0"],
        },
      };
      let previousReducerResultPath: string | undefined;
      if (kind === "previous") {
        const previousRoot = path.join(path.dirname(output), "previous");
        await mkdir(previousRoot, { recursive: true });
        const previousContext = {
          root: previousRoot,
          repoRoot: root,
          layout: "reducer",
          scanId,
          deepReducer: { scanRoot: root, claimedWorkers: [claimed[0]!] },
        };
        const previousInputs =
          await getCodexSecurityDeepReducerInputs(previousContext);
        await recordCodexSecurityDeepReduction(previousContext, {
          scanId,
          findings: previousInputs.discoveries[0].result.findings,
        });
        previousReducerResultPath = path.join(previousRoot, "result.json");
        originals.set(
          previousReducerResultPath,
          await readFile(previousReducerResultPath, "utf8"),
        );
      }
      await recordCodexSecurityDeepReduction(
        {
          root: output,
          repoRoot: root,
          layout: "reducer",
          scanId,
          deepReducer: {
            scanRoot: root,
            claimedWorkers: kind === "previous" ? [claimed[1]!] : claimed,
            ...(previousReducerResultPath ? { previousReducerResultPath } : {}),
          },
        },
        { scanId, findings: [aggregate] },
      );
      const saved = await readJson(path.join(output, "result.json"));
      if (merged) {
        assert.equal(saved.unresolvedCandidates, undefined);
        assert.equal(
          saved.findings[0].provenance.sourceWorkerId,
          "worker-b",
          "two source owners preserve authored merged ownership",
        );
        assert.deepEqual(saved.findings[0].provenance.sourceFindingIds, [
          "worker-a:0",
          "worker-b:0",
        ]);
        for (const [file, bytes] of originals)
          assert.equal(await readFile(file, "utf8"), bytes);
        return;
      }
      assert.equal(saved.unresolvedCandidates.length, 1);
      assert.equal(saved.unresolvedCandidates[0].sourceWorkerId, "worker-b");
      assert.equal(
        unresolvedCandidates(
          {
            surfaces: [],
            explicitExclusions: [],
            deferred: saved.unresolvedCandidates,
          },
          saved.findings,
        ).length,
        1,
        "worker A confirmation does not resolve worker B proof gap",
      );
      assert.equal(saved.findings[0].provenance.sourceWorkerId, "worker-a");
      assert.deepEqual(saved.findings[0].provenance.sourceFindingIds, [
        "worker-a:0",
      ]);
      if (importedOwner)
        assert.equal(
          saved.findings[0].provenance.previousFindings.some(
            (row: { provenance: { sourceWorkerId?: string } }) =>
              row.provenance.sourceWorkerId === "worker-b",
          ),
          true,
          "imported provenance remains evidence",
        );
      for (const [file, bytes] of originals)
        assert.equal(await readFile(file, "utf8"), bytes);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}

for (const receipt of [
  "missing",
  "valid",
  "empty",
  "none",
  "other-worker",
] as const) {
  for (const savedGap of [false, true]) {
    test(`worker terminal candidate receipt ${receipt}, saved gap=${savedGap}`, async () => {
      const root = await temporaryDirectory(
        "deep-worker-candidate-receipt-",
        true,
      );
      try {
        const candidateId = "receipt-candidate";
        const pending = {
          candidateId,
          reason: "Original proof gap remains saved.",
          candidate: { evidence: "Original candidate evidence." },
        };
        const workersRoot = path.join(
          root,
          "artifacts",
          "deep_discovery",
          "workers",
        );
        const worker = await createWorker({
          workersRoot,
          label: "worker-receipt",
          id: "worker-receipt",
          result: workerDraft([], {
            coverage: {
              completeness: "partial",
              explicitExclusions: [],
              surfaces: [
                {
                  id: "decision",
                  label: "Synthetic review",
                  candidateId,
                  candidate: pending.candidate,
                  disposition: "rejected",
                  receiptRefs:
                    receipt === "none" ? [] : ["artifacts/review.txt"],
                },
              ],
              deferred: savedGap ? [pending] : [],
            },
          }),
        });
        if (["valid", "empty", "other-worker"].includes(receipt)) {
          const receiptRoot =
            receipt === "other-worker"
              ? path.join(workersRoot, "another-worker", "output")
              : path.dirname(worker.resultPath);
          await mkdir(path.join(receiptRoot, "artifacts"), { recursive: true });
          await writeFile(
            path.join(receiptRoot, "artifacts", "review.txt"),
            receipt === "empty" ? "" : "Synthetic review receipt.\n",
          );
        }
        const workerBytes = await readFile(worker.resultPath, "utf8");
        const output = path.join(
          root,
          "artifacts",
          "deep_discovery",
          "dedup",
          "reducer",
          "output",
        );
        await mkdir(output, { recursive: true });
        const context = {
          root: output,
          repoRoot: root,
          scanId,
          layout: "reducer",
          deepReducer: { scanRoot: root, claimedWorkers: [worker] },
        };
        const inputs = await getCodexSecurityDeepReducerInputs(context);
        const expectedPending =
          receipt === "missing" || receipt === "other-worker";
        assert.equal(
          inputs.discoveries[0].result.unresolvedCandidates?.length ?? 0,
          expectedPending ? 1 : 0,
        );
        await recordCodexSecurityDeepReduction(context, {
          scanId,
          findings: [],
        });
        const saved = await readJson(path.join(output, "result.json"));
        assert.equal(
          saved.unresolvedCandidates?.length ?? 0,
          expectedPending ? 1 : 0,
        );
        if (expectedPending) {
          assert.equal(saved.unresolvedCandidates[0].candidateId, candidateId);
          assert.equal(saved.unresolvedCandidates[0].sourceWorkerId, worker.id);
          assert.deepEqual(
            saved.unresolvedCandidates[0].candidate,
            pending.candidate,
          );
          if (savedGap)
            assert.equal(saved.unresolvedCandidates[0].reason, pending.reason);
        }
        const { deepReductionScanDraft } = await importSource(
          fileURLToPath(
            new URL("../src/deep-scan/artifact-validation.ts", import.meta.url),
          ),
        );
        const publication = deepReductionScanDraft(saved);
        assert.equal(
          publication.coverage.completeness,
          expectedPending ? "partial" : "complete",
        );
        assert.equal(await readFile(worker.resultPath, "utf8"), workerBytes);
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
  }
}

for (const origin of [
  "legacy-owned",
  "legacy-unowned",
  "worker-named-previous",
] as const) {
  test(`keeps legacy aggregate ownership through repeated public reductions: ${origin}`, async (t) => {
    const root = await temporaryDirectory("deep-legacy-source-owner-", true);
    t.after(() => rm(root, { recursive: true, force: true }));
    const workersRoot = path.join(root, "artifacts/deep_discovery/workers");
    const dedupRoot = path.join(root, "artifacts/deep_discovery/dedup");
    await mkdir(dedupRoot, { recursive: true });
    const owner =
      origin === "legacy-unowned"
        ? undefined
        : origin === "worker-named-previous"
          ? "previous"
          : "worker-a";
    const savedFinding = {
      ...finding("shared", "src/handler.ts"),
      provenance: {
        source: "local_plugin",
        candidateId: "candidate-shared",
        ...(owner === undefined ? {} : { sourceWorkerId: owner }),
      },
    };
    let previousPath = path.join(dedupRoot, "legacy-result.json");
    await writeJson(previousPath, reduction([savedFinding]));
    if (origin === "worker-named-previous") {
      const worker = await createWorker({
        workersRoot,
        label: "previous",
        id: "previous",
        result: workerDraft([savedFinding]),
      });
      const output = path.join(dedupRoot, "initial");
      await mkdir(output);
      const context = {
        root: output,
        repoRoot: root,
        layout: "reducer",
        scanId,
        deepReducer: { scanRoot: root, claimedWorkers: [worker] },
      };
      const inputs = await getCodexSecurityDeepReducerInputs(context);
      await recordCodexSecurityDeepReduction(
        context,
        reduction(inputs.discoveries[0].result.findings),
      );
      previousPath = path.join(output, "result.json");
    }
    for (const workerId of ["worker-b", "worker-c"]) {
      const previousBytes = await readFile(previousPath, "utf8");
      const worker = await createWorker({
        workersRoot,
        label: workerId,
        id: workerId,
        result: workerDraft([]),
      });
      const output = path.join(dedupRoot, workerId);
      await mkdir(output);
      const context = {
        root: output,
        repoRoot: root,
        layout: "reducer",
        scanId,
        deepReducer: {
          scanRoot: root,
          claimedWorkers: [worker],
          previousReducerResultPath: previousPath,
        },
      };
      const inputs = await getCodexSecurityDeepReducerInputs(context);
      const submitted = structuredClone(inputs.previous);
      submitted.findings[0].provenance.sourceFindingIds ??= ["previous:0"];
      await recordCodexSecurityDeepReduction(context, submitted);
      assert.equal(await readFile(previousPath, "utf8"), previousBytes);
      previousPath = path.join(output, "result.json");
      const saved = await readJson(previousPath);
      assert.equal(saved.findings[0].provenance.sourceWorkerId, owner);
      assert.deepEqual(saved.findings[0].provenance.sourceFindingIds, [
        "previous:0",
      ]);
    }
  });
}
