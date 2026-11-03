import { readJson, writeJson } from "./support/json.ts";
import { sourceReferences } from "./support/source-references.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import { finding, scanId, workerDraft } from "./scan-draft-fixture.ts";
import assert from "node:assert/strict";
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
  "Deep reducer submissions no longer accept reviewState",
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
  await testRetainedFindingContent(root);
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
      reviewState: rejectedCoverage,
    }),
  });
  const second = await createWorker({
    workersRoot,
    label: "discovery-0002",
    id: "worker-002",
    result: workerDraft([shared, independent], {
      scope: { summary: "Shared and independent request handling." },
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
    "reducer checkpoints retain the accepted findings and scope without reviewState",
  );

  assert.deepEqual(
    await Promise.all(
      [first, second].map((worker) => readFile(worker.resultPath, "utf8")),
    ),
    originalWorkerArtifacts,
    "reduction must not rewrite raw Standard worker reviewState evidence",
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
    /unaccounted source findings: worker-002:1/,
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
  await writeJson(path.join(outputRoot, "result.json"), enrichedPrevious);
  const previousArtifact = await readFile(
    path.join(outputRoot, "result.json"),
    "utf8",
  );
  await recordCodexSecurityDeepReduction(nextContext, merged);
  const preservedEnrichment = await readJson(nextOutputRoot, "result.json");
  assert.equal(
    await readFile(path.join(outputRoot, "result.json"), "utf8"),
    previousArtifact,
    "the original previous reduction remains unchanged",
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
    { ...workerDraft([]).reviewState, deferred: "invalid" },
  ]) {
    await writeJson(first.resultPath, {
      ...first.result,
      reviewState: invalidCoverage,
    });
    await assert.rejects(
      getCodexSecurityDeepReducerInputs(context),
      /reviewState/,
      "Standard worker reviewState remains required and validated before projection",
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

async function testRetainedFindingContent(root: string) {
  const scanRoot = path.join(root, "content");
  const deepRoot = path.join(scanRoot, "artifacts", "deep_discovery");
  const original = {
    ...finding("retained", "src/handler.ts"),
    rootCause: { summary: "The response omits encoding of request input." },
    writeup: {
      reportPath: "findings/retained/retained.md",
      description: "A crafted query is rendered as executable HTML.",
    },
  };
  const worker = await createWorker({
    workersRoot: path.join(deepRoot, "workers"),
    label: "discovery-0001",
    id: "worker-content",
    result: workerDraft([original]),
  });
  const outputRoot = path.join(deepRoot, "dedup", "first", "output");
  await mkdir(outputRoot, { recursive: true });
  const context = {
    root: outputRoot,
    repoRoot: root,
    scanId,
    layout: "reducer",
    deepReducer: { scanRoot, claimedWorkers: [worker] },
  };
  const replacements = [
    { title: "X" },
    { summary: "X" },
    { rootCause: { summary: "TBD" } },
    { remediation: "..." },
    { writeup: { ...original.writeup, description: "X" } },
  ];
  for (const replacement of replacements) {
    await assert.rejects(
      recordCodexSecurityDeepReduction(
        context,
        reduction([{ ...original, ...replacement }]),
      ),
      /placeholder.*worker-content:0/i,
      "a reducer cannot replace accepted source text with placeholders",
    );
    await assert.rejects(readFile(path.join(outputRoot, "result.json")), {
      code: "ENOENT",
    });
    await assert.rejects(readdir(path.join(outputRoot, "checkpoints")), {
      code: "ENOENT",
    });
  }
  await recordCodexSecurityDeepReduction(context, reduction([original]));
  const accepted = await readJson(outputRoot, "result.json");
  // This detail exists only in the previous aggregate, beyond its originals.
  accepted.findings[0].writeup.additionalProof =
    "A second response branch reaches the same vulnerable HTML sink.";
  await writeJson(path.join(outputRoot, "result.json"), accepted);
  const empty = await createWorker({
    workersRoot: path.join(deepRoot, "workers"),
    label: "discovery-0002",
    id: "worker-empty",
    result: workerDraft([]),
  });
  const nextRoot = path.join(deepRoot, "dedup", "second", "output");
  await mkdir(nextRoot, { recursive: true });
  const nextContext = {
    ...context,
    root: nextRoot,
    deepReducer: {
      scanRoot,
      claimedWorkers: [empty],
      previousReducerResultPath: path.join(outputRoot, "result.json"),
    },
  };
  await assert.rejects(
    recordCodexSecurityDeepReduction(
      nextContext,
      reduction([
        {
          ...accepted.findings[0],
          writeup: { ...accepted.findings[0].writeup, additionalProof: "X" },
        },
      ]),
    ),
    /placeholder.*worker-content:0/i,
    "details synthesized by an earlier reducer must also be preserved",
  );
  await recordCodexSecurityDeepReduction(
    nextContext,
    reduction([], { retainedFindingRefs: ["previous:0"] }),
  );
  assert.deepEqual(
    await readJson(nextRoot, "result.json"),
    accepted,
    "reference-only retention copies the complete body and history verbatim",
  );
  assert.deepEqual(
    (
      await getCodexSecurityDeepReducerInputs({
        ...nextContext,
        deepReducer: {
          ...nextContext.deepReducer,
          previousReducerResultPath: path.join(nextRoot, "result.json"),
        },
      })
    ).previous,
    accepted,
    "reopening the reduction retains substantive text and exact locations",
  );
  for (const retainedFindingRefs of [
    ["previous:1"],
    ["previous:0", "previous:0"],
  ]) {
    await assert.rejects(
      recordCodexSecurityDeepReduction(
        nextContext,
        reduction([], { retainedFindingRefs }),
      ),
      /not assigned|more than once/,
    );
    assert.deepEqual(await readJson(nextRoot, "result.json"), accepted);
  }
  await recordCodexSecurityDeepReduction(
    nextContext,
    reduction([
      { ...accepted.findings[0], summary: "Reflected HTML injection." },
    ]),
  );
  assert.equal(
    (await readJson(nextRoot, "result.json")).findings[0].summary,
    "Reflected HTML injection.",
    "concise substantive synthesis remains allowed without length heuristics",
  );
  for (const legacyRefs of [undefined, ["historical:0"]]) {
    const legacyFinding = {
      ...original,
      summary: "An earlier review recorded a separate response route.",
      provenance: { ...original.provenance, sourceFindingIds: legacyRefs },
    };
    const previousReducerResultPath = path.join(
      deepRoot,
      "dedup",
      "legacy.json",
    );
    await writeJson(previousReducerResultPath, reduction([legacyFinding]));
    await recordCodexSecurityDeepReduction(
      {
        ...nextContext,
        deepReducer: {
          scanRoot,
          claimedWorkers: [worker],
          previousReducerResultPath,
        },
      },
      reduction(
        [
          {
            ...original,
            provenance: {
              ...original.provenance,
              sourceFindingIds: ["worker-content:0"],
            },
          },
        ],
        { retainedFindingRefs: ["previous:0"] },
      ),
    );
    const retained = (await readJson(nextRoot, "result.json")).findings[1];
    assert.equal(retained.summary, legacyFinding.summary);
    assert.deepEqual(
      retained.provenance.sourceFindingIds,
      ["previous:0"],
      "legacy references are explicit even when a fresh finding has the same identity",
    );
  }
}

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
  const { reviewState: _coverage, ...result } = worker.result;
  return {
    ...result,
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
