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
  new URL("../src/artifact-deep-reducer.ts", import.meta.url).pathname,
);

const { validateReducerArtifacts } = await importSource(
  new URL("../src/deep-scan/artifact-validation.ts", import.meta.url).pathname,
);
const { createDeepScanArtifacts } = await importSource(
  new URL("../src/deep-scan/artifacts.ts", import.meta.url).pathname,
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

  const severityError =
    /without recording severity\.rationale and severity\.changeConditions/;
  const severityContext = async (
    label: string,
    workers: Awaited<ReturnType<typeof createWorker>>[],
    previousReducerResultPath?: string,
  ) => {
    const output = path.join(dedupRoot, label, "output");
    await mkdir(output, { recursive: true });
    return {
      ...context,
      root: output,
      deepReducer: {
        scanRoot,
        claimedWorkers: workers,
        previousReducerResultPath,
      },
    };
  };
  for (const [sourceLevel, changedLevel] of [
    ["high", "medium"],
    ["medium", "high"],
  ] as const) {
    const source = { ...shared, severity: { level: sourceLevel } };
    const worker = await createWorker({
      workersRoot,
      label: `severity-${sourceLevel}`,
      id: `severity-${sourceLevel}`,
      result: workerDraft([source]),
    });
    const rawSource = await readFile(worker.resultPath, "utf8");
    const current = await severityContext(`severity-${sourceLevel}`, [worker]);
    const rationale =
      "A source-backed control changes the demonstrated impact.";
    const changeConditions =
      "Different control coverage would change this assessment.";
    for (const explanation of [{}, { rationale }, { changeConditions }]) {
      await assert.rejects(
        recordCodexSecurityDeepReduction(
          current,
          reduction([
            { ...source, severity: { level: changedLevel, ...explanation } },
          ]),
        ),
        severityError,
        `a ${sourceLevel} to ${changedLevel} change needs both explanation fields`,
      );
    }
    await assert.rejects(readFile(path.join(current.root, "result.json")), {
      code: "ENOENT",
    });
    await assert.rejects(readdir(path.join(current.root, "checkpoints")), {
      code: "ENOENT",
    });
    assert.equal(await readFile(worker.resultPath, "utf8"), rawSource);

    const justified = {
      ...source,
      severity: { level: changedLevel, rationale, changeConditions },
    };
    await recordCodexSecurityDeepReduction(current, reduction([justified]));
    const previousPath = path.join(current.root, "result.json");
    const previousBytes = await readFile(previousPath, "utf8");
    const accepted = JSON.parse(previousBytes);
    assert.deepEqual(accepted.findings[0].severity, justified.severity);
    assert.deepEqual(
      accepted.findings[0].provenance.sourceFindings[0].finding,
      source,
    );
    assert.equal(await readFile(worker.resultPath, "utf8"), rawSource);

    const later = await createWorker({
      workersRoot,
      label: `later-severity-${sourceLevel}`,
      id: `later-severity-${sourceLevel}`,
      result: workerDraft([source]),
    });
    const next = await severityContext(
      `revert-${sourceLevel}`,
      [later],
      previousPath,
    );
    await assert.rejects(
      recordCodexSecurityDeepReduction(next, reduction([source])),
      severityError,
      "matching every original source does not justify changing the previous aggregate",
    );
    await assert.rejects(readFile(path.join(next.root, "result.json")), {
      code: "ENOENT",
    });
    await assert.rejects(readdir(path.join(next.root, "checkpoints")), {
      code: "ENOENT",
    });
    assert.equal(await readFile(previousPath, "utf8"), previousBytes);
    const explainedRevert = {
      ...source,
      severity: {
        level: sourceLevel,
        rationale:
          "The new evidence establishes that the limiting control does not apply.",
        changeConditions:
          "Evidence that the control covers this path would restore the earlier assessment.",
      },
    };
    await recordCodexSecurityDeepReduction(next, reduction([explainedRevert]));
    const reverted = await readJson(next.root, "result.json");
    assert.deepEqual(reverted.findings[0].severity, explainedRevert.severity);
    assert.deepEqual(
      reverted.findings[0].provenance.previousFindings[0].severity,
      justified.severity,
    );
    assert.equal(await readFile(previousPath, "utf8"), previousBytes);

    const unchanged = await severityContext(
      `unchanged-${sourceLevel}`,
      [later],
      previousPath,
    );
    await recordCodexSecurityDeepReduction(unchanged, reduction([justified]));
    assert.deepEqual(
      (await readJson(unchanged.root, "result.json")).findings[0].severity,
      justified.severity,
    );

    const direct = await severityContext(`direct-${sourceLevel}`, [worker]);
    const directPath = path.join(direct.root, "result.json");
    const unaccountedChange = JSON.stringify(
      reduction([{ ...source, severity: { level: changedLevel } }]),
    );
    await writeFile(directPath, unaccountedChange);
    const sources = await getCodexSecurityDeepReducerInputs(direct);
    const validate = () =>
      validateReducerArtifacts(
        {
          artifacts: createDeepScanArtifacts(scanRoot),
          artifactDir: direct.root,
          resultPath: directPath,
          reducerId: `direct-${sourceLevel}`,
          sources,
        },
        scanId,
      );
    await assert.rejects(
      validate(),
      severityError,
      "direct worker output obeys the same severity contract",
    );
    assert.equal(await readFile(directPath, "utf8"), unaccountedChange);
    await assert.rejects(readdir(path.join(direct.root, "checkpoints")), {
      code: "ENOENT",
    });
    await writeFile(directPath, JSON.stringify(reduction([justified])));
    const validated = await validate();
    assert.deepEqual(validated.result.findings[0].severity, justified.severity);
    assert.deepEqual(
      await readJson(direct.root, "result.json"),
      validated.result,
    );
  }

  const mediumShared = { ...shared, severity: { level: "medium" } };
  const conflictingWorker = await createWorker({
    workersRoot,
    label: "severity-conflict",
    id: "severity-conflict",
    result: workerDraft([mediumShared]),
  });
  const conflicting = await severityContext("severity-conflict", [
    first,
    conflictingWorker,
  ]);
  const conflictFinding = {
    ...shared,
    provenance: {
      ...shared.provenance,
      sourceFindingIds: ["worker-001:0", "severity-conflict:0"],
    },
  };
  await assert.rejects(
    recordCodexSecurityDeepReduction(conflicting, reduction([conflictFinding])),
    severityError,
  );
  const explainedConflict = {
    ...conflictFinding,
    severity: {
      level: "high",
      rationale:
        "The retained source demonstrates the additional reachable impact.",
      changeConditions:
        "Evidence excluding that impact would lower the assessment.",
    },
  };
  await recordCodexSecurityDeepReduction(
    conflicting,
    reduction([explainedConflict]),
  );
  const reconciled = await readJson(conflicting.root, "result.json");
  assert.deepEqual(reconciled.findings[0].severity, explainedConflict.severity);
  assert.deepEqual(
    reconciled.findings[0].provenance.sourceFindings.map(
      (entry: { finding: Finding }) => entry.finding.severity.level,
    ),
    ["high", "medium"],
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
  const { coverage: _coverage, ...result } = worker.result;
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
