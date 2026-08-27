import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { build } from "esbuild";

const bundled = await build({
  bundle: true,
  entryPoints: [new URL("../src/artifact-deep-reducer.ts", import.meta.url).pathname],
  format: "esm",
  platform: "node",
  write: false
});
const {
  deepReducerInputsInputSchema,
  deepReductionInputSchema,
  getCodexSecurityDeepReducerInputs,
  recordCodexSecurityDeepReduction
} = await import(
  "data:text/javascript;base64,"
  + Buffer.from(bundled.outputFiles[0].contents).toString("base64")
);

const scanId = "7fc17317-9594-49e0-b06a-d72fd7e14bba";
const validDraft = draft([]);

assert.equal(deepReducerInputsInputSchema.safeParse({}).success, true);
assert.equal(deepReducerInputsInputSchema.safeParse({ path: "/tmp" }).success, false);
assert.equal(deepReductionInputSchema.safeParse(validDraft).success, true);
assert.equal(
  deepReductionInputSchema.safeParse({ ...validDraft, resultPath: "/tmp" }).success,
  false
);
assert.equal(
  deepReductionInputSchema.safeParse({ ...validDraft, consumedWorkerIds: ["spoofed"] }).success,
  false
);
assert.equal(
  deepReductionInputSchema.safeParse({ candidates: [], merges: [] }).success,
  false
);

const root = await realpath(
  await mkdtemp(path.join(tmpdir(), "codex-security-deep-reducer-"))
);
try {
  const scanRoot = path.join(root, "scan");
  const workersRoot = path.join(scanRoot, "artifacts", "deep_discovery", "workers");
  const dedupRoot = path.join(scanRoot, "artifacts", "deep_discovery", "dedup");
  await Promise.all([
    mkdir(workersRoot, { recursive: true }),
    mkdir(dedupRoot, { recursive: true })
  ]);

  const shared = finding("shared", "src/shared.ts");
  const independent = finding("independent", "src/independent.ts");
  const first = await createWorker({
    workersRoot,
    label: "discovery-0001",
    id: "worker-001",
    result: draft([shared], {
      threatModel: { summary: "Requests may reach shared code." }
    }),
    completionSequence: 1
  });
  const second = await createWorker({
    workersRoot,
    label: "discovery-0002",
    id: "worker-002",
    result: draft([shared, independent], {
      scope: { summary: "Shared and independent request handling." }
    }),
    completionSequence: 2
  });
  const outputRoot = path.join(dedupRoot, "dedup-0001", "output");
  await mkdir(outputRoot, { recursive: true });
  const context = {
    root: outputRoot,
    repoRoot: root,
    scanId,
    layout: "reducer",
    deepReducer: {
      scanRoot,
      claimedWorkers: [first, second]
    }
  };

  const inputs = await getCodexSecurityDeepReducerInputs(context);
  await assert.rejects(
    recordCodexSecurityDeepReduction(context, draft([shared])),
    /unaccounted|discarded.*finding/,
    "a successful reduction must account for every fresh finding, not just one",
  );
  await assert.rejects(
    recordCodexSecurityDeepReduction(context, draft([shared, independent, finding("invented", "src/unreviewed.ts")])),
    /no assigned source finding/,
    "a reducer cannot introduce an unvalidated finding outside its assigned sources",
  );
  assert.deepEqual(inputs, {
    discoveries: [
      { workerId: first.id, result: withSourceRefs(first) },
      { workerId: second.id, result: withSourceRefs(second) }
    ],
    previous: null
  });
  assert.equal(JSON.stringify(inputs).includes(root), false);
  assert.equal(JSON.stringify(inputs).includes("result.json"), false);

  const invalidCoverage = {
    ...first.result,
    coverage: {
      ...first.result.coverage,
      deferred: [{ reason: "A related path needs follow-up." }]
    }
  };
  await assert.rejects(
    recordCodexSecurityDeepReduction(context, invalidCoverage),
    /complete coverage cannot contain deferred/
  );
  await assert.rejects(
    readFile(path.join(outputRoot, "result.json"), "utf8"),
    { code: "ENOENT" }
  );
  await assert.rejects(
    recordCodexSecurityDeepReduction(context, draft([])),
    /discarded every accepted Standard scan finding/
  );

  const merged = draft([shared, independent], {
    threatModel: { summary: "Requests reach shared and independent code." },
    scope: { summary: "Shared and independent request handling." }
  });
  const outcome = await recordCodexSecurityDeepReduction(context, merged);
  const mergedWithSources = {
    ...merged,
    findings: [
      retainedFinding(shared, [{ id: "worker-001:0", finding: shared }, { id: "worker-002:0", finding: shared }]),
      retainedFinding(independent, [{ id: "worker-002:1", finding: independent }]),
    ],
  };
  assert.deepEqual(outcome, {
    findingCount: 2,
    consumedWorkerIds: [first.id, second.id]
  });
  assert.deepEqual(
    JSON.parse(await readFile(path.join(outputRoot, "result.json"), "utf8")),
    mergedWithSources
  );

  const rejectedCoverage = {
    completeness: "partial",
    surfaces: [
      { label: "SQL route", disposition: "rejected", notes: "Parameterized queries prevent injection." },
      { label: "Archive upload", disposition: "needs_follow_up", notes: "The guard still needs review." },
    ],
    explicitExclusions: [{ pattern: "vendor", reason: "Outside the requested source scope." }],
    deferred: [{ candidateId: "candidate-upload", reason: "Review the guard.", paths: ["src/upload.ts"] }],
    openQuestions: ["Does the alternate upload handler use the guard?"],
  };
  const coverageWorker = await createWorker({
    workersRoot, label: "discovery-coverage", id: "worker-coverage",
    result: draft([], { coverage: rejectedCoverage }), completionSequence: 4,
  });
  const coverageRoot = path.join(dedupRoot, "dedup-coverage", "output");
  await mkdir(coverageRoot, { recursive: true });
  const coverageContext = {
    ...context, root: coverageRoot,
    deepReducer: { scanRoot, claimedWorkers: [coverageWorker] },
  };
  await recordCodexSecurityDeepReduction(coverageContext, draft([]));
  assert.deepEqual(
    JSON.parse(await readFile(path.join(coverageRoot, "result.json"), "utf8")).coverage,
    rejectedCoverage,
    "reduction preserves rejection reasons and unfinished review even when the model omits them",
  );

  const collision = { ...independent, ruleId: shared.ruleId, identity: shared.identity };
  const collisionWorker = await createWorker({
    workersRoot, label: "discovery-collision", id: "worker-collision",
    result: draft([shared, collision]), completionSequence: 5,
  });
  const collisionRoot = path.join(dedupRoot, "dedup-collision", "output");
  await mkdir(collisionRoot, { recursive: true });
  const collisionContext = {
    ...context, root: collisionRoot,
    deepReducer: { scanRoot, claimedWorkers: [collisionWorker] },
  };
  await assert.rejects(recordCodexSecurityDeepReduction(collisionContext, draft([shared])), /ambiguous|unaccounted/);
  const collisionInputs = await getCodexSecurityDeepReducerInputs(collisionContext);
  const sourceFindingIds = collisionInputs.discoveries[0].result.findings.flatMap(
    finding => finding.provenance.sourceFindingIds,
  );
  assert.deepEqual(sourceFindingIds, ["worker-collision:0", "worker-collision:1"]);
  await recordCodexSecurityDeepReduction(collisionContext, draft([{
    ...shared, provenance: { ...shared.provenance, sourceFindingIds },
  }]));
  const collisionOutput = JSON.parse(await readFile(path.join(collisionRoot, "result.json"), "utf8"));
  assert.deepEqual(collisionOutput.findings[0].provenance.sourceFindings, [
    { id: "worker-collision:0", finding: shared },
    { id: "worker-collision:1", finding: collision },
  ]);
  await assert.rejects(recordCodexSecurityDeepReduction(collisionContext, draft([{
    ...shared, provenance: { ...shared.provenance, sourceFindingIds: ["unassigned:0"] },
  }])), /unknown source finding/);
  await assert.rejects(
    readFile(path.join(scanRoot, "artifacts", "02_discovery", "candidate_ledger.jsonl")),
    { code: "ENOENT" }
  );

  const third = await createWorker({
    workersRoot,
    label: "discovery-0003",
    id: "worker-003",
    result: draft([shared]),
    completionSequence: 3
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
      previousReducerResultPath: path.join(outputRoot, "result.json")
    }
  };
  const nextInputs = await getCodexSecurityDeepReducerInputs(nextContext);
  assert.deepEqual(nextInputs, {
    discoveries: [{ workerId: third.id, result: withSourceRefs(third) }],
    previous: mergedWithSources
  });
  await assert.rejects(
    recordCodexSecurityDeepReduction(nextContext, draft([shared])),
    (error) => error.code === "merge_traceability_unstable_candidate_id"
  );
  assert.deepEqual(
    await recordCodexSecurityDeepReduction(nextContext, merged),
    { findingCount: 2, consumedWorkerIds: [third.id] }
  );
  assert.deepEqual(
    JSON.parse(await readFile(path.join(nextOutputRoot, "result.json"), "utf8")),
    {
      ...mergedWithSources,
      findings: [
        retainedFinding(shared, [
          { id: "worker-003:0", finding: shared },
          { id: "worker-001:0", finding: shared },
          { id: "worker-002:0", finding: shared },
        ]),
        mergedWithSources.findings[1],
      ],
    }
  );

  const enrichedPrevious = structuredClone(mergedWithSources);
  enrichedPrevious.findings[0].summary = "The earlier reduction established an additional reachable output route.";
  enrichedPrevious.findings[0].validation = { summary: "Both output routes bypass the same encoding control." };
  await writeFile(path.join(outputRoot, "result.json"), JSON.stringify(enrichedPrevious));
  await recordCodexSecurityDeepReduction(nextContext, merged);
  const preservedEnrichment = JSON.parse(await readFile(path.join(nextOutputRoot, "result.json"), "utf8"));
  assert.equal(
    preservedEnrichment.findings[0].provenance.previousFindings[0].summary,
    enrichedPrevious.findings[0].summary,
    "previous synthesized evidence must survive even when source references are unchanged",
  );

  await assert.rejects(
    getCodexSecurityDeepReducerInputs({ root, repoRoot: root, layout: "scan" }),
    /No active Deep reducer is bound/
  );
  await assert.rejects(
    recordCodexSecurityDeepReduction(context, {
      ...merged,
      scanId: "12c17317-9594-49e0-b06a-d72fd7e14bba"
    }),
    /scanId does not match/
  );
  await assert.rejects(
    recordCodexSecurityDeepReduction(context, {
      ...merged,
      findings: [{ ...shared, locations: [{ path: "src/shared.ts", startLine: 3, endLine: 2 }] }]
    }),
    /endLine/
  );
  await assert.rejects(
    getCodexSecurityDeepReducerInputs({
      ...context,
      deepReducer: { ...context.deepReducer, claimedWorkers: [first, first] }
    }),
    /repeats assigned Standard scan worker/
  );

  await writeFile(first.resultPath, "{invalid Standard scan\n");
  await assert.rejects(
    getCodexSecurityDeepReducerInputs(context),
    (error) => error.name !== "DeepScanNonRetryableError"
      && /Invalid Deep Scan JSON artifact/.test(error.message)
      && !error.message.includes(root)
  );

  await writeFile(first.resultPath, JSON.stringify({
    ...first.result,
    scanId: "12c17317-9594-49e0-b06a-d72fd7e14bba"
  }));
  await assert.rejects(
    getCodexSecurityDeepReducerInputs(context),
    (error) => error.name !== "DeepScanNonRetryableError"
      && /different scan/.test(error.message)
      && !error.message.includes(root)
  );
} finally {
  await rm(root, { recursive: true, force: true });
}

console.log("artifact deep reducer tests passed");

async function createWorker({ workersRoot, label, id, result, completionSequence }) {
  const workerRoot = path.join(workersRoot, label, "output");
  await mkdir(workerRoot, { recursive: true });
  const resultPath = path.join(workerRoot, "result.json");
  await writeFile(resultPath, JSON.stringify(result) + "\n");
  return { id, resultPath, completionSequence, result };
}

function draft(findings, extra = {}) {
  return {
    scanId,
    findings,
    coverage: {
      completeness: "complete",
      surfaces: [],
      explicitExclusions: [],
      deferred: []
    },
    ...extra
  };
}

function withSourceRefs(worker) {
  return {
    ...worker.result,
    findings: worker.result.findings.map((finding, index) => ({
      ...finding,
      provenance: { ...finding.provenance, sourceFindingIds: [`${worker.id}:${index}`] },
    })),
  };
}

function retainedFinding(finding, sourceFindings) {
  return {
    ...finding,
    provenance: {
      ...finding.provenance,
      sourceFindingIds: sourceFindings.map((source) => source.id),
      sourceFindings,
    },
  };
}

function finding(id, repositoryPath) {
  return {
    ruleId: "cross-site-scripting." + id,
    identity: { anchor: id },
    title: "Unsafe request output " + id,
    summary: "A request-controlled value reaches an HTML response.",
    severity: { level: "high" },
    confidence: { level: "high", rationale: "The source establishes reachability." },
    taxonomy: { category: "cross-site-scripting", cwe: ["CWE-79"] },
    locations: [{ path: repositoryPath, startLine: 1, endLine: 2 }],
    remediation: "Encode request-controlled values before emitting HTML.",
    provenance: { source: "local_plugin" }
  };
}
