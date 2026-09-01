import assert from "node:assert/strict";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { build } from "esbuild";

const bundle = await build({
  bundle: true,
  entryPoints: [new URL("../src/deep-scan/artifact-validation.ts", import.meta.url).pathname],
  format: "esm",
  platform: "node",
  write: false
});
const {
  validateDiscoveryArtifacts,
  validateReducerArtifacts
} = await import(
  "data:text/javascript;base64,"
  + Buffer.from(bundle.outputFiles[0].contents).toString("base64")
);

const scanId = "7fc17317-9594-49e0-b06a-d72fd7e14bba";
const otherScanId = "12c17317-9594-49e0-b06a-d72fd7e14bba";
const root = await realpath(await mkdtemp(path.join(tmpdir(), "deep-scan-artifact-validation-")));
try {
  await testDiscoveryValidation(root);
  await testReducerValidation(root);
  await testEmptyDiscoveryAndReduction(root);
} finally {
  await rm(root, { recursive: true, force: true });
}

console.log("deep scan artifact validation tests passed");

async function testDiscoveryValidation(root) {
  const artifacts = await createLayout(path.join(root, "discovery"));
  const result = draft([finding("shared", "src/a.js")], {
    threatModel: { summary: "Requests reach shared code." }
  });
  const worker = await createWorker(artifacts, "discovery-0001", "worker-001", result);

  await writeResult(worker.resultPath, { ...result, complete: false });
  await assert.rejects(
    validateDiscoveryArtifacts(artifacts, worker.resultPath, scanId),
    /only a checkpoint|not complete/,
  );
  await writeResult(worker.resultPath, result);

  assert.deepEqual(
    await validateDiscoveryArtifacts(artifacts, worker.resultPath, scanId),
    result
  );

  const legacyFinding = {
    ...result.findings[0],
    attackPath: { steps: { first: "upload" } },
    code_evidence: null,
    root_cause: null,
    validation: { evidence: { kind: "trace" } }
  };
  await writeResult(worker.resultPath, { ...result, findings: [legacyFinding] });
  const recoveredLegacy = await validateDiscoveryArtifacts(
    artifacts,
    worker.resultPath,
    scanId
  );
  assert.deepEqual(recoveredLegacy.findings[0], {
    ...result.findings[0],
    attackPath: {},
    validation: {}
  });
  await writeResult(worker.resultPath, {
    ...result,
    findings: [{ ...result.findings[0], root_cause: "" }]
  });
  assert.deepEqual(
    await validateDiscoveryArtifacts(artifacts, worker.resultPath, scanId),
    result
  );

  await writeResult(worker.resultPath, {
    ...result,
    findings: [{
      ...result.findings[0],
      root_cause: " ",
      validation: {
        method: " ",
        status: " ",
        summary: " ",
        disposition: " ",
        result: " "
      },
      attackPath: {
        summary: " ",
        dataFlow: " ",
        data_flow: { summary: " ", source: " ", sink: " ", outcome: " " },
        reachability: {
          summary: " ",
          attacker: " ",
          entrypoint: " ",
          source: " ",
          sink: " ",
          outcome: " "
        },
        impact: " ",
        likelihood: { level: " ", rationale: " ", why: " " }
      }
    }]
  });
  assert.deepEqual(
    await validateDiscoveryArtifacts(artifacts, worker.resultPath, scanId),
    {
      ...result,
      findings: [{
        ...result.findings[0],
        validation: {},
        attackPath: {
          data_flow: {},
          reachability: {},
          likelihood: {}
        }
      }]
    }
  );

  await writeResult(worker.resultPath, { ...result, scanId: otherScanId });
  await assert.rejects(
    validateDiscoveryArtifacts(artifacts, worker.resultPath, scanId),
    /different scan/
  );

  await writeResult(worker.resultPath, {
    ...result,
    coverage: { ...result.coverage, deferred: [{ reason: "Needs follow-up." }] }
  });
  await assert.rejects(
    validateDiscoveryArtifacts(artifacts, worker.resultPath, scanId),
    /complete coverage cannot contain deferred/
  );

  await writeResult(worker.resultPath, {
    ...result,
    coverage: {
      ...result.coverage,
      surfaces: [{ label: "Unfinished Standard review", disposition: "needs_follow_up" }],
    },
  });
  await assert.rejects(
    validateDiscoveryArtifacts(artifacts, worker.resultPath, scanId),
    /complete coverage cannot contain needs_follow_up/,
    "reducer coverage normalization must not relax Standard discovery semantics",
  );

  await writeResult(worker.resultPath, {
    ...result,
    findings: [{
      ...result.findings[0],
      locations: [{ path: "src/a.js", startLine: 3, endLine: 2 }]
    }]
  });
  await assert.rejects(
    validateDiscoveryArtifacts(artifacts, worker.resultPath, scanId),
    /endLine/
  );

  await writeFile(worker.resultPath, "{invalid JSON");
  await assert.rejects(
    validateDiscoveryArtifacts(artifacts, worker.resultPath, scanId),
    /Invalid Deep Scan JSON artifact/
  );

  await writeResult(worker.resultPath, draft([]));
  await validateDiscoveryArtifacts(artifacts, worker.resultPath, scanId);

  if (process.platform !== "win32") {
    const outside = path.join(root, "outside-result.json");
    await writeResult(outside, result);
    await rm(worker.resultPath);
    await symlink(outside, worker.resultPath, "file");
    await assert.rejects(
      validateDiscoveryArtifacts(artifacts, worker.resultPath, scanId),
      /escaped its scan directory|canonical non-symlink path/
    );
  }
}

async function testReducerValidation(root) {
  const artifacts = await createLayout(path.join(root, "reducer"));
  const firstFinding = finding("shared", "src/a.js");
  const secondFinding = finding("independent", "src/b.js");
  const first = await createWorker(
    artifacts,
    "discovery-0001",
    "worker-001",
    draft([firstFinding])
  );
  const second = await createWorker(
    artifacts,
    "discovery-0002",
    "worker-002",
    draft([firstFinding, secondFinding])
  );
  const artifactDir = path.join(artifacts.dedupRoot, "dedup-0001", "output");
  const resultPath = path.join(artifactDir, "result.json");
  await mkdir(artifactDir, { recursive: true });
  await writeResult(resultPath, draft([firstFinding]));

  const sources = {
    discoveries: [{ workerId: first.id, result: draft([firstFinding, secondFinding]) }],
    previous: null,
  };
  const validateSnapshot = () => validateReducerArtifacts({
    artifacts, artifactDir, resultPath, reducerId: "dedup-0001", sources,
  }, scanId);
  await assert.rejects(validateSnapshot(), /unaccounted source findings/);
  await writeResult(resultPath, draft([firstFinding, secondFinding]));
  await writeFile(first.resultPath, "{source changed after dispatch");
  const validatedSnapshot = await validateSnapshot();
  assert.equal(validatedSnapshot.newFindings, 2);
  const admitted = JSON.parse(await readFile(resultPath, "utf8"));
  assert.deepEqual(
    validatedSnapshot.result,
    admitted,
    "validation returns the same reconciled result that was accepted on disk",
  );
  assert.equal(Object.hasOwn(admitted, "coverage"), false);
  assert.deepEqual(admitted.findings[1].provenance.sourceFindingIds, ["worker-001:1"]);
  sources.previous = structuredClone(admitted);
  sources.previous.findings[0].summary = "Additional proof established by the previous reducer.";
  await writeResult(resultPath, draft([firstFinding, secondFinding]));
  assert.equal((await validateSnapshot()).newFindings, 0);
  assert.equal(
    JSON.parse(await readFile(resultPath, "utf8")).findings[0].provenance.previousFindings[0].summary,
    sources.previous.findings[0].summary,
  );

  const inheritedThreatModel = { summary: "Internet requests reach the shared handler." };
  const threatModelSources = {
    discoveries: [{
      workerId: first.id,
      result: draft([firstFinding], { threatModel: inheritedThreatModel }),
    }],
    previous: null,
  };
  await writeResult(resultPath, draft([firstFinding]));
  await validateReducerArtifacts({
    artifacts,
    artifactDir,
    resultPath,
    reducerId: "dedup-threat-model",
    sources: threatModelSources,
  }, scanId);
  assert.deepEqual(
    JSON.parse(await readFile(resultPath, "utf8")).threatModel,
    inheritedThreatModel,
    "a reducer cannot erase the accepted discovery threat model by omission",
  );

  await writeResult(resultPath, draft([]));
  await assert.rejects(
    validateReducerArtifacts({
      artifacts,
      artifactDir,
      resultPath,
      reducerId: "dedup-ambiguous-threat-model",
      sources: {
        discoveries: [
          { workerId: "worker-a", result: draft([], { threatModel: { summary: "Public API." } }) },
          { workerId: "worker-b", result: draft([], { threatModel: { summary: "Local operator." } }) },
        ],
        previous: null,
      },
    }, scanId),
    /ambiguous threat models/i,
  );

  const inheritedScope = { summary: "Shared request handlers", includePaths: ["src"] };
  await writeResult(resultPath, draft([firstFinding]));
  await validateReducerArtifacts({
    artifacts,
    artifactDir,
    resultPath,
    reducerId: "dedup-scope",
    sources: {
      discoveries: [{ workerId: first.id, result: draft([firstFinding], { scope: inheritedScope }) }],
      previous: null,
    },
  }, scanId);
  assert.deepEqual(
    JSON.parse(await readFile(resultPath, "utf8")).scope,
    inheritedScope,
    "a reducer cannot erase an unambiguous accepted scope by omission",
  );

  const resolvedCoverageSurface = {
    label: "Archive extraction",
    disposition: "reported",
    riskArea: "filesystem",
    notes: "The reducer completed the extraction review.",
  };

  await writeResult(resultPath, draft([]));
  await assert.rejects(
    validateReducerArtifacts({
      artifacts,
      artifactDir,
      resultPath,
      reducerId: "dedup-ambiguous-scope",
      sources: {
        discoveries: [
          { workerId: "worker-a", result: draft([], { scope: { summary: "Public API" } }) },
          { workerId: "worker-b", result: draft([], { scope: { summary: "Admin API" } }) },
        ],
        previous: null,
      },
    }, scanId),
    /ambiguous scopes/i,
  );

  const collidingOriginalA = firstFinding;
  const collidingOriginalB = {
    ...firstFinding,
    title: "Second independently reachable instance",
    summary: "A second route reaches the same vulnerable control.",
    locations: [{ path: "src/second-route.js", startLine: 4 }],
  };
  const previousCollisionA = {
    ...collidingOriginalA,
    summary: "Previous evidence for the first route.",
    provenance: {
      source: "local_plugin",
      sourceFindingIds: ["origin:a"],
      sourceFindings: [{ id: "origin:a", finding: collidingOriginalA }],
    },
  };
  const previousCollisionB = {
    ...collidingOriginalB,
    summary: "Previous evidence for the second route.",
    provenance: {
      source: "local_plugin",
      sourceFindingIds: ["origin:b"],
      sourceFindings: [{ id: "origin:b", finding: collidingOriginalB }],
    },
  };
  const collidingSources = {
    discoveries: [],
    previous: draft([previousCollisionA, previousCollisionB]),
  };
  await writeResult(resultPath, draft([
    {
      ...collidingOriginalA,
      provenance: { source: "local_plugin", sourceFindingIds: ["origin:a"] },
    },
    {
      ...collidingOriginalB,
      provenance: { source: "local_plugin", sourceFindingIds: ["origin:b"] },
    },
  ]));
  await validateReducerArtifacts({
    artifacts,
    artifactDir,
    resultPath,
    reducerId: "dedup-colliding-previous",
    sources: collidingSources,
  }, scanId);
  const reconciledCollisions = JSON.parse(await readFile(resultPath, "utf8")).findings;
  assert.deepEqual(
    reconciledCollisions.map((item) => item.provenance.sourceFindingIds),
    [["origin:a"], ["origin:b"]],
  );
  assert.deepEqual(
    reconciledCollisions.map((item) => item.provenance.previousFindings[0].summary),
    [previousCollisionA.summary, previousCollisionB.summary],
  );
  await writeResult(first.resultPath, draft([firstFinding]));
  await writeResult(resultPath, draft([firstFinding]));

  const validate = (previousReducerResultPath) => validateReducerArtifacts({
    artifacts,
    artifactDir,
    resultPath,
    reducerId: "dedup-0001",
    ...(previousReducerResultPath ? { previousReducerResultPath } : {})
  }, scanId);

  assert.equal((await validate()).newFindings, 1);

  const legacyPartial = draft([firstFinding], {
    coverage: {
      completeness: "partial",
      surfaces: [
        { ...resolvedCoverageSurface, receiptRefs: ["artifacts/missing-worker-receipt.md"] },
        { label: "Legacy follow-up", disposition: "needs_follow_up" },
      ],
      explicitExclusions: [{ pattern: "vendor", reason: "Outside the requested source scope." }],
      deferred: [{ reason: "A previous reducer retained worker follow-up work." }],
      openQuestions: ["Should a future review include generated handlers?"],
    },
  });
  for (const [label, legacyCoverage] of [
    ["partial", legacyPartial.coverage],
    ["complete with pending work", { ...legacyPartial.coverage, completeness: "complete" }],
    ["malformed", null],
  ]) {
    const legacyReducer = {
      ...legacyPartial,
      coverage: legacyCoverage,
    };
    await writeResult(resultPath, legacyReducer);
    const legacyArtifact = await readFile(resultPath, "utf8");
    const resumed = await validate();
    assert.equal(resumed.newFindings, 1);
    assert.deepEqual(resumed.result, { scanId, findings: [firstFinding] });
    assert.equal(
      await readFile(resultPath, "utf8"),
      legacyArtifact,
      `resuming a reducer with ${label} coverage ignores it without rewriting the original artifact`,
    );
  }
  await writeResult(resultPath, { ...legacyPartial, complete: false });
  await assert.rejects(validate(), /only a checkpoint|not complete/);

  await writeResult(resultPath, draft([]));
  assert.equal((await validate()).newFindings, 0);

  await writeResult(resultPath, { ...draft([firstFinding]), resultPath: "/tmp/result.json" });
  await assert.rejects(validate(), /resultPath/);

  await writeResult(resultPath, draft([firstFinding, secondFinding]));
  assert.equal((await validate()).newFindings, 2);

  const previousReducerResultPath = path.join(
    artifacts.dedupRoot,
    "dedup-0000",
    "output",
    "result.json"
  );
  await mkdir(path.dirname(previousReducerResultPath), { recursive: true });
  await writeResult(previousReducerResultPath, {
    ...legacyPartial,
    coverage: "malformed legacy coverage",
  });
  const previousArtifact = await readFile(previousReducerResultPath, "utf8");
  assert.equal(
    (await validate(previousReducerResultPath)).newFindings,
    1,
    "malformed previous reducer coverage is ignored and does not change finding novelty",
  );
  assert.equal(
    await readFile(previousReducerResultPath, "utf8"),
    previousArtifact,
    "reading a previous reducer must not rewrite its original coverage",
  );

  const renamedTitle = { ...firstFinding, title: "Stronger explanation of the same finding." };
  await writeResult(resultPath, draft([renamedTitle, secondFinding]));
  assert.equal(
    (await validate(previousReducerResultPath)).newFindings,
    1
  );

  await writeResult(previousReducerResultPath, draft([firstFinding, secondFinding]));
  await writeResult(resultPath, draft([secondFinding]));
  await assert.rejects(
    validate(previousReducerResultPath),
    (error) => error.code === "merge_traceability_unstable_candidate_id"
  );

  const replacement = finding("replacement", "src/c.js");
  await writeResult(resultPath, draft([firstFinding, secondFinding, replacement]));
  assert.equal(
    (await validate(previousReducerResultPath)).newFindings,
    1
  );

  const implicitFirst = { ...firstFinding };
  delete implicitFirst.identity;
  const implicitRenamed = { ...implicitFirst, summary: "More complete evidence." };
  await writeResult(previousReducerResultPath, draft([implicitFirst]));
  await writeResult(resultPath, draft([implicitRenamed]));
  assert.equal(
    (await validate(previousReducerResultPath)).newFindings,
    0
  );
  await writeResult(resultPath, draft([{
    ...implicitRenamed,
    locations: [
      ...implicitRenamed.locations,
      { path: "src/another-affected-location.js", startLine: 4 }
    ]
  }]));
  assert.equal(
    (await validate(previousReducerResultPath)).newFindings,
    0,
    "An existing finding without an explicit identity may gain affected locations."
  );

  await writeResult(resultPath, { ...draft([firstFinding]), scanId: otherScanId });
  await assert.rejects(
    validate(),
    (error) => error.name !== "DeepScanNonRetryableError"
      && /different scan/.test(error.message)
  );

  await writeResult(resultPath, draft([firstFinding]));
  await writeResult(first.resultPath, { ...draft([firstFinding]), scanId: otherScanId });
  assert.equal(
    (await validate()).newFindings,
    1,
    "A completed aggregate must not reread already-consumed Standard results."
  );
  await writeFile(first.resultPath, "{invalid Standard scan\n");
  assert.equal(
    (await validate()).newFindings,
    1,
    "Accepted Standard inputs were already validated by the reducer writer."
  );
  await writeResult(first.resultPath, draft([firstFinding]));

  await writeResult(previousReducerResultPath, {
    ...draft([firstFinding]),
    scanId: otherScanId
  });
  await assert.rejects(
    validate(previousReducerResultPath),
    /different scan/
  );

  if (process.platform !== "win32") {
    const actualResult = path.join(artifactDir, "actual-result.json");
    await writeResult(actualResult, draft([firstFinding]));
    await rm(resultPath);
    await symlink(actualResult, resultPath, "file");
    await assert.rejects(
      validate(),
      /canonical non-symlink path/
    );
  }
}

async function testEmptyDiscoveryAndReduction(root) {
  const artifacts = await createLayout(path.join(root, "empty"));
  const worker = await createWorker(
    artifacts,
    "discovery-0001",
    "worker-empty",
    draft([])
  );
  await validateDiscoveryArtifacts(artifacts, worker.resultPath, scanId);
  const artifactDir = path.join(artifacts.dedupRoot, "dedup-empty", "output");
  const resultPath = path.join(artifactDir, "result.json");
  await mkdir(artifactDir, { recursive: true });
  await writeResult(resultPath, { scanId, findings: [] });
  const result = await validateReducerArtifacts({
    artifacts,
    artifactDir,
    resultPath,
    reducerId: "dedup-empty"
  });
  assert.equal(result.newFindings, 0);
  assert.deepEqual(
    result.result,
    { scanId, findings: [] },
    "reducers submit and return results without coverage",
  );
}

async function createLayout(scanDir) {
  const workersRoot = path.join(scanDir, "artifacts", "deep_discovery", "workers");
  const dedupRoot = path.join(scanDir, "artifacts", "deep_discovery", "dedup");
  await Promise.all([
    mkdir(workersRoot, { recursive: true }),
    mkdir(dedupRoot, { recursive: true })
  ]);
  return {
    scanDir,
    workersRoot,
    dedupRoot
  };
}

async function createWorker(artifacts, label, id, result) {
  const output = path.join(artifacts.workersRoot, label, "output");
  await mkdir(output, { recursive: true });
  const resultPath = path.join(output, "result.json");
  await writeResult(resultPath, result);
  return { id, resultPath };
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

function finding(id, candidatePath) {
  return {
    ruleId: "cross-site-scripting." + id,
    identity: { anchor: id },
    title: "Unsafe request output " + id,
    summary: "A request-controlled value reaches an HTML response.",
    severity: { level: "high" },
    confidence: { level: "high", rationale: "The source establishes reachability." },
    taxonomy: { category: "cross-site-scripting", cwe: ["CWE-79"] },
    locations: [{ path: candidatePath, startLine: 1, endLine: 2 }],
    remediation: "Encode request-controlled values before emitting HTML.",
    provenance: { source: "local_plugin" }
  };
}

async function writeResult(file, value) {
  await writeFile(file, JSON.stringify(value) + "\n");
}
