import { readJson, writeJsonLine as writeResult } from "./support/json.ts";
import { finding, scanId, workerDraft as draft } from "./scan-draft-fixture.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import assert from "node:assert/strict";
import { mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { importSource } from "./import-module.ts";

const { validateDiscoveryArtifacts, validateReducerArtifacts } =
  await importSource(
    path.join(import.meta.dirname, "../src/deep-scan/artifact-validation.ts"),
  );

const otherScanId = "12c17317-9594-49e0-b06a-d72fd7e14bba";
const root = await temporaryDirectory("deep-scan-artifact-validation-", true);
try {
  await testDiscoveryValidation(root);
  await testReducerValidation(root);
  await testEmptyDiscoveryAndReduction(root);
} finally {
  await rm(root, { recursive: true, force: true });
}

console.log("deep scan artifact validation tests passed");

async function testDiscoveryValidation(root: string) {
  const result = draft([finding("shared", "src/a.js")], {
    threatModel: { summary: "Requests reach shared code." },
  });
  const { artifacts, ...worker } = await createWorker(
    path.join(root, "discovery"),
    "worker-001",
    result,
  );

  await writeResult(worker.resultPath, { ...result, complete: false });
  await assert.rejects(
    validateDiscoveryArtifacts(artifacts, worker.resultPath, scanId),
    /only a checkpoint|not complete/,
  );
  await writeResult(worker.resultPath, result);

  assert.deepEqual(
    await validateDiscoveryArtifacts(artifacts, worker.resultPath, scanId),
    result,
  );

  const legacyFinding = {
    ...result.findings[0],
    attackPath: { steps: { first: "upload" } },
    code_evidence: null,
    root_cause: null,
    validation: { evidence: { kind: "trace" } },
  };
  await writeResult(worker.resultPath, {
    ...result,
    findings: [legacyFinding],
  });
  const recoveredLegacy = await validateDiscoveryArtifacts(
    artifacts,
    worker.resultPath,
    scanId,
  );
  assert.deepEqual(recoveredLegacy.findings[0], {
    ...result.findings[0],
    attackPath: {},
    validation: {},
  });
  await writeResult(worker.resultPath, {
    ...result,
    findings: [{ ...result.findings[0], root_cause: "" }],
  });
  assert.deepEqual(
    await validateDiscoveryArtifacts(artifacts, worker.resultPath, scanId),
    result,
  );

  await writeResult(worker.resultPath, {
    ...result,
    findings: [
      {
        ...result.findings[0],
        root_cause: " ",
        validation: {
          method: " ",
          status: " ",
          summary: " ",
          disposition: " ",
          result: " ",
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
            outcome: " ",
          },
          impact: " ",
          likelihood: { level: " ", rationale: " ", why: " " },
        },
      },
    ],
  });
  assert.deepEqual(
    await validateDiscoveryArtifacts(artifacts, worker.resultPath, scanId),
    {
      ...result,
      findings: [
        {
          ...result.findings[0],
          validation: {},
          attackPath: {
            data_flow: {},
            reachability: {},
            likelihood: {},
          },
        },
      ],
    },
  );

  await writeResult(worker.resultPath, { ...result, scanId: otherScanId });
  await assert.rejects(
    validateDiscoveryArtifacts(artifacts, worker.resultPath, scanId),
    /different scan/,
  );

  await writeResult(worker.resultPath, {
    ...result,
    coverage: {
      ...result.coverage,
      deferred: [{ reason: "Needs follow-up." }],
    },
  });
  await assert.rejects(
    validateDiscoveryArtifacts(artifacts, worker.resultPath, scanId),
    /complete coverage cannot contain deferred/,
  );

  await writeResult(worker.resultPath, {
    ...result,
    coverage: {
      ...result.coverage,
      surfaces: [
        { label: "Unfinished Standard review", disposition: "needs_follow_up" },
      ],
    },
  });
  await assert.rejects(
    validateDiscoveryArtifacts(artifacts, worker.resultPath, scanId),
    /complete coverage cannot contain needs_follow_up/,
    "reducer coverage normalization must not relax Standard discovery semantics",
  );

  await writeResult(worker.resultPath, {
    ...result,
    findings: [
      {
        ...result.findings[0],
        locations: [{ path: "src/a.js", startLine: 3, endLine: 2 }],
      },
    ],
  });
  await assert.rejects(
    validateDiscoveryArtifacts(artifacts, worker.resultPath, scanId),
    /endLine/,
  );

  await writeFile(worker.resultPath, "{invalid JSON");
  await assert.rejects(
    validateDiscoveryArtifacts(artifacts, worker.resultPath, scanId),
    /Invalid Deep Scan JSON artifact/,
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
      /escaped its scan directory|canonical non-symlink path/,
    );
  }
}

async function testReducerValidation(root: string) {
  const firstFinding = finding("shared", "src/a.js");
  const secondFinding = finding("independent", "src/b.js");
  const { artifacts, ...first } = await createWorker(
    path.join(root, "reducer"),
    "worker-001",
    draft([firstFinding]),
  );
  const artifactDir = path.join(artifacts.dedupRoot, "dedup-0001", "output");
  const resultPath = path.join(artifactDir, "result.json");
  await mkdir(artifactDir, { recursive: true });
  await writeResult(resultPath, draft([firstFinding]));

  const sources: import("../src/deep-scan/artifact-validation.js").DeepReductionSources =
    {
      discoveries: [
        { workerId: first.id, result: draft([firstFinding, secondFinding]) },
      ],
      previous: null,
    };
  const validateSnapshot = (reducerId = "dedup-0001", snapshot = sources) =>
    validateReducerArtifacts(
      { artifacts, artifactDir, resultPath, reducerId, sources: snapshot },
      scanId,
    );
  await assert.rejects(validateSnapshot(), /unaccounted source findings/);
  await writeResult(resultPath, draft([firstFinding, secondFinding]));
  await writeFile(first.resultPath, "{source changed after dispatch");
  const validatedSnapshot = await validateSnapshot();
  assert.equal(validatedSnapshot.newFindings, 2);
  const admitted = await readJson(resultPath);
  assert.deepEqual(
    validatedSnapshot.result,
    admitted,
    "validation returns the same reconciled result that was accepted on disk",
  );
  assert.equal(Object.hasOwn(admitted, "coverage"), false);
  assert.deepEqual(admitted.findings[1].provenance.sourceFindingIds, [
    "worker-001:1",
  ]);
  sources.previous = structuredClone(admitted);
  sources.previous!.findings[0].summary =
    "Additional proof established by the previous reducer.";
  await writeResult(resultPath, draft([firstFinding, secondFinding]));
  assert.equal((await validateSnapshot()).newFindings, 0);
  assert.equal(
    (await readJson(resultPath)).findings[0].provenance.previousFindings[0]
      .summary,
    sources.previous!.findings[0].summary,
  );

  const inheritedThreatModel = {
    summary: "Internet requests reach the shared handler.",
  };
  const threatModelSources = {
    discoveries: [
      {
        workerId: first.id,
        result: draft([firstFinding], { threatModel: inheritedThreatModel }),
      },
    ],
    previous: null,
  };
  await writeResult(resultPath, draft([firstFinding]));
  await validateSnapshot("dedup-threat-model", threatModelSources);
  assert.deepEqual(
    (await readJson(resultPath)).threatModel,
    inheritedThreatModel,
    "a reducer cannot erase the accepted discovery threat model by omission",
  );

  await writeResult(resultPath, draft([]));
  await assert.rejects(
    validateSnapshot("dedup-ambiguous-threat-model", {
      discoveries: [
        {
          workerId: "worker-a",
          result: draft([], {
            threatModel: { summary: "Public API." },
            scope: { summary: "Public API" },
          }),
        },
        {
          workerId: "worker-b",
          result: draft([], {
            threatModel: { summary: "Local operator." },
            scope: { summary: "Local operator" },
          }),
        },
      ],
      previous: null,
    }),
    /ambiguous threat models/i,
  );

  const inheritedScope = {
    summary: "Shared request handlers",
    includePaths: ["src"],
  };
  await writeResult(resultPath, draft([firstFinding]));
  await validateSnapshot("dedup-scope", {
    discoveries: [
      {
        workerId: first.id,
        result: draft([firstFinding], { scope: inheritedScope }),
      },
    ],
    previous: null,
  });
  assert.deepEqual(
    (await readJson(resultPath)).scope,
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
    validateSnapshot("dedup-ambiguous-scope", {
      discoveries: [
        {
          workerId: "worker-a",
          result: draft([], { scope: { summary: "Public API" } }),
        },
        {
          workerId: "worker-b",
          result: draft([], { scope: { summary: "Admin API" } }),
        },
      ],
      previous: null,
    }),
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
  await writeResult(
    resultPath,
    draft([
      {
        ...collidingOriginalA,
        provenance: { source: "local_plugin", sourceFindingIds: ["origin:a"] },
      },
      {
        ...collidingOriginalB,
        provenance: { source: "local_plugin", sourceFindingIds: ["origin:b"] },
      },
    ]),
  );
  await validateSnapshot("dedup-colliding-previous", collidingSources);
  const reconciledCollisions = (await readJson(resultPath)).findings;
  assert.deepEqual(
    reconciledCollisions.map(
      (item: { provenance: { sourceFindingIds: string[] } }) =>
        item.provenance.sourceFindingIds,
    ),
    [["origin:a"], ["origin:b"]],
  );
  assert.deepEqual(
    reconciledCollisions.map(
      (item: { provenance: { previousFindings: { summary: string }[] } }) =>
        item.provenance.previousFindings[0].summary,
    ),
    [previousCollisionA.summary, previousCollisionB.summary],
  );
  const referenced = (original: Record<string, unknown>, refs: string[]) => ({
    ...original,
    provenance: { source: "local_plugin", sourceFindingIds: refs },
  });
  for (const [label, previous, output, expected] of [
    [
      "independent",
      [previousCollisionA],
      [
        referenced(collidingOriginalA, ["origin:a"]),
        referenced(collidingOriginalB, ["fresh:0"]),
      ],
      1,
    ],
    [
      "repeat",
      [previousCollisionA],
      [referenced(collidingOriginalA, ["origin:a", "fresh:0"])],
      0,
    ],
    [
      "consolidate",
      [previousCollisionA, previousCollisionB],
      [
        referenced(collidingOriginalA, ["origin:a", "origin:b"]),
        referenced(collidingOriginalB, ["fresh:0"]),
      ],
      1,
    ],
    [
      "legacy",
      [
        {
          ...referenced(collidingOriginalA, ["legacy-id-without-body"]),
          summary: "Previously accepted legacy evidence.",
        },
      ],
      [
        referenced(collidingOriginalB, ["fresh:0"]),
        referenced(collidingOriginalA, ["previous:0"]),
      ],
      1,
    ],
  ] as const) {
    const snapshot = {
      discoveries: [{ workerId: "fresh", result: draft([collidingOriginalB]) }],
      previous: draft([...previous]),
    };
    await writeResult(resultPath, draft([...output]));
    const accepted = await validateSnapshot(`dedup-${label}`, snapshot);
    assert.equal(accepted.newFindings, expected, label);
    if (label === "legacy") {
      assert.equal(
        accepted.result.findings[0].provenance.previousFindings,
        undefined,
      );
      assert.equal(
        accepted.result.findings[1].provenance.previousFindings[0].title,
        collidingOriginalA.title,
      );
    }
    // Reopening the accepted JSON keeps the same ancestry and adds no finding.
    assert.equal(
      (
        await validateSnapshot(`resume-${label}`, {
          discoveries: [],
          previous: await readJson(resultPath),
        })
      ).newFindings,
      0,
      label,
    );
  }
  await writeResult(first.resultPath, draft([firstFinding]));
  await writeResult(resultPath, draft([firstFinding]));

  const validate = (previousReducerResultPath?: string) =>
    validateReducerArtifacts(
      {
        artifacts,
        artifactDir,
        resultPath,
        reducerId: "dedup-0001",
        ...(previousReducerResultPath ? { previousReducerResultPath } : {}),
      },
      scanId,
    );

  assert.equal((await validate()).newFindings, 1);

  const legacyPartial = draft([firstFinding], {
    coverage: {
      completeness: "partial",
      surfaces: [
        {
          ...resolvedCoverageSurface,
          receiptRefs: ["artifacts/missing-worker-receipt.md"],
        },
        { label: "Legacy follow-up", disposition: "needs_follow_up" },
      ],
      explicitExclusions: [
        { pattern: "vendor", reason: "Outside the requested source scope." },
      ],
      deferred: [
        { reason: "A previous reducer retained worker follow-up work." },
      ],
      openQuestions: ["Should a future review include generated handlers?"],
    },
  });
  for (const [label, legacyCoverage] of [
    ["partial", legacyPartial.coverage],
    [
      "complete with pending work",
      { ...legacyPartial.coverage, completeness: "complete" },
    ],
    ["malformed", null],
  ] as const) {
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

  await writeResult(resultPath, {
    ...draft([firstFinding]),
    resultPath: "/tmp/result.json",
  });
  await assert.rejects(validate(), /resultPath/);

  await writeResult(resultPath, draft([firstFinding, secondFinding]));
  assert.equal((await validate()).newFindings, 2);

  const previousReducerResultPath = path.join(
    artifacts.dedupRoot,
    "dedup-0000",
    "output",
    "result.json",
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

  const renamedTitle = {
    ...firstFinding,
    title: "Stronger explanation of the same finding.",
  };
  await writeResult(resultPath, draft([renamedTitle, secondFinding]));
  assert.equal((await validate(previousReducerResultPath)).newFindings, 1);

  await writeResult(
    previousReducerResultPath,
    draft([firstFinding, secondFinding]),
  );
  await writeResult(resultPath, draft([secondFinding]));
  await assert.rejects(
    validate(previousReducerResultPath),
    (error: NodeJS.ErrnoException) =>
      error.code === "merge_traceability_unstable_candidate_id",
  );

  const replacement = finding("replacement", "src/c.js");
  await writeResult(
    resultPath,
    draft([firstFinding, secondFinding, replacement]),
  );
  assert.equal((await validate(previousReducerResultPath)).newFindings, 1);

  const implicitFirst = { ...firstFinding };
  delete (implicitFirst as { identity?: unknown }).identity;
  const implicitRenamed = {
    ...implicitFirst,
    summary: "More complete evidence.",
  };
  await writeResult(previousReducerResultPath, draft([implicitFirst]));
  await writeResult(resultPath, draft([implicitRenamed]));
  assert.equal((await validate(previousReducerResultPath)).newFindings, 0);
  await writeResult(
    resultPath,
    draft([
      {
        ...implicitRenamed,
        locations: [
          ...implicitRenamed.locations,
          { path: "src/another-affected-location.js", startLine: 4 },
        ],
      },
    ]),
  );
  assert.equal(
    (await validate(previousReducerResultPath)).newFindings,
    0,
    "An existing finding without an explicit identity may gain affected locations.",
  );

  await writeResult(resultPath, {
    ...draft([firstFinding]),
    scanId: otherScanId,
  });
  await assert.rejects(
    validate(),
    (error: NodeJS.ErrnoException) =>
      error.name !== "DeepScanNonRetryableError" &&
      /different scan/.test(error.message),
  );

  await writeResult(resultPath, draft([firstFinding]));
  await writeResult(first.resultPath, {
    ...draft([firstFinding]),
    scanId: otherScanId,
  });
  assert.equal(
    (await validate()).newFindings,
    1,
    "A completed aggregate must not reread already-consumed Standard results.",
  );
  await writeFile(first.resultPath, "{invalid Standard scan\n");
  assert.equal(
    (await validate()).newFindings,
    1,
    "Accepted Standard inputs were already validated by the reducer writer.",
  );
  await writeResult(first.resultPath, draft([firstFinding]));

  await writeResult(previousReducerResultPath, {
    ...draft([firstFinding]),
    scanId: otherScanId,
  });
  await assert.rejects(validate(previousReducerResultPath), /different scan/);

  if (process.platform !== "win32") {
    const actualResult = path.join(artifactDir, "actual-result.json");
    await writeResult(actualResult, draft([firstFinding]));
    await rm(resultPath);
    await symlink(actualResult, resultPath, "file");
    await assert.rejects(validate(), /canonical non-symlink path/);
  }
}

async function testEmptyDiscoveryAndReduction(root: string) {
  const { artifacts, ...worker } = await createWorker(
    path.join(root, "empty"),
    "worker-empty",
    draft([]),
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
    reducerId: "dedup-empty",
  });
  assert.equal(result.newFindings, 0);
  assert.deepEqual(
    result.result,
    { scanId, findings: [] },
    "reducers submit and return results without coverage",
  );
}

async function createWorker(scanDir: string, id: string, result: unknown) {
  const artifacts = {
    scanDir,
    workersRoot: path.join(scanDir, "artifacts", "deep_discovery", "workers"),
    dedupRoot: path.join(scanDir, "artifacts", "deep_discovery", "dedup"),
  };
  const output = path.join(artifacts.workersRoot, "discovery-0001", "output");
  await mkdir(output, { recursive: true });
  const resultPath = path.join(output, "result.json");
  await writeResult(resultPath, result);
  return { artifacts, id, resultPath };
}
