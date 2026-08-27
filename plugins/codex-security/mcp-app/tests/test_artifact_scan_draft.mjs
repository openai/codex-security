import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { promises as fsPromises } from "node:fs";
import {
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  realpath,
  rename,
  rm,
  symlink,
  utimes,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { build } from "esbuild";

const scanId = "7b95abf2-dc04-47a9-9950-53b5c2057f49";
const claimToken = "19bfba38-0913-4bd7-86ef-134e9a4d9a42";

const bundled = await build({
  absWorkingDir: path.dirname(new URL(import.meta.url).pathname),
  bundle: true,
  entryPoints: ["../src/artifact-scan-draft.ts"],
  format: "esm",
  platform: "node",
  write: false,
});

const module = await import(
  `data:text/javascript;base64,${Buffer.from(bundled.outputFiles[0].text).toString("base64")}`
);
const {
  completedScanInputSchema,
  getCodexSecurityCompletedScan,
  recordCodexSecurityScanDraft,
  recordCodexSecurityScanDraftViaWorkbench,
  recordCodexSecurityWorkerScanDraft,
  saveScanDraftCheckpoint,
  scanDraftInputSchema,
} = module;

const root = await realpath(
  await mkdtemp(path.join(tmpdir(), "codex-security-scan-draft-")),
);

try {
  const context = {
    root,
    repoRoot: root,
    layout: "scan",
    scanId,
    scope: ".",
    mode: "standard",
    status: "running",
    handoffClaimToken: claimToken,
    targetRevision: "1234567890abcdef",
    targetContract: {
      target: {
        allowedKinds: ["git_worktree"],
        targetId: "target_example",
        displayName: "example",
        requiredSnapshotDigest:
          "codex-security-snapshot/v1:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      },
      scope: {
        requiredIncludePaths: ["."],
        requiredExcludePaths: [],
      },
      diffTarget: null,
    },
  };

  const finding = {
    ruleId: "path-traversal.archive-extraction",
    title: "Unsafe archive extraction",
    summary: "An untrusted archive entry reaches a filesystem write.",
    severity: { level: "high", score: 8.1, scoringSystem: "CVSS:3.1" },
    confidence: {
      level: "high",
      rationale: "Source evidence establishes reachability.",
    },
    taxonomy: { category: "path-traversal", cwe: ["CWE-22"] },
    locations: [{ path: "src/extract.py", startLine: 41, endLine: 44 }],
    remediation: "Validate each output path before writing.",
    provenance: {
      source: "local_plugin",
      candidateId: "candidate-b5b7a3d14a148f6a",
      workerId: "discovery-worker-1",
    },
    extensions: {
      preserved: "semantic extension",
      candidateId: "candidate-b5b7a3d14a148f6a",
    },
  };

  const coverage = {
    completeness: "complete",
    surfaces: [
      {
        label: "Archive extraction",
        disposition: "reported",
        notes: "Reviewed.",
      },
    ],
    explicitExclusions: [],
    deferred: [],
    extensions: { preserved: true },
  };

  const input = {
    scanId,
    handoffClaimToken: claimToken,
    scope: { summary: "Archive handling" },
    threatModel: { summary: "Untrusted users may upload archives." },
    findings: [finding],
    coverage,
  };

  const workerRoot = path.join(root, "worker-output");
  await mkdir(workerRoot);
  const workerContext = {
    root: workerRoot,
    repoRoot: root,
    layout: "worker",
    scanId,
  };
  const workerInput = {
    scanId,
    scope: { summary: "Archive handling" },
    threatModel: { summary: "Untrusted users may upload archives." },
    findings: [finding],
    coverage,
  };
  const workerResultPath = path.join(workerRoot, "result.json");

  const checkpointRoot = path.join(root, "checkpoint-worker");
  await mkdir(checkpointRoot);
  const checkpointContext = { ...workerContext, root: checkpointRoot };
  const checkpoint = { ...workerInput, complete: false };
  await recordCodexSecurityWorkerScanDraft(checkpointContext, checkpoint);
  const checkpointFiles = await readdir(path.join(checkpointRoot, "checkpoints"));
  assert.equal(checkpointFiles.length, 1);
  assert.deepEqual(
    JSON.parse(await readFile(path.join(checkpointRoot, "checkpoints", checkpointFiles[0]), "utf8")),
    checkpoint,
  );
  const checkpointBytes = await readFile(path.join(checkpointRoot, "checkpoints", checkpointFiles[0]));
  await recordCodexSecurityWorkerScanDraft(checkpointContext, { ...workerInput, findings: [] });
  assert.deepEqual(
    JSON.parse(await readFile(path.join(checkpointRoot, "result.json"), "utf8")).findings,
    [finding],
    "a later write cannot silently remove a saved validated finding",
  );
  assert.deepEqual(await readFile(path.join(checkpointRoot, "checkpoints", checkpointFiles[0])), checkpointBytes);
  assert.equal(
    (await readdir(path.join(checkpointRoot, "checkpoints"))).length,
    3,
    "raw and reconciled drafts remain immutable while the head selects the accepted result",
  );

  const interruptedRoot = path.join(root, "interrupted-checkpoint-worker");
  await mkdir(interruptedRoot);
  const interruptedContext = { ...workerContext, root: interruptedRoot };
  const interruptedFinding = structuredClone(finding);
  interruptedFinding.identity = { anchor: "interrupted-checkpoint" };
  interruptedFinding.provenance.candidateId = "interrupted-checkpoint";
  interruptedFinding.extensions.candidateId = "interrupted-checkpoint";
  await saveScanDraftCheckpoint(interruptedContext, {
    ...workerInput,
    complete: false,
    findings: [interruptedFinding],
    coverage: {
      ...coverage,
      completeness: "partial",
      deferred: [{ candidateId: "interrupted-review", reason: "Review was checkpointed." }],
    },
  }, false);
  await recordCodexSecurityWorkerScanDraft(interruptedContext, {
    ...workerInput,
    findings: [],
  });
  const interruptedResult = JSON.parse(
    await readFile(path.join(interruptedRoot, "result.json"), "utf8"),
  );
  assert.deepEqual(interruptedResult.findings, [interruptedFinding]);
  assert.equal(
    interruptedResult.coverage.deferred.some((item) => (
      item.candidateId === "interrupted-review"
    )),
    true,
  );

  const rejectedIncompleteRoot = path.join(root, "rejected-incomplete-worker");
  await mkdir(rejectedIncompleteRoot);
  const rejectedIncompleteContext = { ...workerContext, root: rejectedIncompleteRoot };
  await recordCodexSecurityWorkerScanDraft(rejectedIncompleteContext, workerInput);
  await recordCodexSecurityWorkerScanDraft(rejectedIncompleteContext, {
    ...workerInput,
    complete: false,
    findings: [],
    coverage: {
      ...coverage,
      completeness: "partial",
      surfaces: [{
        candidateId: finding.provenance.candidateId,
        label: "Archive extraction",
        disposition: "rejected",
        notes: "The incomplete writer rejected this candidate.",
      }],
      deferred: [{
        candidateId: "late-incomplete-review",
        reason: "This arrived after the worker completed.",
      }],
    },
  });
  const acceptedHead = JSON.parse(
    await readFile(path.join(rejectedIncompleteRoot, "checkpoint-head.json"), "utf8"),
  );
  const acceptedHeadDraft = JSON.parse(await readFile(
    path.join(rejectedIncompleteRoot, "checkpoints", acceptedHead.checkpoint),
    "utf8",
  ));
  assert.notEqual(
    acceptedHeadDraft.complete,
    false,
    "a rejected incomplete write must not become the authoritative checkpoint head",
  );
  assert.deepEqual(acceptedHeadDraft.findings, [finding]);
  const acceptedResult = JSON.parse(
    await readFile(path.join(rejectedIncompleteRoot, "result.json"), "utf8"),
  );
  assert.equal(
    acceptedResult.coverage.deferred.some(
      item => item.candidateId === "late-incomplete-review",
    ),
    false,
    "a rejected incomplete write must not change the completed result",
  );

  const deferredDoesNotRejectRoot = path.join(root, "deferred-does-not-reject-worker");
  await mkdir(deferredDoesNotRejectRoot);
  const deferredDoesNotRejectContext = { ...workerContext, root: deferredDoesNotRejectRoot };
  await recordCodexSecurityWorkerScanDraft(deferredDoesNotRejectContext, workerInput);
  await recordCodexSecurityWorkerScanDraft(deferredDoesNotRejectContext, {
    ...workerInput,
    complete: false,
    findings: [],
    coverage: {
      ...coverage,
      completeness: "partial",
      surfaces: [],
      deferred: [{
        candidateId: finding.provenance.candidateId,
        reason: "A stale worker row still says validation is pending.",
      }],
    },
  });
  const deferredDoesNotReject = JSON.parse(
    await readFile(path.join(deferredDoesNotRejectRoot, "result.json"), "utf8"),
  );
  assert.deepEqual(
    deferredDoesNotReject.findings,
    [finding],
    "deferred coverage is not an explicit rejection of an already validated finding",
  );

  const rejection = {
    candidateId: finding.provenance.candidateId,
    label: "Archive extraction",
    disposition: "rejected",
    notes: "The source enforces containment before the write.",
  };
  await recordCodexSecurityWorkerScanDraft(checkpointContext, {
    ...workerInput,
    findings: [],
    coverage: { ...coverage, surfaces: [rejection] },
  });
  const rejectedCheckpoint = JSON.parse(await readFile(path.join(checkpointRoot, "result.json"), "utf8"));
  assert.equal(rejectedCheckpoint.findings.length, 0);
  assert.deepEqual(rejectedCheckpoint.coverage.surfaces[0].finding, finding);

  const rejectionWithoutNotesRoot = path.join(root, "rejection-without-notes-worker");
  await mkdir(rejectionWithoutNotesRoot);
  const rejectionWithoutNotesContext = { ...workerContext, root: rejectionWithoutNotesRoot };
  await recordCodexSecurityWorkerScanDraft(rejectionWithoutNotesContext, checkpoint);
  const { notes: _notes, ...rejectionWithoutNotes } = rejection;
  await recordCodexSecurityWorkerScanDraft(rejectionWithoutNotesContext, {
    ...workerInput,
    findings: [],
    coverage: { ...coverage, surfaces: [rejectionWithoutNotes] },
  });
  const rejectedWithoutNotes = JSON.parse(
    await readFile(path.join(rejectionWithoutNotesRoot, "result.json"), "utf8"),
  );
  assert.equal(rejectedWithoutNotes.findings.length, 0);
  assert.deepEqual(rejectedWithoutNotes.coverage.surfaces[0].finding, finding);

  const carriedContextRoot = path.join(root, "carried-context-worker");
  await mkdir(carriedContextRoot);
  const carriedContext = { ...workerContext, root: carriedContextRoot };
  await recordCodexSecurityWorkerScanDraft(carriedContext, { ...workerInput, complete: false });
  const { scope: _scope, threatModel: _threatModel, ...workerWithoutContext } = workerInput;
  await recordCodexSecurityWorkerScanDraft(carriedContext, workerWithoutContext);
  const carriedWorker = JSON.parse(await readFile(path.join(carriedContextRoot, "result.json"), "utf8"));
  assert.deepEqual(carriedWorker.scope, workerInput.scope);
  assert.deepEqual(carriedWorker.threatModel, workerInput.threatModel);

  const coverageProgressRoot = path.join(root, "coverage-progress-worker");
  await mkdir(coverageProgressRoot);
  const coverageProgressContext = { ...workerContext, root: coverageProgressRoot };
  const pendingQuestion = "Does the alternate archive handler enforce containment?";
  await recordCodexSecurityWorkerScanDraft(coverageProgressContext, {
    ...workerInput,
    complete: false,
    coverage: {
      ...coverage,
      completeness: "partial",
      surfaces: [{
        id: "surface-archive",
        label: "Archive extraction",
        disposition: "needs_follow_up",
        notes: "Containment review is pending.",
      }],
      openQuestions: [pendingQuestion],
    },
  });
  await recordCodexSecurityWorkerScanDraft(coverageProgressContext, {
    ...workerInput,
    coverage: {
      ...coverage,
      surfaces: [{
        id: "surface-archive",
        label: "Archive extraction",
        disposition: "reported",
        notes: "The reachable extraction path lacks containment.",
      }],
    },
  });
  const progressedCoverage = JSON.parse(
    await readFile(path.join(coverageProgressRoot, "result.json"), "utf8"),
  ).coverage;
  assert.deepEqual(
    progressedCoverage.surfaces.map(({ id, disposition }) => ({ id, disposition })),
    [{ id: "surface-archive", disposition: "reported" }],
  );
  assert.deepEqual(progressedCoverage.openQuestions ?? [], []);
  assert.equal(progressedCoverage.completeness, "complete");

  const renamedProgressRoot = path.join(root, "renamed-coverage-progress-worker");
  await mkdir(renamedProgressRoot);
  const renamedProgressContext = { ...workerContext, root: renamedProgressRoot };
  const staleSurfaces = [
    {
      label: "ZIP entry candidate awaiting validation",
      disposition: "needs_follow_up",
      notes: "The archive candidate still needs validation.",
    },
    {
      id: "surface-legacy-archive",
      label: "Original archive extraction surface",
      disposition: "needs_follow_up",
      notes: "The archive candidate still needs validation.",
    },
  ];
  const resolvedCoverage = {
    ...coverage,
    surfaces: [{
      label: "Validated archive path traversal",
      disposition: "reported",
      notes: "The archive candidate was validated.",
    }],
  };
  await recordCodexSecurityWorkerScanDraft(renamedProgressContext, {
    ...workerInput,
    complete: false,
    findings: [],
    coverage: {
      ...coverage,
      completeness: "partial",
      surfaces: staleSurfaces,
      deferred: [{
        candidateId: finding.provenance.candidateId,
        reason: "Archive path traversal validation is pending.",
      }],
    },
  });
  await recordCodexSecurityWorkerScanDraft(renamedProgressContext, {
    ...workerInput,
    complete: false,
    coverage: resolvedCoverage,
  });
  const resolvedProgress = JSON.parse(
    await readFile(path.join(renamedProgressRoot, "result.json"), "utf8"),
  );
  assert.deepEqual(resolvedProgress.coverage.surfaces, resolvedCoverage.surfaces);
  assert.equal(resolvedProgress.coverage.completeness, "complete");

  await saveScanDraftCheckpoint(renamedProgressContext, {
    ...workerInput,
    complete: false,
    coverage: {
      ...resolvedCoverage,
      completeness: "partial",
      surfaces: [...resolvedCoverage.surfaces, ...staleSurfaces],
    },
  }, false);
  await recordCodexSecurityWorkerScanDraft(renamedProgressContext, {
    ...workerInput,
    complete: true,
    coverage: resolvedCoverage,
  });
  const finalProgress = JSON.parse(
    await readFile(path.join(renamedProgressRoot, "result.json"), "utf8"),
  );
  assert.deepEqual(finalProgress.coverage.surfaces, resolvedCoverage.surfaces);
  assert.equal(finalProgress.coverage.completeness, "complete");

  const anchorRoot = path.join(root, "anchor-is-not-candidate-worker");
  await mkdir(anchorRoot);
  const anchorContext = { ...workerContext, root: anchorRoot };
  const anchor = "shared-finding-and-deferred-label";
  const { candidateId: _provenanceCandidate, ...anchorProvenance } = finding.provenance;
  const { candidateId: _extensionCandidate, ...anchorExtensions } = finding.extensions;
  const anchoredFinding = {
    ...finding,
    identity: { anchor },
    provenance: anchorProvenance,
    extensions: anchorExtensions,
  };
  await recordCodexSecurityWorkerScanDraft(anchorContext, {
    ...workerInput,
    complete: false,
    findings: [anchoredFinding],
  });
  await recordCodexSecurityWorkerScanDraft(anchorContext, {
    ...workerInput,
    complete: false,
    findings: [],
    coverage: {
      ...coverage,
      completeness: "partial",
      surfaces: [],
      deferred: [{ id: anchor, reason: "An unrelated review item remains pending." }],
    },
  });
  const anchorResult = JSON.parse(await readFile(path.join(anchorRoot, "result.json"), "utf8"));
  assert.equal(anchorResult.findings.length, 1);
  assert.deepEqual(anchorResult.findings[0].identity, { anchor });
  assert.equal("finding" in anchorResult.coverage.deferred[0], false);

  const parentCheckpointRoot = path.join(root, "checkpoint-parent");
  await mkdir(parentCheckpointRoot);
  await recordCodexSecurityScanDraft({ ...context, root: parentCheckpointRoot }, { ...input, complete: false });
  const parentSnapshot = JSON.parse(await readFile(path.join(
    parentCheckpointRoot, "checkpoints", (await readdir(path.join(parentCheckpointRoot, "checkpoints")))[0],
  ), "utf8"));
  assert.equal(parentSnapshot.handoffClaimToken, undefined);
  assert.equal(parentSnapshot.complete, false);
  assert.deepEqual(parentSnapshot.findings, [finding]);
  await recordCodexSecurityScanDraft({ ...context, root: parentCheckpointRoot }, { ...input, findings: [] });
  assert.equal((await readJson(parentCheckpointRoot, "findings.json")).findings.length, 1);

  const interruptedParentRoot = path.join(root, "interrupted-checkpoint-parent");
  await mkdir(interruptedParentRoot);
  const interruptedParentContext = { ...context, root: interruptedParentRoot };
  await saveScanDraftCheckpoint(interruptedParentContext, {
    ...input,
    complete: false,
    findings: [interruptedFinding],
    coverage: {
      ...coverage,
      completeness: "partial",
      deferred: [{ candidateId: "interrupted-parent-review", reason: "Review was checkpointed." }],
    },
  }, false);
  await recordCodexSecurityScanDraft(interruptedParentContext, {
    ...input,
    findings: [],
  });
  assert.deepEqual(
    (await readJson(interruptedParentRoot, "findings.json")).findings,
    [interruptedFinding],
  );
  assert.equal(
    (await readJson(interruptedParentRoot, "coverage.json")).deferred.some(
      item => item.candidateId === "interrupted-parent-review",
    ),
    true,
  );

  const { scope: _parentScope, threatModel: _parentThreatModel, ...parentWithoutContext } = input;
  await recordCodexSecurityScanDraft(
    { ...context, root: parentCheckpointRoot },
    parentWithoutContext,
  );
  const carriedParentManifest = await readJson(parentCheckpointRoot, "scan-manifest.json");
  assert.deepEqual(carriedParentManifest.scan.scope.summary, input.scope.summary);
  assert.deepEqual(carriedParentManifest.scan.threatModel, input.threatModel);

  const pendingRoot = path.join(root, "pending-worker");
  await mkdir(pendingRoot);
  const pendingContext = { ...workerContext, root: pendingRoot };
  const candidate = { summary: "An unvalidated archive extraction candidate.", evidence: "Original nested-worker source trace." };
  const pending = {
    ...workerInput, complete: false, findings: [],
    coverage: {
      ...coverage, completeness: "partial", surfaces: [],
      deferred: [{ candidateId: finding.provenance.candidateId, reason: "Pending parent validation", candidate }],
    },
  };
  await recordCodexSecurityWorkerScanDraft(pendingContext, pending);
  await recordCodexSecurityWorkerScanDraft(pendingContext, workerInput);
  const resolved = JSON.parse(await readFile(path.join(pendingRoot, "result.json"), "utf8"));
  assert.deepEqual(resolved.coverage.deferred, []);
  assert.equal(resolved.coverage.completeness, "complete");
  assert.deepEqual(resolved.findings[0].provenance.originalCandidates, [candidate]);

  await rm(path.join(pendingRoot, "result.json"));
  await recordCodexSecurityWorkerScanDraft(pendingContext, pending);
  await recordCodexSecurityWorkerScanDraft(pendingContext, {
    ...workerInput, findings: [], coverage: { ...coverage, surfaces: [rejection] },
  });
  const resolvedRejection = JSON.parse(await readFile(path.join(pendingRoot, "result.json"), "utf8"));
  assert.deepEqual(resolvedRejection.coverage.deferred, []);
  assert.deepEqual(resolvedRejection.coverage.surfaces[0].candidate, candidate);

  const undefinedCandidateRoot = path.join(root, "undefined-candidate-worker");
  await mkdir(undefinedCandidateRoot);
  const undefinedCandidateContext = { ...workerContext, root: undefinedCandidateRoot };
  await recordCodexSecurityWorkerScanDraft(undefinedCandidateContext, {
    ...workerInput,
    complete: false,
    findings: [],
    coverage: {
      ...coverage,
      completeness: "partial",
      surfaces: [],
      deferred: [{ reason: "An unrelated anonymous review item remains pending." }],
    },
  });
  const literalUndefinedFinding = structuredClone(finding);
  literalUndefinedFinding.provenance.candidateId = "undefined";
  literalUndefinedFinding.extensions.candidateId = "undefined";
  await recordCodexSecurityWorkerScanDraft(undefinedCandidateContext, {
    ...workerInput,
    complete: false,
    findings: [literalUndefinedFinding],
    coverage: { ...coverage, completeness: "partial", surfaces: [] },
  });
  const undefinedCandidateResult = JSON.parse(
    await readFile(path.join(undefinedCandidateRoot, "result.json"), "utf8"),
  );
  assert.equal(undefinedCandidateResult.coverage.deferred.length, 1);
  assert.equal(
    undefinedCandidateResult.coverage.deferred[0].reason,
    "An unrelated anonymous review item remains pending.",
  );

  for (const [index, previousFindings] of ["legacy metadata", { opaque: true }, 7].entries()) {
    const historyRoot = path.join(root, `legacy-history-${index}`);
    await mkdir(historyRoot);
    const historyContext = { ...workerContext, root: historyRoot };
    const earlierFinding = {
      ...finding,
      summary: "Earlier verified source proof.",
      provenance: { ...finding.provenance, previousFindings },
    };
    await recordCodexSecurityWorkerScanDraft(historyContext, { ...workerInput, findings: [earlierFinding] });
    await recordCodexSecurityWorkerScanDraft(historyContext, workerInput);
    const savedHistory = JSON.parse(await readFile(path.join(historyRoot, "result.json"), "utf8"));
    const original = structuredClone(earlierFinding);
    delete original.provenance.previousFindings;
    assert.deepEqual(
      savedHistory.findings[0].provenance.previousFindings,
      [original],
      "opaque legacy metadata is not interpreted as finding history, but the original proof survives",
    );
    const snapshots = await Promise.all((await readdir(path.join(historyRoot, "checkpoints"))).map(async name => (
      JSON.parse(await readFile(path.join(historyRoot, "checkpoints", name), "utf8"))
    )));
    assert.deepEqual(
      snapshots.find(snapshot => snapshot.findings[0].summary === earlierFinding.summary).findings[0].provenance.previousFindings,
      previousFindings,
      "the immutable snapshot retains otherwise opaque legacy data",
    );
  }

  await assert.rejects(
    recordCodexSecurityWorkerScanDraft(workerContext, {
      ...workerInput,
      scanId: "d7caa0cf-b785-47ef-95e7-e753dc288608",
    }),
    /scanId does not match/,
  );
  await assert.rejects(readFile(workerResultPath), { code: "ENOENT" });
  await assert.rejects(
    recordCodexSecurityWorkerScanDraft(workerContext, {
      ...workerInput,
      coverage: {
        ...coverage,
        deferred: [
          { reason: "The archive upload runtime remains unavailable." },
        ],
      },
    }),
    /complete coverage cannot contain deferred/,
  );
  await assert.rejects(readFile(workerResultPath), { code: "ENOENT" });
  assert.deepEqual(
    await recordCodexSecurityWorkerScanDraft(workerContext, workerInput),
    {
      scanId,
      findingCount: 1,
      surfaceCount: 1,
      operation: "replace",
      status: "draft_written",
    },
  );
  assert.deepEqual(
    JSON.parse(await readFile(workerResultPath, "utf8")),
    workerInput,
  );
  const outOfScopeFinding = {
    ...finding,
    title: "Outside the selected scope",
    locations: [{ path: "outside/secret.py", startLine: 12 }],
  };
  const misleadingPrefixFinding = {
    ...finding,
    title: "Sibling path is not in scope",
    locations: [{ path: "src-private/secret.py", startLine: 14 }],
  };
  const supportedScopedFinding = {
    ...finding,
    title: "In-scope finding with outside supporting code",
    locations: [
      { path: "outside/support.py", startLine: 8 },
      { path: "./src/extract.py", startLine: 41 },
    ],
  };
  const scopedWorkerInput = {
    ...workerInput,
    findings: [
      outOfScopeFinding,
      supportedScopedFinding,
      misleadingPrefixFinding,
    ],
  };
  const originalScopedWorkerInput = structuredClone(scopedWorkerInput);
  // Scope-filtering cases are independent scans, not revisions of the saved audit above.
  const resetWorkerDraft = async () => Promise.all([
    rm(workerResultPath, { force: true }),
    rm(path.join(workerRoot, "checkpoints"), { recursive: true, force: true }),
    rm(path.join(workerRoot, "checkpoint-head.json"), { force: true }),
  ]);
  await resetWorkerDraft();
  assert.deepEqual(
    await recordCodexSecurityWorkerScanDraft(
      { ...workerContext, scope: "src" },
      scopedWorkerInput,
    ),
    {
      scanId,
      findingCount: 1,
      surfaceCount: 1,
      operation: "replace",
      status: "draft_written",
    },
  );
  assert.deepEqual(JSON.parse(await readFile(workerResultPath, "utf8")), {
    ...scopedWorkerInput,
    findings: [supportedScopedFinding],
  });
  assert.deepEqual(scopedWorkerInput, originalScopedWorkerInput);
  await resetWorkerDraft();
  assert.deepEqual(
    await recordCodexSecurityWorkerScanDraft(
      { ...workerContext, scope: "src/extract.py" },
      scopedWorkerInput,
    ),
    {
      scanId,
      findingCount: 1,
      surfaceCount: 1,
      operation: "replace",
      status: "draft_written",
    },
  );
  assert.deepEqual(JSON.parse(await readFile(workerResultPath, "utf8")), {
    ...scopedWorkerInput,
    findings: [supportedScopedFinding],
  });
  await resetWorkerDraft();
  assert.deepEqual(
    await recordCodexSecurityWorkerScanDraft(
      { ...workerContext, scope: "." },
      scopedWorkerInput,
    ),
    {
      scanId,
      findingCount: 3,
      surfaceCount: 1,
      operation: "replace",
      status: "draft_written",
    },
  );
  assert.deepEqual(
    JSON.parse(await readFile(workerResultPath, "utf8")),
    scopedWorkerInput,
  );
  for (const name of ["scan-manifest.json", "findings.json", "coverage.json"]) {
    await assert.rejects(readFile(path.join(workerRoot, name)), {
      code: "ENOENT",
    });
  }
  await assert.rejects(
    recordCodexSecurityWorkerScanDraft(context, workerInput),
    /bound worker context/,
  );

  const semanticFinding = {
    ...finding,
    remediationTests: [
      "Reject an archive entry containing ../ in a regression test.",
    ],
    preventiveControls: ["Use the shared archive-path containment helper."],
  };
  const semanticCoverage = {
    ...coverage,
    completeness: "partial",
    deferred: [
      {
        candidateId: "candidate-deferred-archive",
        reason: "The archive upload runtime was unavailable.",
        paths: ["src/extract.py"],
        evidence: "Preserve the original deferred-candidate metadata.",
      },
      {
        candidateId: "candidate-reserved-archive",
        reason: "A neighboring archive entry still needs validation.",
      },
      {
        id: "candidate-reserved-archive",
        candidateId: "candidate-explicit-archive",
        reason: "Preserve this explicitly supplied deferred identity.",
        surfaceIds: ["surface_archive-extraction"],
      },
      {
        candidateId: "candidate-deferred-archive",
        reason: "A second archive path requires a distinct deferred identity.",
      },
      {
        candidateId: "candidate-reserved-archive",
        reason:
          "Another reserved candidate requires the next available suffix.",
      },
    ],
    openQuestions: [
      "  Can archive entries reach another extraction sink?  ",
      {
        question: "Does upload authorization protect the extraction path?",
        followUpPrompt: "Trace authorization from the upload endpoint.",
        source: "preserve-existing-question-metadata",
      },
    ],
  };
  const semanticInput = {
    ...input,
    findings: [semanticFinding],
    coverage: semanticCoverage,
  };

  const reasonOnlyDeferred = [
    {
      reason: "The archive upload runtime was unavailable.",
    },
    {
      reason: "The archive upload runtime was unavailable.",
      paths: [],
      surfaceIds: [],
    },
    {
      reason: "The archive upload runtime was unavailable.",
      paths: ["src/extract.py"],
      surfaceIds: ["surface_archive-extraction"],
      evidence: "Preserve non-identity deferred metadata.",
    },
    {
      reason: "The archive upload runtime was unavailable during replay.",
      paths: ["src/extract.py"],
      surfaceIds: ["surface_archive-extraction"],
    },
    {
      reason: "The archive upload runtime was unavailable.",
      paths: ["src/alternate.py"],
      surfaceIds: ["surface_archive-extraction"],
    },
    {
      reason: "The archive upload runtime was unavailable.",
      paths: ["src/extract.py"],
      surfaceIds: ["surface_upload-entry"],
    },
    {
      reason: "The archive upload runtime was unavailable.",
      paths: ["src/extract.py"],
      surfaceIds: ["surface_archive-extraction"],
      evidence: "This semantically identical deferred row needs a suffix.",
    },
  ];
  const reasonOnlyInput = {
    ...input,
    coverage: {
      ...coverage,
      completeness: "partial",
      deferred: reasonOnlyDeferred,
    },
  };

  const incompleteCodeEvidence = {
    id: "evidence-archive-sink",
    label: "Archive extraction sink",
    path: "src/extract.py",
    startLine: 41,
    code: "",
    explanation: "The reviewed archive entry reaches a filesystem write.",
  };

  const rejectedDraftInputs = [
    [
      "finding rule IDs must describe a lowercase vulnerability family, not a CWE",
      { ...input, findings: [{ ...finding, ruleId: "CWE-1321" }] },
    ],
    [
      "finding taxonomy must use the candidate's canonical cwe array",
      {
        ...input,
        findings: [
          {
            ...finding,
            taxonomy: { category: "prototype-pollution", cweIds: ["CWE-1321"] },
          },
        ],
      },
    ],
    [
      "finding provenance must identify the actual source",
      {
        ...input,
        findings: [
          {
            ...finding,
            provenance: { candidateId: "candidate-b5b7a3d14a148f6a" },
          },
        ],
      },
    ],
    [
      "provided code evidence must contain the verified source snippet",
      {
        ...input,
        findings: [{ ...finding, codeEvidence: [incompleteCodeEvidence] }],
      },
    ],
    [
      "legacy code evidence must be an array",
      {
        ...input,
        findings: [{ ...finding, code_evidence: null }],
      },
    ],
    [
      "legacy root-cause code must be text",
      {
        ...input,
        findings: [{ ...finding, root_cause: { code: ["not text"] } }],
      },
    ],
    [
      "legacy root-cause language must be text",
      {
        ...input,
        findings: [{ ...finding, root_cause: { language: 42 } }],
      },
    ],
    [
      "canonical root-cause code must be text",
      {
        ...input,
        findings: [
          {
            ...finding,
            rootCause: { summary: "Root cause.", code: ["not text"] },
          },
        ],
      },
    ],
    [
      "canonical root-cause language must be text",
      {
        ...input,
        findings: [
          {
            ...finding,
            rootCause: { summary: "Root cause.", language: 42 },
          },
        ],
      },
    ],
    [
      "coverage surfaces must use canonical labels and dispositions",
      {
        ...input,
        coverage: {
          ...coverage,
          surfaces: [{ surface: "Archive extraction", outcome: "reported" }],
        },
      },
    ],
    [
      "reason-only deferred coverage rejects a missing reason",
      {
        ...input,
        coverage: {
          ...coverage,
          completeness: "partial",
          deferred: [{ paths: ["src/extract.py"] }],
        },
      },
    ],
    [
      "reason-only deferred coverage rejects a whitespace-only reason",
      {
        ...input,
        coverage: {
          ...coverage,
          completeness: "partial",
          deferred: [{ reason: "  \t\n  " }],
        },
      },
    ],
    [
      "explicit deferred identities do not bypass the required reason",
      {
        ...input,
        coverage: {
          ...coverage,
          completeness: "partial",
          deferred: [{ id: "deferred-explicit-archive" }],
        },
      },
    ],
    [
      "deferred candidate identities must not contain only whitespace",
      {
        ...input,
        coverage: {
          ...coverage,
          completeness: "partial",
          deferred: [
            {
              candidateId: "   ",
              reason: "The upload runtime was unavailable.",
            },
          ],
        },
      },
    ],
    [
      "plain-string open questions must contain meaningful text",
      {
        ...input,
        coverage: { ...coverage, openQuestions: ["  \t  "] },
      },
    ],
    [
      "structured open questions require a question",
      {
        ...input,
        coverage: {
          ...coverage,
          openQuestions: [{ followUpPrompt: "Trace the upload boundary." }],
        },
      },
    ],
    [
      "structured open questions must not contain only whitespace",
      {
        ...input,
        coverage: {
          ...coverage,
          openQuestions: [{ question: "  \n  " }],
        },
      },
    ],
    [
      "included scope paths are supplied by the authoritative scan",
      { ...input, scope: { includePaths: ["src"] } },
    ],
    [
      "excluded scope paths are supplied by the authoritative scan",
      { ...input, scope: { excludePaths: ["vendor"] } },
    ],
    [
      "coverage mode is derived by the authoritative scan",
      { ...input, coverage: { ...coverage, mode: "repository" } },
    ],
    [
      "inventory strategy is derived by the authoritative scan",
      { ...input, coverage: { ...coverage, inventoryStrategy: "repository" } },
    ],
    [
      "coverage included paths are derived from the authoritative scope",
      { ...input, coverage: { ...coverage, includePaths: ["src"] } },
    ],
    [
      "coverage excluded paths are derived from the authoritative scope",
      { ...input, coverage: { ...coverage, excludePaths: ["vendor"] } },
    ],
    [
      "top-level receipt references are not semantic coverage inputs",
      {
        ...input,
        coverage: {
          ...coverage,
          receiptRefs: ["artifacts/02_discovery/candidate_ledger.jsonl"],
        },
      },
    ],
    [
      "finding IDs are generated during finalization",
      {
        ...input,
        findings: [
          {
            ...finding,
            findingId: "csf_0123456789abcdef01234567",
          },
        ],
      },
    ],
    [
      "occurrence IDs are generated during finalization",
      {
        ...input,
        findings: [
          {
            ...finding,
            occurrenceId: "cso_0123456789abcdef01234567",
          },
        ],
      },
    ],
    [
      "finding fingerprints are generated during finalization",
      {
        ...input,
        findings: [
          {
            ...finding,
            fingerprints: {
              algorithm: "codex-security/v1",
              primary:
                "codex-security/v1:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            },
          },
        ],
      },
    ],
  ];

  for (const [description, candidateId] of [
    ["path traversal", ".."],
    ["forward slash", "candidate/nested"],
    ["backslash", "candidate\\nested"],
    ["control character", "candidate\u0001nested"],
    ["oversized identity", "a".repeat(513)],
  ]) {
    rejectedDraftInputs.push([
      `deferred candidate identities reject ${description}`,
      {
        ...input,
        coverage: {
          ...coverage,
          completeness: "partial",
          deferred: [
            { candidateId, reason: "The candidate identity must remain safe." },
          ],
        },
      },
    ]);
    rejectedDraftInputs.push([
      `explicit deferred identities do not bypass invalid candidate ${description}`,
      {
        ...input,
        coverage: {
          ...coverage,
          completeness: "partial",
          deferred: [
            {
              id: "deferred-explicit-archive",
              candidateId,
              reason:
                "The candidate identity must remain safe even with an explicit identity.",
            },
          ],
        },
      },
    ]);
  }

  assert.equal(scanDraftInputSchema.safeParse(input).success, true);
  assert.equal(
    scanDraftInputSchema.safeParse(semanticInput).success,
    true,
    "semantic coverage accepts candidate-only deferred rows and plain-string open questions",
  );
  assert.equal(
    scanDraftInputSchema.safeParse(reasonOnlyInput).success,
    true,
    "semantic coverage accepts meaningful reason-only deferred rows",
  );
  for (const [description, rejectedInput] of rejectedDraftInputs) {
    assert.equal(
      scanDraftInputSchema.safeParse(rejectedInput).success,
      false,
      description,
    );
  }
  assert.equal(
    scanDraftInputSchema.safeParse({
      ...input,
      findings: [
        {
          ...finding,
          taxonomy: { category: "path-traversal", cwe: [] },
        },
      ],
    }).success,
    true,
    "do not invent a CWE when the reviewed candidate has none",
  );
  assert.equal(
    completedScanInputSchema.safeParse({
      scanId,
      handoffClaimToken: claimToken,
    }).success,
    true,
  );
  assert.equal(
    scanDraftInputSchema.safeParse({ ...input, coverage: undefined }).success,
    false,
  );
  assert.equal(
    scanDraftInputSchema.safeParse({ ...input, findings: undefined }).success,
    false,
  );
  assert.equal(
    scanDraftInputSchema.safeParse({ ...input, scanId: "not-a-scan-id" })
      .success,
    false,
  );
  assert.equal(
    scanDraftInputSchema.safeParse({
      ...input,
      findings: [{ ...finding, severity: { level: "moderate" } }],
    }).success,
    false,
  );
  assert.equal(
    scanDraftInputSchema.safeParse({
      ...input,
      findings: [{ ...finding, confidence: "high" }],
    }).success,
    false,
  );
  assert.equal(
    scanDraftInputSchema.safeParse({
      ...input,
      coverage: {
        ...coverage,
        surfaces: [{ label: "surface", disposition: "unreviewed" }],
      },
    }).success,
    false,
  );
  assert.equal(
    scanDraftInputSchema.safeParse({
      ...input,
      findings: [
        { ...finding, locations: [{ path: "../outside.py", startLine: 1 }] },
      ],
    }).success,
    false,
  );
  assert.equal(
    scanDraftInputSchema.safeParse({
      ...input,
      scope: { includePaths: ["outside"] },
    }).success,
    false,
  );
  assert.equal(
    scanDraftInputSchema.safeParse({
      ...input,
      coverage: { ...coverage, inventoryStrategy: "directory" },
    }).success,
    false,
  );
  assert.equal(
    scanDraftInputSchema.safeParse({
      ...input,
      coverage: { ...coverage, mode: "repository" },
    }).success,
    false,
  );
  assert.equal(
    scanDraftInputSchema.safeParse({
      ...input,
      coverage: { ...coverage, includePaths: ["outside"] },
    }).success,
    false,
  );
  assert.equal(
    scanDraftInputSchema.safeParse({
      ...input,
      coverage: { ...coverage, excludePaths: ["outside"] },
    }).success,
    false,
  );
  assert.equal(
    scanDraftInputSchema.safeParse({
      ...input,
      findings: [{ ...finding, findingId: "csf_0123456789abcdef01234567" }],
    }).success,
    false,
  );
  assert.equal(
    scanDraftInputSchema.safeParse({
      ...input,
      coverage: {
        ...coverage,
        surfaces: [
          {
            label: "surface",
            disposition: "reported",
            receiptRefs: ["artifacts/02_discovery/candidate_ledger.jsonl"],
          },
        ],
      },
    }).success,
    true,
  );
  assert.equal(
    scanDraftInputSchema.safeParse({
      ...input,
      coverage: {
        ...coverage,
        surfaces: [
          {
            label: "surface",
            disposition: "reported",
            receiptRefs: ["artifacts/../../outside.jsonl"],
          },
        ],
      },
    }).success,
    false,
  );

  let checkpointsVisibleBeforePublication = [];
  await assert.rejects(
    recordCodexSecurityScanDraftViaWorkbench(
      context,
      input,
      async (arguments_) => {
        checkpointsVisibleBeforePublication = await readdir(
          path.join(root, "checkpoints"),
        ).catch((error) => {
          if (error?.code === "ENOENT") return [];
          throw error;
        });
        assert.deepEqual(arguments_.slice(0, 3), [
          "write-scan-draft",
          "--scan-id",
          scanId,
        ]);
        const draftPathIndex = arguments_.indexOf("--draft-path");
        assert.notEqual(draftPathIndex, -1);
        assert.deepEqual(arguments_.slice(-2), ["--claim-token", claimToken]);
        const staged = JSON.parse(
          await readFile(arguments_[draftPathIndex + 1], "utf8"),
        );
        assert.equal(staged.findings.findings.length, 1);
        assert.deepEqual(staged.findings.findings[0].taxonomy, finding.taxonomy);
        assert.deepEqual(staged.manifest.scan.threatModel, input.threatModel);
        assert.equal(staged.coverage.completeness, "complete");
        throw new Error("The scan stopped before the staged draft was published.");
      },
    ),
    /scan stopped before the staged draft was published/,
  );
  assert.deepEqual(
    checkpointsVisibleBeforePublication,
    [],
    "checkpoint publication must share the workbench's terminal-transition lock",
  );
  for (const name of ["scan-manifest.json", "findings.json", "coverage.json"]) {
    await assert.rejects(readFile(path.join(root, name)), { code: "ENOENT" });
  }
  assert.deepEqual(await readdir(path.join(root, "drafts")), []);

  let conflictAttempts = 0;
  const retried = await recordCodexSecurityScanDraft(
    context,
    input,
    async () => {
      conflictAttempts += 1;
      if (conflictAttempts <= 9) {
        throw Object.assign(new Error("scan_draft_conflict"), {
          code: "scan_draft_conflict",
        });
      }
    },
  );
  assert.equal(conflictAttempts, 10);
  assert.equal(retried.status, "draft_written");

  const conflictAbort = new AbortController();
  let abortedConflictAttempts = 0;
  await assert.rejects(
    recordCodexSecurityScanDraft(
      context,
      input,
      async () => {
        abortedConflictAttempts += 1;
        conflictAbort.abort(new Error("draft publication canceled"));
        throw Object.assign(new Error("scan_draft_conflict"), {
          code: "scan_draft_conflict",
        });
      },
      conflictAbort.signal,
    ),
    /draft publication canceled/,
  );
  assert.equal(abortedConflictAttempts, 1);

  const monotonicRoot = path.join(root, "monotonic-final-draft");
  await mkdir(monotonicRoot);
  const monotonicContext = { ...context, root: monotonicRoot };
  const staleCheckpoint = {
    ...input,
    complete: false,
    coverage: {
      ...coverage,
      completeness: "partial",
      surfaces: [{
        id: "surface-archive",
        label: "Archive extraction",
        disposition: "needs_follow_up",
        notes: "The stale writer has not finished validation.",
      }],
    },
  };
  const finalDraft = {
    ...input,
    complete: true,
    coverage: {
      ...coverage,
      surfaces: [{
        id: "surface-archive",
        label: "Archive extraction",
        disposition: "reported",
        notes: "The final writer completed validation.",
      }],
    },
  };
  let monotonicWrites = 0;
  await recordCodexSecurityScanDraftViaWorkbench(
    monotonicContext,
    staleCheckpoint,
    async (arguments_) => {
      const draftPath = arguments_[arguments_.indexOf("--draft-path") + 1];
      const staged = JSON.parse(await readFile(draftPath, "utf8"));
      monotonicWrites += 1;
      if (monotonicWrites === 1) {
        await recordCodexSecurityScanDraft(monotonicContext, finalDraft);
        throw new Error("scan_draft_conflict: final draft won the canonical write");
      }
      assert.notEqual(staged.manifest.scan.complete, false);
      assert.deepEqual(
        staged.coverage.surfaces.map(({ id, disposition }) => ({ id, disposition })),
        [{ id: "surface-archive", disposition: "reported" }],
      );
    },
  );
  assert.equal(monotonicWrites, 2);

  const archivedRetryRoot = path.join(root, "archived-retry-worker");
  const archivedRetryOutput = path.join(archivedRetryRoot, "output");
  await mkdir(archivedRetryOutput, { recursive: true });
  const archivedRetryContext = { ...workerContext, root: archivedRetryOutput };
  await recordCodexSecurityWorkerScanDraft(archivedRetryContext, {
    ...workerInput,
    complete: false,
  });
  const checkpointOnlyFinding = structuredClone(finding);
  checkpointOnlyFinding.title = "Checkpoint-only finding";
  checkpointOnlyFinding.identity = { anchor: "checkpoint-only-finding" };
  checkpointOnlyFinding.provenance.candidateId = "checkpoint-only-candidate";
  checkpointOnlyFinding.extensions.candidateId = "checkpoint-only-candidate";
  await saveScanDraftCheckpoint(archivedRetryContext, {
    ...workerInput,
    complete: false,
    findings: [finding, checkpointOnlyFinding],
  });
  await mkdir(path.join(archivedRetryRoot, "attempts"));
  await rename(
    archivedRetryOutput,
    path.join(archivedRetryRoot, "attempts", "attempt-01"),
  );
  await mkdir(archivedRetryOutput);
  const {
    scope: _archivedScope,
    threatModel: _archivedThreatModel,
    ...replacementAttempt
  } = workerInput;
  await recordCodexSecurityWorkerScanDraft(archivedRetryContext, {
    ...replacementAttempt,
    findings: [],
  });
  const archivedRetryResult = JSON.parse(
    await readFile(path.join(archivedRetryOutput, "result.json"), "utf8"),
  );
  assert.deepEqual(
    new Set(archivedRetryResult.findings.map((item) => item.provenance.candidateId)),
    new Set([finding.provenance.candidateId, "checkpoint-only-candidate"]),
    "a replacement attempt must reconcile newer checkpoints with an older archived result",
  );
  assert.deepEqual(
    archivedRetryResult.scope,
    workerInput.scope,
    "a replacement attempt must retain the scope from archived checkpoints",
  );
  assert.deepEqual(
    archivedRetryResult.threatModel,
    workerInput.threatModel,
    "a replacement attempt must retain the threat model from archived checkpoints",
  );

  const archivedResolutionRoot = path.join(root, "archived-resolution-worker");
  const archivedResolutionOutput = path.join(archivedResolutionRoot, "output");
  await mkdir(archivedResolutionOutput, { recursive: true });
  const archivedResolutionContext = { ...workerContext, root: archivedResolutionOutput };
  await recordCodexSecurityWorkerScanDraft(archivedResolutionContext, {
    ...workerInput,
    complete: false,
  });
  const demotedCandidate = {
    candidateId: finding.provenance.candidateId,
    reason: "The later attempt demoted this candidate for more review.",
  };
  await recordCodexSecurityWorkerScanDraft(archivedResolutionContext, {
    ...workerInput,
    complete: false,
    findings: [],
    coverage: {
      ...coverage,
      completeness: "partial",
      surfaces: [],
      deferred: [demotedCandidate],
    },
  });
  await mkdir(path.join(archivedResolutionRoot, "attempts"));
  await rename(
    archivedResolutionOutput,
    path.join(archivedResolutionRoot, "attempts", "attempt-01"),
  );
  await mkdir(archivedResolutionOutput);
  await recordCodexSecurityWorkerScanDraft(archivedResolutionContext, {
    ...replacementAttempt,
    findings: [],
  });
  const archivedResolutionResult = JSON.parse(
    await readFile(path.join(archivedResolutionOutput, "result.json"), "utf8"),
  );
  assert.deepEqual(
    archivedResolutionResult.findings,
    [finding],
    "deferred coverage does not reject a validated finding from an archived attempt",
  );
  assert.deepEqual(archivedResolutionResult.coverage.deferred, []);

  const repeatedCheckpointRoot = path.join(root, "repeated-checkpoint-worker");
  const repeatedCheckpointOutput = path.join(repeatedCheckpointRoot, "output");
  const repeatedCheckpointContext = { ...workerContext, root: repeatedCheckpointOutput };
  await mkdir(repeatedCheckpointOutput, { recursive: true });
  let repeatedFindingDraft = {
    ...workerInput,
    complete: false,
  };
  await recordCodexSecurityWorkerScanDraft(
    repeatedCheckpointContext,
    repeatedFindingDraft,
  );
  const [findingCheckpointName] = await readdir(
    path.join(repeatedCheckpointOutput, "checkpoints"),
  );
  repeatedFindingDraft = JSON.parse(await readFile(
    path.join(repeatedCheckpointOutput, "checkpoints", findingCheckpointName),
    "utf8",
  ));
  await recordCodexSecurityWorkerScanDraft(repeatedCheckpointContext, {
    ...workerInput,
    complete: false,
    findings: [],
    coverage: {
      ...coverage,
      completeness: "partial",
      surfaces: [],
      deferred: [demotedCandidate],
    },
  });
  const demotionCheckpointName = (
    await readdir(path.join(repeatedCheckpointOutput, "checkpoints"))
  ).find((name) => name !== findingCheckpointName);
  assert.ok(demotionCheckpointName);
  const oldCheckpointTime = new Date("2026-01-01T00:00:00.000Z");
  const newerDemotionTime = new Date("2026-01-01T00:00:10.000Z");
  await utimes(
    path.join(repeatedCheckpointOutput, "checkpoints", findingCheckpointName),
    oldCheckpointTime,
    oldCheckpointTime,
  );
  for (const path_ of [
    path.join(repeatedCheckpointOutput, "checkpoints", demotionCheckpointName),
    path.join(repeatedCheckpointOutput, "result.json"),
  ]) {
    await utimes(path_, newerDemotionTime, newerDemotionTime);
  }
  await saveScanDraftCheckpoint(repeatedCheckpointContext, repeatedFindingDraft);
  await mkdir(path.join(repeatedCheckpointRoot, "attempts"));
  await rename(
    repeatedCheckpointOutput,
    path.join(repeatedCheckpointRoot, "attempts", "attempt-01"),
  );
  await mkdir(repeatedCheckpointOutput);
  await recordCodexSecurityWorkerScanDraft(repeatedCheckpointContext, {
    ...replacementAttempt,
    findings: [],
  });
  const repeatedCheckpointResult = JSON.parse(
    await readFile(path.join(repeatedCheckpointOutput, "result.json"), "utf8"),
  );
  assert.deepEqual(
    repeatedCheckpointResult.findings.map((item) => item.provenance.candidateId),
    [finding.provenance.candidateId],
    "a byte-identical repeated checkpoint must supersede an intervening demotion",
  );

  const multiAttemptRoot = path.join(root, "multi-attempt-resolution-worker");
  const multiAttemptOutput = path.join(multiAttemptRoot, "output");
  const multiAttemptContext = { ...workerContext, root: multiAttemptOutput };
  const multiAttemptArchive = path.join(multiAttemptRoot, "attempts");
  await mkdir(multiAttemptOutput, { recursive: true });
  await recordCodexSecurityWorkerScanDraft(multiAttemptContext, {
    ...workerInput,
    complete: false,
  });
  await mkdir(multiAttemptArchive);
  await rename(multiAttemptOutput, path.join(multiAttemptArchive, "attempt-01"));
  await mkdir(multiAttemptOutput);
  await recordCodexSecurityWorkerScanDraft(multiAttemptContext, {
    ...replacementAttempt,
    complete: false,
    findings: [],
    coverage: {
      ...coverage,
      completeness: "partial",
      surfaces: [],
      deferred: [demotedCandidate],
    },
  });
  await rename(multiAttemptOutput, path.join(multiAttemptArchive, "attempt-02"));
  await mkdir(multiAttemptOutput);
  await recordCodexSecurityWorkerScanDraft(multiAttemptContext, {
    ...replacementAttempt,
    findings: [],
  });
  const multiAttemptResult = JSON.parse(
    await readFile(path.join(multiAttemptOutput, "result.json"), "utf8"),
  );
  assert.deepEqual(
    multiAttemptResult.findings,
    [finding],
    "a newer archived deferred row cannot reject an older validated finding",
  );
  assert.deepEqual(
    multiAttemptResult.coverage.deferred,
    [],
    "the retained finding resolves the stale archived deferred row",
  );

  const malformedArchivedRoot = path.join(root, "malformed-archived-result-worker");
  const malformedArchivedOutput = path.join(malformedArchivedRoot, "output");
  const malformedArchivedContext = { ...workerContext, root: malformedArchivedOutput };
  await mkdir(malformedArchivedOutput, { recursive: true });
  await recordCodexSecurityWorkerScanDraft(malformedArchivedContext, {
    ...workerInput,
    complete: false,
  });
  await writeFile(path.join(malformedArchivedOutput, "result.json"), "{malformed");
  await mkdir(path.join(malformedArchivedRoot, "attempts"));
  await rename(
    malformedArchivedOutput,
    path.join(malformedArchivedRoot, "attempts", "attempt-01"),
  );
  await mkdir(malformedArchivedOutput);
  await recordCodexSecurityWorkerScanDraft(malformedArchivedContext, {
    ...replacementAttempt,
    findings: [],
  });
  assert.deepEqual(
    JSON.parse(await readFile(path.join(malformedArchivedOutput, "result.json"), "utf8")).findings,
    [finding],
    "valid checkpoints must recover evidence when an archived result is malformed",
  );

  const crossScanRetryRoot = path.join(root, "cross-scan-retry-worker");
  const crossScanRetryOutput = path.join(crossScanRetryRoot, "output");
  await mkdir(crossScanRetryOutput, { recursive: true });
  const crossScanRetryContext = { ...workerContext, root: crossScanRetryOutput };
  await recordCodexSecurityWorkerScanDraft(crossScanRetryContext, {
    ...workerInput,
    complete: false,
  });
  const crossScanAttempts = path.join(crossScanRetryRoot, "attempts");
  const crossScanAttempt = path.join(crossScanAttempts, "attempt-01");
  await mkdir(crossScanAttempts);
  await rename(crossScanRetryOutput, crossScanAttempt);
  const crossScanResultPath = path.join(crossScanAttempt, "result.json");
  const crossScanResult = JSON.parse(await readFile(crossScanResultPath, "utf8"));
  crossScanResult.scanId = "11111111-1111-4111-8111-111111111111";
  await writeFile(crossScanResultPath, JSON.stringify(crossScanResult));
  await mkdir(crossScanRetryOutput);
  await assert.rejects(
    recordCodexSecurityWorkerScanDraft(crossScanRetryContext, {
      ...replacementAttempt,
      findings: [],
    }),
    /scanId does not match the authoritative workbench scan/u,
    "a retry must reject archived findings from another scan",
  );

  const unreadableRetryRoot = path.join(root, "unreadable-retry-worker");
  const unreadableRetryOutput = path.join(unreadableRetryRoot, "output");
  const unreadableAttempt = path.join(unreadableRetryRoot, "attempts", "attempt-01");
  const unreadableCheckpointRoot = path.join(unreadableAttempt, "checkpoints");
  await mkdir(unreadableCheckpointRoot, { recursive: true });
  await mkdir(unreadableRetryOutput);
  const originalLstat = fsPromises.lstat;
  fsPromises.lstat = async (candidate, ...arguments_) => {
    if (path.resolve(String(candidate)) === path.resolve(unreadableCheckpointRoot)) {
      throw Object.assign(new Error("permission denied by test filesystem"), {
        code: "EACCES",
      });
    }
    return originalLstat(candidate, ...arguments_);
  };
  try {
    await assert.rejects(
      recordCodexSecurityWorkerScanDraft(
        { ...workerContext, root: unreadableRetryOutput },
        workerInput,
      ),
      /EACCES|permission denied/u,
      "an unreadable archived attempt must not be treated as an empty archive",
    );
  } finally {
    fsPromises.lstat = originalLstat;
  }

  const partialDeferredRoot = path.join(root, "partial-deferred-worker");
  await mkdir(partialDeferredRoot);
  const partialDeferredContext = { ...workerContext, root: partialDeferredRoot };
  const partialDeferredFinding = { summary: "Partial evidence captured before validation." };
  await recordCodexSecurityWorkerScanDraft(partialDeferredContext, {
    ...workerInput,
    complete: false,
    findings: [],
    coverage: {
      ...coverage,
      completeness: "partial",
      surfaces: [],
      deferred: [{
        candidateId: finding.provenance.candidateId,
        reason: "Validation is pending.",
        finding: partialDeferredFinding,
      }],
    },
  });
  await recordCodexSecurityWorkerScanDraft(partialDeferredContext, workerInput);
  const resolvedPartialDeferred = JSON.parse(
    await readFile(path.join(partialDeferredRoot, "result.json"), "utf8"),
  );
  assert.deepEqual(
    resolvedPartialDeferred.findings[0].provenance.previousFindings,
    [partialDeferredFinding],
  );

  const recorded = await recordCodexSecurityScanDraft(context, input);
  assert.deepEqual(recorded, {
    scanId,
    findingCount: 1,
    surfaceCount: 1,
    operation: "replace",
    status: "draft_written",
  });

  const manifest = await readJson(root, "scan-manifest.json");
  const findings = await readJson(root, "findings.json");
  const writtenCoverage = await readJson(root, "coverage.json");

  assert.deepEqual(manifest.scan.target, {
    kind: "git_worktree",
    targetId: "target_example",
    displayName: "example",
    revision: "1234567890abcdef",
    snapshotDigest:
      "codex-security-snapshot/v1:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  });
  assert.deepEqual(manifest.scan.scope, {
    summary: "Archive handling",
    includePaths: ["."],
    excludePaths: [],
  });
  assert.deepEqual(manifest.scan.threatModel, input.threatModel);
  assert.equal("sealedAt" in manifest.scan, false);
  assert.equal("artifacts" in manifest.scan, false);
  assert.equal("producer" in manifest.scan, false);
  assert.equal("hardening" in manifest.scan, false);

  assert.equal(findings.findings.length, 1);
  assert.deepEqual(findings.findings[0].taxonomy, finding.taxonomy);
  assert.deepEqual(findings.findings[0].provenance, finding.provenance);
  assert.deepEqual(findings.findings[0].severity, finding.severity);
  assert.deepEqual(findings.findings[0].confidence, finding.confidence);
  assert.deepEqual(findings.findings[0].extensions, finding.extensions);
  assert.deepEqual(findings.findings[0].identity, {
    anchor: "candidate-b5b7a3d14a148f6a",
  });
  assert.equal("findingId" in findings.findings[0], false);
  assert.equal("occurrenceId" in findings.findings[0], false);
  assert.equal("fingerprints" in findings.findings[0], false);

  assert.equal(writtenCoverage.mode, "repository");
  assert.equal(writtenCoverage.inventoryStrategy, "repository");
  assert.deepEqual(writtenCoverage.includePaths, ["."]);
  assert.deepEqual(writtenCoverage.excludePaths, []);
  assert.deepEqual(writtenCoverage.surfaces, [
    {
      label: "Archive extraction",
      disposition: "reported",
      notes: "Reviewed.",
      id: "surface_archive-extraction",
      receiptRefs: [],
    },
  ]);
  assert.deepEqual(writtenCoverage.extensions, coverage.extensions);

  await recordCodexSecurityScanDraft(context, semanticInput);
  const normalizedSemanticCoverage = await readJson(root, "coverage.json");
  assert.equal(normalizedSemanticCoverage.completeness, "partial");
  assert.deepEqual(normalizedSemanticCoverage.deferred, [
    {
      ...semanticCoverage.deferred[0],
      id: "candidate-deferred-archive",
    },
    {
      ...semanticCoverage.deferred[1],
      id: "candidate-reserved-archive-2",
    },
    semanticCoverage.deferred[2],
    {
      ...semanticCoverage.deferred[3],
      id: "candidate-deferred-archive-2",
    },
    {
      ...semanticCoverage.deferred[4],
      id: "candidate-reserved-archive-3",
    },
  ]);
  assert.deepEqual(normalizedSemanticCoverage.openQuestions, [
    { question: "Can archive entries reach another extraction sink?" },
    semanticCoverage.openQuestions[1],
  ]);
  const preservedSemanticFinding = (await readJson(root, "findings.json"))
    .findings[0];
  assert.equal(
    preservedSemanticFinding.remediation,
    semanticFinding.remediation,
  );
  assert.deepEqual(
    preservedSemanticFinding.remediationTests,
    semanticFinding.remediationTests,
  );
  assert.deepEqual(
    preservedSemanticFinding.preventiveControls,
    semanticFinding.preventiveControls,
  );
  assert.deepEqual(
    preservedSemanticFinding.provenance,
    semanticFinding.provenance,
  );
  assert.deepEqual(
    preservedSemanticFinding.extensions,
    semanticFinding.extensions,
  );
  assert.equal("id" in semanticCoverage.deferred[0], false);
  assert.equal(typeof semanticCoverage.openQuestions[0], "string");

  const originalReasonOnlyDeferred = structuredClone(reasonOnlyDeferred);
  await recordFreshScanDraft(context, reasonOnlyInput);
  const normalizedReasonOnlyCoverage = await readJson(root, "coverage.json");
  const unscopedDeferredId = expectedReasonOnlyDeferredId(
    reasonOnlyDeferred[0],
  );
  const contextualDeferredId = expectedReasonOnlyDeferredId(
    reasonOnlyDeferred[2],
  );
  assert.deepEqual(
    normalizedReasonOnlyCoverage.deferred,
    reasonOnlyDeferred.map((item, index) => ({
      ...item,
      id:
        index === 1
          ? `${unscopedDeferredId}-2`
          : index === 6
            ? `${contextualDeferredId}-2`
            : expectedReasonOnlyDeferredId(item),
    })),
    "reason-only deferred records receive stable semantic identities and collision suffixes",
  );
  assert.equal(
    expectedReasonOnlyDeferredId(reasonOnlyDeferred[0]),
    expectedReasonOnlyDeferredId(reasonOnlyDeferred[1]),
    "missing paths and surface IDs are semantically equivalent to empty arrays",
  );
  assert.notEqual(
    contextualDeferredId,
    expectedReasonOnlyDeferredId(reasonOnlyDeferred[3]),
    "changing a deferred reason changes its semantic identity",
  );
  assert.notEqual(
    contextualDeferredId,
    expectedReasonOnlyDeferredId(reasonOnlyDeferred[4]),
    "changing deferred paths changes their semantic identity",
  );
  assert.notEqual(
    contextualDeferredId,
    expectedReasonOnlyDeferredId(reasonOnlyDeferred[5]),
    "changing deferred surface IDs changes their semantic identity",
  );
  assert.deepEqual(
    reasonOnlyDeferred,
    originalReasonOnlyDeferred,
    "generating deferred identities does not mutate the caller's semantic input",
  );
  await recordCodexSecurityScanDraft(context, reasonOnlyInput);
  assert.deepEqual(
    (await readJson(root, "coverage.json")).deferred,
    normalizedReasonOnlyCoverage.deferred,
    "repeating the same semantic draft produces the same canonical deferred identities",
  );

  const collidingWithExplicit = {
    reason:
      "A later explicit deferred record already owns this semantic identity.",
  };
  const collidingWithCandidate = {
    reason:
      "A later candidate-backed deferred record already owns this semantic identity.",
  };
  const reservedExplicitId = expectedReasonOnlyDeferredId(
    collidingWithExplicit,
  );
  const reservedCandidateId = expectedReasonOnlyDeferredId(
    collidingWithCandidate,
  );
  const reservedDeferred = [
    collidingWithExplicit,
    collidingWithCandidate,
    {
      id: reservedExplicitId,
      reason: "Keep the later explicitly owned deferred identity unchanged.",
    },
    {
      candidateId: reservedCandidateId,
      reason: "Keep the later candidate-backed deferred identity unchanged.",
    },
  ];
  await recordFreshScanDraft(context, {
    ...input,
    coverage: {
      ...coverage,
      completeness: "partial",
      deferred: reservedDeferred,
    },
  });
  assert.deepEqual(
    (await readJson(root, "coverage.json")).deferred,
    [
      { ...collidingWithExplicit, id: `${reservedExplicitId}-2` },
      { ...collidingWithCandidate, id: `${reservedCandidateId}-2` },
      reservedDeferred[2],
      { ...reservedDeferred[3], id: reservedCandidateId },
    ],
    "generated deferred identities never take later explicit or candidate identities",
  );
  assert.equal("id" in collidingWithExplicit, false);
  assert.equal("id" in collidingWithCandidate, false);
  assert.equal("id" in reservedDeferred[3], false);

  const existingReceiptRefs = ["artifacts/02_discovery/candidate_ledger.jsonl"];
  await recordFreshScanDraft(context, {
    ...input,
    coverage: {
      ...coverage,
      surfaces: [
        {
          label: "Archive extraction",
          disposition: "reported",
          receiptRefs: existingReceiptRefs,
        },
      ],
    },
  });
  assert.deepEqual(
    (await readJson(root, "coverage.json")).surfaces[0].receiptRefs,
    existingReceiptRefs,
  );

  const hardeningDirectory = path.join(root, "hardening");
  const hardeningPortfolio = path.join(hardeningDirectory, "hardening.md");
  await mkdir(hardeningDirectory);
  await writeFile(hardeningPortfolio, "# Optional existing hardening\n");
  await recordFreshScanDraft(context, input);
  assert.deepEqual(
    (await readJson(root, "scan-manifest.json")).scan.hardening,
    {
      portfolioPath: "hardening/hardening.md",
    },
  );

  await rm(hardeningPortfolio);
  await recordFreshScanDraft(context, input);
  assert.equal(
    "hardening" in (await readJson(root, "scan-manifest.json")).scan,
    false,
  );

  const externalHardeningPortfolio = path.join(root, "external-hardening.md");
  await writeFile(
    externalHardeningPortfolio,
    "# Not a trusted hardening portfolio\n",
  );
  await symlink(externalHardeningPortfolio, hardeningPortfolio);
  const beforeUnsafeHardening = await readFile(
    path.join(root, "scan-manifest.json"),
    "utf8",
  );
  await assert.rejects(
    recordCodexSecurityScanDraft(context, input),
    /hardening portfolio.*safe regular file/,
  );
  assert.equal(
    await readFile(path.join(root, "scan-manifest.json"), "utf8"),
    beforeUnsafeHardening,
  );
  await rm(hardeningPortfolio);
  await rm(externalHardeningPortfolio);

  const explicitIdentity = { anchor: "preserve-the-existing-finding-identity" };
  await recordFreshScanDraft(context, {
    ...input,
    findings: [{ ...finding, identity: explicitIdentity }],
  });
  assert.deepEqual(
    (await readJson(root, "findings.json")).findings[0].identity,
    explicitIdentity,
  );

  const identityRoot = path.join(root, "preserved-finding-identity-worker");
  await mkdir(identityRoot);
  const identityContext = { ...workerContext, root: identityRoot };
  await recordCodexSecurityWorkerScanDraft(identityContext, {
    ...workerInput,
    findings: [{ ...finding, identity: explicitIdentity }],
  });
  await recordCodexSecurityWorkerScanDraft(identityContext, workerInput);
  assert.deepEqual(
    JSON.parse(await readFile(path.join(identityRoot, "result.json"), "utf8"))
      .findings[0].identity,
    explicitIdentity,
    "a later refinement inherits the stable identity of the matched saved finding",
  );

  await recordFreshScanDraft(context, {
    ...input,
    findings: [
      {
        ...finding,
        extensions: { ...finding.extensions, candidateId: "candidate-a" },
      },
      {
        ...finding,
        extensions: { ...finding.extensions, candidateId: "candidate-b" },
      },
    ],
  });
  assert.deepEqual(
    (await readJson(root, "findings.json")).findings.map(
      (item) => item.identity.anchor,
    ),
    ["candidate-a", "candidate-b"],
  );

  await recordFreshScanDraft(context, {
    ...input,
    findings: [
      {
        ...finding,
        extensions: {
          ...finding.extensions,
          candidateId: "candidate-singleton",
          reportId: "DSS-144-A",
        },
      },
    ],
  });
  assert.deepEqual(
    (await readJson(root, "findings.json")).findings[0].identity,
    { anchor: "candidate-singleton", instance: "dss-144-a" },
    "stable report-backed instances do not depend on sibling count",
  );

  await recordFreshScanDraft(context, {
    ...input,
    findings: [
      {
        ...finding,
        identity: {
          anchor: "candidate-cross-rule",
          instance: "shared-report",
        },
        ruleId: "path-traversal.archive-upload",
      },
      {
        ...finding,
        extensions: {
          ...finding.extensions,
          candidateId: "candidate-cross-rule",
          reportId: "shared-report",
        },
      },
      {
        ...finding,
        extensions: {
          ...finding.extensions,
          candidateId: "candidate-cross-rule",
          reportId: "second-report",
        },
      },
    ],
  });
  assert.deepEqual(
    (await readJson(root, "findings.json")).findings.map(
      (item) => item.identity,
    ),
    [
      { anchor: "candidate-cross-rule", instance: "shared-report" },
      { anchor: "candidate-cross-rule", instance: "shared-report" },
      { anchor: "candidate-cross-rule", instance: "second-report" },
    ],
    "sibling identities are scoped by rule ID and anchor",
  );

  await recordFreshScanDraft(context, {
    ...input,
    findings: [
      {
        ...finding,
        extensions: {
          ...finding.extensions,
          candidateId: "candidate-shared",
          reportId: "DSS-145-A",
        },
      },
      {
        ...finding,
        extensions: {
          ...finding.extensions,
          candidateId: "candidate-shared",
          ledgerRowId: "ledger-row-b",
        },
      },
    ],
  });
  assert.deepEqual(
    (await readJson(root, "findings.json")).findings.map(
      (item) => item.identity,
    ),
    [
      { anchor: "candidate-shared", instance: "dss-145-a" },
      { anchor: "candidate-shared", instance: "ledger-row-b" },
    ],
  );

  await recordFreshScanDraft(context, {
    ...input,
    findings: [
      {
        ...finding,
        identity: { anchor: "candidate-authored-collision" },
      },
      {
        ...finding,
        extensions: {
          ...finding.extensions,
          candidateId: "candidate-authored-collision",
          reportId: "DSS-146-A",
        },
      },
    ],
  });
  assert.deepEqual(
    (await readJson(root, "findings.json")).findings.map(
      (item) => item.identity,
    ),
    [
      { anchor: "candidate-authored-collision" },
      { anchor: "candidate-authored-collision", instance: "dss-146-a" },
    ],
  );

  await recordFreshScanDraft(context, {
    ...input,
    findings: [
      {
        ...finding,
        identity: {
          anchor: "candidate-authored-instance",
          instance: "dss-147-a",
        },
      },
      {
        ...finding,
        extensions: {
          ...finding.extensions,
          candidateId: "candidate-authored-instance",
          reportId: "DSS-147-A",
        },
      },
      {
        ...finding,
        extensions: {
          ...finding.extensions,
          candidateId: "candidate-authored-instance",
          ledgerRowId: "ledger-row-c",
        },
      },
    ],
  });
  assert.deepEqual(
    (await readJson(root, "findings.json")).findings.map(
      (item) => item.identity,
    ),
    [
      { anchor: "candidate-authored-instance", instance: "dss-147-a" },
      { anchor: "candidate-authored-instance", instance: "dss-147-a" },
      {
        anchor: "candidate-authored-instance",
        instance: "ledger-row-c",
      },
    ],
    "duplicate stable instance sources remain collisions for finalization",
  );

  const completeCodeEvidence = {
    ...incompleteCodeEvidence,
    code: "extract_archive_entry(untrusted_entry, output_path)",
  };
  const evidencedFinding = {
    ...finding,
    codeEvidence: [completeCodeEvidence],
    rootCause: {
      summary: "The extraction sink does not constrain the archive entry.",
      evidenceRefs: [completeCodeEvidence.id],
    },
    validation: { evidenceRefs: [completeCodeEvidence.id] },
    attackPath: { evidenceRefs: [completeCodeEvidence.id] },
  };
  await recordFreshScanDraft(context, {
    ...input,
    findings: [evidencedFinding],
  });
  const evidencedOutput = (await readJson(root, "findings.json")).findings[0];
  assert.deepEqual(evidencedOutput.codeEvidence, [completeCodeEvidence]);
  assert.deepEqual(evidencedOutput.rootCause, evidencedFinding.rootCause);
  assert.deepEqual(evidencedOutput.validation, evidencedFinding.validation);
  assert.deepEqual(evidencedOutput.attackPath, evidencedFinding.attackPath);
  assert.deepEqual(evidencedOutput.provenance, finding.provenance);
  assert.deepEqual(evidencedOutput.extensions, finding.extensions);

  const legacyEvidencedFinding = {
    ...finding,
    code_evidence: [completeCodeEvidence],
    attackPath: {
      dataflow: { evidence_refs: [completeCodeEvidence.id] },
    },
  };
  await recordFreshScanDraft(context, {
    ...input,
    findings: [legacyEvidencedFinding],
  });
  const legacyEvidencedOutput = (await readJson(root, "findings.json"))
    .findings[0];
  assert.deepEqual(legacyEvidencedOutput.code_evidence, [
    completeCodeEvidence,
  ]);
  assert.deepEqual(
    legacyEvidencedOutput.attackPath,
    legacyEvidencedFinding.attackPath,
  );

  await recordFreshScanDraft(context, {
    ...input,
    findings: [
      {
        ...finding,
        taxonomy: { category: "path-traversal", cwe: [] },
      },
    ],
  });
  assert.deepEqual(
    (await readJson(root, "findings.json")).findings[0].taxonomy,
    { category: "path-traversal", cwe: [] },
  );

  const directoryContext = {
    ...context,
    targetRevision: "unversioned",
    targetContract: {
      ...context.targetContract,
      target: {
        ...context.targetContract.target,
        allowedKinds: ["directory_snapshot"],
      },
    },
  };
  await recordFreshScanDraft(directoryContext, input);
  const directoryManifest = await readJson(root, "scan-manifest.json");
  assert.equal(directoryManifest.scan.target.kind, "directory_snapshot");
  assert.equal("revision" in directoryManifest.scan.target, false);
  assert.equal(
    (await readJson(root, "coverage.json")).inventoryStrategy,
    "directory",
  );

  await recordFreshScanDraft({ ...context, mode: "deep" }, input);
  assert.equal((await readJson(root, "coverage.json")).mode, "deep_repository");
  assert.equal(
    (await readJson(root, "coverage.json")).inventoryStrategy,
    "repository",
  );

  await recordFreshScanDraft(
    { ...directoryContext, mode: "deep" },
    input,
  );
  assert.equal(
    (await readJson(root, "scan-manifest.json")).scan.target.kind,
    "directory_snapshot",
  );
  assert.equal((await readJson(root, "coverage.json")).mode, "deep_repository");
  assert.equal(
    (await readJson(root, "coverage.json")).inventoryStrategy,
    "repository",
  );

  const scopedContext = {
    ...context,
    scope: "src",
    targetContract: {
      ...context.targetContract,
      scope: {
        requiredIncludePaths: ["src", "lib"],
        requiredExcludePaths: ["vendor"],
      },
    },
  };
  await recordFreshScanDraft(scopedContext, input);
  const scopedCoverage = await readJson(root, "coverage.json");
  assert.equal(scopedCoverage.mode, "scoped_path");
  assert.equal(scopedCoverage.inventoryStrategy, "scoped_path");
  assert.deepEqual(scopedCoverage.includePaths, ["src", "lib"]);
  assert.deepEqual(scopedCoverage.excludePaths, ["vendor"]);

  const diffDigest =
    "codex-security-snapshot/v1:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  const diffContext = {
    ...context,
    mode: "diff",
    targetContract: {
      ...context.targetContract,
      target: {
        allowedKinds: ["git_diff"],
        targetId: "target_diff",
        displayName: "example",
      },
      diffTarget: {
        kind: "working_tree",
        baseRevision: "base123",
        headRevision: "head456",
        contentDigest: diffDigest,
      },
    },
  };
  await recordFreshScanDraft(diffContext, input);
  assert.deepEqual((await readJson(root, "scan-manifest.json")).scan.target, {
    kind: "git_diff",
    targetId: "target_diff",
    displayName: "example",
    baseRevision: "base123",
    headRevision: "head456",
    snapshotDigest: diffDigest,
  });
  const diffCoverage = await readJson(root, "coverage.json");
  assert.equal(diffCoverage.mode, "working_tree");
  assert.equal(diffCoverage.inventoryStrategy, "diff");

  for (const kind of ["commit", "range"]) {
    const committedDiff = {
      ...diffContext,
      targetContract: {
        ...diffContext.targetContract,
        diffTarget: {
          kind,
          baseRevision: "base123",
          headRevision: "head456",
        },
      },
    };
    await recordFreshScanDraft(committedDiff, input);
    const expectedDigest = createHash("sha256")
      .update("codex-security-diff/v1\0")
      .update(kind)
      .update("\0")
      .update("base123")
      .update("\0")
      .update("head456")
      .digest("hex");
    assert.equal(
      (await readJson(root, "scan-manifest.json")).scan.target.snapshotDigest,
      `codex-security-snapshot/v1:sha256:${expectedDigest}`,
    );
    assert.equal(
      (await readJson(root, "coverage.json")).mode,
      kind === "commit" ? "commit" : "branch_diff",
    );
  }

  await recordFreshScanDraft(context, input);

  const originalManifest = await readFile(
    path.join(root, "scan-manifest.json"),
    "utf8",
  );
  const originalFindings = await readFile(
    path.join(root, "findings.json"),
    "utf8",
  );
  const originalCoverage = await readFile(
    path.join(root, "coverage.json"),
    "utf8",
  );

  for (const [description, rejectedInput] of rejectedDraftInputs) {
    await assert.rejects(
      recordCodexSecurityScanDraft(context, rejectedInput),
      Error,
      description,
    );
    assert.equal(
      await readFile(path.join(root, "scan-manifest.json"), "utf8"),
      originalManifest,
      `${description}: scan manifest must not be modified`,
    );
    assert.equal(
      await readFile(path.join(root, "findings.json"), "utf8"),
      originalFindings,
      `${description}: findings must not be modified`,
    );
    assert.equal(
      await readFile(path.join(root, "coverage.json"), "utf8"),
      originalCoverage,
      `${description}: coverage must not be modified`,
    );
  }

  await assert.rejects(
    recordCodexSecurityScanDraft(context, {
      ...input,
      findings: [{ ...finding, severity: { level: "high", score: 8.1 } }],
    }),
    /severity\.scoringSystem/,
  );
  await assert.rejects(
    recordCodexSecurityScanDraft(context, {
      ...input,
      findings: [
        {
          ...finding,
          locations: [{ path: "src/extract.py", startLine: 8, endLine: 2 }],
        },
      ],
    }),
    /endLine.*precede startLine/,
  );
  await assert.rejects(
    recordCodexSecurityScanDraft(context, {
      ...input,
      findings: [
        {
          ...finding,
          code_evidence: [completeCodeEvidence, completeCodeEvidence],
        },
      ],
    }),
    /code_evidence\[1\]\.id duplicates/,
  );
  await assert.rejects(
    recordCodexSecurityScanDraft(context, {
      ...input,
      findings: [
        {
          ...finding,
          codeEvidence: [completeCodeEvidence],
          code_evidence: [completeCodeEvidence],
        },
      ],
    }),
    /code_evidence\[0\]\.id duplicates/,
  );
  await assert.rejects(
    recordCodexSecurityScanDraft(context, {
      ...input,
      coverage: {
        ...coverage,
        deferred: [{ id: "deferred-upload", reason: "Runtime unavailable." }],
      },
    }),
    /complete coverage cannot contain deferred/,
  );
  await assert.rejects(
    recordCodexSecurityScanDraft(context, {
      ...input,
      coverage: {
        ...coverage,
        deferred: [
          {
            candidateId: "candidate-deferred-archive",
            reason: "The upload runtime was unavailable.",
          },
        ],
      },
    }),
    /complete coverage cannot contain deferred/,
  );
  await assert.rejects(
    recordCodexSecurityScanDraft(context, {
      ...input,
      coverage: {
        ...coverage,
        deferred: [{ reason: "The upload runtime was unavailable." }],
      },
    }),
    /complete coverage cannot contain deferred/,
  );
  assert.equal(
    await readFile(path.join(root, "scan-manifest.json"), "utf8"),
    originalManifest,
  );
  assert.equal(
    await readFile(path.join(root, "findings.json"), "utf8"),
    originalFindings,
  );
  assert.equal(
    await readFile(path.join(root, "coverage.json"), "utf8"),
    originalCoverage,
  );
  await assert.rejects(
    recordCodexSecurityScanDraft(context, {
      ...input,
      coverage: {
        ...coverage,
        surfaces: [{ label: "Uploads", disposition: "needs_follow_up" }],
      },
    }),
    /complete coverage cannot contain needs_follow_up/,
  );
  await assert.rejects(
    recordCodexSecurityScanDraft(context, {
      ...input,
      findings: [
        {
          ...finding,
          validation: { evidenceRefs: ["missing-evidence"] },
        },
      ],
    }),
    /evidenceRefs must refer/,
  );
  await assert.rejects(
    recordCodexSecurityScanDraft(context, {
      ...input,
      findings: [
        {
          ...finding,
          root_cause: { evidenceRefs: ["missing-root-cause-evidence"] },
        },
      ],
    }),
    /root_cause\.evidenceRefs must refer/,
  );
  await assert.rejects(
    recordCodexSecurityScanDraft(context, {
      ...input,
      findings: [
        {
          ...finding,
          root_cause: { summary: ["not a string"] },
        },
      ],
    }),
    /root_cause/,
  );
  await assert.rejects(
    recordCodexSecurityScanDraft(context, {
      ...input,
      findings: [
        {
          ...finding,
          attackPath: {
            dataflow: { evidenceRefs: ["missing-dataflow-evidence"] },
          },
        },
      ],
    }),
    /attackPath\.dataflow\.evidenceRefs must refer/,
  );
  await assert.rejects(
    recordCodexSecurityScanDraft(context, {
      ...input,
      findings: [
        {
          ...finding,
          validation: { evidence_refs: ["missing-validation-evidence"] },
        },
      ],
    }),
    /validation\.evidence_refs must refer/,
  );
  await assert.rejects(
    recordCodexSecurityScanDraft(context, {
      ...input,
      handoffClaimToken: "c1a0c0de-c0de-4c0d-8c0d-c0dec0dec0de",
    }),
    /handoffClaimToken/,
  );
  await assert.rejects(
    recordCodexSecurityScanDraft({ ...context, layout: "worker" }, input),
    /authoritative parent scan context/,
  );
  await assert.rejects(
    recordCodexSecurityScanDraft({ ...context, status: "complete" }, input),
    /running workbench scan/,
  );
  await assert.rejects(
    recordCodexSecurityScanDraft(
      { ...context, scanId: "d7caa0cf-b785-47ef-95e7-e753dc288608" },
      input,
    ),
    /scanId does not match/,
  );
  await assert.rejects(
    recordCodexSecurityScanDraft(
      {
        ...context,
        targetContract: {
          ...context.targetContract,
          target: { ...context.targetContract.target, allowedKinds: [] },
        },
      },
      input,
    ),
    /no allowed target kind/,
  );

  assert.equal(
    await readFile(path.join(root, "scan-manifest.json"), "utf8"),
    originalManifest,
  );
  assert.equal(
    await readFile(path.join(root, "findings.json"), "utf8"),
    originalFindings,
  );
  assert.equal(
    await readFile(path.join(root, "coverage.json"), "utf8"),
    originalCoverage,
  );

  const duplicateSurfaceCoverage = {
    ...coverage,
    completeness: "partial",
    surfaces: [
      { id: "surface-web-ui", label: "Web UI", disposition: "reported" },
      { id: "surface-web-ui", label: "Admin UI", disposition: "reported" },
      { id: "surface-web-ui-2", label: "Existing UI", disposition: "reported" },
      { label: "Uploads", disposition: "reported" },
      {
        id: "surface_uploads",
        label: "Existing uploads",
        disposition: "reported",
      },
      { label: "Archive extraction", disposition: "reported" },
      { label: "Archive extraction", disposition: "reported" },
    ],
    deferred: [
      {
        id: "deferred-web-ui",
        reason: "The web UI requires follow-up.",
        surfaceIds: ["surface-web-ui"],
      },
    ],
  };
  await recordFreshScanDraft(context, {
    ...input,
    coverage: duplicateSurfaceCoverage,
  });
  const normalizedDuplicateCoverage = await readJson(root, "coverage.json");
  assert.deepEqual(
    normalizedDuplicateCoverage.surfaces.map((surface) => surface.id),
    [
      "surface-web-ui",
      "surface-web-ui-3",
      "surface-web-ui-2",
      "surface_uploads-2",
      "surface_uploads",
      "surface_archive-extraction",
      "surface_archive-extraction-2",
    ],
  );
  assert.deepEqual(
    normalizedDuplicateCoverage.deferred,
    duplicateSurfaceCoverage.deferred,
  );

  const partialCoverage = {
    completeness: "partial",
    surfaces: [
      {
        label: "Archive extraction",
        disposition: "needs_follow_up",
        notes: "The runtime extraction behavior remains unverified.",
      },
    ],
    explicitExclusions: [],
    deferred: [
      {
        id: "deferred-archive-runtime",
        reason:
          "The repository does not include its runtime extraction dependency.",
        paths: ["src/extract.py"],
      },
    ],
  };
  const repairedPartial = await recordFreshScanDraft(context, {
    ...input,
    coverage: partialCoverage,
  });
  assert.deepEqual(repairedPartial, {
    scanId,
    findingCount: 1,
    surfaceCount: 1,
    operation: "replace",
    status: "draft_written",
  });
  const repairedCoverage = await readJson(root, "coverage.json");
  assert.equal(repairedCoverage.completeness, "partial");
  assert.deepEqual(repairedCoverage.deferred, partialCoverage.deferred);
  assert.equal(repairedCoverage.surfaces[0].disposition, "needs_follow_up");
  assert.deepEqual(
    (await readJson(root, "findings.json")).findings[0].provenance,
    finding.provenance,
  );

  const noFindings = {
    ...input,
    findings: [],
    coverage: {
      completeness: "complete",
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
    },
  };
  const clean = await recordFreshScanDraft(context, noFindings);
  assert.equal(clean.findingCount, 0);
  assert.deepEqual((await readJson(root, "findings.json")).findings, []);

  await assert.rejects(
    getCodexSecurityCompletedScan(context, {
      scanId,
      handoffClaimToken: claimToken,
    }),
    /has not completed/,
  );

  const sealedManifest = {
    scan: {
      id: scanId,
      status: "completed",
      sealedAt: "2026-07-28T02:00:00Z",
      artifacts: [{ path: "findings.json" }, { path: "coverage.json" }],
    },
  };
  const sealedFindings = { scanId, findings: [] };
  const sealedCoverage = { scanId, surfaces: [] };
  await writeFile(
    path.join(root, "scan-manifest.json"),
    `${JSON.stringify(sealedManifest)}\n`,
  );
  await writeFile(
    path.join(root, "findings.json"),
    `${JSON.stringify(sealedFindings)}\n`,
  );
  await writeFile(
    path.join(root, "coverage.json"),
    `${JSON.stringify(sealedCoverage)}\n`,
  );

  const completeContext = { ...context, status: "complete" };
  assert.deepEqual(
    await getCodexSecurityCompletedScan(completeContext, {
      scanId,
      handoffClaimToken: claimToken,
    }),
    {
      scanId,
      manifest: sealedManifest,
      findings: sealedFindings,
      coverage: sealedCoverage,
    },
  );

  await writeFile(
    path.join(root, "findings.json"),
    `${JSON.stringify({ scanId: "d7caa0cf-b785-47ef-95e7-e753dc288608", findings: [] })}\n`,
  );
  await assert.rejects(
    getCodexSecurityCompletedScan(completeContext, {
      scanId,
      handoffClaimToken: claimToken,
    }),
    /do not match the sealed workbench scan/,
  );

  await writeFile(
    path.join(root, "findings.json"),
    `${JSON.stringify(sealedFindings)}\n`,
  );
  await writeFile(path.join(root, "coverage.json"), "{not valid JSON\n");
  await assert.rejects(
    getCodexSecurityCompletedScan(completeContext, {
      scanId,
      handoffClaimToken: claimToken,
    }),
    /malformed|invalid JSON/,
  );

  await writeFile(
    path.join(root, "coverage.json"),
    `${JSON.stringify(sealedCoverage)}\n`,
  );
  const external = path.join(root, "external.json");
  await writeFile(external, `${JSON.stringify(sealedFindings)}\n`);
  await rm(path.join(root, "findings.json"));
  await symlink(external, path.join(root, "findings.json"));
  await assert.rejects(
    getCodexSecurityCompletedScan(completeContext, {
      scanId,
      handoffClaimToken: claimToken,
    }),
    /safe regular file|regular file|symbolic link/,
  );
} finally {
  await rm(root, { recursive: true, force: true });
}

console.log("Codex Security scan draft artifact tests passed");

async function readJson(rootDirectory, name) {
  return JSON.parse(await readFile(path.join(rootDirectory, name), "utf8"));
}

function expectedReasonOnlyDeferredId(item) {
  const semantics = JSON.stringify([
    item.reason,
    item.paths ?? [],
    item.surfaceIds ?? [],
  ]);
  return `deferred-${createHash("sha256").update(semantics).digest("hex").slice(0, 16)}`;
}

// Projection cases below use the same fixture root but model independent scans.
async function recordFreshScanDraft(context, input) {
  await Promise.all([
    ...["scan-manifest.json", "findings.json", "coverage.json", "checkpoint-head.json"].map(
      name => rm(path.join(context.root, name), { force: true }),
    ),
    rm(path.join(context.root, "checkpoints"), { recursive: true, force: true }),
  ]);
  return recordCodexSecurityScanDraft(context, input);
}
