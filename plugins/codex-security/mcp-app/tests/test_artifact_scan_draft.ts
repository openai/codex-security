import { workerDraft } from "./scan-draft-fixture.ts";
import { readJson, snapshotScanDraft, writeJsonLine } from "./support/json.ts";
import { mock } from "node:test";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import type { ArtifactContext } from "../src/artifact-context.js";
import type { ScanDraftInput } from "../src/artifact-scan-draft.js";
type FixtureFinding = Record<string, unknown> & {
  provenance: Record<string, unknown>;
  identity?: { anchor: string; instance?: string };
};

import assert from "node:assert/strict";
import { hash } from "node:crypto";
import { promises as fsPromises } from "node:fs";
import {
  mkdir,
  readdir,
  readFile,
  rename,
  rm,
  symlink,
  utimes,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import {
  claimToken,
  draftApi,
  draftFixture,
  scanId,
  surfaceDisposition,
} from "./scan-draft-recovery-fixture.ts";

const {
  completedScanInputSchema,
  getCodexSecurityCompletedScan,
  recordCodexSecurityScanDraft,
  recordCodexSecurityScanDraftViaWorkbench,
  recordCodexSecurityWorkerScanDraft,
  saveScanDraftCheckpoint,
  scanDraftInputSchema,
} = draftApi;

const root = await temporaryDirectory("codex-security-scan-draft-", true);

try {
  const { context } = draftFixture(root, "standard");

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
        id: "surface_archive-extraction",
        label: "Archive extraction",
        disposition: "reported",
        notes: "Reviewed.",
        receiptRefs: [],
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

  const findingInput = (changes: Record<string, unknown>) => ({
    ...input,
    findings: [{ ...finding, ...changes }],
  });
  const coverageInput = (changes: Record<string, unknown>) => ({
    ...input,
    coverage: { ...coverage, ...changes },
  });

  const rejectsDraft = (
    input: ScanDraftInput,
    error: RegExp,
    boundContext: ArtifactContext = context,
  ) => assert.rejects(recordCodexSecurityScanDraft(boundContext, input), error);

  const workerRoot = path.join(root, "worker-output");
  await mkdir(workerRoot);
  const workerContext = {
    root: workerRoot,
    repoRoot: root,
    layout: "worker",
    scanId,
  };
  const createWorkerContext = async (name: string) => {
    const directory = path.join(root, name);
    await mkdir(directory);
    return { ...workerContext, root: directory };
  };

  const workerInput = {
    scanId,
    scope: { summary: "Archive handling" },
    threatModel: { summary: "Untrusted users may upload archives." },
    findings: [finding],
    coverage,
  };
  const workerResultPath = path.join(workerRoot, "result.json");

  const checkpointContext = await createWorkerContext("checkpoint-worker");
  const checkpointRoot = checkpointContext.root;
  const checkpoint = { ...workerInput, complete: false };
  await recordCodexSecurityWorkerScanDraft(checkpointContext, checkpoint);
  const checkpointFiles = await readdir(
    path.join(checkpointRoot, "checkpoints"),
  );
  assert.equal(checkpointFiles.length, 1);
  assert.deepEqual(
    await readJson(checkpointRoot, "checkpoints", checkpointFiles[0]),
    checkpoint,
  );
  const checkpointBytes = await readFile(
    path.join(checkpointRoot, "checkpoints", checkpointFiles[0]),
  );
  await recordCodexSecurityWorkerScanDraft(checkpointContext, {
    ...workerInput,
    findings: [],
  });
  assert.deepEqual(
    (await readJson(checkpointRoot, "result.json")).findings,
    [finding],
    "a later write cannot silently remove a saved validated finding",
  );
  assert.deepEqual(
    await readFile(
      path.join(checkpointRoot, "checkpoints", checkpointFiles[0]),
    ),
    checkpointBytes,
  );
  assert.equal(
    (await readdir(path.join(checkpointRoot, "checkpoints"))).length,
    3,
    "raw and reconciled drafts remain immutable while the head selects the accepted result",
  );

  const interruptedContext = await createWorkerContext(
    "interrupted-checkpoint-worker",
  );
  const interruptedRoot = interruptedContext.root;
  const interruptedFinding: typeof finding & { identity?: { anchor: string } } =
    structuredClone(finding);
  interruptedFinding.identity = { anchor: "interrupted-checkpoint" };
  interruptedFinding.provenance.candidateId = "interrupted-checkpoint";
  interruptedFinding.extensions.candidateId = "interrupted-checkpoint";
  await saveScanDraftCheckpoint(
    interruptedContext,
    {
      ...workerInput,
      complete: false,
      findings: [interruptedFinding],
      coverage: {
        ...coverage,
        completeness: "partial",
        deferred: [
          {
            candidateId: "interrupted-review",
            reason: "Review was checkpointed.",
          },
        ],
      },
    },
    false,
  );
  await recordCodexSecurityWorkerScanDraft(interruptedContext, {
    ...workerInput,
    findings: [],
  });
  const interruptedResult = await readJson(interruptedRoot, "result.json");
  assert.deepEqual(interruptedResult.findings, [interruptedFinding]);
  assert.equal(
    interruptedResult.coverage.deferred.some(
      (item: FixtureFinding) => item.candidateId === "interrupted-review",
    ),
    true,
  );

  const rejectedIncompleteContext = await createWorkerContext(
    "rejected-incomplete-worker",
  );
  const rejectedIncompleteRoot = rejectedIncompleteContext.root;
  await recordCodexSecurityWorkerScanDraft(
    rejectedIncompleteContext,
    workerInput,
  );
  await recordCodexSecurityWorkerScanDraft(rejectedIncompleteContext, {
    ...workerInput,
    complete: false,
    findings: [],
    coverage: {
      ...coverage,
      completeness: "partial",
      surfaces: [
        {
          candidateId: finding.provenance.candidateId,
          label: "Archive extraction",
          disposition: "rejected",
          notes: "The incomplete writer rejected this candidate.",
        },
      ],
      deferred: [
        {
          candidateId: "late-incomplete-review",
          reason: "This arrived after the worker completed.",
        },
      ],
    },
  });
  const acceptedHead = await readJson(
    rejectedIncompleteRoot,
    "checkpoint-head.json",
  );
  const acceptedHeadDraft = await readJson(
    rejectedIncompleteRoot,
    "checkpoints",
    acceptedHead.checkpoint,
  );
  assert.notEqual(
    acceptedHeadDraft.complete,
    false,
    "a rejected incomplete write must not become the authoritative checkpoint head",
  );
  assert.deepEqual(acceptedHeadDraft.findings, [finding]);
  const acceptedResult = await readJson(rejectedIncompleteRoot, "result.json");
  assert.equal(
    acceptedResult.coverage.deferred.some(
      (item: FixtureFinding) => item.candidateId === "late-incomplete-review",
    ),
    false,
    "a rejected incomplete write must not change the completed result",
  );

  const deferredDoesNotRejectContext = await createWorkerContext(
    "deferred-does-not-reject-worker",
  );
  const deferredDoesNotRejectRoot = deferredDoesNotRejectContext.root;
  await recordCodexSecurityWorkerScanDraft(
    deferredDoesNotRejectContext,
    workerInput,
  );
  await recordCodexSecurityWorkerScanDraft(deferredDoesNotRejectContext, {
    ...workerInput,
    complete: false,
    findings: [],
    coverage: {
      ...coverage,
      completeness: "partial",
      surfaces: [],
      deferred: [
        {
          candidateId: finding.provenance.candidateId,
          reason: "A stale worker row still says validation is pending.",
        },
      ],
    },
  });
  const deferredDoesNotReject = await readJson(
    deferredDoesNotRejectRoot,
    "result.json",
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
  const rejectedCheckpoint = await readJson(checkpointRoot, "result.json");
  assert.equal(rejectedCheckpoint.findings.length, 0);
  assert.deepEqual(rejectedCheckpoint.coverage.surfaces[0].finding, finding);

  const rejectionWithoutNotesContext = await createWorkerContext(
    "rejection-without-notes-worker",
  );
  const rejectionWithoutNotesRoot = rejectionWithoutNotesContext.root;
  await recordCodexSecurityWorkerScanDraft(
    rejectionWithoutNotesContext,
    checkpoint,
  );
  const { notes: _notes, ...rejectionWithoutNotes } = rejection;
  await recordCodexSecurityWorkerScanDraft(rejectionWithoutNotesContext, {
    ...workerInput,
    findings: [],
    coverage: { ...coverage, surfaces: [rejectionWithoutNotes] },
  });
  const rejectedWithoutNotes = await readJson(
    rejectionWithoutNotesRoot,
    "result.json",
  );
  assert.equal(rejectedWithoutNotes.findings.length, 0);
  assert.deepEqual(rejectedWithoutNotes.coverage.surfaces[0].finding, finding);

  const carriedContext = await createWorkerContext("carried-context-worker");
  const carriedContextRoot = carriedContext.root;
  await recordCodexSecurityWorkerScanDraft(carriedContext, {
    ...workerInput,
    complete: false,
  });
  await recordCodexSecurityWorkerScanDraft(
    carriedContext,
    withoutScanContext(workerInput),
  );
  const carriedWorker = await readJson(carriedContextRoot, "result.json");
  assert.deepEqual(carriedWorker.scope, workerInput.scope);
  assert.deepEqual(carriedWorker.threatModel, workerInput.threatModel);

  const coverageProgressContext = await createWorkerContext(
    "coverage-progress-worker",
  );
  const coverageProgressRoot = coverageProgressContext.root;
  const pendingQuestion =
    "Does the alternate archive handler enforce containment?";
  await recordCodexSecurityWorkerScanDraft(coverageProgressContext, {
    ...workerInput,
    complete: false,
    coverage: {
      ...coverage,
      completeness: "partial",
      surfaces: [
        {
          id: "surface-archive",
          label: "Archive extraction",
          disposition: "needs_follow_up",
          notes: "Containment review is pending.",
        },
      ],
      openQuestions: [pendingQuestion],
    },
  });
  await recordCodexSecurityWorkerScanDraft(coverageProgressContext, {
    ...workerInput,
    coverage: {
      ...coverage,
      surfaces: [
        {
          id: "surface-archive",
          label: "Archive extraction",
          disposition: "reported",
          notes: "The reachable extraction path lacks containment.",
        },
      ],
    },
  });
  const progressedCoverage = (
    await readJson(coverageProgressRoot, "result.json")
  ).coverage;
  assert.deepEqual(progressedCoverage.surfaces.map(surfaceDisposition), [
    { id: "surface-archive", disposition: "reported" },
  ]);
  assert.deepEqual(progressedCoverage.openQuestions ?? [], []);
  assert.equal(progressedCoverage.completeness, "complete");

  const renamedProgressContext = await createWorkerContext(
    "renamed-coverage-progress-worker",
  );
  const renamedProgressRoot = renamedProgressContext.root;
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
    surfaces: [
      {
        id: "surface-validated-archive",
        label: "Validated archive path traversal",
        disposition: "reported",
        notes: "The archive candidate was validated.",
        receiptRefs: [],
      },
    ],
  };
  await recordCodexSecurityWorkerScanDraft(renamedProgressContext, {
    ...workerInput,
    complete: false,
    findings: [],
    coverage: {
      ...coverage,
      completeness: "partial",
      surfaces: staleSurfaces,
      deferred: [
        {
          candidateId: finding.provenance.candidateId,
          reason: "Archive path traversal validation is pending.",
        },
      ],
    },
  });
  await recordCodexSecurityWorkerScanDraft(renamedProgressContext, {
    ...workerInput,
    complete: false,
    coverage: resolvedCoverage,
  });
  const resolvedProgress = await readJson(renamedProgressRoot, "result.json");
  assert.deepEqual(
    resolvedProgress.coverage.surfaces,
    resolvedCoverage.surfaces,
  );
  assert.equal(resolvedProgress.coverage.completeness, "complete");

  await saveScanDraftCheckpoint(
    renamedProgressContext,
    {
      ...workerInput,
      complete: false,
      coverage: {
        ...resolvedCoverage,
        completeness: "partial",
        surfaces: [...resolvedCoverage.surfaces, ...staleSurfaces],
      },
    },
    false,
  );
  await recordCodexSecurityWorkerScanDraft(renamedProgressContext, {
    ...workerInput,
    complete: true,
    coverage: resolvedCoverage,
  });
  const finalProgress = await readJson(renamedProgressRoot, "result.json");
  assert.deepEqual(finalProgress.coverage.surfaces, resolvedCoverage.surfaces);
  assert.equal(finalProgress.coverage.completeness, "complete");

  const anchorContext = await createWorkerContext(
    "anchor-is-not-candidate-worker",
  );
  const anchorRoot = anchorContext.root;
  const anchor = "shared-finding-and-deferred-label";
  const { candidateId: _provenanceCandidate, ...anchorProvenance } =
    finding.provenance;
  const { candidateId: _extensionCandidate, ...anchorExtensions } =
    finding.extensions;
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
      deferred: [
        { id: anchor, reason: "An unrelated review item remains pending." },
      ],
    },
  });
  const anchorResult = await readJson(anchorRoot, "result.json");
  assert.equal(anchorResult.findings.length, 1);
  assert.deepEqual(anchorResult.findings[0].identity, { anchor });
  assert.equal("finding" in anchorResult.coverage.deferred[0], false);

  const parentCheckpointRoot = path.join(root, "checkpoint-parent");
  await mkdir(parentCheckpointRoot);
  await recordCodexSecurityScanDraft(
    { ...context, root: parentCheckpointRoot },
    { ...input, complete: false },
  );
  const parentSnapshot = await readJson(
    parentCheckpointRoot,
    "checkpoints",
    (await readdir(path.join(parentCheckpointRoot, "checkpoints")))[0],
  );
  assert.equal(parentSnapshot.handoffClaimToken, undefined);
  assert.equal(parentSnapshot.complete, false);
  assert.deepEqual(parentSnapshot.findings, [finding]);
  await recordCodexSecurityScanDraft(
    { ...context, root: parentCheckpointRoot },
    { ...input, findings: [] },
  );
  assert.equal(
    (await readJson(parentCheckpointRoot, "findings.json")).findings.length,
    1,
  );

  const unresolvedRoot = path.join(root, "resolved-deferred-retains-work");
  await mkdir(unresolvedRoot);
  const unresolvedContext = { ...context, root: unresolvedRoot };
  const closeout = {
    id: "review-closeout",
    reason: "Final submission remains.",
  };
  const unresolved = {
    id: "unavailable-library",
    reason: "Dependency implementation is unavailable.",
  };
  const pendingCandidates = [
    {
      candidateId: "candidate-still-pending",
      reason: "Source validation remains.",
    },
    {
      id: "candidate-with-payload",
      reason: "Source validation remains.",
      candidate: { title: "Archive path needs review." },
    },
    {
      id: "finding-with-payload",
      reason: "The previous finding needs review.",
      finding,
    },
  ];
  const pendingCoverage = {
    ...coverage,
    completeness: "partial",
    deferred: [closeout, unresolved, ...pendingCandidates],
  };
  await recordCodexSecurityScanDraft(unresolvedContext, {
    ...input,
    complete: false,
    findings: [],
    coverage: pendingCoverage,
  });
  const closingDraft = {
    ...input,
    complete: true,
    findings: [],
    coverage: {
      ...coverage,
      resolvedDeferred: [
        { id: closeout.id, reason: "Final review decisions are recorded." },
      ],
    },
  };
  await recordCodexSecurityScanDraft(unresolvedContext, closingDraft);
  const retained = await readJson(unresolvedRoot, "coverage.json");
  assert.equal(retained.completeness, "partial");
  assert.deepEqual(
    retained.deferred
      .map(
        (row: { candidateId?: string; id?: string }) =>
          row.candidateId ?? row.id,
      )
      .sort(),
    [
      ...pendingCandidates.map(
        (row: { candidateId?: string; id?: string }) =>
          row.candidateId ?? row.id,
      ),
      unresolved.id,
    ].sort(),
  );
  for (const [draft, message] of [
    [{ ...closingDraft, complete: false }, /only on a terminal draft/],
    [
      {
        ...closingDraft,
        coverage: {
          ...coverage,
          resolvedDeferred: [{ id: "unknown-review", reason: "Done." }],
        },
      },
      /no saved generic deferral/,
    ],
    ...pendingCandidates.map((row: { candidateId?: string; id?: string }) => [
      {
        ...closingDraft,
        coverage: {
          ...coverage,
          resolvedDeferred: [
            { id: row.candidateId ?? row.id, reason: "Done." },
          ],
        },
      },
      /cannot close candidate/,
    ]),
    [
      {
        ...closingDraft,
        coverage: {
          ...pendingCoverage,
          resolvedDeferred: closingDraft.coverage.resolvedDeferred,
        },
      },
      /still active/,
    ],
  ] as const) {
    const before = await readFile(
      path.join(unresolvedRoot, "coverage.json"),
      "utf8",
    );
    const checkpoints = await readdir(path.join(unresolvedRoot, "checkpoints"));
    await assert.rejects(
      recordCodexSecurityScanDraft(unresolvedContext, draft),
      message,
    );
    assert.equal(
      await readFile(path.join(unresolvedRoot, "coverage.json"), "utf8"),
      before,
    );
    assert.deepEqual(
      await readdir(path.join(unresolvedRoot, "checkpoints")),
      checkpoints,
    );
  }
  await rejectsDraft(
    closingDraft,
    /terminal Deep drafts cannot resolve child deferred work/,
    { ...unresolvedContext, mode: "deep" },
  );

  const interruptedParentRoot = path.join(
    root,
    "interrupted-checkpoint-parent",
  );
  await mkdir(interruptedParentRoot);
  const interruptedParentContext = { ...context, root: interruptedParentRoot };
  await saveScanDraftCheckpoint(
    interruptedParentContext,
    {
      ...input,
      complete: false,
      findings: [interruptedFinding],
      coverage: {
        ...coverage,
        completeness: "partial",
        deferred: [
          {
            candidateId: "interrupted-parent-review",
            reason: "Review was checkpointed.",
          },
        ],
      },
    },
    false,
  );
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
      (item: FixtureFinding) =>
        item.candidateId === "interrupted-parent-review",
    ),
    true,
  );

  await recordCodexSecurityScanDraft(
    { ...context, root: parentCheckpointRoot },
    withoutScanContext(input),
  );
  const carriedParentManifest = await readJson(
    parentCheckpointRoot,
    "scan-manifest.json",
  );
  assert.deepEqual(
    carriedParentManifest.scan.scope.summary,
    input.scope.summary,
  );
  assert.deepEqual(carriedParentManifest.scan.threatModel, input.threatModel);

  const deepParentRoot = path.join(root, "accepted-deep-parent");
  await mkdir(deepParentRoot);
  const deepParentContext = {
    ...context,
    root: deepParentRoot,
    mode: "deep",
    scope: "src",
    targetContract: {
      ...context.targetContract,
      scope: {
        requiredIncludePaths: ["src", "lib"],
        requiredExcludePaths: ["vendor"],
      },
    },
  };
  const obsoleteFinding = {
    ...finding,
    identity: { anchor: "obsolete-parent-finding" },
    provenance: {
      ...finding.provenance,
      candidateId: "obsolete-parent-candidate",
    },
    extensions: { candidateId: "obsolete-parent-candidate" },
  };
  const obsoleteDeepDraft = {
    ...input,
    complete: false,
    findings: [obsoleteFinding],
    coverage: {
      ...coverage,
      completeness: "partial",
      surfaces: [
        {
          label: "Old upload handler",
          disposition: "needs_follow_up",
          notes: "An earlier parent draft left this review unfinished.",
        },
      ],
      deferred: [
        { candidateId: "obsolete-review", reason: "Earlier review work." },
      ],
    },
  };
  await recordCodexSecurityScanDraft(deepParentContext, obsoleteDeepDraft);
  await saveScanDraftCheckpoint(deepParentContext, {
    ...obsoleteDeepDraft,
    findings: [interruptedFinding],
  });
  await recordCodexSecurityScanDraft(deepParentContext, {
    ...input,
    complete: false,
    findings: [],
  });
  assert.deepEqual(
    new Set(
      (await readJson(deepParentRoot, "findings.json")).findings.map(
        (item: FixtureFinding) => item.provenance.candidateId,
      ),
    ),
    new Set(["obsolete-parent-candidate", "interrupted-checkpoint"]),
    "an unfinished Deep parent checkpoint still preserves earlier validated findings",
  );
  assert.equal(
    (await readJson(deepParentRoot, "scan-manifest.json")).scan.complete,
    false,
  );
  assert.equal(
    (await readJson(deepParentRoot, "coverage.json")).completeness,
    "partial",
  );
  const savedDeepCheckpoints = await Promise.all(
    (await readdir(path.join(deepParentRoot, "checkpoints"))).map(
      async (name) => [
        name,
        await readFile(path.join(deepParentRoot, "checkpoints", name), "utf8"),
      ],
    ),
  );
  const acceptedDeepDraft = {
    ...input,
    complete: true,
    coverage: workerDraft([]).coverage,
  };
  await recordCodexSecurityScanDraft(deepParentContext, acceptedDeepDraft);
  const acceptedDeepFindings = await readJson(deepParentRoot, "findings.json");
  const acceptedDeepCoverage = await readJson(deepParentRoot, "coverage.json");
  const acceptedDeepManifest = await readJson(
    deepParentRoot,
    "scan-manifest.json",
  );
  assert.equal(acceptedDeepFindings.findings.length, 1);
  assert.deepEqual(
    acceptedDeepFindings.findings[0].provenance,
    finding.provenance,
  );
  assert.equal(acceptedDeepCoverage.completeness, "complete");
  assert.deepEqual(acceptedDeepCoverage.deferred, []);
  assert.deepEqual(
    acceptedDeepCoverage.surfaces,
    [],
    "accepted Deep coverage does not inherit obsolete parent review work",
  );
  assert.deepEqual(acceptedDeepCoverage.explicitExclusions, []);
  assert.deepEqual(acceptedDeepCoverage.includePaths, ["src", "lib"]);
  assert.deepEqual(acceptedDeepCoverage.excludePaths, ["vendor"]);
  assert.deepEqual(acceptedDeepManifest.scan.scope.includePaths, [
    "src",
    "lib",
  ]);
  assert.deepEqual(acceptedDeepManifest.scan.scope.excludePaths, ["vendor"]);
  for (const [name, contents] of savedDeepCheckpoints) {
    assert.equal(
      await readFile(path.join(deepParentRoot, "checkpoints", name), "utf8"),
      contents,
    );
  }

  const obsoleteCheckpointPath = path.join(
    deepParentRoot,
    "checkpoints",
    "obsolete.json",
  );
  await writeFile(obsoleteCheckpointPath, "{malformed obsolete checkpoint\n");
  const deepWorkbenchWrites = mock.fn(async (arguments_: string[]) => {
    assert.deepEqual(arguments_.slice(0, 3), [
      "write-scan-draft",
      "--scan-id",
      scanId,
    ]);
    assert.equal(arguments_.includes("--expected-draft-digest"), false);
    assert.deepEqual(arguments_.slice(-2), ["--claim-token", claimToken]);
    const draftPath = arguments_[arguments_.indexOf("--draft-path") + 1];
    const checkpointPath =
      arguments_[arguments_.indexOf("--checkpoint-path") + 1];
    const staged = await readJson(draftPath);
    const stagedCheckpoint = await readJson(checkpointPath);
    assert.deepEqual(staged.findings, acceptedDeepFindings);
    assert.deepEqual(staged.coverage, acceptedDeepCoverage);
    assert.deepEqual(stagedCheckpoint.findings, acceptedDeepDraft.findings);
    assert.equal(stagedCheckpoint.handoffClaimToken, undefined);
  });
  await recordCodexSecurityScanDraftViaWorkbench(
    deepParentContext,
    acceptedDeepDraft,
    deepWorkbenchWrites,
  );
  assert.equal(
    deepWorkbenchWrites.mock.callCount(),
    1,
    "terminal Deep drafts still publish through the workbench lock despite obsolete malformed checkpoints",
  );
  assert.deepEqual(await readdir(path.join(deepParentRoot, "drafts")), []);

  const pendingContext = await createWorkerContext("pending-worker");
  const pendingRoot = pendingContext.root;
  const candidate = {
    summary: "An unvalidated archive extraction candidate.",
    evidence: "Original nested-worker source trace.",
  };
  const pending = {
    ...workerInput,
    complete: false,
    findings: [],
    coverage: {
      ...coverage,
      completeness: "partial",
      surfaces: [],
      deferred: [
        {
          candidateId: finding.provenance.candidateId,
          reason: "Pending parent validation",
          candidate,
        },
      ],
    },
  };
  await recordCodexSecurityWorkerScanDraft(pendingContext, pending);
  await recordCodexSecurityWorkerScanDraft(pendingContext, workerInput);
  const resolved = await readJson(pendingRoot, "result.json");
  assert.deepEqual(resolved.coverage.deferred, []);
  assert.equal(resolved.coverage.completeness, "complete");
  assert.deepEqual(resolved.findings[0].provenance.originalCandidates, [
    candidate,
  ]);

  await rm(path.join(pendingRoot, "result.json"));
  await recordCodexSecurityWorkerScanDraft(pendingContext, pending);
  await recordCodexSecurityWorkerScanDraft(pendingContext, {
    ...workerInput,
    findings: [],
    coverage: { ...coverage, surfaces: [rejection] },
  });
  const resolvedRejection = await readJson(pendingRoot, "result.json");
  assert.deepEqual(resolvedRejection.coverage.deferred, []);
  assert.deepEqual(resolvedRejection.coverage.surfaces[0].candidate, candidate);

  const undefinedCandidateContext = await createWorkerContext(
    "undefined-candidate-worker",
  );
  const undefinedCandidateRoot = undefinedCandidateContext.root;
  await recordCodexSecurityWorkerScanDraft(undefinedCandidateContext, {
    ...workerInput,
    complete: false,
    findings: [],
    coverage: {
      ...coverage,
      completeness: "partial",
      surfaces: [],
      deferred: [
        { reason: "An unrelated anonymous review item remains pending." },
      ],
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
  const undefinedCandidateResult = await readJson(
    undefinedCandidateRoot,
    "result.json",
  );
  assert.equal(undefinedCandidateResult.coverage.deferred.length, 1);
  assert.equal(
    undefinedCandidateResult.coverage.deferred[0].reason,
    "An unrelated anonymous review item remains pending.",
  );

  for (const [index, previousFindings] of [
    "legacy metadata",
    { opaque: true },
    7,
  ].entries()) {
    const historyContext = await createWorkerContext(`legacy-history-${index}`);
    const historyRoot = historyContext.root;
    const earlierFinding = {
      ...finding,
      summary: "Earlier verified source proof.",
      provenance: { ...finding.provenance, previousFindings },
    };
    await recordCodexSecurityWorkerScanDraft(historyContext, {
      ...workerInput,
      findings: [earlierFinding],
    });
    await recordCodexSecurityWorkerScanDraft(historyContext, workerInput);
    const savedHistory = await readJson(historyRoot, "result.json");
    const original = structuredClone(earlierFinding);
    delete (original.provenance as { previousFindings?: unknown })
      .previousFindings;
    assert.deepEqual(
      savedHistory.findings[0].provenance.previousFindings,
      [original],
      "opaque legacy metadata is not interpreted as finding history, but the original proof survives",
    );
    const snapshots = await Promise.all(
      (await readdir(path.join(historyRoot, "checkpoints"))).map(
        async (name) => await readJson(historyRoot, "checkpoints", name),
      ),
    );
    assert.deepEqual(
      snapshots.find(
        (snapshot) => snapshot.findings[0].summary === earlierFinding.summary,
      ).findings[0].provenance.previousFindings,
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
      coverage: (await readJson(workerResultPath)).coverage,
      operation: "replace",
      status: "draft_written",
    },
  );
  assert.deepEqual(await readJson(workerResultPath), workerInput);
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
  const resetWorkerDraft = async () =>
    Promise.all([
      rm(workerResultPath, { force: true }),
      rm(path.join(workerRoot, "checkpoints"), {
        recursive: true,
        force: true,
      }),
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
      coverage: (await readJson(workerResultPath)).coverage,
      operation: "replace",
      status: "draft_written",
    },
  );
  assert.deepEqual(await readJson(workerResultPath), {
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
      coverage: (await readJson(workerResultPath)).coverage,
      operation: "replace",
      status: "draft_written",
    },
  );
  assert.deepEqual(await readJson(workerResultPath), {
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
      coverage: (await readJson(workerResultPath)).coverage,
      operation: "replace",
      status: "draft_written",
    },
  );
  assert.deepEqual(await readJson(workerResultPath), scopedWorkerInput);
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
      evidence: "Preserve this caller evidence.",
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
      evidence: "A separate caller needs review.",
    },
  ];
  const reasonOnlyInput = coverageInput({
    completeness: "partial",
    deferred: reasonOnlyDeferred,
  });

  const incompleteCodeEvidence = {
    id: "evidence-archive-sink",
    label: "Archive extraction sink",
    path: "src/extract.py",
    startLine: 41,
    code: "",
    explanation: "The reviewed archive entry reaches a filesystem write.",
  };

  const rejectedDraftInputs: [string, unknown][] = [
    [
      "finding rule IDs must describe a lowercase vulnerability family, not a CWE",
      findingInput({ ruleId: "CWE-1321" }),
    ],
    [
      "finding taxonomy must use the candidate's canonical cwe array",
      findingInput({
        taxonomy: { category: "prototype-pollution", cweIds: ["CWE-1321"] },
      }),
    ],
    [
      "finding provenance must identify the actual source",
      findingInput({
        provenance: { candidateId: "candidate-b5b7a3d14a148f6a" },
      }),
    ],
    [
      "provided code evidence must contain the verified source snippet",
      findingInput({ codeEvidence: [incompleteCodeEvidence] }),
    ],
    [
      "legacy code evidence must be an array",
      findingInput({ code_evidence: null }),
    ],
    [
      "legacy root-cause code must be text",
      findingInput({ root_cause: { code: ["not text"] } }),
    ],
    [
      "legacy root-cause language must be text",
      findingInput({ root_cause: { language: 42 } }),
    ],
    [
      "canonical root-cause code must be text",
      findingInput({
        rootCause: { summary: "Root cause.", code: ["not text"] },
      }),
    ],
    [
      "canonical root-cause language must be text",
      findingInput({ rootCause: { summary: "Root cause.", language: 42 } }),
    ],
    [
      "coverage surfaces must use canonical labels and dispositions",
      coverageInput({
        surfaces: [{ surface: "Archive extraction", outcome: "reported" }],
      }),
    ],
    [
      "reason-only deferred coverage rejects a missing reason",
      coverageInput({
        completeness: "partial",
        deferred: [{ paths: ["src/extract.py"] }],
      }),
    ],
    [
      "reason-only deferred coverage rejects a whitespace-only reason",
      coverageInput({
        completeness: "partial",
        deferred: [{ reason: "  \t\n  " }],
      }),
    ],
    [
      "explicit deferred identities do not bypass the required reason",
      coverageInput({
        completeness: "partial",
        deferred: [{ id: "deferred-explicit-archive" }],
      }),
    ],
    [
      "deferred candidate identities must not contain only whitespace",
      coverageInput({
        completeness: "partial",
        deferred: [
          {
            candidateId: "   ",
            reason: "The upload runtime was unavailable.",
          },
        ],
      }),
    ],
    [
      "plain-string open questions must contain meaningful text",
      coverageInput({ openQuestions: ["  \t  "] }),
    ],
    [
      "structured open questions require a question",
      coverageInput({
        openQuestions: [{ followUpPrompt: "Trace the upload boundary." }],
      }),
    ],
    [
      "structured open questions must not contain only whitespace",
      coverageInput({ openQuestions: [{ question: "  \n  " }] }),
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
      coverageInput({ mode: "repository" }),
    ],
    [
      "inventory strategy is derived by the authoritative scan",
      coverageInput({ inventoryStrategy: "repository" }),
    ],
    [
      "coverage included paths are derived from the authoritative scope",
      coverageInput({ includePaths: ["src"] }),
    ],
    [
      "coverage excluded paths are derived from the authoritative scope",
      coverageInput({ excludePaths: ["vendor"] }),
    ],
    [
      "top-level receipt references are not semantic coverage inputs",
      coverageInput({
        receiptRefs: ["artifacts/02_discovery/candidate_ledger.jsonl"],
      }),
    ],
    [
      "finding IDs are generated during finalization",
      findingInput({ findingId: "csf_0123456789abcdef01234567" }),
    ],
    [
      "occurrence IDs are generated during finalization",
      findingInput({ occurrenceId: "cso_0123456789abcdef01234567" }),
    ],
    [
      "finding fingerprints are generated during finalization",
      findingInput({
        fingerprints: {
          algorithm: "codex-security/v1",
          primary:
            "codex-security/v1:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        },
      }),
    ],
  ];

  for (const [description, candidateId] of [
    ["path traversal", ".."],
    ["forward slash", "candidate/nested"],
    ["backslash", "candidate\\nested"],
    ["control character", "candidate\u0001nested"],
    ["oversized identity", "a".repeat(513)],
  ] as const) {
    rejectedDraftInputs.push([
      `deferred candidate identities reject ${description}`,
      coverageInput({
        completeness: "partial",
        deferred: [
          { candidateId, reason: "The candidate identity must remain safe." },
        ],
      }),
    ]);
    rejectedDraftInputs.push([
      `explicit deferred identities do not bypass invalid candidate ${description}`,
      coverageInput({
        completeness: "partial",
        deferred: [
          {
            id: "deferred-explicit-archive",
            candidateId,
            reason:
              "The candidate identity must remain safe even with an explicit identity.",
          },
        ],
      }),
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
    scanDraftInputSchema.safeParse(
      findingInput({ taxonomy: { category: "path-traversal", cwe: [] } }),
    ).success,
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
    scanDraftInputSchema.safeParse(
      findingInput({ severity: { level: "moderate" } }),
    ).success,
    false,
  );
  assert.equal(
    scanDraftInputSchema.safeParse(findingInput({ confidence: "high" }))
      .success,
    false,
  );
  assert.equal(
    scanDraftInputSchema.safeParse(
      coverageInput({
        surfaces: [{ label: "surface", disposition: "unreviewed" }],
      }),
    ).success,
    false,
  );
  assert.equal(
    scanDraftInputSchema.safeParse(
      findingInput({ locations: [{ path: "../outside.py", startLine: 1 }] }),
    ).success,
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
    scanDraftInputSchema.safeParse(
      coverageInput({ inventoryStrategy: "directory" }),
    ).success,
    false,
  );
  assert.equal(
    scanDraftInputSchema.safeParse(coverageInput({ mode: "repository" }))
      .success,
    false,
  );
  assert.equal(
    scanDraftInputSchema.safeParse(coverageInput({ includePaths: ["outside"] }))
      .success,
    false,
  );
  assert.equal(
    scanDraftInputSchema.safeParse(coverageInput({ excludePaths: ["outside"] }))
      .success,
    false,
  );
  assert.equal(
    scanDraftInputSchema.safeParse(
      findingInput({ findingId: "csf_0123456789abcdef01234567" }),
    ).success,
    false,
  );
  assert.equal(
    scanDraftInputSchema.safeParse(
      coverageInput({
        surfaces: [
          {
            label: "surface",
            disposition: "reported",
            receiptRefs: ["artifacts/02_discovery/candidate_ledger.jsonl"],
          },
        ],
      }),
    ).success,
    true,
  );
  assert.equal(
    scanDraftInputSchema.safeParse(
      coverageInput({
        surfaces: [
          {
            label: "surface",
            disposition: "reported",
            receiptRefs: ["artifacts/../../outside.jsonl"],
          },
        ],
      }),
    ).success,
    false,
  );

  let checkpointsVisibleBeforePublication: string[] = [];
  await assert.rejects(
    recordCodexSecurityScanDraftViaWorkbench(
      context,
      input,
      async (arguments_: string[]) => {
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
        const staged = await readJson(arguments_[draftPathIndex + 1]);
        assert.equal(staged.findings.findings.length, 1);
        assert.deepEqual(
          staged.findings.findings[0].taxonomy,
          finding.taxonomy,
        );
        assert.deepEqual(staged.manifest.scan.threatModel, input.threatModel);
        assert.equal(staged.coverage.completeness, "complete");
        throw new Error(
          "The scan stopped before the staged draft was published.",
        );
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
  const abortedConflictAttempts = mock.fn(async () => {
    conflictAbort.abort(new Error("draft publication canceled"));
    throw Object.assign(new Error("scan_draft_conflict"), {
      code: "scan_draft_conflict",
    });
  });
  await assert.rejects(
    recordCodexSecurityScanDraft(
      context,
      input,
      abortedConflictAttempts,
      conflictAbort.signal,
    ),
    /draft publication canceled/,
  );
  assert.equal(abortedConflictAttempts.mock.callCount(), 1);

  const monotonicRoot = path.join(root, "monotonic-final-draft");
  await mkdir(monotonicRoot);
  const monotonicContext = { ...context, root: monotonicRoot };
  const staleCheckpoint = {
    ...input,
    complete: false,
    coverage: {
      ...coverage,
      completeness: "partial",
      surfaces: [
        {
          id: "surface-archive",
          label: "Archive extraction",
          disposition: "needs_follow_up",
          notes: "The stale writer has not finished validation.",
        },
      ],
    },
  };
  const finalDraft = {
    ...input,
    complete: true,
    coverage: {
      ...coverage,
      surfaces: [
        {
          id: "surface-archive",
          label: "Archive extraction",
          disposition: "reported",
          notes: "The final writer completed validation.",
        },
      ],
    },
  };
  let monotonicWrites = 0;
  await recordCodexSecurityScanDraftViaWorkbench(
    monotonicContext,
    staleCheckpoint,
    async (arguments_: string[]) => {
      const draftPath = arguments_[arguments_.indexOf("--draft-path") + 1];
      const staged = await readJson(draftPath);
      monotonicWrites += 1;
      if (monotonicWrites === 1) {
        await recordCodexSecurityScanDraft(monotonicContext, finalDraft);
        throw new Error(
          "scan_draft_conflict: final draft won the canonical write",
        );
      }
      assert.notEqual(staged.manifest.scan.complete, false);
      assert.deepEqual(staged.coverage.surfaces.map(surfaceDisposition), [
        { id: "surface-archive", disposition: "reported" },
      ]);
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
  const checkpointOnlyFinding: typeof finding & {
    identity?: { anchor: string };
  } = structuredClone(finding);
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
  await recordCodexSecurityWorkerScanDraft(archivedRetryContext, {
    ...withoutScanContext(workerInput),
    findings: [],
  });
  const archivedRetryResult = await readJson(
    archivedRetryOutput,
    "result.json",
  );
  assert.deepEqual(
    new Set(
      archivedRetryResult.findings.map(
        (item: FixtureFinding) => item.provenance.candidateId,
      ),
    ),
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
  const archivedResolutionContext = {
    ...workerContext,
    root: archivedResolutionOutput,
  };
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
    ...withoutScanContext(workerInput),
    findings: [],
  });
  const archivedResolutionResult = await readJson(
    archivedResolutionOutput,
    "result.json",
  );
  assert.deepEqual(
    archivedResolutionResult.findings,
    [finding],
    "deferred coverage does not reject a validated finding from an archived attempt",
  );
  assert.deepEqual(archivedResolutionResult.coverage.deferred, []);

  const repeatedCheckpointRoot = path.join(root, "repeated-checkpoint-worker");
  const repeatedCheckpointOutput = path.join(repeatedCheckpointRoot, "output");
  const repeatedCheckpointContext = {
    ...workerContext,
    root: repeatedCheckpointOutput,
  };
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
  repeatedFindingDraft = await readJson(
    repeatedCheckpointOutput,
    "checkpoints",
    findingCheckpointName,
  );
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
  await saveScanDraftCheckpoint(
    repeatedCheckpointContext,
    repeatedFindingDraft,
  );
  await mkdir(path.join(repeatedCheckpointRoot, "attempts"));
  await rename(
    repeatedCheckpointOutput,
    path.join(repeatedCheckpointRoot, "attempts", "attempt-01"),
  );
  await mkdir(repeatedCheckpointOutput);
  await recordCodexSecurityWorkerScanDraft(repeatedCheckpointContext, {
    ...withoutScanContext(workerInput),
    findings: [],
  });
  const repeatedCheckpointResult = await readJson(
    repeatedCheckpointOutput,
    "result.json",
  );
  assert.deepEqual(
    repeatedCheckpointResult.findings.map(
      (item: FixtureFinding) => item.provenance.candidateId,
    ),
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
  await rename(
    multiAttemptOutput,
    path.join(multiAttemptArchive, "attempt-01"),
  );
  await mkdir(multiAttemptOutput);
  await recordCodexSecurityWorkerScanDraft(multiAttemptContext, {
    ...withoutScanContext(workerInput),
    complete: false,
    findings: [],
    coverage: {
      ...coverage,
      completeness: "partial",
      surfaces: [],
      deferred: [demotedCandidate],
    },
  });
  await rename(
    multiAttemptOutput,
    path.join(multiAttemptArchive, "attempt-02"),
  );
  await mkdir(multiAttemptOutput);
  await recordCodexSecurityWorkerScanDraft(multiAttemptContext, {
    ...withoutScanContext(workerInput),
    findings: [],
  });
  const multiAttemptResult = await readJson(multiAttemptOutput, "result.json");
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

  const malformedArchivedRoot = path.join(
    root,
    "malformed-archived-result-worker",
  );
  const malformedArchivedOutput = path.join(malformedArchivedRoot, "output");
  const malformedArchivedContext = {
    ...workerContext,
    root: malformedArchivedOutput,
  };
  await mkdir(malformedArchivedOutput, { recursive: true });
  await recordCodexSecurityWorkerScanDraft(malformedArchivedContext, {
    ...workerInput,
    complete: false,
  });
  await writeFile(
    path.join(malformedArchivedOutput, "result.json"),
    "{malformed",
  );
  await mkdir(path.join(malformedArchivedRoot, "attempts"));
  await rename(
    malformedArchivedOutput,
    path.join(malformedArchivedRoot, "attempts", "attempt-01"),
  );
  await mkdir(malformedArchivedOutput);
  await recordCodexSecurityWorkerScanDraft(malformedArchivedContext, {
    ...withoutScanContext(workerInput),
    findings: [],
  });
  assert.deepEqual(
    (await readJson(malformedArchivedOutput, "result.json")).findings,
    [finding],
    "valid checkpoints must recover evidence when an archived result is malformed",
  );

  const crossScanRetryRoot = path.join(root, "cross-scan-retry-worker");
  const crossScanRetryOutput = path.join(crossScanRetryRoot, "output");
  await mkdir(crossScanRetryOutput, { recursive: true });
  const crossScanRetryContext = {
    ...workerContext,
    root: crossScanRetryOutput,
  };
  await recordCodexSecurityWorkerScanDraft(crossScanRetryContext, {
    ...workerInput,
    complete: false,
  });
  const crossScanAttempts = path.join(crossScanRetryRoot, "attempts");
  const crossScanAttempt = path.join(crossScanAttempts, "attempt-01");
  await mkdir(crossScanAttempts);
  await rename(crossScanRetryOutput, crossScanAttempt);
  const crossScanResultPath = path.join(crossScanAttempt, "result.json");
  const crossScanResult = await readJson(crossScanResultPath);
  crossScanResult.scanId = "11111111-1111-4111-8111-111111111111";
  await writeFile(crossScanResultPath, JSON.stringify(crossScanResult));
  await mkdir(crossScanRetryOutput);
  await assert.rejects(
    recordCodexSecurityWorkerScanDraft(crossScanRetryContext, {
      ...withoutScanContext(workerInput),
      findings: [],
    }),
    /scanId does not match the authoritative workbench scan/u,
    "a retry must reject archived findings from another scan",
  );

  const unreadableRetryRoot = path.join(root, "unreadable-retry-worker");
  const unreadableRetryOutput = path.join(unreadableRetryRoot, "output");
  const unreadableAttempt = path.join(
    unreadableRetryRoot,
    "attempts",
    "attempt-01",
  );
  const unreadableCheckpointRoot = path.join(unreadableAttempt, "checkpoints");
  await mkdir(unreadableCheckpointRoot, { recursive: true });
  await mkdir(unreadableRetryOutput);
  const originalLstat = fsPromises.lstat;
  fsPromises.lstat = (async (
    candidate: Parameters<typeof originalLstat>[0],
    ...arguments_: [options?: import("node:fs").StatOptions]
  ) => {
    if (
      path.resolve(String(candidate)) === path.resolve(unreadableCheckpointRoot)
    ) {
      throw Object.assign(new Error("permission denied by test filesystem"), {
        code: "EACCES",
      });
    }
    return originalLstat(candidate, ...arguments_);
  }) as typeof fsPromises.lstat;
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

  const partialDeferredContext = await createWorkerContext(
    "partial-deferred-worker",
  );
  const partialDeferredRoot = partialDeferredContext.root;
  const partialDeferredFinding = {
    summary: "Partial evidence captured before validation.",
  };
  await recordCodexSecurityWorkerScanDraft(partialDeferredContext, {
    ...workerInput,
    complete: false,
    findings: [],
    coverage: {
      ...coverage,
      completeness: "partial",
      surfaces: [],
      deferred: [
        {
          candidateId: finding.provenance.candidateId,
          reason: "Validation is pending.",
          finding: partialDeferredFinding,
        },
      ],
    },
  });
  await recordCodexSecurityWorkerScanDraft(partialDeferredContext, workerInput);
  const resolvedPartialDeferred = await readJson(
    partialDeferredRoot,
    "result.json",
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
    coverage: await readJson(root, "coverage.json"),
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
  const generatedIds = normalizedReasonOnlyCoverage.deferred.map(
    ({ id }: { id: string }) => id,
  );
  assert.ok(generatedIds.every((id: string) => typeof id === "string"));
  assert.equal(new Set(generatedIds).size, reasonOnlyDeferred.length);
  assert.deepEqual(
    normalizedReasonOnlyCoverage.deferred.map(
      ({ id, ...row }: { id: string; [key: string]: unknown }) => row,
    ),
    reasonOnlyDeferred,
    "assigning IDs preserves every distinct ID-less observation",
  );
  for (const name of await readdir(path.join(root, "checkpoints"))) {
    const checkpoint = await readJson(path.join(root, "checkpoints"), name);
    assert.deepEqual(
      checkpoint.coverage.deferred.map(({ id }: { id: string }) => id),
      generatedIds,
      "the first saved checkpoint already contains the published IDs",
    );
  }
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
  await recordFreshScanDraft(
    context,
    coverageInput({
      completeness: "partial",
      deferred: [collidingWithExplicit, collidingWithCandidate],
    }),
  );
  const [reservedExplicitId, reservedCandidateId] = (
    await readJson(root, "coverage.json")
  ).deferred.map(({ id }: { id: string }) => id);
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
  await recordFreshScanDraft(
    context,
    coverageInput({ completeness: "partial", deferred: reservedDeferred }),
  );
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
  await recordFreshScanDraft(
    context,
    coverageInput({
      surfaces: [
        {
          label: "Archive extraction",
          disposition: "reported",
          receiptRefs: existingReceiptRefs,
        },
      ],
    }),
  );
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
  await rejectsDraft(input, /hardening portfolio.*safe regular file/);
  assert.equal(
    await readFile(path.join(root, "scan-manifest.json"), "utf8"),
    beforeUnsafeHardening,
  );
  await rm(hardeningPortfolio);
  await rm(externalHardeningPortfolio);

  const explicitIdentity = { anchor: "preserve-the-existing-finding-identity" };
  await recordFreshScanDraft(
    context,
    findingInput({ identity: explicitIdentity }),
  );
  assert.deepEqual(
    (await readJson(root, "findings.json")).findings[0].identity,
    explicitIdentity,
  );

  const identityContext = await createWorkerContext(
    "preserved-finding-identity-worker",
  );
  const identityRoot = identityContext.root;
  await recordCodexSecurityWorkerScanDraft(identityContext, {
    ...workerInput,
    findings: [{ ...finding, identity: explicitIdentity }],
  });
  await recordCodexSecurityWorkerScanDraft(identityContext, workerInput);
  assert.deepEqual(
    (await readJson(identityRoot, "result.json")).findings[0].identity,
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
      (item: FixtureFinding) => item.identity!.anchor,
    ),
    ["candidate-a", "candidate-b"],
  );

  await recordFreshScanDraft(
    context,
    findingInput({
      extensions: {
        ...finding.extensions,
        candidateId: "candidate-singleton",
        reportId: "DSS-144-A",
      },
    }),
  );
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
      (item: FixtureFinding) => item.identity,
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
      (item: FixtureFinding) => item.identity,
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
      (item: FixtureFinding) => item.identity,
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
      (item: FixtureFinding) => item.identity,
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

  const collisionFindings = [
    "src/upload.py",
    "src/import.py",
    "src/restore.py",
  ].map((location) => ({
    ...finding,
    locations: [{ path: location, startLine: 41, endLine: 44 }],
    provenance: { source: "local_plugin" },
    extensions: {},
  }));
  const authoredCollisionIdentity = { anchor: "shared-archive-review" };
  const reservedCollisionIdentity = {
    ...authoredCollisionIdentity,
    instance: "parser",
  };
  const collisionCases = [
    {
      label: "authored",
      findings: collisionFindings.map((item: FixtureFinding) => ({
        ...item,
        identity: authoredCollisionIdentity,
      })),
      originalIdentity: authoredCollisionIdentity,
    },
    {
      label: "generated",
      findings: collisionFindings,
      originalIdentity: {
        anchor: "unsafe-archive-extraction",
        instance: "unsafe-archive-extraction",
      },
    },
    {
      label: "authored with reserved suffixes",
      findings: [
        ...collisionFindings.map((item: FixtureFinding) => ({
          ...item,
          identity: reservedCollisionIdentity,
        })),
        ...collisionFindings.slice(0, 2).map((item: FixtureFinding, index) => ({
          ...item,
          identity: {
            ...reservedCollisionIdentity,
            instance: `parser-${index + 2}`,
          },
        })),
      ],
      originalIdentity: reservedCollisionIdentity,
      expectedIdentities: [
        reservedCollisionIdentity,
        { ...reservedCollisionIdentity, instance: "parser-4" },
        { ...reservedCollisionIdentity, instance: "parser-5" },
        { ...reservedCollisionIdentity, instance: "parser-2" },
        { ...reservedCollisionIdentity, instance: "parser-3" },
      ],
    },
  ];
  for (const collisionCase of collisionCases) {
    const collisionInput = { ...input, findings: collisionCase.findings };
    await recordFreshScanDraft(context, collisionInput);
    const standardFindings = (await readJson(root, "findings.json")).findings;
    assert.deepEqual(
      standardFindings.map((item: FixtureFinding) => item.identity),
      collisionCase.findings.map(
        (item: FixtureFinding) =>
          item.identity ?? collisionCase.originalIdentity,
      ),
      `${collisionCase.label} identity collisions retain the existing Standard shape`,
    );
    assert.deepEqual(
      standardFindings.map((item: FixtureFinding) => item.provenance),
      collisionCase.findings.map((item: FixtureFinding) => item.provenance),
    );

    const deepIdentityContext = { ...context, mode: "deep" };
    await recordFreshScanDraft(deepIdentityContext, collisionInput);
    const deepFindings = (await readJson(root, "findings.json")).findings;
    const deepIdentities = deepFindings.map(
      (item: FixtureFinding) => item.identity,
    );
    assert.equal(
      deepFindings.length,
      collisionCase.findings.length,
      `${collisionCase.label} identity collisions must retain every Deep finding`,
    );
    assert.deepEqual(
      deepIdentities,
      collisionCase.expectedIdentities ??
        collisionCase.findings.map((_, index) =>
          index === 0
            ? collisionCase.originalIdentity
            : {
                ...collisionCase.originalIdentity,
                instance: `${(collisionCase.originalIdentity as { instance?: string }).instance ?? "saved"}-${index + 1}`,
              },
        ),
      `${collisionCase.label} collisions receive successive numeric suffixes without replacing authored identities`,
    );
    assert.deepEqual(
      deepFindings.map((item: FixtureFinding) => item.provenance),
      collisionCase.findings.map((item: FixtureFinding, index) =>
        index === 1 || index === 2
          ? {
              ...item.provenance,
              preservedIdentity: collisionCase.originalIdentity,
            }
          : item.provenance,
      ),
    );
    assert.deepEqual(
      deepFindings.map((item: FixtureFinding) => item.locations),
      collisionCase.findings.map((item: FixtureFinding) => item.locations),
    );

    await recordCodexSecurityScanDraft(deepIdentityContext, collisionInput);
    assert.deepEqual(
      (await readJson(root, "findings.json")).findings.map(
        (item: FixtureFinding) => item.identity,
      ),
      deepIdentities,
      `${collisionCase.label} Deep finding identities remain stable when the accepted aggregate is republished`,
    );
  }

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
  assert.deepEqual(legacyEvidencedOutput.code_evidence, [completeCodeEvidence]);
  assert.deepEqual(
    legacyEvidencedOutput.attackPath,
    legacyEvidencedFinding.attackPath,
  );

  await recordFreshScanDraft(
    context,
    findingInput({ taxonomy: { category: "path-traversal", cwe: [] } }),
  );
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
        ...(context.targetContract!.target as Record<string, unknown>),
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

  await recordFreshScanDraft({ ...directoryContext, mode: "deep" }, input);
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
    const expectedDigest = hash(
      "sha256",
      `codex-security-diff/v1\0${kind}\0base123\0head456`,
    );
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

  const originalDraft = await snapshotScanDraft(root);
  assert.ok(originalDraft.every((artifact) => artifact !== null));

  for (const [description, rejectedInput] of rejectedDraftInputs) {
    await assert.rejects(
      recordCodexSecurityScanDraft(context, rejectedInput),
      Error,
      description,
    );
    const currentDraft = await snapshotScanDraft(root);
    for (const [index, artifact] of [
      "scan manifest",
      "findings",
      "coverage",
    ].entries()) {
      assert.equal(
        currentDraft[index],
        originalDraft[index],
        `${description}: ${artifact} must not be modified`,
      );
    }
  }

  await rejectsDraft(
    findingInput({ severity: { level: "high", score: 8.1 } }),
    /severity\.scoringSystem/,
  );
  await rejectsDraft(
    findingInput({
      locations: [{ path: "src/extract.py", startLine: 8, endLine: 2 }],
    }),
    /endLine.*precede startLine/,
  );
  await rejectsDraft(
    findingInput({
      code_evidence: [completeCodeEvidence, completeCodeEvidence],
    }),
    /code_evidence\[1\]\.id duplicates/,
  );
  await rejectsDraft(
    findingInput({
      codeEvidence: [completeCodeEvidence],
      code_evidence: [completeCodeEvidence],
    }),
    /code_evidence\[0\]\.id duplicates/,
  );
  await rejectsDraft(
    coverageInput({
      deferred: [{ id: "deferred-upload", reason: "Runtime unavailable." }],
    }),
    /complete coverage cannot contain deferred/,
  );
  await rejectsDraft(
    coverageInput({
      deferred: [
        {
          candidateId: "candidate-deferred-archive",
          reason: "The upload runtime was unavailable.",
        },
      ],
    }),
    /complete coverage cannot contain deferred/,
  );
  await rejectsDraft(
    coverageInput({
      deferred: [{ reason: "The upload runtime was unavailable." }],
    }),
    /complete coverage cannot contain deferred/,
  );
  assert.deepEqual(await snapshotScanDraft(root), originalDraft);
  await rejectsDraft(
    coverageInput({
      surfaces: [{ label: "Uploads", disposition: "needs_follow_up" }],
    }),
    /complete coverage cannot contain needs_follow_up/,
  );
  await rejectsDraft(
    findingInput({ validation: { evidenceRefs: ["missing-evidence"] } }),
    /evidenceRefs must refer/,
  );
  await rejectsDraft(
    findingInput({
      root_cause: { evidenceRefs: ["missing-root-cause-evidence"] },
    }),
    /root_cause\.evidenceRefs must refer/,
  );
  await rejectsDraft(
    findingInput({ root_cause: { summary: ["not a string"] } }),
    /root_cause/,
  );
  await rejectsDraft(
    findingInput({
      attackPath: {
        dataflow: { evidenceRefs: ["missing-dataflow-evidence"] },
      },
    }),
    /attackPath\.dataflow\.evidenceRefs must refer/,
  );
  await rejectsDraft(
    findingInput({
      validation: { evidence_refs: ["missing-validation-evidence"] },
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
  await rejectsDraft(input, /scanId does not match/, {
    ...context,
    scanId: "d7caa0cf-b785-47ef-95e7-e753dc288608",
  });
  await rejectsDraft(input, /no allowed target kind/, {
    ...context,
    targetContract: {
      ...context.targetContract,
      target: {
        ...(context.targetContract!.target as Record<string, unknown>),
        allowedKinds: [],
      },
    },
  });

  assert.deepEqual(await snapshotScanDraft(root), originalDraft);

  const duplicateSurfaceCoverage = {
    ...coverage,
    completeness: "partial",
    surfaces: [
      {
        id: "surface-web-ui",
        label: "Web UI",
        disposition: "reported",
        receiptRefs: ["artifacts/primary.json"],
      },
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
  const originalDuplicateSurfaceCoverage = structuredClone(
    duplicateSurfaceCoverage,
  );
  await recordFreshScanDraft(context, {
    ...input,
    coverage: duplicateSurfaceCoverage,
  });
  const normalizedDuplicateCoverage = await readJson(root, "coverage.json");
  const surfaceIds = normalizedDuplicateCoverage.surfaces.map(
    ({ id }: { id: string }) => id,
  );
  assert.equal(
    new Set(surfaceIds).size,
    duplicateSurfaceCoverage.surfaces.length,
  );
  assert.deepEqual(surfaceIds.slice(0, 3), [
    "surface-web-ui",
    "surface-web-ui-3",
    "surface-web-ui-2",
  ]);
  assert.equal(surfaceIds[4], "surface_uploads");
  assert.ok(
    surfaceIds.every((id: string) => /^[a-z0-9][a-z0-9._/-]*$/u.test(id)),
  );
  assert.deepEqual(
    normalizedDuplicateCoverage.deferred,
    duplicateSurfaceCoverage.deferred,
  );
  assert.deepEqual(
    normalizedDuplicateCoverage.surfaces.map(
      (surface: { disposition: string; label: string }) => surface.label,
    ),
    duplicateSurfaceCoverage.surfaces.map(
      (surface: { disposition: string; label: string }) => surface.label,
    ),
  );
  assert.deepEqual(normalizedDuplicateCoverage.surfaces[0].receiptRefs, [
    "artifacts/primary.json",
  ]);
  assert.deepEqual(normalizedDuplicateCoverage.surfaces[1].receiptRefs, []);
  assert.deepEqual(duplicateSurfaceCoverage, originalDuplicateSurfaceCoverage);

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
    coverage: await readJson(root, "coverage.json"),
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
    coverage: workerDraft([]).coverage,
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
  await writeJsonLine(path.join(root, "scan-manifest.json"), sealedManifest);
  await writeJsonLine(path.join(root, "findings.json"), sealedFindings);
  await writeJsonLine(path.join(root, "coverage.json"), sealedCoverage);

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

  await writeJsonLine(path.join(root, "findings.json"), {
    scanId: "d7caa0cf-b785-47ef-95e7-e753dc288608",
    findings: [],
  });
  await assert.rejects(
    getCodexSecurityCompletedScan(completeContext, {
      scanId,
      handoffClaimToken: claimToken,
    }),
    /do not match the sealed workbench scan/,
  );

  await writeJsonLine(path.join(root, "findings.json"), sealedFindings);
  await writeFile(path.join(root, "coverage.json"), "{not valid JSON\n");
  await assert.rejects(
    getCodexSecurityCompletedScan(completeContext, {
      scanId,
      handoffClaimToken: claimToken,
    }),
    /malformed|invalid JSON/,
  );

  await writeJsonLine(path.join(root, "coverage.json"), sealedCoverage);
  const external = path.join(root, "external.json");
  await writeJsonLine(external, sealedFindings);
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

// Projection cases below use the same fixture root but model independent scans.
async function recordFreshScanDraft(
  context: ArtifactContext,
  input: ScanDraftInput,
) {
  await Promise.all([
    ...[
      "scan-manifest.json",
      "findings.json",
      "coverage.json",
      "checkpoint-head.json",
    ].map((name) => rm(path.join(context.root, name), { force: true })),
    rm(path.join(context.root, "checkpoints"), {
      recursive: true,
      force: true,
    }),
  ]);
  return recordCodexSecurityScanDraft(context, input);
}

function withoutScanContext<
  Input extends { scope?: unknown; threatModel?: unknown },
>({ scope: _scope, threatModel: _threatModel, ...input }: Input) {
  return input;
}
