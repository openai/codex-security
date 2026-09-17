import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  realpath,
  rm,
  symlink,
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

  const interruptedFinding = structuredClone(finding);
  interruptedFinding.identity = { anchor: "interrupted-checkpoint" };
  interruptedFinding.provenance.candidateId = "interrupted-checkpoint";
  interruptedFinding.extensions.candidateId = "interrupted-checkpoint";

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
  });
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
    provenance: { ...finding.provenance, candidateId: "obsolete-parent-candidate" },
    extensions: { candidateId: "obsolete-parent-candidate" },
  };
  const obsoleteDeepDraft = {
    ...input,
    complete: false,
    findings: [obsoleteFinding],
    coverage: {
      ...coverage,
      completeness: "partial",
      surfaces: [{
        label: "Old upload handler",
        disposition: "needs_follow_up",
        notes: "An earlier parent draft left this review unfinished.",
      }],
      deferred: [{ candidateId: "obsolete-review", reason: "Earlier review work." }],
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
    new Set((await readJson(deepParentRoot, "findings.json")).findings.map(
      (item) => item.provenance.candidateId,
    )),
    new Set(["obsolete-parent-candidate", "interrupted-checkpoint"]),
    "an unfinished Deep parent checkpoint still preserves earlier validated findings",
  );
  assert.equal((await readJson(deepParentRoot, "scan-manifest.json")).scan.complete, false);
  assert.equal((await readJson(deepParentRoot, "coverage.json")).completeness, "partial");
  const savedDeepCheckpoints = await Promise.all(
    (await readdir(path.join(deepParentRoot, "checkpoints"))).map(async (name) => [
      name,
      await readFile(path.join(deepParentRoot, "checkpoints", name), "utf8"),
    ]),
  );
  const acceptedDeepDraft = {
    ...input,
    complete: true,
    coverage: { completeness: "complete", surfaces: [], explicitExclusions: [], deferred: [] },
  };
  await recordCodexSecurityScanDraft(deepParentContext, acceptedDeepDraft);
  const acceptedDeepFindings = await readJson(deepParentRoot, "findings.json");
  const acceptedDeepCoverage = await readJson(deepParentRoot, "coverage.json");
  const acceptedDeepManifest = await readJson(deepParentRoot, "scan-manifest.json");
  assert.equal(acceptedDeepFindings.findings.length, 1);
  assert.deepEqual(acceptedDeepFindings.findings[0].provenance, finding.provenance);
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
  assert.deepEqual(acceptedDeepManifest.scan.scope.includePaths, ["src", "lib"]);
  assert.deepEqual(acceptedDeepManifest.scan.scope.excludePaths, ["vendor"]);
  for (const [name, contents] of savedDeepCheckpoints) {
    assert.equal(await readFile(path.join(deepParentRoot, "checkpoints", name), "utf8"), contents);
  }

  const obsoleteCheckpointPath = path.join(deepParentRoot, "checkpoints", "obsolete.json");
  await writeFile(obsoleteCheckpointPath, "{malformed obsolete checkpoint\n");
  let deepWorkbenchWrites = 0;
  await recordCodexSecurityScanDraftViaWorkbench(
    deepParentContext,
    acceptedDeepDraft,
    async (arguments_) => {
      deepWorkbenchWrites += 1;
      assert.deepEqual(arguments_.slice(0, 3), ["write-scan-draft", "--scan-id", scanId]);
      assert.equal(arguments_.includes("--expected-draft-digest"), false);
      assert.deepEqual(arguments_.slice(-2), ["--claim-token", claimToken]);
      const draftPath = arguments_[arguments_.indexOf("--draft-path") + 1];
      const checkpointPath = arguments_[arguments_.indexOf("--checkpoint-path") + 1];
      const staged = JSON.parse(await readFile(draftPath, "utf8"));
      const stagedCheckpoint = JSON.parse(await readFile(checkpointPath, "utf8"));
      assert.deepEqual(staged.findings, acceptedDeepFindings);
      assert.deepEqual(staged.coverage, acceptedDeepCoverage);
      assert.deepEqual(stagedCheckpoint.findings, acceptedDeepDraft.findings);
      assert.equal(stagedCheckpoint.handoffClaimToken, undefined);
    },
  );
  assert.equal(deepWorkbenchWrites, 1, "terminal Deep drafts still publish through the workbench lock despite obsolete malformed checkpoints");
  assert.deepEqual(await readdir(path.join(deepParentRoot, "drafts")), []);

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

  const collisionFindings = ["src/upload.py", "src/import.py", "src/restore.py"].map((location) => ({
    ...finding,
    locations: [{ path: location, startLine: 41, endLine: 44 }],
    provenance: { source: "local_plugin" },
    extensions: {},
  }));
  const authoredCollisionIdentity = { anchor: "shared-archive-review" };
  const reservedCollisionIdentity = { ...authoredCollisionIdentity, instance: "parser" };
  const collisionCases = [
    {
      label: "authored",
      findings: collisionFindings.map((item) => ({ ...item, identity: authoredCollisionIdentity })),
      originalIdentity: authoredCollisionIdentity,
    },
    {
      label: "generated",
      findings: collisionFindings,
      originalIdentity: { anchor: "unsafe-archive-extraction", instance: "unsafe-archive-extraction" },
    },
    {
      label: "authored with reserved suffixes",
      findings: [
        ...collisionFindings.map((item) => ({ ...item, identity: reservedCollisionIdentity })),
        ...collisionFindings.slice(0, 2).map((item, index) => ({
          ...item,
          identity: { ...reservedCollisionIdentity, instance: `parser-${index + 2}` },
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
      standardFindings.map((item) => item.identity),
      collisionCase.findings.map((item) => item.identity ?? collisionCase.originalIdentity),
      `${collisionCase.label} identity collisions retain the existing Standard shape`,
    );
    assert.deepEqual(
      standardFindings.map((item) => item.provenance),
      collisionCase.findings.map((item) => item.provenance),
    );

    const deepIdentityContext = { ...context, mode: "deep" };
    await recordFreshScanDraft(deepIdentityContext, collisionInput);
    const deepFindings = (await readJson(root, "findings.json")).findings;
    const deepIdentities = deepFindings.map((item) => item.identity);
    assert.equal(deepFindings.length, collisionCase.findings.length, `${collisionCase.label} identity collisions must retain every Deep finding`);
    assert.deepEqual(
      deepIdentities,
      collisionCase.expectedIdentities ?? collisionCase.findings.map((_, index) => (
        index === 0 ? collisionCase.originalIdentity : {
          ...collisionCase.originalIdentity,
          instance: `${collisionCase.originalIdentity.instance ?? "saved"}-${index + 1}`,
        }
      )),
      `${collisionCase.label} collisions receive successive numeric suffixes without replacing authored identities`,
    );
    assert.deepEqual(
      deepFindings.map((item) => item.provenance),
      collisionCase.findings.map((item, index) => (
        index === 1 || index === 2 ? {
          ...item.provenance, preservedIdentity: collisionCase.originalIdentity,
        } : item.provenance
      )),
    );
    assert.deepEqual(
      deepFindings.map((item) => item.locations),
      collisionCase.findings.map((item) => item.locations),
    );

    await recordCodexSecurityScanDraft(deepIdentityContext, collisionInput);
    assert.deepEqual(
      (await readJson(root, "findings.json")).findings.map((item) => item.identity),
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
