import { readJson, writeJsonLine as writeResult } from "./support/json.ts";
import { finding, scanId, workerDraft as draft } from "./scan-draft-fixture.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import assert from "node:assert/strict";
import {
  mkdir,
  readFile,
  readdir,
  utimes,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { importSource } from "./import-module.ts";
import type { ScanDraftInput } from "../src/artifact-scan-draft.ts";
import type { DeepReductionInput } from "../src/deep-scan/artifact-validation.ts";
import type { JsonObject } from "../src/types.ts";

const {
  validateDiscoveryArtifacts,
  validateReducerArtifacts,
  aggregateSourceCoverage,
  deepReductionForPersistence,
  projectDiscoveryCoverage,
} = await importSource(
  path.join(import.meta.dirname, "../src/deep-scan/artifact-validation.ts"),
);

const {
  recordCodexSecurityWorkerScanDraft,
  parseScanDraft,
  saveScanDraftCheckpoint,
} = await importSource(
  path.join(import.meta.dirname, "../src/artifact-scan-draft.ts"),
);

const otherScanId = "12c17317-9594-49e0-b06a-d72fd7e14bba";
const root = await temporaryDirectory("deep-scan-artifact-validation-", true);
try {
  await testDiscoveryValidation(root);
  await testDiscoveryReceipts(root);
  for (const includeValidCheckpoint of [false, true])
    await testArchivedReceiptPathValidation(root, includeValidCheckpoint);
  await testCoveragePublicationParity(root);
  await testWorkerPublicationBeforeCheckpoint(root);
  await testLegacyDeferredPublication(root);
  testResolvedDeferredPublication();
  await testMissingReceiptRepair(root);
  for (const reverse of [false, true])
    await testMissingReceiptRepair(root, { shared: true, reverse });
  for (const complete of [false, true])
    await testMissingReceiptRepair(root, { archived: false, complete });
  for (const complete of [false, true])
    for (const reverse of [false, true])
      await testMissingReceiptRepair(root, {
        archived: false,
        shared: true,
        complete,
        reverse,
      });
  await testSharedMissingReceiptRepairHistory(root);
  for (const resolution of [
    "generic",
    "candidate",
    "linked-candidate",
  ] as const)
    await testCurrentReceiptSelectionBeforeArchivedHistory(root, resolution);
  for (const candidate of [false, true])
    for (const reverse of [false, true])
      await testCurrentAnonymousReceiptSelection(root, candidate, reverse);
  await testReducerValidation(root);
  await testReducerLineageConvergence(root);
  await testEmptyDiscoveryAndReduction(root);
} finally {
  await rm(root, { recursive: true, force: true });
}

console.log("deep scan artifact validation tests passed");

function testResolvedDeferredPublication() {
  const source = {
    surfaces: [],
    explicitExclusions: [],
    deferred: [{ id: "pending", reason: "A separate task remains." }],
    resolvedDeferred: [{ id: "1", reason: "The original review finished." }],
  };
  let previous: DeepReductionInput | null = null;
  for (const worker of [
    { id: "first", attempt: 1 },
    { id: "second", attempt: 1 },
    { id: "first", attempt: 2 },
  ]) {
    const coverage = projectDiscoveryCoverage(source, worker, "worker/output");
    const result = { scanId, findings: [] };
    previous = {
      ...result,
      sourceCoverage: aggregateSourceCoverage(
        [{ workerId: worker.id, coverage, result }],
        previous,
      ),
    };
  }
  const parsed: ScanDraftInput = parseScanDraft({
    ...draft([]),
    reviewState: previous!.sourceCoverage,
  });
  const closures = parsed.reviewState.resolvedDeferred ?? [];
  assert.equal(new Set(closures.map((row) => row.id)).size, 3);
  assert.deepEqual(
    closures.map((row) => row.reason),
    Array(3).fill("The original review finished."),
  );
  assert.equal(parsed.reviewState.deferred.length, 3);
  assert.deepEqual(source.resolvedDeferred, [
    { id: "1", reason: "The original review finished." },
  ]);
}

async function testDiscoveryReceipts(root: string) {
  const result = draft([], {
    reviewState: {
      surfaces: [
        {
          id: "api",
          label: "API",
          disposition: "no_issue_found",
          receiptRefs: ["artifacts/review.md"],
        },
      ],
      explicitExclusions: [],
      deferred: [],
    },
  });
  const worker = await createWorker(
    path.join(root, "receipts"),
    "worker-001",
    result,
  );
  const output = path.dirname(worker.resultPath);
  const context = {
    root: output,
    repoRoot: root,
    layout: "worker" as const,
    scanId,
  };
  await assert.rejects(
    validateDiscoveryArtifacts(worker.artifacts, worker.resultPath, scanId),
    /coverage receipt.*unavailable/,
    "missing evidence must fail admission before parent publication",
  );
  await mkdir(path.join(output, "artifacts"));
  const receipt = path.join(output, "artifacts/review.md");
  await writeFile(receipt, "Original attempt review evidence.\n");
  await validateDiscoveryArtifacts(worker.artifacts, worker.resultPath, scanId);
  await rm(receipt);
  await symlink(worker.resultPath, receipt);
  await assert.rejects(
    validateDiscoveryArtifacts(worker.artifacts, worker.resultPath, scanId),
    /safe regular file/,
  );
  await rm(receipt);
  await writeFile(receipt, "Original attempt review evidence.\n");
  await recordCodexSecurityWorkerScanDraft(context, {
    ...result,
    complete: false,
  });
  const archived = path.join(path.dirname(output), "attempts", "attempt-01");
  await mkdir(path.dirname(archived));
  await rename(output, archived);
  await mkdir(output);
  await recordCodexSecurityWorkerScanDraft(context, {
    ...draft([]),
    complete: true,
  });
  const accepted = await validateDiscoveryArtifacts(
    worker.artifacts,
    worker.resultPath,
    scanId,
  );
  const [retained] = accepted.reviewState.surfaces;
  assert.equal(retained.id, "api");
  assert.deepEqual(retained.receiptRefs, [
    workerReceiptRef(
      output,
      "artifacts/archived-receipts/attempt-01/artifacts/review.md",
    ),
  ]);
  assert.equal(
    await readFile(receiptPath(output, retained.receiptRefs[0]), "utf8"),
    "Original attempt review evidence.\n",
  );
  assert.equal(
    await readFile(path.join(archived, "artifacts/review.md"), "utf8"),
    "Original attempt review evidence.\n",
  );
  await rename(output, path.join(path.dirname(archived), "attempt-02"));
  await mkdir(output);
  await recordCodexSecurityWorkerScanDraft(context, {
    ...draft([]),
    complete: true,
  });
  const retried = await validateDiscoveryArtifacts(
    worker.artifacts,
    worker.resultPath,
    scanId,
  );
  assert.equal(retried.reviewState.surfaces.length, 1);
  for (const ref of retried.reviewState.surfaces[0].receiptRefs) {
    assert.equal(
      await readFile(receiptPath(output, ref), "utf8"),
      "Original attempt review evidence.\n",
    );
  }
}

async function testLegacyDeferredPublication(root: string) {
  const tasks = [
    { id: "review", reason: "Review authentication." },
    { id: "review", reason: "Review authorization." },
    { id: "review-2", reason: "Review routing." },
  ];
  const result = draft([], {
    reviewState: {
      surfaces: [],
      explicitExclusions: [],
      deferred: tasks,
    },
  });
  const worker = await createWorker(
    path.join(root, "legacy-tasks"),
    "first",
    result,
  );
  const accepted = await validateDiscoveryArtifacts(
    worker.artifacts,
    worker.resultPath,
    scanId,
  );
  const coverage = projectDiscoveryCoverage(
    accepted.reviewState,
    { id: worker.id, attempt: 1 },
    "artifacts/deep_discovery/workers/discovery-0001/output",
  );
  const parent = parseScanDraft({ ...result, reviewState: coverage });
  assert.deepEqual(
    parent.reviewState.deferred.map((row: { id: string }) => row.id),
    [
      "first-attempt-1-deferred-1",
      "first-attempt-1-deferred-2",
      "first-attempt-1-deferred-3",
    ],
  );
  assert.deepEqual(
    parent.reviewState.deferred.map((row: { reason: string }) => row.reason),
    tasks.map((row) => row.reason),
  );
}

async function testArchivedReceiptPathValidation(
  root: string,
  includeValidCheckpoint: boolean,
) {
  const surface = {
    id: "api",
    label: "API",
    disposition: "no_issue_found",
    receiptRefs: ["/artifacts/review.md"],
  };
  const result = draft([], {
    reviewState: {
      surfaces: [surface],
      explicitExclusions: [],
      deferred: [],
    },
  });
  const worker = await createWorker(
    path.join(root, `archived-absolute-${includeValidCheckpoint}`),
    "first",
    result,
  );
  const output = path.dirname(worker.resultPath);
  await mkdir(path.join(output, "artifacts"));
  await writeFile(
    path.join(output, "artifacts/review.md"),
    "Original review.\n",
  );
  const archive = path.join(path.dirname(output), "attempts/attempt-01");
  await mkdir(path.dirname(archive));
  await rename(output, archive);
  const archivedBytes = await readFile(path.join(archive, "result.json"));
  await mkdir(path.join(output, "artifacts"), { recursive: true });
  const context = {
    root: output,
    repoRoot: root,
    layout: "worker" as const,
    scanId,
  };
  if (includeValidCheckpoint)
    await saveScanDraftCheckpoint(
      { ...context, root: archive },
      {
        ...result,
        complete: false,
        reviewState: {
          ...result.reviewState,
          surfaces: [
            {
              ...surface,
              receiptRefs: ["artifacts/review.md"],
            },
          ],
        },
      },
      false,
    );
  await recordCodexSecurityWorkerScanDraft(
    context,
    draft([], { complete: true }),
  );
  const accepted = await validateDiscoveryArtifacts(
    worker.artifacts,
    worker.resultPath,
    scanId,
  );
  assert.equal(
    accepted.reviewState.surfaces.length,
    includeValidCheckpoint ? 1 : 0,
  );
  if (includeValidCheckpoint) {
    const refs = accepted.reviewState.surfaces[0].receiptRefs;
    assert.deepEqual(refs, [
      workerReceiptRef(
        output,
        "artifacts/archived-receipts/attempt-01/artifacts/review.md",
      ),
    ]);
    assert.equal(
      await readFile(receiptPath(output, refs[0]), "utf8"),
      "Original review.\n",
    );
  } else {
    assert.deepEqual(await readdir(path.join(output, "artifacts")), []);
  }
  assert.deepEqual(
    await readFile(path.join(archive, "result.json")),
    archivedBytes,
  );
}

async function testMissingReceiptRepair(
  root: string,
  {
    shared = false,
    reverse = false,
    archived = true,
    complete = true,
  }: {
    shared?: boolean;
    reverse?: boolean;
    archived?: boolean;
    complete?: boolean;
  } = {},
) {
  const missing = shared ? "artifacts/review.md" : "artifacts/missing.md";
  const existing = shared ? "artifacts/Review.md" : "artifacts/existing.md";
  const surfaces: JsonObject[] = [
    {
      id: "api",
      label: "API",
      disposition: "needs_follow_up",
      receiptRefs: reverse ? [existing, missing] : [missing, existing],
    },
    ...(shared
      ? [
          {
            id: "candidate",
            candidateId: "candidate",
            label: "Candidate",
            disposition: "needs_follow_up",
            receiptRefs: [missing],
          },
        ]
      : []),
  ];
  if (reverse) surfaces.reverse();
  const result = draft([], {
    complete,
    reviewState: {
      explicitExclusions: [],
      surfaces,
      deferred: [
        { id: "review", reason: "Review pending.", surfaceIds: ["api"] },
        ...(shared
          ? [
              {
                id: "candidate",
                candidateId: "candidate",
                reason: "Validate candidate.",
              },
            ]
          : []),
      ],
    },
  });
  const worker = await createWorker(
    path.join(root, `repair-${shared}-${reverse}-${archived}-${complete}`),
    "first",
    result,
  );
  const output = path.dirname(worker.resultPath);
  const context = {
    root: output,
    repoRoot: root,
    layout: "worker" as const,
    scanId,
  };
  await mkdir(path.join(output, "artifacts"));
  await writeFile(path.join(output, existing), "Original valid evidence.\n");
  if (
    shared &&
    (await readFile(path.join(output, missing)).then(
      () => true,
      (error: NodeJS.ErrnoException) => {
        if (error.code === "ENOENT") return false;
        throw error;
      },
    ))
  )
    return; // A missing case variant requires a case-sensitive filesystem.
  await recordCodexSecurityWorkerScanDraft(context, result);
  await assert.rejects(
    validateDiscoveryArtifacts(worker.artifacts, worker.resultPath, scanId),
    complete ? /coverage receipt.*unavailable/ : /only a checkpoint/,
  );
  const archive = path.join(path.dirname(output), "attempts/attempt-01");
  await mkdir(path.dirname(archive));
  const history = archived ? archive : output;
  if (archived) {
    await rename(output, archive);
    await mkdir(path.join(output, "artifacts"), { recursive: true });
  }
  const checkpoints = await readdir(path.join(history, "checkpoints"));
  const checkpointBytes = await Promise.all(
    checkpoints.map((name) =>
      readFile(path.join(history, "checkpoints", name), "utf8"),
    ),
  );
  const replacementDraft = draft(
    shared
      ? [
          {
            ...finding("candidate", "src/fixture.py"),
            provenance: { source: "local_plugin", candidateId: "candidate" },
          },
        ]
      : [],
    {
      complete: true,
      reviewState: {
        explicitExclusions: [],
        deferred: [],
        surfaces: [
          {
            id: "api",
            label: "API",
            disposition: "no_issue_found",
            receiptRefs: ["artifacts/replacement.md"],
          },
        ],
        resolvedDeferred: [
          { id: "review", reason: "Source review completed." },
        ],
      },
    },
  );
  if (archived)
    await assert.rejects(
      recordCodexSecurityWorkerScanDraft(context, replacementDraft),
      /replacement coverage receipt.*unavailable/,
    );
  await writeFile(
    path.join(output, "artifacts/replacement.md"),
    "Corrected review evidence.\n",
  );
  if (!archived && !complete) {
    await recordCodexSecurityWorkerScanDraft(
      context,
      draft([], {
        complete: false,
        reviewState: {
          ...result.reviewState,
          surfaces: [
            { ...surfaces[0], receiptRefs: ["artifacts/replacement.md"] },
          ],
        },
      }),
    );
  }
  const repaired = await recordCodexSecurityWorkerScanDraft(
    context,
    replacementDraft,
  );
  const accepted = await validateDiscoveryArtifacts(
    worker.artifacts,
    worker.resultPath,
    scanId,
  );
  assert.match(
    repaired.warnings.join("\n"),
    shared
      ? /Replaced (missing|invalid) (archived|saved) coverage receipt /
      : archived
        ? /Replaced missing archived coverage receipt /
        : /Replaced missing saved coverage receipt /,
  );
  assert.deepEqual(accepted.reviewState.deferred, []);
  assert.equal(accepted.findings.length, shared ? 1 : 0);
  const receipts = accepted.reviewState.surfaces[0].receiptRefs;
  assert.equal(receipts.length, 2);
  assert.deepEqual(
    new Set(
      await Promise.all(
        receipts.map((ref: string) =>
          readFile(receiptPath(output, ref), "utf8"),
        ),
      ),
    ),
    new Set(["Original valid evidence.\n", "Corrected review evidence.\n"]),
  );
  assert.equal(
    await readFile(path.join(history, existing), "utf8"),
    "Original valid evidence.\n",
  );
  assert.deepEqual(
    await Promise.all(
      checkpoints.map((name) =>
        readFile(path.join(history, "checkpoints", name), "utf8"),
      ),
    ),
    checkpointBytes,
  );
  // The saved closeout remains valid when later writes omit unchanged work.
  for (const complete of [false, true]) {
    await recordCodexSecurityWorkerScanDraft(context, draft([], { complete }));
  }
  await rename(output, path.join(path.dirname(archive), "attempt-02"));
  await mkdir(output);
  await recordCodexSecurityWorkerScanDraft(
    context,
    draft([], { complete: true }),
  );
  const retried = await validateDiscoveryArtifacts(
    worker.artifacts,
    worker.resultPath,
    scanId,
  );
  assert.deepEqual(retried.reviewState.deferred, []);
  assert.equal(retried.reviewState.surfaces[0].disposition, "no_issue_found");
  assert.deepEqual(
    new Set(
      await Promise.all(
        retried.reviewState.surfaces[0].receiptRefs.map((ref: string) =>
          readFile(receiptPath(output, ref), "utf8"),
        ),
      ),
    ),
    new Set(["Original valid evidence.\n", "Corrected review evidence.\n"]),
  );
}

async function testWorkerPublicationBeforeCheckpoint(root: string) {
  for (const complete of [false, true]) {
    for (const samples of [Number.MAX_SAFE_INTEGER + 1, "\ud800"]) {
      const workersRoot = path.join(
        root,
        `metadata-${complete}-${typeof samples}`,
      );
      const workerRoot = path.join(workersRoot, "first");
      const output = path.join(workerRoot, "output");
      await mkdir(output, { recursive: true });
      const context = {
        root: output,
        repoRoot: root,
        layout: "worker" as const,
        scanId,
      };
      const exclusion = {
        pattern: "vendor/**",
        reason: "External code.",
        metrics: { samples },
      };
      const input = draft([finding("preserved", "fixture.py")], {
        complete,
        reviewState: {
          surfaces: [],
          explicitExclusions: [exclusion],
          deferred: [],
        },
      });
      await assert.rejects(
        recordCodexSecurityWorkerScanDraft(context, input),
        /unsafe integer|well-formed Unicode/,
      );
      assert.deepEqual(
        await readdir(output),
        [],
        "invalid metadata must not create a checkpoint or result",
      );
      const corrected = {
        ...input,
        complete: false,
        reviewState: {
          ...input.reviewState,
          explicitExclusions: [{ ...exclusion, metrics: { samples: 1 } }],
        },
      };
      await recordCodexSecurityWorkerScanDraft(context, corrected);
      const checkpoint = await readFile(
        path.join(output, "checkpoint-head.json"),
        "utf8",
      );
      const files = await readdir(output, { recursive: true });
      await assert.rejects(
        recordCodexSecurityWorkerScanDraft(context, input),
        /unsafe integer|well-formed Unicode/,
      );
      assert.equal(
        await readFile(path.join(output, "checkpoint-head.json"), "utf8"),
        checkpoint,
      );
      assert.deepEqual(await readdir(output, { recursive: true }), files);
      const archived = path.join(workerRoot, "attempts", "attempt-01");
      await mkdir(path.dirname(archived));
      await rename(output, archived);
      await mkdir(output);
      await recordCodexSecurityWorkerScanDraft(context, {
        ...corrected,
        findings: [],
        complete: true,
      });
      const accepted = await validateDiscoveryArtifacts(
        { workersRoot },
        path.join(output, "result.json"),
        scanId,
      );
      assert.equal(accepted.findings.length, 1);
      assert.deepEqual(
        accepted.reviewState.explicitExclusions,
        corrected.reviewState.explicitExclusions,
      );
    }
  }
}

async function testCoveragePublicationParity(root: string) {
  const original = draft([], {
    reviewState: {
      explicitExclusions: [],
      deferred: [],
      surfaces: [
        {
          id: "api",
          label: "API",
          disposition: "no_issue_found",
          receiptRefs: ["artifacts/review.md"],
        },
      ],
    },
  }) as ScanDraftInput & {
    reviewState: {
      surfaces: JsonObject[];
      deferred: JsonObject[];
      explicitExclusions: JsonObject[];
    };
  };
  const worker = await createWorker(
    path.join(root, "publication-parity"),
    "first",
    original,
  );
  const output = path.dirname(worker.resultPath);
  await mkdir(path.join(output, "artifacts"));
  await writeFile(
    path.join(output, "artifacts/review.md"),
    "Review evidence.\n",
  );
  for (const ref of [
    "artifacts/review.md",
    "artifacts/./review.md",
    "artifacts//review.md",
  ]) {
    const result = structuredClone(original);
    result.reviewState.surfaces[0].receiptRefs = [ref];
    result.reviewState.deferred = [
      {
        id: "review",
        reason: "Review another route.",
        paths: [".", "./src//api.ts"],
        surfaceIds: ["api"],
        receiptRefs: { external: "opaque metadata" },
      },
    ];
    result.reviewState.explicitExclusions = [
      {
        id: "external",
        pattern: "vendor/**",
        reason: "External code.",
        receiptRefs: ["opaque/missing.md"],
        surfaceIds: ["opaque-id"],
      },
    ];
    await writeResult(worker.resultPath, result);
    const accepted = await validateDiscoveryArtifacts(
      worker.artifacts,
      worker.resultPath,
      scanId,
    );
    const coverage = projectDiscoveryCoverage(
      accepted.reviewState,
      { id: worker.id, attempt: 1 },
      "artifacts/deep_discovery/workers/discovery-0001/output",
    );
    assert.deepEqual(coverage.deferred[0].receiptRefs, {
      external: "opaque metadata",
    });
    assert.deepEqual(coverage.deferred[0].surfaceIds, [
      "first-attempt-1-surface-1",
    ]);
    assert.deepEqual(coverage.explicitExclusions[0].receiptRefs, [
      "opaque/missing.md",
    ]);
    assert.deepEqual(coverage.explicitExclusions[0].surfaceIds, ["opaque-id"]);
  }
  const cases: { patch: (result: typeof original) => void; error: RegExp }[] = [
    {
      patch: (result) => {
        result.reviewState.deferred = [
          { reason: "Review route.", paths: ["/repository/src/api.ts"] },
        ];
      },
      error: /safe repository-relative/,
    },
    {
      patch: (result) => {
        result.reviewState.surfaces[0].receiptRefs = ["artifacts/review?.md"];
      },
      error: /safe scan-relative/,
    },
    {
      patch: (result) => {
        result.reviewState.surfaces[0].metrics = {
          samples: Number.MAX_SAFE_INTEGER + 1,
        };
      },
      error: /unsafe integer/,
    },
    {
      patch: (result) => {
        result.reviewState.openQuestions = [
          { question: "Review \ud800 deployment?" },
        ];
      },
      error: /well-formed Unicode/,
    },
  ];
  for (const ref of ["artifacts/conİn$", "artifacts/conın$"]) {
    cases.push({
      patch: (result) => {
        result.reviewState.surfaces[0].receiptRefs = [ref];
      },
      error: /safe scan-relative/,
    });
  }
  cases.push({
    patch: (result) => {
      result.reviewState.deferred = [
        { reason: "Review route.", paths: ["\u0085"] },
      ];
    },
    // Either validation layer can reject the whitespace-only path first.
    error: /safe repository-relative|Invalid string: must match pattern/,
  });
  await writeFile(
    path.join(output, "artifacts/Review.md"),
    "Other case-sensitive evidence.\n",
  );
  cases.push({
    patch: (result) => {
      result.reviewState.surfaces[0].receiptRefs = [
        "artifacts/review.md",
        "artifacts/Review.md",
      ];
    },
    error: /duplicate artifact path/,
  });
  for (const { patch, error } of cases) {
    const result = structuredClone(original);
    patch(result);
    await writeResult(worker.resultPath, result);
    await assert.rejects(
      validateDiscoveryArtifacts(worker.artifacts, worker.resultPath, scanId),
      error,
    );
  }
}

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

  for (const details of [
    { code_evidence: [{ id: "legacy", code: "source()" }] },
    { root_cause: "Legacy root cause" },
    { validation: { evidence: { kind: "trace" } } },
    { attackPath: { steps: { first: "upload" } } },
  ]) {
    await writeResult(worker.resultPath, {
      ...result,
      findings: [{ ...result.findings[0], ...details }],
    });
    const original = await readFile(worker.resultPath, "utf8");
    await assert.rejects(
      validateDiscoveryArtifacts(artifacts, worker.resultPath, scanId),
    );
    assert.equal(await readFile(worker.resultPath, "utf8"), original);
  }

  await writeResult(worker.resultPath, { ...result, scanId: otherScanId });
  await assert.rejects(
    validateDiscoveryArtifacts(artifacts, worker.resultPath, scanId),
    /different scan/,
  );

  await writeResult(worker.resultPath, {
    ...result,
    reviewState: {
      ...result.reviewState,
      deferred: [{ reason: "Needs follow-up." }],
    },
  });
  const withDeferred = await validateDiscoveryArtifacts(
    artifacts,
    worker.resultPath,
    scanId,
  );

  assert.deepEqual(withDeferred.reviewState.deferred, [
    { reason: "Needs follow-up." },
  ]);

  await writeResult(worker.resultPath, {
    ...result,
    reviewState: {
      ...result.reviewState,
      surfaces: [
        { label: "Unfinished Standard review", disposition: "needs_follow_up" },
      ],
    },
  });
  const withFollowUp = await validateDiscoveryArtifacts(
    artifacts,
    worker.resultPath,
    scanId,
  );

  assert.deepEqual(withFollowUp.reviewState.surfaces, [
    { label: "Unfinished Standard review", disposition: "needs_follow_up" },
  ]);

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
  await writeResult(resultPath, reduction([firstFinding]));

  const sources: import("../src/deep-scan/artifact-validation.js").DeepReductionSources =
    {
      discoveries: [
        {
          workerId: first.id,
          result: reduction([firstFinding, secondFinding]),
        },
      ],
      previous: null,
    };
  const validateSnapshot = (reducerId = "dedup-0001", snapshot = sources) =>
    validateReducerArtifacts(
      { artifacts, artifactDir, resultPath, reducerId, sources: snapshot },
      scanId,
    );
  await assert.rejects(validateSnapshot(), /unaccounted source findings/);
  await writeResult(resultPath, reduction([firstFinding, secondFinding]));
  await writeFile(first.resultPath, "{source changed after dispatch");
  const validatedSnapshot = await validateSnapshot();
  assert.equal(validatedSnapshot.newFindings, 2);
  const admitted = await readJson(resultPath);
  const { sourceCoverage, ...persistedResult } = validatedSnapshot.result;
  assert.ok(sourceCoverage);
  assert.equal(sourceCoverage.completeness, undefined);
  assert.deepEqual(
    persistedResult,
    admitted,
    "accepted findings retain the legacy persisted shape while coverage stays host-owned",
  );
  assert.equal(Object.hasOwn(admitted, "reviewState"), false);
  assert.deepEqual(admitted.findings[1].provenance.sourceFindingIds, [
    "worker-001:1",
  ]);
  sources.previous = structuredClone(admitted);
  sources.previous!.findings[0].summary =
    "Additional proof established by the previous reducer.";
  await writeResult(resultPath, reduction([firstFinding, secondFinding]));
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
        result: reduction([firstFinding], {
          threatModel: inheritedThreatModel,
        }),
      },
    ],
    previous: null,
  };
  await writeResult(resultPath, reduction([firstFinding]));
  await validateSnapshot("dedup-threat-model", threatModelSources);
  assert.deepEqual(
    (await readJson(resultPath)).threatModel,
    inheritedThreatModel,
    "a reducer cannot erase the accepted discovery threat model by omission",
  );

  await writeResult(resultPath, reduction([]));
  await assert.rejects(
    validateSnapshot("dedup-ambiguous-threat-model", {
      discoveries: [
        {
          workerId: "worker-a",
          result: reduction([], {
            threatModel: { summary: "Public API." },
            scope: { summary: "Public API" },
          }),
        },
        {
          workerId: "worker-b",
          result: reduction([], {
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
  await writeResult(resultPath, reduction([firstFinding]));
  await validateSnapshot("dedup-scope", {
    discoveries: [
      {
        workerId: first.id,
        result: reduction([firstFinding], { scope: inheritedScope }),
      },
    ],
    previous: null,
  });
  assert.deepEqual(
    (await readJson(resultPath)).scope,
    inheritedScope,
    "a reducer cannot erase an unambiguous accepted scope by omission",
  );

  await writeResult(resultPath, reduction([]));
  await assert.rejects(
    validateSnapshot("dedup-ambiguous-scope", {
      discoveries: [
        {
          workerId: "worker-a",
          result: reduction([], { scope: { summary: "Public API" } }),
        },
        {
          workerId: "worker-b",
          result: reduction([], { scope: { summary: "Admin API" } }),
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
    previous: reduction([previousCollisionA, previousCollisionB]),
  };
  await writeResult(
    resultPath,
    reduction([
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
  const referenced = <Finding extends Record<string, unknown>>(
    original: Finding,
    refs: string[],
  ) => ({
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
      discoveries: [
        { workerId: "fresh", result: reduction([collidingOriginalB]) },
      ],
      previous: reduction([...previous]),
    };
    await writeResult(resultPath, reduction([...output]));
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
  await writeResult(resultPath, reduction([firstFinding]));

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

  await writeResult(resultPath, draft([firstFinding]));
  const invalidArtifact = await readFile(resultPath, "utf8");
  await assert.rejects(validate(), /reviewState/);
  assert.equal(await readFile(resultPath, "utf8"), invalidArtifact);
  await writeResult(resultPath, reduction([firstFinding], { complete: false }));
  await assert.rejects(validate(), /only a checkpoint|not complete/);

  await writeResult(resultPath, reduction([]));
  assert.equal((await validate()).newFindings, 0);

  await writeResult(resultPath, {
    ...reduction([firstFinding]),
    resultPath: "/tmp/result.json",
  });
  await assert.rejects(validate(), /resultPath/);

  await writeResult(resultPath, reduction([firstFinding, secondFinding]));
  assert.equal((await validate()).newFindings, 2);

  const previousReducerResultPath = path.join(
    artifacts.dedupRoot,
    "dedup-0000",
    "output",
    "result.json",
  );
  await mkdir(path.dirname(previousReducerResultPath), { recursive: true });
  await writeResult(previousReducerResultPath, reduction([firstFinding]));
  const previousArtifact = await readFile(previousReducerResultPath, "utf8");
  assert.equal(
    (await validate(previousReducerResultPath)).newFindings,
    1,
    "only findings absent from the previous reducer are new",
  );
  assert.equal(
    await readFile(previousReducerResultPath, "utf8"),
    previousArtifact,
    "reading a previous reducer must not rewrite it",
  );

  const renamedTitle = {
    ...firstFinding,
    title: "Stronger explanation of the same finding.",
  };
  await writeResult(resultPath, reduction([renamedTitle, secondFinding]));
  assert.equal((await validate(previousReducerResultPath)).newFindings, 1);

  await writeResult(
    previousReducerResultPath,
    reduction([firstFinding, secondFinding]),
  );
  await writeResult(resultPath, reduction([secondFinding]));
  await assert.rejects(
    validate(previousReducerResultPath),
    (error: NodeJS.ErrnoException) =>
      error.code === "merge_traceability_unstable_candidate_id",
  );

  const replacement = finding("replacement", "src/c.js");
  await writeResult(
    resultPath,
    reduction([firstFinding, secondFinding, replacement]),
  );
  assert.equal((await validate(previousReducerResultPath)).newFindings, 1);

  const implicitFirst = { ...firstFinding };
  delete (implicitFirst as { identity?: unknown }).identity;
  const implicitRenamed = {
    ...implicitFirst,
    summary: "More complete evidence.",
  };
  await writeResult(previousReducerResultPath, reduction([implicitFirst]));
  await writeResult(resultPath, reduction([implicitRenamed]));
  assert.equal((await validate(previousReducerResultPath)).newFindings, 0);
  await writeResult(
    resultPath,
    reduction([
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
    ...reduction([firstFinding]),
    scanId: otherScanId,
  });
  await assert.rejects(
    validate(),
    (error: NodeJS.ErrnoException) =>
      error.name !== "DeepScanNonRetryableError" &&
      /different scan/.test(error.message),
  );

  await writeResult(resultPath, reduction([firstFinding]));
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
    ...reduction([firstFinding]),
    scanId: otherScanId,
  });
  await assert.rejects(validate(previousReducerResultPath), /different scan/);

  if (process.platform !== "win32") {
    const actualResult = path.join(artifactDir, "actual-result.json");
    await writeResult(actualResult, reduction([firstFinding]));
    await rm(resultPath);
    await symlink(actualResult, resultPath, "file");
    await assert.rejects(validate(), /canonical non-symlink path/);
  }
}

async function testReducerLineageConvergence(root: string) {
  const { artifacts } = await createWorker(
    path.join(root, "lineage-convergence"),
    "worker-lineage",
    draft([]),
  );
  const artifactDir = path.join(artifacts.dedupRoot, "dedup-current", "output");
  const resultPath = path.join(artifactDir, "result.json");
  const previousReducerResultPath = path.join(
    artifacts.dedupRoot,
    "dedup-previous",
    "output",
    "result.json",
  );
  await mkdir(artifactDir, { recursive: true });
  await mkdir(path.dirname(previousReducerResultPath), { recursive: true });
  const originals = {
    a: finding("root-a", "src/a.js"),
    b: finding("alias-b", "src/b.js"),
    c: finding("fresh-c", "src/c.js"),
  };
  const referenced = (name: string, refs: string[]) => ({
    ...finding(name, `src/${name}.js`),
    provenance: { source: "local_plugin", sourceFindingIds: refs },
  });
  const retained = (name: string, keys: (keyof typeof originals)[]) => ({
    ...referenced(
      name,
      keys.map((key) => `origin:${key}`),
    ),
    provenance: {
      source: "local_plugin",
      sourceFindingIds: keys.map((key) => `origin:${key}`),
      sourceFindings: keys.map((key) => ({
        id: `origin:${key}`,
        finding: originals[key],
      })),
    },
  });
  const previousA = retained("root-a", ["a"]);
  const previousB = {
    ...retained("alias-b", ["b"]),
    rootCause:
      "The previous reduction established another reachable response branch.",
  };
  const discoveries = [{ workerId: "fresh", result: reduction([originals.c]) }];
  for (const [label, previous, output, newFindings] of [
    [
      "retain-canonical-alias",
      [previousA, previousB],
      [referenced("root-a", ["origin:a", "origin:b", "fresh:0"])],
      0,
    ],
    [
      "new-canonical-alias",
      [previousA, previousB],
      [referenced("merged-root", ["origin:a", "origin:b", "fresh:0"])],
      0,
    ],
    [
      "independent-root",
      [previousA, previousB],
      [
        referenced("merged-root", ["origin:a", "origin:b"]),
        referenced("fresh-c", ["fresh:0"]),
      ],
      1,
    ],
    [
      "keep-independent-instances",
      [previousA, previousB],
      [
        referenced("root-a", ["origin:a", "fresh:0"]),
        referenced("alias-b", ["origin:b"]),
      ],
      0,
    ],
  ] as const) {
    await writeResult(resultPath, reduction([...output]));
    await writeResult(previousReducerResultPath, reduction([...previous]));
    const input = { artifacts, artifactDir, resultPath, reducerId: label };
    const accepted = await validateReducerArtifacts(
      {
        ...input,
        sources: { discoveries, previous: reduction([...previous]) },
      },
      scanId,
    );
    assert.equal(accepted.newFindings, newFindings, label);
    const saved = await readJson(resultPath);
    assert.deepEqual(deepReductionForPersistence(accepted.result), saved);
    assert.equal(
      (
        await validateReducerArtifacts(
          { ...input, previousReducerResultPath },
          scanId,
        )
      ).newFindings,
      newFindings,
      `${label}: reopening the saved reduction must reconstruct the same novelty`,
    );
    if (label === "new-canonical-alias") {
      assert.deepEqual(
        saved.findings[0].provenance.previousFindings.map(
          (item: JsonObject) => item.title,
        ),
        [previousA.title, previousB.title],
        "semantic consolidation keeps both prior canonical bodies",
      );
      for (const field of ["summary", "rootCause"]) {
        const degraded = structuredClone(saved);
        degraded.findings[0][field] = "X";
        await writeResult(resultPath, degraded);
        await assert.rejects(
          validateReducerArtifacts(
            {
              ...input,
              sources: { discoveries, previous: reduction([...previous]) },
            },
            scanId,
          ),
          /placeholder.*origin:/,
          "renaming merged aliases cannot bypass original or synthesized content preservation",
        );
        await assert.rejects(
          validateReducerArtifacts(
            { ...input, previousReducerResultPath },
            scanId,
          ),
          /placeholder.*origin:/,
          "stored recovery rejects the same content loss as live reduction",
        );
        assert.deepEqual(await readJson(resultPath), degraded);
      }
    }
  }
  for (const [label, previous, output] of [
    [
      "split-previous-group",
      [retained("root-a", ["a", "b"])],
      [
        referenced("root-a", ["origin:a"]),
        referenced("alias-b", ["origin:b", "fresh:0"]),
      ],
    ],
    [
      "rename-independent-root",
      [previousA],
      [referenced("renamed-root", ["origin:a", "fresh:0"])],
    ],
    [
      "ambiguous-previous-group",
      [previousA],
      [
        referenced("root-a", ["origin:a"]),
        referenced("alias-b", ["origin:a", "fresh:0"]),
      ],
    ],
  ] as const) {
    await writeResult(resultPath, reduction([...output]));
    await writeResult(previousReducerResultPath, reduction([...previous]));
    const input = { artifacts, artifactDir, resultPath, reducerId: label };
    await assert.rejects(
      validateReducerArtifacts(
        {
          ...input,
          sources: { discoveries, previous: reduction([...previous]) },
        },
        scanId,
      ),
      /previously accepted finding|more than once/,
      label,
    );
    await assert.rejects(
      validateReducerArtifacts({ ...input, previousReducerResultPath }, scanId),
      /previously accepted finding/,
      `${label}: stored recovery must enforce the same assignment`,
    );
  }
  const legacy = reduction([originals.a, originals.b]);
  const legacyMerge = reduction([
    referenced("merged-root", ["previous:0", "previous:1"]),
  ]);
  const validateLegacy = (previous: typeof legacy) =>
    validateReducerArtifacts(
      {
        artifacts,
        artifactDir,
        resultPath,
        reducerId: "legacy-consolidation",
        sources: { discoveries: [], previous },
      },
      scanId,
    );
  await writeResult(resultPath, legacyMerge);
  await assert.rejects(
    validateLegacy(legacy),
    /previously accepted finding identity/,
    "legacy findings without retained source bodies keep their identities",
  );
  await writeResult(resultPath, legacy);
  const upgraded = (await validateLegacy(legacy)).result;
  assert.deepEqual(
    upgraded.findings.map(
      (item: { provenance: { sourceFindingIds: string[] } }) =>
        item.provenance.sourceFindingIds,
    ),
    [["previous:0"], ["previous:1"]],
  );
  await writeResult(resultPath, legacyMerge);
  assert.equal(
    (await validateLegacy(upgraded)).newFindings,
    0,
    "host-retained legacy source bodies support later alias consolidation",
  );
  await writeResult(
    previousReducerResultPath,
    deepReductionForPersistence(upgraded),
  );
  assert.equal(
    (
      await validateReducerArtifacts(
        {
          artifacts,
          artifactDir,
          resultPath,
          reducerId: "legacy-consolidation-recovery",
          previousReducerResultPath,
        },
        scanId,
      )
    ).newFindings,
    0,
  );
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
    "reducers submit and return results without reviewState",
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

async function testSharedMissingReceiptRepairHistory(root: string) {
  const surface = (id: string, disposition: string, receipt: string) => ({
    id,
    label: id,
    disposition,
    receiptRefs: [receipt],
  });
  const task = (id: string) => ({
    id,
    reason: "Review remains.",
    surfaceIds: [id],
  });
  const close = (id: string) => ({ id, reason: "Review completed." });
  const makeDraft = (
    surfaces: JsonObject[],
    deferred: JsonObject[] = [],
    resolvedDeferred: JsonObject[] = [],
  ) =>
    draft([], {
      complete: true,
      reviewState: {
        surfaces,
        deferred,
        resolvedDeferred,
        explicitExclusions: [],
      },
    });
  const broken = makeDraft(
    [surface("writer", "needs_follow_up", "artifacts/shared-missing.md")],
    [task("writer")],
  );
  const worker = await createWorker(
    path.join(root, "shared-receipt-history"),
    "first",
    broken,
  );
  const output = path.dirname(worker.resultPath);
  const archive = path.join(path.dirname(output), "attempts/attempt-01");
  await mkdir(path.dirname(archive));
  await rename(output, archive);
  await mkdir(path.join(archive, "artifacts"));
  await mkdir(path.join(output, "artifacts"), { recursive: true });
  const archivedContext = {
    root: archive,
    repoRoot: root,
    layout: "worker" as const,
    scanId,
  };
  const context = { ...archivedContext, root: output };
  await saveScanDraftCheckpoint(archivedContext, broken, false);
  const previousNames = await readdir(path.join(archive, "checkpoints"));
  for (const name of previousNames)
    await utimes(path.join(archive, "checkpoints", name), 100, 100);
  await writeFile(
    path.join(archive, "artifacts/writer.md"),
    "Previously completed writer review.\n",
  );
  const repaired = makeDraft(
    [surface("writer", "no_issue_found", "artifacts/writer.md")],
    [],
    [close("writer")],
  );
  await saveScanDraftCheckpoint(archivedContext, repaired, false);
  for (const name of await readdir(path.join(archive, "checkpoints"))) {
    if (!previousNames.includes(name))
      await utimes(path.join(archive, "checkpoints", name), 200, 200);
  }
  const latest = makeDraft(
    [
      surface("reader", "needs_follow_up", "artifacts/shared-missing.md"),
      surface("writer", "no_issue_found", "artifacts/writer.md"),
    ],
    [task("reader")],
    [close("writer")],
  );
  await writeResult(path.join(archive, "result.json"), latest);
  await utimes(path.join(archive, "result.json"), 300, 300);
  const original = await readFile(path.join(archive, "result.json"), "utf8");
  await writeFile(
    path.join(output, "artifacts/reader.md"),
    "Current reader review.\n",
  );
  await recordCodexSecurityWorkerScanDraft(
    context,
    makeDraft(
      [surface("reader", "no_issue_found", "artifacts/reader.md")],
      [],
      [close("reader")],
    ),
  );
  const accepted = await validateDiscoveryArtifacts(
    worker.artifacts,
    worker.resultPath,
    scanId,
  );
  assert.deepEqual(accepted.reviewState.deferred, []);
  assert.equal(accepted.reviewState.surfaces.length, 2);
  for (const row of accepted.reviewState.surfaces) {
    assert.equal(row.disposition, "no_issue_found");
    assert.equal(row.receiptRefs.length, 1);
    const content = await readFile(
      receiptPath(output, row.receiptRefs[0]),
      "utf8",
    );
    assert.equal(
      content,
      row.id === "writer"
        ? "Previously completed writer review.\n"
        : "Current reader review.\n",
    );
  }
  const retainedWriter = accepted.reviewState.surfaces.find(
    (row: JsonObject) => row.id === "writer",
  )!;
  const retainedPath = receiptPath(output, retainedWriter.receiptRefs[0]);
  await rm(retainedPath);
  await recordCodexSecurityWorkerScanDraft(context, accepted);
  await validateDiscoveryArtifacts(worker.artifacts, worker.resultPath, scanId);
  assert.equal(
    await readFile(retainedPath, "utf8"),
    "Previously completed writer review.\n",
    "a saved reference must restore a missing copy from its intact archive",
  );
  await writeFile(retainedPath, "Updated writer review.\n");
  await recordCodexSecurityWorkerScanDraft(context, accepted);
  assert.equal(
    await readFile(retainedPath, "utf8"),
    "Updated writer review.\n",
  );
  await rm(path.join(archive, "artifacts/writer.md"));
  await recordCodexSecurityWorkerScanDraft(context, accepted);
  assert.equal(
    await readFile(retainedPath, "utf8"),
    "Updated writer review.\n",
  );
  assert.equal(
    await readFile(path.join(archive, "result.json"), "utf8"),
    original,
  );
}

async function testCurrentAnonymousReceiptSelection(
  root: string,
  candidate: boolean,
  reverse: boolean,
) {
  const selectedRef = reverse ? "artifacts/Review.md" : "artifacts/review.md";
  const historicalRef = reverse ? "artifacts/review.md" : "artifacts/Review.md";
  const old = draft([], {
    complete: true,
    reviewState: {
      explicitExclusions: [],
      surfaces: [
        {
          id: "writer",
          label: "Retained review",
          disposition: "needs_follow_up",
          receiptRefs: [historicalRef],
        },
      ],
      deferred: [
        { id: "review", reason: "Review remains.", surfaceIds: ["writer"] },
      ],
    },
  });
  const worker = await createWorker(
    path.join(root, `anonymous-receipt-${candidate}-${reverse}`),
    "first",
    old,
  );
  const output = path.dirname(worker.resultPath);
  await mkdir(path.join(output, "artifacts"));
  await writeFile(path.join(output, historicalRef), "Historical review.\n");
  await writeFile(
    path.join(output, selectedRef),
    "Current anonymous review.\n",
  );
  await writeFile(
    path.join(output, "artifacts/replacement.md"),
    "Replacement review.\n",
  );
  const originalReceipts = await Promise.all(
    [selectedRef, historicalRef].map((ref) =>
      readFile(receiptPath(output, ref)),
    ),
  );
  const context = {
    root: output,
    repoRoot: root,
    layout: "worker" as const,
    scanId,
  };
  await saveScanDraftCheckpoint(context, old, false);
  const checkpoints = await readdir(path.join(output, "checkpoints"));
  const originals = await Promise.all(
    checkpoints.map((name) => readFile(path.join(output, "checkpoints", name))),
  );
  const current = draft([], {
    complete: true,
    reviewState: {
      explicitExclusions: [],
      deferred: [],
      resolvedDeferred: [{ id: "review", reason: "Review completed." }],
      surfaces: [
        {
          id: "writer",
          label: "Retained review",
          disposition: "no_issue_found",
          receiptRefs: ["artifacts/replacement.md"],
        },
        {
          ...(candidate ? { candidateId: "anonymous" } : {}),
          label: "Current anonymous review",
          disposition: "no_issue_found",
          receiptRefs: [selectedRef],
        },
      ],
    },
  });
  for (let attempt = 0; attempt < 2; attempt++) {
    await recordCodexSecurityWorkerScanDraft(context, current);
    const accepted = await validateDiscoveryArtifacts(
      worker.artifacts,
      worker.resultPath,
      scanId,
    );
    assert.equal(accepted.reviewState.surfaces.length, 2);
    const selected = accepted.reviewState.surfaces.find(
      (row: JsonObject) => row.label === "Current anonymous review",
    );
    assert.deepEqual(selected.receiptRefs, [
      workerReceiptRef(output, selectedRef),
    ]);
    assert.equal(selected.disposition, "no_issue_found");
    const writer = accepted.reviewState.surfaces.find(
      (row: JsonObject) => row.id === "writer",
    );
    assert.deepEqual(writer.receiptRefs, [
      workerReceiptRef(output, "artifacts/replacement.md"),
    ]);
  }
  assert.deepEqual(
    await Promise.all(
      checkpoints.map((name) =>
        readFile(path.join(output, "checkpoints", name)),
      ),
    ),
    originals,
  );
  assert.deepEqual(
    await Promise.all(
      [selectedRef, historicalRef].map((ref) =>
        readFile(receiptPath(output, ref)),
      ),
    ),
    originalReceipts,
  );
}

async function testCurrentReceiptSelectionBeforeArchivedHistory(
  root: string,
  resolution: "generic" | "candidate" | "linked-candidate",
) {
  const candidate = resolution !== "generic";
  for (const repairId of ["reader", "writer"]) {
    for (const reverse of [false, true]) {
      const refs = {
        reader: "artifacts/review.md",
        writer: "artifacts/Review.md",
      };
      const keptId = repairId === "reader" ? "writer" : "reader";
      const old = draft([], {
        complete: true,
        reviewState: {
          explicitExclusions: [],
          deferred: [
            {
              id: resolution === "candidate" ? repairId : "review",
              ...(candidate ? { candidateId: repairId } : {}),
              reason: "Review remains.",
              surfaceIds: [repairId],
            },
          ],
          surfaces: Object.entries(refs).map(([id, ref]) => ({
            id,
            label: id,
            disposition: id === repairId ? "needs_follow_up" : "no_issue_found",
            ...(candidate && id === repairId ? { candidateId: repairId } : {}),
            receiptRefs: [ref],
          })),
        },
      });
      if (reverse) old.reviewState.surfaces.reverse();
      const worker = await createWorker(
        path.join(root, `selected-${repairId}-${reverse}-${resolution}`),
        "first",
        old,
      );
      const output = path.dirname(worker.resultPath);
      const archive = path.join(path.dirname(output), "attempts/attempt-01");
      await mkdir(path.dirname(archive));
      await rename(output, archive);
      await mkdir(path.join(archive, "artifacts"));
      for (const [id, ref] of Object.entries(refs))
        await writeFile(path.join(archive, ref), `Original ${id} review.\n`);
      const originals = await Promise.all(
        Object.values(refs).map((ref) =>
          readFile(path.join(archive, ref), "utf8"),
        ),
      );
      const oldResult = await readFile(
        path.join(archive, "result.json"),
        "utf8",
      );
      await mkdir(path.join(output, "artifacts"), { recursive: true });
      await writeFile(
        path.join(output, "artifacts/replacement.md"),
        "Corrected selected review.\n",
      );
      await recordCodexSecurityWorkerScanDraft(
        { root: output, repoRoot: root, layout: "worker", scanId },
        draft(
          candidate
            ? [
                {
                  ...finding(repairId, "src/fixture.py"),
                  provenance: { source: "local_plugin", candidateId: repairId },
                },
              ]
            : [],
          {
            complete: true,
            reviewState: {
              explicitExclusions: [],
              deferred: [],
              surfaces: candidate
                ? []
                : [
                    {
                      id: repairId,
                      label: repairId,
                      disposition: "no_issue_found",
                      receiptRefs: ["artifacts/replacement.md"],
                    },
                  ],
              resolvedDeferred: candidate
                ? []
                : [{ id: "review", reason: "Review completed." }],
            },
          },
        ),
      );
      const result = await validateDiscoveryArtifacts(
        worker.artifacts,
        worker.resultPath,
        scanId,
      );
      assert.deepEqual(result.reviewState.deferred, []);
      assert.equal(result.reviewState.surfaces.length, candidate ? 1 : 2);
      assert.equal(result.findings.length, candidate ? 1 : 0);
      const kept = result.reviewState.surfaces.find(
        (row: JsonObject) => row.id === keptId,
      );
      assert.deepEqual(kept.receiptRefs, [
        workerReceiptRef(
          output,
          `artifacts/archived-receipts/attempt-01/${refs[keptId]}`,
        ),
      ]);
      assert.equal(
        await readFile(receiptPath(output, kept.receiptRefs[0]), "utf8"),
        await readFile(path.join(archive, refs[keptId]), "utf8"),
      );
      const repaired = result.reviewState.surfaces.find(
        (row: JsonObject) => row.id === repairId,
      );
      if (candidate) assert.equal(repaired, undefined);
      else
        assert.deepEqual(repaired.receiptRefs, [
          workerReceiptRef(output, "artifacts/replacement.md"),
        ]);
      assert.equal(
        await readFile(path.join(archive, "result.json"), "utf8"),
        oldResult,
      );
      assert.deepEqual(
        await Promise.all(
          Object.values(refs).map((ref) =>
            readFile(path.join(archive, ref), "utf8"),
          ),
        ),
        originals,
      );
    }
  }
}

function reduction<Finding extends Record<string, unknown>>(
  findings: Finding[],
  extra = {},
) {
  return { scanId, findings, ...extra };
}

function workerReceiptRef(
  output: string,
  ref: string,
  directory = "output",
): string {
  return `artifacts/deep_discovery/workers/${path.basename(path.dirname(output))}/${directory}/${ref}`;
}

function receiptPath(output: string, ref: string): string {
  const root = ref.startsWith("artifacts/deep_discovery/workers/")
    ? path.resolve(output, "../../../../..")
    : output;
  return path.join(root, ref);
}
