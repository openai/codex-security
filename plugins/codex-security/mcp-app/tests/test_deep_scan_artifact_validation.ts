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
import type { ScanUnion } from "../src/deep-scan/artifact-validation.ts";
import type { JsonObject } from "../src/types.ts";

const { addScanCoverage, scanCoverage, validateDiscoveryArtifacts } =
  await importSource(
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
  const previous: ScanUnion = { scanId, findings: [] };
  for (const worker of [
    { id: "first", attempt: 1 },
    { id: "second", attempt: 1 },
    { id: "first", attempt: 2 },
  ]) {
    addScanCoverage(
      previous,
      {
        ...worker,
        resultPath: "worker/output/result.json",
        result: draft([], { reviewState: source }),
      },
      ".",
    );
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
  const coverage = scanCoverage(
    { ...worker, result: accepted },
    worker.artifacts.scanDir,
  );
  const parent = parseScanDraft({ ...result, reviewState: coverage });
  assert.deepEqual(
    parent.reviewState.deferred.map((row: { id: string }) => row.id),
    [
      "first-attempt-unknown-deferred-1",
      "first-attempt-unknown-deferred-2",
      "first-attempt-unknown-deferred-3",
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
    const coverage = scanCoverage(
      { ...worker, result: accepted },
      worker.artifacts.scanDir,
    );
    assert.deepEqual(coverage.deferred[0].receiptRefs, {
      external: "opaque metadata",
    });
    assert.deepEqual(coverage.deferred[0].surfaceIds, [
      "first-attempt-unknown-surface-1",
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
