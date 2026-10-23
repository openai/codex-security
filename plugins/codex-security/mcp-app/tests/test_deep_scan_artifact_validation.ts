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
import type { JsonObject } from "../src/types.ts";

const {
  validateDiscoveryArtifacts,
  validateReducerArtifacts,
  aggregateDiscoveryCoverage,
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
  await testEmptyDiscoveryAndReduction(root);
} finally {
  await rm(root, { recursive: true, force: true });
}

console.log("deep scan artifact validation tests passed");

async function testDiscoveryReceipts(root: string) {
  const result = draft([], {
    coverage: {
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
  const [retained] = accepted.coverage.surfaces;
  assert.equal(retained.id, "api");
  assert.deepEqual(retained.receiptRefs, [
    "artifacts/archived-receipts/attempt-01/artifacts/review.md",
  ]);
  assert.equal(
    await readFile(path.join(output, retained.receiptRefs[0]), "utf8"),
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
  assert.equal(retried.coverage.surfaces.length, 1);
  for (const ref of retried.coverage.surfaces[0].receiptRefs) {
    assert.equal(
      await readFile(path.join(output, ref), "utf8"),
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
    coverage: {
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
  const coverage = aggregateDiscoveryCoverage(worker.artifacts, [
    { ...worker, result: accepted },
  ]);
  const parent = parseScanDraft({ ...result, coverage });
  assert.deepEqual(
    parent.coverage.deferred.map((row: { id: string }) => row.id),
    ["first/review", "first/review-3", "first/review-2"],
  );
  assert.deepEqual(
    parent.coverage.deferred.map((row: { reason: string }) => row.reason),
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
    coverage: {
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
        coverage: {
          ...result.coverage,
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
    accepted.coverage.surfaces.length,
    includeValidCheckpoint ? 1 : 0,
  );
  if (includeValidCheckpoint) {
    const refs = accepted.coverage.surfaces[0].receiptRefs;
    assert.deepEqual(refs, [
      "artifacts/archived-receipts/attempt-01/artifacts/review.md",
    ]);
    assert.equal(
      await readFile(path.join(output, refs[0]), "utf8"),
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
    coverage: {
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
      coverage: {
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
        coverage: {
          ...result.coverage,
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
  assert.deepEqual(accepted.coverage.deferred, []);
  assert.equal(accepted.findings.length, shared ? 1 : 0);
  const receipts = accepted.coverage.surfaces[0].receiptRefs;
  assert.equal(receipts.length, 2);
  assert.deepEqual(
    new Set(
      await Promise.all(
        receipts.map((ref: string) => readFile(path.join(output, ref), "utf8")),
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
  assert.deepEqual(retried.coverage.deferred, []);
  assert.equal(retried.coverage.surfaces[0].disposition, "no_issue_found");
  assert.deepEqual(
    new Set(
      await Promise.all(
        retried.coverage.surfaces[0].receiptRefs.map((ref: string) =>
          readFile(path.join(output, ref), "utf8"),
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
        coverage: {
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
        coverage: {
          ...input.coverage,
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
        accepted.coverage.explicitExclusions,
        corrected.coverage.explicitExclusions,
      );
    }
  }
}

async function testCoveragePublicationParity(root: string) {
  const original = draft([], {
    coverage: {
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
    coverage: {
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
    result.coverage.surfaces[0].receiptRefs = [ref];
    result.coverage.deferred = [
      {
        id: "review",
        reason: "Review another route.",
        paths: [".", "./src//api.ts"],
        surfaceIds: ["api"],
        receiptRefs: { external: "opaque metadata" },
      },
    ];
    result.coverage.explicitExclusions = [
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
    const coverage = aggregateDiscoveryCoverage(worker.artifacts, [
      { ...worker, result: accepted },
    ]);
    assert.deepEqual(coverage.deferred[0].receiptRefs, {
      external: "opaque metadata",
    });
    assert.deepEqual(coverage.deferred[0].surfaceIds, ["first/api"]);
    assert.deepEqual(coverage.explicitExclusions[0].receiptRefs, [
      "opaque/missing.md",
    ]);
    assert.deepEqual(coverage.explicitExclusions[0].surfaceIds, ["opaque-id"]);
  }
  const cases: { patch: (result: typeof original) => void; error: RegExp }[] = [
    {
      patch: (result) => {
        result.coverage.deferred = [
          { reason: "Review route.", paths: ["/repository/src/api.ts"] },
        ];
      },
      error: /safe repository-relative/,
    },
    {
      patch: (result) => {
        result.coverage.surfaces[0].receiptRefs = ["artifacts/review?.md"];
      },
      error: /safe scan-relative/,
    },
    {
      patch: (result) => {
        result.coverage.surfaces[0].metrics = {
          samples: Number.MAX_SAFE_INTEGER + 1,
        };
      },
      error: /unsafe integer/,
    },
    {
      patch: (result) => {
        result.coverage.openQuestions = [
          { question: "Review \ud800 deployment?" },
        ];
      },
      error: /well-formed Unicode/,
    },
  ];
  for (const ref of ["artifacts/conİn$", "artifacts/conın$"]) {
    cases.push({
      patch: (result) => {
        result.coverage.surfaces[0].receiptRefs = [ref];
      },
      error: /safe scan-relative/,
    });
  }
  cases.push({
    patch: (result) => {
      result.coverage.deferred = [
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
      result.coverage.surfaces[0].receiptRefs = [
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
    coverage: {
      ...result.coverage,
      deferred: [{ reason: "Needs follow-up." }],
    },
  });
  const withDeferred = await validateDiscoveryArtifacts(
    artifacts,
    worker.resultPath,
    scanId,
  );

  assert.deepEqual(withDeferred.coverage.deferred, [
    { reason: "Needs follow-up." },
  ]);

  await writeResult(worker.resultPath, {
    ...result,
    coverage: {
      ...result.coverage,
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

  assert.deepEqual(withFollowUp.coverage.surfaces, [
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
  await assert.rejects(validate(), /coverage/);
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
      coverage: {
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
  assert.deepEqual(accepted.coverage.deferred, []);
  assert.equal(accepted.coverage.surfaces.length, 2);
  for (const row of accepted.coverage.surfaces) {
    assert.equal(row.disposition, "no_issue_found");
    assert.equal(row.receiptRefs.length, 1);
    const content = await readFile(
      path.join(output, row.receiptRefs[0]),
      "utf8",
    );
    assert.equal(
      content,
      row.id === "writer"
        ? "Previously completed writer review.\n"
        : "Current reader review.\n",
    );
  }
  const retainedWriter = accepted.coverage.surfaces.find(
    (row: JsonObject) => row.id === "writer",
  )!;
  const retainedPath = path.join(output, retainedWriter.receiptRefs[0]);
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
    coverage: {
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
    [selectedRef, historicalRef].map((ref) => readFile(path.join(output, ref))),
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
    coverage: {
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
    assert.equal(accepted.coverage.surfaces.length, 2);
    const selected = accepted.coverage.surfaces.find(
      (row: JsonObject) => row.label === "Current anonymous review",
    );
    assert.deepEqual(selected.receiptRefs, [selectedRef]);
    assert.equal(selected.disposition, "no_issue_found");
    const writer = accepted.coverage.surfaces.find(
      (row: JsonObject) => row.id === "writer",
    );
    assert.deepEqual(writer.receiptRefs, ["artifacts/replacement.md"]);
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
        readFile(path.join(output, ref)),
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
        coverage: {
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
      if (reverse) old.coverage.surfaces.reverse();
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
            coverage: {
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
      assert.deepEqual(result.coverage.deferred, []);
      assert.equal(result.coverage.surfaces.length, candidate ? 1 : 2);
      assert.equal(result.findings.length, candidate ? 1 : 0);
      const kept = result.coverage.surfaces.find(
        (row: JsonObject) => row.id === keptId,
      );
      assert.deepEqual(kept.receiptRefs, [
        `artifacts/archived-receipts/attempt-01/${refs[keptId]}`,
      ]);
      assert.equal(
        await readFile(path.join(output, kept.receiptRefs[0]), "utf8"),
        await readFile(path.join(archive, refs[keptId]), "utf8"),
      );
      const repaired = result.coverage.surfaces.find(
        (row: JsonObject) => row.id === repairId,
      );
      if (candidate) assert.equal(repaired, undefined);
      else assert.deepEqual(repaired.receiptRefs, ["artifacts/replacement.md"]);
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
