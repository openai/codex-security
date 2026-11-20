import assert from "node:assert/strict";
import {
  cp,
  mkdir,
  readFile,
  readdir,
  rm,
  utimes,
  unlink,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { importSource } from "./import-module.ts";
import {
  workerHistoryFixture,
  workerDraft,
  reviewDraft,
  scanId,
} from "./scan-draft-fixture.ts";

const { readAcceptedDiscovery } = await importSource(
  fileURLToPath(
    new URL("../src/deep-scan/artifact-validation.ts", import.meta.url),
  ),
);
const {
  recordCodexSecurityWorkerScanDraft,
  readArchivedWorkerCheckpoints,
  parseScanDraft,
} = await importSource(
  fileURLToPath(new URL("../src/artifact-scan-draft.ts", import.meta.url)),
);
const { archiveDirectory, createDeepScanArtifacts } = await importSource(
  fileURLToPath(new URL("../src/deep-scan/artifacts.ts", import.meta.url)),
);

test("three actual cumulative worker attempts retain original coverage ownership", async (t) => {
  const f = await workerHistoryFixture(t, 3);

  for (const attempt of [1, 2, 3]) {
    await mkdir(f.output, { recursive: true });
    await f.record(
      reviewDraft(attempt === 3, {
        surfaces: [
          {
            id: `surface-${attempt}`,
            label: `Review ${attempt}`,
            disposition: "no_issue_found",
          },
        ],
      }),
    );
    if (attempt < 3)
      await f.archive(
        path.join(f.workerRoot, "attempts", `attempt-0${attempt}`),
      );
  }
  const source = (await f.readAccepted()).coverage;
  for (const attempt of [1, 2, 3]) {
    assert.equal(
      source.surfaces.find(
        (row: { label: string }) => row.label === `Review ${attempt}`,
      ).provenance.attempt,
      attempt,
    );
    assert.ok(
      source.reviews.some(
        (review: { attempt: number }) => review.attempt === attempt,
      ),
    );
  }
});

test("an accepted retry reconciles each occurrence of legacy ID-less surfaces and deferrals", async (t) => {
  const f = await workerHistoryFixture(t, 2);
  const task = { reason: "Synthetic pending review" };
  const single = { label: "Single review", disposition: "no_issue_found" };
  const repeated = { ...single, label: "Repeated review" };
  const named = { ...single, label: "Named review" };
  const mixed = { ...single, label: "Mixed IDs" };
  const archive = path.join(f.workerRoot, "attempts/attempt-01");
  await mkdir(archive, { recursive: true });
  await writeFile(
    path.join(archive, "result.json"),
    JSON.stringify({
      scanId,
      findings: [],
      complete: false,
      coverage: {
        completeness: "partial",
        surfaces: [
          single,
          repeated,
          repeated,
          { ...named, id: "prior" },
          mixed,
          { ...mixed, id: "known" },
        ],
        explicitExclusions: [],
        deferred: [task, { ...task, id: "saved" }],
      },
    }),
  );
  await writeFile(
    f.resultPath,
    JSON.stringify(
      reviewDraft(true, {
        surfaces: [
          { ...single, receiptRefs: [] },
          ...["first", "second", "third"].map((id) => ({ ...repeated, id })),
          { ...named, id: "current" },
          { ...mixed, id: "known" },
          { ...mixed, id: "assigned" },
        ],
        deferred: [task, { ...task, id: "assigned" }, task],
      }),
    ),
  );
  const { result, coverage } = await f.readAccepted();
  assert.deepEqual(
    coverage.deferred.map(
      (row: { provenance: { attempt: number } }) => row.provenance.attempt,
    ),
    [1, 1, 2],
  );
  assert.equal(result.reviewState.deferred[0].id, "saved");
  assert.equal(coverage.deferred[0].provenance.sourceId, undefined);
  assert.equal(coverage.deferred[1].provenance.sourceId, "assigned");
  assert.equal(coverage.deferred[2].provenance.sourceId, undefined);
  assert.deepEqual(
    coverage.surfaces.map(
      (row: { label: string; provenance: { attempt: number } }) => [
        row.label,
        row.provenance.attempt,
      ],
    ),
    [
      [single.label, 1],
      [repeated.label, 1],
      [repeated.label, 1],
      [repeated.label, 2],
      [named.label, 2],
      [mixed.label, 1],
      [mixed.label, 1],
      [named.label, 1],
    ],
  );
  assert.deepEqual(
    coverage.surfaces
      .slice(1)
      .map(
        (row: { provenance: { sourceId: string } }) => row.provenance.sourceId,
      ),
    ["first", "second", "third", "current", "known", "assigned", "prior"],
  );
});

for (const kind of ["candidate reservation", "generated reuse"] as const) {
  test(`saved generic task inference preserves ${kind}`, async (t) => {
    const f = await workerHistoryFixture(t, 2);
    const previous =
      kind === "candidate reservation"
        ? [{ id: "owned", reason: "Synthetic generic task" }]
        : [
            {
              reason: "Synthetic generated task",
              details: { second: 2, first: 1 },
            },
          ];
    const current =
      kind === "candidate reservation"
        ? [
            { reason: "Synthetic generic task" },
            { candidateId: "owned", reason: "Synthetic candidate task" },
          ]
        : [
            {
              reason: "Synthetic generated task",
              details: { first: 1, second: 2 },
            },
          ];
    const archive = path.join(f.workerRoot, "attempts/attempt-01/result.json");
    await mkdir(path.dirname(archive), { recursive: true });
    const saved = JSON.stringify({
      scanId,
      findings: [],
      complete: false,
      coverage: {
        completeness: "partial",
        surfaces: [],
        explicitExclusions: [],
        deferred: previous,
      },
    });
    const terminal = JSON.stringify(reviewDraft(true, { deferred: current }));
    await writeFile(archive, saved);
    await writeFile(f.resultPath, terminal);
    const { result, coverage } = await f.readAccepted();
    assert.equal(await readFile(archive, "utf8"), saved);
    assert.equal(await readFile(f.resultPath, "utf8"), terminal);
    const rows = result.reviewState.deferred;
    if (kind === "candidate reservation") {
      assert.equal(rows[0].reason, "Synthetic generic task");
      assert.notEqual(rows[0].id, "owned");
      assert.equal(
        rows.find(
          (row: { candidateId?: string }) => row.candidateId === "owned",
        )?.id,
        "owned",
      );
    } else {
      assert.equal(rows.length, 1);
      assert.equal(coverage.deferred.length, 1);
      assert.equal(coverage.deferred[0].provenance.attempt, 1);
      assert.equal(coverage.deferred[0].provenance.sourceId, undefined);
    }
  });
}

for (const field of ["surfaces", "deferred"] as const) {
  for (const checkpointOnly of [false, true]) {
    test(`accepted ${field} preserve authored identities, checkpoint only=${checkpointOnly}`, async (t) => {
      const f = await workerHistoryFixture(t, 2);
      const anonymous =
        field === "surfaces"
          ? { label: "Synthetic review", disposition: "no_issue_found" }
          : { reason: "Review the synthetic authentication boundary" };
      const rows = [anonymous, { ...anonymous, id: "authored-review" }];
      const coverage = {
        surfaces: [],
        explicitExclusions: [],
        deferred: [],
      };
      const result = JSON.stringify(
        workerDraft([], {
          complete: true,
          reviewState: { ...coverage, [field]: checkpointOnly ? [] : rows },
        }),
      );
      await writeFile(f.resultPath, result);
      const checkpoint = JSON.stringify(
        workerDraft([], {
          complete: false,
          reviewState: { ...coverage, [field]: checkpointOnly ? rows : [] },
        }),
      );
      const directory = path.join(f.output, "checkpoints");
      await mkdir(directory, { recursive: true });
      const checkpointPath = path.join(directory, "saved.json");
      await writeFile(checkpointPath, checkpoint);

      const accepted = await readAcceptedDiscovery(
        createDeepScanArtifacts(f.scanRoot),
        f.worker,
        scanId,
      );
      assert.deepEqual(
        accepted.coverage[field].map(
          (row: { provenance: { sourceId?: string } }) =>
            row.provenance.sourceId,
        ),
        [undefined, "authored-review"],
      );
      assert.equal(await readFile(f.resultPath, "utf8"), result);
      assert.equal(await readFile(checkpointPath, "utf8"), checkpoint);
    });
  }
}

for (const field of [
  "deferred",
  "explicitExclusions",
  "openQuestions",
] as const) {
  for (const sameText of [false, true]) {
    test(`accepted ${field} occurrences retain one source attempt each, same text=${sameText}`, async (t) => {
      const f = await workerHistoryFixture(t, 3);

      const archives: Array<[string, Buffer]> = [];
      for (const attempt of [1, 2, 3]) {
        const rows = Array.from({ length: attempt }, (_, index) => {
          const text = sameText
            ? "Synthetic proof"
            : `Synthetic proof ${index + 1}`;
          return field === "openQuestions"
            ? { question: text }
            : field === "explicitExclusions"
              ? { pattern: "synthetic/excluded/**", reason: text }
              : { reason: text };
        });
        await f.record(
          reviewDraft(true, {
            [field]: rows,
          }),
        );
        if (attempt < 3) {
          const archive = path.join(
            f.workerRoot,
            "attempts",
            `attempt-0${attempt}`,
          );
          await f.archive(archive);
          const result = path.join(archive, "result.json");
          archives.push([result, await readFile(result)]);
        }
      }
      const accepted = await readFile(f.resultPath);
      const source = (await f.readAccepted()).coverage;
      assert.equal(source[field].length, 3);
      assert.deepEqual(
        source[field].map(
          (row: { provenance: { attempt: number } }) => row.provenance.attempt,
        ),
        [1, 2, 3],
      );
      if (field === "deferred")
        assert.equal(
          new Set(source.deferred.map((row: { id: string }) => row.id)).size,
          3,
        );
      assert.deepEqual(await readFile(f.resultPath), accepted);
      for (const [result, bytes] of archives)
        assert.deepEqual(await readFile(result), bytes);
    });
  }
}

for (const id of ["opaque/review:shared", { section: "shared" }]) {
  test(`independent exclusions retain a shared ${typeof id} extension ID`, async (t) => {
    const f = await workerHistoryFixture(t, 3);

    for (const reason of [
      "Synthetic first exclusion.",
      "Synthetic independent exclusion.",
    ]) {
      await f.record(
        reviewDraft(true, {
          explicitExclusions: [
            { id, pattern: "synthetic/excluded/**", reason },
          ],
        }),
      );
    }
    const saved = JSON.parse(await readFile(f.resultPath, "utf8"));
    assert.deepEqual(
      saved.reviewState.explicitExclusions
        .map((row: { reason: string }) => row.reason)
        .sort(),
      ["Synthetic first exclusion.", "Synthetic independent exclusion."].sort(),
    );
    assert.deepEqual(
      saved.reviewState.explicitExclusions.map(
        (row: { id: unknown }) => row.id,
      ),
      [id, id],
    );
  });
}

test("readable retry origin survives one unsafe unrelated archive", async (t) => {
  const f = await workerHistoryFixture(t, 3);

  await f.record(
    reviewDraft(false, {
      surfaces: [
        {
          id: "saved-review",
          label: "Synthetic retained review",
          disposition: "no_issue_found",
        },
      ],
    }),
  );
  const archive = path.join(f.workerRoot, "attempts/attempt-01");
  await f.archive(archive);
  await f.record(reviewDraft(true));
  const current = await readFile(f.resultPath);
  const historical = await readFile(path.join(archive, "result.json"));
  await mkdir(
    path.join(f.workerRoot, "attempts/attempt-02/checkpoint-head.json"),
    { recursive: true },
  );
  await assert.rejects(
    readArchivedWorkerCheckpoints(f.workerContext),
    /archived checkpoint head is not a safe file/,
  );
  const source = await f.readAccepted();
  assert.equal(source.coverage.surfaces.length, 1);
  assert.equal(source.coverage.surfaces[0].provenance.attempt, 1);
  assert.deepEqual(await readFile(f.resultPath), current);
  assert.deepEqual(
    await readFile(path.join(archive, "result.json")),
    historical,
  );
});

test("retry coverage ignores projected origin claims and rejects invalid archived paths", async (t) => {
  const f = await workerHistoryFixture(t, 3);
  const row = {
    reason: "Retained review",
    provenance: { note: "Worker note" },
  };
  const draft = reviewDraft(true, {
    surfaces: [],
    explicitExclusions: [],
    deferred: [row],
  });
  await mkdir(f.output, { recursive: true });
  await writeFile(f.resultPath, JSON.stringify(draft));
  for (const attempt of [1, 2]) {
    const saved = structuredClone(draft);
    Object.assign(
      saved.reviewState.deferred[0]!,
      attempt === 1
        ? {
            provenance: {
              note: "Worker note",
              workerId: "stale",
              attempt: 9,
              sourceId: "stale",
              candidateId: "stale",
            },
          }
        : { paths: ["../outside"] },
    );
    const archive = path.join(f.workerRoot, "attempts", "attempt-0" + attempt);
    await mkdir(archive, { recursive: true });
    await writeFile(path.join(archive, "result.json"), JSON.stringify(saved));
  }
  const { coverage } = await f.readAccepted();
  assert.equal(coverage.deferred.length, 1, JSON.stringify(coverage.deferred));
  assert.equal(coverage.deferred[0].provenance.attempt, 1);
  assert.equal(coverage.deferred[0].provenance.note, "Worker note");
});

test("archived shared receipts follow the surface's reference order", async (t) => {
  const f = await workerHistoryFixture(t, 2);
  const receiptRefs = [
    "artifacts/review/nested/first.txt",
    "artifacts/second.txt",
  ];
  for (const ref of receiptRefs) {
    const file = path.join(f.scanRoot, ref);
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, "Synthetic review receipt.\n");
  }
  const checkpoint = reviewDraft(false, {
    surfaces: [
      {
        id: "saved-review",
        label: "Synthetic retained review",
        disposition: "no_issue_found",
        receiptRefs,
        provenance: { scanReceiptRefs: [receiptRefs[1]] },
      },
    ],
  });
  const directory = path.join(f.workerRoot, "attempts/attempt-01/checkpoints");
  await mkdir(directory, { recursive: true });
  await writeFile(
    path.join(directory, "saved.json"),
    JSON.stringify(checkpoint),
  );

  const [saved] = await readArchivedWorkerCheckpoints(f.workerContext);
  assert.deepEqual(
    saved.input.reviewState.surfaces[0].provenance.scanReceiptRefs,
    receiptRefs,
  );
});

test("current typed checkpoint receipt aliases retain one source observation", async (t) => {
  const f = await workerHistoryFixture(t, 1);
  const surface = {
    label: "Synthetic current evidence",
    disposition: "no_issue_found",
    receiptRefs: ["artifacts/evidence.txt"],
  };
  await mkdir(path.join(f.output, "artifacts"));
  await writeFile(
    path.join(f.output, surface.receiptRefs[0]!),
    "Synthetic evidence",
  );
  await recordCodexSecurityWorkerScanDraft(
    f.workerContext,
    workerDraft([], {
      complete: false,
      reviewState: {
        surfaces: [{ ...surface, id: "saved-review" }],
        explicitExclusions: [],
        deferred: [],
      },
    }),
  );
  const checkpointDirectory = path.join(f.output, "checkpoints");
  const checkpoints = await Promise.all(
    (await readdir(checkpointDirectory)).map(async (name) => {
      const file = path.join(checkpointDirectory, name);
      return [file, await readFile(file, "utf8")] as const;
    }),
  );
  const current = JSON.stringify(
    workerDraft([], {
      complete: true,
      reviewState: {
        surfaces: [surface],
        explicitExclusions: [],
        deferred: [],
      },
    }),
  );
  await writeFile(f.resultPath, current);
  const { coverage } = await readAcceptedDiscovery(
    createDeepScanArtifacts(f.scanRoot),
    f.worker,
    scanId,
  );
  assert.equal(coverage.surfaces.length, 1);
  assert.equal(coverage.surfaces[0].provenance.attempt, 1);
  assert.equal(coverage.surfaces[0].provenance.sourceId, undefined);
  assert.equal(await readFile(f.resultPath, "utf8"), current);
  for (const [file, bytes] of checkpoints)
    assert.equal(await readFile(file, "utf8"), bytes);
});

for (const changedReceipt of [false, true]) {
  test(`legacy surface identity follows receipt bytes, changed=${changedReceipt}`, async (t) => {
    const f = await workerHistoryFixture(t, 2);
    const archive = path.join(f.workerRoot, "attempts/attempt-01");
    const row = {
      label: "Synthetic evidence review",
      disposition: "no_issue_found",
      receiptRefs: ["artifacts/evidence.txt"],
    };
    for (const directory of [archive, f.output]) {
      await mkdir(path.join(directory, "artifacts"), { recursive: true });
      await writeFile(
        path.join(directory, row.receiptRefs[0]!),
        changedReceipt && directory === f.output
          ? "Changed evidence"
          : "Original evidence",
      );
    }
    const old = JSON.stringify(
      workerDraft([], {
        complete: false,
        reviewState: { surfaces: [row], explicitExclusions: [], deferred: [] },
      }),
    );
    const current = JSON.stringify(
      workerDraft([], {
        complete: true,
        reviewState: {
          surfaces: [{ ...row, id: "review" }],
          explicitExclusions: [],
          deferred: [],
        },
      }),
    );
    const archived = path.join(archive, "result.json");
    await writeFile(archived, old);
    await writeFile(f.resultPath, current);
    const { coverage } = await readAcceptedDiscovery(
      createDeepScanArtifacts(f.scanRoot),
      f.worker,
      scanId,
    );
    assert.equal(coverage.surfaces.length, changedReceipt ? 2 : 1);
    assert.equal(
      coverage.surfaces[0].provenance.attempt,
      changedReceipt ? 2 : 1,
    );
    assert.equal(coverage.surfaces[0].provenance.sourceId, "review");
    assert.equal(await readFile(archived, "utf8"), old);
    assert.equal(await readFile(f.resultPath, "utf8"), current);
  });
}

for (const currentId of [undefined, "different-review"]) {
  test(`legacy terminal deferral keeps its saved identity, current id=${currentId}`, async (t) => {
    const f = await workerHistoryFixture(t, 2);
    const task = { reason: "Review synthetic authentication" };
    const archive = path.join(f.workerRoot, "attempts/attempt-01");
    await mkdir(archive, { recursive: true });
    const old = JSON.stringify(
      workerDraft([], {
        complete: false,
        reviewState: {
          surfaces: [],
          explicitExclusions: [],
          deferred: [{ ...task, id: "saved-review" }],
        },
      }),
    );
    const current = JSON.stringify(
      workerDraft([], {
        complete: true,
        reviewState: {
          surfaces: [],
          explicitExclusions: [],
          deferred: [
            { ...task, ...(currentId === undefined ? {} : { id: currentId }) },
          ],
        },
      }),
    );
    await writeFile(path.join(archive, "result.json"), old);
    await writeFile(f.resultPath, current);
    const { coverage } = await readAcceptedDiscovery(
      createDeepScanArtifacts(f.scanRoot),
      f.worker,
      scanId,
    );
    assert.deepEqual(
      coverage.deferred.map(
        (row: { provenance: { attempt: number; sourceId?: string } }) => [
          row.provenance.attempt,
          row.provenance.sourceId,
        ],
      ),
      currentId === undefined
        ? [[1, undefined]]
        : [
            [2, currentId],
            [1, "saved-review"],
          ],
    );
    assert.equal(
      await readFile(path.join(archive, "result.json"), "utf8"),
      old,
    );
    assert.equal(await readFile(f.resultPath, "utf8"), current);
  });
}

for (const [identical, contracted] of [
  [false, false],
  [true, false],
  [true, true],
  [false, true],
] as const) {
  test(`accepted duplicate surface IDs retain each authored occurrence, identical=${identical}, contracted=${contracted}`, async (t) => {
    const f = await workerHistoryFixture(t, 2);
    const surfaces = [
      "First review",
      identical ? "First review" : "Second review",
    ].map((label) => ({
      id: "api",
      label,
      disposition: "no_issue_found",
      receiptRefs: [],
    }));
    const archive = path.join(f.workerRoot, "attempts/attempt-01");
    await mkdir(archive, { recursive: true });
    const draft = workerDraft([], {
      complete: true,
      reviewState: { surfaces, explicitExclusions: [], deferred: [] },
    });
    const old = JSON.stringify({
      ...draft,
      complete: false,
      reviewState: {
        ...draft.reviewState,
        surfaces: identical && !contracted ? surfaces.slice(0, 1) : surfaces,
      },
    });
    const current = JSON.stringify({
      ...draft,
      reviewState: {
        ...draft.reviewState,
        surfaces: contracted ? surfaces.slice(1) : surfaces,
      },
    });
    await writeFile(path.join(archive, "result.json"), old);
    await writeFile(f.resultPath, current);
    const { coverage } = await readAcceptedDiscovery(
      createDeepScanArtifacts(f.scanRoot),
      f.worker,
      scanId,
    );
    assert.deepEqual(
      coverage.surfaces.map(
        (row: { provenance: { sourceId: string; attempt: number } }) => [
          row.provenance.sourceId,
          row.provenance.attempt,
        ],
      ),
      [
        ["api", 1],
        ["api", identical && !contracted ? 2 : 1],
      ],
    );
    assert.deepEqual(
      coverage.surfaces.map((row: { label: string }) => row.label).sort(),
      surfaces.map((row) => row.label).sort(),
    );
    assert.equal(
      new Set(coverage.surfaces.map((row: { id: string }) => row.id)).size,
      2,
    );
    assert.equal(
      await readFile(path.join(archive, "result.json"), "utf8"),
      old,
    );
    assert.equal(await readFile(f.resultPath, "utf8"), current);
  });
}

for (const shadow of [
  "absent",
  "unreferenced",
  "authored-local",
  "pending-local",
]) {
  test(`accepted closeout retains inherited receipt ownership, shadow=${shadow}`, async (t) => {
    const f = await workerHistoryFixture(t, 2);
    const pending = shadow === "pending-local";
    const localAuthored = shadow === "authored-local" || pending;
    const remaining = {
      id: "remaining",
      reason: "Remaining review",
      surfaceIds: ["scope"],
    };
    const shared = "artifacts/shared.txt",
      local = "artifacts/local.txt";
    await mkdir(path.join(f.scanRoot, "artifacts"), { recursive: true });
    await writeFile(path.join(f.scanRoot, shared), "Scan-owned evidence");
    await recordCodexSecurityWorkerScanDraft(
      f.workerContext,
      workerDraft([], {
        complete: false,
        reviewState: {
          surfaces: [
            {
              id: "scope",
              label: "Synthetic scope",
              disposition: "needs_follow_up",
              receiptRefs: [shared],
            },
          ],
          explicitExclusions: [],
          deferred: [
            { id: "task", reason: "Synthetic review", surfaceIds: ["scope"] },
            ...(pending ? [remaining] : []),
          ],
        },
      }),
    );
    await mkdir(path.join(f.output, "artifacts"), { recursive: true });
    await writeFile(path.join(f.output, local), "Local evidence");
    if (shadow !== "absent")
      await writeFile(path.join(f.output, shared), "Local shadow");
    const current = JSON.stringify(
      workerDraft([], {
        complete: true,
        reviewState: {
          surfaces: [
            {
              id: "scope",
              label: "Synthetic scope",
              disposition: "no_issue_found",
              receiptRefs: localAuthored ? [local, shared] : [local],
            },
          ],
          explicitExclusions: [],
          deferred: pending ? [remaining] : [],
          resolvedDeferred: [
            { id: "task", reason: "Synthetic review complete" },
          ],
        },
      }),
    );
    await writeFile(f.resultPath, current);
    const checkpoints = await Promise.all(
      (await readdir(path.join(f.output, "checkpoints"))).map(async (name) => {
        const file = path.join(f.output, "checkpoints", name);
        return [file, await readFile(file)] as const;
      }),
    );
    const { coverage } = await readAcceptedDiscovery(
      createDeepScanArtifacts(f.scanRoot),
      f.worker,
      scanId,
    );
    assert.equal(coverage.surfaces.length, 1);
    assert.equal(
      coverage.surfaces[0].disposition,
      pending ? "needs_follow_up" : "no_issue_found",
    );
    assert.deepEqual(
      await Promise.all(
        coverage.surfaces[0].receiptRefs.map((ref: string) =>
          readFile(path.join(f.scanRoot, ref), "utf8"),
        ),
      ),
      [
        "Local evidence",
        localAuthored ? "Local shadow" : "Scan-owned evidence",
      ],
    );
    assert.equal(await readFile(f.resultPath, "utf8"), current);
    for (const [file, bytes] of checkpoints)
      assert.deepEqual(await readFile(file), bytes);
  });
}

for (const [field, change] of [
  ["surfaces", "reordered"],
  ["surfaces", "omitted"],
  ["surfaces", "added"],
  ["surfaces", "changed"],
  ["surfaces", "anonymous"],
  ["surfaces", "checkpoint"],
  ["surfaces", "checkpoint-only-names"],
  ["deferred", "reordered"],
] as const) {
  test(`accepted ${field} keep established retry lineage, ${change}`, async (t) => {
    const f = await workerHistoryFixture(t, 3);
    const item =
      field === "surfaces"
        ? { label: "Synthetic review", disposition: "no_issue_found" }
        : { reason: "Complete the synthetic review" };
    const alpha = { ...item, id: "alpha" };
    const beta = { ...item, id: "beta" };
    const coverage = { surfaces: [], explicitExclusions: [], deferred: [] };
    const archive = path.join(f.workerRoot, "attempts/attempt-01/result.json");
    await mkdir(path.dirname(archive), { recursive: true });
    await writeFile(
      archive,
      JSON.stringify({
        scanId,
        findings: [],
        complete: false,
        coverage: {
          ...coverage,
          completeness: "partial",
          [field]: [change === "anonymous" ? alpha : item],
        },
      }),
    );
    const checkpoint =
      change === "checkpoint" || change === "checkpoint-only-names";
    if (checkpoint) {
      if (change === "checkpoint-only-names")
        await recordCodexSecurityWorkerScanDraft(
          f.workerContext,
          workerDraft([], {
            complete: false,
            reviewState: { ...coverage, [field]: [alpha] },
          }),
        );
      await recordCodexSecurityWorkerScanDraft(
        f.workerContext,
        workerDraft([], {
          complete: false,
          reviewState: { ...coverage, [field]: [beta, alpha] },
        }),
      );
      for (const name of await readdir(path.join(f.output, "checkpoints")))
        await utimes(path.join(f.output, "checkpoints", name), 100, 100);
      await utimes(path.join(f.output, "checkpoint-head.json"), 300, 300);
    }
    await writeFile(
      f.resultPath,
      JSON.stringify(
        workerDraft([], {
          complete: true,
          reviewState: {
            ...coverage,
            [field]:
              change === "anonymous"
                ? [item]
                : change === "checkpoint-only-names"
                  ? []
                  : [alpha, beta],
          },
        }),
      ),
    );
    if (checkpoint) await utimes(f.resultPath, 200, 200);
    const baseline = await readAcceptedDiscovery(
      createDeepScanArtifacts(f.scanRoot),
      { ...f.worker, attempt: 2 },
      scanId,
    );
    const identities = (
      rows: { provenance: { sourceId?: string; attempt: number } }[],
    ) =>
      rows.map(({ provenance }) => [provenance.sourceId, provenance.attempt]);
    assert.deepEqual(
      identities(baseline.coverage[field]),
      change === "anonymous"
        ? [[undefined, 1]]
        : change === "checkpoint-only-names"
          ? [
              ["beta", 1],
              ["alpha", 2],
            ]
          : [
              ["alpha", 1],
              ["beta", 2],
            ],
    );
    const second = path.join(f.workerRoot, "attempts/attempt-02");
    await archiveDirectory(f.output, second);
    await mkdir(f.output, { recursive: true });
    const current =
      change === "anonymous"
        ? [alpha]
        : change === "checkpoint-only-names"
          ? [alpha, beta]
          : change === "omitted"
            ? [beta]
            : change === "added"
              ? [beta, { ...item, id: "gamma" }]
              : change === "changed"
                ? [{ ...beta, label: "Changed review" }, alpha]
                : [beta, alpha];
    await writeFile(
      f.resultPath,
      JSON.stringify(
        workerDraft([], {
          complete: true,
          reviewState: { ...coverage, [field]: current },
        }),
      ),
    );
    const paths = [archive, path.join(second, "result.json"), f.resultPath];
    if (checkpoint)
      paths.push(
        path.join(second, "checkpoint-head.json"),
        ...(await readdir(path.join(second, "checkpoints"))).map((name) =>
          path.join(second, "checkpoints", name),
        ),
      );
    const originals = await Promise.all(
      paths.map((file) => readFile(file, "utf8")),
    );
    const accepted = await readAcceptedDiscovery(
      createDeepScanArtifacts(f.scanRoot),
      f.worker,
      scanId,
    );
    const expected =
      change === "anonymous"
        ? [["alpha", 1]]
        : change === "added"
          ? [
              ["alpha", 1],
              ["beta", 2],
              ["gamma", 3],
            ]
          : change === "checkpoint-only-names"
            ? [
                ["alpha", 2],
                ["beta", 1],
              ]
            : [
                ["alpha", 1],
                ["beta", change === "changed" ? 3 : 2],
              ];
    assert.deepEqual(identities(accepted.coverage[field]).sort(), expected);
    assert.deepEqual(
      await Promise.all(paths.map((file) => readFile(file, "utf8"))),
      originals,
    );
  });
}

for (const history of ["removed", "invalid", "none"]) {
  test(`accepted closure survives unavailable optional history: ${history}`, async (t) => {
    const f = await workerHistoryFixture(t, 2);
    const state = { surfaces: [], explicitExclusions: [], deferred: [] };
    if (history !== "none") {
      await recordCodexSecurityWorkerScanDraft(
        f.workerContext,
        workerDraft([], { complete: false, reviewState: state }),
      );
    }
    await recordCodexSecurityWorkerScanDraft(
      f.workerContext,
      workerDraft([], {
        complete: false,
        reviewState: {
          ...state,
          deferred: [{ id: "task", reason: "Review the synthetic scope" }],
        },
      }),
    );
    const head = JSON.parse(
      await readFile(path.join(f.output, "checkpoint-head.json"), "utf8"),
    );
    const pending = path.join(f.output, "checkpoints", head.checkpoint);
    if (history === "invalid") await writeFile(pending, "invalid checkpoint");
    else await rm(pending);
    const result = JSON.stringify(
      workerDraft([], {
        complete: true,
        reviewState: {
          ...state,
          resolvedDeferred: [{ id: "task", reason: "Review completed" }],
        },
      }),
    );
    await writeFile(f.resultPath, result);
    const saved = await Promise.all(
      (await readdir(path.join(f.output, "checkpoints"))).map(async (name) => {
        const file = path.join(f.output, "checkpoints", name);
        return [file, await readFile(file)] as const;
      }),
    );
    const accepted = await readAcceptedDiscovery(
      createDeepScanArtifacts(f.scanRoot),
      f.worker,
      scanId,
      {},
      "previously-accepted",
    );
    assert.deepEqual(accepted.coverage.deferred, []);
    assert.deepEqual(
      accepted.result.reviewState.resolvedDeferred.map(
        (row: { id: string }) => row.id,
      ),
      ["task"],
    );
    if (history !== "none") {
      await assert.rejects(
        readAcceptedDiscovery(
          createDeepScanArtifacts(f.scanRoot),
          f.worker,
          scanId,
        ),
        /names no saved generic deferral/,
      );
    }
    assert.equal(await readFile(f.resultPath, "utf8"), result);
    for (const [file, original] of saved)
      assert.deepEqual(await readFile(file), original);
  });
}

for (const copies of [1, 2]) {
  for (const observation of [
    "copied-selected",
    "copied-unselected",
    "reselected",
  ]) {
    test(`retry keeps checkpoint chronology: ${observation}, copies=${copies}`, async (t) => {
      const f = await workerHistoryFixture(t, copies + 1);
      const state = { surfaces: [], explicitExclusions: [], deferred: [] };
      await recordCodexSecurityWorkerScanDraft(
        f.workerContext,
        workerDraft([], {
          complete: false,
          reviewState: {
            ...state,
            deferred: [{ id: "task", reason: "Review the synthetic scope" }],
          },
        }),
      );
      const headPath = path.join(f.output, "checkpoint-head.json");
      const head = JSON.parse(await readFile(headPath, "utf8"));
      const checkpoint = path.join(f.output, "checkpoints", head.checkpoint);
      await utimes(checkpoint, 1.00025, 1.00025);
      await utimes(headPath, 2.00025, 2.00025);
      const closed = JSON.stringify(
        workerDraft([], {
          complete: true,
          reviewState: {
            ...state,
            resolvedDeferred: [{ id: "task", reason: "Review completed" }],
          },
        }),
      );
      await writeFile(f.resultPath, closed);
      await utimes(f.resultPath, 3, 3);
      const archive = path.join(f.workerRoot, "attempts/attempt-01");
      await mkdir(path.dirname(archive), { recursive: true });
      await cp(f.output, archive, {
        recursive: true,
        preserveTimestamps: true,
      });
      const result = JSON.stringify(
        workerDraft([], { complete: true, reviewState: state }),
      );
      await writeFile(f.resultPath, result);
      await utimes(f.resultPath, 4, 4);
      if (copies === 2) {
        await cp(f.output, path.join(f.workerRoot, "attempts/attempt-02"), {
          recursive: true,
          preserveTimestamps: true,
        });
        await writeFile(f.resultPath, result);
        await utimes(f.resultPath, 4.5, 4.5);
      }
      if (observation === "copied-unselected") await rm(headPath);
      if (observation === "reselected") await utimes(headPath, 5, 5);
      const checkpointBytes = await readFile(checkpoint);
      const { coverage, result: acceptedResult } = await readAcceptedDiscovery(
        createDeepScanArtifacts(f.scanRoot),
        f.worker,
        scanId,
      );
      const pending = observation === "reselected";
      assert.equal(coverage.deferred.length, pending ? 1 : 0);
      assert.equal((coverage.resolvedDeferred ?? []).length, pending ? 0 : 1);
      assert.equal(
        (pending
          ? acceptedResult.reviewState.deferred
          : acceptedResult.reviewState.resolvedDeferred)[0].id,
        "task",
      );
      assert.equal(await readFile(f.resultPath, "utf8"), result);
      assert.equal(
        await readFile(path.join(archive, "result.json"), "utf8"),
        closed,
      );
      assert.deepEqual(await readFile(checkpoint), checkpointBytes);
      assert.deepEqual(
        await readFile(path.join(archive, "checkpoints", head.checkpoint)),
        checkpointBytes,
      );
    });
  }
}

for (const [reservedSuffix, completed, reversed, roundtrip] of [
  [false, false, false, false],
  [false, true, false, false],
  [true, false, false, false],
  [true, true, false, false],
  [false, false, true, false],
  [false, false, false, true],
]) {
  test(`typed retry preserves duplicate surface occurrences (reserved=${reservedSuffix}, completed=${completed}, reversed=${reversed}, roundtrip=${roundtrip})`, async (t) => {
    const f = await workerHistoryFixture(t, roundtrip ? 3 : 2);
    const surfaces = [
      {
        id: "api",
        label: "First review",
        disposition: "no_issue_found",
        receiptRefs: [],
      },
      {
        id: "api",
        label: "Second review",
        disposition: completed ? "needs_follow_up" : "no_issue_found",
        receiptRefs: [],
      },
      ...(reservedSuffix
        ? [
            {
              id: "api-2",
              label: "Reserved identity",
              disposition: "no_issue_found",
              receiptRefs: [],
            },
          ]
        : []),
    ];
    const archived = path.join(f.workerRoot, "attempts/attempt-1/result.json");
    await mkdir(path.dirname(archived), { recursive: true });
    await writeFile(
      archived,
      JSON.stringify(
        workerDraft([], {
          complete: true,
          reviewState: { surfaces, explicitExclusions: [], deferred: [] },
        }),
      ),
    );
    const current = surfaces.map((surface) => ({
      ...surface,
      disposition: "no_issue_found",
    }));
    if (reversed) current.reverse();
    await recordCodexSecurityWorkerScanDraft(
      f.workerContext,
      workerDraft([], {
        complete: true,
        reviewState: {
          surfaces: current,
          explicitExclusions: [],
          deferred: [],
        },
      }),
    );
    const written = JSON.parse(await readFile(f.resultPath, "utf8"));
    assert.deepEqual(
      written.reviewState.surfaces.map((surface: { id: string }) => surface.id),
      reservedSuffix ? ["api", "api-3", "api-2"] : ["api", "api-2"],
    );
    const files = [archived, f.resultPath];
    if (roundtrip) {
      const second = path.join(f.workerRoot, "attempts/attempt-2");
      await archiveDirectory(f.output, second);
      files.push(path.join(second, "result.json"));
      await writeFile(
        f.resultPath,
        JSON.stringify(
          workerDraft([], {
            complete: true,
            reviewState: {
              surfaces: current,
              explicitExclusions: [],
              deferred: [],
            },
          }),
        ),
      );
    }
    const original = await Promise.all(files.map((file) => readFile(file)));
    const accepted = (
      await readAcceptedDiscovery(
        createDeepScanArtifacts(f.scanRoot),
        f.worker,
        scanId,
      )
    ).coverage;
    assert.equal(accepted.surfaces.length, surfaces.length);
    assert.deepEqual(
      accepted.surfaces.map((surface: { label: string }) => surface.label),
      current.map((surface) => surface.label),
    );
    assert.ok(
      accepted.surfaces.every(
        (surface: { disposition: string }) =>
          surface.disposition === "no_issue_found",
      ),
    );
    assert.deepEqual(
      accepted.surfaces.map(
        (surface: { provenance: { attempt: number } }) =>
          surface.provenance.attempt,
      ),
      current.map(({ label }) =>
        completed && label === "Second review" ? 2 : 1,
      ),
    );
    assert.deepEqual(
      await Promise.all(files.map((file) => readFile(file))),
      original,
    );
  });
}

test("writer IDs match shared surface comparison fixtures", async () => {
  const cases = JSON.parse(
    await readFile(
      new URL(
        "../../tests/fixtures/surface-normalization.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  for (const fixture of cases) {
    const input = workerDraft([], {
      complete: true,
      reviewState: {
        surfaces: fixture.surfaces,
        explicitExclusions: [],
        deferred: [],
      },
    });
    const before = JSON.stringify(input);
    const parsed = parseScanDraft(input);
    assert.deepEqual(
      parsed.reviewState.surfaces.map((row: { id: string }) => row.id),
      fixture.ids,
      fixture.case,
    );
    assert.equal(JSON.stringify(input), before);
  }
});

test("typed retry keeps named occurrence priority beside an older anonymous surface", async (t) => {
  const f = await workerHistoryFixture(t, 3);
  const anonymous = {
    label: "First synthetic review",
    disposition: "no_issue_found",
    receiptRefs: [],
  };
  const named = { ...anonymous, id: "api" };
  const artifacts = createDeepScanArtifacts(f.scanRoot);
  const files: string[] = [];
  for (const attempt of [1, 2]) {
    await mkdir(f.output, { recursive: true });
    await writeFile(
      f.resultPath,
      JSON.stringify(
        workerDraft([], {
          complete: true,
          reviewState: {
            surfaces: attempt === 1 ? [anonymous] : [anonymous, named, named],
            explicitExclusions: [],
            deferred: [],
          },
        }),
      ),
    );
    const accepted = (
      await readAcceptedDiscovery(artifacts, { ...f.worker, attempt }, scanId)
    ).coverage;
    assert.deepEqual(
      accepted.surfaces.map(
        (row: { provenance: { attempt: number } }) => row.provenance.attempt,
      ),
      attempt === 1 ? [1] : [1, 2, 2],
    );
    const archived = path.join(f.workerRoot, "attempts", `attempt-${attempt}`);
    await archiveDirectory(f.output, archived);
    files.push(path.join(archived, "result.json"));
  }
  await mkdir(f.output, { recursive: true });
  await recordCodexSecurityWorkerScanDraft(
    f.workerContext,
    workerDraft([], {
      complete: true,
      reviewState: {
        surfaces: [named, named, anonymous],
        explicitExclusions: [],
        deferred: [],
      },
    }),
  );
  files.push(f.resultPath);
  const before = await Promise.all(files.map((file) => readFile(file)));
  const accepted = (await readAcceptedDiscovery(artifacts, f.worker, scanId))
    .coverage;
  assert.deepEqual(
    accepted.surfaces.map(
      (row: { provenance: { sourceId: string; attempt: number } }) => [
        row.provenance.sourceId,
        row.provenance.attempt,
      ],
    ),
    [
      ["api", 2],
      ["api-2", 2],
      ["surface-48521adab43e8a78", 1],
    ],
  );
  assert.deepEqual(
    await Promise.all(files.map((file) => readFile(file))),
    before,
  );
});
for (const ref of [
  "artifacts/review.txt",
  "artifacts/./review.txt",
  "artifacts//review.txt",
]) {
  for (const state of ["copied", "changed", "missing-archive"]) {
    test(`supported typed writer receipt origin (${ref}, ${state})`, async (t) => {
      const f = await workerHistoryFixture(t, 2);
      const { workerRoot, output, resultPath } = f;
      await mkdir(path.join(output, "artifacts"), { recursive: true });
      await writeFile(
        path.join(output, "artifacts/review.txt"),
        "Synthetic original receipt.\n",
      );
      const draft = reviewDraft(false, {
        surfaces: [
          {
            label: "Synthetic receipt review",
            disposition: "needs_follow_up",
            receiptRefs: [ref],
          },
        ],
      });
      await f.record(draft);
      const saved = JSON.parse(await readFile(resultPath, "utf8"));
      assert.equal(
        typeof saved.reviewState.surfaces[0].id,
        "string",
        "typed writer assigns implicit ID before retry snapshot",
      );
      const archive = path.join(workerRoot, "attempts/attempt-01");
      await cp(output, archive, {
        recursive: true,
        preserveTimestamps: true,
      });
      const archivedBytes = await readFile(path.join(archive, "result.json"));
      if (state === "changed")
        await writeFile(
          path.join(output, "artifacts/review.txt"),
          "Synthetic changed receipt.\n",
        );
      if (state === "missing-archive")
        await unlink(path.join(archive, "artifacts/review.txt"));
      await f.record({
        ...draft,
        complete: true,
      });
      const current = JSON.parse(await readFile(resultPath, "utf8"));
      assert.equal(
        current.reviewState.surfaces.length,
        1,
        "supported resumed writer retains one matching normalized surface",
      );
      assert.equal(
        current.reviewState.surfaces[0].id,
        saved.reviewState.surfaces[0].id,
      );
      assert.deepEqual(
        current.reviewState.surfaces[0].receiptRefs,
        saved.reviewState.surfaces[0].receiptRefs,
      );
      const resultBytes = await readFile(resultPath);
      const worker = await f.readAccepted();
      const surface = worker.coverage.surfaces[0];
      assert.equal(
        surface.provenance.attempt,
        state === "copied" ? 1 : 2,
        "identical readable receipt retains original attempt; changed/missing evidence retains current attempt",
      );
      assert.deepEqual(
        await readFile(path.join(archive, "result.json")),
        archivedBytes,
      );
      assert.deepEqual(await readFile(resultPath), resultBytes);
    });
  }
}
