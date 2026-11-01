import { readJson } from "./support/json.ts";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { copyFile, mkdir, writeFile, readdir, utimes } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { importSource } from "./import-module.ts";
import {
  draftFixture,
  interruptDraftWrite,
  interruptDraftAfterRaw,
} from "./scan-draft-recovery-fixture.ts";
import {
  type FixtureFinding,
  type RecoveredFinding,
  finding,
  recoveryPair,
  savedWorker,
  dateDraftFiles,
} from "./scan-identity-recovery-fixture.ts";

const replayWithProvenance = {
  details: true,
  replay: true,
  provenanceDetails: true,
};

// Publish independently so a location-dependent identity remains observable.
async function publishedPair(
  t: Parameters<typeof recoveryPair>[0],
  layout: "standard" | "deep",
  findings: FixtureFinding[],
  { complete = false, scoped = false, time = 100 } = {},
) {
  const pair = await recoveryPair(t, layout);
  const { normal, recovered } = pair;
  for (const target of [normal, recovered]) {
    if (scoped) {
      target.context.scope = "src";
      (
        target.context.targetContract!.scope as Record<string, unknown>
      ).requiredIncludePaths = ["src"];
    }
    await target.writeFindings(findings, { complete });
    await dateDraftFiles(target.root, time);
  }
  return pair;
}

async function terminalAt(
  { normal, recovered, recover }: Awaited<ReturnType<typeof recoveryPair>>,
  findings: FixtureFinding[],
  time: number,
  cut: "raw input" | "committed head",
) {
  const checkpoints = path.join(recovered.root, "checkpoints");
  const original = new Set(await readdir(checkpoints));
  await normal.writeFindings(findings, { complete: true });
  const input = recovered.findingsDraft(findings, { complete: true });
  if (cut === "raw input") await recovered.checkpoint(input);
  else
    await interruptDraftWrite(recovered.findingsPath, () =>
      recovered.write(input),
    );
  for (const name of await readdir(checkpoints))
    if (!original.has(name))
      await utimes(path.join(checkpoints, name), time, time);
  if (cut === "committed head")
    await utimes(path.join(recovered.root, "checkpoint-head.json"), time, time);
  return recover(replayWithProvenance);
}

for (const authored of [false, true]) {
  for (const owner of [undefined, "reviewer"]) {
    for (const changedCandidate of [false, true]) {
      test(`parent and moved worker keep publication identities on frozen retry (authored=${authored}, owner=${owner ?? "omitted"}, changedCandidate=${changedCandidate})`, async (t) => {
        const first = finding("Review", {
          ...(authored ? { identity: { anchor: "review" } } : {}),
          provenance: {
            source: "local_plugin",
            ...(owner ? { workerId: owner } : {}),
            ...(changedCandidate ? { candidateId: "candidate-a" } : {}),
          },
        });
        const revised = {
          ...first,
          summary: "Second synthetic location.",
          locations: [{ path: "src/example.py", startLine: 2 }],
          provenance: { source: "local_plugin", candidateId: "candidate-b" },
        };
        const { normal, recovered, recover } = await publishedPair(t, "deep", [
          first,
        ]);
        const workerRoot = path.join(recovered.root, "reviewer");
        await mkdir(workerRoot);
        const worker = draftFixture(workerRoot, "worker");
        await worker.checkpoint(worker.findingsDraft([first]));
        await dateDraftFiles(workerRoot, 50);
        await writeFile(
          path.join(workerRoot, "result.json"),
          JSON.stringify(worker.findingsDraft([revised])),
        );
        await normal.writeFindings(
          [
            first,
            {
              ...revised,
              provenance: { ...revised.provenance, workerId: "reviewer" },
            },
          ],
          { complete: true },
        );
        const result = await recover({
          workers: [savedWorker(workerRoot, "reviewer", "succeeded")],
          details: true,
          replay: true,
        });
        const byEvidence = (rows: RecoveredFinding[]) =>
          new Map(rows.map((row) => [row.summary, row]));
        assert.equal(result.normal.length, 2);
        assert.equal(result.recovered.length, 2);
        assert.deepEqual(
          byEvidence(result.recovered),
          byEvidence(result.normal),
        );
        assert.deepEqual(result.warnings, []);
      });
    }
  }
}

for (const layout of ["standard", "deep"] as const) {
  for (const scoped of [false, true]) {
    for (const variant of [
      "anonymous",
      "authored",
      "changed candidate",
      "authored changed candidate",
      "owned",
      "authored owned",
    ]) {
      test(`${layout}: terminal replacement ${variant} matches frozen recovery (scoped=${scoped})`, async (t) => {
        const initial = finding("First review", {
          ...(variant.includes("authored")
            ? { identity: { anchor: "authored-review" } }
            : {}),
          provenance: {
            source: "local_plugin",
            ...(variant.includes("candidate")
              ? { candidateId: "candidate-a" }
              : {}),
            ...(variant.includes("owned") ? { workerId: "reviewer" } : {}),
          },
        });
        const revised = {
          ...initial,
          title: "Revised review",
          summary: "Revised synthetic evidence.",
          provenance: {
            ...initial.provenance,
            ...(variant.includes("candidate")
              ? { candidateId: "candidate-b" }
              : {}),
          },
        };
        const { normal, recovered, recover } = await publishedPair(
          t,
          layout,
          [initial],
          { complete: true, scoped },
        );
        await normal.writeFindings([revised], { complete: true });
        await recovered.checkpoint(
          recovered.findingsDraft([revised], { complete: true }),
        );
        const result = await recover(replayWithProvenance);
        const byEvidence = (rows: RecoveredFinding[]) =>
          new Map(
            rows.map(({ evidenceProvenance, ...row }) => [row.summary, row]),
          );
        assert.equal(result.recovered.length, result.normal.length);
        assert.deepEqual(
          byEvidence(result.recovered),
          byEvidence(result.normal),
        );
        if (layout === "deep")
          for (const row of [...result.normal, ...result.recovered]) {
            assert.deepEqual(
              (row.evidenceProvenance as { previousFindings: unknown[] })
                .previousFindings,
              [],
            );
          }
        assert.deepEqual(result.warnings, []);
      });
    }
  }
}

for (const scoped of [false, true]) {
  for (const time of [99, 100, 101]) {
    for (const cut of ["raw input", "committed head"] as const) {
      test(`terminal Deep identity follows producer context at time ${time} (scoped=${scoped}, cut=${cut})`, async (t) => {
        const first = finding("First review");
        const revised = {
          ...first,
          title: "Revised review",
          summary: "Revised synthetic evidence.",
        };
        const pair = await publishedPair(t, "deep", [first], { scoped });
        const result = await terminalAt(pair, [revised], time, cut);
        assert.equal(result.normal.length, 1);
        assert.deepEqual(result.recovered, result.normal);
        assert.deepEqual(result.warnings, []);
      });
    }
  }
}

for (const cut of ["raw input", "committed head"] as const) {
  test(`later partial Deep evidence survives the terminal clock tie (${cut})`, async (t) => {
    const { normal, recovered, recover } = await recoveryPair(t, "deep");
    const terminal = finding("Terminal review");
    const later = finding("Later independent review", {
      locations: [{ path: "src/later.py", startLine: 2 }],
    });
    for (const f of [normal, recovered])
      await f.writeFindings([terminal], { complete: true });
    const pending = {
      deferred: [{ id: "later-work", reason: "More review remains." }],
    };
    await normal.write({ ...normal.draft(pending), findings: [later] });
    if (cut === "raw input")
      await recovered.checkpoint({
        ...recovered.draft(pending),
        findings: [later],
      });
    else
      await recovered.write({ ...recovered.draft(pending), findings: [later] });
    for (const f of [normal, recovered]) await dateDraftFiles(f.root, 100);
    const result = await recover(replayWithProvenance);
    const byId = (rows: RecoveredFinding[]) =>
      new Map(rows.map((row) => [row.findingId, row]));
    assert.equal(result.normal.length, 2);
    assert.deepEqual(byId(result.recovered), byId(result.normal));
    assert.deepEqual(result.warnings, []);
  });
}

test("a later worker attempt survives the terminal parent's clock tie", async (t) => {
  const { normal, recovered, recover } = await recoveryPair(t, "deep");
  const workerRoot = path.join(recovered.root, "reviewer");
  const archiveRoot = path.join(workerRoot, "attempts", "attempt-1");
  await mkdir(archiveRoot, { recursive: true });
  const archived = draftFixture(archiveRoot, "worker");
  await archived.writeFindings([finding("Archived worker review")], {
    complete: true,
  });
  await dateDraftFiles(archiveRoot, 99);
  const terminal = finding("Terminal review");
  for (const f of [normal, recovered]) {
    await f.writeFindings([terminal], { complete: true });
    for (const name of [
      "findings.json",
      "coverage.json",
      "scan-manifest.json",
      "checkpoint-head.json",
    ])
      await utimes(path.join(f.root, name), 100, 100);
    await dateDraftFiles(path.join(f.root, "checkpoints"), 100);
  }
  const worker = draftFixture(workerRoot, "worker");
  const later = finding("Later worker review", {
    locations: [{ path: "src/later.py", startLine: 2 }],
  });
  await worker.writeFindings([later]);
  await dateDraftFiles(path.join(workerRoot, "checkpoints"), 100);
  for (const name of ["result.json", "checkpoint-head.json"])
    await utimes(path.join(workerRoot, name), 100, 100);
  await normal.writeFindings(
    [
      terminal,
      { ...later, provenance: { ...later.provenance, workerId: "reviewer" } },
    ],
    { complete: true },
  );
  const result = await recover({
    workers: [
      { ...savedWorker(workerRoot, "reviewer", "succeeded"), attempt: 2 },
    ],
    details: true,
    replay: true,
  });
  assert.equal(result.normal.length, 2);
  const byId = (rows: RecoveredFinding[]) =>
    new Map(rows.map((row) => [row.findingId, row]));
  assert.deepEqual(byId(result.recovered), byId(result.normal));
  assert.deepEqual(result.warnings, []);
});

for (const reversed of [false, true]) {
  test(`tied legacy surface observations retain distinct rows and frozen IDs (reversed=${reversed})`, async (t) => {
    const { normal, recovered, recover } = await recoveryPair(t, "deep");
    const surfaces = ["First legacy surface", "Second legacy surface"].map(
      (label) => ({
        id: "legacy-shared",
        label,
        disposition: "needs_follow_up",
        receiptRefs: [],
      }),
    );
    if (reversed) surfaces.reverse();
    const deferred = [
      {
        id: "review",
        reason: "Review remains.",
        surfaceIds: ["legacy-shared"],
      },
    ];
    await normal.writeReviewState({
      surfaces: surfaces.map((row, index) => ({
        ...row,
        id: index === 0 ? row.id : "legacy-second",
      })),
      deferred,
    });
    await recovered.writeReviewState();
    await recovered.checkpoint(recovered.draft({ surfaces, deferred }));
    await recovered.checkpoint(recovered.draft({}, true));
    await dateDraftFiles(recovered.root, 100);
    const result = await recover({ details: true, replay: true });
    const rows = result.recoveredCoverage.surfaces as Array<{
      id: string;
      label: string;
    }>;
    assert.deepEqual(
      rows.map((row) => row.label).sort(),
      surfaces.map((row) => row.label).sort(),
    );
    assert.equal(new Set(rows.map((row) => row.id)).size, 2);
    assert.deepEqual(result.warnings, []);
    await recovered.checkpoint(recovered.draft());
    await dateDraftFiles(recovered.root, 100);
    const replay = await recover({ details: true, replay: true });
    assert.deepEqual(replay.recoveredCoverage.surfaces, rows);
  });
}

for (const authored of [false, true]) {
  for (const time of [99, 100, 101]) {
    for (const cut of ["raw input", "committed head"] as const) {
      test(`terminal Deep replacement retains unchanged siblings (authored=${authored}, time=${time}, cut=${cut})`, async (t) => {
        const [unchanged, removed, added] = [
          "Unchanged",
          "Removed",
          "Added",
        ].map((title) =>
          finding(
            title,
            authored ? { identity: { anchor: title.toLowerCase() } } : {},
          ),
        );
        const pair = await publishedPair(t, "deep", [unchanged, removed], {
          complete: true,
        });
        const result = await terminalAt(pair, [unchanged, added], time, cut);
        assert.equal(result.normal.length, 2);
        assert.deepEqual(result.recovered, result.normal);
        for (const row of result.recovered)
          assert.deepEqual(
            (row.evidenceProvenance as { previousFindings: unknown[] })
              .previousFindings,
            [],
          );
        assert.deepEqual(result.warnings, []);
      });
    }
  }
}

for (const parentState of ["absent", "partial", "terminal"] as const) {
  test(`a reducer preserves its claimed batch and unconsumed workers (${parentState} parent)`, async (t) => {
    const { normal, recovered, recover } = await recoveryPair(t, "deep");
    const parentFinding = finding("Parent review", {
      locations: [{ path: "src/parent.py", startLine: 1 }],
    });
    if (parentState === "partial") {
      await recovered.writeFindings([parentFinding]);
      await dateDraftFiles(recovered.root, 100);
    }
    const rows = ["Assigned", "Unconsumed"].map((title) =>
      finding(title, {
        locations: [{ path: `src/${title.toLowerCase()}.py`, startLine: 1 }],
      }),
    );
    const workers: Record<string, unknown>[] = [];
    for (const [index, row] of rows.entries()) {
      const id = `worker-${index + 1}`;
      const root = path.join(
        recovered.root,
        "artifacts/deep_discovery/workers",
        id,
        "output",
      );
      await mkdir(root, { recursive: true });
      const worker = draftFixture(root, "worker");
      await worker.writeFindings([row], { complete: true });
      await dateDraftFiles(root, 101 + index);
      workers.push({
        id,
        kind: "discovery",
        status: "succeeded",
        completed_at: `2026-10-11T20:00:0${index}Z`,
        artifact_dir: root,
        result_manifest_path: path.join(root, "result.json"),
        attempt: 1,
      });
    }
    const reducer = await importSource("../src/artifact-deep-reducer.ts", {
      absWorkingDir: import.meta.dirname,
    });
    const root = path.join(
      recovered.root,
      "artifacts/deep_discovery/dedup/reducer-1/output",
    );
    await mkdir(root, { recursive: true });
    const receipt = await reducer.recordCodexSecurityDeepReduction(
      {
        root,
        repoRoot: recovered.root,
        scanId: recovered.context.scanId,
        layout: "reducer",
        deepReducer: {
          scanRoot: recovered.root,
          claimedWorkers: [
            { id: workers[0].id, resultPath: workers[0].result_manifest_path },
          ],
        },
      },
      { scanId: recovered.context.scanId, complete: true, findings: [rows[0]] },
    );
    assert.deepEqual(receipt.consumedWorkerIds, ["worker-1"]);
    await dateDraftFiles(root, 103);
    workers.push({
      id: "reducer-1",
      kind: "dedup",
      status: "succeeded",
      completed_at: "2026-10-11T20:00:02Z",
      artifact_dir: root,
      result_manifest_path: path.join(root, "result.json"),
      attempt: 1,
    });
    const reduced = await readJson(root, "result.json");
    const findings =
      parentState === "terminal"
        ? [parentFinding]
        : [
            ...(parentState === "partial" ? [parentFinding] : []),
            ...reduced.findings,
            {
              ...rows[1],
              provenance: { ...rows[1].provenance, workerId: "worker-2" },
            },
          ];
    await normal.writeFindings(findings, { complete: true });
    if (parentState === "terminal") {
      await recovered.writeFindings(findings, { complete: true });
      for (const name of [
        "findings.json",
        "coverage.json",
        "scan-manifest.json",
        "checkpoint-head.json",
      ])
        await utimes(path.join(recovered.root, name), 104, 104);
      await dateDraftFiles(path.join(recovered.root, "checkpoints"), 104);
    }
    const result = await recover({ workers, ...replayWithProvenance });
    const byEvidence = (rows: RecoveredFinding[]) =>
      new Map(rows.map((row) => [row.title, row]));
    assert.equal(
      result.normal.length,
      parentState === "terminal" ? 1 : parentState === "partial" ? 3 : 2,
    );
    assert.deepEqual(byEvidence(result.recovered), byEvidence(result.normal));
    assert.deepEqual(result.warnings, []);
  });
}

for (const abandonedTime of [99, 200, 300]) {
  test(`an accepted Deep publication supersedes an abandoned terminal at time ${abandonedTime}`, async (t) => {
    const { normal, recovered, recover } = await recoveryPair(t, "deep");
    await interruptDraftAfterRaw(() =>
      recovered.writeFindings([finding("Abandoned terminal draft")], {
        complete: true,
      }),
    );
    const abandoned = await readdir(path.join(recovered.root, "checkpoints"));
    for (const f of [normal, recovered])
      await f.writeFindings([finding("Accepted replacement")], {
        complete: true,
      });
    await dateDraftFiles(recovered.root, 200);
    for (const name of abandoned)
      await utimes(
        path.join(recovered.root, "checkpoints", name),
        abandonedTime,
        abandonedTime,
      );
    const result = await recover(replayWithProvenance);
    assert.deepEqual(result.recovered, result.normal);
    assert.equal(result.recovered[0]!.title, "Accepted replacement");
    assert.deepEqual(result.warnings, []);
  });
}

test("a newer file-authored canonical Deep result supersedes the accepted head", async (t) => {
  const { normal, recovered, recover } = await publishedPair(
    t,
    "deep",
    [finding("Earlier accepted result")],
    { complete: true },
  );
  await normal.writeFindings(
    [
      finding("File authored update", {
        identity: { anchor: "file-authored" },
        locations: [{ path: "src/updated.py", startLine: 8 }],
      }),
    ],
    { complete: true },
  );
  for (const name of ["scan-manifest.json", "findings.json", "coverage.json"]) {
    await copyFile(
      path.join(normal.root, name),
      path.join(recovered.root, name),
    );
    await utimes(path.join(recovered.root, name), 300, 300);
  }
  const result = await recover(replayWithProvenance);
  assert.deepEqual(result.recovered, result.normal);
  assert.equal(result.recovered[0]!.title, "File authored update");
  assert.deepEqual(result.warnings, []);
});

for (const reversed of [false, true]) {
  test(`a raw terminal rewrite preserves authored identity collisions (reversed=${reversed})`, async (t) => {
    const findings = [
      "First independent report",
      "Second independent report",
    ].map((title) => finding(title, { identity: { anchor: "same" } }));
    if (reversed) findings.reverse();
    const { normal, recovered, recover } = await publishedPair(
      t,
      "deep",
      findings,
      { complete: true },
    );
    const revised = findings.map((row) => ({
      ...row,
      summary: `Updated ${row.title}`,
    }));
    await normal.writeFindings(revised, { complete: true });
    await interruptDraftAfterRaw(() =>
      recovered.writeFindings(revised, { complete: true }),
    );
    const result = await recover(replayWithProvenance);
    assert.equal(result.recovered.length, 2);
    assert.deepEqual(result.recovered, result.normal);
    assert.deepEqual(
      result.preservedIdentities[1],
      result.preservedIdentities[0],
    );
    assert.deepEqual(result.warnings, []);
  });
}

for (const [metadata, preservedIdentity] of Object.entries({
  omitted: undefined,
  annotation: "Synthetic preserved annotation",
  authored: { anchor: "same", description: "Earlier authored identity" },
})) {
  const preserved = preservedIdentity !== undefined;
  for (const workerUpdate of ["none", "unchanged", "revised"]) {
    test(`interrupted terminal collisions retain authored identity with ${workerUpdate} worker (metadata=${metadata})`, async (t) => {
      const { normal, recovered, recover } = await recoveryPair(t, "deep");
      const identity = { anchor: "same", description: "Authored identity" };
      const findings = ["First report", "Second report"].map((title, index) =>
        finding(title, {
          identity,
          locations: [{ path: "src/example.py", startLine: index + 1 }],
          provenance: {
            source: "local_plugin",
            workerId: "reviewer",
            candidateId: `candidate-${index}`,
            ...(preserved ? { preservedIdentity } : {}),
          },
        }),
      );
      await normal.writeFindings(findings, { complete: true });
      await interruptDraftAfterRaw(() =>
        recovered.writeFindings(findings, { complete: true }),
      );
      await dateDraftFiles(recovered.root, 100);
      const workers = [];
      if (workerUpdate !== "none") {
        const workerRoot = path.join(recovered.root, "reviewer");
        await mkdir(workerRoot);
        const worker = draftFixture(workerRoot, "worker");
        const revised = {
          ...findings[1]!,
          ...(workerUpdate === "revised"
            ? {
                summary: "Revised synthetic evidence.",
                severity: { level: "high" },
              }
            : {}),
        };
        await worker.writeFindings([revised], { complete: true });
        await dateDraftFiles(workerRoot, 200);
        workers.push(savedWorker(workerRoot, "reviewer", "succeeded"));
        await normal.writeFindings([findings[0]!, revised], { complete: true });
      }
      const result = await recover({ workers, details: true, replay: true });
      assert.equal(result.normal.length, 2);
      assert.equal(result.recovered.length, 2);
      assert.deepEqual(result.recovered, result.normal);
      assert.deepEqual(result.preservedIdentities, [
        [
          preserved ? preservedIdentity : null,
          preserved ? preservedIdentity : identity,
        ],
        [
          preserved ? preservedIdentity : null,
          preserved ? preservedIdentity : identity,
        ],
      ]);
      assert.deepEqual(result.warnings, []);
    });
  }
}

for (const cut of ["published", "pending"] as const) {
  test(`reselecting an earlier Deep result retains its publication ancestry (${cut})`, async (t) => {
    const { normal, recovered, recover } = await recoveryPair(t, "deep");
    const first = finding("First publication"),
      second = finding("Second publication");
    for (const row of [first, second, first])
      for (const f of [normal, recovered])
        await f.writeFindings([row], { complete: true });
    await dateDraftFiles(recovered.root, 100);
    if (cut === "pending") {
      const revised = { ...second, summary: "Revised second publication" };
      await normal.writeFindings([revised], { complete: true });
      await interruptDraftAfterRaw(() =>
        recovered.writeFindings([revised], { complete: true }),
      );
    }
    const result = await recover(replayWithProvenance);
    assert.deepEqual(result.recovered, result.normal);
    assert.equal(result.recovered.length, 1);
    assert.deepEqual(result.warnings, []);
  });
}

test("a backdated legacy terminal retains both possible publication histories", async (t) => {
  const accepted = finding("Accepted review"),
    unordered = finding("Unordered legacy review");
  const { normal, recovered, recover } = await publishedPair(
    t,
    "deep",
    [accepted],
    { complete: true, time: 200 },
  );
  await normal.writeFindings([accepted, unordered], { complete: true });
  // Older writers did not record whether this input preceded or followed the head.
  const contents = JSON.stringify(
    recovered.findingsDraft([unordered], { complete: true }),
  );
  const raw = path.join(
    recovered.root,
    "checkpoints",
    createHash("sha256").update(contents).digest("hex") + ".json",
  );
  await writeFile(raw, contents);
  await utimes(raw, 100, 100);
  const result = await recover(replayWithProvenance);
  const byTitle = (rows: RecoveredFinding[]) =>
    new Map(rows.map((row) => [row.title, row]));
  assert.equal(result.recovered.length, 2);
  assert.deepEqual(byTitle(result.recovered), byTitle(result.normal));
  assert.deepEqual(result.warnings, []);
});
