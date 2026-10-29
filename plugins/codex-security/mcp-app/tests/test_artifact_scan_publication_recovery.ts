import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  copyFile,
  mkdir,
  writeFile,
  readFile,
  readdir,
  utimes,
} from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { importSource } from "./import-module.ts";
import {
  draftApi,
  draftFixture,
  fixture,
  interruptDraftWrite,
  interruptDraftAfterRaw,
} from "./scan-draft-recovery-fixture.ts";
import {
  type RecoveredFinding,
  finding,
  recoverAndFinalize,
  dateDraftFiles,
} from "./scan-identity-recovery-fixture.ts";

for (const authored of [false, true]) {
  for (const owner of [undefined, "reviewer"]) {
    for (const changedCandidate of [false, true]) {
      test(`parent and moved worker keep publication identities on frozen retry (authored=${authored}, owner=${owner ?? "omitted"}, changedCandidate=${changedCandidate})`, async (t) => {
        const normal = await fixture(t, "deep");
        const recovered = await fixture(t, "deep");
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
        for (const target of [normal, recovered]) {
          await target.write({ ...target.draft(), findings: [first] });
          await dateDraftFiles(target.root, 100);
        }
        const workerRoot = path.join(recovered.root, "reviewer");
        await mkdir(workerRoot);
        const worker = draftFixture(workerRoot, "worker");
        await draftApi.saveScanDraftCheckpoint(
          worker.context,
          { ...worker.draft(), findings: [first] },
          false,
        );
        await dateDraftFiles(workerRoot, 50);
        await writeFile(
          path.join(workerRoot, "result.json"),
          JSON.stringify({ ...worker.draft(), findings: [revised] }),
        );
        await normal.write({
          ...normal.draft({}, true),
          findings: [
            first,
            {
              ...revised,
              provenance: { ...revised.provenance, workerId: "reviewer" },
            },
          ],
        });
        const result = await recoverAndFinalize(
          normal,
          recovered,
          [
            {
              id: "reviewer",
              kind: "discovery",
              status: "succeeded",
              artifact_dir: workerRoot,
              result_manifest_path: path.join(workerRoot, "result.json"),
              attempt: 1,
            },
          ],
          true,
          true,
        );
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
        const normal = await fixture(t, layout);
        const recovered = await fixture(t, layout);
        if (scoped)
          for (const target of [normal, recovered]) {
            target.context.scope = "src";
            (
              target.context.targetContract!.scope as Record<string, unknown>
            ).requiredIncludePaths = ["src"];
          }
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
        for (const target of [normal, recovered]) {
          await target.write({
            ...target.draft({}, true),
            findings: [initial],
          });
          await dateDraftFiles(target.root, 100);
        }
        await normal.write({ ...normal.draft({}, true), findings: [revised] });
        await draftApi.saveScanDraftCheckpoint(
          recovered.context,
          { ...recovered.draft({}, true), findings: [revised] },
          false,
        );
        const result = await recoverAndFinalize(
          normal,
          recovered,
          [],
          true,
          true,
          true,
        );
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
        const normal = await fixture(t, "deep");
        const recovered = await fixture(t, "deep");
        if (scoped)
          for (const f of [normal, recovered]) {
            f.context.scope = "src";
            (
              f.context.targetContract!.scope as Record<string, unknown>
            ).requiredIncludePaths = ["src"];
          }
        const first = finding("First review");
        const revised = {
          ...first,
          title: "Revised review",
          summary: "Revised synthetic evidence.",
        };
        for (const f of [normal, recovered]) {
          await f.write({ ...f.draft(), findings: [first] });
          await dateDraftFiles(f.root, 100);
        }
        const checkpoints = path.join(recovered.root, "checkpoints");
        const original = new Set(await readdir(checkpoints));
        await normal.write({ ...normal.draft({}, true), findings: [revised] });
        const input = { ...recovered.draft({}, true), findings: [revised] };
        if (cut === "raw input")
          await draftApi.saveScanDraftCheckpoint(
            recovered.context,
            input,
            false,
          );
        else
          await interruptDraftWrite(
            path.join(recovered.root, "findings.json"),
            () => recovered.write(input),
          );
        for (const name of await readdir(checkpoints))
          if (!original.has(name))
            await utimes(path.join(checkpoints, name), time, time);
        if (cut === "committed head")
          await utimes(
            path.join(recovered.root, "checkpoint-head.json"),
            time,
            time,
          );
        const result = await recoverAndFinalize(
          normal,
          recovered,
          [],
          true,
          true,
          true,
        );
        assert.equal(result.normal.length, 1);
        assert.deepEqual(result.recovered, result.normal);
        assert.deepEqual(result.warnings, []);
      });
    }
  }
}

for (const cut of ["raw input", "committed head"] as const) {
  test(`later partial Deep evidence survives the terminal clock tie (${cut})`, async (t) => {
    const normal = await fixture(t, "deep");
    const recovered = await fixture(t, "deep");
    const terminal = finding("Terminal review");
    const later = finding("Later independent review", {
      locations: [{ path: "src/later.py", startLine: 2 }],
    });
    for (const f of [normal, recovered])
      await f.write({ ...f.draft({}, true), findings: [terminal] });
    const pending = {
      deferred: [{ id: "later-work", reason: "More review remains." }],
    };
    await normal.write({ ...normal.draft(pending), findings: [later] });
    if (cut === "raw input")
      await draftApi.saveScanDraftCheckpoint(
        recovered.context,
        { ...recovered.draft(pending), findings: [later] },
        false,
      );
    else
      await recovered.write({ ...recovered.draft(pending), findings: [later] });
    for (const f of [normal, recovered]) await dateDraftFiles(f.root, 100);
    const result = await recoverAndFinalize(
      normal,
      recovered,
      [],
      true,
      true,
      true,
    );
    const byId = (rows: RecoveredFinding[]) =>
      new Map(rows.map((row) => [row.findingId, row]));
    assert.equal(result.normal.length, 2);
    assert.deepEqual(byId(result.recovered), byId(result.normal));
    assert.deepEqual(result.warnings, []);
  });
}

test("a later worker attempt survives the terminal parent's clock tie", async (t) => {
  const normal = await fixture(t, "deep");
  const recovered = await fixture(t, "deep");
  const workerRoot = path.join(recovered.root, "reviewer");
  const archiveRoot = path.join(workerRoot, "attempts", "attempt-1");
  await mkdir(archiveRoot, { recursive: true });
  const archived = draftFixture(archiveRoot, "worker");
  await archived.write({
    ...archived.draft({}, true),
    findings: [finding("Archived worker review")],
  });
  await dateDraftFiles(archiveRoot, 99);
  const terminal = finding("Terminal review");
  for (const f of [normal, recovered]) {
    await f.write({ ...f.draft({}, true), findings: [terminal] });
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
  await worker.write({ ...worker.draft(), findings: [later] });
  await dateDraftFiles(path.join(workerRoot, "checkpoints"), 100);
  for (const name of ["result.json", "checkpoint-head.json"])
    await utimes(path.join(workerRoot, name), 100, 100);
  await normal.write({
    ...normal.draft({}, true),
    findings: [
      terminal,
      { ...later, provenance: { ...later.provenance, workerId: "reviewer" } },
    ],
  });
  const result = await recoverAndFinalize(
    normal,
    recovered,
    [
      {
        id: "reviewer",
        kind: "discovery",
        status: "succeeded",
        artifact_dir: workerRoot,
        result_manifest_path: path.join(workerRoot, "result.json"),
        attempt: 2,
      },
    ],
    true,
    true,
  );
  assert.equal(result.normal.length, 2);
  const byId = (rows: RecoveredFinding[]) =>
    new Map(rows.map((row) => [row.findingId, row]));
  assert.deepEqual(byId(result.recovered), byId(result.normal));
  assert.deepEqual(result.warnings, []);
});

for (const reversed of [false, true]) {
  test(`tied legacy surface observations retain distinct rows and frozen IDs (reversed=${reversed})`, async (t) => {
    const normal = await fixture(t, "deep");
    const recovered = await fixture(t, "deep");
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
    await normal.write(
      normal.draft({
        surfaces: surfaces.map((row, index) => ({
          ...row,
          id: index === 0 ? row.id : "legacy-second",
        })),
        deferred,
      }),
    );
    await recovered.write(recovered.draft());
    await draftApi.saveScanDraftCheckpoint(
      recovered.context,
      recovered.draft({ surfaces, deferred }),
      false,
    );
    await draftApi.saveScanDraftCheckpoint(
      recovered.context,
      recovered.draft({}, true),
      false,
    );
    await dateDraftFiles(recovered.root, 100);
    const result = await recoverAndFinalize(normal, recovered, [], true, true);
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
    await draftApi.saveScanDraftCheckpoint(
      recovered.context,
      recovered.draft(),
      false,
    );
    await dateDraftFiles(recovered.root, 100);
    const replay = await recoverAndFinalize(normal, recovered, [], true, true);
    assert.deepEqual(replay.recoveredCoverage.surfaces, rows);
  });
}

for (const authored of [false, true]) {
  for (const time of [99, 100, 101]) {
    for (const cut of ["raw input", "committed head"] as const) {
      test(`terminal Deep replacement retains unchanged siblings (authored=${authored}, time=${time}, cut=${cut})`, async (t) => {
        const normal = await fixture(t, "deep");
        const recovered = await fixture(t, "deep");
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
        for (const f of [normal, recovered]) {
          await f.write({
            ...f.draft({}, true),
            findings: [unchanged, removed],
          });
          await dateDraftFiles(f.root, 100);
        }
        const checkpoints = path.join(recovered.root, "checkpoints");
        const original = new Set(await readdir(checkpoints));
        await normal.write({
          ...normal.draft({}, true),
          findings: [unchanged, added],
        });
        const input = {
          ...recovered.draft({}, true),
          findings: [unchanged, added],
        };
        if (cut === "raw input")
          await draftApi.saveScanDraftCheckpoint(
            recovered.context,
            input,
            false,
          );
        else
          await interruptDraftWrite(
            path.join(recovered.root, "findings.json"),
            () => recovered.write(input),
          );
        for (const name of await readdir(checkpoints))
          if (!original.has(name))
            await utimes(path.join(checkpoints, name), time, time);
        if (cut === "committed head")
          await utimes(
            path.join(recovered.root, "checkpoint-head.json"),
            time,
            time,
          );
        const result = await recoverAndFinalize(
          normal,
          recovered,
          [],
          true,
          true,
          true,
        );
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
    const normal = await fixture(t, "deep");
    const recovered = await fixture(t, "deep");
    const parentFinding = finding("Parent review", {
      locations: [{ path: "src/parent.py", startLine: 1 }],
    });
    if (parentState === "partial") {
      await recovered.write({
        ...recovered.draft(),
        findings: [parentFinding],
      });
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
      await worker.write({ ...worker.draft({}, true), findings: [row] });
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
    const root = path.join(
      recovered.root,
      "artifacts/deep_discovery/dedup/iteration-1",
    );
    await mkdir(root, { recursive: true });
    const source = rows[0];
    await writeFile(
      path.join(root, "result.json"),
      JSON.stringify({
        scanId: recovered.context.scanId,
        findings: [
          {
            ...source,
            provenance: {
              ...source.provenance,
              sourceFindingIds: ["worker-1:0"],
              sourceFindings: [{ id: "worker-1:0", finding: source }],
            },
          },
        ],
      }),
    );
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
    const reduced = JSON.parse(
      await readFile(path.join(root, "result.json"), "utf8"),
    );
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
    await normal.write({ ...normal.draft({}, true), findings });
    if (parentState === "terminal") {
      await recovered.write({ ...recovered.draft({}, true), findings });
      for (const name of [
        "findings.json",
        "coverage.json",
        "scan-manifest.json",
        "checkpoint-head.json",
      ])
        await utimes(path.join(recovered.root, name), 104, 104);
      await dateDraftFiles(path.join(recovered.root, "checkpoints"), 104);
    }
    const result = await recoverAndFinalize(
      normal,
      recovered,
      workers,
      true,
      true,
      true,
    );
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
    const normal = await fixture(t, "deep"),
      recovered = await fixture(t, "deep");
    await interruptDraftAfterRaw(() =>
      recovered.write({
        ...recovered.draft({}, true),
        findings: [finding("Abandoned terminal draft")],
      }),
    );
    const abandoned = await readdir(path.join(recovered.root, "checkpoints"));
    for (const f of [normal, recovered])
      await f.write({
        ...f.draft({}, true),
        findings: [finding("Accepted replacement")],
      });
    await dateDraftFiles(recovered.root, 200);
    for (const name of abandoned)
      await utimes(
        path.join(recovered.root, "checkpoints", name),
        abandonedTime,
        abandonedTime,
      );
    const result = await recoverAndFinalize(
      normal,
      recovered,
      [],
      true,
      true,
      true,
    );
    assert.deepEqual(result.recovered, result.normal);
    assert.equal(result.recovered[0]!.title, "Accepted replacement");
    assert.deepEqual(result.warnings, []);
  });
}

test("a newer file-authored canonical Deep result supersedes the accepted head", async (t) => {
  const normal = await fixture(t, "deep"),
    recovered = await fixture(t, "deep");
  for (const f of [normal, recovered]) {
    await f.write({
      ...f.draft({}, true),
      findings: [finding("Earlier accepted result")],
    });
    await dateDraftFiles(f.root, 100);
  }
  await normal.write({
    ...normal.draft({}, true),
    findings: [
      finding("File authored update", {
        identity: { anchor: "file-authored" },
        locations: [{ path: "src/updated.py", startLine: 8 }],
      }),
    ],
  });
  for (const name of ["scan-manifest.json", "findings.json", "coverage.json"]) {
    await copyFile(
      path.join(normal.root, name),
      path.join(recovered.root, name),
    );
    await utimes(path.join(recovered.root, name), 300, 300);
  }
  const result = await recoverAndFinalize(
    normal,
    recovered,
    [],
    true,
    true,
    true,
  );
  assert.deepEqual(result.recovered, result.normal);
  assert.equal(result.recovered[0]!.title, "File authored update");
  assert.deepEqual(result.warnings, []);
});

for (const reversed of [false, true]) {
  test(`a raw terminal rewrite preserves authored identity collisions (reversed=${reversed})`, async (t) => {
    const normal = await fixture(t, "deep"),
      recovered = await fixture(t, "deep");
    const findings = [
      "First independent report",
      "Second independent report",
    ].map((title) => finding(title, { identity: { anchor: "same" } }));
    if (reversed) findings.reverse();
    for (const f of [normal, recovered]) {
      await f.write({ ...f.draft({}, true), findings });
      await dateDraftFiles(f.root, 100);
    }
    const revised = findings.map((row) => ({
      ...row,
      summary: `Updated ${row.title}`,
    }));
    await normal.write({ ...normal.draft({}, true), findings: revised });
    await interruptDraftAfterRaw(() =>
      recovered.write({ ...recovered.draft({}, true), findings: revised }),
    );
    const result = await recoverAndFinalize(
      normal,
      recovered,
      [],
      true,
      true,
      true,
    );
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
      const normal = await fixture(t, "deep"),
        recovered = await fixture(t, "deep");
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
      await normal.write({ ...normal.draft({}, true), findings });
      await interruptDraftAfterRaw(() =>
        recovered.write({ ...recovered.draft({}, true), findings }),
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
        await worker.write({ ...worker.draft({}, true), findings: [revised] });
        await dateDraftFiles(workerRoot, 200);
        workers.push({
          id: "reviewer",
          kind: "discovery",
          status: "succeeded",
          artifact_dir: workerRoot,
          result_manifest_path: path.join(workerRoot, "result.json"),
          attempt: 1,
        });
        await normal.write({
          ...normal.draft({}, true),
          findings: [findings[0]!, revised],
        });
      }
      const result = await recoverAndFinalize(
        normal,
        recovered,
        workers,
        true,
        true,
      );
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
    const normal = await fixture(t, "deep"),
      recovered = await fixture(t, "deep");
    const first = finding("First publication"),
      second = finding("Second publication");
    for (const row of [first, second, first])
      for (const f of [normal, recovered])
        await f.write({ ...f.draft({}, true), findings: [row] });
    await dateDraftFiles(recovered.root, 100);
    if (cut === "pending") {
      const revised = { ...second, summary: "Revised second publication" };
      await normal.write({ ...normal.draft({}, true), findings: [revised] });
      await interruptDraftAfterRaw(() =>
        recovered.write({ ...recovered.draft({}, true), findings: [revised] }),
      );
    }
    const result = await recoverAndFinalize(
      normal,
      recovered,
      [],
      true,
      true,
      true,
    );
    assert.deepEqual(result.recovered, result.normal);
    assert.equal(result.recovered.length, 1);
    assert.deepEqual(result.warnings, []);
  });
}

test("a backdated legacy terminal retains both possible publication histories", async (t) => {
  const normal = await fixture(t, "deep"),
    recovered = await fixture(t, "deep");
  const accepted = finding("Accepted review"),
    unordered = finding("Unordered legacy review");
  for (const f of [normal, recovered]) {
    await f.write({ ...f.draft({}, true), findings: [accepted] });
    await dateDraftFiles(f.root, 200);
  }
  await normal.write({
    ...normal.draft({}, true),
    findings: [accepted, unordered],
  });
  // Older writers did not record whether this input preceded or followed the head.
  const contents = JSON.stringify({
    ...recovered.draft({}, true),
    findings: [unordered],
  });
  const raw = path.join(
    recovered.root,
    "checkpoints",
    createHash("sha256").update(contents).digest("hex") + ".json",
  );
  await writeFile(raw, contents);
  await utimes(raw, 100, 100);
  const result = await recoverAndFinalize(
    normal,
    recovered,
    [],
    true,
    true,
    true,
  );
  const byTitle = (rows: RecoveredFinding[]) =>
    new Map(rows.map((row) => [row.title, row]));
  assert.equal(result.recovered.length, 2);
  assert.deepEqual(byTitle(result.recovered), byTitle(result.normal));
  assert.deepEqual(result.warnings, []);
});
