import type { ScanUnion } from "../src/deep-scan/artifact-validation.js";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { importSource } from "./import-module.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import {
  workerHistoryFixture,
  reviewDraft,
  scanId,
  finding,
} from "./scan-draft-fixture.ts";
import {
  publishCoverageFixture,
  readFixtureCoverage,
} from "./deep_scan_coverage_fixture.ts";

const source = fileURLToPath(new URL("../src", import.meta.url));
const { parsePersistedScanDraft } = await importSource(
  path.join(source, "artifact-scan-draft.ts"),
);
const {
  persistedScanUnion,
  parseScanUnion,
  scanUnionToDraft,
  readAcceptedDiscovery,
} = await importSource(path.join(source, "deep-scan/artifact-validation.ts"));
const { mergeBatch } = await importSource(
  path.join(source, "deep-scan/iteration.ts"),
);

async function artifactTree(
  root: string,
): Promise<Array<{ path: string; sha256: string | null }>> {
  const files: Array<{ path: string; sha256: string | null }> = [];
  const visit = async (directory: string) => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const file = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        files.push({
          path: `${path.relative(root, file).split(path.sep).join("/")}/`,
          sha256: null,
        });
        await visit(file);
      } else {
        assert.ok(entry.isFile(), `Unexpected non-regular artifact: ${file}`);
        files.push({
          path: path.relative(root, file).split(path.sep).join("/"),
          sha256: createHash("sha256")
            .update(await readFile(file))
            .digest("hex"),
        });
      }
    }
  };
  await visit(root);
  return files.sort((left, right) => left.path.localeCompare(right.path));
}

async function publishAndReplay(
  f: Awaited<ReturnType<typeof workerHistoryFixture>>,
) {
  async function aggregate() {
    const worker = await f.readAccepted();
    const result: ScanUnion = { scanId, complete: true, findings: [] };
    await mergeBatch(
      result,
      [worker],
      f.scanRoot,
      () => {
        throw new Error("unexpected comparison");
      },
      (error: unknown) => {
        throw error;
      },
    );
    assert.ok(result.sourceCoverage);
    return { ...result, sourceCoverage: result.sourceCoverage };
  }
  const result = await aggregate();
  const stored = persistedScanUnion(result);
  assert.equal(Object.hasOwn(stored, "sourceCoverage"), false);
  assert.deepEqual(parseScanUnion(stored).findings, result.findings);
  assert.deepEqual(await aggregate(), result);
  return result;
}

for (const archived of [false, true]) {
  for (const currentIds of [
    "duplicates",
    "reordered duplicates",
    "explicit",
    "authored task",
  ]) {
    test(`retained task links follow matched surfaces: archived=${archived}, ${currentIds}`, async (t) => {
      const f = await workerHistoryFixture(t, archived ? 2 : 1);
      const surfaces = ["First", "Second"].map((label) => ({
        id: "api",
        label,
        disposition: "needs_follow_up",
        receiptRefs: [],
      }));
      await f.record(
        reviewDraft(false, {
          surfaces,
          deferred: [
            {
              id: "later",
              reason: "Synthetic follow-up",
              surfaceIds: ["api-2"],
            },
          ],
        }),
      );
      if (archived) await f.archive();
      await mkdir(f.output, { recursive: true });
      const current = structuredClone(surfaces);
      if (currentIds === "explicit") current[1]!.id = "api-2";
      if (currentIds === "reordered duplicates") current.reverse();
      await writeFile(
        f.resultPath,
        JSON.stringify(
          reviewDraft(true, {
            surfaces: current,
            deferred:
              currentIds === "authored task"
                ? [
                    {
                      id: "current",
                      reason: "Current follow-up",
                      surfaceIds: ["api"],
                    },
                  ]
                : [],
          }),
        ),
      );
      const before = await artifactTree(f.workerRoot);
      const accepted = await f.readAccepted();
      assert.deepEqual(accepted.result.reviewState.surfaces, current);
      const resumed = await readAcceptedDiscovery(
        f.artifacts,
        f.worker,
        scanId,
        {},
        "previously-accepted",
      );
      assert.deepEqual(resumed.coverage, accepted.coverage);
      const aggregate = await publishAndReplay(f);
      const published = scanUnionToDraft(aggregate).reviewState;
      assert.equal(published.surfaces.length, 2);
      assert.equal(
        published.deferred.length,
        currentIds === "authored task" ? 2 : 1,
      );
      assert.deepEqual(
        published.deferred.find(
          (row: { reason: string }) => row.reason === "Synthetic follow-up",
        ).surfaceIds,
        [
          published.surfaces.find(
            (row: { label: string }) => row.label === "Second",
          ).id,
        ],
      );
      if (currentIds === "authored task") {
        assert.deepEqual(
          published.deferred.find(
            (row: { reason: string }) => row.reason === "Current follow-up",
          ).surfaceIds,
          [published.surfaces[0].id],
        );
      }
      assert.deepEqual(await artifactTree(f.workerRoot), before);
    });
  }
}

for (const currentIds of ["duplicates", "reordered", "explicit"]) {
  test(`legacy same-ID task links follow their matched occurrences: ${currentIds}`, async (t) => {
    const f = await workerHistoryFixture(t, 2);
    const surfaces = ["First", "Second"].map((label, index) => ({
      id: index === 0 ? "api" : "api-2",
      label,
      disposition: "needs_follow_up",
      receiptRefs: [],
    }));
    await writeFile(
      f.resultPath,
      JSON.stringify(
        reviewDraft(true, {
          surfaces,
          deferred: surfaces.map((surface) => ({
            id: "legacy",
            reason: `${surface.label} follow-up`,
            surfaceIds: [surface.id],
          })),
        }),
      ),
    );
    await f.archive();
    await mkdir(f.output, { recursive: true });
    const current = structuredClone(surfaces);
    if (currentIds !== "explicit") current[1]!.id = "api";
    if (currentIds === "reordered") current.reverse();
    await writeFile(
      f.resultPath,
      JSON.stringify(
        reviewDraft(true, {
          surfaces: current,
          deferred: [
            {
              id: "current",
              reason: "Current follow-up",
              surfaceIds: ["api", "unknown"],
            },
          ],
        }),
      ),
    );
    const before = await artifactTree(f.workerRoot);
    const accepted = await f.readAccepted();
    const resumed = await readAcceptedDiscovery(
      f.artifacts,
      f.worker,
      scanId,
      {},
      "previously-accepted",
    );
    assert.deepEqual(resumed.coverage, accepted.coverage);
    assert.deepEqual(accepted.result.reviewState.surfaces, current);
    const published = scanUnionToDraft(await publishAndReplay(f)).reviewState;
    assert.equal(published.surfaces.length, 2);
    assert.equal(published.deferred.length, 3);
    for (const label of ["First", "Second"])
      assert.deepEqual(
        published.deferred.find(
          (row: { reason: string }) => row.reason === `${label} follow-up`,
        ).surfaceIds,
        [
          published.surfaces.find(
            (row: { label: string }) => row.label === label,
          ).id,
        ],
      );
    assert.deepEqual(
      published.deferred.find(
        (row: { reason: string }) => row.reason === "Current follow-up",
      ).surfaceIds,
      [published.surfaces[0].id, "unknown"],
    );
    assert.deepEqual(await artifactTree(f.workerRoot), before);
  });
}

for (const close of [false, true]) {
  test(`accepted worker ${close ? "closure" : "pending control"} survives aggregation and replay`, async (t) => {
    const f = await workerHistoryFixture(t, 2);
    const pending = {
      id: "review",
      reason: "Synthetic review still needs evidence.",
    };
    await f.record(
      reviewDraft(false, {
        deferred: [pending],
      }),
    );
    await f.record(
      reviewDraft(true, {
        deferred: close ? [] : [pending],
        ...(close
          ? {
              resolvedDeferred: [
                { id: "review", reason: "Synthetic review completed." },
              ],
            }
          : {}),
      }),
    );
    const original = await readFile(f.resultPath);
    const accepted = parsePersistedScanDraft(JSON.parse(original.toString()));
    if (close) assert.equal(accepted.reviewState.resolvedDeferred.length, 1);
    await f.validate();
    const { sourceCoverage: coverage } = await publishAndReplay(f);
    if (close) {
      assert.equal(coverage.resolvedDeferred?.length, 1);
      assert.equal(
        coverage.resolvedDeferred[0].id,
        "synthetic-worker-attempt-2-resolved-review",
      );
      assert.equal(
        coverage.resolvedDeferred[0].reason,
        "Synthetic review completed.",
      );
      assert.equal(coverage.deferred.length, 0);
    } else {
      assert.equal(coverage.deferred.length, 1);
      assert.equal(coverage.resolvedDeferred?.length ?? 0, 0);
    }
    assert.deepEqual(await readFile(f.resultPath), original);
  });
}

for (const changed of [false, true]) {
  test(`typed retry closure keeps its originating attempt, changed=${changed}`, async (t) => {
    const f = await workerHistoryFixture(t, 2);
    await f.record(
      reviewDraft(false, {
        deferred: [{ id: "review", reason: "Synthetic pending review." }],
      }),
    );
    await f.record(
      reviewDraft(true, {
        resolvedDeferred: [{ id: "review", reason: "Original closure." }],
      }),
    );
    const archive = path.join(f.workerRoot, "attempts/attempt-01");
    await f.archive(archive);
    const historical = await readFile(path.join(archive, "result.json"));
    await mkdir(f.output, { recursive: true });
    const current = reviewDraft(true);
    if (changed)
      Object.assign(current.reviewState, {
        resolvedDeferred: [{ id: "review", reason: "Updated closure." }],
      });
    await f.record(current);
    const original = await readFile(f.resultPath);
    const acceptedReduction = await publishAndReplay(f);
    const { sourceCoverage } = acceptedReduction;
    const attempt = changed ? 2 : 1;
    assert.deepEqual(sourceCoverage.resolvedDeferred, [
      {
        id: `synthetic-worker-attempt-${attempt}-resolved-review`,
        reason: changed ? "Updated closure." : "Original closure.",
      },
    ]);
    assert.ok(
      (sourceCoverage.reviews as { attempt: number }[]).some(
        (review: { attempt: number }) => review.attempt === attempt,
      ),
    );
    assert.equal(sourceCoverage.deferred.length, 0);
    assert.deepEqual(await readFile(f.resultPath), original);
    const secondArchive = path.join(f.workerRoot, "attempts/attempt-02");
    await f.archive(secondArchive);
    f.worker.attempt = 3;
    await f.record(reviewDraft(true));
    const repeated = await publishAndReplay(f);
    assert.deepEqual(
      repeated.sourceCoverage.resolvedDeferred,
      sourceCoverage.resolvedDeferred,
    );
    assert.ok(
      (repeated.sourceCoverage.reviews as { attempt: number }[]).some(
        (review: { attempt: number }) => review.attempt === attempt,
      ),
    );
    assert.deepEqual(
      await readFile(path.join(secondArchive, "result.json")),
      original,
    );
    assert.deepEqual(
      await readFile(path.join(archive, "result.json")),
      historical,
    );
  });
}

for (const history of [
  "current",
  "malformed optional current history",
  "archived",
  "malformed optional archived history",
]) {
  const archived = history.includes("archived");
  test(`an accepted direct-file result retains ${history} checkpoint coverage without rewriting artifacts`, async (t) => {
    const f = await workerHistoryFixture(t, 2);
    await f.record(
      reviewDraft(false, {
        surfaces: [
          {
            id: "saved-surface",
            label: "Synthetic archived-only surface",
            disposition: "needs_follow_up",
            receiptRefs: [],
          },
        ],
        explicitExclusions: [
          {
            pattern: "synthetic-excluded/**",
            reason: "Synthetic archived exclusion.",
          },
        ],
        deferred: [
          {
            id: "saved-task",
            reason: "Synthetic archived proof remains.",
            surfaceIds: ["saved-surface"],
          },
        ],
      }),
    );
    const saved = archived
      ? path.join(f.workerRoot, "attempts/attempt-01")
      : f.output;
    if (archived) await f.archive(saved);
    if (history.startsWith("malformed")) {
      await writeFile(path.join(saved, "checkpoints/unusable.json"), "{");
      const head = path.join(saved, "checkpoint-head.json");
      await rm(head);
      await mkdir(head);
      if (archived) {
        // Only the older immutable checkpoint is usable after an interrupted retry.
        const result = path.join(saved, "result.json");
        await rm(result, { force: true });
        await mkdir(result);
      }
    }
    await mkdir(f.output, { recursive: true });
    const terminal = reviewDraft(true);
    await writeFile(f.resultPath, JSON.stringify(terminal));
    const before = await artifactTree(f.scanRoot);
    const admitted = await f.validate();
    assert.deepEqual(admitted.findings, terminal.findings);
    assert.equal(admitted.reviewState.surfaces.length, 0);
    const source = await f.readAccepted();
    assert.deepEqual(source.result.findings, admitted.findings);
    assert.equal(Object.hasOwn(source.result, "coverage"), false);
    assert.deepEqual(await artifactTree(f.scanRoot), before);
    const coverage = source.coverage;
    assert.deepEqual(
      [
        coverage.surfaces.length,
        coverage.explicitExclusions.length,
        coverage.deferred.length,
      ],
      [1, 1, 1],
      "accepted direct-file completion must retain independent checkpoint observations",
    );
    for (const field of ["surfaces", "explicitExclusions", "deferred"]) {
      assert.equal(coverage[field][0].provenance.workerId, "synthetic-worker");
      assert.equal(coverage[field][0].provenance.attempt, archived ? 1 : 2);
    }
    assert.equal(
      coverage.surfaces[0].id,
      "synthetic-worker-attempt-2-surface-1",
    );
    assert.equal(
      coverage.deferred[0].id,
      "synthetic-worker-attempt-2-deferred-1",
    );
    assert.deepEqual(coverage.deferred[0].surfaceIds, [
      coverage.surfaces[0].id,
    ]);
    assert.equal(coverage.surfaces[0].label, "Synthetic archived-only surface");
    assert.equal(
      coverage.explicitExclusions[0].reason,
      "Synthetic archived exclusion.",
    );
    assert.equal(
      coverage.deferred[0].reason,
      "Synthetic archived proof remains.",
    );
  });
}

for (const repair of [
  "matching closeout",
  "no valid replacement",
  "independent source",
]) {
  test(`accepted direct-file history receipt repair: ${repair}`, async (t) => {
    const f = await workerHistoryFixture(t, 2);
    const original = "artifacts/original.txt";
    const missing = "artifacts/missing.txt";
    const replacement = "artifacts/replacement.txt";
    await mkdir(path.join(f.output, "artifacts"), { recursive: true });
    await writeFile(
      path.join(f.output, original),
      "Synthetic original evidence.\n",
    );
    await f.record(
      reviewDraft(false, {
        surfaces: [
          {
            id: "review",
            label: "Synthetic review",
            disposition: "needs_follow_up",
            receiptRefs: [original, missing],
          },
          ...(repair === "independent source"
            ? [
                {
                  id: "independent",
                  label: "Independent incomplete review",
                  disposition: "needs_follow_up",
                  receiptRefs: [missing],
                },
              ]
            : []),
        ],
        deferred: [
          {
            id: "review-gap",
            reason: "Synthetic pending evidence.",
            surfaceIds: ["review"],
          },
        ],
      }),
    );
    await f.archive();
    await mkdir(path.join(f.output, "artifacts"), { recursive: true });
    await writeFile(
      path.join(f.output, replacement),
      "Synthetic replacement evidence.\n",
    );
    await writeFile(
      f.resultPath,
      JSON.stringify(
        reviewDraft(true, {
          surfaces: [
            {
              id: "review",
              label: "Synthetic review",
              disposition: "no_issue_found",
              receiptRefs:
                repair === "no valid replacement" ? [] : [replacement],
            },
          ],
          resolvedDeferred: [
            { id: "review-gap", reason: "Synthetic completed evidence." },
          ],
        }),
      ),
    );
    await f.validate();
    const readDiscovery = () => f.readAccepted();
    const before = await artifactTree(f.scanRoot);
    if (repair !== "matching closeout") {
      // A missing receipt still needed by any observation prevents acceptance.
      await assert.rejects(readDiscovery, /requested artifact is unavailable/);
      assert.deepEqual(await artifactTree(f.scanRoot), before);
      return;
    }
    const { coverage } = await readDiscovery();
    assert.deepEqual(await artifactTree(f.scanRoot), before);
    const reviewed = coverage.surfaces.find(
      (row: { label: string }) => row.label === "Synthetic review",
    );
    assert.ok(reviewed);
    const archivedMissing =
      "artifacts/deep_discovery/workers/discovery-0001/attempts/attempt-01/" +
      missing;
    assert.ok(!reviewed.receiptRefs.includes(archivedMissing));
    assert.ok(
      reviewed.receiptRefs.some((ref: string) => ref.endsWith("/" + original)),
      "Keep independent readable evidence from the earlier observation.",
    );
  });
}

for (const copy of [
  "unchanged",
  "changed",
  "missing",
  "same bytes independent receipt",
]) {
  test(`accepted history retains the original receipt when its writer copy is ${copy}`, async (t) => {
    const f = await workerHistoryFixture(t, 2);
    const receipt = "artifacts/prior.txt";
    const originalBytes = "Synthetic archived receipt.\n";
    await mkdir(path.dirname(path.join(f.output, receipt)), {
      recursive: true,
    });
    await writeFile(path.join(f.output, receipt), originalBytes);
    const surface = {
      id: "review",
      label: "Synthetic retained review",
      disposition: "needs_follow_up",
      receiptRefs: [receipt],
    };
    await f.record(
      reviewDraft(false, {
        surfaces: [surface],
        deferred: [
          {
            id: "review-gap",
            reason: "Synthetic pending proof.",
            surfaceIds: [surface.id],
          },
        ],
      }),
    );
    const archive = path.join(f.workerRoot, "attempts/attempt-01");
    await f.archive(archive);
    await mkdir(path.dirname(path.join(f.output, receipt)), {
      recursive: true,
    });
    await writeFile(
      path.join(f.output, receipt),
      copy === "same bytes independent receipt"
        ? originalBytes
        : "Synthetic current receipt.\n",
    );
    await f.record(
      reviewDraft(true, {
        surfaces: [{ ...surface, disposition: "no_issue_found" }],
        resolvedDeferred: [
          { id: "review-gap", reason: "Synthetic completed proof." },
        ],
      }),
    );
    const accepted = JSON.parse(await readFile(f.resultPath, "utf8"));
    assert.equal(accepted.reviewState.surfaces[0].receiptRefs.length, 2);
    const prefix = "artifacts/deep_discovery/workers/discovery-0001/";
    const copied = `${prefix}output/artifacts/archived-receipts/attempt-01/${receipt}`;
    const original = `${prefix}attempts/attempt-01/${receipt}`;
    assert.ok(accepted.reviewState.surfaces[0].receiptRefs.includes(copied));
    await f.validate();
    if (copy === "changed")
      await writeFile(
        path.join(f.scanRoot, copied),
        "Synthetic changed copy.\n",
      );
    if (copy === "missing") await rm(path.join(f.scanRoot, copied));
    const before = await artifactTree(f.scanRoot);
    const source = await f.readAccepted();
    assert.deepEqual(await artifactTree(f.scanRoot), before);
    assert.equal(source.coverage.surfaces.length, 1);
    const refs = source.coverage.surfaces[0].receiptRefs;
    const preservedOriginal = copy === "changed" || copy === "missing";
    assert.equal(refs.length, copy === "changed" ? 3 : 2);
    assert.equal(refs.includes(original), preservedOriginal);
    assert.equal(refs.includes(copied), copy !== "missing");
    assert.ok(
      refs.includes(`${prefix}output/${receipt}`),
      "Distinct current work must keep its own receipt even when bytes agree.",
    );
    assert.equal(
      await readFile(path.join(archive, receipt), "utf8"),
      originalBytes,
    );
    assert.deepEqual(source.coverage.deferred, []);
  });
}

for (const local of [false, true]) {
  test(`archiving a direct result preserves its receipt owner, local=${local}`, async (t) => {
    const f = await workerHistoryFixture(t, 2);
    const ref = "artifacts/proof.txt";
    await writeFile(path.join(f.scanRoot, ref), "scan-owned evidence");
    const checkpoint = {
      id: "checkpointed",
      label: "Checkpointed review",
      disposition: "no_issue_found",
      receiptRefs: [ref],
    };
    const direct = {
      ...checkpoint,
      id: "direct",
      label: "Direct review",
      provenance: { scanReceiptRefs: [ref] },
    };
    const draft = (surface: typeof checkpoint, complete: boolean) =>
      reviewDraft(complete, {
        surfaces: [surface],
      });
    await f.record(draft(checkpoint, false));
    if (local) {
      await mkdir(path.dirname(path.join(f.output, ref)), { recursive: true });
      await writeFile(path.join(f.output, ref), "worker-owned evidence");
    }
    await writeFile(f.resultPath, JSON.stringify(draft(direct, true)));

    const first = f.validate();
    if (local) await first;
    else await assert.rejects(first, /artifact is unavailable/);
    await f.archive();
    const terminal = reviewDraft(true);
    await writeFile(f.resultPath, JSON.stringify(terminal));
    for (const viaWriter of [false, true]) {
      if (viaWriter) {
        // A same-thread retry retains the previous output alongside its archive.
        await cp(path.join(f.workerRoot, "attempts/attempt-01"), f.output, {
          recursive: true,
        });
        await f.record(terminal);
      }
      const before = await artifactTree(f.scanRoot);
      const { coverage } = await f.readAccepted();
      assert.deepEqual(await artifactTree(f.scanRoot), before);
      assert.equal(coverage.surfaces.length, local ? 2 : 1);
      for (const row of coverage.surfaces) {
        assert.equal(row.provenance.attempt, 1);
        const ownedByScan = row.label === checkpoint.label;
        assert.equal(row.label, ownedByScan ? checkpoint.label : direct.label);
        assert.equal(row.receiptRefs.length, 1);
        assert.equal(row.receiptRefs[0] === ref, ownedByScan);
        assert.equal(
          await readFile(path.join(f.scanRoot, row.receiptRefs[0]), "utf8"),
          ownedByScan ? "scan-owned evidence" : "worker-owned evidence",
        );
      }
    }
  });
}

test("a direct-file surface cannot inherit archived shared receipt ownership from a matching row", async (t) => {
  const f = await workerHistoryFixture(t, 2);
  const ref = "artifacts/evidence.txt";
  const sharedBytes = "Synthetic shared proof.\n";
  const localBytes = "Synthetic current local proof.\n";
  await mkdir(path.dirname(path.join(f.scanRoot, ref)), { recursive: true });
  await writeFile(path.join(f.scanRoot, ref), sharedBytes);
  const repeated = {
    id: "same-review",
    label: "Synthetic repeated review",
    disposition: "no_issue_found",
    receiptRefs: [ref],
  };
  await f.record(
    reviewDraft(false, {
      surfaces: [
        repeated,
        {
          id: "independent-review",
          label: "Synthetic independent archived review",
          disposition: "needs_follow_up",
          receiptRefs: [ref],
        },
      ],
    }),
  );
  const recorded = JSON.parse(await readFile(f.resultPath, "utf8"));
  for (const surface of recorded.reviewState.surfaces) {
    assert.deepEqual(surface.provenance.scanReceiptRefs, [ref]);
  }
  await f.archive();
  await mkdir(path.dirname(path.join(f.output, ref)), { recursive: true });
  await writeFile(path.join(f.output, ref), localBytes);
  await writeFile(
    f.resultPath,
    JSON.stringify(
      reviewDraft(true, {
        surfaces: [{ ...repeated, provenance: { scanReceiptRefs: [ref] } }],
      }),
    ),
  );
  const before = await artifactTree(f.scanRoot);
  const admitted = await f.validate();
  assert.equal(
    admitted.reviewState.surfaces[0].provenance.scanReceiptRefs,
    undefined,
  );
  const { coverage } = await f.readAccepted();
  assert.deepEqual(await artifactTree(f.scanRoot), before);
  const current = coverage.surfaces.find(
    (surface: { label: string }) => surface.label === repeated.label,
  );
  const independent = coverage.surfaces.find(
    (surface: { label: string }) =>
      surface.label === "Synthetic independent archived review",
  );
  assert.ok(current);
  assert.ok(independent);
  assert.deepEqual(independent.receiptRefs, [ref]);
  assert.equal(independent.provenance.attempt, 1);
  assert.equal(
    await readFile(path.join(f.scanRoot, independent.receiptRefs[0]), "utf8"),
    sharedBytes,
  );
  const localRef = `artifacts/deep_discovery/workers/discovery-0001/output/${ref}`;
  assert.deepEqual(current.receiptRefs, [localRef]);
  assert.equal(current.provenance.attempt, 2);
  assert.equal(
    await readFile(path.join(f.scanRoot, current.receiptRefs[0]), "utf8"),
    localBytes,
  );
  assert.equal(Object.hasOwn(current.provenance, "scanReceiptRefs"), false);
  assert.equal(Object.hasOwn(independent.provenance, "scanReceiptRefs"), false);
});

test("an archived generic closure cannot close a new candidate with the same raw task ID", async (t) => {
  const f = await workerHistoryFixture(t, 2);
  const pending = { id: "review", reason: "Synthetic pending review." };
  const closure = { id: "review", reason: "Synthetic review completed." };
  await f.record(
    reviewDraft(false, {
      deferred: [pending],
    }),
  );
  await f.record(
    reviewDraft(true, {
      resolvedDeferred: [closure],
    }),
  );
  const archive = path.join(f.workerRoot, "attempts/attempt-01");
  await f.archive(archive);
  const archived = await readFile(path.join(archive, "result.json"));
  await f.record(
    reviewDraft(true, {
      deferred: [{ ...pending, candidateId: "review" }],
    }),
  );
  const current = await readFile(f.resultPath);
  const accepted = JSON.parse(current.toString());
  assert.equal(accepted.reviewState.deferred.length, 1);
  assert.equal(accepted.reviewState.deferred[0].candidateId, "review");
  assert.equal(accepted.reviewState.resolvedDeferred?.length ?? 0, 0);
  const reduced = await publishAndReplay(f);
  assert.equal(reduced.sourceCoverage.deferred.length, 1);
  assert.equal(reduced.sourceCoverage.resolvedDeferred?.length ?? 0, 0);
  await assert.rejects(
    f.record(
      reviewDraft(true, {
        resolvedDeferred: [closure],
      }),
    ),
    /reviewState\.resolvedDeferred cannot close candidate review/,
  );
  assert.deepEqual(await readFile(f.resultPath), current);
  assert.deepEqual(await readFile(path.join(archive, "result.json")), archived);
});

for (const outcome of [
  "rejected",
  "not_applicable",
  "independent",
  "generic",
] as const) {
  test(`typed writer retry exclusion ${outcome} preserves the accepted candidate decision`, async (t) => {
    const f = await workerHistoryFixture(t, 2);
    const archivedFinding = {
      ...finding("archived-exclusion", "src/synthetic.ts"),
      provenance: { source: "local_plugin", candidateId: "candidate-1" },
    };
    await f.record(
      reviewDraft(
        true,
        {
          deferred: [
            {
              id: "generic-review",
              reason: "Synthetic independent proof remains.",
            },
          ],
        },
        [archivedFinding],
      ),
    );
    const archive = path.join(f.workerRoot, "attempts/attempt-01");
    await f.archive(archive);
    const historical = await readFile(path.join(archive, "result.json"));
    await mkdir(f.output, { recursive: true });
    const terminal = outcome === "rejected" || outcome === "not_applicable";
    const exclusion = {
      pattern: "src/synthetic.ts",
      reason: "Synthetic accepted exclusion decision.",
      ...(outcome === "generic"
        ? {}
        : {
            candidateId:
              outcome === "independent" ? "candidate-2" : "candidate-1",
            disposition: terminal ? outcome : "rejected",
          }),
    };
    const submitted = reviewDraft(true, {
      explicitExclusions: [exclusion],
    });
    await f.record(submitted);
    await f.validate();
    const current = await readFile(f.resultPath);
    const accepted = await f.readAccepted();
    assert.equal(accepted.result.findings.length, terminal ? 0 : 1);
    assert.equal(accepted.coverage.deferred.length, 1);
    assert.equal(
      accepted.coverage.deferred[0].reason,
      "Synthetic independent proof remains.",
    );
    const publishedExclusion = accepted.coverage.explicitExclusions[0];
    assert.equal(publishedExclusion.reason, exclusion.reason);
    if (terminal)
      assert.equal(publishedExclusion.finding.title, archivedFinding.title);
    const { sourceCoverage: coverage } = await publishAndReplay(f);
    assert.equal(coverage.explicitExclusions.length, 1);
    assert.equal(coverage.deferred.length, 1);
    assert.deepEqual(await readFile(f.resultPath), current);
    assert.deepEqual(
      await readFile(path.join(archive, "result.json")),
      historical,
    );
  });
}

for (const workflowVersion of [
  "deep-scan-mcp/v1",
  "deep-security-scan/v2",
] as const) {
  for (const stopBeforeDraft of [false, true]) {
    test(`worker retry evidence survives ${workflowVersion} ${stopBeforeDraft ? "stop and replay" : "completion"}`, async () => {
      const root = await temporaryDirectory("worker-retry-coverage-", true);
      try {
        const { scanDir } = await publishCoverageFixture(root, "complete", {
          workflowVersion,
          receiptRetry: true,
          streamRetry: true,
          outcome: stopBeforeDraft ? "no parent" : "completion",
        });
        const coverage = await readFixtureCoverage(scanDir);
        assert.equal(
          coverage.surfaces.find(
            (surface) => surface.label === "Current review",
          )?.provenance.attempt,
          2,
        );
        assert.ok(coverage.reviews.some((review) => review.attempt === 1));
        for (const surface of coverage.surfaces.filter((surface) =>
          surface.label.startsWith("Prior "),
        )) {
          assert.equal(surface.provenance.attempt, 1);
        }
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
  }
}
