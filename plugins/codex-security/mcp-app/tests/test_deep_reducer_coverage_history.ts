import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { importSource } from "./import-module.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import {
  workerHistoryFixture,
  workerDraft,
  scanId,
  finding,
} from "./scan-draft-fixture.ts";
import {
  publishCoverageFixture,
  readFixtureCoverage,
} from "./deep_scan_coverage_fixture.ts";

const source = fileURLToPath(new URL("../src", import.meta.url));
const { recordCodexSecurityWorkerScanDraft, parsePersistedScanDraft } =
  await importSource(path.join(source, "artifact-scan-draft.ts"));
const { readDeepReductionSources, recordCodexSecurityDeepReduction } =
  await importSource(path.join(source, "artifact-deep-reducer.ts"));
const {
  validateDiscoveryArtifacts,
  validateReducerArtifacts,
  parseDeepReduction,
  reconcileDeepReduction,
} = await importSource(path.join(source, "deep-scan/artifact-validation.ts"));
const { archiveDirectory, createDeepScanArtifacts } = await importSource(
  path.join(source, "deep-scan/artifacts.ts"),
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
  findings: unknown[] = [],
) {
  const sources = await readDeepReductionSources(f.context);
  await recordCodexSecurityDeepReduction(f.context, {
    scanId,
    complete: true,
    findings,
  });
  const resultPath = path.join(f.reducerRoot, "result.json");
  const input = {
    artifacts: createDeepScanArtifacts(f.scanRoot),
    artifactDir: f.reducerRoot,
    resultPath,
    reducerId: "dedup-0001",
    sources,
  };
  const accepted = await validateReducerArtifacts(input, scanId);
  const bytes = await readFile(resultPath);
  const persisted = JSON.parse(bytes.toString());
  assert.equal(Object.hasOwn(persisted, "sourceCoverage"), false);
  assert.deepEqual(
    parseDeepReduction(persisted).findings,
    accepted.result.findings,
  );
  for (const name of await readdir(path.join(f.reducerRoot, "checkpoints"))) {
    const checkpoint = JSON.parse(
      await readFile(path.join(f.reducerRoot, "checkpoints", name), "utf8"),
    );
    assert.equal(Object.hasOwn(checkpoint, "sourceCoverage"), false);
    parseDeepReduction(checkpoint);
  }
  const replay = await validateReducerArtifacts(input, scanId);
  assert.deepEqual(replay.result, accepted.result);
  assert.deepEqual(await readFile(resultPath), bytes);
  return accepted.result;
}

for (const close of [false, true]) {
  test(`accepted worker ${close ? "closure" : "pending control"} survives actual reducer publication`, async (t) => {
    const f = await workerHistoryFixture(t, 2);
    const pending = {
      id: "review",
      reason: "Synthetic review still needs evidence.",
    };
    await recordCodexSecurityWorkerScanDraft(
      f.workerContext,
      workerDraft([], {
        complete: false,
        reviewState: {
          surfaces: [],
          explicitExclusions: [],
          deferred: [pending],
        },
      }),
    );
    await recordCodexSecurityWorkerScanDraft(
      f.workerContext,
      workerDraft([], {
        complete: true,
        reviewState: {
          surfaces: [],
          explicitExclusions: [],
          deferred: close ? [] : [pending],
          ...(close
            ? {
                resolvedDeferred: [
                  { id: "review", reason: "Synthetic review completed." },
                ],
              }
            : {}),
        },
      }),
    );
    const original = await readFile(f.resultPath);
    const accepted = parsePersistedScanDraft(JSON.parse(original.toString()));
    if (close) assert.equal(accepted.reviewState.resolvedDeferred.length, 1);
    await validateDiscoveryArtifacts(
      { workersRoot: path.dirname(f.workerRoot) },
      f.resultPath,
      scanId,
    );
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
    await recordCodexSecurityWorkerScanDraft(
      f.workerContext,
      workerDraft([], {
        complete: false,
        reviewState: {
          surfaces: [],
          explicitExclusions: [],
          deferred: [{ id: "review", reason: "Synthetic pending review." }],
        },
      }),
    );
    await recordCodexSecurityWorkerScanDraft(
      f.workerContext,
      workerDraft([], {
        complete: true,
        reviewState: {
          surfaces: [],
          explicitExclusions: [],
          deferred: [],
          resolvedDeferred: [{ id: "review", reason: "Original closure." }],
        },
      }),
    );
    const archive = path.join(f.workerRoot, "attempts/attempt-01");
    await archiveDirectory(f.output, archive);
    const historical = await readFile(path.join(archive, "result.json"));
    await mkdir(f.output, { recursive: true });
    const current = workerDraft([], { complete: true });
    if (changed)
      Object.assign(current.reviewState, {
        resolvedDeferred: [{ id: "review", reason: "Updated closure." }],
      });
    await recordCodexSecurityWorkerScanDraft(f.workerContext, current);
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
      sourceCoverage.reviews.some(
        (review: { attempt: number }) => review.attempt === attempt,
      ),
    );
    assert.equal(sourceCoverage.deferred.length, 0);
    const canonical = structuredClone(acceptedReduction);
    const nextReduction = reconcileDeepReduction(
      { scanId, complete: true, findings: [] },
      [],
      acceptedReduction,
    );
    assert.deepEqual(nextReduction.sourceCoverage, canonical.sourceCoverage);
    assert.deepEqual(acceptedReduction, canonical);
    assert.deepEqual(await readFile(f.resultPath), original);
    const secondArchive = path.join(f.workerRoot, "attempts/attempt-02");
    await archiveDirectory(f.output, secondArchive);
    f.context.deepReducer.claimedWorkers[0].attempt = 3;
    await recordCodexSecurityWorkerScanDraft(
      f.workerContext,
      workerDraft([], { complete: true }),
    );
    const repeated = await publishAndReplay(f);
    assert.deepEqual(
      repeated.sourceCoverage.resolvedDeferred,
      sourceCoverage.resolvedDeferred,
    );
    assert.ok(
      repeated.sourceCoverage.reviews.some(
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
]) {
  const archived = history === "archived";
  test(`an accepted direct-file result retains ${history} checkpoint coverage without rewriting artifacts`, async (t) => {
    const f = await workerHistoryFixture(t, 2);
    await recordCodexSecurityWorkerScanDraft(
      f.workerContext,
      workerDraft([], {
        complete: false,
        reviewState: {
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
        },
      }),
    );
    if (archived) {
      await archiveDirectory(
        f.output,
        path.join(f.workerRoot, "attempts/attempt-01"),
      );
    }
    if (history === "malformed optional current history") {
      await writeFile(path.join(f.output, "checkpoints/unusable.json"), "{");
      const head = path.join(f.output, "checkpoint-head.json");
      await rm(head);
      await mkdir(head);
    }
    await mkdir(f.output, { recursive: true });
    const terminal = workerDraft([], { complete: true });
    await writeFile(f.resultPath, JSON.stringify(terminal));
    const before = await artifactTree(f.scanRoot);
    const admitted = await validateDiscoveryArtifacts(
      createDeepScanArtifacts(f.scanRoot),
      f.resultPath,
      scanId,
    );
    assert.deepEqual(admitted.findings, terminal.findings);
    assert.equal(admitted.reviewState.surfaces.length, 0);
    const source = (await readDeepReductionSources(f.context)).discoveries[0];
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
    await recordCodexSecurityWorkerScanDraft(
      f.workerContext,
      workerDraft([], {
        complete: false,
        reviewState: {
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
          explicitExclusions: [],
          deferred: [
            {
              id: "review-gap",
              reason: "Synthetic pending evidence.",
              surfaceIds: ["review"],
            },
          ],
        },
      }),
    );
    await archiveDirectory(
      f.output,
      path.join(f.workerRoot, "attempts/attempt-01"),
    );
    await mkdir(path.join(f.output, "artifacts"), { recursive: true });
    await writeFile(
      path.join(f.output, replacement),
      "Synthetic replacement evidence.\n",
    );
    await writeFile(
      f.resultPath,
      JSON.stringify(
        workerDraft([], {
          complete: true,
          reviewState: {
            surfaces: [
              {
                id: "review",
                label: "Synthetic review",
                disposition: "no_issue_found",
                receiptRefs:
                  repair === "no valid replacement" ? [] : [replacement],
              },
            ],
            explicitExclusions: [],
            deferred: [],
            resolvedDeferred: [
              { id: "review-gap", reason: "Synthetic completed evidence." },
            ],
          },
        }),
      ),
    );
    await validateDiscoveryArtifacts(
      createDeepScanArtifacts(f.scanRoot),
      f.resultPath,
      scanId,
    );
    const before = await artifactTree(f.scanRoot);
    const { coverage } = (await readDeepReductionSources(f.context))
      .discoveries[0];
    assert.deepEqual(await artifactTree(f.scanRoot), before);
    const reviewed = coverage.surfaces.find(
      (row: { label: string }) => row.label === "Synthetic review",
    );
    assert.ok(reviewed);
    const archivedMissing =
      "artifacts/deep_discovery/workers/discovery-0001/attempts/attempt-01/" +
      missing;
    assert.equal(
      reviewed.receiptRefs.includes(archivedMissing),
      repair === "no valid replacement",
    );
    assert.ok(
      reviewed.receiptRefs.some((ref: string) => ref.endsWith("/" + original)),
      "Keep independent readable evidence from the earlier observation.",
    );
    if (repair === "independent source") {
      const independent = coverage.surfaces.find(
        (row: { label: string }) =>
          row.label === "Independent incomplete review",
      );
      assert.ok(independent);
      assert.equal(independent.disposition, "needs_follow_up");
      assert.deepEqual(independent.receiptRefs, [archivedMissing]);
    }
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
    await recordCodexSecurityWorkerScanDraft(
      f.workerContext,
      workerDraft([], {
        complete: false,
        reviewState: {
          surfaces: [surface],
          explicitExclusions: [],
          deferred: [
            {
              id: "review-gap",
              reason: "Synthetic pending proof.",
              surfaceIds: [surface.id],
            },
          ],
        },
      }),
    );
    const archive = path.join(f.workerRoot, "attempts/attempt-01");
    await archiveDirectory(f.output, archive);
    await mkdir(path.dirname(path.join(f.output, receipt)), {
      recursive: true,
    });
    await writeFile(
      path.join(f.output, receipt),
      copy === "same bytes independent receipt"
        ? originalBytes
        : "Synthetic current receipt.\n",
    );
    await recordCodexSecurityWorkerScanDraft(
      f.workerContext,
      workerDraft([], {
        complete: true,
        reviewState: {
          surfaces: [{ ...surface, disposition: "no_issue_found" }],
          explicitExclusions: [],
          deferred: [],
          resolvedDeferred: [
            { id: "review-gap", reason: "Synthetic completed proof." },
          ],
        },
      }),
    );
    const accepted = JSON.parse(await readFile(f.resultPath, "utf8"));
    assert.equal(accepted.reviewState.surfaces[0].receiptRefs.length, 2);
    const prefix = "artifacts/deep_discovery/workers/discovery-0001/";
    const copied = `${prefix}output/artifacts/archived-receipts/attempt-01/${receipt}`;
    const original = `${prefix}attempts/attempt-01/${receipt}`;
    assert.ok(accepted.reviewState.surfaces[0].receiptRefs.includes(copied));
    await validateDiscoveryArtifacts(
      createDeepScanArtifacts(f.scanRoot),
      f.resultPath,
      scanId,
    );
    if (copy === "changed")
      await writeFile(
        path.join(f.scanRoot, copied),
        "Synthetic changed copy.\n",
      );
    if (copy === "missing") await rm(path.join(f.scanRoot, copied));
    const before = await artifactTree(f.scanRoot);
    const source = (await readDeepReductionSources(f.context)).discoveries[0];
    assert.deepEqual(await artifactTree(f.scanRoot), before);
    assert.equal(source.coverage.surfaces.length, 1);
    const refs = source.coverage.surfaces[0].receiptRefs;
    const preservedOriginal = copy === "changed" || copy === "missing";
    assert.equal(refs.length, preservedOriginal ? 3 : 2);
    assert.equal(refs.includes(original), preservedOriginal);
    assert.ok(refs.includes(copied));
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
  await recordCodexSecurityWorkerScanDraft(
    f.workerContext,
    workerDraft([], {
      complete: false,
      reviewState: {
        surfaces: [
          repeated,
          {
            id: "independent-review",
            label: "Synthetic independent archived review",
            disposition: "needs_follow_up",
            receiptRefs: [ref],
          },
        ],
        explicitExclusions: [],
        deferred: [],
      },
    }),
  );
  const recorded = JSON.parse(await readFile(f.resultPath, "utf8"));
  for (const surface of recorded.reviewState.surfaces) {
    assert.deepEqual(surface.provenance.scanReceiptRefs, [ref]);
  }
  await archiveDirectory(
    f.output,
    path.join(f.workerRoot, "attempts/attempt-01"),
  );
  await mkdir(path.dirname(path.join(f.output, ref)), { recursive: true });
  await writeFile(path.join(f.output, ref), localBytes);
  await writeFile(
    f.resultPath,
    JSON.stringify(
      workerDraft([], {
        complete: true,
        reviewState: {
          surfaces: [{ ...repeated, provenance: { scanReceiptRefs: [ref] } }],
          explicitExclusions: [],
          deferred: [],
        },
      }),
    ),
  );
  const before = await artifactTree(f.scanRoot);
  const admitted = await validateDiscoveryArtifacts(
    createDeepScanArtifacts(f.scanRoot),
    f.resultPath,
    scanId,
  );
  assert.equal(
    admitted.reviewState.surfaces[0].provenance.scanReceiptRefs,
    undefined,
  );
  const { coverage } = (await readDeepReductionSources(f.context))
    .discoveries[0];
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
  await recordCodexSecurityWorkerScanDraft(
    f.workerContext,
    workerDraft([], {
      complete: false,
      reviewState: {
        surfaces: [],
        explicitExclusions: [],
        deferred: [pending],
      },
    }),
  );
  await recordCodexSecurityWorkerScanDraft(
    f.workerContext,
    workerDraft([], {
      complete: true,
      reviewState: {
        surfaces: [],
        explicitExclusions: [],
        deferred: [],
        resolvedDeferred: [closure],
      },
    }),
  );
  const archive = path.join(f.workerRoot, "attempts/attempt-01");
  await archiveDirectory(f.output, archive);
  const archived = await readFile(path.join(archive, "result.json"));
  await recordCodexSecurityWorkerScanDraft(
    f.workerContext,
    workerDraft([], {
      complete: true,
      reviewState: {
        surfaces: [],
        explicitExclusions: [],
        deferred: [{ ...pending, candidateId: "review" }],
      },
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
    recordCodexSecurityWorkerScanDraft(
      f.workerContext,
      workerDraft([], {
        complete: true,
        reviewState: {
          surfaces: [],
          explicitExclusions: [],
          deferred: [],
          resolvedDeferred: [closure],
        },
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
    await recordCodexSecurityWorkerScanDraft(
      f.workerContext,
      workerDraft([archivedFinding], {
        complete: true,
        reviewState: {
          surfaces: [],
          explicitExclusions: [],
          deferred: [
            {
              id: "generic-review",
              reason: "Synthetic independent proof remains.",
            },
          ],
        },
      }),
    );
    const archive = path.join(f.workerRoot, "attempts/attempt-01");
    await archiveDirectory(f.output, archive);
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
    const submitted = workerDraft([], {
      complete: true,
      reviewState: {
        surfaces: [],
        explicitExclusions: [exclusion],
        deferred: [],
      },
    });
    await recordCodexSecurityWorkerScanDraft(f.workerContext, submitted);
    await validateDiscoveryArtifacts(
      { workersRoot: path.dirname(f.workerRoot) },
      f.resultPath,
      scanId,
    );
    const current = await readFile(f.resultPath);
    const inputs = await readDeepReductionSources(f.context);
    const accepted = inputs.discoveries[0];
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
    const { sourceCoverage: coverage } = await publishAndReplay(
      f,
      accepted.result.findings,
    );
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
    test(`typed reducer artifacts remain compatible through ${workflowVersion} ${stopBeforeDraft ? "stop and replay" : "completion"}`, async () => {
      const root = await temporaryDirectory(
        "reducer-format-compatibility-",
        true,
      );
      try {
        const { scanDir } = await publishCoverageFixture(root, "complete", {
          workflowVersion,
          receiptRetry: true,
          streamRetry: true,
          stopBeforeDraft,
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
