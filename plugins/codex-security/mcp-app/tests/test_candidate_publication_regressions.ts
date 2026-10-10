import assert from "node:assert/strict";
import { mkdir, readFile, readdir, utimes, writeFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import { importSource } from "./import-module.ts";
import {
  draftApi,
  fixture,
  recordCodexSecurityScanDraft,
} from "./scan-draft-recovery-fixture.ts";
import { finding, workerDraft } from "./scan-draft-fixture.ts";

const {
  deepReductionScanDraft,
  discoveryReductionInput,
  reconcileDeepReduction,
  validateDiscoveryArtifacts,
} = await importSource(
  new URL("../src/deep-scan/artifact-validation.ts", import.meta.url).pathname,
);

const savedOwners = [
  null,
  ["legacy-worker"],
  { worker: "legacy-worker" },
  "",
  " ",
  "legacy-worker",
];

for (const mode of ["standard", "diff", "worker"] as const) {
  for (const source of ["published", "checkpoint"] as const) {
    for (const field of ["surfaces", "deferred"] as const) {
      for (const [index, owner] of savedOwners.entries()) {
        test(`updates saved ${mode}/${source}/${field} owner metadata ${index}`, async (t) => {
          const f = await fixture(t, mode);
          const row =
            field === "surfaces"
              ? {
                  id: "legacy-surface",
                  label: "Saved review",
                  disposition: "needs_follow_up",
                }
              : { id: "legacy-gap", reason: "Retain the saved proof gap." };
          const legacyCoverage = {
            [field]: [{ ...row, sourceWorkerId: owner }],
          };
          await f.write(
            f.draft({ [field]: [{ ...row, sourceWorkerId: "legacy-worker" }] }),
          );
          if (source === "checkpoint") {
            // Model a later checkpoint without relying on filesystem clock precision.
            const previous = [
              path.join(
                f.root,
                mode === "worker" ? "result.json" : "coverage.json",
              ),
              path.join(f.root, "checkpoint-head.json"),
              ...(await readdir(path.join(f.root, "checkpoints"))).map((name) =>
                path.join(f.root, "checkpoints", name),
              ),
            ];
            await Promise.all(previous.map((file) => utimes(file, 1, 1)));
            await draftApi.saveScanDraftCheckpoint(
              f.context,
              f.draft(legacyCoverage),
            );
          } else {
            const file = path.join(
              f.root,
              mode === "worker" ? "result.json" : "coverage.json",
            );
            const saved = JSON.parse(await readFile(file, "utf8"));
            const coverage = mode === "worker" ? saved.coverage : saved;
            coverage[field][0].sourceWorkerId = owner;
            const earlierFiles = [
              path.join(f.root, "checkpoint-head.json"),
              ...(await readdir(path.join(f.root, "checkpoints"))).map((name) =>
                path.join(f.root, "checkpoints", name),
              ),
            ];
            await Promise.all(earlierFiles.map((saved) => utimes(saved, 1, 1)));
            await writeFile(file, JSON.stringify(saved, null, 2) + "\n");
          }
          const checkpointRoot = path.join(f.root, "checkpoints");
          const checkpoints = await Promise.all(
            (await readdir(checkpointRoot)).map(
              async (name) =>
                [
                  name,
                  await readFile(path.join(checkpointRoot, name), "utf8"),
                ] as const,
            ),
          );
          await f.write(
            f.draft({
              deferred: [
                {
                  id: "independent-gap",
                  reason: "Independent unfinished work.",
                },
              ],
            }),
          );
          for (const [name, contents] of checkpoints)
            assert.equal(
              await readFile(path.join(checkpointRoot, name), "utf8"),
              contents,
            );
          const restored = await f.read();
          assert.ok(
            restored[field].some(
              (saved: { sourceWorkerId?: unknown }) =>
                JSON.stringify(saved.sourceWorkerId) === JSON.stringify(owner),
            ),
          );
          assert.ok(
            restored.deferred.some(
              (saved: { id: string }) => saved.id === "independent-gap",
            ),
          );
        });
      }
    }
  }
}

for (const field of ["surfaces", "deferred"] as const) {
  for (const [index, owner] of savedOwners.entries()) {
    test(`recovers persisted Deep worker ${field} owner metadata ${index}`, async (t) => {
      const f = await fixture(t, "worker");
      await f.write({
        ...f.draft(
          {
            surfaces: [
              {
                id: "legacy-surface",
                label: "Saved review",
                disposition: "needs_follow_up",
                sourceWorkerId: "legacy-worker",
              },
            ],
            deferred: [
              {
                id: "legacy-gap",
                candidateId: "legacy-gap",
                reason: "Retain the saved proof gap.",
                sourceWorkerId: "legacy-worker",
              },
            ],
          },
          true,
        ),
        complete: true,
      });
      const resultPath = path.join(f.root, "result.json");
      const saved = JSON.parse(await readFile(resultPath, "utf8"));
      saved.coverage[field][0].sourceWorkerId = owner;
      const contents = JSON.stringify(saved, null, 2) + "\n";
      await writeFile(resultPath, contents);
      const restored = await validateDiscoveryArtifacts(
        {
          scanDir: path.dirname(f.root),
          workersRoot: path.dirname(f.root),
          dedupRoot: path.join(path.dirname(f.root), "dedup"),
        },
        resultPath,
        f.context.scanId,
      );
      assert.deepEqual(restored.coverage[field][0].sourceWorkerId, owner);
      assert.deepEqual(
        discoveryReductionInput(restored, "actual-worker").unresolvedCandidates,
        [{ ...saved.coverage.deferred[0], sourceWorkerId: "actual-worker" }],
      );
      assert.equal(await readFile(resultPath, "utf8"), contents);
    });
  }
}

for (const candidateId of ["legacy-candidate", "review/auth"]) {
  for (const mode of ["standard", "diff", "worker"] as const) {
    for (const outcome of ["reported", "rejected"] as const) {
      for (const sameOwner of [false, true]) {
        if (mode === "worker" && !sameOwner) continue;
        for (const payload of ["candidate", "finding"] as const) {
          test(`legacy candidate coverage reconciles ${candidateId}/${mode}/${outcome}/${payload}/${sameOwner ? "same" : "other"} owner`, async (t) => {
            const f = await fixture(t, mode);
            const previous = {
              id: candidateId,
              sourceWorkerId: "worker-before",
              reason: "Saved candidate evidence remains available.",
              [payload]: {
                ...finding("legacy", "src/legacy.ts"),
                summary: "Saved older review evidence.",
              },
            };
            const generic = {
              id: "generic-review",
              reason: "Independent unfinished work.",
            };
            await f.write(f.draft({ deferred: [previous, generic] }));
            const current = finding("legacy", "src/legacy.ts");
            const resolved = {
              ...current,
              provenance: {
                ...current.provenance,
                candidateId,
                sourceWorkerId: sameOwner ? "worker-before" : "worker-after",
              },
            };
            await f.write({
              ...f.draft(),
              findings: outcome === "reported" ? [resolved] : [],
              coverage: {
                ...f.draft().coverage,
                surfaces:
                  outcome === "rejected"
                    ? [
                        {
                          id: "current-decision",
                          candidateId,
                          sourceWorkerId: resolved.provenance.sourceWorkerId,
                          label: "Current candidate review",
                          disposition: "rejected",
                          notes: "Current validation resolved this candidate.",
                        },
                      ]
                    : [],
              },
            });
            const coverage = await f.read();
            assert.equal(
              coverage.deferred.some(
                (row: { id: string }) => row.id === candidateId,
              ),
              !sameOwner,
            );
            assert.ok(
              coverage.deferred.some(
                (row: { id: string }) => row.id === generic.id,
              ),
            );
            if (sameOwner && outcome === "reported") {
              const saved = JSON.parse(
                await readFile(
                  path.join(
                    f.root,
                    mode === "worker" ? "result.json" : "findings.json",
                  ),
                  "utf8",
                ),
              );
              assert.ok(
                JSON.stringify(saved.findings[0].provenance).includes(
                  "Saved older review evidence.",
                ),
              );
            }
          });
        }
      }
    }
  }
}

const { recordCodexSecurityScanDraftViaWorkbench } = await importSource(
  new URL("../src/artifact-scan-draft.ts", import.meta.url).pathname,
);

test("publishes colliding worker-local deferred IDs without changing their evidence", async (t) => {
  const { context } = await fixture(t, "deep");
  const candidate = {
    id: "candidate-review",
    candidateId: "candidate-review",
    reason: "Synthetic validation remains pending.",
    candidate: { evidence: "Retain the saved review evidence." },
  };
  const discoveries = ["worker-one", "worker-two", "worker-three"].map(
    (workerId, index) => ({
      workerId,
      result: discoveryReductionInput(
        workerDraft([], {
          scanId: context.scanId,
          coverage: {
            completeness: "partial",
            surfaces: [],
            explicitExclusions: [],
            deferred: [
              {
                ...candidate,
                ...(index === 2
                  ? { id: "candidate-review-2", candidateId: "reserved-review" }
                  : {}),
              },
            ],
          },
        }),
        workerId,
      ),
    }),
  );
  const aggregate = reconcileDeepReduction(
    { scanId: context.scanId, findings: [] },
    discoveries,
    null,
  );
  const original = structuredClone(aggregate);
  const projected = deepReductionScanDraft(aggregate);
  let published = false;
  await recordCodexSecurityScanDraftViaWorkbench(
    context,
    { ...projected, handoffClaimToken: context.handoffClaimToken },
    async (args: string[]) => {
      const draft = JSON.parse(
        await readFile(args[args.indexOf("--draft-path") + 1]!, "utf8"),
      );
      const rows = draft.coverage.deferred;
      assert.equal(new Set(rows.map((row: { id: string }) => row.id)).size, 3);
      assert.equal(rows[2].id, "candidate-review-2");
      for (let index = 0; index < rows.length; index++) {
        const { id: _id, ...actual } = rows[index];
        const { id: _localId, ...expected } =
          original.unresolvedCandidates[index];
        assert.deepEqual(actual, expected);
      }
      published = true;
    },
  );
  assert.equal(published, true);
  assert.deepEqual(aggregate, original);
  assert.deepEqual(deepReductionScanDraft(aggregate), projected);
});

for (const mode of ["standard", "diff"] as const) {
  for (const identity of ["derived", "explicit"] as const) {
    for (const owner of ["changed", "omitted"] as const) {
      test(`keeps a ${mode} reassessment with ${identity} identity and ${owner} attribution`, async (t) => {
        const { context, draft } = await fixture(t, mode);
        const { identity: _identity, ...details } = finding(
          "shared",
          "src/handler.ts",
        );
        const earlier = {
          ...details,
          ...(identity === "explicit"
            ? { identity: { anchor: "shared-review" } }
            : {}),
          provenance: {
            source: "local_plugin",
            sourceWorkerId: "earlier-worker",
          },
        };
        const current = {
          ...earlier,
          summary: "Current evidence lowers the severity.",
          severity: { level: "low" },
          provenance: {
            source: "local_plugin",
            ...(owner === "changed"
              ? { sourceWorkerId: "current-worker" }
              : {}),
          },
        };
        await recordCodexSecurityScanDraft(context, {
          ...draft({}, true),
          findings: [earlier],
        });
        for (const replay of [false, true]) {
          await recordCodexSecurityScanDraft(context, {
            ...draft({}, true),
            findings: [current],
          });
          const saved = JSON.parse(
            await readFile(path.join(context.root, "findings.json"), "utf8"),
          );
          assert.equal(saved.findings.length, 1, `replay=${replay}`);
          assert.equal(saved.findings[0].severity.level, "low");
          assert.equal(saved.findings[0].summary, current.summary);
          const history = saved.findings[0].provenance.previousFindings;
          assert.deepEqual(
            identity === "explicit"
              ? history
              : history.filter(
                  (item: { identity?: unknown }) => item.identity === undefined,
                ),
            [earlier],
          );
        }

        const independentRoot = path.join(context.root, "independent");
        await mkdir(independentRoot);
        const independentContext = { ...context, root: independentRoot };
        await recordCodexSecurityScanDraft(independentContext, {
          ...draft({}, true),
          findings: [
            { ...earlier, identity: { anchor: "shared-review" } },
            {
              ...current,
              identity: { anchor: "shared-review", instance: "independent" },
            },
          ],
        });
        const independent = JSON.parse(
          await readFile(path.join(independentRoot, "findings.json"), "utf8"),
        );
        assert.equal(independent.findings.length, 2);
      });
    }
  }

  for (const candidate of ["same", "different"] as const) {
    for (const owner of ["changed", "omitted"] as const) {
      test(`keeps independent ${mode} candidates with ${candidate} ID and ${owner} owner`, async (t) => {
        const { context, draft } = await fixture(t, mode);
        const { identity: _identity, ...details } = finding(
          "shared",
          "src/handler.ts",
        );
        const earlier = {
          ...details,
          provenance: {
            source: "local_plugin",
            candidateId: "candidate-a",
            sourceWorkerId: "earlier-worker",
          },
        };
        const current = {
          ...details,
          severity: { level: "low" },
          provenance: {
            source: "local_plugin",
            candidateId: candidate === "same" ? "candidate-a" : "candidate-b",
            ...(owner === "changed"
              ? { sourceWorkerId: "current-worker" }
              : {}),
          },
        };
        await recordCodexSecurityScanDraft(context, {
          ...draft({}, true),
          findings: [earlier],
        });
        for (const replay of [false, true]) {
          await recordCodexSecurityScanDraft(context, {
            ...draft({}, true),
            findings: [current],
          });
          const saved = JSON.parse(
            await readFile(path.join(context.root, "findings.json"), "utf8"),
          );
          assert.equal(saved.findings.length, 2, `replay=${replay}`);
          assert.deepEqual(
            saved.findings.map(
              (item: { severity: { level: string } }) => item.severity.level,
            ),
            ["low", "high"],
          );
          assert.deepEqual(saved.findings[0].provenance, current.provenance);
          assert.deepEqual(saved.findings[1].provenance, earlier.provenance);
        }
      });
    }
  }
}

for (const mode of ["standard", "diff"] as const) {
  for (const sharedId of [false, true]) {
    test(`preserves owner-linked ${mode} deferred surfaces with sharedId=${sharedId}`, async (t) => {
      const f = await fixture(t, mode);
      const earlier = {
        id: sharedId ? "review" : "earlier-review",
        label: "Earlier worker review",
        sourceWorkerId: "worker-before",
        disposition: "needs_follow_up",
        notes: "Earlier independent review evidence.",
      };
      await f.write(
        f.draft({
          surfaces: [earlier],
          deferred: [
            {
              id: "earlier-pending",
              candidateId: "earlier-candidate",
              sourceWorkerId: "worker-before",
              reason: "Earlier independent proof gap.",
              surfaceIds: [earlier.id],
            },
          ],
        }),
      );
      const current = {
        id: "review",
        label: "Current worker review",
        sourceWorkerId: "worker-after",
        disposition: "needs_follow_up",
        notes: "Current independent review evidence.",
      };
      const next = f.draft({
        surfaces: [current],
        deferred: [
          {
            id: "current-pending",
            candidateId: "current-candidate",
            sourceWorkerId: "worker-after",
            reason: "Current independent proof gap.",
            surfaceIds: [current.id],
          },
        ],
      });
      for (let replay = 0; replay < 2; replay++) {
        await f.write(next);
        const coverage = await f.read();
        for (const original of [earlier, current]) {
          const pending = coverage.deferred.find(
            (row: any) => row.sourceWorkerId === original.sourceWorkerId,
          );
          assert.ok(
            pending,
            "each independent worker's pending work remains available",
          );
          const linked = coverage.surfaces.find(
            (row: any) => row.id === pending.surfaceIds[0],
          );
          assert.equal(linked?.sourceWorkerId, original.sourceWorkerId);
          assert.equal(linked.notes, original.notes);
        }
        assert.equal(
          new Set(coverage.surfaces.map((row: any) => row.id)).size,
          coverage.surfaces.length,
        );
      }
    });
  }
}

for (const provenance of [undefined, null, "Saved annotation", {}]) {
  for (const disposition of ["rejected", "not_applicable"] as const) {
    test(`preserves compact rejected candidate evidence: ${JSON.stringify(provenance)}/${disposition}`, async (t) => {
      const f = await fixture(t, "standard");
      const original = finding("earlier", "src/handler.ts");
      const canonical = {
        ...original,
        provenance: {
          ...original.provenance,
          candidateId: "candidate-evidence",
        },
      };
      await f.write({ ...f.draft({}, true), findings: [canonical] });
      const compact = {
        title: "Earlier authored evidence",
        ...(provenance === undefined ? {} : { provenance }),
      };
      await f.write(
        f.draft(
          {
            surfaces: [
              {
                id: "candidate-decision",
                candidateId: "candidate-evidence",
                label: "Reviewed candidate",
                disposition,
                finding: compact,
                notes: "Authored review rationale.",
              },
            ],
          },
          true,
        ),
      );
      const coverage = await f.read();
      const row = coverage.surfaces.find(
        (item: { candidateId?: string }) =>
          item.candidateId === "candidate-evidence",
      );
      if (provenance && typeof provenance === "object") {
        assert.equal(row.finding.title, compact.title);
        assert.deepEqual(row.finding.provenance.previousFindings, [canonical]);
      } else {
        assert.deepEqual(row.finding, compact);
        assert.deepEqual(row.previousFindings, [canonical]);
      }
      assert.equal(row.notes, "Authored review rationale.");
      await f.write(f.draft({}, true));
      assert.deepEqual(
        (await f.read()).surfaces.find(
          (item: { candidateId?: string }) =>
            item.candidateId === "candidate-evidence",
        ),
        row,
      );
    });
  }
}

for (const mode of ["standard", "diff"] as const) {
  for (const disposition of [
    undefined,
    "imported-review",
    "rejected",
  ] as const) {
    for (const update of ["deferred", "finding"] as const) {
      test(`saved ordinary exclusion survives ${mode}/${disposition}/${update}`, async (t) => {
        const f = await fixture(t, mode);
        const exclusion = {
          pattern: "vendor/**",
          reason: "Third-party sources were excluded.",
          candidateId: "review-candidate",
          sourceWorkerId: "review-worker",
          annotation: "Preserve the original scope rationale.",
          ...(disposition === undefined ? {} : { disposition }),
        };
        await f.write(f.draft({ explicitExclusions: [exclusion] }));
        const current = f.draft({
          deferred:
            update === "deferred"
              ? [
                  {
                    id: "current-review",
                    candidateId: "review-candidate",
                    sourceWorkerId: "review-worker",
                    reason: "The candidate still needs validation.",
                  },
                ]
              : [],
        });
        if (update === "finding") {
          const reported = finding("current", "src/handler.ts");
          current.findings = [
            {
              ...reported,
              provenance: {
                ...reported.provenance,
                candidateId: "review-candidate",
                sourceWorkerId: "review-worker",
              },
            },
          ];
        }
        await f.write(current);
        const saved = await f.read();
        assert.equal(
          saved.explicitExclusions.some(
            (row: unknown) => JSON.stringify(row) === JSON.stringify(exclusion),
          ),
          disposition !== "rejected",
        );
      });
    }
  }
  for (const source of ["published", "checkpoint"] as const) {
    for (const legacy of [true, false]) {
      test(`saved surface extension identifier remains readable ${mode}/${source}/${legacy}`, async (t) => {
        const f = await fixture(t, mode);
        const previous = {
          id: "historical-review",
          label: "Saved review",
          disposition: "no_issue_found",
          candidateId: legacy ? "review/auth" : "review-auth",
          notes: "Preserve original historical metadata.",
        };
        await f.write(
          f.draft({ surfaces: [{ ...previous, candidateId: "review-auth" }] }),
        );
        if (source === "checkpoint") {
          const earlierFiles = [
            path.join(f.root, "coverage.json"),
            path.join(f.root, "checkpoint-head.json"),
            ...(await readdir(path.join(f.root, "checkpoints"))).map((name) =>
              path.join(f.root, "checkpoints", name),
            ),
          ];
          await Promise.all(earlierFiles.map((file) => utimes(file, 1, 1)));
          await draftApi.saveScanDraftCheckpoint(
            f.context,
            f.draft({ surfaces: [previous] }),
          );
        } else {
          const file = path.join(f.root, "coverage.json");
          const coverage = JSON.parse(await readFile(file, "utf8"));
          coverage.surfaces[0].candidateId = previous.candidateId;
          const earlierFiles = [
            path.join(f.root, "checkpoint-head.json"),
            ...(await readdir(path.join(f.root, "checkpoints"))).map((name) =>
              path.join(f.root, "checkpoints", name),
            ),
          ];
          await Promise.all(earlierFiles.map((saved) => utimes(saved, 1, 1)));
          await writeFile(file, JSON.stringify(coverage, null, 2) + "\n");
        }
        await f.write(
          f.draft({
            deferred: [
              { id: "independent-gap", reason: "Independent unfinished work." },
            ],
          }),
        );
        const saved = await f.read();
        assert.ok(
          saved.surfaces.some(
            (row: any) =>
              row.candidateId === previous.candidateId &&
              row.notes === previous.notes,
          ),
        );
        assert.ok(
          saved.deferred.some((row: any) => row.id === "independent-gap"),
        );
      });
    }
  }
}

for (const mode of ["standard", "diff"] as const) {
  for (const duplicateId of [false, true]) {
    test(`replays owner-distinct deferred rows in ${mode} (duplicate ID: ${duplicateId})`, async (t) => {
      const f = await fixture(t, mode);
      const original = {
        id: "shared-gap",
        candidateId: "candidate-a",
        sourceWorkerId: "worker-a",
        reason: "Original worker source proof remains.",
        candidate: { evidence: "Original candidate evidence." },
      };
      const incoming = {
        id: duplicateId ? original.id : "independent-gap",
        candidateId: "candidate-b",
        sourceWorkerId: "worker-b",
        reason: "Independent worker source proof remains.",
        candidate: { evidence: "Independent candidate evidence." },
      };
      await f.write(f.draft({ deferred: [original] }));
      await f.write(f.draft({ deferred: [incoming] }));
      const saved = await f.read();
      assert.equal(saved.deferred.length, 2);
      assert.equal(
        new Set(saved.deferred.map((row: { id: string }) => row.id)).size,
        2,
      );
      for (const row of [original, incoming]) {
        const restored = saved.deferred.find(
          (item: { sourceWorkerId: string }) =>
            item.sourceWorkerId === row.sourceWorkerId,
        );
        assert.deepEqual({ ...restored, id: row.id }, row);
      }
      await f.write(
        f.draft({
          surfaces: saved.surfaces,
          deferred: saved.deferred,
          explicitExclusions: saved.explicitExclusions,
        }),
      );
      assert.deepEqual((await f.read()).deferred, saved.deferred);
    });
  }
}

for (const mode of ["standard", "diff"] as const) {
  for (const independentPending of [false, true]) {
    test(`retains merged candidate resolutions: ${mode}, independent=${independentPending}`, async (t) => {
      const f = await fixture(t, mode);
      const candidateId = "candidate-shared";
      const pending = (sourceWorkerId: string) => ({
        id: `${sourceWorkerId}-gap`,
        candidateId,
        sourceWorkerId,
        reason: "Saved proof gap.",
      });
      await f.write(
        f.draft({
          deferred: [
            pending("worker-b"),
            ...(independentPending ? [pending("worker-c")] : []),
          ],
        }),
      );
      const earlier = {
        ...finding("shared", "src/handler.ts"),
        provenance: {
          source: "local_plugin",
          candidateId,
          sourceWorkerId: "worker-b",
        },
      };
      await f.write({ ...f.draft({}, true), findings: [earlier] });
      const checkpoints = path.join(f.root, "checkpoints");
      const originalBytes = await Promise.all(
        (await readdir(checkpoints)).map(
          async (name) =>
            [
              name,
              await readFile(path.join(checkpoints, name), "utf8"),
            ] as const,
        ),
      );
      const current = {
        ...earlier,
        provenance: { ...earlier.provenance, sourceWorkerId: "worker-a" },
      };
      for (let replay = 0; replay < 2; replay++) {
        await f.write({ ...f.draft({}, true), findings: [current] });
        const coverage = await f.read();
        assert.equal(
          coverage.completeness,
          independentPending ? "partial" : "complete",
        );
        assert.deepEqual(
          coverage.deferred,
          independentPending ? [pending("worker-c")] : [],
        );
        const saved = JSON.parse(
          await readFile(path.join(f.root, "findings.json"), "utf8"),
        );
        assert.equal(saved.findings.length, 1);
        assert.equal(saved.findings[0].provenance.sourceWorkerId, "worker-a");
        assert.ok(
          saved.findings[0].provenance.previousFindings.some(
            (row: typeof earlier) =>
              row.provenance.sourceWorkerId === "worker-b",
          ),
        );
      }
      for (const [name, bytes] of originalBytes)
        assert.equal(
          await readFile(path.join(checkpoints, name), "utf8"),
          bytes,
        );
    });
  }
}

for (const reopened of [false, true]) {
  for (const disposition of ["deferred", "suppressed"]) {
    test(`Diff draft respects recovered candidate status: ${reopened}/${disposition}`, async (t) => {
      const f = await fixture(t, "diff");
      const candidateId = "reopened-candidate";
      const historical = {
        ...finding("reopened", "src/handler.ts"),
        provenance: {
          source: "local_plugin",
          candidateId,
          candidateReopened: reopened,
        },
      };
      const pending = {
        candidateId,
        reason: "New evidence requires further review.",
      };
      const ledger = path.join(
        f.root,
        "artifacts",
        "02_discovery",
        "candidate_ledger.jsonl",
      );
      await mkdir(path.dirname(ledger), { recursive: true });
      await writeFile(
        ledger,
        JSON.stringify({
          candidate_id: candidateId,
          summary: "Synthetic candidate review.",
          evidence: "Saved source evidence.",
          cwe_ids: [],
          locations: [
            {
              path: "src/handler.ts",
              start_line: 1,
              end_line: 2,
              role: "evidence",
            },
          ],
          validation: { disposition },
        }) + "\n",
      );
      if (reopened)
        await f.write({
          ...f.draft(),
          findings: [
            {
              ...historical,
              provenance: {
                ...historical.provenance,
                candidateReopened: false,
              },
            },
          ],
        });
      await f.write({
        ...f.draft({ deferred: [pending] }),
        findings: [historical],
      });
      const dismissed = reopened && disposition === "suppressed";
      const assertCurrent = async () => {
        const coverage = await f.read();
        assert.equal(
          coverage.deferred.some(
            (row: { candidateId?: string }) => row.candidateId === candidateId,
          ),
          reopened && !dismissed,
        );
        assert.equal(
          coverage.surfaces.some(
            (row: { candidateId?: string; disposition: string }) =>
              row.candidateId === candidateId && row.disposition === "rejected",
          ),
          dismissed,
        );
        const saved = JSON.parse(
          await readFile(path.join(f.root, "findings.json"), "utf8"),
        );
        assert.equal(saved.findings.length, dismissed ? 0 : 1);
        if (!dismissed)
          assert.equal(
            saved.findings[0].provenance.candidateReopened,
            reopened,
          );
        else
          assert.ok(
            coverage.surfaces
              .find(
                (row: { candidateId?: string }) =>
                  row.candidateId === candidateId,
              )
              .previousFindings.some(
                (row: unknown) =>
                  JSON.stringify(row) === JSON.stringify(historical),
              ),
          );
      };
      await assertCurrent();
      const checkpoints = path.join(f.root, "checkpoints");
      const originals = await Promise.all(
        (await readdir(checkpoints)).map(
          async (name) =>
            [
              name,
              await readFile(path.join(checkpoints, name), "utf8"),
            ] as const,
        ),
      );
      await f.write(f.draft());
      await assertCurrent();
      for (const [name, contents] of originals)
        assert.equal(
          await readFile(path.join(checkpoints, name), "utf8"),
          contents,
        );
    });
  }

  for (const submittedState of ["preserved", "omitted", "cleared"]) {
    test(`Deep reducer retains reopened candidate review: ${reopened}/${submittedState}`, async (t) => {
      const f = await fixture(t, "deep");
      const workerRoot = path.join(
        f.root,
        "artifacts",
        "deep_discovery",
        "workers",
        "worker-a",
        "output",
      );
      const reducerRoot = path.join(
        f.root,
        "artifacts",
        "deep_discovery",
        "dedup",
        "round",
        "output",
      );
      await mkdir(workerRoot, { recursive: true });
      await mkdir(reducerRoot, { recursive: true });
      const historical = {
        ...finding("reopened", "src/handler.ts"),
        provenance: {
          source: "local_plugin",
          candidateId: "candidate-one",
          candidateReopened: reopened,
        },
      };
      const pending = {
        id: "candidate-one",
        candidateId: "candidate-one",
        reason: "New evidence requires further review.",
      };
      const resultPath = path.join(workerRoot, "result.json");
      const draft = f.draft({ deferred: [pending] });
      const { handoffClaimToken, ...worker } = draft;
      await draftApi.recordCodexSecurityWorkerScanDraft(
        {
          root: workerRoot,
          repoRoot: f.root,
          scanId: f.context.scanId,
          layout: "worker",
        },
        { ...worker, complete: true, findings: [historical] },
      );
      const original = await readFile(resultPath, "utf8");
      const {
        getCodexSecurityDeepReducerInputs,
        recordCodexSecurityDeepReduction,
      } = await importSource(
        new URL("../src/artifact-deep-reducer.ts", import.meta.url).pathname,
      );
      const context = {
        root: reducerRoot,
        repoRoot: f.root,
        scanId: f.context.scanId,
        layout: "reducer",
        deepReducer: {
          scanRoot: f.root,
          claimedWorkers: [{ id: "worker-a", resultPath }],
        },
      };
      const inputs = await getCodexSecurityDeepReducerInputs(context);
      const discovery = inputs.discoveries[0].result;
      const expected = reopened
        ? [{ ...pending, sourceWorkerId: "worker-a" }]
        : [];
      assert.deepEqual(discovery.unresolvedCandidates ?? [], expected);
      const { unresolvedCandidates } = await importSource(
        new URL("../../../../sdk/typescript/src/candidates.ts", import.meta.url)
          .pathname,
      );
      const submitted = structuredClone(discovery.findings);
      if (submittedState === "omitted")
        delete submitted[0].provenance.candidateReopened;
      if (submittedState === "cleared")
        submitted[0].provenance.candidateReopened = false;
      for (let replay = 0; replay < 2; replay++) {
        await recordCodexSecurityDeepReduction(context, {
          scanId: f.context.scanId,
          findings: submitted,
        });
        const saved = JSON.parse(
          await readFile(path.join(reducerRoot, "result.json"), "utf8"),
        );
        assert.deepEqual(saved.unresolvedCandidates ?? [], expected);
        assert.equal(
          saved.findings[0].provenance.candidateReopened === true,
          reopened,
        );
        await f.write({ ...deepReductionScanDraft(saved), handoffClaimToken });
        const coverage = await f.read();
        const published = JSON.parse(
          await readFile(path.join(f.root, "findings.json"), "utf8"),
        );
        assert.equal(
          unresolvedCandidates(coverage, published.findings).length,
          expected.length,
        );
        assert.deepEqual(coverage.deferred, expected);
        assert.equal(await readFile(resultPath, "utf8"), original);
      }
    });
  }
}

test("Deep reducer clears historical reopening after the same worker accepts the candidate", async (t) => {
  const f = await fixture(t, "deep");
  const workerRoot = path.join(
    f.root,
    "artifacts/deep_discovery/workers/worker-a/output",
  );
  const reducerRoot = path.join(
    f.root,
    "artifacts/deep_discovery/dedup/round-1/output",
  );
  await mkdir(workerRoot, { recursive: true });
  await mkdir(reducerRoot, { recursive: true });
  const workerContext = {
    root: workerRoot,
    repoRoot: f.root,
    scanId: f.context.scanId,
    layout: "worker",
  };
  const resultPath = path.join(workerRoot, "result.json");
  const accepted = {
    ...finding("reopened", "src/handler.ts"),
    provenance: { source: "local_plugin", candidateId: "candidate-one" },
  };
  const pending = {
    candidateId: "candidate-one",
    reason: "New evidence requires further review.",
  };
  const { handoffClaimToken, ...worker } = f.draft({ deferred: [pending] });
  await draftApi.recordCodexSecurityWorkerScanDraft(workerContext, {
    ...worker,
    complete: true,
    findings: [
      {
        ...accepted,
        provenance: { ...accepted.provenance, candidateReopened: true },
      },
    ],
  });
  const {
    getCodexSecurityDeepReducerInputs,
    recordCodexSecurityDeepReduction,
  } = await importSource(
    new URL("../src/artifact-deep-reducer.ts", import.meta.url).pathname,
  );
  const context = {
    root: reducerRoot,
    repoRoot: f.root,
    scanId: f.context.scanId,
    layout: "reducer",
    deepReducer: {
      scanRoot: f.root,
      claimedWorkers: [{ id: "worker-a", resultPath }],
    },
  };
  const inputs = await getCodexSecurityDeepReducerInputs(context);
  await recordCodexSecurityDeepReduction(context, {
    scanId: f.context.scanId,
    findings: inputs.discoveries[0].result.findings,
  });
  const previousPath = path.join(reducerRoot, "result.json");
  const previousBytes = await readFile(previousPath, "utf8");
  const previous = JSON.parse(previousBytes);
  assert.equal(previous.unresolvedCandidates.length, 1);
  await f.write({ ...deepReductionScanDraft(previous), handoffClaimToken });
  await draftApi.recordCodexSecurityWorkerScanDraft(workerContext, {
    ...worker,
    complete: true,
    findings: [accepted],
    coverage: {
      completeness: "complete",
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
    },
  });
  const nextRoot = path.join(
    f.root,
    "artifacts/deep_discovery/dedup/round-2/output",
  );
  await mkdir(nextRoot, { recursive: true });
  const next = {
    ...context,
    root: nextRoot,
    deepReducer: {
      ...context.deepReducer,
      previousReducerResultPath: previousPath,
    },
  };
  const refreshed = await getCodexSecurityDeepReducerInputs(next);
  assert.equal(refreshed.discoveries[0].result.unresolvedCandidates, undefined);
  for (let replay = 0; replay < 2; replay++) {
    await recordCodexSecurityDeepReduction(next, {
      scanId: f.context.scanId,
      findings: previous.findings,
    });
    const saved = JSON.parse(
      await readFile(path.join(nextRoot, "result.json"), "utf8"),
    );
    assert.equal(saved.unresolvedCandidates, undefined);
    assert.notEqual(saved.findings[0].provenance.candidateReopened, true);
    await f.write({ ...deepReductionScanDraft(saved), handoffClaimToken });
    assert.deepEqual((await f.read()).deferred, []);
    assert.equal(await readFile(previousPath, "utf8"), previousBytes);
  }
});

for (const mode of ["standard", "diff"] as const) {
  for (const transition of ["same", "reassigned", "reopened"] as const) {
    test(`preserves candidate payload when finding identity is ${transition} in ${mode}`, async (t) => {
      const f = await fixture(t, mode);
      const previous = {
        ...finding("shared", "src/handler.ts"),
        identity: { anchor: "shared-review" },
        provenance: {
          source: "local_plugin",
          candidateId: "candidate-b",
          sourceWorkerId: "worker-b",
          ...(transition === "reopened" ? { candidateReopened: true } : {}),
        },
      };
      const pending = {
        id: "proof-b",
        candidateId: "candidate-b",
        sourceWorkerId: "worker-b",
        reason: "Saved boundary review evidence.",
        candidate: { evidence: "Original candidate evidence." },
        originalCandidates: [{ evidence: "Earlier candidate evidence." }],
        finding: { title: "Saved finding annotation." },
        previousFindings: [{ title: "Earlier finding annotation." }],
      };
      await f.write({
        ...f.draft({ deferred: [pending] }, true),
        findings: [previous],
      });
      const checkpointRoot = path.join(f.root, "checkpoints");
      const originals = await Promise.all(
        (await readdir(checkpointRoot)).map(
          async (name) =>
            [
              name,
              await readFile(path.join(checkpointRoot, name), "utf8"),
            ] as const,
        ),
      );
      const current = {
        ...previous,
        provenance: {
          source: "local_plugin",
          candidateId: transition === "same" ? "candidate-b" : "candidate-a",
          sourceWorkerId: transition === "same" ? "worker-b" : "worker-a",
        },
      };
      for (const replay of [false, true]) {
        await f.write({ ...f.draft({}, true), findings: [current] });
        const savedFindings = JSON.parse(
          await readFile(path.join(f.root, "findings.json"), "utf8"),
        );
        const coverage = await f.read();
        const checkpoints = await Promise.all(
          (await readdir(checkpointRoot)).map(async (name) =>
            JSON.parse(await readFile(path.join(checkpointRoot, name), "utf8")),
          ),
        );
        const checkpoint = checkpoints.find(
          (saved) =>
            JSON.stringify(saved.findings) ===
              JSON.stringify(savedFindings.findings) &&
            JSON.stringify(saved.coverage.deferred) ===
              JSON.stringify(coverage.deferred),
        );
        assert.ok(
          checkpoint,
          "The reconciled checkpoint matches the published candidate state.",
        );
        assert.equal(savedFindings.findings.length, 1);
        assert.equal(
          savedFindings.findings[0].provenance.candidateId,
          current.provenance.candidateId,
        );
        for (const document of [
          { findings: savedFindings.findings, coverage },
          checkpoint,
        ]) {
          if (transition === "reopened")
            assert.deepEqual(document.coverage.deferred, [pending]);
          else {
            assert.equal(
              document.coverage.deferred.length,
              0,
              "The previously reported candidate stays resolved.",
            );
            const provenance = document.findings[0].provenance;
            for (const candidate of [
              pending.candidate,
              ...pending.originalCandidates,
            ])
              assert.ok(
                provenance.originalCandidates?.some(
                  (item: unknown) =>
                    JSON.stringify(item) === JSON.stringify(candidate),
                ),
                `Candidate evidence survives replay=${replay}`,
              );
            for (const finding of [
              pending.finding,
              ...pending.previousFindings,
            ])
              assert.ok(
                provenance.previousFindings?.some(
                  (item: unknown) =>
                    JSON.stringify(item) === JSON.stringify(finding),
                ),
                `Finding evidence survives replay=${replay}`,
              );
          }
        }
        for (const [name, contents] of originals)
          assert.equal(
            await readFile(path.join(checkpointRoot, name), "utf8"),
            contents,
          );
      }
    });
  }
}
