import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  mkdir,
  readFile,
  rm,
  symlink,
  utimes,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { test, type TestContext } from "node:test";
import type { ArtifactContext } from "../src/artifact-context.js";
import type { ScanDraftInput } from "../src/artifact-scan-draft.js";
import type { PreparedScanDraft } from "../../../../sdk/typescript/src/scan-semantics.js";
import type {
  SemanticFinding,
  SemanticCoverage,
} from "../../../../sdk/typescript/src/semantic-models.js";
type FixtureDocuments = PreparedScanDraft & {
  reconciledCheckpointIds: string[];
  manifest: { scan: PreparedScanDraft["manifest"]["scan"] & { id: string } };
  findings: { scanId: string };
  coverage: { scanId: string };
};
import { loadSourceModule, privateDirectory } from "./helpers/source.mjs";

const {
  recordCodexSecurityScanDraft,
  recordCodexSecurityScanDraftViaWorkbench,
  getCodexSecurityCompletedScan,
  parseScanDraft,
} = await loadSourceModule<typeof import("../src/artifact-scan-draft.js")>(
  new URL("../src/artifact-scan-draft.ts", import.meta.url),
);
const { semanticFinding, semanticCoverage } = await loadSourceModule<
  typeof import("../../../../sdk/typescript/tests-ts/helpers/semantic-scan.js")
>(
  new URL(
    "../../../../sdk/typescript/tests-ts/helpers/semantic-scan.ts",
    import.meta.url,
  ),
);

const scanId = "7b95abf2-dc04-47a9-9950-53b5c2057f49";
const claimToken = "19bfba38-0913-4bd7-86ef-134e9a4d9a42";
const draft = (overrides: Record<string, unknown> = {}): ScanDraftInput => ({
  scanId,
  handoffClaimToken: claimToken,
  findings: [],
  coverage: semanticCoverage(),
  ...overrides,
});
const finding = (
  id: string,
  overrides: Record<string, unknown> = {},
): SemanticFinding =>
  semanticFinding({
    identity: { anchor: id },
    provenance: { source: "local_plugin", candidateId: id },
    ...overrides,
  });

async function fixture(
  t: TestContext,
  mode: ArtifactContext["mode"] = "standard",
) {
  const root = await privateDirectory("codex-security-draft-");
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, "artifacts"), { mode: 0o700 });
  const context: ArtifactContext = {
    root,
    repoRoot: root,
    scanId,
    mode,
    status: "running",
    handoffClaimToken: claimToken,
    targetContract: {
      target: {
        allowedKinds: ["directory_snapshot"],
        targetId: "target_example",
        displayName: "example",
      },
      scope: { requiredIncludePaths: ["."], requiredExcludePaths: [] },
      diffTarget:
        mode === "diff"
          ? {
              kind: "range",
              baseRevision: "a".repeat(40),
              headRevision: "b".repeat(40),
            }
          : null,
    },
  };
  const snapshotPath = join(root, "artifacts", "scan-draft.json");
  let last: FixtureDocuments;
  const publish = async (
    documents: PreparedScanDraft,
    expected?: string,
    _checkpoint?: ScanDraftInput,
    reconciledCheckpointIds: readonly string[] = [],
  ) => {
    const before = await readFile(snapshotPath, "utf8").catch(() => undefined);
    if (expected !== undefined) {
      const digest = createHash("sha256");
      for (const name of [
        ...(before === undefined ? [] : ["artifacts/scan-draft.json"]),
        "scan-manifest.json",
        "findings.json",
        "coverage.json",
      ]) {
        const contents = await readFile(join(root, name)).catch(
          () => undefined,
        );
        digest.update(name).update("\0");
        if (contents === undefined) digest.update("missing\0");
        else digest.update("present\0").update(contents).update("\0");
      }
      assert.equal(expected, digest.digest("hex"));
    }
    last = documents as FixtureDocuments;
    last.reconciledCheckpointIds = [...reconciledCheckpointIds];
    last.manifest.scan.id = scanId;
    last.findings.scanId = scanId;
    last.coverage.scanId = scanId;
    await writeFile(snapshotPath, JSON.stringify(documents));
  };
  return {
    root,
    context,
    snapshotPath,
    publish,
    save: (input: ScanDraftInput) =>
      recordCodexSecurityScanDraft(context, input, publish),
    get documents() {
      return last;
    },
  };
}

test("draft saves read one committed snapshot and preserve accepted findings by identity", async (t) => {
  const f = await fixture(t);
  const original = finding("first", {
    remediation: "Preserve this original repair.",
  });
  await f.save(draft({ complete: false, findings: [original] }));
  const persisted = JSON.parse(await readFile(f.snapshotPath, "utf8"));
  persisted.findings.findings[0].code_evidence = null;
  persisted.findings.findings[0].root_cause = null;
  await writeFile(f.snapshotPath, JSON.stringify(persisted));
  // Archived checkpoints are evidence, not inputs to every subsequent write.
  await mkdir(join(f.root, "checkpoints"));
  await writeFile(join(f.root, "checkpoints", "invalid.json"), "not JSON");
  await f.save(draft({ findings: [finding("second")] }));
  assert.deepEqual(
    f.documents.findings.findings.map((row) => row.identity!.anchor),
    ["second", "first"],
  );
  assert.equal(
    f.documents.findings.findings[1].remediation,
    original.remediation,
  );
  await f.save(
    draft({ findings: [finding("first", { remediation: "Updated repair." })] }),
  );
  const updated = f.documents.findings.findings.find(
    (row) => row.identity!.anchor === "first",
  );
  assert.equal(updated!.remediation, "Updated repair.");
  assert.equal(
    (updated!.provenance.previousFindings as SemanticFinding[])[0].remediation,
    original.remediation,
  );
  assert.equal(f.documents.findings.findings.length, 2);
});

test("normalization assigns canonical IDs and explicit updates are idempotent", async (t) => {
  const f = await fixture(t);
  const input = draft({
    complete: false,
    findings: [semanticFinding()],
    coverage: semanticCoverage({
      completeness: "partial",
      surfaces: [{ label: "Request handler", disposition: "needs_follow_up" }],
      deferred: [{ reason: "Awaiting review", paths: ["src/render.js"] }],
    }),
  });
  await f.save(input);
  assert.ok(f.documents.findings.findings[0].identity.anchor);
  assert.ok(f.documents.coverage.surfaces[0].id);
  assert.ok(f.documents.coverage.deferred[0].id);
  input.findings = f.documents.findings.findings;
  input.coverage.surfaces = f.documents.coverage.surfaces;
  input.coverage.deferred = f.documents.coverage.deferred;
  await f.save(input);
  assert.equal(f.documents.findings.findings.length, 1);
  assert.equal(f.documents.coverage.surfaces.length, 1);
  assert.equal(f.documents.coverage.deferred.length, 1);
});

test("new same-label surfaces retain pending coverage until its explicit ID is resolved", async (t) => {
  const f = await fixture(t);
  const pending: SemanticCoverage["surfaces"][number] = {
    label: "Request handler",
    riskArea: "authentication",
    paths: ["src/login.ts"],
    disposition: "needs_follow_up",
  };
  await f.save(
    draft({
      complete: false,
      coverage: semanticCoverage({
        completeness: "partial",
        surfaces: [pending],
      }),
    }),
  );
  const pendingId = f.documents.coverage.surfaces[0].id;
  const reviewed: SemanticCoverage["surfaces"][number] = {
    label: pending.label,
    riskArea: "file-handling",
    paths: ["src/download.ts"],
    disposition: "no_issue_found",
  };
  await f.save(draft({ coverage: semanticCoverage({ surfaces: [reviewed] }) }));
  const saved = f.documents.coverage.surfaces;
  assert.equal(saved.length, 2);
  assert.notEqual(saved[0].id, pendingId);
  assert.equal(saved[1].id, pendingId);
  assert.deepEqual(
    saved.map(({ riskArea, paths, disposition }) => ({
      riskArea,
      paths,
      disposition,
    })),
    [reviewed, pending].map(({ riskArea, paths, disposition }) => ({
      riskArea,
      paths,
      disposition,
    })),
  );
  assert.equal(f.documents.coverage.completeness, "partial");

  await f.save(
    draft({
      coverage: semanticCoverage({
        surfaces: [
          {
            ...pending,
            id: pendingId,
            disposition: "no_issue_found",
          },
        ],
      }),
    }),
  );
  assert.equal(f.documents.coverage.surfaces.length, 2);
  assert.deepEqual(
    new Set(f.documents.coverage.surfaces.map(({ id }) => id)),
    new Set(saved.map(({ id }) => id)),
  );
  assert.equal(f.documents.coverage.surfaces[0].id, pendingId);
  assert.equal(f.documents.coverage.surfaces[0].disposition, "no_issue_found");
  assert.equal(f.documents.coverage.completeness, "complete");
});

test("missing deferred IDs preserve distinct candidates and stable IDs revise saved rows", async (t) => {
  for (const candidateId of [undefined, "pending-candidate"]) {
    const f = await fixture(t);
    const first = {
      ...(candidateId === undefined ? {} : { candidateId }),
      reason: "Needs validation",
      paths: ["src/handler.ts"],
      candidate: { explanation: "Review authentication flow" },
    };
    const saveDeferred = (row: SemanticCoverage["deferred"][number]) =>
      f.save(
        draft({
          complete: false,
          coverage: semanticCoverage({
            completeness: "partial",
            deferred: [row],
          }),
        }),
      );
    await saveDeferred(first);
    const firstId = f.documents.coverage.deferred[0].id;
    const second = {
      ...first,
      candidate: { explanation: "Review download flow" },
    };
    await saveDeferred(second);
    const saved = f.documents.coverage.deferred;
    const expectedCount = candidateId === undefined ? 2 : 1;
    assert.equal(saved.length, expectedCount);
    assert.deepEqual(saved[0].candidate, second.candidate);
    assert.equal(f.documents.coverage.completeness, "partial");
    if (candidateId === undefined) {
      assert.notEqual(saved[0].id, firstId);
      assert.equal(saved[1].id, firstId);
      assert.deepEqual(saved[1].candidate, first.candidate);
    } else {
      assert.equal(saved[0].id, firstId);
    }

    await saveDeferred({
      ...second,
      id: saved[0].id,
      reason: "Awaiting fixture",
    });
    const revised = f.documents.coverage.deferred;
    assert.equal(revised.length, expectedCount);
    assert.deepEqual(
      revised.map(({ id, candidate }) => ({ id, candidate })),
      saved.map(({ id, candidate }) => ({ id, candidate })),
    );
    assert.equal(revised[0].reason, "Awaiting fixture");
    assert.equal(f.documents.coverage.completeness, "partial");
  }
});

test("candidate-only deferred updates preserve the unique saved ID and evidence", async (t) => {
  const f = await fixture(t);
  const original = {
    id: "work-1",
    candidateId: "candidate",
    reason: "Needs validation",
    candidate: { explanation: "Saved candidate evidence" },
    finding: finding("candidate"),
  };
  const save = (deferred: SemanticCoverage["deferred"]) =>
    f.save(
      draft({
        complete: false,
        coverage: semanticCoverage({ completeness: "partial", deferred }),
      }),
    );
  await save([original]);
  for (const reason of ["Awaiting fixture", "Ready for validation"]) {
    await save([{ candidateId: original.candidateId, reason }]);
    assert.deepEqual(f.documents.coverage.deferred, [{ ...original, reason }]);
    assert.equal(f.documents.coverage.completeness, "partial");
  }
});

test("deferred ID inference preserves distinct work sharing a candidate", async (t) => {
  const original = ["work-1", "work-2"].map((id) => ({
    id,
    candidateId: "candidate",
    reason: "Needs validation",
    candidate: { explanation: `Saved evidence for ${id}` },
  }));
  for (const input of [
    [{ id: "work-1", candidateId: "candidate", reason: "Updated work" }],
    [{ candidateId: "candidate", reason: "Ambiguous update" }],
  ] as SemanticCoverage["deferred"][]) {
    const f = await fixture(t);
    const save = (deferred: SemanticCoverage["deferred"]) =>
      f.save(
        draft({
          complete: false,
          coverage: semanticCoverage({ completeness: "partial", deferred }),
        }),
      );
    await save(original);
    await save(input);
    const saved = f.documents.coverage.deferred;
    assert.equal(saved.length, input[0].id ? 2 : 3);
    for (const row of original) {
      const updated = saved.find(({ id }) => id === row.id);
      assert.deepEqual(updated!.candidate, row.candidate);
      assert.equal(
        updated!.reason,
        row.id === input[0].id ? input[0].reason : row.reason,
      );
    }
    if (!input[0].id) assert.equal(saved[0].candidate, undefined);
  }
});

test("candidate-only inference does not reuse an explicitly claimed row ID", async (t) => {
  for (const candidateId of ["candidate", "other-candidate"]) {
    const f = await fixture(t);
    const save = (deferred: SemanticCoverage["deferred"]) =>
      f.save(
        draft({
          complete: false,
          coverage: semanticCoverage({ completeness: "partial", deferred }),
        }),
      );
    await save([{ id: "work-1", candidateId: "candidate", reason: "Review" }]);
    await save([
      { id: "work-1", candidateId, reason: "Explicit update" },
      { candidateId: "candidate", reason: "Separate work" },
    ]);
    const [explicit, separate] = f.documents.coverage.deferred;
    assert.equal(explicit.id, "work-1");
    assert.equal(explicit.reason, "Explicit update");
    assert.notEqual(separate.id, explicit.id);
    assert.equal(separate.reason, "Separate work");
  }
});

test("missing finding IDs preserve distinct candidates across draft updates", async (t) => {
  const f = await fixture(t);
  const first = semanticFinding({
    locations: [{ path: "src/first.js", startLine: 1 }],
    provenance: { source: "local_plugin", candidateId: "first" },
  });
  const second = semanticFinding({
    severity: { level: "low" },
    locations: [{ path: "src/second.js", startLine: 1 }],
    provenance: { source: "local_plugin", candidateId: "second" },
  });
  await f.save(draft({ complete: false, findings: [first] }));
  const firstIdentity = f.documents.findings.findings[0].identity;
  await f.save(draft({ complete: false, findings: [second] }));
  const saved = f.documents.findings.findings;
  assert.equal(saved.length, 2);
  assert.notDeepEqual(saved[0].identity, firstIdentity);
  assert.deepEqual(saved[1].identity, firstIdentity);
  assert.deepEqual(
    saved.map((row) => [
      row.provenance.candidateId,
      row.locations,
      row.severity,
    ]),
    [second, first].map((row) => [
      row.provenance.candidateId,
      row.locations,
      row.severity,
    ]),
  );

  const revised = { ...saved[0], remediation: "Updated second repair." };
  await f.save(draft({ findings: [revised] }));
  assert.equal(f.documents.findings.findings.length, 2);
  assert.deepEqual(
    f.documents.findings.findings[0].identity,
    saved[0].identity,
  );
  assert.equal(
    (
      f.documents.findings.findings[0].provenance
        .previousFindings as SemanticFinding[]
    )[0].remediation,
    second.remediation,
  );
});

test("missing finding IDs are unique within a batch and preserve explicit IDs", async (t) => {
  const f = await fixture(t);
  const explicit = finding("unsafe-output", {
    identity: { anchor: "unsafe-output", instance: "unsafe-output" },
  });
  await f.save(
    draft({
      findings: [
        semanticFinding({
          locations: [{ path: "src/first.js", startLine: 1 }],
        }),
        semanticFinding({
          locations: [{ path: "src/second.js", startLine: 1 }],
        }),
        explicit,
      ],
    }),
  );
  const saved = f.documents.findings.findings;
  assert.equal(saved.length, 3);
  assert.equal(
    new Set(saved.map((row) => JSON.stringify(row.identity))).size,
    3,
  );
  assert.deepEqual(saved[2].identity, explicit.identity);
});

test("pending candidate evidence is preserved until its explicit finding or rejection", async (t) => {
  for (const disposition of ["reported", "rejected"] as const) {
    const f = await fixture(t);
    const candidate = { explanation: "Original supporting evidence" };
    const pending = draft({
      complete: false,
      coverage: semanticCoverage({
        completeness: "partial",
        surfaces: [
          {
            id: "surface",
            label: "Handler",
            disposition: "needs_follow_up",
            candidateId: "candidate",
          },
        ],
        deferred: [
          {
            id: "pending",
            candidateId: "candidate",
            reason: "Needs validation",
            candidate,
          },
        ],
      }),
    });
    await f.save(pending);
    await f.save(draft({ complete: false }));
    assert.deepEqual(f.documents.coverage.deferred[0].candidate, candidate);
    const final = draft({
      findings: disposition === "reported" ? [finding("candidate")] : [],
      coverage: semanticCoverage({
        surfaces: [
          {
            id: "surface",
            candidateId: "candidate",
            label: "Handler",
            disposition,
          },
        ],
      }),
    });
    await f.save(final);
    assert.equal(f.documents.coverage.deferred.length, 0);
    assert.equal(f.documents.coverage.completeness, "complete");
    if (disposition === "reported")
      assert.deepEqual(
        f.documents.findings.findings[0].provenance.originalCandidates,
        [candidate],
      );
    else
      assert.deepEqual(f.documents.coverage.surfaces[0].candidate, candidate);
  }
});

for (const next of ["rejected", "reported", "deferred"]) {
  test(`rejected surface evidence survives a later ${next} draft`, async (t) => {
    const f = await fixture(t);
    const candidate = { explanation: "Original candidate evidence" };
    const original = finding("candidate", {
      remediation: "Original candidate repair.",
    });
    await f.save(
      draft({
        complete: false,
        coverage: semanticCoverage({
          completeness: "partial",
          deferred: [
            {
              id: "pending",
              candidateId: "candidate",
              reason: "Needs validation",
              candidate,
              finding: original,
            },
          ],
        }),
      }),
    );
    const surface: SemanticCoverage["surfaces"][number] = {
      id: "surface",
      candidateId: "candidate",
      label: "Handler",
      disposition: "rejected",
    };
    const rejected = draft({
      coverage: semanticCoverage({ surfaces: [surface] }),
    });
    await f.save(rejected);
    assert.deepEqual(f.documents.coverage.surfaces[0].candidate, candidate);
    assert.deepEqual(f.documents.coverage.surfaces[0].finding, original);

    const updated =
      next === "rejected"
        ? rejected
        : next === "reported"
          ? draft({
              findings: [
                finding("candidate", { remediation: "Current repair." }),
              ],
            })
          : draft({
              coverage: semanticCoverage({
                completeness: "partial",
                surfaces: [{ ...surface, disposition: "needs_follow_up" }],
                deferred: [
                  {
                    id: "reopened",
                    candidateId: "candidate",
                    reason: "Review again",
                  },
                ],
              }),
            });
    await f.save(updated);
    if (next === "reported") {
      const reported = f.documents.findings.findings[0];
      assert.deepEqual(reported.provenance.originalCandidates, [candidate]);
      assert.deepEqual(reported.provenance.previousFindings, [original]);
      assert.equal(reported.remediation, "Current repair.");
      assert.deepEqual(f.documents.coverage.surfaces, []);
    } else {
      const rows =
        next === "deferred"
          ? f.documents.coverage.deferred
          : f.documents.coverage.surfaces;
      assert.equal(rows.length, 1);
      assert.deepEqual(rows[0].candidate, candidate);
      assert.deepEqual(rows[0].finding, original);
      assert.equal(f.documents.coverage.surfaces.length, 1);
      assert.equal(
        f.documents.coverage.surfaces[0].disposition,
        next === "deferred" ? "needs_follow_up" : "rejected",
      );
    }
    assert.equal(
      f.documents.findings.findings.length,
      next === "reported" ? 1 : 0,
    );
    assert.equal(
      f.documents.coverage.deferred.length,
      next === "deferred" ? 1 : 0,
    );
  });
}

for (const field of ["candidateId", "reportId", "ledgerRowId"]) {
  test(`extension ${field} resolves pending work and honors rejection`, async (t) => {
    for (const disposition of ["rejected", "not_applicable"] as const) {
      const f = await fixture(t);
      const candidate = { explanation: "Saved candidate evidence" };
      await f.save(
        draft({
          complete: false,
          coverage: semanticCoverage({
            completeness: "partial",
            deferred: [
              {
                id: "pending",
                candidateId: "candidate",
                reason: "Review",
                candidate,
              },
            ],
          }),
        }),
      );
      await f.save(
        draft({
          findings: [
            semanticFinding({
              identity: { anchor: "finding" },
              extensions: { [field]: "candidate" },
            }),
          ],
        }),
      );
      assert.equal(f.documents.coverage.deferred.length, 0);
      assert.equal(f.documents.coverage.completeness, "complete");
      const reported = f.documents.findings.findings[0];
      assert.deepEqual(reported.provenance.originalCandidates, [candidate]);
      await f.save(
        draft({
          coverage: semanticCoverage({
            surfaces: [
              {
                id: "reviewed",
                candidateId: "candidate",
                label: "Reviewed candidate",
                disposition,
              },
            ],
          }),
        }),
      );
      assert.deepEqual(f.documents.findings.findings, []);
      assert.deepEqual(f.documents.coverage.surfaces[0].finding, reported);
    }
  });
}

test("surface resolution preserves candidate work and evidence without a candidate ID", async (t) => {
  const f = await fixture(t);
  const candidate = { explanation: "Candidate evidence awaiting review" };
  const deferredFinding = finding("unvalidated");
  await f.save(
    draft({
      complete: false,
      coverage: semanticCoverage({
        completeness: "partial",
        surfaces: [
          {
            id: "surface",
            label: "Before label",
            disposition: "needs_follow_up",
          },
        ],
        deferred: [
          {
            id: "surface-work",
            surfaceIds: ["surface"],
            reason: "Review this surface",
          },
          {
            id: "candidate-work",
            candidateId: "candidate",
            surfaceIds: ["surface"],
            reason: "Validate this candidate",
          },
          {
            id: "candidate-evidence",
            surfaceIds: ["surface"],
            reason: "Review this candidate evidence",
            candidate,
          },
          {
            id: "finding-evidence",
            surfaceIds: ["surface"],
            reason: "Review this finding evidence",
            finding: deferredFinding,
          },
        ],
      }),
    }),
  );
  await f.save(
    draft({
      coverage: semanticCoverage({
        surfaces: [
          {
            id: "surface",
            label: "After label",
            disposition: "no_issue_found",
          },
        ],
      }),
    }),
  );
  assert.deepEqual(
    f.documents.coverage.deferred.map((row) => row.id),
    ["candidate-work", "candidate-evidence", "finding-evidence"],
  );
  assert.deepEqual(f.documents.coverage.deferred[1].candidate, candidate);
  assert.deepEqual(f.documents.coverage.deferred[2].finding, deferredFinding);
  assert.equal(f.documents.coverage.surfaces.length, 1);
  assert.equal(f.documents.coverage.completeness, "partial");
});

test("a late partial writer preserves final presentation and retains new evidence", async (t) => {
  const f = await fixture(t);
  const final = finding("accepted", { remediation: "Final repair." });
  await f.save(
    draft({
      findings: [final],
      coverage: semanticCoverage({
        surfaces: [
          {
            id: "reviewed-surface",
            label: "Reviewed surface",
            disposition: "rejected",
          },
        ],
      }),
    }),
  );
  const accepted = await readFile(f.snapshotPath, "utf8");
  await f.save(draft({ complete: false }));
  assert.equal(await readFile(f.snapshotPath, "utf8"), accepted);

  let checkpoint!: ScanDraftInput;
  const result = await recordCodexSecurityScanDraftViaWorkbench(
    f.context,
    draft({
      complete: false,
      findings: [
        finding("accepted", { remediation: "Earlier repair evidence." }),
        finding("late"),
      ],
      coverage: semanticCoverage({
        completeness: "partial",
        surfaces: [
          {
            id: "reviewed-surface",
            label: "Reviewed surface",
            disposition: "needs_follow_up",
          },
        ],
        deferred: [
          {
            id: "late-review",
            surfaceIds: ["reviewed-surface"],
            reason: "Retain this late review evidence.",
          },
        ],
      }),
    }),
    async (argv, input) => {
      const payload = {
        documents: JSON.parse(
          await readFile(argv[argv.indexOf("--draft-path") + 1], "utf8"),
        ),
        checkpoint: JSON.parse(
          await readFile(argv[argv.indexOf("--checkpoint-path") + 1], "utf8"),
        ),
      };
      checkpoint = payload.checkpoint;
      await f.publish(
        payload.documents,
        argv[argv.indexOf("--expected-draft-digest") + 1],
      );
      return {};
    },
  );
  assert.equal(result.findingCount, 2);
  assert.equal(checkpoint.complete, false);
  assert.deepEqual(
    checkpoint.findings.map((row) => row.identity!.anchor),
    ["accepted", "late"],
  );
  assert.equal(checkpoint.findings[0].remediation, "Earlier repair evidence.");
  assert.equal(
    checkpoint.coverage.deferred[0].reason,
    "Retain this late review evidence.",
  );
  const committed = JSON.parse(await readFile(f.snapshotPath, "utf8"));
  assert.notEqual(committed.manifest.scan.complete, false);
  assert.deepEqual(committed.coverage.deferred, []);
  assert.equal(committed.findings.findings[0].remediation, final.remediation);
  assert.deepEqual(
    committed.findings.findings.map(
      (row: SemanticFinding) => row.identity!.anchor,
    ),
    ["accepted", "late"],
  );
  await f.save(draft());
  assert.deepEqual(f.documents.findings.findings, committed.findings.findings);
});

test("Deep completion uses the accepted aggregate without reintroducing older findings", async (t) => {
  const f = await fixture(t, "deep");
  await f.save(draft({ complete: false, findings: [finding("obsolete")] }));
  await f.save(draft({ findings: [finding("accepted")] }));
  assert.deepEqual(
    f.documents.findings.findings.map((row) => row.identity!.anchor),
    ["accepted"],
  );
});

test("one staged publication transports documents and evidence under the workbench lock", async (t) => {
  const f = await fixture(t);
  let calls = 0;
  const result = await recordCodexSecurityScanDraftViaWorkbench(
    f.context,
    draft(),
    async (argv, input) => {
      calls++;
      assert.equal(argv[0], "write-scan-draft");
      assert.equal(argv.includes("--draft-path"), true);
      assert.equal(argv[argv.indexOf("--claim-token") + 1], claimToken);
      const payload = {
        documents: JSON.parse(
          await readFile(argv[argv.indexOf("--draft-path") + 1], "utf8"),
        ),
        checkpoint: JSON.parse(
          await readFile(argv[argv.indexOf("--checkpoint-path") + 1], "utf8"),
        ),
      };
      assert.equal(payload.checkpoint.handoffClaimToken, undefined);
      assert.equal(payload.checkpoint.scanId, scanId);
      await f.publish(
        payload.documents,
        argv[argv.indexOf("--expected-draft-digest") + 1],
      );
      return {};
    },
  );
  assert.equal(calls, 1);
  assert.equal(result.status, "draft_written");
});

test("CAS conflicts reread the committed head and cancellation stops retries", async (t) => {
  const f = await fixture(t);
  let calls = 0;
  await recordCodexSecurityScanDraft(
    f.context,
    draft({ findings: [finding("mine")] }),
    async (...args) => {
      if (++calls === 1) {
        await f.save(
          draft({ complete: false, findings: [finding("concurrent")] }),
        );
        throw Object.assign(new Error("concurrent publication"), {
          code: "scan_draft_conflict",
        });
      }
      await f.publish(...args);
    },
  );
  assert.equal(calls, 2);
  assert.deepEqual(
    f.documents.findings.findings.map((row) => row.identity!.anchor),
    ["mine", "concurrent"],
  );
  const controller = new AbortController();
  await assert.rejects(
    recordCodexSecurityScanDraft(
      f.context,
      draft(),
      async () => {
        controller.abort(new Error("stop saving"));
        throw Object.assign(new Error("conflict"), {
          code: "scan_draft_conflict",
        });
      },
      controller.signal,
    ),
    /stop saving/,
  );
});

test("CAS retries reuse operation IDs while preserving concurrent findings", async (t) => {
  const f = await fixture(t);
  let calls = 0;
  let initialIdentity;
  let concurrentIdentity;
  await recordCodexSecurityScanDraft(
    f.context,
    draft({
      findings: [
        semanticFinding({
          provenance: { source: "local_plugin", candidateId: "mine" },
        }),
      ],
    }),
    async (...args) => {
      if (++calls === 1) {
        initialIdentity = args[0].findings.findings[0].identity;
        await f.save(
          draft({
            complete: false,
            findings: [
              semanticFinding({
                provenance: {
                  source: "local_plugin",
                  candidateId: "concurrent",
                },
              }),
            ],
          }),
        );
        concurrentIdentity = f.documents.findings.findings[0].identity;
        throw Object.assign(new Error("concurrent publication"), {
          code: "scan_draft_conflict",
        });
      }
      await f.publish(...args);
    },
  );
  assert.equal(calls, 2);
  assert.notDeepEqual(initialIdentity, concurrentIdentity);
  const saved = f.documents.findings.findings;
  assert.deepEqual(
    saved.map((row) => row.provenance.candidateId),
    ["mine", "concurrent"],
  );
  assert.deepEqual(saved[0].identity, initialIdentity);
  assert.deepEqual(saved[1].identity, concurrentIdentity);
});

test("unavailable and incompatible snapshots cannot silently drop saved evidence", async (t) => {
  const f = await fixture(t);
  await f.save(draft({ complete: false, findings: [finding("accepted")] }));
  const stored = JSON.parse(await readFile(f.snapshotPath, "utf8"));
  stored.findings.findings[0].remediation = 17;
  await writeFile(f.snapshotPath, JSON.stringify(stored));
  await assert.rejects(f.save(draft()), /remediation/);
  assert.equal(
    JSON.parse(await readFile(f.snapshotPath, "utf8")).findings.findings[0]
      .remediation,
    17,
  );
  if (process.platform !== "win32") {
    const outside = join(f.root, "outside.json");
    await writeFile(outside, JSON.stringify(stored));
    await rm(f.snapshotPath);
    await symlink(outside, f.snapshotPath);
    await assert.rejects(f.save(draft()), /symbolic|symlink|regular|safe/i);
  }
});

test("semantic drafts retain nested finding report references", () => {
  const reportPath = "findings/original/secondary/report.md";
  const parsed = parseScanDraft(
    draft({ findings: [finding("nested", { writeup: { reportPath } })] }),
  );
  assert.equal(parsed.findings[0].writeup!.reportPath, reportPath);
});

test("scan claims, status, and semantic validation precede publication", async (t) => {
  const f = await fixture(t);
  const publish = async () => assert.fail("invalid draft reached publisher");
  await assert.rejects(
    recordCodexSecurityScanDraft(
      { ...f.context, status: "complete" },
      draft(),
      publish,
    ),
    /running/,
  );
  await assert.rejects(
    recordCodexSecurityScanDraft(
      f.context,
      draft({ handoffClaimToken: undefined }),
      publish,
    ),
    /handoffClaimToken/,
  );
  await assert.rejects(
    recordCodexSecurityScanDraft(
      f.context,
      draft({ scanId: "731c1b07-8a76-4859-bd99-19718c9178f0" }),
      publish,
    ),
    /scanId/,
  );
  assert.throws(
    () =>
      parseScanDraft(
        draft({
          coverage: semanticCoverage({
            deferred: [{ reason: "Outstanding work" }],
          }),
        }),
      ),
    /complete coverage/,
  );
  assert.throws(
    () =>
      parseScanDraft(
        draft({
          findings: [
            finding("bad", {
              locations: [{ path: "src/a.ts", startLine: 10, endLine: 2 }],
            }),
          ],
        }),
      ),
    /endLine/,
  );
});

test("ambiguous identities and snapshots from another scan are rejected", async (t) => {
  const f = await fixture(t);
  await assert.rejects(
    f.save(
      draft({
        findings: [
          finding("same"),
          finding("same", { summary: "A separate observation" }),
        ],
      }),
    ),
    /repeats an identity/,
  );
  await f.save(draft({ complete: false, findings: [finding("original")] }));
  const stored = JSON.parse(await readFile(f.snapshotPath, "utf8"));
  delete stored.findings.findings[0].identity;
  await writeFile(f.snapshotPath, JSON.stringify(stored));
  await assert.rejects(f.save(draft()), /stable IDs/);
  stored.findings.findings[0].identity = { anchor: "original" };
  stored.manifest.scan.id = "731c1b07-8a76-4859-bd99-19718c9178f0";
  await writeFile(f.snapshotPath, JSON.stringify(stored));
  await assert.rejects(f.save(draft()), /different scan/);
});

test("completed results require a sealed, matching workbench result", async (t) => {
  const f = await fixture(t);
  await assert.rejects(
    getCodexSecurityCompletedScan(f.context, {
      scanId,
      handoffClaimToken: claimToken,
    }),
    /completed successfully/,
  );
  const documents = {
    "scan-manifest.json": {
      scan: {
        id: scanId,
        status: "completed",
        sealedAt: "2026-01-01T00:00:00Z",
        artifacts: [],
      },
    },
    "findings.json": { scanId, findings: [] },
    "coverage.json": { scanId, surfaces: [] },
  };
  for (const [name, value] of Object.entries(documents))
    await writeFile(join(f.root, name), JSON.stringify(value));
  const input = { scanId, handoffClaimToken: claimToken };
  const context = { ...f.context, status: "complete" };
  assert.equal(
    (await getCodexSecurityCompletedScan(context, input)).scanId,
    scanId,
  );
  await writeFile(
    join(f.root, "findings.json"),
    JSON.stringify({ scanId: "another-scan", findings: [] }),
  );
  await assert.rejects(
    getCodexSecurityCompletedScan(context, input),
    /sealed workbench/,
  );
});

for (const mode of ["standard", "deep"] as const) {
  test(`${mode} draft reconciles pending evidence without rereading accepted history`, async (t) => {
    const f = await fixture(t, mode);
    await f.save(draft({ complete: false }));
    const pending = draft({
      complete: false,
      findings: [finding("pending-evidence")],
    });
    delete pending.handoffClaimToken;
    const contents = JSON.stringify(pending);
    const name = createHash("sha256").update(contents).digest("hex") + ".json";
    await mkdir(join(f.root, "checkpoints", "pending"), { recursive: true });
    await writeFile(join(f.root, "checkpoints", name), contents);
    await writeFile(join(f.root, "checkpoints", "pending", name), "");
    await writeFile(
      join(f.root, "checkpoints", "0".repeat(64) + ".json"),
      "not JSON",
    );
    await f.save(draft({ findings: [finding("later-evidence")] }));
    assert.deepEqual(
      f.documents.findings.findings.map((row) => row.identity!.anchor),
      ["later-evidence", "pending-evidence"],
    );
    assert.deepEqual(f.documents.reconciledCheckpointIds, [name]);
    // An interruption after the head write may leave its accepted marker in place.
    const rejected = draft({
      coverage: semanticCoverage({
        surfaces: [
          {
            id: "rejected-pending",
            label: "Pending evidence reviewed",
            candidateId: "pending-evidence",
            disposition: "rejected",
            receiptRefs: [],
          },
        ],
      }),
    });
    rejected.findings = [finding("later-evidence")];
    await f.save(rejected);
    assert.deepEqual(
      f.documents.findings.findings.map((row) => row.identity!.anchor),
      ["later-evidence"],
    );
    assert.equal(
      await readFile(join(f.root, "checkpoints", name), "utf8"),
      contents,
    );
  });
}

test("pending checkpoint directories cannot redirect reads outside the scan", async (t) => {
  const f = await fixture(t);
  const outside = await privateDirectory("codex-security-pending-outside-");
  t.after(() => rm(outside, { recursive: true, force: true }));
  await f.save(draft());
  await mkdir(join(f.root, "checkpoints"));
  await symlink(outside, join(f.root, "checkpoints", "pending"), "junction");
  await assert.rejects(f.save(draft()), /safe directory/u);
});

for (const scenario of [
  "pending only",
  "same saved ID",
  "ambiguous candidate",
]) {
  test(`candidate-only deferred inference considers ${scenario} across pending drafts`, async (t) => {
    const f = await fixture(t);
    const row = (id: string) => ({
      id,
      candidateId: "candidate",
      reason: "Review",
      candidate: { summary: id },
    });
    const committed =
      scenario === "pending only"
        ? []
        : [row(scenario === "ambiguous candidate" ? "candidate" : "work-1")];
    await f.save(
      draft({
        complete: false,
        coverage: semanticCoverage({
          completeness: "partial",
          deferred: committed,
        }),
      }),
    );
    const pending = draft({
      complete: false,
      coverage: semanticCoverage({
        completeness: "partial",
        deferred: [
          row(scenario === "ambiguous candidate" ? "work-2" : "work-1"),
        ],
      }),
    });
    const contents = JSON.stringify(pending);
    const name = createHash("sha256").update(contents).digest("hex") + ".json";
    await mkdir(join(f.root, "checkpoints", "pending"), { recursive: true });
    await writeFile(join(f.root, "checkpoints", name), contents);
    await writeFile(join(f.root, "checkpoints", "pending", name), "");
    await f.save(
      draft({
        complete: false,
        coverage: semanticCoverage({
          completeness: "partial",
          deferred: [{ candidateId: "candidate", reason: "Updated review" }],
        }),
      }),
    );
    const saved = f.documents.coverage.deferred;
    assert.equal(saved.length, scenario === "ambiguous candidate" ? 3 : 1);
    if (scenario === "ambiguous candidate") {
      assert.notEqual(saved[0].id, "candidate");
      assert.notEqual(saved[0].id, "work-2");
      assert.deepEqual(
        saved
          .slice(1)
          .map((row) => (row.candidate as { summary: string }).summary)
          .sort(),
        ["candidate", "work-2"],
      );
    } else {
      assert.equal(saved[0].id, "work-1");
      assert.equal(saved[0].reason, "Updated review");
      assert.deepEqual(saved[0].candidate, { summary: "work-1" });
    }
  });
}

for (const disposition of ["no_issue_found", "reported"] as const) {
  test(`unchanged ${disposition} surface retains independent deferred work`, async (t) => {
    const f = await fixture(t);
    const surfaces = [
      { id: "surface", label: "Reviewed surface", disposition },
    ];
    const deferred = [
      {
        id: "independent",
        reason: "Review additional evidence",
        surfaceIds: ["surface"],
      },
    ];
    await f.save(
      draft({
        complete: false,
        coverage: semanticCoverage({
          completeness: "partial",
          surfaces,
          deferred,
        }),
      }),
    );
    await f.save(draft({ coverage: semanticCoverage({ surfaces }) }));
    assert.deepEqual(f.documents.coverage.deferred, deferred);
    assert.equal(f.documents.coverage.completeness, "partial");
  });
}

for (const storage of ["legacy", "pending payload", "staged path"]) {
  test(`reconciles ${storage} checkpoint evidence`, async (t) => {
    const f = await fixture(t);
    const pending = draft({
      complete: false,
      findings: [finding("saved-evidence")],
    });
    delete pending.handoffClaimToken;
    const contents = JSON.stringify(pending);
    const name = createHash("sha256").update(contents).digest("hex") + ".json";
    const directory = join(
      f.root,
      "checkpoints",
      ...(storage === "legacy" ? [] : ["pending"]),
    );
    await mkdir(directory, { recursive: true });
    const stagedPath =
      "drafts/11111111-1111-4111-8111-111111111111.checkpoint.json";
    if (storage === "staged path") {
      await mkdir(join(f.root, "drafts"));
      await writeFile(join(f.root, stagedPath), contents);
    }
    const marker = storage === "staged path" ? stagedPath : contents;
    await writeFile(join(directory, name), marker);
    if (storage === "staged path") {
      await writeFile(join(f.root, stagedPath), contents + " ");
      await assert.rejects(
        f.save(draft()),
        /staged checkpoint digest changed/u,
      );
      await writeFile(join(f.root, stagedPath), contents);
    }
    await f.save(draft());
    assert.equal(
      f.documents.findings.findings[0].identity.anchor,
      "saved-evidence",
    );
    assert.deepEqual(f.documents.reconciledCheckpointIds, [name]);
    assert.equal(await readFile(join(directory, name), "utf8"), marker);
  });
}

for (const storage of ["legacy", "indexed", "pending payload"]) {
  test(`incomplete retry keeps the newest final ${storage} checkpoint authoritative`, async (t) => {
    const f = await fixture(t);
    const accepted = draft({ findings: [finding("removed-candidate")] });
    const rejected = draft({
      coverage: semanticCoverage({
        surfaces: [
          {
            id: "reviewed-surface",
            label: "Reviewed candidate",
            riskArea: "input_validation",
            paths: ["src/example.ts"],
            disposition: "rejected",
            candidateId: "removed-candidate",
            rationale: "The later review rejects this candidate.",
          },
        ],
      }),
    });
    const checkpoints = [accepted, rejected].map((input) => {
      delete input.handoffClaimToken;
      const contents = JSON.stringify(input);
      return {
        contents,
        name: createHash("sha256").update(contents).digest("hex") + ".json",
      };
    });
    assert.ok(
      checkpoints[0].name < checkpoints[1].name,
      "fixture hash order puts the older final first",
    );
    const directory = join(f.root, "checkpoints");
    await mkdir(join(directory, "pending"), { recursive: true });
    if (storage === "legacy")
      await rm(join(directory, "pending"), { recursive: true });
    for (const [index, checkpoint] of checkpoints.entries()) {
      for (const target of storage === "legacy"
        ? [join(directory, checkpoint.name)]
        : storage === "indexed"
          ? [
              join(directory, checkpoint.name),
              join(directory, "pending", checkpoint.name),
            ]
          : [join(directory, "pending", checkpoint.name)]) {
        await writeFile(target, checkpoint.contents);
        await utimes(target, 1700000000 + index * 10, 1700000000 + index * 10);
      }
    }
    await f.save(draft({ complete: false }));
    assert.deepEqual(f.documents.findings.findings, []);
    const surface = f.documents.coverage.surfaces.find(
      (row) => row.candidateId === "removed-candidate",
    );
    assert.equal(surface!.disposition, "rejected");
    assert.equal(
      (surface!.finding as SemanticFinding).identity!.anchor,
      "removed-candidate",
    );
    assert.deepEqual(
      f.documents.reconciledCheckpointIds,
      checkpoints.map(({ name }) => name).reverse(),
    );
    for (const checkpoint of checkpoints) {
      const path = join(
        directory,
        ...(storage === "pending payload" ? ["pending"] : []),
        checkpoint.name,
      );
      assert.equal(await readFile(path, "utf8"), checkpoint.contents);
    }
  });
}

for (const mode of ["standard", "diff"]) {
  test(`${mode} terminal drafts close saved generic work and allow it to reopen`, async (t) => {
    const f = await fixture(t, mode);
    const pending = {
      id: "generic-task",
      reason: "Inspect the shared boundary.",
    };
    await f.save(
      draft({
        complete: false,
        coverage: semanticCoverage({
          deferred: [pending],
          completeness: "partial",
        }),
      }),
    );
    await f.save(
      draft({
        coverage: semanticCoverage({
          resolvedDeferred: [{ id: pending.id, reason: "Boundary reviewed." }],
        }),
      }),
    );
    assert.deepEqual(f.documents.coverage.deferred, []);
    assert.deepEqual(f.documents.coverage.resolvedDeferred, [
      { id: pending.id, reason: "Boundary reviewed." },
    ]);
    await f.save(draft({ complete: false }));
    assert.deepEqual(f.documents.coverage.deferred, []);
    await f.save(
      draft({
        complete: false,
        coverage: semanticCoverage({
          deferred: [pending],
          completeness: "partial",
        }),
      }),
    );
    assert.deepEqual(f.documents.coverage.deferred, [pending]);
    assert.equal(f.documents.coverage.resolvedDeferred, undefined);
    assert.equal(f.documents.manifest.scan.complete, false);
  });
}

for (const mode of ["standard", "diff"]) {
  for (const outcome of ["reported", "rejected", "not_applicable"] as const) {
    test(`${mode} final ${outcome} candidate accepts a redundant deferred closure and retains evidence`, async (t) => {
      const f = await fixture(t, mode);
      const candidate = { explanation: "Saved candidate evidence." };
      const surface = {
        id: "candidate-surface",
        label: "Request handler",
        candidateId: "candidate",
      };
      await f.save(
        draft({
          complete: false,
          coverage: semanticCoverage({
            completeness: "partial",
            surfaces: [{ ...surface, disposition: "needs_follow_up" }],
            deferred: [
              {
                id: "candidate-task",
                candidateId: "candidate",
                candidate,
                surfaceIds: [surface.id],
                reason: "Validate candidate.",
              },
            ],
          }),
        }),
      );
      await f.save(
        draft({
          findings: outcome === "reported" ? [finding("candidate")] : [],
          coverage: semanticCoverage({
            surfaces: [{ ...surface, disposition: outcome }],
            resolvedDeferred: [
              { id: "candidate-task", reason: "Candidate reviewed." },
            ],
          }),
        }),
      );
      assert.deepEqual(f.documents.coverage.deferred, []);
      assert.equal(f.documents.coverage.completeness, "complete");
      assert.equal(f.documents.coverage.surfaces[0].disposition, outcome);
      if (outcome === "reported") {
        assert.equal(f.documents.findings.findings.length, 1);
        assert.deepEqual(
          f.documents.findings.findings[0].provenance.originalCandidates,
          [candidate],
        );
      } else {
        assert.deepEqual(f.documents.findings.findings, []);
        assert.deepEqual(f.documents.coverage.surfaces[0].candidate, candidate);
      }
    });
  }
}

test("generic closure cannot discard candidate work, unknown work, or still-active work", async (t) => {
  const f = await fixture(t);
  await f.save(
    draft({
      complete: false,
      coverage: semanticCoverage({
        deferred: [
          {
            id: "candidate-task",
            candidateId: "candidate",
            reason: "Validate candidate.",
          },
          { id: "generic-task", reason: "Inspect boundary." },
        ],
        completeness: "partial",
      }),
    }),
  );
  for (const [id, expected] of [
    ["candidate-task", /cannot close candidate/],
    ["unknown", /no saved generic deferral/],
  ] as const) {
    await assert.rejects(
      f.save(
        draft({
          coverage: semanticCoverage({
            resolvedDeferred: [{ id, reason: "Reviewed." }],
          }),
        }),
      ),
      expected,
    );
  }
  await assert.rejects(
    f.save(
      draft({
        coverage: semanticCoverage({
          completeness: "partial",
          deferred: [{ id: "generic-task", reason: "Still pending." }],
          resolvedDeferred: [{ id: "generic-task", reason: "Reviewed." }],
        }),
      }),
    ),
    /still active/,
  );
  assert.equal(f.documents.coverage.deferred.length, 2);
});

test("terminal Deep publication retains an omitted model and forwards projection warnings", async (t) => {
  const f = await fixture(t, "deep");
  const threatModel = { format: "markdown", content: "# Saved model\n" };
  await f.save(draft({ complete: false, threatModel }));
  const result = await recordCodexSecurityScanDraftViaWorkbench(
    f.context,
    draft(),
    async (argv) => {
      const documents = JSON.parse(
        await readFile(argv[argv.indexOf("--draft-path") + 1], "utf8"),
      );
      const checkpoint = JSON.parse(
        await readFile(argv[argv.indexOf("--checkpoint-path") + 1], "utf8"),
      );
      assert.deepEqual(documents.manifest.scan.threatModel, threatModel);
      assert.deepEqual(checkpoint.threatModel, threatModel);
      return { warnings: ["Synthetic optional projection warning.", 42] };
    },
  );
  assert.deepEqual(result.warnings, ["Synthetic optional projection warning."]);
});

for (const scenario of ["retry", "explicit", "different owner", "ambiguous"])
  test(`implicit finding identities preserve independent findings (${scenario})`, async (t) => {
    const f = await fixture(t);
    const implicit = (sourceScanId = "owner-a") =>
      finding("candidate-a", {
        identity: undefined,
        provenance: {
          source: "local_plugin",
          candidateId: "candidate-a",
          sourceScanId,
        },
      });
    await f.save(
      draft({
        complete: false,
        findings:
          scenario === "ambiguous" ? [implicit(), implicit()] : [implicit()],
      }),
    );
    const firstAnchor = f.documents.findings.findings[0].identity.anchor;
    await f.save(
      draft({
        findings: [
          scenario === "explicit"
            ? finding("explicit-second", {
                provenance: {
                  source: "local_plugin",
                  candidateId: "candidate-a",
                  sourceScanId: "owner-a",
                },
              })
            : implicit(scenario === "different owner" ? "owner-b" : "owner-a"),
        ],
      }),
    );
    assert.equal(
      f.documents.findings.findings.length,
      scenario === "retry" ? 1 : scenario === "ambiguous" ? 3 : 2,
    );
    if (scenario === "retry")
      assert.equal(
        f.documents.findings.findings[0].identity.anchor,
        firstAnchor,
      );
  });
