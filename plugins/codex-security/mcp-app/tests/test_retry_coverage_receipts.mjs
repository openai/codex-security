import assert from "node:assert/strict";
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { publishCoverageFixture } from "./deep_scan_coverage_fixture.mjs";

for (const resume of [false, true]) {
  for (const stopAfterDraft of [false, true]) {
    test(`archived receipt survives ${resume ? "reconstruction" : "live retry"} and ${stopAfterDraft ? "recovery" : "completion"}`, async () => {
      const root = await mkdtemp(path.join(tmpdir(), "retry-coverage-"));
      try {
        await publishCoverageFixture(root, "complete", {
          receiptRetry: true,
          stopAfterDraft,
          resume,
        });
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
  }
}

const { readDeepReductionSources, recordCodexSecurityDeepReduction } = await (
  await import("./import-module.ts")
).importSource(
  fileURLToPath(new URL("../src/artifact-deep-reducer.ts", import.meta.url)),
);
const { recordCodexSecurityWorkerScanDraft } = await (
  await import("./import-module.ts")
).importSource(
  fileURLToPath(new URL("../src/artifact-scan-draft.ts", import.meta.url)),
);
const { parseDeepReduction } = await (
  await import("./import-module.ts")
).importSource(
  fileURLToPath(
    new URL("../src/deep-scan/artifact-validation.ts", import.meta.url),
  ),
);
const { workerDraft, scanId } = await import("./scan-draft-fixture.ts");
const { archiveDirectory } = await (
  await import("./import-module.ts")
).importSource(
  fileURLToPath(new URL("../src/deep-scan/artifacts.ts", import.meta.url)),
);

for (const mode of ["archived", "fresh", "reassessed"]) {
  test(`resolved retry task retains its accepted origin (${mode})`, async () => {
    const root = await mkdtemp(path.join(tmpdir(), "retry-closure-"));
    try {
      const workerRoot = path.join(
        root,
        "artifacts",
        "deep_discovery",
        "workers",
        "discovery-0001",
      );
      const output = path.join(workerRoot, "output");
      const archive = path.join(workerRoot, "attempts", "attempt-01");
      await mkdir(output, { recursive: true });
      const context = {
        root: output,
        repoRoot: root,
        scanId,
        layout: "worker",
      };
      const coverage = {
        completeness: "complete",
        surfaces: [],
        explicitExclusions: [],
        deferred: [],
      };
      const closure = {
        id: "review-task",
        reason: "Synthetic source review completed.",
      };
      const pending = {
        ...coverage,
        completeness: "partial",
        deferred: [
          { id: closure.id, reason: "Synthetic source review pending." },
        ],
      };
      const saved = new Map();
      if (mode !== "fresh") {
        await recordCodexSecurityWorkerScanDraft(
          context,
          workerDraft([], { complete: false, coverage: pending }),
        );
        await recordCodexSecurityWorkerScanDraft(
          context,
          workerDraft([], {
            complete: true,
            coverage: { ...coverage, resolvedDeferred: [closure] },
          }),
        );
        await archiveDirectory(output, archive);
        for (const relative of await readdir(archive, { recursive: true })) {
          const file = path.join(archive, relative);
          try {
            saved.set(file, await readFile(file));
          } catch (error) {
            if (error.code !== "EISDIR") throw error;
          }
        }
      }
      await mkdir(output, { recursive: true });
      if (mode !== "archived") {
        await recordCodexSecurityWorkerScanDraft(
          context,
          workerDraft([], { complete: false, coverage: pending }),
        );
      }
      const currentClosure =
        mode === "reassessed"
          ? { ...closure, reason: "Synthetic review reassessed during retry." }
          : closure;
      await recordCodexSecurityWorkerScanDraft(
        context,
        workerDraft([], {
          complete: true,
          coverage: {
            ...coverage,
            ...(mode === "archived"
              ? {}
              : { resolvedDeferred: [currentClosure] }),
          },
        }),
      );
      const resultPath = path.join(output, "result.json");
      const persisted = JSON.parse(await readFile(resultPath, "utf8"));
      assert.equal(persisted.coverage.resolvedDeferred.length, 1);
      const reductionContext = {
        root: path.join(
          root,
          "artifacts",
          "deep_discovery",
          "dedup",
          "dedup-0001",
          "output",
        ),
        repoRoot: root,
        scanId,
        layout: "reducer",
        deepReducer: {
          scanRoot: root,
          persistSourceCoverage: true,
          claimedWorkers: [{ id: "worker", attempt: 2, resultPath }],
        },
      };
      const sources = await readDeepReductionSources(reductionContext);
      const projected = sources.discoveries[0].coverage;
      const expectedAttempt = mode === "archived" ? 1 : 2;
      assert.equal(
        projected.resolvedDeferred[0].id,
        `worker-attempt-${expectedAttempt}-resolved-${closure.id}`,
      );
      assert.equal(projected.resolvedDeferred[0].reason, currentClosure.reason);
      assert.ok(
        projected.reviews.some((review) => review.attempt === expectedAttempt),
      );
      await mkdir(reductionContext.root, { recursive: true });
      await recordCodexSecurityDeepReduction(reductionContext, {
        scanId,
        complete: true,
        findings: [],
      });
      const reduced = JSON.parse(
        await readFile(path.join(reductionContext.root, "result.json"), "utf8"),
      );
      const accepted = parseDeepReduction(reduced, true);
      assert.deepEqual(
        accepted.sourceCoverage.resolvedDeferred,
        projected.resolvedDeferred,
      );
      for (const [file, bytes] of saved)
        assert.deepEqual(await readFile(file), bytes);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}

for (const history of [
  "valid",
  "unreadable",
  "mixed",
  "malformed-head",
  "missing-selected",
  "malformed-selected",
  "invalid-head",
  "invalid-selected",
  "wrong-scan-selected",
  "wrong-scan-result",
]) {
  const malformedHistory = history !== "valid";
  const readableHistory = history !== "unreadable";
  test(`accepted retry coverage preserves available history (${history})`, async () => {
    const root = await mkdtemp(path.join(tmpdir(), "retry-origin-"));
    try {
      const workerRoot = path.join(
        root,
        "artifacts",
        "deep_discovery",
        "workers",
        "discovery-0001",
      );
      const output = path.join(workerRoot, "output");
      const resultPath = path.join(output, "result.json");
      const archivePrefix =
        "artifacts/deep_discovery/workers/discovery-0001/attempts/attempt-01/";
      const descriptions = {
        workerId: "unrelated",
        attempt: 99,
        description: "Original review.",
      };
      const retained = {
        completeness: "partial",
        surfaces: [
          {
            id: "prior",
            label: "Prior review",
            disposition: "needs_follow_up",
            receiptRefs: ["artifacts/prior.txt"],
            provenance: descriptions,
          },
        ],
        explicitExclusions: [
          {
            pattern: "vendor/",
            reason: "External sources.",
            provenance: descriptions,
          },
        ],
        deferred: [
          {
            id: "pending",
            reason: "Review remains.",
            surfaceIds: ["prior"],
            provenance: descriptions,
          },
        ],
        openQuestions: ["Retained question."],
      };
      const carried = structuredClone(retained);
      carried.surfaces[0].receiptRefs = [archivePrefix + "artifacts/prior.txt"];
      const current = structuredClone(carried);
      current.surfaces.push({
        id: "same-id",
        label: "Current review",
        disposition: "no_issue_found",
        receiptRefs: [],
      });
      const files = new Map();
      const save = async (file, value) => {
        await mkdir(path.dirname(file), { recursive: true });
        const bytes = JSON.stringify(value);
        await writeFile(file, bytes);
        files.set(file, bytes);
      };
      await save(
        resultPath,
        workerDraft([], { complete: true, coverage: current }),
      );
      if (malformedHistory) {
        const attempt = path.join(workerRoot, "attempts", "attempt-02");
        const checkpoint = "a".repeat(64) + ".json";
        if (history === "malformed-head") {
          await mkdir(attempt, { recursive: true });
          const headPath = path.join(attempt, "checkpoint-head.json");
          await writeFile(headPath, "{");
          files.set(headPath, "{");
        } else if (history === "invalid-head") {
          await save(path.join(attempt, "checkpoint-head.json"), {
            checkpoint: "../unrelated.json",
          });
        } else if (history.endsWith("selected")) {
          await save(path.join(attempt, "checkpoint-head.json"), {
            checkpoint,
          });
          if (history === "malformed-selected") {
            const selected = path.join(attempt, "checkpoints", checkpoint);
            await mkdir(path.dirname(selected), { recursive: true });
            await writeFile(selected, "{");
            files.set(selected, "{");
          } else if (
            history === "invalid-selected" ||
            history === "wrong-scan-selected"
          ) {
            await save(
              path.join(attempt, "checkpoints", checkpoint),
              history === "invalid-selected"
                ? { scanId }
                : {
                    ...workerDraft([], { complete: false, coverage: retained }),
                    scanId: "22222222-2222-4222-8222-222222222222",
                  },
            );
          }
        } else if (history !== "wrong-scan-result") {
          const broken = path.join(attempt, "checkpoints", "broken.json");
          await mkdir(path.dirname(broken), { recursive: true });
          await writeFile(broken, "{");
          files.set(broken, "{");
        }
      }
      if (readableHistory) {
        const receipt = path.join(
          workerRoot,
          "attempts",
          "attempt-01",
          "artifacts",
          "prior.txt",
        );
        await mkdir(path.dirname(receipt), { recursive: true });
        const receiptBytes = "Synthetic prior receipt.\n";
        await writeFile(receipt, receiptBytes);
        files.set(receipt, receiptBytes);
        const old = structuredClone(retained);
        old.surfaces.push({
          id: "same-id",
          label: "Previous review",
          disposition: "no_issue_found",
          receiptRefs: [],
        });
        await save(
          path.join(workerRoot, "attempts", "attempt-01", "result.json"),
          workerDraft([], { complete: false, coverage: old }),
        );
        await save(
          path.join(workerRoot, "attempts", "attempt-02", "result.json"),
          workerDraft([], { complete: false, coverage: carried }),
        );
      }
      if (history === "wrong-scan-result") {
        await save(
          path.join(workerRoot, "attempts", "attempt-02", "result.json"),
          {
            ...workerDraft([], { complete: false, coverage: carried }),
            scanId: "22222222-2222-4222-8222-222222222222",
          },
        );
      }
      const sources = await readDeepReductionSources({
        root: path.join(
          root,
          "artifacts",
          "deep_discovery",
          "dedup",
          "dedup-0001",
          "output",
        ),
        repoRoot: root,
        scanId,
        layout: "reducer",
        deepReducer: {
          scanRoot: root,
          claimedWorkers: [{ id: "worker", attempt: 3, resultPath }],
        },
      });
      const coverage = sources.discoveries[0].coverage;
      if (readableHistory) {
        assert.deepEqual(
          coverage.reviews.map((review) => review.attempt).sort(),
          [1, 3],
        );
        for (const field of [
          "surfaces",
          "explicitExclusions",
          "deferred",
          "openQuestions",
        ])
          assert.equal(coverage[field][0].provenance.attempt, 1, field);
        assert.equal(coverage.surfaces[1].provenance.attempt, 3);
        assert.deepEqual(coverage.deferred[0].surfaceIds, [
          coverage.surfaces[0].id,
        ]);
        assert.equal(coverage.surfaces[0].provenance.workerId, "worker");
      }
      assert.equal(coverage.surfaces.length, 2);
      if (malformedHistory)
        await assert.rejects(
          recordCodexSecurityWorkerScanDraft(
            { root: output, repoRoot: root, scanId, layout: "worker" },
            workerDraft([], { complete: true, coverage: current }),
          ),
          history === "invalid-head"
            ? /archived checkpoint head is invalid/
            : history === "wrong-scan-selected" ||
                history === "wrong-scan-result"
              ? /scanId does not match the authoritative workbench scan/
              : history === "invalid-selected"
                ? /Invalid input: expected array, received undefined/
                : /archived scan checkpoint.*(?:stored JSON is malformed|requested artifact is unavailable)/,
        );
      for (const [file, bytes] of files)
        assert.equal(await readFile(file, "utf8"), bytes);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}

for (const workflowVersion of ["deep-scan-mcp/v1", "deep-security-scan/v2"]) {
  for (const resume of [false, true]) {
    test(`workbench version reaches reducer persistence (${workflowVersion}, resume: ${resume})`, async () => {
      const root = await mkdtemp(path.join(tmpdir(), "coverage-version-"));
      try {
        await publishCoverageFixture(root, "partial", {
          workflowVersion,
          resume,
          continueAfterResume: resume,
        });
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
  }
}

for (const omitted of ["none", "receipts", "ids-and-receipts"]) {
  test(`direct-file retry attribution follows persisted normalization (${omitted})`, async () => {
    const root = await mkdtemp(path.join(tmpdir(), "retry-normalization-"));
    try {
      const workerRoot = path.join(
        root,
        "artifacts",
        "deep_discovery",
        "workers",
        "discovery-0001",
      );
      const output = path.join(workerRoot, "output");
      const archive = path.join(
        workerRoot,
        "attempts",
        "attempt-01",
        "result.json",
      );
      await mkdir(path.dirname(archive), { recursive: true });
      await mkdir(output);
      const missingIds = omitted === "ids-and-receipts";
      const prior = workerDraft([], {
        complete: false,
        coverage: {
          completeness: "partial",
          surfaces: [
            {
              ...(missingIds ? {} : { id: "prior" }),
              label: "Prior review",
              disposition: "needs_follow_up",
              ...(omitted === "none" ? { receiptRefs: [] } : {}),
            },
          ],
          explicitExclusions: [],
          deferred: [
            {
              ...(missingIds ? {} : { id: "pending", surfaceIds: ["prior"] }),
              reason: "Prior review remains.",
            },
          ],
        },
      });
      const archivedBytes = JSON.stringify(prior);
      await writeFile(archive, archivedBytes);
      await recordCodexSecurityWorkerScanDraft(
        { root: output, repoRoot: root, scanId, layout: "worker" },
        workerDraft([], {
          complete: true,
          coverage: {
            completeness: "complete",
            surfaces: [
              {
                id: "current",
                label: "Current review",
                disposition: "no_issue_found",
                receiptRefs: [],
              },
            ],
            explicitExclusions: [],
            deferred: [],
          },
        }),
      );
      const resultPath = path.join(output, "result.json");
      const acceptedBytes = await readFile(resultPath, "utf8");
      const accepted = JSON.parse(acceptedBytes);
      assert.equal(accepted.coverage.surfaces.length, 2);
      assert.equal(typeof accepted.coverage.surfaces[1].id, "string");
      assert.deepEqual(accepted.coverage.surfaces[1].receiptRefs, []);
      assert.equal(typeof accepted.coverage.deferred[0].id, "string");
      const sources = await readDeepReductionSources({
        root: path.join(
          root,
          "artifacts",
          "deep_discovery",
          "dedup",
          "dedup-0001",
          "output",
        ),
        repoRoot: root,
        scanId,
        layout: "reducer",
        deepReducer: {
          scanRoot: root,
          claimedWorkers: [{ id: "discovery-0001", attempt: 2, resultPath }],
        },
      });
      const coverage = sources.discoveries[0].coverage;
      assert.deepEqual(
        coverage.surfaces.map((row) => row.provenance.attempt),
        [2, 1],
      );
      assert.equal(coverage.deferred[0].provenance.attempt, 1);
      assert.deepEqual(
        coverage.reviews.map((row) => row.attempt).sort(),
        [1, 2],
      );
      if (!missingIds)
        assert.deepEqual(coverage.deferred[0].surfaceIds, [
          coverage.surfaces[1].id,
        ]);
      assert.equal(await readFile(archive, "utf8"), archivedBytes);
      assert.equal(await readFile(resultPath, "utf8"), acceptedBytes);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}

for (const workflowVersion of ["deep-scan-mcp/v1", "deep-security-scan/v2"]) {
  for (const directFile of [false, true]) {
    for (const omitCoverageIds of [false, true]) {
      test(`persisted coverage identities survive recovery (${workflowVersion}, direct: ${directFile}, omitted: ${omitCoverageIds})`, async () => {
        const root = await mkdtemp(path.join(tmpdir(), "coverage-identities-"));
        try {
          await publishCoverageFixture(root, "partial", {
            workflowVersion,
            directFile,
            omitCoverageIds,
            stopAfterDraft: true,
          });
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      });
    }
  }
}

for (const workflowVersion of ["deep-scan-mcp/v1", "deep-security-scan/v2"]) {
  test(`direct-file coverage retains competing explicit identities (${workflowVersion})`, async () => {
    const root = await mkdtemp(path.join(tmpdir(), "coverage-competing-"));
    try {
      await publishCoverageFixture(root, "partial", {
        workflowVersion,
        directFile: true,
        omitCoverageIds: true,
        competingIds: true,
        stopAfterDraft: true,
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}

for (const workflowVersion of ["deep-scan-mcp/v1", "deep-security-scan/v2"]) {
  for (const directFile of [false, true]) {
    for (const omitCoverageIds of [false, true]) {
      test(`named retry coverage survives recovery (${workflowVersion}, direct: ${directFile}, omitted: ${omitCoverageIds})`, async () => {
        const root = await mkdtemp(
          path.join(tmpdir(), "coverage-named-retry-"),
        );
        try {
          await publishCoverageFixture(root, "partial", {
            workflowVersion,
            directFile,
            omitCoverageIds,
            namedRetry: true,
            stopAfterDraft: true,
          });
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      });
    }
  }
  for (const linkedRetry of [false, true]) {
    test(`named retry coverage retains ${linkedRetry ? "linked" : "competing"} identities (${workflowVersion})`, async () => {
      const root = await mkdtemp(
        path.join(tmpdir(), "coverage-named-identity-"),
      );
      try {
        await publishCoverageFixture(root, "partial", {
          workflowVersion,
          directFile: true,
          omitCoverageIds: true,
          competingIds: !linkedRetry,
          linkedRetry,
          namedRetry: true,
          stopAfterDraft: true,
        });
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
  }
}

for (const workflowVersion of ["deep-scan-mcp/v1", "deep-security-scan/v2"]) {
  for (const missingProjection of ["surfaces", "deferred", "both"]) {
    test(`named retry fills a missing linked projection (${workflowVersion}, ${missingProjection})`, async () => {
      const root = await mkdtemp(
        path.join(tmpdir(), "coverage-missing-retry-"),
      );
      try {
        await publishCoverageFixture(root, "partial", {
          workflowVersion,
          directFile: true,
          omitCoverageIds: true,
          namedRetry: true,
          linkedRetry: true,
          missingProjection,
          stopAfterDraft: true,
        });
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
  }
  for (const omitCoverageIds of [false, true]) {
    test(`named retry preserves changed observations (${workflowVersion}, omitted: ${omitCoverageIds})`, async () => {
      const root = await mkdtemp(
        path.join(tmpdir(), "coverage-changed-retry-"),
      );
      try {
        await publishCoverageFixture(root, "partial", {
          workflowVersion,
          directFile: true,
          omitCoverageIds,
          namedRetry: true,
          changedRetry: true,
          stopAfterDraft: true,
        });
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
  }
}

for (const interruptReducer of ["merging", "buffered"]) {
  for (const directFile of [false, true]) {
    for (const omitCoverageIds of [false, true]) {
      test(`uncommitted reducer preserves represented and pending coverage (${interruptReducer}, ${directFile ? "direct" : "writer"}, ${omitCoverageIds ? "omitted" : "explicit"} IDs)`, async () => {
        const root = await mkdtemp(
          path.join(tmpdir(), "uncommitted-coverage-"),
        );
        try {
          await publishCoverageFixture(root, "partial", {
            resume: true,
            workflowVersion: "deep-security-scan/v2",
            interruptReducer,
            directFile,
            omitCoverageIds,
            namedRetry: true,
            linkedRetry: true,
          });
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      });
    }
  }
}

for (const workflowVersion of ["deep-scan-mcp/v1", "deep-security-scan/v2"]) {
  for (const directFile of [false, true]) {
    test(`partial parent retains descriptive coverage variants (${workflowVersion}, ${directFile ? "direct" : "writer"})`, async () => {
      const root = await mkdtemp(path.join(tmpdir(), "coverage-descriptions-"));
      try {
        await publishCoverageFixture(root, "partial", {
          workflowVersion,
          directFile,
          omitCoverageIds: directFile,
          resume: true,
          stopAfterDraft: true,
          descriptiveVariants: true,
        });
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
  }
}
for (const provenanceKind of ["owner-only", "absent"]) {
  test(`retained projection accepts ${provenanceKind} provenance`, async () => {
    const root = await mkdtemp(path.join(tmpdir(), "coverage-provenance-"));
    try {
      await publishCoverageFixture(root, "partial", {
        workflowVersion: "deep-security-scan/v2",
        directFile: true,
        omitCoverageIds: true,
        stopAfterDraft: true,
        provenanceKind,
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}
for (const interruptReducer of ["merging", "buffered"]) {
  for (const directFile of [false, true]) {
    test(`checkpoint-only reducer preserves represented coverage (${interruptReducer}, ${directFile ? "direct" : "writer"})`, async () => {
      const root = await mkdtemp(
        path.join(tmpdir(), "coverage-checkpoint-only-"),
      );
      try {
        await publishCoverageFixture(root, "partial", {
          workflowVersion: "deep-security-scan/v2",
          resume: true,
          interruptReducer,
          checkpointOnly: true,
          directFile,
          omitCoverageIds: directFile,
          namedRetry: true,
          linkedRetry: true,
        });
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
  }
}
for (const parentTiming of ["older", "newer"]) {
  test(`checkpoint-only reducer reconciles ${parentTiming} parent`, async () => {
    const root = await mkdtemp(
      path.join(tmpdir(), "coverage-checkpoint-parent-"),
    );
    try {
      await publishCoverageFixture(root, "partial", {
        workflowVersion: "deep-security-scan/v2",
        resume: true,
        interruptReducer: "buffered",
        checkpointOnly: true,
        parentTiming,
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}

for (const workflowVersion of ["deep-scan-mcp/v1", "deep-security-scan/v2"]) {
  for (const directFile of [false, true]) {
    test(`same-attempt changed surface keeps its deferred links (${workflowVersion}, ${directFile ? "direct" : "writer"})`, async () => {
      const root = await mkdtemp(
        path.join(tmpdir(), "coverage-changed-surface-"),
      );
      try {
        await publishCoverageFixture(root, "partial", {
          workflowVersion,
          directFile,
          sameAttemptChange: true,
          stopAfterDraft: true,
        });
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
  }
}

for (const workflowVersion of ["deep-scan-mcp/v1", "deep-security-scan/v2"]) {
  test(`missing equal ID-less surface rows preserve separate positions (${workflowVersion})`, async () => {
    const root = await mkdtemp(path.join(tmpdir(), "coverage-equal-surface-"));
    try {
      await publishCoverageFixture(root, "partial", {
        workflowVersion,
        directFile: true,
        omitCoverageIds: true,
        duplicateRows: true,
        missingProjection: "surfaces",
        stopAfterDraft: true,
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}

for (const completeness of ["complete", "partial"]) {
  for (const stopAfterDraft of [false, true]) {
    test(`streamed discovery retry retains origin through ${completeness} ${stopAfterDraft ? "recovery" : "completion"}`, async () => {
      const root = await mkdtemp(path.join(tmpdir(), "retry-origin-stream-"));
      try {
        await publishCoverageFixture(root, completeness, {
          streamRetry: true,
          stopAfterDraft,
        });
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
  }
}

for (const failClosedResult of [false, true]) {
  test(`generic closing checkpoint replaces retained host surface after failed result=${failClosedResult}`, async () => {
    const root = await mkdtemp(path.join(tmpdir(), "retry-generic-closure-"));
    try {
      await publishCoverageFixture(root, "complete", {
        closeGeneric: true,
        failClosedResult,
        stopAfterDraft: true,
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}

for (const ref of [
  "artifacts/review.txt",
  "artifacts/./review.txt",
  "artifacts//review.txt",
]) {
  for (const state of ["copied", "changed", "missing-archive"]) {
    test(`supported typed writer receipt origin (${ref}, ${state})`, async () => {
      const root = await mkdtemp(path.join(tmpdir(), "pr921-receipt-"));
      try {
        const workerRoot = path.join(
          root,
          "artifacts/deep_discovery/workers/discovery-0001",
        );
        const output = path.join(workerRoot, "output");
        await mkdir(path.join(output, "artifacts"), { recursive: true });
        await writeFile(
          path.join(output, "artifacts/review.txt"),
          "Synthetic original receipt.\n",
        );
        const context = {
          root: output,
          repoRoot: root,
          scanId,
          layout: "worker",
        };
        const draft = workerDraft([], {
          complete: false,
          coverage: {
            completeness: "partial",
            surfaces: [
              {
                label: "Synthetic receipt review",
                disposition: "needs_follow_up",
                receiptRefs: [ref],
              },
            ],
            explicitExclusions: [],
            deferred: [],
          },
        });
        await recordCodexSecurityWorkerScanDraft(context, draft);
        const saved = JSON.parse(
          await readFile(path.join(output, "result.json"), "utf8"),
        );
        assert.equal(
          typeof saved.coverage.surfaces[0].id,
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
        await recordCodexSecurityWorkerScanDraft(context, {
          ...draft,
          complete: true,
        });
        const current = JSON.parse(
          await readFile(path.join(output, "result.json"), "utf8"),
        );
        assert.equal(
          current.coverage.surfaces.length,
          1,
          "supported resumed writer retains one matching normalized surface",
        );
        assert.equal(
          current.coverage.surfaces[0].id,
          saved.coverage.surfaces[0].id,
        );
        assert.deepEqual(current.coverage.surfaces[0].receiptRefs, [ref]);
        const resultPath = path.join(output, "result.json");
        const resultBytes = await readFile(resultPath);
        const sources = await readDeepReductionSources({
          root: path.join(
            root,
            "artifacts/deep_discovery/dedup/dedup-0001/output",
          ),
          repoRoot: root,
          scanId,
          layout: "reducer",
          deepReducer: {
            scanRoot: root,
            claimedWorkers: [{ id: "discovery-0001", attempt: 2, resultPath }],
          },
        });
        const surface = sources.discoveries[0].coverage.surfaces[0];
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
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
  }
}
