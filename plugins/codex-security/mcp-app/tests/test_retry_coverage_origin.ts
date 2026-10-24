import assert from "node:assert/strict";
import { mkdir, readFile, rm } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { importSource } from "./import-module.ts";
import { scanId, workerDraft } from "./scan-draft-fixture.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

const { readDeepReductionSources } = await importSource(
  fileURLToPath(new URL("../src/artifact-deep-reducer.ts", import.meta.url)),
);
const { recordCodexSecurityWorkerScanDraft, readArchivedWorkerCheckpoints } =
  await importSource(
    fileURLToPath(new URL("../src/artifact-scan-draft.ts", import.meta.url)),
  );
const { archiveDirectory } = await importSource(
  fileURLToPath(new URL("../src/deep-scan/artifacts.ts", import.meta.url)),
);

async function fixture() {
  const root = await temporaryDirectory("retry-coverage-origin-", true);
  const scanRoot = path.join(root, "scan");
  const workerRoot = path.join(
    scanRoot,
    "artifacts",
    "deep_discovery",
    "workers",
    "discovery-0001",
  );
  const output = path.join(workerRoot, "output");
  await mkdir(output, { recursive: true });
  const resultPath = path.join(output, "result.json");
  const context = {
    root: path.join(
      scanRoot,
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
      scanRoot,
      claimedWorkers: [{ id: "synthetic-worker", attempt: 3, resultPath }],
    },
  };
  return { root, workerRoot, output, resultPath, context };
}

test("three actual cumulative worker attempts retain original coverage ownership", async () => {
  const f = await fixture();
  try {
    const worker = {
      root: f.output,
      repoRoot: f.root,
      scanId,
      layout: "worker",
    };
    for (const attempt of [1, 2, 3]) {
      await mkdir(f.output, { recursive: true });
      await recordCodexSecurityWorkerScanDraft(
        worker,
        workerDraft([], {
          complete: attempt === 3,
          coverage: {
            completeness: attempt === 3 ? "complete" : "partial",
            surfaces: [
              {
                id: `surface-${attempt}`,
                label: `Review ${attempt}`,
                disposition: "no_issue_found",
              },
            ],
            explicitExclusions: [],
            deferred: [],
          },
        }),
      );
      if (attempt < 3)
        await archiveDirectory(
          f.output,
          path.join(f.workerRoot, "attempts", `attempt-0${attempt}`),
        );
    }
    const source = (await readDeepReductionSources(f.context)).discoveries[0]
      .coverage;
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
  } finally {
    await rm(f.root, { recursive: true, force: true });
  }
});

for (const field of [
  "deferred",
  "explicitExclusions",
  "openQuestions",
] as const) {
  for (const sameText of [false, true]) {
    test(`accepted ${field} occurrences retain one source attempt each, same text=${sameText}`, async () => {
      const f = await fixture();
      try {
        const worker = {
          root: f.output,
          repoRoot: f.root,
          scanId,
          layout: "worker",
        };
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
          await recordCodexSecurityWorkerScanDraft(
            worker,
            workerDraft([], {
              complete: true,
              coverage: {
                completeness: "partial",
                surfaces: [],
                explicitExclusions: [],
                deferred: [],
                [field]: rows,
              },
            }),
          );
          if (attempt < 3) {
            const archive = path.join(
              f.workerRoot,
              "attempts",
              `attempt-0${attempt}`,
            );
            await archiveDirectory(f.output, archive);
            const result = path.join(archive, "result.json");
            archives.push([result, await readFile(result)]);
          }
        }
        const accepted = await readFile(f.resultPath);
        const source = (await readDeepReductionSources(f.context))
          .discoveries[0].coverage;
        assert.equal(source[field].length, 3);
        assert.deepEqual(
          source[field].map(
            (row: { provenance: { attempt: number } }) =>
              row.provenance.attempt,
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
      } finally {
        await rm(f.root, { recursive: true, force: true });
      }
    });
  }
}

for (const id of ["opaque/review:shared", { section: "shared" }]) {
  test(`independent exclusions retain a shared ${typeof id} extension ID`, async () => {
    const f = await fixture();
    try {
      const worker = {
        root: f.output,
        repoRoot: f.root,
        scanId,
        layout: "worker",
      };
      for (const reason of [
        "Synthetic first exclusion.",
        "Synthetic independent exclusion.",
      ]) {
        await recordCodexSecurityWorkerScanDraft(
          worker,
          workerDraft([], {
            complete: true,
            coverage: {
              completeness: "complete",
              surfaces: [],
              explicitExclusions: [
                { id, pattern: "synthetic/excluded/**", reason },
              ],
              deferred: [],
            },
          }),
        );
      }
      const saved = JSON.parse(await readFile(f.resultPath, "utf8"));
      assert.deepEqual(
        saved.coverage.explicitExclusions
          .map((row: { reason: string }) => row.reason)
          .sort(),
        [
          "Synthetic first exclusion.",
          "Synthetic independent exclusion.",
        ].sort(),
      );
      assert.deepEqual(
        saved.coverage.explicitExclusions.map((row: { id: unknown }) => row.id),
        [id, id],
      );
    } finally {
      await rm(f.root, { recursive: true, force: true });
    }
  });
}

test("readable retry origin survives one unsafe unrelated archive", async () => {
  const f = await fixture();
  try {
    const worker = {
      root: f.output,
      repoRoot: f.root,
      scanId,
      layout: "worker",
    };
    await recordCodexSecurityWorkerScanDraft(
      worker,
      workerDraft([], {
        complete: false,
        coverage: {
          completeness: "partial",
          surfaces: [
            {
              id: "saved-review",
              label: "Synthetic retained review",
              disposition: "no_issue_found",
            },
          ],
          explicitExclusions: [],
          deferred: [],
        },
      }),
    );
    const archive = path.join(f.workerRoot, "attempts/attempt-01");
    await archiveDirectory(f.output, archive);
    await recordCodexSecurityWorkerScanDraft(
      worker,
      workerDraft([], { complete: true }),
    );
    const current = await readFile(f.resultPath);
    const historical = await readFile(path.join(archive, "result.json"));
    await mkdir(
      path.join(f.workerRoot, "attempts/attempt-02/checkpoint-head.json"),
      { recursive: true },
    );
    await assert.rejects(
      readArchivedWorkerCheckpoints(worker),
      /archived checkpoint head is not a safe file/,
    );
    const source = (await readDeepReductionSources(f.context)).discoveries[0];
    assert.equal(source.coverage.surfaces.length, 1);
    assert.equal(source.coverage.surfaces[0].provenance.attempt, 1);
    assert.deepEqual(await readFile(f.resultPath), current);
    assert.deepEqual(
      await readFile(path.join(archive, "result.json")),
      historical,
    );
  } finally {
    await rm(f.root, { recursive: true, force: true });
  }
});
