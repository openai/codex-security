import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { importSource } from "./import-module.ts";
import {
  workerHistoryFixture,
  scanId,
  workerDraft,
} from "./scan-draft-fixture.ts";

const { readAcceptedDiscovery } = await importSource(
  fileURLToPath(
    new URL("../src/deep-scan/artifact-validation.ts", import.meta.url),
  ),
);
const { recordCodexSecurityWorkerScanDraft, readArchivedWorkerCheckpoints } =
  await importSource(
    fileURLToPath(new URL("../src/artifact-scan-draft.ts", import.meta.url)),
  );
const { archiveDirectory, createDeepScanArtifacts } = await importSource(
  fileURLToPath(new URL("../src/deep-scan/artifacts.ts", import.meta.url)),
);

test("three actual cumulative worker attempts retain original coverage ownership", async (t) => {
  const f = await workerHistoryFixture(t, 3);
  const worker = f.workerContext;
  for (const attempt of [1, 2, 3]) {
    await mkdir(f.output, { recursive: true });
    await recordCodexSecurityWorkerScanDraft(
      worker,
      workerDraft([], {
        complete: attempt === 3,
        reviewState: {
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
  const source = (
    await readAcceptedDiscovery(
      createDeepScanArtifacts(f.scanRoot),
      f.worker,
      scanId,
    )
  ).coverage;
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

for (const field of [
  "deferred",
  "explicitExclusions",
  "openQuestions",
] as const) {
  for (const sameText of [false, true]) {
    test(`accepted ${field} occurrences retain one source attempt each, same text=${sameText}`, async (t) => {
      const f = await workerHistoryFixture(t, 3);
      const worker = f.workerContext;
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
            reviewState: {
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
      const source = (
        await readAcceptedDiscovery(
          createDeepScanArtifacts(f.scanRoot),
          f.worker,
          scanId,
        )
      ).coverage;
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
    const worker = f.workerContext;
    for (const reason of [
      "Synthetic first exclusion.",
      "Synthetic independent exclusion.",
    ]) {
      await recordCodexSecurityWorkerScanDraft(
        worker,
        workerDraft([], {
          complete: true,
          reviewState: {
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
  const worker = f.workerContext;
  await recordCodexSecurityWorkerScanDraft(
    worker,
    workerDraft([], {
      complete: false,
      reviewState: {
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
  const source = await readAcceptedDiscovery(
    createDeepScanArtifacts(f.scanRoot),
    f.worker,
    scanId,
  );
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
  const draft = workerDraft([], {
    complete: true,
    reviewState: { surfaces: [], explicitExclusions: [], deferred: [row] },
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
  const { coverage } = await readAcceptedDiscovery(
    createDeepScanArtifacts(f.scanRoot),
    f.worker,
    scanId,
  );
  assert.equal(coverage.deferred.length, 1, JSON.stringify(coverage.deferred));
  assert.equal(coverage.deferred[0].provenance.attempt, 1);
  assert.equal(coverage.deferred[0].provenance.note, "Worker note");
});
