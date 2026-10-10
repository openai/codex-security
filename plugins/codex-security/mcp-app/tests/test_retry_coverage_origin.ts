import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import {
  cp,
  mkdir,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { importSource } from "./import-module.ts";
import { finding, scanId, workerDraft } from "./scan-draft-fixture.ts";
import {
  draftFixture,
  recordCodexSecurityScanDraft,
} from "./scan-draft-recovery-fixture.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

const { readDeepReductionSources } = await importSource(
  fileURLToPath(new URL("../src/artifact-deep-reducer.ts", import.meta.url)),
);
const {
  recordCodexSecurityWorkerScanDraft,
  parsePersistedScanDraft,
  parseScanDraft,
  readArchivedWorkerCheckpoints,
} = await importSource(
  fileURLToPath(new URL("../src/artifact-scan-draft.ts", import.meta.url)),
);
const { validateDiscoveryArtifacts } = await importSource(
  fileURLToPath(
    new URL("../src/deep-scan/artifact-validation.ts", import.meta.url),
  ),
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

for (const malformed of [
  "none",
  "json",
  "schema",
  "head-json",
  "head-checkpoint",
  "head-missing",
]) {
  test(`accepted current coverage survives archived ${malformed}`, async () => {
    const f = await fixture();
    try {
      const archive = path.join(f.workerRoot, "attempts", "attempt-01");
      await mkdir(path.join(archive, "checkpoints"), { recursive: true });
      const name = "a".repeat(64) + ".json";
      const contents =
        malformed === "json"
          ? "{"
          : JSON.stringify(
              malformed === "schema" || malformed === "head-checkpoint"
                ? {}
                : workerDraft([]),
            );
      if (malformed !== "head-missing")
        await writeFile(path.join(archive, "checkpoints", name), contents);
      if (
        malformed === "head-json" ||
        malformed === "head-checkpoint" ||
        malformed === "head-missing"
      )
        await writeFile(
          path.join(archive, "checkpoint-head.json"),
          malformed === "head-json"
            ? "{"
            : JSON.stringify({ checkpoint: name }),
        );
      await writeFile(
        f.resultPath,
        JSON.stringify(workerDraft([], { complete: true })),
      );
      await validateDiscoveryArtifacts(
        { workersRoot: path.dirname(f.workerRoot) },
        f.resultPath,
        scanId,
      );
      const before = await readFile(f.resultPath);
      const sources = await readDeepReductionSources(f.context);
      assert.equal(sources.discoveries.length, 1);
      assert.deepEqual(await readFile(f.resultPath), before);
    } finally {
      await rm(f.root, { recursive: true, force: true });
    }
  });
}

for (const unreadableHead of [false, true]) {
  test(`readable retry history survives one head read failure=${unreadableHead}`, async (t) => {
    const f = await fixture();
    try {
      const worker = {
        root: f.output,
        repoRoot: f.root,
        scanId,
        layout: "worker",
      };
      for (const attempt of [1, 2]) {
        await recordCodexSecurityWorkerScanDraft(
          worker,
          workerDraft([], {
            complete: false,
            coverage: {
              completeness: "partial",
              surfaces: [],
              explicitExclusions: [],
              deferred: [
                {
                  id: `task-${attempt}`,
                  reason: `Synthetic proof ${attempt}.`,
                },
              ],
            },
          }),
        );
        await archiveDirectory(
          f.output,
          path.join(f.workerRoot, "attempts", `attempt-0${attempt}`),
        );
      }
      const head = path.join(
        f.workerRoot,
        "attempts",
        "attempt-02",
        "checkpoint-head.json",
      );
      const before = await readFile(head);
      assert.ok((await fs.lstat(head)).isFile());
      // Direct-file worker results remain accepted after a failed retry checkpoint.
      await writeFile(
        f.resultPath,
        JSON.stringify(workerDraft([], { complete: true })),
      );
      const resultBefore = await readFile(f.resultPath);
      await validateDiscoveryArtifacts(
        { workersRoot: path.dirname(f.workerRoot) },
        f.resultPath,
        scanId,
      );
      if (unreadableHead) {
        const open = fs.open;
        t.mock.method(fs, "open", async (...args: Parameters<typeof open>) => {
          if (args[0] === head && args[1] === "r") {
            throw Object.assign(
              new Error("Synthetic regular-file read failure."),
              { code: "EIO" },
            );
          }
          return open(...args);
        });
        await assert.rejects(
          readArchivedWorkerCheckpoints(worker),
          /cannot be read/,
        );
      }
      const coverage = (await readDeepReductionSources(f.context))
        .discoveries[0].coverage;
      assert.deepEqual(
        new Set(
          coverage.deferred.map(
            (row: { provenance: { sourceId: string } }) =>
              row.provenance.sourceId,
          ),
        ),
        new Set(["task-1", "task-2"]),
      );
      assert.deepEqual(await readFile(head), before);
      assert.deepEqual(await readFile(f.resultPath), resultBefore);
    } finally {
      t.mock.restoreAll();
      await rm(f.root, { recursive: true, force: true });
    }
  });
}

for (const inaccessibleAttempt of [0, 1, 2]) {
  test(`readable retry history survives inaccessible archive=${inaccessibleAttempt}`, async (t) => {
    const f = await fixture();
    const originals = new Map<string, Buffer>();
    try {
      const worker = {
        root: f.output,
        repoRoot: f.root,
        scanId,
        layout: "worker",
      };
      for (const attempt of [1, 2]) {
        await recordCodexSecurityWorkerScanDraft(
          worker,
          workerDraft([], {
            complete: false,
            coverage: {
              completeness: "partial",
              surfaces: [],
              explicitExclusions: [],
              deferred: [
                {
                  id: `task-${attempt}`,
                  reason: `Synthetic proof ${attempt}.`,
                },
              ],
            },
          }),
        );
        const archive = path.join(
          f.workerRoot,
          "attempts",
          `attempt-0${attempt}`,
        );
        await archiveDirectory(f.output, archive);
        for (const name of await readdir(archive, { recursive: true })) {
          const saved = path.join(archive, name);
          if ((await fs.lstat(saved)).isFile())
            originals.set(saved, await readFile(saved));
        }
      }
      for (const attempt of [1, 2]) {
        const saved = originals.get(
          path.join(
            f.workerRoot,
            "attempts",
            `attempt-0${attempt}`,
            "result.json",
          ),
        )!;
        const produced = JSON.parse(saved.toString("utf8"));
        assert.deepEqual(
          produced.coverage.deferred
            .map((row: { id: string }) => row.id)
            .sort(),
          attempt === 1 ? ["task-1"] : ["task-1", "task-2"],
        );
      }
      await writeFile(
        f.resultPath,
        JSON.stringify(workerDraft([], { complete: true })),
      );
      originals.set(f.resultPath, await readFile(f.resultPath));
      await validateDiscoveryArtifacts(
        { workersRoot: path.dirname(f.workerRoot) },
        f.resultPath,
        scanId,
      );
      if (inaccessibleAttempt !== 0) {
        const archive = await fs.realpath(
          path.join(
            f.workerRoot,
            "attempts",
            `attempt-0${inaccessibleAttempt}`,
          ),
        );
        const lstat = fs.lstat;
        t.mock.method(
          fs,
          "lstat",
          async (...args: Parameters<typeof lstat>) => {
            if (
              typeof args[0] === "string" &&
              args[0].startsWith(archive + path.sep)
            ) {
              throw Object.assign(
                new Error("Synthetic inaccessible archived attempt."),
                { code: "EACCES" },
              );
            }
            return lstat(...args);
          },
        );
        await assert.rejects(readArchivedWorkerCheckpoints(worker), {
          code: "EACCES",
          message: "Synthetic inaccessible archived attempt.",
        });
      }
      const coverage = (await readDeepReductionSources(f.context))
        .discoveries[0].coverage;
      t.mock.restoreAll();
      for (const [saved, contents] of originals)
        assert.deepEqual(await readFile(saved), contents);
      assert.deepEqual(
        coverage.deferred
          .map(
            (row: {
              provenance: {
                sourceId: string;
                attempt: number;
                workerId: string;
              };
            }) => [
              row.provenance.sourceId,
              row.provenance.attempt,
              row.provenance.workerId,
            ],
          )
          .sort(),
        inaccessibleAttempt === 2
          ? [["task-1", 1, "synthetic-worker"]]
          : [
              ["task-1", inaccessibleAttempt === 1 ? 2 : 1, "synthetic-worker"],
              ["task-2", 2, "synthetic-worker"],
            ],
      );
      assert.equal(coverage.completeness, "partial");
    } finally {
      t.mock.restoreAll();
      await rm(f.root, { recursive: true, force: true });
    }
  });
}

for (const unsafe of ["wrong-scan", "linked-checkpoints"]) {
  test(`archived ${unsafe} retains its existing rejection`, async () => {
    const f = await fixture();
    try {
      const archive = path.join(f.workerRoot, "attempts", "attempt-01");
      await mkdir(archive, { recursive: true });
      if (unsafe === "wrong-scan") {
        await mkdir(path.join(archive, "checkpoints"));
        await writeFile(
          path.join(archive, "checkpoints", "a.json"),
          JSON.stringify(
            workerDraft([], { scanId: "12c17317-9594-49e0-b06a-d72fd7e14bba" }),
          ),
        );
      } else {
        const outside = path.join(f.root, "outside");
        await mkdir(outside);
        await symlink(
          outside,
          path.join(archive, "checkpoints"),
          process.platform === "win32" ? "junction" : "dir",
        );
      }
      await writeFile(
        f.resultPath,
        JSON.stringify(workerDraft([], { complete: true })),
      );
      await assert.rejects(
        readArchivedWorkerCheckpoints({
          root: f.output,
          repoRoot: f.root,
          scanId,
          layout: "worker",
        }),
        unsafe === "wrong-scan"
          ? /scanId does not match|different scan/
          : /safe directory/,
      );
      const accepted = await readDeepReductionSources(f.context);
      assert.equal(accepted.discoveries.length, 1);
      assert.deepEqual(accepted.discoveries[0].result.findings, []);
      assert.deepEqual(
        JSON.parse(await readFile(f.resultPath, "utf8")),
        workerDraft([], { complete: true }),
      );
    } finally {
      await rm(f.root, { recursive: true, force: true });
    }
  });
}

for (const duplicate of [false, true]) {
  test(`raw saved surface references retain every matching target=${duplicate}`, async () => {
    const f = await fixture();
    try {
      const coverage = {
        completeness: "partial",
        surfaces: [
          {
            id: "shared",
            label: "First surface",
            disposition: "needs_follow_up",
          },
          {
            id: duplicate ? "shared" : "second",
            label: "Second surface",
            disposition: "needs_follow_up",
          },
        ],
        explicitExclusions: [],
        deferred: [
          {
            id: "task",
            reason: "Follow up first surface.",
            surfaceIds: ["shared"],
          },
        ],
      };
      await writeFile(
        f.resultPath,
        JSON.stringify(workerDraft([], { complete: true, coverage })),
      );
      const source = (await readDeepReductionSources(f.context)).discoveries[0]
        .coverage;
      assert.deepEqual(
        source.deferred[0].surfaceIds,
        source.surfaces
          .slice(0, duplicate ? 2 : 1)
          .map((surface: { id: string }) => surface.id),
      );
      assert.notEqual(source.surfaces[0].id, source.surfaces[1].id);
    } finally {
      await rm(f.root, { recursive: true, force: true });
    }
  });
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

for (const withReceipts of [false, true]) {
  for (const directFile of [false, true]) {
    for (const optionalIds of [false, true]) {
      test(`retry writer retains raw archived coverage ownership, optional IDs=${optionalIds}, receipts=${withReceipts}, direct file=${directFile}`, async () => {
        const f = await fixture();
        try {
          f.context.deepReducer.claimedWorkers[0].attempt = 2;
          const inherited = workerDraft([], {
            complete: false,
            coverage: {
              completeness: "partial",
              surfaces: [
                {
                  ...(optionalIds
                    ? { id: "first-surface", receiptRefs: [] }
                    : {}),
                  receiptRefs: withReceipts ? ["artifacts/review.txt"] : [],
                  label: "First attempt review",
                  disposition: "needs_follow_up",
                },
              ],
              explicitExclusions: [],
              deferred: [
                {
                  ...(optionalIds ? { id: "first-task" } : {}),
                  reason: "First attempt still needs validation.",
                },
              ],
            },
          });
          // A worker can finish with an incomplete result; its retry uses the normal
          // recording API to retain those saved observations.
          if (withReceipts) {
            await mkdir(path.join(f.output, "artifacts"), { recursive: true });
            await writeFile(
              path.join(f.output, "artifacts/review.txt"),
              "Original synthetic review.\n",
            );
          }
          await writeFile(f.resultPath, JSON.stringify(inherited));
          const archive = path.join(f.workerRoot, "attempts", "attempt-01");
          await archiveDirectory(f.output, archive);
          const archiveResult = path.join(archive, "result.json");
          const before = await readFile(archiveResult);
          await mkdir(f.output, { recursive: true });
          if (directFile) {
            if (withReceipts) {
              await mkdir(path.join(f.output, "artifacts"), {
                recursive: true,
              });
              await writeFile(
                path.join(f.output, "artifacts/review.txt"),
                "Original synthetic review.\n",
              );
            }
            await writeFile(
              f.resultPath,
              JSON.stringify({ ...inherited, complete: true }),
            );
            await validateDiscoveryArtifacts(
              { workersRoot: path.dirname(f.workerRoot) },
              f.resultPath,
              scanId,
            );
          } else
            await recordCodexSecurityWorkerScanDraft(
              {
                root: f.output,
                repoRoot: f.root,
                scanId,
                layout: "worker",
              },
              workerDraft([], { complete: true }),
            );
          const source = (await readDeepReductionSources(f.context))
            .discoveries[0].coverage;
          for (const field of ["surfaces", "deferred"])
            assert.equal(source[field][0].provenance.attempt, 1);
          assert.ok(
            source.reviews.some(
              (review: { attempt: number }) => review.attempt === 1,
            ),
          );
          assert.deepEqual(await readFile(archiveResult), before);
        } finally {
          await rm(f.root, { recursive: true, force: true });
        }
      });
    }
  }
}

test("persisted optional coverage IDs retain their original host-projection shape", async () => {
  const f = await fixture();
  try {
    const source = workerDraft([], {
      complete: true,
      coverage: {
        completeness: "partial",
        surfaces: [
          {
            label: "Synthetic pending surface",
            disposition: "needs_follow_up",
            receiptRefs: [],
          },
        ],
        explicitExclusions: [],
        deferred: [{ reason: "Review the synthetic pending task." }],
      },
    });
    await writeFile(f.resultPath, JSON.stringify(source));
    const original = await readFile(f.resultPath);
    const sources = await readDeepReductionSources(f.context);
    const discovery = sources.discoveries[0];
    const parsed = parsePersistedScanDraft(JSON.parse(original.toString()));
    assert.equal(parsed.coverage.surfaces[0].id, undefined);
    assert.equal(parsed.coverage.deferred[0].id, undefined);
    assert.equal(discovery.coverage.surfaces[0].provenance.sourceId, undefined);
    assert.equal(discovery.coverage.deferred[0].provenance.sourceId, undefined);
    assert.equal(
      discovery.coverage.surfaces[0].id,
      "synthetic-worker-attempt-3-surface-1",
    );
    assert.equal(
      discovery.coverage.deferred[0].id,
      "synthetic-worker-attempt-3-deferred-1",
    );
    assert.deepEqual(await readFile(f.resultPath), original);
  } finally {
    await rm(f.root, { recursive: true, force: true });
  }
});

test("generic Deep progress preserves parent review and provenance extensions", async () => {
  const root = await temporaryDirectory("parent-review-extensions-", true);
  try {
    const { context, draft } = draftFixture(root, "deep");
    const reviews = [
      { workerId: "synthetic-child", attempt: 1, completeness: "complete" },
    ];
    const provenance = {
      workerId: "synthetic-child",
      attempt: 1,
      candidateId: "candidate-1",
    };
    const surfaces = [
      {
        id: "parent-surface",
        candidateId: "candidate-1",
        label: "Parent review",
        disposition: "rejected",
        receiptRefs: [],
        provenance,
      },
    ];
    await recordCodexSecurityScanDraft(
      context,
      draft({ reviews, surfaces }, false),
    );
    const coverage = JSON.parse(
      await readFile(path.join(root, "coverage.json"), "utf8"),
    );
    assert.deepEqual(coverage.reviews, reviews);
    assert.deepEqual(coverage.surfaces, surfaces);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

for (const nestedKeyOrder of [false, true]) {
  test(`copied incomplete retries retain their first receipt and raw deferred origin, nested order=${nestedKeyOrder}`, async () => {
    const f = await fixture();
    try {
      const input = workerDraft([], {
        complete: false,
        coverage: {
          completeness: "partial",
          surfaces: [
            {
              id: "original-review",
              label: "Original review",
              disposition: "needs_follow_up",
              receiptRefs: ["artifacts/review.txt"],
            },
          ],
          explicitExclusions: [],
          deferred: [
            {
              reason: "Original pending proof.",
              provenance: { details: { a: 1, b: 2 } },
            },
          ],
        },
      });
      await mkdir(path.join(f.output, "artifacts"));
      await writeFile(
        path.join(f.output, "artifacts/review.txt"),
        "Synthetic original review.\n",
      );
      await writeFile(f.resultPath, JSON.stringify(input));
      const first = path.join(f.workerRoot, "attempts", "attempt-01");
      await cp(f.output, first, { recursive: true, preserveTimestamps: true });
      const second = path.join(f.workerRoot, "attempts", "attempt-02");
      await archiveDirectory(f.output, second);
      await mkdir(f.output, { recursive: true });
      if (nestedKeyOrder) {
        const final = {
          ...structuredClone(input),
          complete: true,
          coverage: {
            ...input.coverage,
            deferred: [
              {
                reason: "Original pending proof.",
                provenance: { details: { b: 2, a: 1 } },
              },
            ],
          },
        };
        await mkdir(path.join(f.output, "artifacts"));
        await writeFile(
          path.join(f.output, "artifacts/review.txt"),
          "Synthetic original review.\n",
        );
        await writeFile(f.resultPath, JSON.stringify(final));
        await validateDiscoveryArtifacts(
          { workersRoot: path.dirname(f.workerRoot) },
          f.resultPath,
          scanId,
        );
      } else {
        await recordCodexSecurityWorkerScanDraft(
          { root: f.output, repoRoot: f.root, scanId, layout: "worker" },
          workerDraft([], { complete: true }),
        );
      }
      const source = (await readDeepReductionSources(f.context)).discoveries[0]
        .coverage;
      for (const field of ["surfaces", "deferred"])
        assert.equal(source[field][0].provenance.attempt, 1);
      assert.ok(
        source.reviews.some((row: { attempt: number }) => row.attempt === 1),
      );
    } finally {
      await rm(f.root, { recursive: true, force: true });
    }
  });
}

test("a failed nonregular attempt preserves readable retry origin history", async () => {
  const f = await fixture();
  try {
    const original = workerDraft([], {
      complete: false,
      coverage: {
        completeness: "partial",
        surfaces: [
          {
            id: "original",
            label: "Retained review",
            disposition: "needs_follow_up",
            receiptRefs: [],
          },
        ],
        explicitExclusions: [],
        deferred: [
          {
            id: "original-gap",
            reason: "The first review still needs validation.",
          },
        ],
      },
    });
    await writeFile(f.resultPath, JSON.stringify(original));
    const first = path.join(f.workerRoot, "attempts", "attempt-01");
    await archiveDirectory(f.output, first);
    await mkdir(path.join(f.output, "result.json"), { recursive: true });
    await archiveDirectory(
      f.output,
      path.join(f.workerRoot, "attempts", "attempt-02"),
    );
    await mkdir(f.output, { recursive: true });
    await writeFile(
      f.resultPath,
      JSON.stringify({ ...original, complete: true }),
    );
    await validateDiscoveryArtifacts(
      { workersRoot: path.dirname(f.workerRoot) },
      f.resultPath,
      scanId,
    );
    const bytes = await readFile(path.join(first, "result.json"));
    await assert.rejects(
      readArchivedWorkerCheckpoints({
        root: f.output,
        repoRoot: f.root,
        scanId,
        layout: "worker",
      }),
      /archived result is not a safe file/,
    );
    const coverage = (await readDeepReductionSources(f.context)).discoveries[0]
      .coverage;
    assert.equal(coverage.surfaces[0].provenance.attempt, 1);
    assert.equal(coverage.deferred[0].provenance.attempt, 1);
    assert.ok(
      coverage.reviews.some(
        (review: { attempt: number }) => review.attempt === 1,
      ),
    );
    assert.deepEqual(await readFile(path.join(first, "result.json")), bytes);
  } finally {
    await rm(f.root, { recursive: true, force: true });
  }
});

for (const checkpointCollection of ["file", "linked", "readable"]) {
  test(`an unusable checkpoint collection preserves independent retry history: ${checkpointCollection}`, async () => {
    const f = await fixture();
    try {
      const original = workerDraft([], {
        complete: false,
        coverage: {
          completeness: "partial",
          surfaces: [
            {
              id: "review",
              label: "First accepted review",
              disposition: "needs_follow_up",
              receiptRefs: [],
            },
          ],
          explicitExclusions: [],
          deferred: [
            { id: "gap", reason: "The first review still needs proof." },
          ],
        },
      });
      await writeFile(f.resultPath, JSON.stringify(original));
      const first = path.join(f.workerRoot, "attempts", "attempt-01");
      await archiveDirectory(f.output, first);
      const second = path.join(f.workerRoot, "attempts", "attempt-02");
      await mkdir(second, { recursive: true });
      await writeFile(
        path.join(second, "result.json"),
        JSON.stringify(workerDraft([], { complete: false })),
      );
      if (checkpointCollection === "file") {
        await writeFile(
          path.join(second, "checkpoints"),
          "Unusable failed checkpoint collection.\n",
        );
      } else if (checkpointCollection === "linked") {
        const outside = path.join(f.root, "unrelated-checkpoints");
        await mkdir(outside);
        await writeFile(
          path.join(outside, "unrelated.json"),
          "{unrelated bytes}",
        );
        await symlink(
          outside,
          path.join(second, "checkpoints"),
          process.platform === "win32" ? "junction" : "dir",
        );
      } else {
        await mkdir(path.join(second, "checkpoints"));
      }
      await mkdir(f.output, { recursive: true });
      await writeFile(
        f.resultPath,
        JSON.stringify({ ...original, complete: true }),
      );
      await validateDiscoveryArtifacts(
        { workersRoot: path.dirname(f.workerRoot) },
        f.resultPath,
        scanId,
      );
      const oldBytes = await readFile(path.join(first, "result.json"));
      if (checkpointCollection !== "readable") {
        await assert.rejects(
          readArchivedWorkerCheckpoints({
            root: f.output,
            repoRoot: f.root,
            scanId,
            layout: "worker",
          }),
          /safe directory/,
        );
      }
      const coverage = (await readDeepReductionSources(f.context))
        .discoveries[0].coverage;
      assert.equal(coverage.surfaces[0].provenance.attempt, 1);
      assert.equal(coverage.deferred[0].provenance.attempt, 1);
      assert.ok(
        coverage.reviews.some(
          (review: { attempt: number }) => review.attempt === 1,
        ),
      );
      assert.deepEqual(
        await readFile(path.join(first, "result.json")),
        oldBytes,
      );
      if (checkpointCollection === "linked") {
        assert.equal(
          await readFile(
            path.join(f.root, "unrelated-checkpoints", "unrelated.json"),
            "utf8",
          ),
          "{unrelated bytes}",
        );
      }
    } finally {
      await rm(f.root, { recursive: true, force: true });
    }
  });
}

for (const changedReceipt of [false, true]) {
  test(`actual receipt bytes determine a retried surface origin: changed=${changedReceipt}`, async () => {
    const f = await fixture();
    try {
      const original = workerDraft([], {
        complete: false,
        coverage: {
          completeness: "partial",
          surfaces: [
            {
              id: "surface",
              label: "Same review metadata",
              disposition: "needs_follow_up",
              receiptRefs: ["artifacts/review.txt"],
            },
          ],
          explicitExclusions: [],
          deferred: [
            { id: "gap", reason: "The same review still needs proof." },
          ],
        },
      });
      await mkdir(path.join(f.output, "artifacts"));
      await writeFile(
        path.join(f.output, "artifacts/review.txt"),
        "Original synthetic review.\n",
      );
      await writeFile(f.resultPath, JSON.stringify(original));
      const archive = path.join(f.workerRoot, "attempts", "attempt-01");
      await archiveDirectory(f.output, archive);
      await mkdir(path.join(f.output, "artifacts"));
      const currentBytes = changedReceipt
        ? "Changed synthetic review.\n"
        : "Original synthetic review.\n";
      await writeFile(
        path.join(f.output, "artifacts/review.txt"),
        currentBytes,
      );
      await writeFile(
        f.resultPath,
        JSON.stringify({ ...original, complete: true }),
      );
      await validateDiscoveryArtifacts(
        { workersRoot: path.dirname(f.workerRoot) },
        f.resultPath,
        scanId,
      );
      const coverage = (await readDeepReductionSources(f.context))
        .discoveries[0].coverage;
      assert.equal(
        coverage.surfaces[0].provenance.attempt,
        changedReceipt ? 3 : 1,
      );
      assert.equal(coverage.deferred[0].provenance.attempt, 1);
      assert.equal(
        await readFile(path.join(f.output, "artifacts/review.txt"), "utf8"),
        currentBytes,
      );
      assert.equal(
        await readFile(path.join(archive, "artifacts/review.txt"), "utf8"),
        "Original synthetic review.\n",
      );
      assert.ok(
        coverage.reviews.some(
          (review: { attempt: number }) => review.attempt === 1,
        ),
      );
    } finally {
      await rm(f.root, { recursive: true, force: true });
    }
  });
}

for (const mode of ["idless", "explicit", "mixed"]) {
  for (const attempts of [2, 3]) {
    test(`legacy equal coverage rows keep occurrence origins, mode=${mode}, attempts=${attempts}`, async () => {
      const f = await fixture();
      try {
        f.context.deepReducer.claimedWorkers[0].attempt = attempts;
        const archivedBytes: { path: string; bytes: Buffer }[] = [];
        for (let attempt = 1; attempt <= attempts; attempt++) {
          await mkdir(f.output, { recursive: true });
          const surface = {
            label: "Synthetic repeated legacy observation",
            disposition: "needs_follow_up",
            receiptRefs: [],
          };
          const surfaces = Array.from({ length: attempt }, (_, index) => ({
            ...surface,
            ...(mode === "explicit" || (mode === "mixed" && index > 0)
              ? { id: `legacy-${index + 1}` }
              : {}),
          }));
          // Persisted older worker outputs retain optional IDs and row order.
          await writeFile(
            f.resultPath,
            JSON.stringify(
              workerDraft([], {
                complete: true,
                coverage: {
                  completeness: "partial",
                  surfaces,
                  explicitExclusions: [],
                  deferred: [],
                },
              }),
            ),
          );
          if (attempt < attempts) {
            const bytes = await readFile(f.resultPath);
            const archive = path.join(
              f.workerRoot,
              "attempts",
              `attempt-0${attempt}`,
            );
            await archiveDirectory(f.output, archive);
            archivedBytes.push({
              path: path.join(archive, "result.json"),
              bytes,
            });
          }
        }
        const original = await readFile(f.resultPath);
        await validateDiscoveryArtifacts(
          { workersRoot: path.dirname(f.workerRoot) },
          f.resultPath,
          scanId,
        );
        const coverage = (await readDeepReductionSources(f.context))
          .discoveries[0].coverage;
        assert.deepEqual(
          coverage.surfaces.map(
            (row: { provenance: { attempt: number } }) =>
              row.provenance.attempt,
          ),
          Array.from({ length: attempts }, (_, index) => index + 1),
        );
        assert.equal(
          new Set(coverage.surfaces.map((row: { id: string }) => row.id)).size,
          attempts,
        );
        assert.deepEqual(await readFile(f.resultPath), original);
        for (const archived of archivedBytes)
          assert.deepEqual(await readFile(archived.path), archived.bytes);
      } finally {
        await rm(f.root, { recursive: true, force: true });
      }
    });
  }
}

for (const receiptPath of [
  "artifacts/review.txt",
  "artifacts/./review.txt",
  "artifacts//review.txt",
]) {
  for (const evidence of ["same", "changed", "none"] as const) {
    for (const explicitId of [false, true]) {
      test(`retry resubmitted surface keeps receipt-backed identity: evidence=${evidence}, explicit=${explicitId}`, async () => {
        const f = await fixture();
        try {
          f.context.deepReducer.claimedWorkers[0].attempt = 2;
          const surface = {
            ...(explicitId ? { id: "authored-review" } : {}),
            label: "Retained review",
            disposition: "needs_follow_up",
            receiptRefs: evidence === "none" ? [] : [receiptPath],
          };
          const inherited = workerDraft([], {
            complete: false,
            coverage: {
              completeness: "partial",
              surfaces: [surface],
              explicitExclusions: [],
              deferred: [
                {
                  id: "pending-review",
                  reason: "Retained validation remains unresolved.",
                },
              ],
            },
          });
          if (evidence !== "none") {
            await mkdir(path.join(f.output, "artifacts"), { recursive: true });
            await writeFile(
              path.join(f.output, "artifacts/review.txt"),
              "Original synthetic review.\n",
            );
          }
          await writeFile(f.resultPath, JSON.stringify(inherited));
          const archive = path.join(f.workerRoot, "attempts", "attempt-01");
          await archiveDirectory(f.output, archive);
          const archiveResult = path.join(archive, "result.json");
          const before = await readFile(archiveResult);
          await mkdir(f.output, { recursive: true });
          if (evidence !== "none") {
            await mkdir(path.join(f.output, "artifacts"), { recursive: true });
            await writeFile(
              path.join(f.output, "artifacts/review.txt"),
              evidence === "changed"
                ? "New independent review.\n"
                : "Original synthetic review.\n",
            );
          }
          await recordCodexSecurityWorkerScanDraft(
            { root: f.output, repoRoot: f.root, scanId, layout: "worker" },
            { ...inherited, complete: true },
          );
          const source = (await readDeepReductionSources(f.context))
            .discoveries[0].coverage;
          if (evidence !== "changed") {
            assert.equal(
              source.surfaces.length,
              1,
              JSON.stringify(source.surfaces),
            );
            assert.equal(source.surfaces[0].provenance.attempt, 1);
          } else {
            assert.equal(source.surfaces.length, explicitId ? 1 : 2);
            assert.ok(
              source.surfaces.some(
                (row: { provenance: { attempt: number } }) =>
                  row.provenance.attempt === 2,
              ),
            );
          }
          assert.deepEqual(await readFile(archiveResult), before);
          for (const row of source.surfaces)
            for (const ref of row.receiptRefs)
              assert.equal(
                await readFile(
                  path.join(f.context.deepReducer.scanRoot, ref),
                  "utf8",
                ),
                ref.includes("/attempts/")
                  ? "Original synthetic review.\n"
                  : evidence === "changed"
                    ? "New independent review.\n"
                    : "Original synthetic review.\n",
              );
        } finally {
          await rm(f.root, { recursive: true, force: true });
        }
      });
    }
  }
}

for (const malformed of ["none", "json", "schema", "head-json"]) {
  for (const complete of [false, true]) {
    test(
      "retry checkpoint retains a valid submission before archived " +
        malformed +
        ", complete=" +
        complete,
      async () => {
        const f = await fixture();
        try {
          const archive = path.join(f.workerRoot, "attempts", "attempt-01");
          await mkdir(path.join(archive, "checkpoints"), { recursive: true });
          const broken =
            malformed === "head-json"
              ? path.join(archive, "checkpoint-head.json")
              : path.join(archive, "checkpoints", "a".repeat(64) + ".json");
          const bytes = malformed === "schema" ? "{}\n" : "{broken\n";
          if (malformed !== "none") await writeFile(broken, bytes);
          const context = {
            root: f.output,
            repoRoot: f.root,
            scanId,
            layout: "worker",
          };
          const input = workerDraft(
            [finding("retained-submission", "src/example.ts")],
            {
              complete,
              coverage: {
                completeness: "partial",
                surfaces: [
                  {
                    id: "new-review",
                    label: "New review",
                    disposition: "needs_follow_up",
                    receiptRefs: [],
                  },
                ],
                explicitExclusions: [],
                deferred: [
                  { id: "new-task", reason: "New proof remains pending." },
                ],
              },
            },
          );
          const expected = parseScanDraft(input);
          if (malformed === "none")
            await recordCodexSecurityWorkerScanDraft(context, input);
          else {
            await assert.rejects(
              recordCodexSecurityWorkerScanDraft(context, input),
            );
            assert.equal(await readFile(broken, "utf8"), bytes);
          }
          const checkpoints = path.join(f.output, "checkpoints");
          const names = await readdir(checkpoints);
          assert.equal(names.length, 1);
          assert.deepEqual(
            JSON.parse(
              await readFile(path.join(checkpoints, names[0]), "utf8"),
            ),
            expected,
          );
          if (malformed !== "none") await rm(broken);
          await recordCodexSecurityWorkerScanDraft(
            context,
            workerDraft([], { complete: true }),
          );
          const result = JSON.parse(await readFile(f.resultPath, "utf8"));
          assert.deepEqual(result.findings, expected.findings);
          assert.deepEqual(
            result.coverage.deferred,
            expected.coverage.deferred,
          );
        } finally {
          await rm(f.root, { recursive: true, force: true });
        }
      },
    );
  }
}

for (const availableReceipt of [false, true]) {
  for (const explicitId of [false, true]) {
    test(`omitted archived surface retains known origin: receipt=${availableReceipt}, explicit=${explicitId}`, async () => {
      const f = await fixture();
      try {
        f.context.deepReducer.claimedWorkers[0].attempt = 2;
        const context = {
          root: f.output,
          repoRoot: f.root,
          scanId,
          layout: "worker",
        };
        if (availableReceipt) {
          await mkdir(path.join(f.output, "artifacts"), { recursive: true });
          await writeFile(
            path.join(f.output, "artifacts/review.txt"),
            "Original synthetic review.\n",
          );
        }
        await recordCodexSecurityWorkerScanDraft(
          context,
          workerDraft([], {
            complete: false,
            coverage: {
              completeness: "partial",
              surfaces: [
                {
                  ...(explicitId ? { id: "first-review" } : {}),
                  label: "Retained archived review",
                  disposition: "needs_follow_up",
                  receiptRefs: ["artifacts/review.txt"],
                },
              ],
              explicitExclusions: [],
              deferred: [
                {
                  id: "first-task",
                  reason: "The original review remains pending.",
                },
              ],
            },
          }),
        );
        const first = JSON.parse(await readFile(f.resultPath, "utf8"));
        const archive = path.join(f.workerRoot, "attempts", "attempt-01");
        await archiveDirectory(f.output, archive);
        const archivedBytes = await readFile(path.join(archive, "result.json"));
        await mkdir(f.output, { recursive: true });
        await recordCodexSecurityWorkerScanDraft(
          context,
          workerDraft([], { complete: true }),
        );
        const currentBytes = await readFile(f.resultPath);
        const coverage = (await readDeepReductionSources(f.context))
          .discoveries[0].coverage;
        assert.equal(coverage.surfaces.length, 1);
        assert.equal(coverage.surfaces[0].provenance.attempt, 1);
        assert.equal(
          coverage.surfaces[0].provenance.sourceId,
          first.coverage.surfaces[0].id,
        );
        assert.equal(coverage.deferred[0].provenance.attempt, 1);
        assert.ok(
          coverage.reviews.some(
            (review: { attempt: number }) => review.attempt === 1,
          ),
        );
        assert.deepEqual(coverage.surfaces[0].receiptRefs, [
          "artifacts/deep_discovery/workers/discovery-0001/attempts/attempt-01/artifacts/review.txt",
        ]);
        assert.deepEqual(
          await readFile(path.join(archive, "result.json")),
          archivedBytes,
        );
        assert.deepEqual(await readFile(f.resultPath), currentBytes);
      } finally {
        await rm(f.root, { recursive: true, force: true });
      }
    });
  }
}

test("different unreadable receipt cannot establish an earlier surface origin", async () => {
  const f = await fixture();
  try {
    f.context.deepReducer.claimedWorkers[0].attempt = 2;
    const context = {
      root: f.output,
      repoRoot: f.root,
      scanId,
      layout: "worker",
    };
    const input = workerDraft([], {
      complete: false,
      coverage: {
        completeness: "partial",
        surfaces: [
          {
            label: "Independent unproven review",
            disposition: "needs_follow_up",
            receiptRefs: ["artifacts/review.txt"],
          },
        ],
        explicitExclusions: [],
        deferred: [],
      },
    });
    await recordCodexSecurityWorkerScanDraft(context, input);
    const archive = path.join(f.workerRoot, "attempts", "attempt-01");
    await archiveDirectory(f.output, archive);
    const archivedBytes = await readFile(path.join(archive, "result.json"));
    await mkdir(f.output, { recursive: true });
    await recordCodexSecurityWorkerScanDraft(context, {
      ...input,
      complete: true,
    });
    const coverage = (await readDeepReductionSources(f.context)).discoveries[0]
      .coverage;
    assert.ok(
      coverage.surfaces.some(
        (row: { provenance: { attempt: number } }) =>
          row.provenance.attempt === 2,
      ),
    );
    assert.deepEqual(
      await readFile(path.join(archive, "result.json")),
      archivedBytes,
    );
  } finally {
    await rm(f.root, { recursive: true, force: true });
  }
});

for (const mode of ["explicit", "normalized"]) {
  for (const interrupted of [false, true]) {
    test(`selected current checkpoint retains original IDs ${mode} interrupted=${interrupted}`, async (t) => {
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
          workerDraft([], { complete: true }),
        );
        await archiveDirectory(
          f.output,
          path.join(f.workerRoot, "attempts", "attempt-01"),
        );
        await recordCodexSecurityWorkerScanDraft(
          worker,
          workerDraft([], { complete: true }),
        );
        const prior = await readFile(f.resultPath);
        const submitted = workerDraft([], {
          complete: true,
          coverage: {
            completeness: "partial",
            surfaces: [
              {
                ...(mode === "explicit" ? { id: "current-review" } : {}),
                label: "Synthetic current-checkpoint evidence",
                disposition: "needs_follow_up",
                receiptRefs: [],
              },
            ],
            explicitExclusions: [],
            deferred: [
              {
                ...(mode === "explicit"
                  ? { id: "current-gap", surfaceIds: ["current-review"] }
                  : {}),
                reason: "Review this synthetic current-checkpoint proof.",
              },
            ],
          },
        });
        if (interrupted) {
          const rename = fs.rename;
          t.mock.method(
            fs,
            "rename",
            async (...args: Parameters<typeof rename>) => {
              if (args[1] === f.resultPath)
                throw Object.assign(
                  new Error("Synthetic result publication interruption."),
                  { code: "EIO" },
                );
              return rename(...args);
            },
          );
          await assert.rejects(
            recordCodexSecurityWorkerScanDraft(worker, submitted),
            /Synthetic result publication interruption/,
          );
          t.mock.restoreAll();
          assert.deepEqual(await readFile(f.resultPath), prior);
        } else await recordCodexSecurityWorkerScanDraft(worker, submitted);
        const head = JSON.parse(
          await readFile(path.join(f.output, "checkpoint-head.json"), "utf8"),
        );
        const checkpointPath = path.join(
          f.output,
          "checkpoints",
          head.checkpoint,
        );
        const acceptedBytes = await readFile(checkpointPath);
        const accepted = JSON.parse(acceptedBytes.toString());
        assert.equal(accepted.complete, true);
        const coverage = (await readDeepReductionSources(f.context))
          .discoveries[0].coverage;
        assert.equal(coverage.surfaces.length, 1);
        assert.equal(coverage.deferred.length, 1);
        assert.equal(
          coverage.surfaces[0].provenance.sourceId,
          accepted.coverage.surfaces[0].id,
        );
        assert.equal(
          coverage.deferred[0].provenance.sourceId,
          accepted.coverage.deferred[0].id,
        );
        assert.equal(coverage.surfaces[0].provenance.attempt, 3);
        assert.equal(coverage.deferred[0].provenance.attempt, 3);
        assert.deepEqual(await readFile(checkpointPath), acceptedBytes);
        if (interrupted) assert.deepEqual(await readFile(f.resultPath), prior);
      } finally {
        t.mock.restoreAll();
        await rm(f.root, { recursive: true, force: true });
      }
    });
  }
}

for (const field of [
  "deferred",
  "explicitExclusions",
  "openQuestions",
] as const) {
  for (const scenario of [
    "one archive",
    "repeated archives",
    "changed",
    "fresh",
  ]) {
    test(`retry consumes each historical ${field} occurrence: ${scenario}`, async () => {
      const f = await fixture();
      try {
        const worker = {
          root: f.output,
          repoRoot: f.root,
          scanId,
          layout: "worker",
        };
        const text = "Synthetic review occurrence.";
        const row = (value: string) =>
          field === "openQuestions"
            ? { question: value }
            : field === "explicitExclusions"
              ? { pattern: "synthetic-excluded/**", reason: value }
              : { reason: value };
        const draft = (rows: ReturnType<typeof row>[], complete: boolean) =>
          workerDraft([], {
            complete,
            coverage: {
              completeness: "partial",
              surfaces: [],
              explicitExclusions: [],
              deferred: [],
              [field]: rows,
            },
          });
        const archiveCount =
          scenario === "fresh" ? 0 : scenario === "repeated archives" ? 2 : 1;
        const archives = new Map<string, Buffer>();
        for (let attempt = 1; attempt <= archiveCount; attempt++) {
          await mkdir(f.output, { recursive: true });
          // Accepted legacy direct-file results may omit the worker-local ID.
          const original = draft([row(text)], false);
          parsePersistedScanDraft(original);
          await writeFile(f.resultPath, JSON.stringify(original));
          const archive = path.join(
            f.workerRoot,
            "attempts",
            `attempt-0${attempt}`,
          );
          await archiveDirectory(f.output, archive);
          const result = path.join(archive, "result.json");
          archives.set(result, await readFile(result));
        }
        await mkdir(f.output, { recursive: true });
        const currentText =
          scenario === "changed" ? "Different current review." : text;
        await recordCodexSecurityWorkerScanDraft(
          worker,
          draft([row(currentText), row(currentText)], true),
        );
        const history = await readArchivedWorkerCheckpoints(worker);
        assert.equal(history.length, archiveCount);
        for (const source of history) {
          assert.equal(source.input.coverage[field].length, 1);
          assert.equal(source.input.coverage[field][0].id, undefined);
        }
        const current = await readFile(f.resultPath);
        await validateDiscoveryArtifacts(
          { workersRoot: path.dirname(f.workerRoot) },
          f.resultPath,
          scanId,
        );
        const coverage = (await readDeepReductionSources(f.context))
          .discoveries[0].coverage;
        const observed = coverage[field].filter(
          (item: { question?: string; reason?: string }) =>
            (field === "openQuestions" ? item.question : item.reason) ===
            currentText,
        );
        assert.equal(observed.length, 2);
        assert.deepEqual(
          observed.map(
            (item: { provenance: { attempt: number } }) =>
              item.provenance.attempt,
          ),
          archiveCount && scenario !== "changed" ? [1, 3] : [3, 3],
        );
        if (field === "deferred")
          assert.equal(
            new Set(observed.map((item: { id: string }) => item.id)).size,
            2,
          );
        assert.deepEqual(await readFile(f.resultPath), current);
        for (const [result, bytes] of archives)
          assert.deepEqual(await readFile(result), bytes);
      } finally {
        await rm(f.root, { recursive: true, force: true });
      }
    });
  }
}

for (const changed of [false, true]) {
  test(`mixed unreadable and copied receipts retain only proven origin: changed=${changed}`, async () => {
    const f = await fixture();
    try {
      f.context.deepReducer.claimedWorkers[0].attempt = 2;
      const worker = {
        root: f.output,
        repoRoot: f.root,
        scanId,
        layout: "worker",
      };
      const surface = {
        id: "mixed-receipts",
        label: "Synthetic mixed receipt evidence",
        disposition: "needs_follow_up",
        receiptRefs: ["artifacts/unreadable.txt", "artifacts/readable.txt"],
      };
      await mkdir(path.join(f.output, "artifacts"), { recursive: true });
      await writeFile(
        path.join(f.output, "artifacts/readable.txt"),
        "Accepted evidence.\n",
      );
      await writeFile(
        path.join(f.output, "artifacts/unreadable.txt"),
        "Accepted earlier evidence.\n",
      );
      await recordCodexSecurityWorkerScanDraft(
        worker,
        workerDraft([], {
          complete: false,
          coverage: {
            completeness: "partial",
            surfaces: [surface],
            explicitExclusions: [],
            deferred: [],
          },
        }),
      );
      const archive = path.join(f.workerRoot, "attempts/attempt-01");
      await archiveDirectory(f.output, archive);
      const accepted = await readFile(path.join(archive, "result.json"));
      await rm(path.join(archive, "artifacts/unreadable.txt"));
      await mkdir(path.join(f.output, "artifacts"), { recursive: true });
      const history = await readArchivedWorkerCheckpoints(worker);
      const missing = history[0].input.coverage.surfaces[0].receiptRefs.find(
        (ref: string) => ref.endsWith("/unreadable.txt"),
      );
      assert.equal(typeof missing, "string");
      await writeFile(
        path.join(f.output, "artifacts/readable.txt"),
        changed ? "Different current evidence.\n" : "Accepted evidence.\n",
      );
      await recordCodexSecurityWorkerScanDraft(
        worker,
        workerDraft([], {
          complete: true,
          coverage: {
            completeness: "partial",
            surfaces: [
              { ...surface, receiptRefs: [missing, "artifacts/readable.txt"] },
            ],
            explicitExclusions: [],
            deferred: [],
          },
        }),
      );
      const current = await readFile(f.resultPath);
      const coverage = (await readDeepReductionSources(f.context))
        .discoveries[0].coverage;
      assert.equal(coverage.surfaces.length, 1);
      assert.equal(coverage.surfaces[0].provenance.attempt, changed ? 2 : 1);
      assert.deepEqual(
        await readFile(path.join(archive, "result.json")),
        accepted,
      );
      assert.deepEqual(await readFile(f.resultPath), current);
    } finally {
      await rm(f.root, { recursive: true, force: true });
    }
  });
}

for (const interrupted of [false, true]) {
  for (const changed of [false, true]) {
    test(`current checkpoint receipt preserves retry origin interrupted=${interrupted} changed=${changed}`, async (t) => {
      const f = await fixture();
      try {
        f.context.deepReducer.claimedWorkers[0].attempt = 2;
        const worker = {
          root: f.output,
          repoRoot: f.root,
          scanId,
          layout: "worker",
        };
        const surface = {
          id: "accepted-review",
          label: "Synthetic retained checkpoint evidence",
          disposition: "needs_follow_up",
          receiptRefs: ["artifacts/review.txt"],
        };
        const draft = workerDraft([], {
          complete: true,
          coverage: {
            completeness: "partial",
            surfaces: [surface],
            explicitExclusions: [],
            deferred: [],
          },
        });
        await mkdir(path.join(f.output, "artifacts"), { recursive: true });
        await writeFile(
          path.join(f.output, "artifacts/review.txt"),
          "Accepted evidence.\n",
        );
        await recordCodexSecurityWorkerScanDraft(worker, draft);
        const archive = path.join(f.workerRoot, "attempts/attempt-01");
        await archiveDirectory(f.output, archive);
        const archivedBytes = await readFile(path.join(archive, "result.json"));
        await mkdir(path.join(f.output, "artifacts"), { recursive: true });
        await writeFile(
          path.join(f.output, "artifacts/review.txt"),
          changed ? "Different evidence.\n" : "Accepted evidence.\n",
        );
        // A direct-file retry result may lag the accepted current checkpoint.
        await writeFile(
          f.resultPath,
          JSON.stringify(workerDraft([], { complete: true })),
        );
        const prior = await readFile(f.resultPath);
        if (interrupted) {
          const rename = fs.rename;
          t.mock.method(
            fs,
            "rename",
            async (...args: Parameters<typeof rename>) => {
              if (args[1] === f.resultPath)
                throw Object.assign(
                  new Error("Synthetic result publication interruption."),
                  { code: "EIO" },
                );
              return rename(...args);
            },
          );
          await assert.rejects(
            recordCodexSecurityWorkerScanDraft(worker, draft),
            /Synthetic result publication interruption/,
          );
          t.mock.restoreAll();
          assert.deepEqual(await readFile(f.resultPath), prior);
        } else await recordCodexSecurityWorkerScanDraft(worker, draft);
        const head = JSON.parse(
          await readFile(path.join(f.output, "checkpoint-head.json"), "utf8"),
        );
        const checkpoint = path.join(f.output, "checkpoints", head.checkpoint);
        const acceptedBytes = await readFile(checkpoint);
        const currentBytes = await readFile(f.resultPath);
        const coverage = (await readDeepReductionSources(f.context))
          .discoveries[0].coverage;
        assert.equal(coverage.surfaces.length, 1);
        assert.equal(coverage.surfaces[0].provenance.attempt, changed ? 2 : 1);
        assert.deepEqual(
          await readFile(path.join(archive, "result.json")),
          archivedBytes,
        );
        assert.deepEqual(await readFile(checkpoint), acceptedBytes);
        assert.deepEqual(await readFile(f.resultPath), currentBytes);
      } finally {
        t.mock.restoreAll();
        await rm(f.root, { recursive: true, force: true });
      }
    });
  }
}

for (const headState of [
  "readable",
  "unreadable",
  "missing",
  "unsafe",
  "unreadable-checkpoint",
]) {
  test(`accepted retry retains readable coverage with current head ${headState}`, async (t) => {
    const f = await fixture();
    try {
      const worker = {
        root: f.output,
        repoRoot: f.root,
        scanId,
        layout: "worker",
      };
      const archive = path.join(f.workerRoot, "attempts", "attempt-01");
      for (const attempt of [1, 2]) {
        await recordCodexSecurityWorkerScanDraft(
          worker,
          workerDraft([], {
            complete: false,
            coverage: {
              completeness: "partial",
              surfaces: [],
              explicitExclusions: [],
              deferred: [
                {
                  id: `task-${attempt}`,
                  reason: `Synthetic proof ${attempt}.`,
                },
              ],
            },
          }),
        );
        if (attempt === 1) await archiveDirectory(f.output, archive);
      }
      const head = path.join(f.output, "checkpoint-head.json");
      const headBefore = await readFile(head);
      assert.ok((await fs.lstat(head)).isFile());
      const current = workerDraft([], { complete: true });
      await writeFile(f.resultPath, JSON.stringify(current));
      await validateDiscoveryArtifacts(
        { workersRoot: path.dirname(f.workerRoot) },
        f.resultPath,
        scanId,
      );
      const resultBefore = await readFile(f.resultPath);
      const archiveBefore = await readFile(path.join(archive, "result.json"));
      const checkpoints = await readdir(path.join(f.output, "checkpoints"));
      const checkpointBytes = await Promise.all(
        checkpoints.map((name) =>
          readFile(path.join(f.output, "checkpoints", name)),
        ),
      );
      if (headState === "missing" || headState === "unsafe") {
        await rm(head);
        if (headState === "unsafe") await mkdir(head);
      }
      if (headState === "unreadable") {
        const open = fs.open;
        t.mock.method(fs, "open", async (...args: Parameters<typeof open>) => {
          if (args[0] === head && args[1] === "r") {
            throw Object.assign(
              new Error("Synthetic current-head read failure."),
              { code: "EIO" },
            );
          }
          return open(...args);
        });
      }
      if (headState === "unreadable-checkpoint") {
        const checkpoint = path.join(
          f.output,
          "checkpoints",
          JSON.parse(headBefore.toString()).checkpoint,
        );
        const read = fs.readFile;
        t.mock.method(
          fs,
          "readFile",
          async (...args: Parameters<typeof read>) => {
            if (args[0] === checkpoint)
              throw Object.assign(
                new Error("Synthetic current-checkpoint read failure."),
                {
                  code: "EIO",
                },
              );
            return read(...args);
          },
        );
      }
      if (headState === "unsafe") {
        await assert.rejects(
          readDeepReductionSources(f.context),
          /current checkpoint head is not a safe file/,
        );
        assert.ok((await fs.lstat(head)).isDirectory());
      } else {
        const coverage = (await readDeepReductionSources(f.context))
          .discoveries[0].coverage;
        assert.deepEqual(
          new Set(
            coverage.deferred.map(
              (row: { provenance: { sourceId: string } }) =>
                row.provenance.sourceId,
            ),
          ),
          new Set(["task-1", "task-2"]),
        );
        if (headState !== "missing")
          assert.deepEqual(await readFile(head), headBefore);
      }
      assert.deepEqual(await readFile(f.resultPath), resultBefore);
      assert.deepEqual(
        await readFile(path.join(archive, "result.json")),
        archiveBefore,
      );
      assert.deepEqual(
        await readdir(path.join(f.output, "checkpoints")),
        checkpoints,
      );
      assert.deepEqual(
        await Promise.all(
          checkpoints.map((name) =>
            readFile(path.join(f.output, "checkpoints", name)),
          ),
        ),
        checkpointBytes,
      );
      if (headState === "unreadable" || headState === "unreadable-checkpoint") {
        await assert.rejects(
          recordCodexSecurityWorkerScanDraft(worker, current),
          /cannot be read/,
        );
        assert.deepEqual(await readFile(f.resultPath), resultBefore);
      }
    } finally {
      t.mock.restoreAll();
      await rm(f.root, { recursive: true, force: true });
    }
  });
}

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

for (const legacy of [false, true]) {
  for (const copied of [false, true]) {
    for (const interrupted of [false, true]) {
      test(`checkpoint-only receipt origin legacy=${legacy} copied=${copied} interrupted=${interrupted}`, async (t) => {
        const f = await fixture();
        const worker = {
          root: f.output,
          repoRoot: f.root,
          scanId,
          layout: "worker",
        };
        const row = {
          ...(legacy ? {} : { id: "retained-review" }),
          label: "Synthetic copied evidence",
          disposition: "needs_follow_up",
          receiptRefs: ["artifacts/review.txt"],
        };
        const draft = (surfaces: unknown[]) =>
          workerDraft([], {
            complete: true,
            coverage: {
              completeness: "partial",
              surfaces,
              explicitExclusions: [],
              deferred: [],
            },
          });
        try {
          await mkdir(path.join(f.output, "artifacts"), { recursive: true });
          await writeFile(
            path.join(f.output, "artifacts/review.txt"),
            "Synthetic original evidence.\n",
          );
          if (legacy) {
            // Older accepted worker results retain surfaces without generated IDs.
            await writeFile(f.resultPath, JSON.stringify(draft([row])));
          } else await recordCodexSecurityWorkerScanDraft(worker, draft([row]));
          const archive = path.join(f.workerRoot, "attempts", "attempt-01");
          await archiveDirectory(f.output, archive);
          const archived = await readFile(path.join(archive, "result.json"));
          await recordCodexSecurityWorkerScanDraft(worker, draft([]));
          const inherited = JSON.parse(await readFile(f.resultPath, "utf8"));
          assert.equal(inherited.coverage.surfaces.length, 1);
          const changed = {
            ...inherited.coverage.surfaces[0],
            label: "Synthetic accepted updated observation",
            receiptRefs: ["artifacts/accepted.txt"],
          };
          await mkdir(path.join(f.output, "artifacts"), { recursive: true });
          await writeFile(
            path.join(f.output, "artifacts/accepted.txt"),
            "Synthetic separate accepted evidence.\n",
          );
          await recordCodexSecurityWorkerScanDraft(worker, draft([changed]));
          const before = await readFile(f.resultPath);
          const checkpointOnly = { ...row, id: "checkpoint-only-review" };
          await writeFile(
            path.join(f.output, "artifacts/review.txt"),
            copied
              ? "Synthetic original evidence.\n"
              : "Synthetic changed evidence.\n",
          );
          if (interrupted) {
            const rename = fs.rename;
            t.mock.method(
              fs,
              "rename",
              async (...args: Parameters<typeof rename>) => {
                if (args[1] === f.resultPath)
                  throw Object.assign(
                    new Error("Synthetic result-only rename interruption."),
                    { code: "EIO" },
                  );
                return rename(...args);
              },
            );
            await assert.rejects(
              recordCodexSecurityWorkerScanDraft(
                worker,
                draft([changed, checkpointOnly]),
              ),
              /Synthetic result-only rename interruption/,
            );
            t.mock.restoreAll();
          } else
            await recordCodexSecurityWorkerScanDraft(
              worker,
              draft([changed, checkpointOnly]),
            );
          const head = JSON.parse(
            await readFile(path.join(f.output, "checkpoint-head.json"), "utf8"),
          );
          const checkpoint = path.join(
            f.output,
            "checkpoints",
            head.checkpoint,
          );
          const accepted = await readFile(checkpoint);
          const coverage = (await readDeepReductionSources(f.context))
            .discoveries[0].coverage;
          const current = coverage.surfaces.filter(
            (surface: { label: string; receiptRefs: string[] }) =>
              surface.label === row.label &&
              surface.receiptRefs.includes(
                "artifacts/deep_discovery/workers/discovery-0001/output/artifacts/review.txt",
              ),
          );
          assert.equal(current.length, 1);
          assert.equal(current[0].provenance.attempt, legacy && copied ? 1 : 3);
          assert.deepEqual(
            await readFile(path.join(archive, "result.json")),
            archived,
          );
          assert.deepEqual(await readFile(checkpoint), accepted);
          if (interrupted)
            assert.deepEqual(await readFile(f.resultPath), before);
        } finally {
          t.mock.restoreAll();
          await rm(f.root, { recursive: true, force: true });
        }
      });
    }
  }
}
