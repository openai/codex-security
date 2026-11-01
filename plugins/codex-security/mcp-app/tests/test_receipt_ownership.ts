import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  utimes,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { readJson, writeJson } from "./support/json.ts";
import { importSource } from "./import-module.ts";
import {
  claimDedupInputs,
  FakeExecutor,
  FakeStore,
  fixtureRun,
  runCoordinator,
} from "./deep_scan_coordinator_fixture.ts";
import { finding, scanId, workerDraft } from "./scan-draft-fixture.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

const { readDeepReductionSources } = await importSource(
  path.join(import.meta.dirname, "../src/artifact-deep-reducer.ts"),
);
const { recordCodexSecurityWorkerScanDraft, saveScanDraftCheckpoint } =
  await importSource(
    path.join(import.meta.dirname, "../src/artifact-scan-draft.ts"),
  );

const { archiveDirectory } = await importSource(
  path.join(import.meta.dirname, "../src/deep-scan/artifacts.ts"),
);

async function fixture() {
  const root = await temporaryDirectory("receipt-ownership-", true);
  const prefix = "artifacts/deep_discovery/workers/discovery-0001/output";
  const workerRoot = path.join(root, prefix);
  const reducerRoot = path.join(
    root,
    "artifacts/deep_discovery/dedup/run/output",
  );
  await mkdir(workerRoot, { recursive: true });
  await mkdir(reducerRoot, { recursive: true });
  const worker = { root: workerRoot, repoRoot: root, scanId, layout: "worker" };
  const reducer = {
    root: reducerRoot,
    repoRoot: root,
    scanId,
    layout: "reducer",
    deepReducer: {
      scanRoot: root,
      claimedWorkers: [
        { id: "worker-1", resultPath: path.join(workerRoot, "result.json") },
      ],
    },
  };
  return {
    root,
    prefix,
    workerRoot,
    worker,
    resultPath: path.join(workerRoot, "result.json"),
    recordDraft: (input: unknown) =>
      recordCodexSecurityWorkerScanDraft(worker, input),
    async coverage(includePaths?: string[]) {
      const sources = await readDeepReductionSources(
        includePaths ? { ...reducer, includePaths } : reducer,
      );
      return sources.discoveries[0].coverage;
    },
  };
}

function receiptTest(
  name: string,
  run: (f: Awaited<ReturnType<typeof fixture>>) => Promise<void>,
) {
  test(name, async () => {
    const f = await fixture();
    try {
      await run(f);
    } finally {
      await rm(f.root, { recursive: true, force: true });
    }
  });
}

function legacyReceiptFixture() {
  return readJson(
    import.meta.dirname,
    "fixtures",
    "legacy-scoped-worker-receipts.json",
  );
}

function draft(receiptRefs: string[], extra = {}) {
  return workerDraft([], {
    reviewState: {
      ...workerDraft([]).reviewState,
      surfaces: [
        {
          id: "reviewed-route",
          label: "Reviewed route",
          disposition: "no_issue_found",
          receiptRefs,
          ...extra,
        },
      ],
    },
  });
}

async function receipt(root: string, ref: string, contents: string) {
  await mkdir(path.dirname(path.join(root, ref)), { recursive: true });
  await writeFile(path.join(root, ref), contents);
}

function recoverCoverage(
  f: Awaited<ReturnType<typeof fixture>>,
  complete = true,
  attempt = 1,
  includePaths = ["."],
  publishDuringCapture = false,
  explicitRecovery = false,
) {
  return JSON.parse(
    execFileSync(
      process.env.PYTHON || "python3",
      [
        "-B",
        "-c",
        `
import json, sys
from types import SimpleNamespace
from pathlib import Path
plugin, root, active = map(Path, sys.argv[1:4])
scan_id, complete = sys.argv[4], sys.argv[5] == "true"
sys.path[:0] = [str(plugin / "scripts"), str(plugin / "tests")]
import workbench_saved_results as saved
import workbench.retained_coverage as retained
from workbench_saved_results import merge_saved_results
from workbench_test_support import saved_binding, saved_discovery_worker
from finalize_scan_contract import _recover_unsealed_coverage
worker = {**saved_discovery_worker(active, "worker-1", int(sys.argv[6])), "status": "succeeded" if complete else "running", "result_manifest_path": str(active / "result.json") if complete else None}
binding = saved_binding("deep_repository")
binding["target"].update(targetId="synthetic", displayName="Synthetic repository")
binding["scope"]["includePaths"] = json.loads(sys.argv[7])
args = (root, scan_id, binding, [worker], [])
original_capture = saved._capture_saved_source
original_retained_capture = retained._capture_saved_source
published = []
def capture(*args, **kwargs):
    captured = original_capture(*args, **kwargs)
    if sys.argv[8] == "true" and args[1].endswith("output/checkpoint-head.json") and not published:
        staged = root / "publication"
        for checkpoint in (staged / "checkpoints").iterdir():
            destination = active / "checkpoints" / checkpoint.name
            checkpoint.replace(destination)
            published.append(destination.relative_to(root).as_posix())
        for name in ("checkpoint-head.json", "result.json"):
            (staged / name).replace(active / name)
    return captured
saved._capture_saved_source = capture
retained._capture_saved_source = capture
frozen = heads = None
if sys.argv[9] == "true":
    db = SimpleNamespace(require_canonical_scan_directory=lambda path: path, artifact_path=lambda *args, **kwargs: None, ARTIFACTS={"manifest": "scan-manifest.json"})
    connection = SimpleNamespace(execute=lambda *args: SimpleNamespace(fetchall=lambda: [worker]))
    scan = {"scan_dir": str(root), "id": scan_id, "retained_source_digests_json": None, "retained_checkpoint_heads_json": None, "seal_manifest_digest": None}
    frozen, _, heads = saved._recovery_source_digests(db, connection, scan)
merged = merge_saved_results(*args, stopped=True, reason="interrupted", frozen_source_digests=frozen, checkpoint_heads=heads)
saved._capture_saved_source = original_capture
retained._capture_saved_source = original_retained_capture
snapshot = merged[0]["scan"]
def replay():
    return merge_saved_results(*args, stopped=True, reason="interrupted", frozen_source_digests=snapshot["preservedSources"], checkpoint_heads=snapshot["preservedCheckpointHeads"])
assert merged[2] == replay()[2]
rejects_changed_checkpoint = None
if published:
    checkpoint = root / published[-1]
    original = checkpoint.read_bytes()
    checkpoint.write_text("{}")
    try:
        replay()
    except saved.ContractError:
        rejects_changed_checkpoint = True
    else:
        rejects_changed_checkpoint = False
    finally:
        checkpoint.write_bytes(original)
refs = merged[2]["surfaces"][0]["receiptRefs"]
warnings = []
coverage = merged[2]
_recover_unsealed_coverage(coverage, plugin / "schemas", root, warnings, [])
print(json.dumps({"refs": refs, "surfaces": coverage["surfaces"], "warnings": warnings, "published": published, "captured": snapshot["preservedSources"], "rejectsChangedCheckpoint": rejects_changed_checkpoint}))
`,
        path.resolve(import.meta.dirname, "../.."),
        f.root,
        f.workerRoot,
        scanId,
        String(complete),
        String(attempt),
        JSON.stringify(includePaths),
        String(publishDuringCapture),
        String(explicitRecovery),
      ],
      {
        encoding: "utf8",
        ...(explicitRecovery
          ? { env: { ...process.env, PYTHONHASHSEED: "0" } }
          : {}),
      },
    ),
  );
}

const evidenceRef = "artifacts/evidence.txt";

for (const sharedExists of [false, true]) {
  receiptTest(
    `direct worker provenance cannot change local receipt ownership (shared exists: ${sharedExists})`,
    async (f) => {
      await receipt(f.workerRoot, evidenceRef, "Local evidence\n");
      if (sharedExists)
        await receipt(f.root, evidenceRef, "Unrelated shared evidence\n");
      await writeJson(
        f.resultPath,
        draft([evidenceRef], {
          provenance: { scanReceiptRefs: [evidenceRef] },
        }),
      );
      const coverage = await f.coverage();
      const [projected] = coverage.surfaces;
      assert.deepEqual(projected.receiptRefs, [`${f.prefix}/${evidenceRef}`]);
      assert.equal(
        await readFile(path.join(f.root, projected.receiptRefs[0]), "utf8"),
        "Local evidence\n",
      );
    },
  );
}

receiptTest(
  "direct worker receipts fall back to an existing shared file without a local receipt",
  async (f) => {
    await receipt(f.root, evidenceRef, "Shared evidence\n");
    await writeJson(f.resultPath, draft([evidenceRef]));
    const coverage = await f.coverage();
    assert.deepEqual(coverage.surfaces[0].receiptRefs, [evidenceRef]);
  },
);

for (const update of ["notes", "receipt order"] as const) {
  receiptTest(
    `retained shared ownership survives changed ${update} and a local collision`,
    async (f) => {
      const refs = ["artifacts/first.txt", "artifacts/second.txt"];
      for (const ref of refs) await receipt(f.root, ref, "Shared evidence\n");
      await f.recordDraft(draft(refs));
      for (const ref of refs)
        await receipt(f.workerRoot, ref, "Unrelated local evidence\n");
      await f.recordDraft(
        draft(
          update === "receipt order" ? [...refs].reverse() : refs,
          update === "notes" ? { notes: "Updated review notes." } : {},
        ),
      );
      const coverage = await f.coverage();
      const [projected] = coverage.surfaces;
      assert.deepEqual([...projected.receiptRefs].sort(), [...refs].sort());
      for (const ref of projected.receiptRefs)
        assert.equal(
          await readFile(path.join(f.root, ref), "utf8"),
          "Shared evidence\n",
        );
    },
  );
}

for (const changed of ["result provenance", "checkpoint contents"] as const) {
  receiptTest(
    `saved ownership requires the exact checkpoint payload after changed ${changed}`,
    async (f) => {
      await receipt(f.root, evidenceRef, "Shared evidence\n");
      await f.recordDraft(draft([evidenceRef]));
      await receipt(f.workerRoot, evidenceRef, "Local evidence\n");

      if (changed === "result provenance") {
        const saved = await readJson(f.resultPath);
        saved.reviewState.surfaces[0].provenance.extra =
          "Directly authored extension";
        await writeJson(f.resultPath, saved);
      } else {
        const checkpointRoot = path.join(f.workerRoot, "checkpoints");
        for (const name of await readdir(checkpointRoot)) {
          const checkpoint = path.join(checkpointRoot, name);
          const saved = await readJson(checkpoint);
          saved.reviewState.surfaces[0].provenance.extra = "Changed checkpoint";
          await writeJson(checkpoint, saved);
        }
      }
      const coverage = await f.coverage();
      assert.deepEqual(coverage.surfaces[0].receiptRefs, [
        `${f.prefix}/${evidenceRef}`,
      ]);
    },
  );
}

for (const fileScope of [false, true]) {
  for (const inScope of [false, true]) {
    for (const complete of [false, true]) {
      receiptTest(
        `scoped worker ${complete ? "publication" : "checkpoint"} retains shared receipts from a legacy draft (finding in scope: ${inScope}, exact file: ${fileScope})`,
        async (f) => {
          await receipt(f.root, evidenceRef, "Shared evidence\n");
          // Older workers saved progress without the requested-path binding.
          await f.recordDraft({
            ...draft([evidenceRef]),
            findings: [
              finding("inherited", inScope ? "src/route.ts" : "other/route.ts"),
              ...(fileScope
                ? [finding("file-descendant", "src/route.ts/generated")]
                : []),
            ],
          });
          await receipt(
            f.workerRoot,
            evidenceRef,
            "Unrelated local evidence\n",
          );
          await recordCodexSecurityWorkerScanDraft(
            {
              ...f.worker,
              includePaths: [fileScope ? "src/route.ts" : "src"],
              filePaths: fileScope ? ["src/route.ts"] : [],
            },
            { ...workerDraft([]), complete },
          );
          const published = await readJson(f.resultPath);
          assert.equal(published.findings.length, inScope ? 1 : 0);
          const coverage = complete ? await f.coverage() : undefined;
          const recovered = recoverCoverage(f, complete);
          assert.deepEqual(
            {
              reduction: coverage?.surfaces[0].receiptRefs,
              recovery: recovered.refs,
            },
            {
              reduction: complete ? [evidenceRef] : undefined,
              recovery: [evidenceRef],
            },
          );
          assert.equal(recovered.surfaces[0].disposition, "no_issue_found");
          assert.deepEqual(recovered.warnings, []);
          assert.equal(
            await readFile(path.join(f.root, recovered.refs[0]), "utf8"),
            "Shared evidence\n",
          );
          const head = await readJson(f.workerRoot, "checkpoint-head.json");
          assert.deepEqual(
            await readJson(f.workerRoot, "checkpoints", head.checkpoint),
            published,
          );
        },
      );
    }
  }
}

for (const scenario of [
  "scoped",
  "unscoped",
  "wrong scope",
  "changed finding",
  "changed coverage",
] as const) {
  for (const resultIsNewer of [true, false]) {
    receiptTest(
      `legacy worker receipt ownership: ${scenario} (${resultIsNewer ? "newer result" : "tied observations"})`,
      async (f) => {
        // Captured from the writer before it checkpointed the final scope filter.
        const legacy = await legacyReceiptFixture();
        await receipt(f.root, evidenceRef, "Shared evidence\n");
        await receipt(f.workerRoot, evidenceRef, "Unrelated local evidence\n");
        await saveScanDraftCheckpoint(f.worker, legacy.checkpoint);
        const result =
          scenario === "unscoped" ? legacy.checkpoint : legacy.result;
        if (scenario === "changed finding")
          result.findings[0].title = "Changed finding";
        if (scenario === "changed coverage")
          result.coverage.surfaces[0].notes = "Changed review";
        await writeJson(f.resultPath, result);
        const head = await readJson(f.workerRoot, "checkpoint-head.json");
        // Filesystems can give sequential writes equal mtimes. Bind the intended
        // observation order explicitly instead of depending on clock resolution.
        await Promise.all([
          utimes(path.join(f.workerRoot, "checkpoints", head.checkpoint), 1, 1),
          utimes(path.join(f.workerRoot, "checkpoint-head.json"), 1, 1),
          utimes(f.resultPath, resultIsNewer ? 2 : 1, resultIsNewer ? 2 : 1),
        ]);
        const includePaths =
          scenario === "unscoped"
            ? ["."]
            : scenario === "wrong scope"
              ? ["other"]
              : ["src"];
        const coverage = await f.coverage(includePaths);
        const recovered = recoverCoverage(f, true, 1, includePaths);
        const expected =
          scenario === "scoped" || scenario === "unscoped"
            ? evidenceRef
            : `${f.prefix}/${evidenceRef}`;
        assert.deepEqual(coverage.surfaces[0].receiptRefs, [expected]);
        if (resultIsNewer) {
          assert.deepEqual(recovered.refs, [expected]);
        } else {
          // Recovery keeps the separate trusted checkpoint when observations tie;
          // direct reducer admission still rejects the unrecorded result above.
          assert.deepEqual(recovered.refs, [evidenceRef]);
          assert.equal(recovered.surfaces[0].notes, undefined);
        }
      },
    );
  }
}

for (const explicit of [false, true]) {
  for (const concurrent of [false, true]) {
    receiptTest(
      `${explicit ? "explicit recovery" : "cancellation"} captures the checkpoint for a host-published result (concurrent: ${concurrent})`,
      async (f) => {
        await receipt(f.root, evidenceRef, "Shared evidence\n");
        await f.recordDraft(draft([evidenceRef]));
        const checkpointRoot = path.join(f.workerRoot, "checkpoints");
        const initialCheckpoints = new Set(await readdir(checkpointRoot));
        const initial = await Promise.all(
          ["checkpoint-head.json", "result.json"].map(
            async (name) =>
              [name, await readFile(path.join(f.workerRoot, name))] as const,
          ),
        );
        await receipt(f.workerRoot, evidenceRef, "Unrelated local evidence\n");
        await f.recordDraft({
          ...draft([evidenceRef]),
          scope: { summary: "Additional scope context" },
        });
        if (concurrent) {
          const staged = path.join(f.root, "publication");
          await mkdir(path.join(staged, "checkpoints"), { recursive: true });
          for (const name of await readdir(checkpointRoot)) {
            if (!initialCheckpoints.has(name))
              await rename(
                path.join(checkpointRoot, name),
                path.join(staged, "checkpoints", name),
              );
          }
          for (const [name, contents] of initial) {
            await rename(
              path.join(f.workerRoot, name),
              path.join(staged, name),
            );
            await writeFile(path.join(f.workerRoot, name), contents);
            await utimes(path.join(f.workerRoot, name), 1, 1);
          }
        }
        const recovered = recoverCoverage(
          f,
          true,
          1,
          ["."],
          concurrent,
          explicit,
        );
        assert.deepEqual(recovered.refs, [evidenceRef]);
        if (concurrent) {
          assert.ok(recovered.published.length > 0);
          assert.ok(
            recovered.published.every(
              (name: string) => name in recovered.captured,
            ),
          );
          assert.equal(recovered.rejectsChangedCheckpoint, true);
        }
      },
    );
  }
}

for (const fileScope of [false, true])
  for (const localReceipt of [false, true]) {
    test(`the coordinator binds the requested scope while reducing legacy receipt ownership (exact file: ${fileScope}, local receipt: ${localReceipt})`, async () => {
      const fixture = await fixtureRun();
      fixture.run.scope = fileScope ? "src/route.ts" : "src";
      fixture.run.includePaths = [fixture.run.scope];
      fixture.run.filePaths = fileScope ? [fixture.run.scope] : [];
      const store = new FakeStore(fixture.run);
      const executor = new FakeExecutor();
      const run = executor.run.bind(executor);
      executor.run = async (request) => {
        const result = await run(request);
        if (request.kind === "discovery") {
          const legacy = await legacyReceiptFixture();
          if (fileScope)
            legacy.checkpoint.findings[1].locations[0].path =
              "src/route.ts/generated";
          legacy.checkpoint.scanId = fixture.run.scanId;
          legacy.result.scanId = fixture.run.scanId;
          await receipt(fixture.run.scanDir, evidenceRef, "Shared evidence\n");
          if (localReceipt)
            await receipt(
              request.workingDirectory,
              evidenceRef,
              "Unrelated local evidence\n",
            );
          await saveScanDraftCheckpoint(
            {
              ...request.artifactContext,
              scanId: fixture.run.scanId,
              repoRoot: fixture.run.targetPath,
            },
            legacy.checkpoint,
          );
          await writeJson(
            path.join(request.workingDirectory, "result.json"),
            legacy.result,
          );
        }
        return result;
      };
      try {
        for (const resume of [false, true]) {
          if (resume) {
            store.run = {
              ...store.run,
              status: "running",
              terminalReason: undefined,
              manifestPath: undefined,
              persistedWorkers: structuredClone([...store.workers.values()]),
              persistedDedupInputs: store.dedupClaims.flatMap(claimDedupInputs),
            };
          }
          const activeExecutor = resume ? new FakeExecutor() : executor;
          const receiptRefs: unknown[] = [];
          const terminal = await runCoordinator(
            fixture,
            store,
            activeExecutor,
            {
              run: store.run,
              onComplete: async (draft) => {
                receiptRefs.push(
                  ...(
                    draft.reviewState.surfaces as { receiptRefs: string[] }[]
                  ).flatMap((surface) => surface.receiptRefs),
                );
              },
            },
          );
          assert.equal(terminal?.status, "succeeded", terminal?.error);
          assert.equal(activeExecutor.discoveryCalls, resume ? 0 : 1);
          assert.equal(activeExecutor.dedupCalls, resume ? 0 : 1);
          assert.deepEqual(receiptRefs, [evidenceRef]);
        }
      } finally {
        await rm(path.dirname(fixture.run.scanDir), {
          recursive: true,
          force: true,
        });
      }
    });
  }

receiptTest(
  "a retained surface keeps only retained shared references and resolves new receipts locally",
  async (f) => {
    const retained = "artifacts/retained.txt";
    const removed = "artifacts/removed.txt";
    const added = "artifacts/added.txt";
    for (const ref of [retained, removed, added])
      await receipt(f.root, ref, "Shared evidence\n");
    await f.recordDraft(draft([retained, removed]));
    for (const ref of [retained, added])
      await receipt(f.workerRoot, ref, "Local evidence\n");
    const result = await f.recordDraft(
      draft([retained, added], { notes: "Updated review." }),
    );
    assert.deepEqual(
      result.reviewState.surfaces[0].provenance.scanReceiptRefs,
      [retained],
    );
    const coverage = await f.coverage();
    assert.deepEqual(coverage.surfaces[0].receiptRefs, [
      retained,
      `${f.prefix}/${added}`,
    ]);
  },
);

receiptTest(
  "ambiguous saved surface IDs do not transfer shared ownership to an edited observation",
  async (f) => {
    await receipt(f.root, evidenceRef, "Shared evidence\n");
    await f.recordDraft(draft([evidenceRef]));

    const previous = await readJson(f.resultPath);
    previous.reviewState.surfaces.push({
      ...previous.reviewState.surfaces[0],
      label: "Separate review with a reused ID",
    });
    await writeJson(f.resultPath, previous);
    await receipt(f.workerRoot, evidenceRef, "Local evidence\n");
    await f.recordDraft(draft([evidenceRef], { notes: "Updated review." }));
    const coverage = await f.coverage();
    const edited = coverage.surfaces.find(
      (surface: { notes?: string }) => surface.notes === "Updated review.",
    );
    assert.deepEqual(edited.receiptRefs, [`${f.prefix}/${evidenceRef}`]);
  },
);

for (const archived of [false, true]) {
  receiptTest(
    `an unrecorded ${archived ? "archived" : "current"} result cannot transfer shared ownership through a later draft`,
    async (f) => {
      await receipt(f.root, evidenceRef, "Unrelated shared evidence\n");
      await receipt(f.workerRoot, evidenceRef, "Local evidence\n");
      await writeJson(
        f.resultPath,
        draft([evidenceRef], {
          provenance: { scanReceiptRefs: [evidenceRef] },
        }),
      );
      let prefix = f.prefix;
      if (archived) {
        const archive = path.join(
          path.dirname(f.workerRoot),
          "attempts/attempt-01",
        );
        await mkdir(path.dirname(archive), { recursive: true });
        await rename(f.workerRoot, archive);
        await mkdir(f.workerRoot);
        prefix = `${f.prefix}/artifacts/archived-receipts/attempt-01`;
      }
      await f.recordDraft(
        archived
          ? workerDraft([])
          : draft([evidenceRef], { notes: "Updated review." }),
      );
      const coverage = await f.coverage();
      const [surface] = coverage.surfaces;
      assert.deepEqual(surface.receiptRefs, [`${prefix}/${evidenceRef}`]);
      assert.equal(
        await readFile(path.join(f.root, surface.receiptRefs[0]), "utf8"),
        "Local evidence\n",
      );
    },
  );
}

receiptTest(
  "newly resolved shared receipts survive a later local collision alongside inherited receipts",
  async (f) => {
    const refs = ["artifacts/first.txt", "artifacts/second.txt"];
    for (const ref of refs) await receipt(f.root, ref, "Shared evidence\n");
    await f.recordDraft(draft([refs[0]!]));
    await f.recordDraft(draft(refs));
    await receipt(f.workerRoot, refs[1]!, "Unrelated local evidence\n");
    const coverage = await f.coverage();
    assert.deepEqual(coverage.surfaces[0].receiptRefs, refs);
  },
);

for (const complete of [false, true]) {
  for (const archived of [false, true]) {
    for (const lost of [false, true]) {
      receiptTest(
        `first saved local receipt in a ${complete ? "result" : "checkpoint"} stays owned after ${archived ? "archiving" : "acceptance"} (${lost ? "lost" : "present"})`,
        async (f) => {
          await receipt(f.workerRoot, evidenceRef, "Local evidence\n");
          await receipt(f.root, evidenceRef, "Unrelated shared evidence\n");
          await f.recordDraft({
            ...draft([evidenceRef]),
            complete,
          });
          let output = f.workerRoot;
          if (archived) {
            output = path.join(
              path.dirname(f.workerRoot),
              "attempts/attempt-01",
            );
            await mkdir(path.dirname(output), { recursive: true });
            await rename(f.workerRoot, output);
          }
          if (lost) await rm(path.join(output, evidenceRef));
          if (archived) {
            await mkdir(f.workerRoot);
            await f.recordDraft(workerDraft([]));
          }
          const expected =
            archived && !lost
              ? `${f.prefix}/artifacts/archived-receipts/attempt-01/${evidenceRef}`
              : `${path.relative(f.root, output).split(path.sep).join("/")}/${evidenceRef}`;
          if (complete) {
            const coverage = await f.coverage();
            assert.deepEqual(coverage.surfaces[0].receiptRefs, [expected]);
          }
          const recovered = recoverCoverage(f, complete);
          assert.deepEqual(recovered.refs, [expected]);
          assert.equal(
            recovered.surfaces[0].disposition,
            lost ? "needs_follow_up" : "no_issue_found",
          );
          assert.equal(
            recovered.warnings.some((warning: string) =>
              warning.includes("coverage receipt"),
            ),
            lost,
          );
        },
      );
    }
  }
}

receiptTest(
  "a draft preserved after a malformed result keeps its local receipt after loss",
  async (f) => {
    await receipt(f.workerRoot, evidenceRef, "Local evidence\n");
    await receipt(f.root, evidenceRef, "Unrelated shared evidence\n");

    await writeFile(f.resultPath, "{broken");
    await assert.rejects(
      f.recordDraft(draft([evidenceRef])),
      /stored JSON is malformed/,
    );
    await rm(f.resultPath);
    await rm(path.join(f.workerRoot, evidenceRef));
    await f.recordDraft(workerDraft([]));
    const coverage = await f.coverage();
    assert.deepEqual(coverage.surfaces[0].receiptRefs, [
      `${f.prefix}/${evidenceRef}`,
    ]);
  },
);

for (const spelling of ["original", "returned"] as const) {
  for (const sharedExists of [false, true]) {
    for (const observation of [
      "same",
      "notes",
      "new id",
      "new disposition",
    ] as const) {
      for (const newLocal of [false, true]) {
        receiptTest(
          `resubmitted ${spelling} receipt survives two archives: ${observation}, shared=${sharedExists}, new local=${newLocal}`,
          async (f) => {
            await receipt(
              f.workerRoot,
              evidenceRef,
              "Original local evidence\n",
            );
            if (sharedExists)
              await receipt(f.root, evidenceRef, "Unrelated shared evidence\n");
            const first = await f.recordDraft(draft([evidenceRef]));
            const submitted =
              spelling === "original"
                ? evidenceRef
                : first.reviewState.surfaces[0].receiptRefs[0];
            let ownedRef = `${f.prefix}/${evidenceRef}`;
            let contents = "Original local evidence\n";
            for (const attempt of [1, 2]) {
              const archive = path.join(
                path.dirname(f.workerRoot),
                "attempts",
                `attempt-0${attempt}`,
              );
              const priorResult = await readFile(f.resultPath, "utf8");
              await archiveDirectory(f.workerRoot, archive);
              if (ownedRef.startsWith(`${f.prefix}/`))
                ownedRef = `${f.prefix}/artifacts/archived-receipts/attempt-0${attempt}/${ownedRef.slice(f.prefix.length + 1)}`;
              const retained =
                observation === "same" || observation === "notes";
              if (newLocal) {
                contents = `New local evidence ${attempt}\n`;
                await receipt(f.workerRoot, evidenceRef, contents);
                ownedRef = `${f.prefix}/${evidenceRef}`;
              } else if (!retained) {
                ownedRef =
                  sharedExists && spelling === "original"
                    ? evidenceRef
                    : `${f.prefix}/${evidenceRef}`;
                contents = "Unrelated shared evidence\n";
              }
              const id =
                observation === "new id"
                  ? `new-route-${attempt}`
                  : "reviewed-route";
              await f.recordDraft(
                draft([submitted], {
                  id,
                  ...(observation === "notes"
                    ? { notes: `Retry notes ${attempt}` }
                    : {}),
                  ...(observation === "new disposition"
                    ? {
                        disposition:
                          attempt === 1 ? "not_applicable" : "rejected",
                      }
                    : {}),
                }),
              );
              const coverage = await f.coverage();
              const projected = coverage.surfaces.find(
                (surface: { provenance?: { sourceId?: string } }) =>
                  surface.provenance?.sourceId === id,
              );
              assert.ok(projected);
              assert.deepEqual(projected.receiptRefs, [ownedRef]);
              if (
                newLocal ||
                retained ||
                (sharedExists && spelling === "original")
              ) {
                assert.equal(
                  await readFile(path.join(f.root, ownedRef), "utf8"),
                  contents,
                );
              } else {
                await assert.rejects(readFile(path.join(f.root, ownedRef)), {
                  code: "ENOENT",
                });
              }
              assert.equal(
                await readFile(path.join(archive, "result.json"), "utf8"),
                priorResult,
              );
            }
            if (observation === "same" || observation === "notes") {
              const recovered = recoverCoverage(f, true, 3);
              assert.deepEqual(recovered.refs, [ownedRef]);
              assert.equal(recovered.surfaces[0].disposition, "no_issue_found");
              assert.deepEqual(recovered.warnings, []);
            }
          },
        );
      }
    }
  }
}

for (const spelling of ["original", "returned"] as const) {
  receiptTest(
    `resubmitted ${spelling} receipt cannot fall back to shared evidence after archived evidence is lost`,
    async (f) => {
      await receipt(f.workerRoot, evidenceRef, "Original local evidence\n");
      await receipt(f.root, evidenceRef, "Unrelated shared evidence\n");
      const first = await f.recordDraft(draft([evidenceRef]));
      const archive = path.join(
        path.dirname(f.workerRoot),
        "attempts/attempt-01",
      );
      await archiveDirectory(f.workerRoot, archive);
      await rm(path.join(archive, evidenceRef));
      await f.recordDraft(
        draft([
          spelling === "original"
            ? evidenceRef
            : first.reviewState.surfaces[0].receiptRefs[0],
        ]),
      );
      const expected = `${path.relative(f.root, archive).split(path.sep).join("/")}/${evidenceRef}`;
      const coverage = await f.coverage();
      assert.deepEqual(coverage.surfaces[0].receiptRefs, [expected]);
      const recovered = recoverCoverage(f, true, 2);
      assert.deepEqual(recovered.refs, [expected]);
      assert.equal(recovered.surfaces[0].disposition, "needs_follow_up");
      assert.ok(
        recovered.warnings.some((warning: string) =>
          warning.includes("coverage receipt"),
        ),
      );
    },
  );
}

for (const disposition of ["rejected", "not_applicable"]) {
  for (const archived of [false, true]) {
    receiptTest(
      `a ${disposition} decision cycle resolves fresh receipts (archived=${archived})`,
      async (f) => {
        const candidateId = "candidate-1";
        await receipt(f.root, evidenceRef, "Old shared evidence\n");
        await f.recordDraft(draft([evidenceRef], { disposition, candidateId }));
        for (const [index, next] of [
          "needs_follow_up",
          disposition,
        ].entries()) {
          if (archived)
            await archiveDirectory(
              f.workerRoot,
              path.join(
                path.dirname(f.workerRoot),
                "attempts",
                `attempt-0${index + 1}`,
              ),
            );
          await receipt(
            f.workerRoot,
            evidenceRef,
            index ? "New final local evidence\n" : "Reopened local evidence\n",
          );
          const input = draft([evidenceRef], {
            disposition: next,
            candidateId,
          });
          const result = await f.recordDraft({
            ...input,
            reviewState: {
              ...input.reviewState,
              ...(next === "needs_follow_up"
                ? {
                    completeness: "partial",
                    deferred: [
                      {
                        id: candidateId,
                        candidateId,
                        reason: "Revalidate the candidate.",
                      },
                    ],
                  }
                : {}),
            },
          });
          assert.deepEqual(result.reviewState.surfaces[0].receiptRefs, [
            `${f.prefix}/${evidenceRef}`,
          ]);
        }
        for (const reconstructed of [false, true]) {
          if (reconstructed) {
            await rm(f.resultPath);
            await f.recordDraft(workerDraft([]));
          }
          const coverage = await f.coverage();
          assert.deepEqual(coverage.deferred, []);
          assert.equal(coverage.surfaces.length, 1);
          assert.equal(coverage.surfaces[0].disposition, disposition);
          assert.deepEqual(coverage.surfaces[0].receiptRefs, [
            `${f.prefix}/${evidenceRef}`,
          ]);
          assert.equal(
            await readFile(
              path.join(f.root, coverage.surfaces[0].receiptRefs[0]),
              "utf8",
            ),
            "New final local evidence\n",
          );
          const recovered = recoverCoverage(f, true, archived ? 3 : 1);
          assert.deepEqual(recovered.refs, [`${f.prefix}/${evidenceRef}`]);
          assert.equal(recovered.surfaces[0].disposition, disposition);
          assert.deepEqual(recovered.warnings, []);
        }
      },
    );
  }
}
