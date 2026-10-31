import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { after, test } from "node:test";
import type { CoordinatorOptions } from "../src/deep-scan/coordinator.js";
import type { CodexWorkerRequest } from "../src/deep-scan/types.js";
import { importSource } from "./import-module.ts";
import {
  DeepScanCoordinatorRegistry,
  FakeExecutor,
  FakeStore,
  fixtureRun,
  temporaryDirectories,
} from "./deep_scan_coordinator_fixture.ts";
import { draftFixture } from "./scan-draft-recovery-fixture.ts";
import { finding, workerDraft } from "./scan-draft-fixture.ts";

const { startDeepScanEngine } = await importSource("src/deep-scan/engine.ts", {
  loader: { ".md": "text" },
  define: {
    "import.meta.url": JSON.stringify(
      new URL("../src/deep-scan/engine.ts", import.meta.url).href,
    ),
  },
});
const { recordCodexSecurityDeepReduction } = await importSource(
  "src/artifact-deep-reducer.ts",
);
after(() => temporaryDirectories.cleanup());

test("Deep engine preserves stopped results for an option-shaped thread ID", async () => {
  const fixture = await fixtureRun();
  const store = new FakeStore(fixture.run);
  store.run.coordinatorGeneration = 7;
  const handoffClaimToken = randomUUID();
  const registry = new DeepScanCoordinatorRegistry();
  const executor = new FakeExecutor({ blockDiscoveryAfterCalls: 0 });
  const start = registry.start.bind(registry);
  registry.start = (options: CoordinatorOptions) =>
    start({
      ...options,
      executor,
      prepareReviewItems: async () => ({ reviewItemsTotal: 1 }),
    });
  const calls: string[][] = [];
  const { coordinator } = await startDeepScanEngine({
    run: store.run,
    store,
    registry,
    pluginRoot: fixture.pluginRoot,
    pythonCommand: "fixture-python",
    parentSandbox: { filesystemDenies: [] },
    threadId: "--fixture-owner",
    handoffClaimToken,
    runWorkbench: async (args: string[]) => {
      calls.push(args);
      return {};
    },
  });
  await executor.discoveryStarted.promise;
  store.run.status = "canceled";
  coordinator.cancel("fixture canceled");
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "canceled");
  assert.deepEqual(calls, [
    [
      "preserve-scan-results",
      "--scan-id",
      store.run.scanId,
      "--thread-id=--fixture-owner",
      "--claim-token",
      handoffClaimToken,
      "--coordinator-generation",
      String(store.run.coordinatorGeneration),
    ],
  ]);
});

for (const route of ["mcp", "file"] as const) {
  test(`Deep engine publishes historical metadata inherited by a ${route} reducer`, async () => {
    const fixture = await fixtureRun({ maxDiscoveryRuns: 1 });
    const store = new FakeStore(fixture.run);
    const registry = new DeepScanCoordinatorRegistry();
    const run = store.run;
    const source = finding("shared", "api/source.py");
    const legacy = {
      scanId: run.scanId,
      findings: [{ ...source, extensions: { measurement: "OVERFLOW" } }],
      threatModel: { summary: "Historical model", measurement: "OVERFLOW" },
    };
    const encode = (value: unknown) =>
      JSON.stringify(value).replaceAll('"OVERFLOW"', "1e400");
    const deepRoot = join(run.scanDir, "artifacts/deep_discovery");
    const workerPath = join(
      deepRoot,
      "workers/discovery-0001/output/result.json",
    );
    await mkdir(dirname(workerPath), { recursive: true });
    await mkdir(run.targetPath, { recursive: true });
    const rawWorker = encode({ ...workerDraft(legacy.findings), ...legacy });
    await writeFile(workerPath, rawWorker);
    const worker = {
      id: "historical-worker",
      scanId: run.scanId,
      kind: "discovery" as const,
      status: "succeeded" as const,
      attempt: 1,
      promptPath: join(dirname(workerPath), "../prompt.md"),
      artifactDir: dirname(workerPath),
      resultManifestPath: workerPath,
      completionSequence: 1,
      mergeState: "buffered" as const,
    };
    store.workers.set(worker.id, worker);
    run.persistedWorkers = [worker];
    run.dispatchedCount = 1;
    let reducerCalls = 0;
    const start = registry.start.bind(registry);
    registry.start = (options: CoordinatorOptions) =>
      start({
        ...options,
        executor: {
          async run(request: CodexWorkerRequest) {
            assert.equal(request.kind, "dedup");
            assert.ok(request.artifactContext);
            reducerCalls += 1;
            const input = { scanId: run.scanId, findings: [source] };
            if (route === "mcp") {
              await recordCodexSecurityDeepReduction(
                request.artifactContext,
                input,
              );
            } else {
              await writeFile(
                join(request.artifactContext.root, "result.json"),
                JSON.stringify(input),
              );
            }
            return {};
          },
        },
      });
    const staged: { draft: string; checkpoint: string }[] = [];
    const context = draftFixture(run.scanDir, "deep").context;
    const { coordinator } = await startDeepScanEngine({
      run,
      store,
      registry,
      pluginRoot: fixture.pluginRoot,
      pythonCommand: "fixture-python",
      parentSandbox: { filesystemDenies: [] },
      threadId: "fixture-owner",
      runWorkbench: async (args: string[]) => {
        if (args[0] === "get-scan")
          return {
            scan: {
              scanId: run.scanId,
              scanDir: run.scanDir,
              targetPath: run.targetPath,
              scope: ".",
              mode: "deep",
              status: "running",
              contract: context.targetContract,
              targetRevision: context.targetRevision,
            },
          };
        if (args[0] === "preserve-scan-results") return {};
        assert.equal(args[0], "write-scan-draft");
        staged.push({
          draft: await readFile(args[args.indexOf("--draft-path") + 1], "utf8"),
          checkpoint: await readFile(
            args[args.indexOf("--checkpoint-path") + 1],
            "utf8",
          ),
        });
        return {};
      },
    });
    const terminal = await coordinator.wait(undefined, 30_000);
    assert.equal(terminal?.status, "succeeded", terminal?.error);
    assert.equal(reducerCalls, 1);
    assert.equal(staged.length, 1);
    const draft = JSON.parse(staged[0].draft);
    const checkpoint = JSON.parse(staged[0].checkpoint);
    assert.equal(draft.manifest.scan.threatModel.measurement, null);
    assert.equal(checkpoint.threatModel.measurement, null);
    const selectedPath = store.dedupCommits.at(-1)!.resultManifestPath;
    assert.equal(draft.deepScanPublication.resultPath, selectedPath);
    const retained = checkpoint.findings[0];
    assert.equal(
      retained.provenance.sourceFindings[0].finding.extensions.measurement,
      null,
    );
    assert.equal(await readFile(workerPath, "utf8"), rawWorker);
    const saved = JSON.parse(await readFile(selectedPath, "utf8"));
    assert.equal(saved.threatModel.measurement, null);
  });
}
