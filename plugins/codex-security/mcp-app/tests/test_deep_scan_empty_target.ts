import assert from "node:assert/strict";
import { execFile as nodeExecFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { after, test } from "node:test";
import { promisify } from "node:util";
import type { CoordinatorOptions } from "../src/deep-scan/coordinator.js";
import {
  DeepScanCoordinatorRegistry,
  FakeExecutor,
  FakeStore,
  createCoordinator,
  fixtureRun,
  runCoordinator,
  standardScanDraft,
  temporaryDirectories,
  type TestWorker,
} from "./deep_scan_coordinator_fixture.ts";
import { importSource } from "./import-module.ts";
import { writeJson } from "./support/json.ts";

const execFile = promisify(nodeExecFile);
const { startDeepScanEngine } = await importSource("src/deep-scan/engine.ts", {
  loader: { ".md": "text" },
  define: {
    "import.meta.url": JSON.stringify(
      new URL(
        "../../../../sdk/typescript/_bundled_plugin/mcp/helpers.mjs",
        import.meta.url,
      ).href,
    ),
  },
});
const artifactInventory = await importSource("src/artifact-inventory.ts", {
  define: {
    "import.meta.url": JSON.stringify(
      new URL(
        "../../../../sdk/typescript/_bundled_plugin/mcp/helpers.mjs",
        import.meta.url,
      ).href,
    ),
  },
});

after(() => temporaryDirectories.cleanup());

for (const selection of ["file", "replaced file", "directory"])
  test(`the packaged engine preserves a registered ${selection} selection`, async () => {
    const fixture = await fixtureRun();
    fixture.run.includePaths = ["selected"];
    fixture.run.filePaths = selection === "directory" ? [] : ["selected"];
    await mkdir(fixture.run.targetPath, { recursive: true });
    const selected = path.join(fixture.run.targetPath, "selected");
    if (selection === "file") await writeFile(selected, "export {};\n");
    else {
      await mkdir(selected);
      await writeFile(path.join(selected, "nested.ts"), "export {};\n");
    }
    const store = new FakeStore(fixture.run);
    const executor = new FakeExecutor({ blockDiscoveryAfterCalls: 0 });
    const registry = new DeepScanCoordinatorRegistry();
    const start = registry.start.bind(registry);
    registry.start = (options: CoordinatorOptions) =>
      start({ ...options, executor });
    const { coordinator } = await startDeepScanEngine({
      run: store.run,
      store,
      registry,
      runWorkbench: async (args: string[]) => {
        if (args[0] === "preserve-scan-results") return {};
        assert.equal(args[0], "get-scan");
        return {
          scan: {
            scanId: fixture.run.scanId,
            scanDir: fixture.run.scanDir,
            targetPath: fixture.run.targetPath,
            scope: "selected",
            mode: "deep",
            status: "running",
            contract: {
              scope: {
                requiredIncludePaths: ["selected"],
                requiredExcludePaths: [],
              },
            },
          },
        };
      },
      pluginRoot: path.resolve(
        import.meta.dirname,
        "../../../../sdk/typescript/_bundled_plugin",
      ),
      pythonCommand: "fixture-python",
      parentSandbox: { filesystemDenies: [] },
      threadId: "fixture-owner",
    });
    if (selection === "replaced file") {
      const terminal = await coordinator.wait(undefined, 10_000);
      coordinator.cancel("fixture complete");
      assert.equal(terminal?.status, "failed");
      assert.match(terminal?.error ?? "", /selected file.*regular file/iu);
      assert.equal(executor.discoveryCalls, 0);
      assert.equal(executor.dedupCalls, 0);
    } else {
      await executor.discoveryStarted.promise;
      assert.equal(executor.discoveryCalls, 1);
      coordinator.cancel("fixture complete");
      await coordinator.wait(undefined, 10_000);
    }
  });

test("a fresh empty target fails before discovery or reduction", async () => {
  const fixture = await fixtureRun();
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor();
  let completed = false;

  const terminal = await runCoordinator(fixture, store, executor, {
    prepareReviewItems: async () => ({ reviewItemsTotal: 0 }),
    onComplete: async () => {
      completed = true;
    },
  });

  assert.equal(terminal?.status, "failed");
  assert.match(
    terminal?.error ?? "",
    /no reviewable source files.*no security audit was performed/iu,
  );
  assert.equal(executor.discoveryCalls, 0);
  assert.equal(executor.dedupCalls, 0);
  assert.deepEqual(store.workerUpdates, []);
  assert.deepEqual(store.finishCalls, []);
  assert.equal(store.failureMessages.length, 1);
  assert.equal(completed, false);
});

test("a nonempty target retains normal discovery and reduction", async () => {
  const fixture = await fixtureRun();
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor();

  const terminal = await runCoordinator(fixture, store, executor, {
    prepareReviewItems: async () => ({ reviewItemsTotal: 1 }),
  });

  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(executor.discoveryCalls, 1);
  assert.equal(executor.dedupCalls, 1);
});

test("an inventory failure is not treated as an empty target", async () => {
  const fixture = await fixtureRun();
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor();

  const terminal = await runCoordinator(fixture, store, executor, {
    prepareReviewItems: async () => {
      throw new Error("synthetic inventory failure");
    },
  });

  assert.equal(terminal?.status, "failed");
  assert.equal(terminal?.error, "synthetic inventory failure");
  assert.doesNotMatch(terminal?.error ?? "", /empty target/iu);
  assert.equal(executor.discoveryCalls, 0);
  assert.equal(executor.dedupCalls, 0);
  assert.deepEqual(store.workerUpdates, []);
});

test("resume preserves accepted work without replacing the source inventory", async () => {
  const fixture = await fixtureRun();
  const resultPath = path.join(
    fixture.run.scanDir,
    "artifacts",
    "deep_discovery",
    "workers",
    "discovery-0001",
    "output",
    "result.json",
  );
  await mkdir(path.dirname(resultPath), { recursive: true });
  await writeJson(
    resultPath,
    standardScanDraft(fixture.run.scanId, undefined, "discovery-0001"),
  );
  const worker: TestWorker = {
    id: "accepted-discovery",
    kind: "discovery",
    status: "succeeded",
    mergeState: "buffered",
    promptPath: path.join(
      fixture.run.scanDir,
      "artifacts",
      "deep_discovery",
      "workers",
      "discovery-0001",
      "prompt.md",
    ),
    artifactDir: path.dirname(resultPath),
    attempt: 1,
    resultManifestPath: resultPath,
    completionSequence: 1,
  };
  fixture.run.persistedWorkers = [worker];
  fixture.run.dispatchedCount = 1;
  const store = new FakeStore(fixture.run);
  store.workers.set(worker.id, worker);
  store.completionSequence = 1;
  const executor = new FakeExecutor();
  let preflightCalls = 0;

  const terminal = await runCoordinator(fixture, store, executor, {
    prepareReviewItems: async () => {
      preflightCalls += 1;
      return { reviewItemsTotal: 0 };
    },
  });

  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(preflightCalls, 0);
  assert.equal(executor.discoveryCalls, 0);
  assert.equal(executor.dedupCalls, 1);
  assert.equal(store.dedupClaims[0]?.workerIds.includes(worker.id), true);
});

test("cancellation reaches a pending inventory preflight", async () => {
  const fixture = await fixtureRun();
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor();
  let receivedSignal: AbortSignal | undefined;
  const entered = Promise.withResolvers<void>();
  const coordinator = createCoordinator(fixture, store, executor, {
    prepareReviewItems: async (signal?: AbortSignal) => {
      receivedSignal = signal;
      assert.ok(signal instanceof AbortSignal);
      entered.resolve();
      await new Promise<void>((resolve) =>
        signal.addEventListener("abort", () => resolve(), { once: true }),
      );
      return { reviewItemsTotal: 0 };
    },
  });
  coordinator.start();
  await entered.promise;
  coordinator.cancel("cancel pending inventory");
  const terminal = await coordinator.wait(undefined, 5_000);

  assert.ok(receivedSignal?.aborted);
  assert.equal(terminal?.status, "canceled");
  assert.equal(executor.discoveryCalls, 0);
  assert.equal(executor.dedupCalls, 0);
  assert.deepEqual(store.failureMessages, []);
});

test("cancellation before inventory preflight does not launch it", async () => {
  const fixture = await fixtureRun();
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor();
  let preflightCalls = 0;
  const coordinator = createCoordinator(fixture, store, executor, {
    prepareReviewItems: async () => {
      preflightCalls += 1;
      return { reviewItemsTotal: 1 };
    },
  });
  coordinator.cancel("cancel before inventory");
  coordinator.start();
  const terminal = await coordinator.wait(undefined, 5_000);

  assert.equal(terminal?.status, "canceled");
  assert.equal(preflightCalls, 0);
  assert.equal(executor.discoveryCalls, 0);
  assert.equal(executor.dedupCalls, 0);
});

test("cancellation after inventory preflight wins over an empty result", async () => {
  const fixture = await fixtureRun();
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor();
  let coordinator: ReturnType<typeof createCoordinator>;
  coordinator = createCoordinator(fixture, store, executor, {
    prepareReviewItems: async () => {
      coordinator.cancel("cancel after inventory");
      return { reviewItemsTotal: 0 };
    },
  });
  coordinator.start();
  const terminal = await coordinator.wait(undefined, 5_000);

  assert.equal(terminal?.status, "canceled");
  assert.equal(executor.discoveryCalls, 0);
  assert.equal(executor.dedupCalls, 0);
  assert.deepEqual(store.failureMessages, []);
});

test("an empty child of a nonempty Git repository fails through the shared engine", async () => {
  const fixture = await fixtureRun();
  const repository = path.dirname(fixture.run.targetPath);
  await mkdir(fixture.run.targetPath, { recursive: true });
  await writeFile(path.join(repository, "parent-source.ts"), "export {}\n");
  await runGit(repository, "init", "-q");
  await runGit(repository, "add", "parent-source.ts");
  await runGit(repository, "commit", "-qm", "parent source");
  const revision = await runGit(
    fixture.run.targetPath,
    "rev-parse",
    "--verify",
    "HEAD",
  );
  assert.match(revision, /^[0-9a-f]+$/u);

  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor();
  const registry = new DeepScanCoordinatorRegistry();
  const start = registry.start.bind(registry);
  registry.start = (options: CoordinatorOptions) =>
    start({ ...options, executor });
  const pluginRoot = path.resolve(
    import.meta.dirname,
    "../../../../sdk/typescript/_bundled_plugin",
  );
  const { coordinator } = await startDeepScanEngine({
    run: store.run,
    store,
    registry,
    runWorkbench: async (args: string[]) => {
      if (args[0] === "preserve-scan-results") return {};
      assert.equal(args[0], "get-scan");
      return {
        scan: {
          scanId: fixture.run.scanId,
          scanDir: fixture.run.scanDir,
          targetPath: fixture.run.targetPath,
          scope: ".",
          mode: "deep",
          status: "running",
          contract: {},
          targetRevision: revision,
        },
      };
    },
    pluginRoot,
    pythonCommand: "fixture-python",
    parentSandbox: { filesystemDenies: [] },
    threadId: "fixture-owner",
  });
  const terminal = await coordinator.wait(undefined, 10_000);

  assert.equal(terminal?.status, "failed");
  assert.match(terminal?.error ?? "", /no security audit was performed/iu);
  assert.equal(executor.discoveryCalls, 0);
  assert.equal(executor.dedupCalls, 0);
  await assert.rejects(
    readFile(
      path.join(
        fixture.run.scanDir,
        "artifacts",
        "02_discovery",
        "in_scope_files.txt",
      ),
      "utf8",
    ),
    /ENOENT/iu,
  );
});

for (const included of [false, true])
  test(`an inherited .ignore ${included ? "retains an included sibling" : "can make a selected child empty"}`, async () => {
    const fixture = await fixtureRun();
    const repository = path.dirname(fixture.run.targetPath);
    await mkdir(path.join(fixture.run.targetPath, "excluded"), {
      recursive: true,
    });
    await writeFile(path.join(repository, ".ignore"), "excluded/\n");
    await writeFile(
      path.join(fixture.run.targetPath, "excluded", "example.py"),
      "# ignored source\n",
    );
    if (included)
      await writeFile(
        path.join(fixture.run.targetPath, "included.py"),
        "# included source\n",
      );
    await runGit(repository, "init", "-q");
    await runGit(repository, "add", ".ignore");
    await runGit(repository, "commit", "-qm", "ignore rules");

    const store = new FakeStore(fixture.run);
    const executor = new FakeExecutor();
    const pluginRoot = path.resolve(
      import.meta.dirname,
      "../../../../sdk/typescript/_bundled_plugin",
    );
    const terminal = await runCoordinator(fixture, store, executor, {
      prepareReviewItems: (signal) =>
        artifactInventory.preflightCodexSecurityReviewItems(
          {
            root: fixture.run.scanDir,
            repoRoot: fixture.run.targetPath,
            layout: "scan",
            scope: ".",
            pluginRoot,
          },
          signal,
        ),
    });

    if (included) {
      assert.equal(terminal?.status, "succeeded", terminal?.error);
      assert.equal(executor.discoveryCalls, 1);
      assert.equal(executor.dedupCalls, 1);
    } else {
      assert.equal(terminal?.status, "failed");
      assert.match(terminal?.error ?? "", /no security audit was performed/iu);
      assert.equal(executor.discoveryCalls, 0);
      assert.equal(executor.dedupCalls, 0);
      assert.deepEqual(store.finishCalls, []);
    }
  });

test("empty requested paths do not widen to the repository root", async () => {
  const fixture = await fixtureRun();
  await mkdir(path.join(fixture.run.targetPath, "left"), { recursive: true });
  await mkdir(path.join(fixture.run.targetPath, "right"), { recursive: true });
  await writeFile(
    path.join(fixture.run.targetPath, "outside-selection.py"),
    "# outside the requested scope\n",
  );
  await runGit(fixture.run.targetPath, "init", "-q");
  await runGit(fixture.run.targetPath, "add", "outside-selection.py");
  await runGit(fixture.run.targetPath, "commit", "-qm", "root source");
  const revision = await runGit(
    fixture.run.targetPath,
    "rev-parse",
    "--verify",
    "HEAD",
  );
  fixture.run.includePaths = ["left", "right"];

  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor();
  const registry = new DeepScanCoordinatorRegistry();
  const start = registry.start.bind(registry);
  registry.start = (options: CoordinatorOptions) =>
    start({ ...options, executor });
  const pluginRoot = path.resolve(
    import.meta.dirname,
    "../../../../sdk/typescript/_bundled_plugin",
  );
  const { coordinator } = await startDeepScanEngine({
    run: store.run,
    store,
    registry,
    runWorkbench: async (args: string[]) => {
      if (args[0] === "preserve-scan-results") return {};
      assert.equal(args[0], "get-scan");
      return {
        scan: {
          scanId: fixture.run.scanId,
          scanDir: fixture.run.scanDir,
          targetPath: fixture.run.targetPath,
          scope: ".",
          mode: "deep",
          status: "running",
          contract: {
            scope: {
              requiredIncludePaths: ["left", "right"],
              requiredExcludePaths: [],
            },
          },
          targetRevision: revision,
        },
      };
    },
    pluginRoot,
    pythonCommand: "fixture-python",
    parentSandbox: { filesystemDenies: [] },
    threadId: "fixture-owner",
  });
  const terminal = await coordinator.wait(undefined, 10_000);

  assert.equal(terminal?.status, "failed");
  assert.match(terminal?.error ?? "", /no security audit was performed/iu);
  assert.equal(executor.discoveryCalls, 0);
  assert.equal(executor.dedupCalls, 0);
  await assert.rejects(
    readFile(
      path.join(
        fixture.run.scanDir,
        "artifacts",
        "02_discovery",
        "in_scope_files.txt",
      ),
      "utf8",
    ),
    /ENOENT/iu,
  );
});

for (const selected of ["left", "right"]) {
  test(`a source in requested path ${selected} retains normal scanning`, async () => {
    const fixture = await fixtureRun();
    await mkdir(path.join(fixture.run.targetPath, "left"), {
      recursive: true,
    });
    await mkdir(path.join(fixture.run.targetPath, "right"), {
      recursive: true,
    });
    await writeFile(
      path.join(fixture.run.targetPath, selected, "selected.py"),
      "# selected source\n",
    );
    await writeFile(
      path.join(fixture.run.targetPath, "outside-selection.py"),
      "# outside the requested scope\n",
    );
    await runGit(fixture.run.targetPath, "init", "-q");
    await runGit(fixture.run.targetPath, "add", ".");
    await runGit(fixture.run.targetPath, "commit", "-qm", "source tree");
    fixture.run.includePaths = ["left", "right"];

    const store = new FakeStore(fixture.run);
    const executor = new FakeExecutor();
    const pluginRoot = path.resolve(
      import.meta.dirname,
      "../../../../sdk/typescript/_bundled_plugin",
    );
    const context = {
      root: fixture.run.scanDir,
      repoRoot: fixture.run.targetPath,
      layout: "scan" as const,
      scope: ".",
      pluginRoot,
      targetContract: {
        scope: {
          requiredIncludePaths: ["left", "right"],
          requiredExcludePaths: [],
        },
      },
    };
    const terminal = await runCoordinator(fixture, store, executor, {
      prepareReviewItems: (signal) =>
        artifactInventory.preflightCodexSecurityReviewItems(context, signal),
    });

    assert.equal(terminal?.status, "succeeded", terminal?.error);
    assert.equal(executor.discoveryCalls, 1);
    assert.equal(executor.dedupCalls, 1);
  });
}

async function runGit(repository: string, ...arguments_: string[]) {
  const { stdout } = await execFile(
    "git",
    [
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.com",
      ...arguments_,
    ],
    { cwd: repository, encoding: "utf8" },
  );
  return stdout.trim();
}
