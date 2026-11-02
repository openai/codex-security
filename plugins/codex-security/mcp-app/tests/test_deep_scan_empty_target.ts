import assert from "node:assert/strict";
import { execFile as nodeExecFile } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
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
  immediateClock,
  runCoordinator,
  standardScanDraft,
  temporaryDirectories,
  type TestWorker,
} from "./deep_scan_coordinator_fixture.ts";
import { importSource } from "./import-module.ts";
import { writeJson } from "./support/json.ts";

const execFile = promisify(nodeExecFile);
const { decodePosixBytes } = await importSource("src/helpers/posix-path.ts");
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
after(() => temporaryDirectories.cleanup());

for (const checkpoint of ["persisted phase", "dispatched worker"]) {
  test(`resumed ${checkpoint} preserves admission before any accepted result`, async () => {
    const fixture = await fixtureRun({ maxDiscoveryRuns: 2 });
    fixture.run.discoveryStarted = checkpoint === "persisted phase";
    fixture.run.dispatchedCount = checkpoint === "dispatched worker" ? 1 : 0;
    const store = new FakeStore(fixture.run),
      executor = new FakeExecutor({ blockDiscoveryAfterCalls: 0 });
    let checks = 0;
    const coordinator = createCoordinator(fixture, store, executor, {
      checkTarget: async () => {
        checks++;
        throw new Error("Admission must not repeat");
      },
    });
    coordinator.start();
    await assertDiscoveryThenCancel(coordinator, executor);
    assert.equal(checks, 0);
  });
}

test(
  "POSIX encoded directories retain their filesystem bytes",
  { skip: process.platform === "win32" },
  async () => {
    const fixture = await fixtureRun();
    const name =
      process.platform === "darwin"
        ? Buffer.from("selected-雪")
        : Buffer.from([115, 101, 108, 101, 99, 116, 101, 100, 45, 255]);
    const selected = Buffer.concat([
      Buffer.from(fixture.run.targetPath + path.sep),
      name,
    ]);
    await mkdir(selected, { recursive: true });
    await writeFile(
      Buffer.concat([selected, Buffer.from("/source.py")]),
      "pass\n",
    );
    fixture.run.includePaths = [decodePosixBytes(name)];
    const { coordinator, executor } = await startFixture(fixture);
    await assertDiscoveryThenCancel(coordinator, executor);
  },
);

test("an empty child of a nonempty Git repository dispatches no workers", async () => {
  const fixture = await fixtureRun();
  await mkdir(fixture.run.targetPath, { recursive: true });
  const parent = path.dirname(fixture.run.targetPath);
  await writeFile(path.join(parent, "outside.ts"), "export {};\n");
  await execFile("git", ["init", "-q"], { cwd: parent });
  const { coordinator, executor } = await startFixture(fixture);
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "failed");
  assert.match(terminal?.error ?? "", /target is empty.*no security audit/iu);
  assert.equal(executor.discoveryCalls, 0);
  assert.equal(executor.dedupCalls, 0);
});

for (const selection of [
  "file",
  "replaced file",
  "directory",
  "joining empty directory",
]) {
  test(`the engine preserves a registered ${selection} selection`, async () => {
    const fixture = await fixtureRun();
    fixture.run.includePaths = ["selected"];
    fixture.run.filePaths = ["file", "replaced file"].includes(selection)
      ? ["selected"]
      : [];
    await mkdir(fixture.run.targetPath, { recursive: true });
    const selected = path.join(fixture.run.targetPath, "selected");
    if (selection === "file") await writeFile(selected, "");
    else {
      await mkdir(selected);
      if (selection !== "joining empty directory")
        await writeFile(path.join(selected, "source.ts"), "export {};\n");
    }
    const { coordinator, executor, claims } = await startFixture(
      fixture,
      selection === "joining empty directory",
    );
    if (
      selection === "replaced file" ||
      selection === "joining empty directory"
    ) {
      const terminal = await coordinator.wait(undefined, 5_000);
      assert.equal(terminal?.status, "failed");
      assert.match(
        terminal?.error ?? "",
        selection === "replaced file"
          ? /selected file.*regular file/iu
          : /target is empty/iu,
      );
      assert.equal(claims(), 1);
      assert.equal(executor.discoveryCalls, 0);
    } else await assertDiscoveryThenCancel(coordinator, executor);
  });
}

test("physical nonemptiness preserves the existing ignore interpretation", async () => {
  const fixture = await fixtureRun();
  await mkdir(fixture.run.targetPath, { recursive: true });
  await writeFile(path.join(fixture.run.targetPath, ".gitignore"), "*.py\n");
  await writeFile(path.join(fixture.run.targetPath, "ignored.py"), "pass\n");
  const { coordinator, executor } = await startFixture(fixture);
  await assertDiscoveryThenCancel(coordinator, executor);
});

for (const selected of [undefined, "left", "right"]) {
  test(`multiple selections retain a nonempty ${selected ?? "neither"} side`, async () => {
    const fixture = await fixtureRun();
    fixture.run.includePaths = ["left", "right"];
    await mkdir(path.join(fixture.run.targetPath, "left"), { recursive: true });
    await mkdir(path.join(fixture.run.targetPath, "right"));
    await writeFile(
      path.join(fixture.run.targetPath, "outside.ts"),
      "export {};\n",
    );
    if (selected)
      await writeFile(
        path.join(fixture.run.targetPath, selected, "source.ts"),
        "export {};\n",
      );
    const { coordinator, executor } = await startFixture(fixture);
    if (selected) await assertDiscoveryThenCancel(coordinator, executor);
    else {
      assert.equal(
        (await coordinator.wait(undefined, 5_000))?.status,
        "failed",
      );
      assert.equal(executor.discoveryCalls, 0);
    }
  });
}

test("an escaping authoritative selection is rejected before dispatch", async () => {
  const fixture = await fixtureRun();
  await mkdir(fixture.run.targetPath, { recursive: true });
  fixture.run.includePaths = ["../outside"];
  const { coordinator, executor } = await startFixture(fixture);
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "failed");
  assert.match(terminal?.error ?? "", /scope.*inside|outside/iu);
  assert.equal(executor.discoveryCalls, 0);
});

test("a discovery preparation error retains its diagnostic", async () => {
  const fixture = await fixtureRun(),
    store = new FakeStore(fixture.run),
    executor = new FakeExecutor();
  const terminal = await runCoordinator(fixture, store, executor, {
    checkTarget: async () => {
      throw new Error("Synthetic directory read failure");
    },
  });
  assert.equal(terminal?.status, "failed");
  assert.equal(terminal?.error, "Synthetic directory read failure");
  assert.equal(executor.discoveryCalls, 0);
});

test("cancellation before preparation launches no check", async () => {
  const fixture = await fixtureRun(),
    store = new FakeStore(fixture.run),
    executor = new FakeExecutor();
  let calls = 0;
  const coordinator = createCoordinator(fixture, store, executor, {
    checkTarget: async () => {
      calls++;
    },
  });
  coordinator.cancel("cancel before preparation");
  coordinator.start();
  assert.equal((await coordinator.wait(undefined, 5_000))?.status, "canceled");
  assert.equal(calls, 0);
  assert.equal(executor.discoveryCalls, 0);
});

test("cancellation reaches pending preparation", async () => {
  const fixture = await fixtureRun(),
    store = new FakeStore(fixture.run),
    executor = new FakeExecutor();
  const entered = Promise.withResolvers<void>();
  let received: AbortSignal | undefined;
  const coordinator = createCoordinator(fixture, store, executor, {
    checkTarget: async (_run, signal) => {
      received = signal;
      entered.resolve();
      await new Promise<void>((resolve) =>
        signal.addEventListener("abort", () => resolve(), { once: true }),
      );
      signal.throwIfAborted();
    },
  });
  coordinator.start();
  await entered.promise;
  coordinator.cancel("cancel preparation");
  assert.equal((await coordinator.wait(undefined, 5_000))?.status, "canceled");
  assert.equal(received?.aborted, true);
  assert.equal(executor.discoveryCalls, 0);
});

for (const empty of [false, true]) {
  test(`an already expired run preserves its capped result, empty=${empty}`, async () => {
    const fixture = await fixtureRun({ maxTimeHours: 1 });
    fixture.run.createdAt = new Date(
      immediateClock.now() - 7_200_000,
    ).toISOString();
    const store = new FakeStore(fixture.run),
      executor = new FakeExecutor();
    let calls = 0,
      published = false;
    const terminal = await runCoordinator(fixture, store, executor, {
      checkTarget: async () => {
        calls++;
        if (empty) throw new Error("empty");
      },
      onComplete: async (draft) => {
        assert.match(JSON.stringify(draft.reviewState), /time limit elapsed/iu);
        published = true;
      },
    });
    assert.equal(terminal?.status, "succeeded");
    assert.equal(terminal?.terminalReason, "capped");
    assert.equal(calls, 0);
    assert.equal(executor.discoveryCalls, 0);
    assert.equal(executor.dedupCalls, 0);
    assert.equal(published, true);
  });
  test(`a deadline stops outstanding preparation and preserves its capped result, empty=${empty}`, async () => {
    const fixture = await fixtureRun(),
      store = new FakeStore(fixture.run),
      executor = new FakeExecutor();
    const release = Promise.withResolvers<void>(),
      finished = Promise.withResolvers<void>();
    let calls = 0,
      received: AbortSignal | undefined;
    const coordinator = createCoordinator(fixture, store, executor, {
      discoveryTimeoutMs: 500,
      checkTarget: async (_run, signal) => {
        calls++;
        received = signal;
        try {
          await release.promise;
          if (empty) throw new Error("empty");
        } finally {
          finished.resolve();
        }
      },
      onComplete: async (draft) => {
        assert.match(JSON.stringify(draft.reviewState), /time limit elapsed/iu);
      },
    });
    coordinator.start();
    try {
      const terminal = await coordinator.wait(undefined, 5_000);
      assert.equal(terminal?.status, "succeeded");
      assert.equal(terminal?.terminalReason, "capped");
      assert.equal(calls, 1);
      assert.equal(received?.aborted, true);
      assert.equal(executor.discoveryCalls, 0);
      assert.equal(executor.dedupCalls, 0);
    } finally {
      release.resolve();
      await finished.promise;
    }
  });
}

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
    checkTarget: async () => {
      preflightCalls += 1;
      throw new Error("Unexpected admission check");
    },
  });

  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(preflightCalls, 0);
  assert.equal(executor.discoveryCalls, 0);
  assert.equal(executor.dedupCalls, 1);
  assert.equal(store.dedupClaims[0]?.workerIds.includes(worker.id), true);
});

async function startFixture(
  fixture: Awaited<ReturnType<typeof fixtureRun>>,
  joining = false,
) {
  const store = new FakeStore(fixture.run),
    executor = new FakeExecutor({ blockDiscoveryAfterCalls: 0 });
  let claims = 0;
  const claim = store.claimCoordinator.bind(store);
  store.claimCoordinator = async () => {
    claims++;
    return claim();
  };
  const registry = new DeepScanCoordinatorRegistry(),
    start = registry.start.bind(registry);
  registry.start = (options: CoordinatorOptions) =>
    start({ ...options, executor });
  const started = await startDeepScanEngine({
    run: joining ? await store.get() : store.run,
    store,
    registry,
    runWorkbench: async (args: string[]) => {
      assert.equal(args[0], "preserve-scan-results");
      return {};
    },
    pluginRoot: fixture.pluginRoot,
    pythonCommand: "fixture-python",
    parentSandbox: { filesystemDenies: [] },
    threadId: "fixture-owner",
  });
  return { ...started, executor, store, claims: () => claims };
}

async function assertDiscoveryThenCancel(
  coordinator: {
    wait(signal: undefined, timeout: number): Promise<unknown>;
    cancel(reason: string): void;
  },
  executor: FakeExecutor,
) {
  try {
    const started = await Promise.race([
      executor.discoveryStarted.promise.then(() => true),
      coordinator.wait(undefined, 5_000).then(() => false),
    ]);
    assert.equal(started, true);
    assert.equal(executor.discoveryCalls, 1);
  } finally {
    coordinator.cancel("fixture complete");
    await coordinator.wait(undefined, 5_000);
  }
}
