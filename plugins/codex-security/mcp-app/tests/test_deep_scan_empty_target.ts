import assert from "node:assert/strict";
import { execFile as nodeExecFile } from "node:child_process";
import { once } from "node:events";
import { promises as fs } from "node:fs";
import { chmod, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { after, test } from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";
import type { CoordinatorOptions } from "../src/deep-scan/coordinator.js";
import {
  DeepScanCoordinatorRegistry,
  FakeExecutor,
  FakeStore,
  assertNoPublishedCandidates,
  createCoordinator,
  fixtureRun as coordinatorFixtureRun,
  runCoordinator,
  temporaryDirectories,
} from "./deep_scan_coordinator_fixture.ts";
import { importSource } from "./import-module.ts";

const execFile = promisify(nodeExecFile);
const permissionTestUnavailable =
  process.platform === "win32" || process.getuid?.() === 0;
const { startDeepScanEngine, checkFreshTarget } = await importSource(
  "src/deep-scan/engine.ts",
  {
    loader: { ".md": "text" },
    define: {
      "import.meta.url": JSON.stringify(
        new URL("../src/deep-scan/engine.ts", import.meta.url).href,
      ),
    },
  },
);

after(() => temporaryDirectories.cleanup());

async function fixtureRun(
  config: Parameters<typeof coordinatorFixtureRun>[0] = {},
) {
  const fixture = await coordinatorFixtureRun(config);
  fixture.run.phase = "setup";
  return fixture;
}

test("an empty directory beneath a Git repository starts no workers", async () => {
  const fixture = await fixtureRun();
  const repository = path.dirname(fixture.run.targetPath);
  await mkdir(fixture.run.targetPath, { recursive: true });
  await writeFile(path.join(repository, "parent-source.ts"), "export {};\n");
  await runGit(repository, "init", "-q");
  await runGit(repository, "add", "parent-source.ts");
  await runGit(repository, "commit", "-qm", "parent source");
  assert.match(
    await runGit(repository, "rev-parse", "--verify", "HEAD"),
    /^[0-9a-f]+$/u,
  );

  const { coordinator, executor, store } = await startFixture(fixture);
  const terminal = await coordinator.wait(undefined, 10_000);

  assert.equal(terminal?.status, "failed");
  assert.match(
    terminal?.error ?? "",
    /target is empty.*no security audit was performed/iu,
  );
  assert.equal(executor.discoveryCalls, 0);
  assert.equal(executor.dedupCalls, 0);
  assert.deepEqual(store.workerUpdates, []);
  assert.deepEqual(store.finishCalls, []);
  await assertNoPublishedCandidates(fixture.run.scanDir);
});

test("a nonempty directory retains ordinary discovery", async () => {
  const fixture = await fixtureRun();
  await mkdir(fixture.run.targetPath, { recursive: true });
  await writeFile(
    path.join(fixture.run.targetPath, "source.ts"),
    "export {};\n",
  );

  const { coordinator, executor } = await startFixture(
    fixture,
    new FakeExecutor({ blockDiscoveryAfterCalls: 0 }),
  );
  await executor.discoveryStarted.promise;
  assert.equal(executor.discoveryCalls, 1);

  coordinator.cancel("fixture complete");
  assert.equal((await coordinator.wait(undefined, 10_000))?.status, "canceled");
});

test("a physically nonempty target is not reinterpreted through ignore rules", async () => {
  const fixture = await fixtureRun();
  await mkdir(fixture.run.targetPath, { recursive: true });
  await writeFile(path.join(fixture.run.targetPath, ".gitignore"), "*.py\n");
  await writeFile(path.join(fixture.run.targetPath, "generated.py"), "pass\n");

  const { coordinator, executor } = await startFixture(
    fixture,
    new FakeExecutor({ blockDiscoveryAfterCalls: 0 }),
  );
  await executor.discoveryStarted.promise;
  assert.equal(executor.discoveryCalls, 1);
  coordinator.cancel("fixture complete");
  await coordinator.wait(undefined, 10_000);
});

test("multiple selected paths are empty only when every path is empty", async () => {
  const emptyFixture = await fixtureRun();
  emptyFixture.run.includePaths = ["left", "right"];
  await mkdir(path.join(emptyFixture.run.targetPath, "left"), {
    recursive: true,
  });
  await mkdir(path.join(emptyFixture.run.targetPath, "right"));

  const empty = await startFixture(emptyFixture);
  const emptyTerminal = await empty.coordinator.wait(undefined, 10_000);
  assert.equal(emptyTerminal?.status, "failed");
  assert.match(emptyTerminal?.error ?? "", /target is empty/iu);
  assert.equal(empty.executor.discoveryCalls, 0);

  const nonemptyFixture = await fixtureRun();
  nonemptyFixture.run.includePaths = ["left", "right"];
  await mkdir(path.join(nonemptyFixture.run.targetPath, "left"), {
    recursive: true,
  });
  await mkdir(path.join(nonemptyFixture.run.targetPath, "right"));
  await writeFile(
    path.join(nonemptyFixture.run.targetPath, "right", "ok.py"),
    "pass\n",
  );
  const nonempty = await startFixture(
    nonemptyFixture,
    new FakeExecutor({ blockDiscoveryAfterCalls: 0 }),
  );
  await nonempty.executor.discoveryStarted.promise;
  assert.equal(nonempty.executor.discoveryCalls, 1);
  nonempty.coordinator.cancel("fixture complete");
  await nonempty.coordinator.wait(undefined, 10_000);
});

for (const replacement of ["file", "directory"] as const) {
  test(`an exact-file selection remains eligible when it is a ${replacement}`, async () => {
    const fixture = await fixtureRun();
    fixture.run.includePaths = ["selected.py"];
    fixture.run.filePaths = ["selected.py"];
    await mkdir(fixture.run.targetPath, { recursive: true });
    const selected = path.join(fixture.run.targetPath, "selected.py");
    if (replacement === "file") await writeFile(selected, "");
    else await mkdir(selected);

    const { coordinator, executor } = await startFixture(
      fixture,
      new FakeExecutor({ blockDiscoveryAfterCalls: 0 }),
    );
    await executor.discoveryStarted.promise;
    assert.equal(executor.discoveryCalls, 1);
    coordinator.cancel("fixture complete");
    await coordinator.wait(undefined, 10_000);
  });
}

test("a deleted exact-file selection retains its filesystem diagnostic", async () => {
  const fixture = await fixtureRun();
  fixture.run.includePaths = ["selected.py"];
  fixture.run.filePaths = ["selected.py"];
  await mkdir(fixture.run.targetPath, { recursive: true });

  const { coordinator, executor } = await startFixture(fixture);
  const terminal = await coordinator.wait(undefined, 10_000);
  assert.equal(terminal?.status, "failed");
  assert.match(terminal?.error ?? "", /ENOENT|no such file/iu);
  assert.equal(executor.discoveryCalls, 0);
  assert.equal(executor.dedupCalls, 0);
});

test(
  "an unreadable selected directory retains its filesystem diagnostic",
  { skip: permissionTestUnavailable },
  async () => {
    const fixture = await fixtureRun();
    await mkdir(fixture.run.targetPath, { recursive: true });
    await chmod(fixture.run.targetPath, 0);
    try {
      const { coordinator, executor } = await startFixture(fixture);
      const terminal = await coordinator.wait(undefined, 10_000);
      assert.equal(terminal?.status, "failed");
      assert.match(terminal?.error ?? "", /EACCES|permission denied/iu);
      assert.doesNotMatch(terminal?.error ?? "", /target is empty/iu);
      assert.equal(executor.discoveryCalls, 0);
      assert.equal(executor.dedupCalls, 0);
    } finally {
      await chmod(fixture.run.targetPath, 0o700);
    }
  },
);

test(
  "an unreadable selected directory does not hide another usable selection",
  { skip: permissionTestUnavailable },
  async () => {
    const fixture = await fixtureRun();
    fixture.run.includePaths = ["left", "right"];
    const left = path.join(fixture.run.targetPath, "left");
    await mkdir(left, { recursive: true });
    await mkdir(path.join(fixture.run.targetPath, "right"));
    await writeFile(
      path.join(fixture.run.targetPath, "right", "ok.py"),
      "pass\n",
    );
    await chmod(left, 0);
    try {
      const { coordinator, executor } = await startFixture(
        fixture,
        new FakeExecutor({ blockDiscoveryAfterCalls: 0 }),
      );
      await executor.discoveryStarted.promise;
      assert.equal(executor.discoveryCalls, 1);
      coordinator.cancel("fixture complete");
      await coordinator.wait(undefined, 10_000);
    } finally {
      await chmod(left, 0o700);
    }
  },
);

test("an already expired discovery budget keeps capped finalization", async () => {
  const fixture = await fixtureRun();
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor();
  const completedDrafts: unknown[] = [];
  let checks = 0;

  const terminal = await runCoordinator(fixture, store, executor, {
    discoveryTimeoutMs: 0,
    checkFreshTarget: async (_run, signal) => {
      checks += 1;
      assert.equal(signal.aborted, true);
    },
    onComplete: async (draft) => void completedDrafts.push(draft),
  });

  assert.equal(checks, 1);
  assert.equal(terminal?.status, "succeeded");
  assert.equal(terminal?.terminalReason, "capped");
  assert.equal(executor.discoveryCalls, 0);
  assert.equal(executor.dedupCalls, 0);
  assert.deepEqual(
    (completedDrafts[0] as { reviewState: { deferred: unknown[] } }).reviewState
      .deferred,
    [
      {
        reason:
          "The configured discovery time limit elapsed before any source review completed.",
      },
    ],
  );
});

test("a discovery budget expiring during admission keeps capped finalization", async () => {
  const fixture = await fixtureRun();
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor();
  const inspectionStarted = Promise.withResolvers<void>();
  const completedDrafts: unknown[] = [];
  const coordinator = createCoordinator(fixture, store, executor, {
    discoveryTimeoutMs: 20,
    checkFreshTarget: async (_run, signal) => {
      inspectionStarted.resolve();
      if (!signal.aborted) await once(signal, "abort");
    },
    onComplete: async (draft) => void completedDrafts.push(draft),
  });
  coordinator.start();
  await inspectionStarted.promise;

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "succeeded");
  assert.equal(terminal?.terminalReason, "capped");
  assert.equal(executor.discoveryCalls, 0);
  assert.equal(executor.dedupCalls, 0);
  assert.equal(completedDrafts.length, 1);
});

test("explicit cancellation during admission remains canceled", async () => {
  const fixture = await fixtureRun();
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor();
  const inspectionStarted = Promise.withResolvers<void>();
  let completed = 0;
  const coordinator = createCoordinator(fixture, store, executor, {
    discoveryTimeoutMs: 60_000,
    checkFreshTarget: async (_run, signal) => {
      inspectionStarted.resolve();
      if (!signal.aborted) await once(signal, "abort");
    },
    onComplete: async () => void (completed += 1),
  });
  coordinator.start();
  await inspectionStarted.promise;
  coordinator.cancel("fixture user cancellation");

  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "canceled");
  assert.equal(terminal?.terminalReason, undefined);
  assert.equal(executor.discoveryCalls, 0);
  assert.equal(executor.dedupCalls, 0);
  assert.equal(completed, 0);
});

test("a deadline during the single-entry probe does not await queued close", async (t) => {
  const fixture = await fixtureRun();
  await mkdir(fixture.run.targetPath, { recursive: true });
  const realOpen = fs.opendir.bind(fs);
  const readStarted = Promise.withResolvers<void>();
  const readFinished = Promise.withResolvers<null>();
  const closeFinished = Promise.withResolvers<void>();
  let closeCalls = 0;
  t.mock.method(
    fs,
    "opendir",
    async (...args: Parameters<typeof fs.opendir>) => {
      const directory = await realOpen(...args);
      return {
        read: async () => {
          readStarted.resolve();
          return await readFinished.promise;
        },
        close: async () => {
          closeCalls += 1;
          await closeFinished.promise;
          await directory.close();
        },
      } as unknown as Awaited<ReturnType<typeof fs.opendir>>;
    },
  );
  const controller = new AbortController();
  const check = checkFreshTarget(fixture.run, controller.signal);
  await readStarted.promise;
  controller.abort("deep_scan_discovery_deadline_reached");

  await completesWithin(check);
  assert.equal(closeCalls, 1);
  readFinished.reject(new Error("late directory read failure"));
  closeFinished.resolve();
  await delay(0);
  assert.equal(closeCalls, 1);
});

test("an abort racing listener registration closes its directory handle", async (t) => {
  const fixture = await fixtureRun();
  await mkdir(fixture.run.targetPath, { recursive: true });
  const readFinished = Promise.withResolvers<null>();
  let closeCalls = 0;
  t.mock.method(fs, "opendir", async () => {
    return {
      read: async () => await readFinished.promise,
      close: async () => void (closeCalls += 1),
    } as unknown as Awaited<ReturnType<typeof fs.opendir>>;
  });
  let aborted = false;
  let listenerRegistrations = 0;
  const signal = {
    get aborted() {
      return aborted;
    },
    addEventListener() {
      listenerRegistrations += 1;
      if (listenerRegistrations === 3) aborted = true;
    },
    removeEventListener() {},
  } as unknown as AbortSignal;

  await checkFreshTarget(fixture.run, signal);
  assert.equal(closeCalls, 1);
  readFinished.resolve(null);
});

test("cancellation interrupts pending metadata and ignores its late rejection", async (t) => {
  const fixture = await fixtureRun();
  const statStarted = Promise.withResolvers<void>();
  const statFinished =
    Promise.withResolvers<Awaited<ReturnType<typeof fs.stat>>>();
  t.mock.method(fs, "stat", async () => {
    statStarted.resolve();
    return await statFinished.promise;
  });
  const controller = new AbortController();
  const check = checkFreshTarget(fixture.run, controller.signal);
  await statStarted.promise;
  controller.abort("fixture cancellation");

  await completesWithin(check);
  statFinished.reject(new Error("late metadata failure"));
  await delay(0);
});

test("cancellation interrupts pending open and closes a late directory handle", async (t) => {
  const fixture = await fixtureRun();
  await mkdir(fixture.run.targetPath, { recursive: true });
  const openStarted = Promise.withResolvers<void>();
  const openFinished =
    Promise.withResolvers<Awaited<ReturnType<typeof fs.opendir>>>();
  let closeCalls = 0;
  t.mock.method(fs, "opendir", async () => {
    openStarted.resolve();
    return await openFinished.promise;
  });
  const controller = new AbortController();
  const check = checkFreshTarget(fixture.run, controller.signal);
  await openStarted.promise;
  controller.abort("fixture cancellation");

  await completesWithin(check);
  openFinished.resolve({
    close: async () => void (closeCalls += 1),
  } as Awaited<ReturnType<typeof fs.opendir>>);
  await waitFor(() => closeCalls === 1);
});

test("cancellation interrupts a pending close and ignores its late rejection", async (t) => {
  const fixture = await fixtureRun();
  await mkdir(fixture.run.targetPath, { recursive: true });
  const closeStarted = Promise.withResolvers<void>();
  const closeFinished = Promise.withResolvers<void>();
  t.mock.method(fs, "opendir", async () => {
    return {
      read: async () => ({ name: "source.py" }),
      close: async () => {
        closeStarted.resolve();
        await closeFinished.promise;
      },
    } as Awaited<ReturnType<typeof fs.opendir>>;
  });
  const controller = new AbortController();
  const check = checkFreshTarget(fixture.run, controller.signal);
  await closeStarted.promise;
  controller.abort("fixture cancellation");

  await completesWithin(check);
  closeFinished.reject(new Error("late close failure"));
  await delay(0);
});

test("filesystem admission removes abort listeners after normal operations", async (t) => {
  const fixture = await fixtureRun();
  await mkdir(fixture.run.targetPath, { recursive: true });
  const listeners = new Set<unknown>();
  const signal = {
    aborted: false,
    addEventListener(_type: string, listener: unknown) {
      listeners.add(listener);
    },
    removeEventListener(_type: string, listener: unknown) {
      listeners.delete(listener);
    },
  } as unknown as AbortSignal;
  t.mock.method(fs, "opendir", async () => {
    return {
      read: async () => ({ name: "source.py" }),
      close: async () => {},
    } as Awaited<ReturnType<typeof fs.opendir>>;
  });

  await checkFreshTarget(fixture.run, signal);
  assert.equal(listeners.size, 0);
});

test("a real directory read does not make aborted admission await queued close", async (t) => {
  const fixture = await fixtureRun();
  await mkdir(fixture.run.targetPath, { recursive: true });
  await writeFile(path.join(fixture.run.targetPath, "source.py"), "pass\n");
  const realOpen = fs.opendir.bind(fs);
  const readStarted = Promise.withResolvers<void>();
  let readSettled = false;
  let closeCalls = 0;
  t.mock.method(
    fs,
    "opendir",
    async (...args: Parameters<typeof fs.opendir>) => {
      const directory = await realOpen(...args);
      const realRead = directory.read.bind(directory);
      const realClose = directory.close.bind(directory);
      return {
        read: () => {
          const read = realRead();
          readStarted.resolve();
          void read.then(
            () => void (readSettled = true),
            () => void (readSettled = true),
          );
          return read;
        },
        close: async () => {
          closeCalls += 1;
          await realClose();
        },
      } as Awaited<ReturnType<typeof fs.opendir>>;
    },
  );
  const controller = new AbortController();
  const check = checkFreshTarget(fixture.run, controller.signal);
  await readStarted.promise;
  assert.equal(readSettled, false);
  controller.abort("fixture cancellation");

  await completesWithin(check);
  await waitFor(() => closeCalls === 1);
  assert.equal(closeCalls, 1);
});

test("a large flat directory is admitted with one entry read", async (t) => {
  const fixture = await fixtureRun();
  await mkdir(fixture.run.targetPath, { recursive: true });
  const fileCount = 20_000;
  for (let offset = 0; offset < fileCount; offset += 250) {
    await Promise.all(
      Array.from({ length: Math.min(250, fileCount - offset) }, (_, index) =>
        writeFile(
          path.join(
            fixture.run.targetPath,
            `entry-${String(offset + index).padStart(5, "0")}`,
          ),
          "",
        ),
      ),
    );
  }
  const realOpen = fs.opendir.bind(fs);
  let reads = 0;
  let closes = 0;
  t.mock.method(
    fs,
    "opendir",
    async (...args: Parameters<typeof fs.opendir>) => {
      const directory = await realOpen(...args);
      return {
        read: async () => {
          reads += 1;
          return await directory.read();
        },
        close: async () => {
          closes += 1;
          await directory.close();
        },
      } as unknown as Awaited<ReturnType<typeof fs.opendir>>;
    },
  );

  await checkFreshTarget(fixture.run, new AbortController().signal);
  assert.equal(reads, 1);
  assert.equal(closes, 1);
});

test("prior dispatch history bypasses the fresh-target check", async () => {
  const fixture = await fixtureRun({ maxDiscoveryRuns: 1 });
  fixture.run.dispatchedCount = 1;
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor();
  let checks = 0;

  const terminal = await runCoordinator(fixture, store, executor, {
    checkFreshTarget: async () => {
      checks += 1;
      throw new Error("fresh-target check should not run");
    },
  });

  assert.equal(checks, 0);
  assert.equal(terminal?.status, "failed");
  assert.match(
    terminal?.error ?? "",
    /ended without a successfully reduced Standard scan/iu,
  );
  assert.doesNotMatch(terminal?.error ?? "", /target is empty/iu);
});

test("a durably admitted run with no dispatch history preserves the resume path", async () => {
  const fixture = await fixtureRun();
  fixture.run.phase = "discovery";
  await mkdir(fixture.run.targetPath, { recursive: true });
  const { coordinator, executor } = await startFixture(
    fixture,
    new FakeExecutor({ blockDiscoveryAfterCalls: 0 }),
  );

  await executor.discoveryStarted.promise;
  assert.equal(executor.discoveryCalls, 1);
  coordinator.cancel("fixture complete");
  await coordinator.wait(undefined, 10_000);
});

async function startFixture(
  fixture: Awaited<ReturnType<typeof fixtureRun>>,
  executor = new FakeExecutor(),
) {
  const store = new FakeStore(fixture.run);
  const registry = new DeepScanCoordinatorRegistry();
  const start = registry.start.bind(registry);
  registry.start = (options: CoordinatorOptions) =>
    start({ ...options, executor });
  const started = await startDeepScanEngine({
    run: store.run,
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
  return { ...started, executor, store };
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

async function completesWithin<T>(operation: Promise<T>): Promise<T> {
  return await new Promise((resolve, reject) => {
    const timer = setTimeout(
      () =>
        reject(
          new Error("filesystem admission did not respond to cancellation"),
        ),
      1_000,
    );
    void operation.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

async function waitFor(condition: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (condition()) return;
    await delay(10);
  }
  assert.fail("eventual directory cleanup did not finish");
}
