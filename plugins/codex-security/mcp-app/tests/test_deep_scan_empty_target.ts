import assert from "node:assert/strict";
import childProcess, {
  execFile as nodeExecFile,
  type ChildProcessWithoutNullStreams,
} from "node:child_process";
import { once } from "node:events";
import fsModule, { promises as fs } from "node:fs";
import { chmod, mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { after, test, type TestContext } from "node:test";
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
const { decodePosixBytes } = await importSource("src/helpers/posix-path.ts");
const { windowsFiles } = await importSource(
  "src/helpers/resolve-security-md.ts",
  {
    define: {
      "import.meta.url": JSON.stringify(
        new URL(
          "../../../../sdk/typescript/_bundled_plugin/mcp/helpers.mjs",
          import.meta.url,
        ).href,
      ),
    },
  },
);
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

test(
  "a POSIX directory name with invalid UTF-8 bytes retains its filesystem identity",
  { skip: process.platform !== "linux" },
  async () => {
    const fixture = await fixtureRun();
    const name = Buffer.from([115, 101, 108, 101, 99, 116, 101, 100, 45, 0xff]);
    const selected = Buffer.concat([
      Buffer.from(fixture.run.targetPath),
      Buffer.from(path.sep),
      name,
    ]);
    await mkdir(selected, { recursive: true });
    await writeFile(
      Buffer.concat([selected, Buffer.from(`${path.sep}source.py`)]),
      "pass\n",
    );
    fixture.run.includePaths = [decodePosixBytes(name)];

    const { coordinator, executor } = await startFixture(
      fixture,
      new FakeExecutor({ blockDiscoveryAfterCalls: 0 }),
    );
    await assertDiscoveryThenCancel(coordinator, executor);
  },
);

test(
  "a DT_UNKNOWN entry retains its invalid UTF-8 filename during fallback stat",
  { skip: process.platform !== "linux" },
  async (t) => {
    const fixture = await fixtureRun();
    fixture.run.includePaths = ["selected"];
    const selected = path.join(fixture.run.targetPath, "selected");
    const rawName = Buffer.from([
      115, 111, 117, 114, 99, 101, 45, 0xfe, 46, 112, 121,
    ]);
    const rawSelected = Buffer.from(selected);
    await mkdir(selected, { recursive: true });
    await writeFile(
      Buffer.concat([rawSelected, Buffer.from(path.sep), rawName]),
      "pass\n",
    );

    const probe = interceptDirectoryProbe(
      t,
      String.raw`
const fixtureFs = require("node:fs");
const fixtureProcessReadResult = fixtureFs.Dir.prototype.processReadResult;
fixtureFs.Dir.prototype.processReadResult = function(path, result) {
  for (let index = 1; index < result.length; index += 2) result[index] = 0;
  return fixtureProcessReadResult.call(this, path, result);
};`,
    );

    const { coordinator, executor } = await startFixture(
      fixture,
      new FakeExecutor({ blockDiscoveryAfterCalls: 0 }),
    );
    await assertDiscoveryThenCancel(coordinator, executor);
    const child = await probe;
    await waitFor(() => !processExists(child.pid as number));
  },
);

test("slow DT_UNKNOWN metadata does not delay a discovery deadline", async (t) => {
  const fixture = await fixtureRun();
  await mkdir(fixture.run.targetPath, { recursive: true });
  await writeFile(path.join(fixture.run.targetPath, "source.py"), "pass\n");

  const delayMs = 400;
  const dirPrototype = fsModule.Dir.prototype as unknown as {
    processReadResult(path: unknown, result: unknown[]): void;
  };
  const processReadResult = dirPrototype.processReadResult;
  t.mock.method(
    dirPrototype,
    "processReadResult",
    function (this: unknown, directoryPath: unknown, result: unknown[]) {
      for (let index = 1; index < result.length; index += 2) result[index] = 0;
      return processReadResult.call(this, directoryPath, result);
    },
  );
  const lstatSync = fsModule.lstatSync.bind(fsModule);
  t.mock.method(fsModule, "lstatSync", (...arguments_: unknown[]) => {
    const started = Date.now();
    while (Date.now() - started < delayMs) {
      // Reproduce a slow synchronous metadata lookup in Node's Dirent fallback.
    }
    return lstatSync(...(arguments_ as Parameters<typeof fsModule.lstatSync>));
  });

  const realSpawn = childProcess.spawn.bind(childProcess);
  let probePid: number | undefined;
  t.mock.method(
    childProcess,
    "spawn",
    (...arguments_: Parameters<typeof childProcess.spawn>) => {
      const [command, originalArguments, options] = arguments_;
      const childArguments = [...originalArguments];
      const evaluate = childArguments.indexOf("-e");
      if (command === process.execPath && evaluate >= 0) {
        childArguments[evaluate + 1] = `
const fixtureFs = require("node:fs");
const fixtureProcessReadResult = fixtureFs.Dir.prototype.processReadResult;
fixtureFs.Dir.prototype.processReadResult = function(path, result) {
  for (let index = 1; index < result.length; index += 2) result[index] = 0;
  return fixtureProcessReadResult.call(this, path, result);
};
const fixtureLstatSync = fixtureFs.lstatSync;
fixtureFs.lstatSync = function(...args) {
  const started = Date.now();
  while (Date.now() - started < ${delayMs}) {}
  return fixtureLstatSync.apply(this, args);
};
${childArguments[evaluate + 1] ?? ""}`;
      }
      const child = realSpawn(command, childArguments, options);
      probePid = child.pid;
      return child;
    },
  );

  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor();
  const coordinator = createCoordinator(fixture, store, executor, {
    discoveryTimeoutMs: 100,
    checkFreshTarget,
  });
  const started = Date.now();
  coordinator.start();
  const terminal = await coordinator.wait(undefined, 5_000);
  const elapsed = Date.now() - started;
  assert.equal(terminal?.status, "succeeded");
  assert.equal(terminal?.terminalReason, "capped");
  assert.equal(executor.discoveryCalls, 0);
  assert.ok(
    elapsed < 250,
    `slow metadata delayed the discovery deadline by ${elapsed} ms`,
  );
  if (probePid !== undefined)
    await waitFor(() => !processExists(probePid as number));
});

test("directory probe protocol ignores inherited stdout instrumentation", async () => {
  const fixture = await fixtureRun();
  await mkdir(fixture.run.targetPath, { recursive: true });
  await writeFile(path.join(fixture.run.targetPath, "source.py"), "pass\n");
  const preload = path.join(
    path.dirname(fixture.run.targetPath),
    "stdout-preload.cjs",
  );
  await writeFile(
    preload,
    'process.stdout.write("instrumentation active\\n");\n',
  );

  await withNodeOptionsPreload(preload, async () => {
    const { coordinator, executor } = await startFixture(
      fixture,
      new FakeExecutor({ blockDiscoveryAfterCalls: 0 }),
    );
    await assertDiscoveryThenCancel(coordinator, executor);
  });
});

test("directory probe protocol preserves errors with inherited stderr instrumentation", async (t) => {
  const fixture = await fixtureRun();
  await mkdir(fixture.run.targetPath, { recursive: true });
  const preload = path.join(
    path.dirname(fixture.run.targetPath),
    "stderr-preload.cjs",
  );
  await writeFile(
    preload,
    'process.stderr.write("instrumentation error\\n");\n',
  );
  const realStat = fs.stat.bind(fs);
  t.mock.method(
    fs,
    "stat",
    async (...arguments_: Parameters<typeof fs.stat>) => {
      const metadata = await realStat(...arguments_);
      await rm(fixture.run.targetPath, { recursive: true, force: true });
      return metadata;
    },
  );

  await withNodeOptionsPreload(preload, async () => {
    await assert.rejects(
      checkFreshTarget(fixture.run, new AbortController().signal),
      (error: NodeJS.ErrnoException) => {
        assert.equal(error.code, "ENOENT");
        assert.match(error.message, /ENOENT|no such file/iu);
        return true;
      },
    );
  });
});

test(
  "a Windows directory selection preserves a lone surrogate",
  { skip: process.platform !== "win32" },
  async () => {
    const fixture = await fixtureRun();
    await mkdir(fixture.run.targetPath, { recursive: true });
    const name = "selected-\ud800";
    const selected = path.join(fixture.run.targetPath, name);
    const replacement = path.join(fixture.run.targetPath, "selected-\ufffd");
    const files = windowsFiles();
    const wide = Buffer.from(selected, "utf16le");
    const source = Buffer.from(path.join(selected, "source.py"), "utf16le");
    files.mkdir(wide);
    await mkdir(replacement);
    files.writeFile(source, [Buffer.from("pass\n")]);
    fixture.run.includePaths = [name];
    try {
      const { coordinator, executor } = await startFixture(
        fixture,
        new FakeExecutor({ blockDiscoveryAfterCalls: 0 }),
      );
      await assertDiscoveryThenCancel(coordinator, executor);
    } finally {
      files.unlink(source);
      files.unlink(wide);
    }
  },
);

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
  await writeFile(path.join(fixture.run.targetPath, "source.py"), "pass\n");
  const probe = interceptDirectoryProbe(
    t,
    String.raw`
const fixturePromises = require("node:fs/promises");
const fixtureOpen = fixturePromises.opendir;
fixturePromises.opendir = async function(...args) {
  const directory = await fixtureOpen.apply(this, args);
  return {
    read: directory.read.bind(directory),
    close: async () => {
      process.stderr.write("close-started");
      return await new Promise(() => {});
    },
  };
};`,
  );
  const controller = new AbortController();
  const check = checkFreshTarget(fixture.run, controller.signal);
  const child = await probe;
  await once(child.stderr, "data");
  controller.abort("deep_scan_discovery_deadline_reached");

  await completesWithin(check);
  await waitFor(() => !processExists(child.pid as number));
});

test("an abort racing listener registration closes its directory handle", async (t) => {
  const fixture = await fixtureRun();
  await mkdir(fixture.run.targetPath, { recursive: true });
  const probe = interceptDirectoryProbe(
    t,
    String.raw`
const fixturePromises = require("node:fs/promises");
fixturePromises.opendir = async function() {
  return await new Promise(() => {});
};`,
  );
  let aborted = false;
  let listenerRegistrations = 0;
  const signal = {
    get aborted() {
      return aborted;
    },
    addEventListener() {
      listenerRegistrations += 1;
      if (listenerRegistrations === 2) aborted = true;
    },
    removeEventListener() {},
  } as unknown as AbortSignal;

  await checkFreshTarget(fixture.run, signal);
  const child = await probe;
  await waitFor(() => !processExists(child.pid as number));
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
  const probe = interceptDirectoryProbe(
    t,
    String.raw`
const fixturePromises = require("node:fs/promises");
fixturePromises.opendir = async function() {
  process.stderr.write("open-started");
  return await new Promise(() => {});
};`,
  );
  const controller = new AbortController();
  const check = checkFreshTarget(fixture.run, controller.signal);
  const child = await probe;
  await once(child.stderr, "data");
  controller.abort("fixture cancellation");

  await completesWithin(check);
  await waitFor(() => !processExists(child.pid as number));
});

test("cancellation interrupts a pending close and ignores its late rejection", async (t) => {
  const fixture = await fixtureRun();
  await mkdir(fixture.run.targetPath, { recursive: true });
  await writeFile(path.join(fixture.run.targetPath, "source.py"), "pass\n");
  const probe = interceptDirectoryProbe(
    t,
    String.raw`
const fixturePromises = require("node:fs/promises");
const fixtureOpen = fixturePromises.opendir;
fixturePromises.opendir = async function(...args) {
  const directory = await fixtureOpen.apply(this, args);
  return {
    read: directory.read.bind(directory),
    close: async () => {
      process.stderr.write("close-started");
      return await new Promise(() => {});
    },
  };
};`,
  );
  const controller = new AbortController();
  const check = checkFreshTarget(fixture.run, controller.signal);
  const child = await probe;
  await once(child.stderr, "data");
  controller.abort("fixture cancellation");

  await completesWithin(check);
  await waitFor(() => !processExists(child.pid as number));
});

test("filesystem admission removes abort listeners after normal operations", async (t) => {
  const fixture = await fixtureRun();
  await mkdir(fixture.run.targetPath, { recursive: true });
  await writeFile(path.join(fixture.run.targetPath, "source.py"), "pass\n");
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
  await checkFreshTarget(fixture.run, signal);
  assert.equal(listeners.size, 0);
});

test("a real directory read does not make aborted admission await queued close", async (t) => {
  const fixture = await fixtureRun();
  await mkdir(fixture.run.targetPath, { recursive: true });
  await writeFile(path.join(fixture.run.targetPath, "source.py"), "pass\n");
  const probe = interceptDirectoryProbe(
    t,
    String.raw`
const fixturePromises = require("node:fs/promises");
const fixtureOpen = fixturePromises.opendir;
fixturePromises.opendir = async function(...args) {
  const directory = await fixtureOpen.apply(this, args);
  return {
    read: async () => {
      process.stderr.write("read-started");
      return await new Promise(() => {});
    },
    close: directory.close.bind(directory),
  };
};`,
  );
  const controller = new AbortController();
  const check = checkFreshTarget(fixture.run, controller.signal);
  const child = await probe;
  await once(child.stderr, "data");
  controller.abort("fixture cancellation");

  await completesWithin(check);
  await waitFor(() => !processExists(child.pid as number));
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
  const probe = interceptDirectoryProbe(
    t,
    String.raw`
const fixturePromises = require("node:fs/promises");
const fixtureOpen = fixturePromises.opendir;
fixturePromises.opendir = async function(path, options) {
  if (options?.encoding !== "buffer" || options?.bufferSize !== 1)
    throw new Error("directory probe did not request one raw entry");
  const directory = await fixtureOpen.call(this, path, options);
  let reads = 0;
  let closes = 0;
  return {
    read: async () => {
      reads += 1;
      if (reads > 1) throw new Error("directory probe read more than one entry");
      return await directory.read();
    },
    close: async () => {
      closes += 1;
      if (closes > 1) throw new Error("directory probe closed more than once");
      await directory.close();
      if (reads !== 1 || closes !== 1)
        throw new Error("directory probe did not read and close exactly once");
    },
  };
};`,
  );

  await checkFreshTarget(fixture.run, new AbortController().signal);
  const child = await probe;
  await waitFor(() => !processExists(child.pid as number));
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

function interceptDirectoryProbe(
  t: TestContext,
  prefix: string,
): Promise<ChildProcessWithoutNullStreams> {
  const realSpawn = childProcess.spawn.bind(childProcess);
  const started = Promise.withResolvers<ChildProcessWithoutNullStreams>();
  t.mock.method(
    childProcess,
    "spawn",
    (...arguments_: Parameters<typeof childProcess.spawn>) => {
      const [command, originalArguments, options] = arguments_;
      const childArguments = [...originalArguments];
      const evaluate = childArguments.indexOf("-e");
      if (command === process.execPath && evaluate >= 0)
        childArguments[evaluate + 1] =
          `${prefix}\n${childArguments[evaluate + 1] ?? ""}`;
      const child = realSpawn(
        command,
        childArguments,
        options,
      ) as ChildProcessWithoutNullStreams;
      started.resolve(child);
      return child;
    },
  );
  return started.promise;
}

function processExists(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ESRCH";
  }
}

async function withNodeOptionsPreload<T>(
  preload: string,
  operation: () => Promise<T>,
): Promise<T> {
  const original = process.env.NODE_OPTIONS;
  process.env.NODE_OPTIONS =
    `${original ?? ""} --require ${JSON.stringify(preload)}`.trim();
  try {
    return await operation();
  } finally {
    if (original === undefined) delete process.env.NODE_OPTIONS;
    else process.env.NODE_OPTIONS = original;
  }
}

async function assertDiscoveryThenCancel(
  coordinator: {
    wait(
      signal: undefined,
      timeout: number,
    ): Promise<{ status: string; error?: string } | undefined>;
    cancel(reason: string): void;
  },
  executor: FakeExecutor,
): Promise<void> {
  try {
    const result = await Promise.race([
      executor.discoveryStarted.promise.then(() => ({ started: true })),
      coordinator
        .wait(undefined, 5_000)
        .then((terminal) => ({ started: false, terminal })),
    ]);
    assert.equal(
      result.started,
      true,
      "terminal" in result
        ? (result.terminal?.error ?? "discovery did not start")
        : "discovery did not start",
    );
    assert.equal(executor.discoveryCalls, 1);
  } finally {
    coordinator.cancel("fixture complete");
    await coordinator.wait(undefined, 10_000);
  }
}
